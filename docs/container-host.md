# Container-host VMs (nested nspawn)

A **container host** is a single `kind = "vm"` guest that runs many nested
`systemd-nspawn` containers sharing its kernel. It is the macOS answer to
Linux's native `kind = "container"` (which shares the *host* kernel), and the
density model of one VM for many workloads rather than one VM per workload.

This document is the technical reference. The full design and phase history
live in the plan: [`docs/plans/container-host-vms.md`](plans/container-host-vms.md).

**Status:** P1–P6 are implemented and evaluate cleanly, and the **P0 runtime
gate has been verified** (nested nspawn boot, virtiofs CA-key readability,
restart persistence and the ProxyJump SSH path). Feature parity for real
workloads (host services, user shares, relays, proxy routing) is implemented in
[`plans/nested-container-parity.md`](plans/nested-container-parity.md).

---

## 1. Goal and motivation

On Linux a `kind = "container"` guest is already a `systemd-nspawn` container
on the host kernel: it boots once, shares the kernel, and costs only cgroup
memory/CPU when working. macOS cannot run nspawn directly, so the classical
model puts each workload in its own microVM.

A container host recovers the density model on macOS:

| | Classical per-guest VM | Container host |
| --- | --- | --- |
| Kernel / boot | one per guest | one for all nested containers |
| Memory floor | full VM each | container cost only, shared VM kernel |
| Start latency | full NixOS boot | process start inside a running VM |
| Host shares | one virtiofs per VM | one virtiofs, bind-mounted inward |
| Darwin network glue | per-guest socat relay + ARP lookup | a normal inner Linux bridge |

The feature is **opt-in and off by default**. Per-guest `kind = "vm"` microVMs
and Linux `kind = "container"` nspawn are unchanged, and a host may run
classical VMs, native Linux containers and a container host at the same time.

## 2. Option surface

### Guest options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `tartarus.guests.<name>.host` | null or str | `null` | For a `kind = "container"` guest, the name of the container-host VM it runs inside. `null` means the native host-kernel container path (Linux). Required on Darwin. |
| `tartarus.guests.<vm>.vm.containerHost.enable` | bool | `false` | Marks a `kind = "vm"` guest as a container host. |
| `...vm.containerHost.stateVolume.size` | int | `10240` | MiB backing `/var/lib/nixos-containers` inside the host VM. |
| `...vm.containerHost.network.bridge` | str | `"trs2"` | VM-local inner bridge. |
| `...vm.containerHost.network.hostIP` | str | `"10.202.0.1"` | Container host's address on the inner bridge. |
| `...vm.containerHost.network.subnet` | str | `"10.202.0.0/24"` | Inner container subnet. |

`host` is container-only and `vm.containerHost.enable` is VM-only; the
assertions in `nix/host/default.nix` enforce both.

### Host options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `tartarus.hostMemoryMiB` | null or int | `null` | Host RAM in MiB, used to resolve any VM's `vm.mem = "host"`. |
| `tartarus.hostCores` | null or int | `null` | Host CPU count, used to resolve any VM's `vm.vcpu = "host"`. |

### CLI config (`config.toml`)

`nix/host/config.nix` renders **schema 2**, which adds one field per VM
(`container_host = <bool>`) and one optional field per nested container
(`host = "<vm>"`, omitted for native containers). `src/tartarus/config.py`
parses both and defaults them for schema-1 files, so an old `config.toml`
keeps working.

## 3. Build engine

A container host is still a VM: it is collected by `mkGuests` under
`vmGuests` and emits the ordinary `packages.<system>.vm-<name>` runner. There
is **no new `kind`** and no new flake output bucket.

1. `nix/lib/mkGuests.nix` groups enabled `kind = "container"` guests by their
   `host` pointer (`innerByHost`). Only a VM with
   `vm.containerHost.enable = true` receives them; a plain VM gets none.
2. `nix/guest/build.nix` `mkVm` re-evaluates each inner container through the
   **same guest engine** (`mkGuest` with `inHostVm = true`) so the nested and
   standalone `ctn-<name>` configurations stay in lockstep. It then imports
   `nix/guest/container-host.nix` with the evaluated records.
3. `nix/guest/container-host.nix` declares each inner container as a NixOS
   `containers.<name>` entry and wires the VM-local network/state described
   below.

Each nested container's `config = {imports = inner.modules;}` and
`specialArgs` are exactly what the top-level `ctn-<name>` configuration gets,
while `inHostVm = true` makes `platform.nix`/`network.nix` address it on the
inner bridge. The `containers.*` block uses the `hostBridge` +
`privateNetwork = true` model rather than per-container
`localAddress`/`hostAddress`, because the shared-bridge model gives each
container a distinct address without every container claiming the same host
address.

Eager only: one `nix build` realises the VM and every nested container
together. Lazy `nixos-container create` inside a running VM is deferred (see
the plan, §9).

## 4. Networking

Nested containers live entirely inside the host VM; nothing about the inner
network is visible to the macOS host.

- **Inner bridge.** The VM creates `trs2` with address `10.202.0.1/24`
  (overridable via `vm.containerHost.network`). This is a VM-local bridge,
  never one of the host's `trs0`/`trs1` bridges.
- **Addresses.** Each container derives its address from its id:
  `10.202.0.<id>` (the same id pool as native containers). The standalone
  `ctn-<name>` configuration is also generated with this inner address.
- **Forwarding + NAT.** `boot.kernel.sysctl."net.ipv4.ip_forward" = 1`; an
  nftables table `tartarus_inner` masquerades `10.202.0.0/24` out of the
  bridge. The VM's own egress is unchanged (host `trs0` on Linux, vmnet-shared
  on Darwin).
- **DNS.** `services.dnsmasq` listens on `10.202.0.1:53` and forwards to the
  VM's upstream gateway (`resolveLocalQueries = false`, so the VM's own DNS is
  untouched). Containers use `10.202.0.1` as nameserver and default gateway.
- **Names.** The VM's `/etc/hosts` maps each inner address to `<name>` and
  `<name>.trs`, which is what the ProxyJump resolves on the jump host.

## 5. Identity, CA and SSH

Inner containers are ordinary CA-signed guests:

- `src/tartarus/ca.py` `ensure_ctn_certs` signs each nested container's host
  key and issues its client cert under `machines/containers/<name>` in both
  the SSH and X.509 CA roots.
- `nix/guest/shares.nix` exports that key material into the VM at
  `/var/lib/tartarus-inner/<name>/{ssh,x509}` (read-only, never snapshotted),
  and `container-host.nix` bind-mounts it read-only at `/etc/tartarus/ssh` and
  `/etc/tartarus/x509` inside the container.
- `vm.action_start` ensures every inner container's certs exist *before* the
  host VM is built, so the bind-mount sources are present at build time.

SSH goes through the host VM because a nested container has no
host-reachable address:

```
tartarus --container ssh inner
# -> ssh -o HostName=inner -o ProxyJump=ch.trs -o HostKeyAlias=inner.trs ... inner
```

- `HostName=inner` pins the connection to the container's name, resolving
  through the VM's `/etc/hosts`.
- `ProxyJump=ch.trs` reaches the host VM through the existing `*.trs`
  wildcard.
- `HostKeyAlias=inner.trs` makes the `@cert-authority *.trs` line in
  `known_hosts_trs` apply to the CA-signed `inner.trs` principal.

The container-host VM also permits key-only root SSH (`PermitRootLogin =
"prohibit-password"`) using the same shared MicroVM client key the `user`
account trusts (`~/.ssh/tartarus.pub`). This lets the host CLI manage nested
containers' units as root without a passwordless-sudo grant; no other guest
enables root login.

## 6. State persistence

`/var/lib/nixos-containers` inside the host VM is backed by a `microvm.volumes`
image (`nixos-containers.img`, size `vm.containerHost.stateVolume.size`), in
the same way `persistentHome` backs `home.img`. The declarative containers are
declared with `ephemeral = false`, so their root filesystems, logs and any
non-bind-mounted data survive VM restarts and rebuilds.

## 7. Resource ceilings

`vm.mem` and `vm.vcpu` accept three shapes (they are shared by every VM, not
just container hosts):

- a positive integer — passed to microvm.nix unchanged;
- `null` — the definition is omitted, so microvm.nix's own default applies
  (pinned source: 512 MiB / 1 vCPU);
- `"host"` — resolved at evaluation time from `tartarus.hostMemoryMiB` /
  `tartarus.hostCores`.

If `"host"` is requested and the matching host option is `null`, evaluation
fails with an error naming the option. A hypervisor needs a fixed RAM size at
boot, so `"host"` is a host-sized cap, not truly unbounded; guest RAM is
host-backed and faulted on demand, and idle vCPUs cost nothing.

The numeric defaults remain `1` / `768` for backward compatibility.

## 8. Host-side suppression and hard errors

A nested container is **absent from host-side wiring**. `instances.nix`
exposes the host-side predicate as `tartarus.instances.container.hostSideNames`
(enabled containers with `host = null`); the firewall, `/etc/hosts`,
proxy-client list, relay generation and host service modules all filter on it.
`enabledNames`/`idByName` still include nested containers so id assignment and
`config.toml` rendering stay complete and unchanged.

The following are hard evaluation errors:

- `host` names an unknown/disabled guest, or a guest that is not a `kind =
  "vm"` with `vm.containerHost.enable = true`.
- `host` on a `kind = "vm"` guest, or `vm.containerHost.enable` on a
  `kind = "container"` guest.
- a `kind = "container"` on Darwin with no `host`.

Host services, user shares, relays and proxy routing are **supported** for
nested containers (see below); `graphical` / `apps` remain unsupported.

### Nested host services, shares, relays and proxy

A nested container's traffic to the host is DNAT'd out of the container-host
VM (its `eth0`), and the VM's existing masquerade SNATs it, so the macOS host
sees the container-host VM (named by the VM, not the inner container). The VM
stands in for its inner containers in `nix/host/services.nix` and
`nix/host/proxy.nix`, and the host ACLs target the VM name.

| Feature | Wiring |
| --- | --- |
| Host services (`sudoAuthProxy`, `sshAgentProxy`, `clipboardBridge`) | VM `prerouting` DNATs the service ports from the inner bridge to the VM gateway; the host server authorizes the VM. |
| `gpgAgentProxy` | Pure SSH `RemoteForward`; reached by ProxyJump (nixcfg `ssh.nix` Host block). |
| User `shares` / `sharedFolder` | Declared on the container-host VM (mounted under `/var/lib/tartarus-inner/<inner>/…`) and bind-mounted into the container at its guest paths. |
| `relays` | Two-hop: the host socat targets the VM's NAT address; the VM DNATs the relayed port to the inner container. The same port on the inner bridge is also a VM-local "service" so sibling containers can reach it via the gateway name. |
| `proxy.enable` | VM DNATs the proxy port (`hostProxyIP` = inner host IP) to the VM gateway; a proxy-only container is fenced to that gateway by a VM `forward` drop. |

`vm.persistentHome` / `vm.nixStoreOverlay` remain VM-only; a nested container's
rootfs lives on the VM's persistent `nixos-containers.img` volume, so its
`/home/user` persists there.

Autostart is two-level. A nested container's `autostart = true` is a request to
start its **host VM** *and* to declare that container `autoStart = true` inside
the VM, so only the opted-in inner containers come up with the VM — the rest
stay down until `tartarus --container start <name>`. A host VM and a nested
container that both ask for autostart collapse to one host unit (the VM).

## 9. CLI behaviour

| Command | Behaviour for a nested container |
| --- | --- |
| `tartarus list` | lists **every** enabled guest: MicroVMs (with a `(container host)` marker) followed by containers, each container's `HOST` column naming its container-host VM. Nested unit states are queried inside the VM (one SSH round-trip per host). `--vm` / `--container` narrow by kind; `-t`/`--tree` nests each container under its host VM. |
| `tartarus --container list` | containers only (native and nested), the pre-unification form of the above. |
| `tartarus --container status <inner>` | reports the nested container's own `container@<name>` unit state, queried over SSH. |
| `start` / `ssh -s` | ensures the inner certs, starts (or reuses) the host VM, then starts `container@<name>` as root over SSH. |
| `build` | builds the host VM (the nested container is part of that build). |
| `ssh` | ProxyJumps through the host VM (see §5). |
| `stop` / `restart` | drives `systemctl stop/restart container@<name>` as root inside the host VM over SSH (`--purge` is refused). |
| `cid` / `ip` / `proxy` / `proxy-ip` | refused: no host-reachable address. |
| `logs` / `spawn` | refused, pointing at the host VM (or, for `spawn`, at adding a declarative container). |

The SSH control path logs into the container-host VM as **root** over key-only
SSH (the shared MicroVM client key, `PermitRootLogin = "prohibit-password"`) and
runs `systemctl {start,stop,restart} container@*` directly, so no passwordless
sudoers entry is required (`nix/guest/container-host.nix`).

`tartarus list` marks a container-host VM's type column with `(container host)`
and lists its nested containers beneath it (or, with `--tree`, indented under
it).

## 10. Minimal end-to-end example

```nix
# On a macOS host, in the tartarus host module.
tartarus.guests = {
  workbench = {
    enable = true;
    kind = "vm";
    internet = true;
    vm = {
      containerHost.enable = true;
      mem = "host";            # cap at tartarus.hostMemoryMiB
      vcpu = "host";           # cap at tartarus.hostCores
      containerHost.stateVolume.size = 10240;
    };
  };

  toolbox = {
    enable = true;
    kind = "container";
    host = "workbench";        # run nested inside `workbench`
    internet = true;
    systemConfig = { /* packages, secrets, ... */ };
  };
};
```

```bash
tartarus start workbench          # boots the VM; toolbox starts with it
tartarus --container ssh toolbox  # ProxyJump through workbench.trs
tartarus list                     # workbench marked "(container host)", toolbox nested under it
tartarus list --tree              # same, toolbox indented beneath workbench
```

`tartarus.hostMemoryMiB` / `tartarus.hostCores` must be set on the host when a
guest uses the `"host"` sentinel.

## 11. Limitations and the P0 manual gate

- **Runtime verified (P0).** Nested nspawn boot under microvm.nix (cgroup-v2
  delegation), readability of the virtiofs-backed CA key files inside nested
  nspawn, persistence of `/var/lib/nixos-containers` across a VM restart, and
  the `ProxyJump` SSH path have all been exercised. Feature parity (host
  services, shares, relays, proxy) is implemented but was validated by
  evaluation, not yet by a full runtime pass on every workload.
- **Shared kernel.** Nested containers share the host VM's kernel, so their
  isolation is weaker than one VM per guest — the deliberate trade that mirrors
  Linux-native nspawn.
- **Eager only.** Adding a nested container rebuilds and restarts the host VM.
  Lazy creation is deferred (plan §9).
- **Writable-share ownership** across macOS host → virtiofs → VM → bind →
  container relies on matching uids; a nested container's `user` takes the
  invoking host uid for this reason. Validate when a workload writes to a
  shared folder.
- **Host-service identity collapses to the VM.** The VM's masquerade means the
  host sees the container-host VM, so per-inner `ssh-agent-proxy` ACL rules
  must target the VM name.
- **macOS-first.** Linux already has native `kind = "container"` and does not
  need a container host.

### Ballooning verdict

Memory ballooning is a **documented non-goal**. The pinned microvm.nix does
expose `microvm.balloon` and a virtio-mem hotplug pair, and QEMU implements
ballooning — but vfkit/VZ (the macOS hypervisor the container host runs on)
throws `"vfkit does not support memory ballooning"`. Since the feature is
macOS-first and Linux already has native nspawn, ballooning cannot be enabled
on the target hypervisor. The practical mitigation is the `mem = "host"` cap,
which is host-backed and faulted on demand. Revisit if microvm.nix gains
vfkit/VZ `VZMemoryBalloonDevice` support.

## 12. Consumer: nixcfg `ssh.nix`

`modules/programs/user/ssh.nix` excludes nested containers (`host != null`)
from the direct `10.201.0.<id>` Host blocks and instead emits a ProxyJump block
(`ProxyJump <host>.trs`, `HostKeyAlias <name>.trs`,
`IdentityFile ~/.ssh/containers`), mirroring what `tartarus ssh <inner>`
already does. A bare `ssh <inner>` therefore works.

## See also

- Plan (full design + phased history): [`docs/plans/container-host-vms.md`](plans/container-host-vms.md)
- Manual smoke pass: [`docs/smoke.md`](smoke.md)
- Shares and read-only enforcement: [`docs/shares.md`](shares.md)

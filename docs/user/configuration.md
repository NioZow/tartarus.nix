# Configuration

## Who this is for

Users and operators who need the exact name, type and default of every Tartarus
option.

## What you'll learn

- the global options (`proxy`, `dns`, `containers`),
- every `tartarus.guests.<name>` option and its default,
- the host-level path/resource options,
- how memory is returned to the host, and which assertions reject bad configs.

All options live on the host configuration (the module importing
`inputs.tartarus.nixosModules.tartarus`). Guests are declared under
`tartarus.guests.<name>`.

## `tartarus.proxy`

Global **transport** config only — filtering is per guest.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Enable the HTTP proxy. |
| `location` | str | `"host"` | `"host"`, or the name of an enabled guest with `internet = true` to host the proxy there. |
| `port` | port | `3128` | Proxy port. |
| `listenAddresses` | null or list | `null` | Bind addresses; derived from the enabled guest kinds (the `trs` bridges, or the vmnet gateway on Darwin) when null. Never loopback. |
| `log` | bool | `false` | Metadata-only logging (client IP, CONNECT host) to journald. |

## `tartarus.dns`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `location` | null or str | `null` | Name of the enabled guest that is the resolver for all guests. When set, the firewall accepts DNS (UDP/TCP 53) from every guest kind to that resolver. `null` disables the carve-out. |

## `tartarus.containers.*`

Host-wide defaults for `kind = "container"` guests.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `sudoNoPassword.enable` | bool | `false` | Add a scoped `NOPASSWD` sudo rule for `systemctl <verb> container@*`, so `tartarus start`/`stop <container>` no longer prompts. Linux only. |
| `sudoNoPassword.verbs` | list | `["start"]` | The `systemctl` verbs granted without a password. |
| `sudoNoPassword.users` | list | `[]` | Users granted the rule. |
| `sudoNoPassword.groups` | list | `["wheel"]` | Groups granted the rule. |
| `privateUsers` | `"no"` \| `"identity"` \| `"pick"` \| int | `"no"` | Default user namespace for every container (`systemd-nspawn --private-users`). `"pick"`/an int is real UID isolation; requires ID-mapped-mount support on the CA/share source filesystems. A guest overrides it with `privateUsers`. |
| `containerHost` | null or str | `null` | Host-wide default container-host VM: every `kind = "container"` guest without an explicit `host` nests into it. A Linux host leaves it unset (containers stay native); a Darwin host sets it to its container-host VM. |

## `tartarus.guests.<name>`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Whether this guest *exists* on this host: gates the `vm-`/`ctn-<name>` flake outputs, the host CA cert, firewall rules, proxy entries and autostart. Does not force an eager build. |
| `kind` | `"vm"` \| `"container"` | `"vm"` | Guest kind. |
| `vmOnly` | bool | `false` | Pin this guest to `kind = "vm"`; fails evaluation if it is ever switched to a container. |
| `id` | null or int | `null` | Static id 3–100 (determines IP/MAC/CID); auto-assigned from 101 when null. Must be unique within a kind. |
| `host` | null or str | `tartarus.containers.containerHost` | Container only: run nested inside the named container-host VM. `null` keeps the native host-kernel nspawn path. Required on Darwin unless the host-wide option is set. |
| `privateUsers` | null \| `"no"` \| `"identity"` \| `"pick"` \| int | `null` | Container only. Per-guest override of the host-wide default. |
| `graphical` | bool | `false` | Graphical remote display via the `wprs` transport. |
| `internet` | bool | `true` | Direct NAT egress. Mutually exclusive with `proxy.enable`. |
| `sharedFolder` | bool | `false` | Mount a per-guest host directory at `~/shared`. |
| `shares` | list | `[]` | Extra host/guest directory shares (a `readOnly = true` share is enforced by the hypervisor on Linux and a read-only store snapshot on macOS; `overlay = true` gives a writable overlay view of a Linux host directory while the host source stays read-only). See [Shares](../technical/shares.md). |
| `apps` | list | `[]` | Host `.desktop` launchers for apps running in the guest. |
| `autostart` | bool | `false` | Start on login via a tartarus user service. |
| `requires` | list | `[]` | Names of other enabled guests started before this one. Must be acyclic. |
| `relays` | list | `[]` | Host port forwards into this guest (`{ port; targetPort; protocol; host; }`). Every guest can reach the relay as `host:<port>` (the `host` alias is in its `/etc/hosts`); on Linux the host firewall DNATs the port, on Darwin a `socat` relay binds the gateway. |
| `services.clipboardBridge` | bool | `false` | Clipboard bridge (guest client + host server, mTLS). |
| `services.sshAgentProxy` | bool | `false` | Forward the host ssh-agent into the guest. |
| `services.sudoAuthProxy` | bool | `false` | PAM sudo authentication proxy. |
| `services.gpgAgentProxy` | bool | `false` | GPG agent forwarding over SSH. |
| `services.disableVsock` | bool | `false` | Force TCP instead of VSOCK (no-op where VSOCK is unavailable). |
| `services.sudoAuthProxyTransport` | `"vsock"` \| `"tcp"` \| `"unix"` | `"vsock"` | Transport for the sudo-auth-proxy integration. `unix` requests the SSH-forwarded socket. |
| `services.sshAgentProxyTransport` | `"vsock"` \| `"tcp"` \| `"unix"` | `"vsock"` | Transport for the ssh-agent-proxy integration. |
| `vm.vcpu` | int / null / `"host"` | `1` | VM only. A positive int, `null` for the hypervisor default, or `"host"` to cap at `tartarus.hostCores`. |
| `vm.mem` | int / null / `"host"` | `768` | VM only. MiB, `null` for the hypervisor default, or `"host"` to cap at `tartarus.hostMemoryMiB`. |
| `vm.balloon.enable` | bool | `true` | VM only, Linux/QEMU. virtio-balloon + free page reporting. |
| `vm.balloon.deflateOnOOM` | bool | `true` | VM only. Auto-deflate the balloon on guest OOM. |
| `vm.persistentHome.enable` | bool | `false` | VM only. Writable home disk image. |
| `vm.persistentHome.size` | int | `5120` | VM only. MiB. |
| `vm.nixStoreOverlay.size` | int | `2048` | VM only. Writable `/nix/store` overlay, MiB. |
| `vm.containerHost.enable` | bool | `false` | VM only. Host nested `systemd-nspawn` containers inside this VM. |
| `vm.containerHost.stateVolume.size` | int | `10240` | VM only. MiB backing `/var/lib/nixos-containers` inside the host VM. |
| `vm.containerHost.network.bridge` | str | `"trs2"` | VM-local inner bridge for nested containers. |
| `vm.containerHost.network.hostIP` | str | `"10.202.0.1"` | Host IP on the inner bridge. |
| `vm.containerHost.network.subnet` | str | `"10.202.0.0/24"` | Inner container subnet. |
| `vm.containerHost.dns.enable` | bool | `true` | Run dnsmasq on the inner bridge as the nested containers' resolver. |
| `vm.containerHost.dns.upstream` | null or str | `null` | Upstream the inner dnsmasq forwards to; `null` forwards to the VM's gateway. |
| `firewall.enable` | bool | `false` | Enable a tartarus-managed firewall. |
| `firewall.location` | `"host"` \| `"guest"` | `"guest"` | `"host"` is Linux-only; `"guest"` runs nftables inside the guest. |
| `firewall.allow` | list | `[]` | Extra host-service allowances (not an egress backdoor). |
| `proxy.enable` | bool | `false` | Route egress through the proxy (requires the global `tartarus.proxy.enable`). |
| `proxy.allowHosts` | list | `[]` | Squid `dstdomain` allowlist; HTTPS/443 only. |
| `systemConfig` | attrs | `{}` | Your NixOS configuration for the guest. |
| `userConfig` | attrs | `{}` | Your home-manager configuration for the guest. |

`enable` decides whether a guest is part of the host at all, not when it is
built. A disabled guest contributes no flake output, no CA certificate, no
firewall rule, no proxy entry and no autostart, and is omitted from
`config.toml`. The guest closure is only realised when you build it.

## Host path and resource options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `tartarus.flakePath` | str | `$HOME/.config/nixcfg` | Absolute path to **your** flake root (written to `config.toml`). Never the Tartarus repo. |
| `tartarus.stateRoot` | str | `$HOME/.local/state/tartarus` | Per-guest runtime state root (pid/cid/console log/overlay). |
| `tartarus.sshDir` | str | `$HOME/.ssh` | Your SSH directory (client key, `known_hosts`). |
| `tartarus.system` | null or str | `null` | Guest (Linux) system the CLI builds for; derived from the host when null. |
| `tartarus.log` | bool | `false` | Default logging toggle written to `config.toml`. |
| `tartarus.hostMemoryMiB` | null or int | `null` | Host physical RAM in MiB, used to resolve a guest's `vm.mem = "host"`. |
| `tartarus.hostCores` | null or int | `null` | Host CPU count, used to resolve `vm.vcpu = "host"`. |
| `tartarus.ca.enable` | bool | `true` | The shared per-host SSH + X.509 CA. |
| `tartarus.ssh.enable` | bool | `true` | System-wide SSH trust for the Tartarus CA. |
| `tartarus.ssh.knownHostsFile` | str | — | Path of the generated `known_hosts` file carrying the `@cert-authority *.trs` line. |
| `tartarus.ssh.retries` | int | `5` | How many times `tartarus ssh` retries a failed connection (ssh exit 255). |
| `tartarus.ssh.retryDelay` | float | `2.0` | Seconds between `tartarus ssh` connection retries. |

`tartarus.ca.*` also exposes the CA paths (`ssh.caDir`, `ssh.keyPath`,
`ssh.pubPath`, `ssh.machinesDir`, `x509.caDir`, `x509.keyPath`, `x509.crtPath`,
`x509.hostDir`, `x509.hostCertPath`, `x509.hostKeyPath`, `x509.machinesDir`) for
advanced/key-rotation setups; the defaults are suitable for most hosts.

## Memory management

A guest's RAM is fixed at boot (`vm.mem`, default 768 MiB) and its *usable* size
never changes — there is no memory hotplug on QEMU's `microvm` machine type.
What is dynamic is only how much of that allocation the **host** keeps resident.

For a full explanation, see
[How it works](../technical/how-it-works.md#memory-management). In short:

| Mechanism | Triggered by | Automatic? | Returns RAM to host |
| --- | --- | --- | --- |
| Free page reporting | the guest kernel | yes | yes (idle memory) |
| Balloon inflation | the host, via QMP / `microvm-balloon` | no | yes (in-use memory) |
| deflate-on-OOM | QEMU, when the guest nears OOM | yes | no (returns pages to the guest) |

Free page reporting is on by default (`vm.balloon.enable = true`). The balloon
stays at 0 until you inflate it manually from the VM's state dir:

```bash
cd ~/.local/state/tartarus/<vm>
./result/bin/microvm-balloon 512   # MiB; 0 deflates fully
```

## Assertions

Evaluation fails with an actionable message when:

- `internet = true` and `proxy.enable = true` (mutually exclusive);
- `proxy.enable` without the global `tartarus.proxy.enable`;
- `tartarus.proxy.location` is neither `"host"` nor an enabled guest with
  `internet = true`;
- `firewall.location = "host"` on Darwin (Linux only);
- a static id is outside 3–100, or duplicate within a kind;
- `host` names a guest that is not an enabled `kind = "vm"` with
  `vm.containerHost.enable = true` (or `host`/`vm.containerHost` is set on the
  wrong kind);
- a `kind = "container"` guest on Darwin has no `host` and no host-wide
  `tartarus.containers.containerHost`;
- `requires` references an unknown/disabled guest or forms a cycle;
- `vmOnly = true` on a `kind = "container"` guest;
- `privateUsers` is set on a VM.

See [Interfaces](../technical/interfaces.md) for the full assertion list.

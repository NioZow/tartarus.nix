# Configuration

## Who this is for

Users and operators who need the exact name, type and default of every Tartarus
option.

## What you'll learn

- the global options (`proxy`, `dns`, `containers`),
- every `tartarus.guests.<name>` option and its default,
- the lifecycle hooks (`tartarus.hooks`, `tartarus.guests.<name>.hooks`),
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

## Lifecycle hooks

Hooks run a shell command on the **host**, around every lifecycle operation.
They live in two places with the same shape:

- `tartarus.hooks` — host-wide, applying to every enabled guest;
- `tartarus.guests.<name>.hooks` — per guest (sugar, see below).

Both are keyed `event → phase → list of entries`, with the events `create`,
`start`, `stop`, `remove`, `build` and the phases `before` and `after`.
Rebuilds render them to `~/.config/tartarus/hooks.toml`, which the CLI reads on
every operation.

### Shape and defaults

```nix
tartarus.hooks.start.after = [
  {
    command = "logger tartarus guest {name} started";
    guests = [ "*" ];              # default: [ "*" ] (every guest)
    kinds = [ "vm" "container" ];  # default: both kinds
    timeout = 20;                  # seconds, default 30
    retries = 15;                  # default 0 (one attempt)
    retryDelay = 2.0;              # seconds, default 2.0
    onFailure = "warn";            # "warn" | "abort", default "warn"
    description = "Guest started"; # default null (logs fall back to command)
  }
];

# Per guest: the guest's own name and kind are forced.
tartarus.guests.vault.hooks.stop.before = [
  { command = "printf 'stopping %s\n' {name} >> ~/tartarus.log"; }
];
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `command` | str | — (required) | Shell command, run as `/bin/sh -c <command>`. |
| `guests` | list of str | `["*"]` | `fnmatch` glob patterns over instance name and base template; `!pat` excludes, `[]` disables. |
| `kinds` | list of `"vm"`/`"container"` | both | Guest kinds the hook applies to. |
| `timeout` | positive int | `30` | Per-attempt timeout in seconds; a slower command is killed and counts as a failure. |
| `retries` | non-negative int | `0` | Extra attempts after the first failure. |
| `retryDelay` | non-negative number | `2.0` | Seconds between attempts. |
| `onFailure` | `"warn"` \| `"abort"` | `"warn"` | After the last failed attempt: warn and continue, or fail the command. |
| `description` | null or str | `null` | Label for the hook log line and for warnings/errors. |

`guests`/`kinds` written on a **per-guest** entry are ignored: the renderer
forces `guests = ["<name>"]` and `kinds = ["<kind>"]`, so the hook only fires
for that guest (numbered instances such as `notes-2` included) and the guest's
own kind always wins. Use `tartarus.hooks` to cover several guests.

### Events

| Event | When it fires |
| --- | --- |
| `create` | A new instance is provisioned: `tartarus spawn` (VM), or the `nixos-container create` of an ad-hoc container instance. |
| `start` | Every real stopped→running transition, including the start implied by `create`. |
| `stop` | Every real running→stopped transition. |
| `remove` | `tartarus stop --purge` (the VM state dir or the container registration is destroyed). |
| `build` | An explicit `tartarus build <name>`. |

Ordering:

- **create + start** (spawn, or a first container start that provisions):
  `before create` → `before start` → operation → `after start` →
  `after create`.
- **purge**: `before stop` → stop → `after stop` → `before remove` →
  remove → `after remove`. Purging an **already-stopped** instance fires only
  the remove hooks.
- **no-op transitions** (already running / already stopped) fire nothing.
- **`restart`** has no event of its own: it is exactly stop + start, so both
  hook sets fire, stop first.
- A nested container's `build` is delegated to its container-host VM: the
  container's `build` pair brackets the VM build, which fires its own pair.

`after start` runs once the relays are up, which is the earliest a
`tartarus ssh`-style command can succeed.

### Filtering

`guests` holds `fnmatch` glob patterns (`*`, `?`, `[seq]`). Each pattern is
matched against **both** the instance name and its base template, so
`guests = ["notes"]` covers `notes` and `notes-2`, and `guests = ["dev-*"]`
covers every numbered `dev` instance.

- A leading `!` excludes: `guests = ["*" "!vpn"]` is every guest except `vpn`.
- Negations are evaluated **first** and exclude outright; the positive
  patterns then OR together.
- `guests = []` matches nothing (the hook is disabled); `["*"]` is the
  all-inclusive spelling and the default.
- `kinds` narrows to `["vm"]` or `["container"]` (default: both).

### Tokens and environment

`command` may use these tokens, substituted before the shell sees it:

| Token | Environment variable | Value |
| --- | --- | --- |
| `{name}` | `TARTARUS_GUEST` | Instance name (`notes-2`). |
| `{template}` | `TARTARUS_TEMPLATE` | Base guest the instance came from (`notes`). |
| `{kind}` | `TARTARUS_KIND` | `vm` or `container`. |
| `{id}` | `TARTARUS_GUEST_ID` | Guest id (empty when not applicable, e.g. `build.before`). |
| `{event}` | `TARTARUS_EVENT` | `create`, `start`, `stop`, `remove` or `build`. |
| `{phase}` | `TARTARUS_PHASE` | `before` or `after`. |

Substitution is a plain string replace, not `str.format`, so ordinary shell
braces are safe: `${HOME}`, `${1:-default}`, `awk '{print $1}'` all pass
through untouched.

### Execution model

- Each hook runs as `/bin/sh -c <command>` as the **invoking host user** —
  never root, never sudo — with the working directory set to your home
  directory.
- Output is inherited, so it appears in the terminal with the rest of the
  `tartarus` output.
- Each attempt is bounded by `timeout`; `retries` extra attempts are made,
  `retryDelay` seconds apart. Only the last attempt's outcome is reported.
- `onFailure = "warn"` prints a warning and the tartarus command carries on.
  `onFailure = "abort"` fails the command: a `before` hook aborts the
  operation before it runs; an `after` hook fails it although the operation
  already happened.
- Entries run in file order: host-wide hooks before per-guest ones for the
  same event/phase, and list order within a phase is preserved.

### Where the file comes from

At rebuild, the host module writes `~/.config/tartarus/hooks.toml` (schema
`1`, separate from `config.toml`, which stays schema `2`). A missing file is
normal and silent — most hosts have no hooks. Two overrides select another
file:

- `TARTARUS_HOOKS=/path/to/hooks.toml` in the environment;
- `tartarus --hooks /path/to/hooks.toml <command>` as a global flag.

The flag wins over the variable, which wins over the file next to the
effective `config.toml` (so `--config /elsewhere/config.toml` picks
`/elsewhere/hooks.toml`). An explicitly named file that does not exist is an
error.

Hooks are not installed by hand: edit the Nix options and rebuild. The
generated file carries a "do not edit" header.

### Known limitation

Containers that auto-start **inside** a container-host VM are not started
through the host CLI, so their `start.after` hooks do not fire when the host VM
boots. An explicit `tartarus -c start <name>` does fire them.

### Example: host-side plumbing that follows the guest

A common reason for hooks is host-side plumbing that must follow the guest: a
log entry after every start and before every stop. The entries below do that for
every guest (the generated file is shown in
[Data model](../technical/data-model.md#the-hookstoml-artifact)):

```nix
{ ... }: {
  config.tartarus.hooks = {
    start.after = [
      {
        command = "logger tartarus guest {name} started";
        timeout = 20;      # seconds per attempt
        retries = 15;      # 16 attempts, ~30 s of retrying
        retryDelay = 2.0;
        description = "Guest started";
      }
    ];
    stop.before = [
      {
        command = "logger tartarus guest {name} stopping";
        description = "Guest stopping";
      }
    ];
  };
}
```

`guests`/`kinds` are left at their defaults, so the hooks cover every enabled
guest on the host. A host that wants to skip one writes `guests = ["*" "!vpn"]`
on that entry instead of dropping the hook. Because the command runs as the
invoking user, it sees that user's environment and `$HOME`.

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
| `services.clipboardBridge` | bool | `false` | Clipboard bridge: a guest client plus a host server that binds several self-contained listeners — `vsock` guest callback with no TLS, `tcp` guest callback with mTLS, and a same-user Unix admin listener for the local CLI. No shared secret. |
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

## Service modules: `pubkey` (no CA)

The standalone service modules `sudo-auth-proxy`, `ssh-agent-proxy` and
`clipboard-bridge` normally authenticate mTLS peers with a CA (`mtls`). Each
also offers a **no-CA** mode, `pubkey`, where each side presents a self-signed
certificate and whitelists the peer's certificate. The two are mutually
exclusive; `pubkey` forces the effective transport to mTLS, exactly like
`mtls.enable`. The generated TOML keeps the internal `[mtls]` table, but
`ca_file` becomes the concatenation of the whitelisted peer certificates.

```nix
pubkey = {
  certFile = ./server.crt;                 # this side's self-signed cert
  keyFile = "/etc/<service>/server.key";   # private key, never in the store
  trustedPeerCerts = [ ./peer.crt ];       # one or more peer certs (non-empty)
  requiredOid = "1.3.6.1.4.1.99999.N.1";   # optional: this role's OID
  peerOid = "1.3.6.1.4.1.99999.N.2";       # optional: the peer role's OID
};
```

`requiredOid` and `peerOid` default to the same per-role OIDs as `mtls`
(server/client, and the admin OID `…3.3` for the clipboard admin client). The
option is available on `tartarus.sudo-auth-proxy` (client) and `.server.listeners`
/ `.extraServer.listeners`; on `tartarus.ssh-agent-proxy.server.listeners` and
`.bridge`; and on `tartarus.clipboard-bridge.server.listeners`, `.client` and
`.adminClient`. `settings.key`/`settings.rule` on ssh-agent-proxy are an
unrelated SSH-key policy and are not the `pubkey` trust mode.

Generate the material with the `tartarus-certs` tool (no CA is created):

```sh
# server (e.g. athena)
tartarus-certs selfsigned --role server --cn athena \
  --service sudo-auth-proxy \
  --key ~/.config/sudo-auth-proxy/server.key \
  --cert ~/.config/sudo-auth-proxy/server.crt \
  --pub ~/.config/sudo-auth-proxy/server.pub

# client (e.g. zeus)
sudo tartarus-certs selfsigned --role client --cn zeus \
  --service sudo-auth-proxy \
  --key /etc/sudo-auth-proxy/client.key \
  --cert /etc/sudo-auth-proxy/client.crt \
  --pub /etc/sudo-auth-proxy/client.pub
```

`--service` accepts `sudo-auth-proxy`, `ssh-agent-proxy`, `clipboard-bridge`
(or `sudo`/`ssh-agent`/`clipboard`) and `clipboard-admin`. The produced cert is
`CA:FALSE` and carries the standard `serverAuth`/`clientAuth` EKU **plus** the
service OID; the standard EKU is mandatory, because OpenSSL refuses a
self-signed leaf as a trust anchor otherwise (`unsuitable certificate purpose`).
Commit only the public `.crt`/`.pub`; keep `.key` local.

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

## `tartarus.ssh.client.*` (home-manager)

This option set lives in the separate home-manager module
`inputs.tartarus.homeManagerModules."tartarus-ssh"`. It writes the user's SSH
client entries for every enabled guest and includes them from the main SSH
config, so enabling one option is enough:

```nix
imports = [inputs.tartarus.homeManagerModules."tartarus-ssh"];
tartarus.ssh.client.enable = true;
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Generate the guest SSH entries. |
| `configFile` | str | `".ssh/config.d/tartarus"` | Generated fragment path, relative to the home directory. |
| `include` | bool | `true` | Add the fragment to `programs.ssh.includes`. |
| `strictHostKeyChecking` | bool | `true` | Set `StrictHostKeyChecking yes` on guest blocks. |
| `vmVsock` | bool | `true` | Reach VSOCK-enabled VMs through `tartarus proxy` instead of their bridge IP. |
| `containerJumps` | list | `[]` | Explicit `{ name; id; via; }` container entries for Darwin/standalone home-manager. |
| `tartarusUid` | int | host user's uid | UID used for guest-side gpg-agent socket paths. |

The module reads guest data from `osConfig.tartarus.instances`, which exists
when the tartarus host module is imported in the same NixOS/nix-darwin
configuration. It adds the fragment at include order 1100, after the
consumer's generated host files and before an unmanaged custom file.

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

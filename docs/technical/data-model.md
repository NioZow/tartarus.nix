# Data model

## Who this is for

Contributors and operators who need to know exactly what Tartarus stores and how
its identifiers are derived.

## What you'll learn

- the `config.toml` schema and its precedence rules,
- how a guest id becomes an IP, MAC and VSOCK CID,
- the share record and the read-only/snapshot model,
- where per-guest runtime state lives.

## `config.toml`

Rendered by `nix/host/config.nix` at rebuild time to
`$XDG_CONFIG_HOME/tartarus/config.toml` (default
`~/.config/tartarus/config.toml`). It is the only place the CLI learns your
flake path, runtime paths and the enabled guest set. It never points at the
Tartarus repo.

```toml
user = "user"
home = "/home/user"
system = "aarch64-linux"
flake = "/home/user/.config/nixcfg"
state_root = "/home/user/.local/state/tartarus"
ssh_dir = "/home/user/.ssh"
ssh_ca_dir = "/home/user/.local/share/tartarus/ssh"
x509_ca_dir = "/home/user/.local/share/tartarus/x509"
log = false
schema = 2

[proxy]
enable = true
location = "host"
port = 3128
listen_addresses = ["10.200.0.1"]   # resolved by Nix; never loopback
log = false

[[guests]]
name = "vault"
kind = "vm"
id = 3
internet = false
graphical = false
autostart = false
shared_folder = false
container_host = false          # VMs only
requires = []
proxy = { enable = true, allow_hosts = ["example.com"] }
# host = "ch"                   # nested containers only
# [[guests.relays]]             # host relays (Darwin)
# port = 8080
# protocol = "tcp"
```

Key schema points:

- `schema` is `1` (implicit, pre-marker) or `2` (adds `container_host` / `host`).
- `ssh_ca_dir`/`x509_ca_dir` are the **parents** of the `ca` subtrees; the CA
  layout is `<root>/ca/...` and `<root>/machines/...`.
- `[[guests]]` contains only `enable = true` guests, each with its effective
  `id`. Presence there **is** the "enabled on this host" predicate the CLI
  guards on.
- `container_host` appears on VM blocks; `host` appears only on nested
  containers.

### Precedence

`CLI flag > environment variable > config.toml > built-in default`.
Environment variables are `TARTARUS_`-prefixed; `TARTARUS_CONFIG` selects the
TOML file itself. A missing default file is not an error: the loader warns and
falls back to built-in defaults so `tartarus --help` still works.

## Id → network identity

Ids are unique per kind and stable: a forced `id` is used verbatim; the rest are
auto-assigned from 101 over the sorted names, skipping forced and earlier auto
ids (`nix/lib/ids.nix`, mirrored by `src/tartarus`). The CLI derives identity
locally from the id and never runs `nix eval` to locate a guest.

| Kind / platform | IP | VSOCK CID | MAC |
| --- | --- | --- | --- |
| VM, Linux | `10.200.0.<id>` (trs0) | `<id>` | `02:00:00:00:00:<id hex>` |
| VM, macOS | `192.168.64.<id+42>` (vmnet) | — | — |
| Native container | `10.201.0.<id>` (trs1) | — | — |
| Nested container | `10.202.0.<id>` (trs2, VM-local) | — | — |

Bridges: `trs0` VMs, `trs1` native containers, `trs2` nested containers
(VM-local). Host IPs are `.1` on each.

## Shares

A share is a host directory exported into a guest, handed through to
`microvm.shares`. Each entry needs at least `tag`, `source` and `mountPoint`;
`proto` (`9p`/`virtiofs`) defaults to `virtiofs`, is forced to it on macOS, and
is otherwise taken from the share (Linux-only 9p opt-in).

| Field | Meaning |
| --- | --- |
| `tag` | Virtio/9p tag. |
| `source` | Host directory (or store snapshot on macOS read-only). |
| `mountPoint` | Guest mount path. |
| `readOnly` | Enforced by the hypervisor on Linux; a store snapshot on macOS. |
| `snapshot` | Tartarus-only. `false` disables the macOS store copy (use for secrets). |

`readOnly = true` must not be guest-writable: a guest that can write a
host-owned config file gets host code execution the next time the host loads it.
Linux enforces it at the hypervisor; vfkit ignores it, so the engine copies the
source into the read-only Nix store on macOS. Because the store is
world-readable, secret-bearing read-only shares must set `snapshot = false`;
sources under `/nix/store` and `/run` are never copied, and Tartarus's own
key-bearing shares set `snapshot = false`. Full detail in
[Shares and read-only enforcement](./shares.md).

## Service listener schemas

The standalone services each render a TOML config with a `[[listeners]]` array
(one per bound transport), each entry self-contained and carrying its own
`[security]`/`[mtls]` blocks (the server-only `[acl]` is the client's server
pin). There is no `[listener_defaults]` block. The exact schema and generation
rules are pinned in
[Design: multi-transport server listeners](./design/transport-listeners.md),
and the runtime semantics in [ssh-agent-proxy](./ssh-agent-proxy.md) and
[sudo-auth-proxy](./sudo-auth-proxy.md).

## Per-guest runtime state

| What | Where |
| --- | --- |
| Runtime state root | `tartarus.stateRoot` (default `~/.local/state/tartarus`) |
| One guest's state | `<state_root>/<name>/` (pid, cid, console log, overlay, `result`) |
| Container registration | `/etc/nixos-containers/<name>.conf` |
| Guest proxy env | `~/.config/environment.d/10-tartarus.conf` |

## `mkGuests` output shape

```nix
{
  nixosConfigurations = {
    "vm-<name>" = <nixosSystem>;
    "ctn-<name>" = <nixosSystem>;
  };
  packages.<guest-system> = { "vm-<name>" = <microvm runner>; }; # VMs only
  vmIds = { "<name>" = <id>; };
}
```

Only VMs produce a runnable package; containers are built with
`nixos-container create --flake`, which reads `nixosConfigurations` directly.
See [Interfaces](./interfaces.md) for the full contract.

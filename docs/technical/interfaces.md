# Interfaces

## Who this is for

Integrators and contributors who consume Tartarus from another flake or extend
it.

## What you'll learn

- the flake outputs (modules, packages, apps, checks),
- the full `lib.mkGuests` signature and return value,
- the environment variables the engine reads,
- the CLI contract and its generated runtime config.

## Flake outputs

Current flake (`nix/default.nix`), per system in `x86_64-linux`,
`aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`:

| Output | Contents |
| --- | --- |
| `lib.mkGuests` | The build contract (below). |
| `nixosModules.tartarus` | The host module (options, firewall, proxy, CA, launcher). |
| `nixosModules."sudo-auth-proxy"` | PAM client module (same as `...-pam`). |
| `nixosModules."sudo-auth-proxy-pam"` | Explicit alias for the PAM client. |
| `nixosModules."ssh-agent-proxy"` | Host-side server module. |
| `nixosModules."clipboard-bridge"` | Host-side server module. |
| `homeManagerModules."sudo-auth-proxy"` | Server module. |
| `homeManagerModules."ssh-agent-proxy"` | Server/bridge/agent module. |
| `homeManagerModules."clipboard-bridge"` | Server/client/adminClient module. |
| `packages.<system>` | `tartarus`, `sudo-auth-proxy`, `ssh-agent-proxy`, `clipboard-bridge`, `tartarus-certs`. |
| `apps.<system>."tartarus-certs"` | Runnable certificate tool. |
| `checks.<system>` | The eval-level suite plus the sudo-auth-proxy TOML-shape check. |
| `devShells.<system>.default` | `uv` + Python for the CLI. |

## `lib.mkGuests`

```nix
inputs.tartarus.lib.mkGuests {
  inputs ? {};          # your flake inputs; tartarus injects its own
  self ? null;          # your flake self (defaults to tartarus's)
  nixpkgs ? null;       # pinned nixpkgs (defaults to whichever side provided one)
  system ? null;        # guest system; defaults from TARTARUS_SYSTEM / hostSystem
  hostSystem ? builtins.currentSystem;
  config ? {};          # the host's evaluated config (tartarus.guests / tartarus.proxy)
  username ? "user";
  homeDir ? null;       # defaults from $HOME
  overlays ? [];
  pkgs ? null;          # already-overlaid guest pkgs (wins over nixpkgs)
  hostPkgs ? null;
}
```

Returns:

```nix
{
  nixosConfigurations = {
    "vm-<name>" = <nixosSystem>;   # kind = "vm"
    "ctn-<name>" = <nixosSystem>;  # kind = "container"
  };
  packages.<guest-system> = { "vm-<name>" = <microvm runner>; };  # VMs only
  vmIds = { "<name>" = <id>; };    # effective ids
}
```

Behaviour: filters to `enable = true` guests, assigns effective ids, builds one
system per guest, and returns the `vmIds` map. `pkgs`/`overlays`/`hostPkgs`
control the package set; when `pkgs` is absent it imports nixpkgs with
`allowUnfree = true`.

## Environment variables

The engine reads these through `builtins.getEnv`, which is why evaluation must
be `--impure`. They are the per-invocation (instance/shares) interface: the
same flake attribute can produce a differently-configured instance per
invocation.

| Variable | Effect |
| --- | --- |
| `MICROVM_INSTANCE_SUFFIX` | Suffix for numbered `vm spawn` instances. |
| `MICROVM_ID_OVERRIDE` | Forced id/CID for a numbered VM instance. |
| `MICROVM_EXTRA_SHARES` | JSON list of ad-hoc `vm start --mount` shares. |
| `CONTAINER_INSTANCE_SUFFIX` | Same as `MICROVM_INSTANCE_SUFFIX`, for containers. |
| `CONTAINER_ID_OVERRIDE` | Same as `MICROVM_ID_OVERRIDE`, for containers. |
| `TARTARUS_HOST_UID` | Invoking host uid (virtiofs ownership). |
| `TARTARUS_SYSTEM` | Default guest system when `system` is not passed. |
| `TARTARUS_MOUNT_ROOT` | Absolute host staging root for a VM instance's runtime mounts; defaults to `<home>/.local/state/tartarus/<name>/mounts`. |
| `HOME` | Invoking host home (share sources, pubkey). |

## CLI contract

`packages.<system>.tartarus` (`tartarus.cli:main`). The CLI builds VMs with
`nix build <user-flake>#packages.<system>.vm-<name> --impure` and containers
with `nixos-container create <name> --flake <user-flake>#ctn-<name>`. Runtime
configuration lives in `~/.config/tartarus/config.toml`.

```
tartarus list [-c|--container] [-t|--tree] [--vm] [--json]
tartarus status [name]
tartarus start <name> [-u|--upgrade] [--mount HOST:GUEST]
tartarus build <name> [-u|--upgrade] [--mount HOST:GUEST]
tartarus spawn <template> [--name N] [-u|--upgrade]
tartarus stop <name> [--purge] [-d|--debug]
tartarus restart <name> [-u|--upgrade] [-d|--debug]
tartarus mount <guest> HOST:GUEST [-r|--read-only|--overlay] [--no-idmap]
tartarus unmount <guest> GUEST        # alias: umount
tartarus mounts [guest] [--json]
tartarus logs <name>
tartarus ssh <name> [-s|--start] [-r|--retry N] [--retry-delay SECONDS]
tartarus cid <name>          # MicroVM only
tartarus ip <name>
tartarus proxy <name>        # MicroVM only (ProxyCommand)
tartarus proxy-ip <name>     # MicroVM only (vmnet, macOS)
```

Global flags: `-c/--container` (tri-state: force container, or infer from
`config.toml`), `--config PATH`, `--flake PATH`, `--user NAME`, `--system
SYSTEM`, `--state-root PATH`, `--log/--no-log`.

- `list` spans both kinds; `--vm` and `-c` narrow it. `-t` nests nested
  containers under their host VM (`--json` mirrors this with `children`).
- Commands that name one guest infer its kind from `config.toml`.
- `cid`/`proxy`/`proxy-ip` are MicroVM-only and error under `--container`.
- Every named-guest command passes the enabled-guest guard before acting.
- `mount`, `unmount`/`umount` and `mounts` are handled before
  `flake.require_flake`: they need no user-flake evaluation, but named variants
  still run the enabled-guest guard.

Runtime mounts are recorded per guest in
`<state_root>/<name>/runtime-mounts.json`, written atomically (temp file plus
`os.replace`) and removed on unmount, stop, restart and `--purge`:

| Key | Meaning |
| --- | --- |
| `id` | Opaque staging id (`[A-Za-z0-9_-]+`). |
| `kind` | `"vm"` or `"container"`. |
| `source` | Resolved host directory. |
| `target` | Absolute guest mount point. |
| `mode` | `"rw"`, `"ro"` or `"overlay"`. |
| `stage` | Host staging dir (VM) or container-side `/run/tartarus-mount/staging/<id>`. |

## Invariants and assertions

The host module asserts (evaluation errors) that:

- `internet` and `proxy.enable` are not both true;
- `proxy.enable` implies the global `tartarus.proxy.enable`;
- `tartarus.proxy.location` is `"host"` or an enabled guest with `internet`;
- `tartarus.dns.location` names an enabled guest;
- `firewall.location = "host"` only on Linux;
- static ids are unique per kind and in 3–100;
- `requires` entries exist and are acyclic;
- `host`/`vm.containerHost`/`privateUsers`/`vmOnly` are used on the right kind;
- on Darwin, a container without `host` is rejected;
- a nested container does not set `relays`, a host `services.*` integration or
  `proxy.enable`.

The full predicates live in `nix/host/default.nix` (exposed for tests as
`tartarus.internalAssertions`).

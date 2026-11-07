# Interfaces

## Who this is for

Integrators and contributors who consume Tartarus from another flake or extend
it.

## What you'll learn

- the flake outputs (modules, packages, apps, checks),
- the full `lib.mkGuests` signature and return value,
- the lifecycle hook contract (`tartarus.hooks`, `hooks.toml`, the Python
  engine) and which operation fires which event,
- the environment variables the engine reads,
- the CLI contract and its generated runtime config.

## Flake outputs

Current flake (`nix/default.nix`), per system in `x86_64-linux`,
`aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`:

| Output | Contents |
| --- | --- |
| `lib.mkGuests` | The build contract (below). |
| `lib.sshConfig` | `{ mkBlock, mkFile }` OpenSSH config renderer used by `tartarus-ssh` and reusable by consumers. |
| `lib.sshForwardWrapper` | `{ mkHostCase, mkForwardWrapper }` `RemoteForward`/`SetEnv` SSH wrapper builder used by the proxy integrations. |
| `nixosModules.tartarus` | The host module (options, firewall, proxy, CA, launcher). |
| `nixosModules."sudo-auth-proxy"` | PAM client module (same as `...-pam`). |
| `nixosModules."sudo-auth-proxy-pam"` | Explicit alias for the PAM client. |
| `nixosModules."ssh-agent-proxy"` | Host-side server module. |
| `nixosModules."clipboard-bridge"` | Host-side server module (multi-listener, per-listener security). |
| `homeManagerModules."sudo-auth-proxy"` | Server module. |
| `homeManagerModules."ssh-agent-proxy"` | Server/bridge/agent module. |
| `homeManagerModules."clipboard-bridge"` | Server/client/adminClient module; the server binds multiple self-contained listeners (guest `vsock`/`tcp` plus the same-user Unix admin listener), each with its own `security`/`mtls`/`resolution`. |
| `homeManagerModules."tartarus-ssh"` | Guest SSH client config (`tartarus.ssh.client.*`). |
| `packages.<system>` | `tartarus`, `sudo-auth-proxy`, `ssh-agent-proxy`, `clipboard-bridge`, `tartarus-certs`. |
| `apps.<system>."tartarus-certs"` | Runnable certificate tool (`init-ca`, `issue-server`, `issue-client`, `issue-admin`). |
| `checks.<system>` | The eval-level suite plus the sudo-auth-proxy TOML-shape check. |
| `devShells.<system>.default` | `uv` + Python for the CLI. |

## `lib.sshConfig`

The shared OpenSSH config renderer (`nix/lib/ssh-config.nix`):

- `mkBlock host attrs` renders a `Host <host>` block, mapping booleans to
  `yes`/`no` and lists to repeated directives.
- `mkFile header blocks` joins blocks under a managed-by header.

`tartarus-ssh` uses it for `~/.ssh/config.d/tartarus`; consumers can use it for
their own static host files (nixcfg renders `hosts`, `olympus`, `pwncollege`
and `synacktiv` this way).

## `lib.sshForwardWrapper`

`mkForwardWrapper pkgs name opts` builds the wrapper installed as
`sudo-auth-proxy-ssh` / `ssh-agent-proxy-ssh` (and optionally as `ssh` when
`shadowSsh = true`). It resolves the destination with `ssh -G`, adds an
unpredictable per-session token to the guest socket, and execs the real ssh
with `RemoteForward` + `SetEnv`. `opts` carries `hosts`, `hostSocket`,
`remoteSocket` and `envVar`.

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
tartarus list [-c|--container] [-t|--tree] [--vm] [--json]   # alias: ls
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
tartarus ca ensure <name>    # provision a guest's CA material
tartarus ca admin            # optional clipboard admin certificate
```

Global flags: `-c/--container` (tri-state: force container, or infer from
`config.toml`), `--config PATH`, `--hooks PATH`, `--flake PATH`, `--user NAME`,
`--system SYSTEM`, `--state-root PATH`, `--log/--no-log`.

- `--hooks PATH` selects the lifecycle-hook file. Precedence: the flag, then
  the `TARTARUS_HOOKS` environment variable, then `hooks.toml` next to the
  effective `config.toml` (`--config /elsewhere/config.toml` reads
  `/elsewhere/hooks.toml`; the default is `~/.config/tartarus/hooks.toml`).
  A missing default file is silent; an explicitly named missing file is a
  `TartarusError`. The resolved path is printed by `tartarus --help`.
- `list` (alias `ls`) spans both kinds; `--vm` and `-c` narrow it. `-t` nests nested
  containers under their host VM (`--json` mirrors this with `children`).
- Commands that name one guest infer its kind from `config.toml`.
- `cid`/`proxy`/`proxy-ip` are MicroVM-only and error under `--container`.
- `ca ensure` materialises a guest's CA files without starting it; `ca admin`
  mints the **optional** clipboard admin certificate (admin EKU
  `1.3.6.1.4.1.99999.3.3`) and takes no guest — the default clipboard admin path
  is the same-user Unix socket and needs no certificate.
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

## Lifecycle hooks

### Options

| Option | Type | Default |
| --- | --- | --- |
| `tartarus.hooks` | `hooksType` (event → phase → list of `hookType`) | `{}` |
| `tartarus.guests.<name>.hooks` | `hooksType` | `{}` |

`hooksType` (in `nix/lib/types.nix`) declares `create`, `start`, `stop`,
`remove` and `build`, each a submodule with `before` and `after` lists
(default `[]`). One entry (`hookType`):

| Field | Type | Default |
| --- | --- | --- |
| `command` | `types.str` | — (required) |
| `guests` | `listOf str` | `["*"]` |
| `kinds` | `listOf (enum ["vm" "container"])` | `["vm" "container"]` |
| `timeout` | `ints.positive` | `30` |
| `retries` | `ints.unsigned` | `0` |
| `retryDelay` | `numbers.nonnegative` | `2.0` |
| `onFailure` | `enum ["warn" "abort"]` | `"warn"` |
| `description` | `nullOr str` | `null` |

Per-guest entries are sugar: the renderer forces `guests = ["<name>"]` and
`kinds = ["<kind>"]`, so the per-guest scope wins over any `guests`/`kinds`
written there. The plain guest record in `tartarus.instances.guests.<name>`
carries the same data as `hooks`, for consumers that must not force the
`tartarus.guests` submodule.

### Python API (`src/tartarus/hooks.py`)

The module is a leaf: it imports neither the action modules nor `config` at
runtime (only `errors` and `output`), and takes `Config` behind
`TYPE_CHECKING`.

```python
EVENTS = ("create", "start", "stop", "remove", "build")
PHASES = ("before", "after")
KINDS = ("vm", "container")
ON_FAILURE = ("warn", "abort")
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRY_DELAY = 2.0

@dataclass(frozen=True)
class Hook:
    event: str
    phase: str
    command: str
    guests: list[str] = ["*"]
    kinds: list[str] = ["vm", "container"]
    timeout: float = 30.0
    retries: int = 0
    retry_delay: float = 2.0
    on_failure: str = "warn"
    description: str | None = None

    def matches(self, name: str, template: str, kind: str) -> bool: ...

def substitute(command: str, values: dict[str, str]) -> str: ...
def load_hooks(path: Path) -> list[Hook]: ...
def run_hooks(config, event, phase, name, *,
              template, kind, guest_id=None) -> None: ...
```

Guarantees:

- `Hook.matches` returns `False` immediately when `kind not in kinds`. It
  splits `guests` into `!`-prefixed exclusions and positives; any exclusion
  matching **either** `name` or `template` (via `fnmatch.fnmatchcase`) rejects
  the guest, then any positive matching either accepts it. No positive pattern
  means no match, so `[]` (and a lone `["!vpn"]`) matches nothing.
- `substitute` is a plain `str.replace` of `{key}` for each key of `values`,
  never `str.format`, so other shell braces survive.
- `load_hooks` returns hooks in file order; a missing file is `[]`; malformed
  TOML, a non-list `hooks` key, a field of the wrong type, an unknown
  `event`/`phase`/`kind`/`on_failure`, a non-positive `timeout`, a negative
  `retries`/`retry_delay` or an empty `command` raise `TartarusError`. A
  `schema` above `1` only warns.
- `run_hooks` asks `config.hooks_for(event, phase, name, template=...,
  kind=...)`, returning early when none match. For each hook it substitutes
  `name`, `template`, `kind`, `id` (`""` when `guest_id is None`), `event` and
  `phase`, exports them as `TARTARUS_GUEST`, `TARTARUS_TEMPLATE`,
  `TARTARUS_KIND`, `TARTARUS_GUEST_ID`, `TARTARUS_EVENT` and `TARTARUS_PHASE`,
  logs `hook <event>.<phase>: <description or command>` with `info` when
  `config.log` is set, and runs `/bin/sh -c <command>` with the inherited
  stdout/stderr and `cwd = config.home_dir`. Attempts are `retries + 1` with
  `time.sleep(retry_delay)` between them and `timeout` per attempt (a timeout
  counts as a failed attempt; the last attempt's outcome is reported).
  `on_failure = "abort"` raises `TartarusError`, `"warn"` calls `warn`.
- `Config.hooks_for(event, phase, name, *, template, kind) -> list[Hook]`
  filters `Config.hooks` on event/phase and `Hook.matches`, preserving order.

### Call sites

`action_*` in `src/tartarus/vm.py` and `src/tartarus/ctn.py`:

| Function | Hooks fired |
| --- | --- |
| `vm.action_build` | `build.before` → build → `build.after` (no id on `before`). |
| `vm.action_start` | `start.before` after the already-running guard, → launch + relays → `start.after` (with cid). |
| `vm.action_spawn` | `create.before` → `action_start` (its `start` pair) → `create.after`. |
| `vm.action_stop` | `stop.before`/`stop.after` only when it was running; `remove.before` → purge → `remove.after` under `--purge`, running or not. |
| `vm.action_restart` | None directly: composes `action_stop` then `action_start`. |
| `ctn.action_start` | Nested container: `start.before`/`start.after` around the unit start, after the already-running guard. Ad-hoc instance (`name != base`, not registered): `create.before` → `start.before` → `nixos-container create --auto-start` → `start.after` → `create.after`. Otherwise `start.before` → `systemctl start container@<name>` → `start.after`. |
| `ctn.action_spawn` | Same create+start order as the ad-hoc path above, around `_create_adhoc`. |
| `ctn.action_build` | `build.before` → build → `build.after`; a **nested** container brackets the delegated `vm.action_build` on its container-host VM (which fires that VM's own `build` pair). |
| `ctn.action_stop` | `stop.before`/`stop.after` only when it was running; `remove.before` → `nixos-container destroy` → `remove.after` under `--purge`. |
| `ctn.action_restart` | None directly: composes `action_stop` then `action_start` (nested containers too). |

`create_adhoc`/`_create_adhoc` fire no hooks; every caller brackets them.
No-op transitions (already running / already stopped, or a nested stop while
the host VM is down) fire nothing. Nested containers that auto-start inside
their container-host VM during the VM boot are not started through the CLI, so
their `start.after` does not fire then.

### Renderer contract

`nix/host/hooks.nix` must produce exactly what `src/tartarus/hooks.py` parses:
`[[hooks]]` tables with the keys `event`, `phase`, `command`, `guests`,
`kinds`, `timeout` (float), `retries`, `retry_delay` (float), `on_failure` and
an optional `description`, under `schema = 1`, in the explicit event/phase
order with host-wide entries before per-guest ones. `EVENTS`/`PHASES`/`KINDS`
in `hooks.py` and the matrix in `types.nix`/`hooks.nix` must stay in step; a
value outside them is rejected rather than ignored.

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

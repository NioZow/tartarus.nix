# Cheatsheet

## Who this is for

Returning users who know the model and want the essentials on one page.

## What you'll learn

- the minimal flake wiring and the most-used options,
- the everyday CLI commands,
- the common failures and their fixes.

## Minimal wiring

```nix
# inputs
inputs.tartarus.url = "github:niozow/tartarus.nix";

# host module
imports = [ inputs.tartarus.nixosModules.tartarus ];
tartarus.guests.vault.enable = true;

# flake outputs (build contract)
guests = inputs.tartarus.lib.mkGuests {
  inherit inputs nixpkgs;
  system = "aarch64-linux";
  config = self.nixosConfigurations.myhost.config;
  username = "user";
};
```

Rebuild with `--impure`; then `tartarus list`.

## Options at a glance

```nix
tartarus.proxy.enable = true;           # global proxy transport
tartarus.proxy.location = "host";       # or a guest name

tartarus.ssh.retries = 5;               # ssh connection retries
tartarus.ssh.retryDelay = 2.0;          # seconds between retries

tartarus.guests.vault = {
  enable = true;                        # makes the guest exist at all
  kind = "vm";                          # or "container"
  id = 3;                               # 3-100; auto from 101 if omitted
  internet = true;                      # XOR proxy.enable
  graphical = false;
  autostart = false;
  requires = [ "db" ];                  # start dependencies first
  sharedFolder = true;                  # host dir at ~/shared
  proxy = { enable = false; allowHosts = [ ".example.com" ]; };
  services.sshAgentProxy = true;        # + clipboardBridge / sudoAuthProxy
  vm.mem = 1024;                        # or "host"
  vm.vcpu = 2;
  vm.persistentHome.enable = true;
  firewall = { enable = true; location = "guest"; };
  systemConfig = { /* NixOS */ };
  userConfig = { /* home-manager */ };
};

tartarus.containers.containerHost = "ch";        # Darwin: nest containers
tartarus.containers.sudoNoPassword.enable = true; # no sudo prompt on start/stop

# Lifecycle hooks: run after a start / before a stop, for every guest
tartarus.hooks.start.after = [{ command = "rex-tunnel up {name}"; retries = 15; }];
tartarus.hooks.stop.before = [{ command = "rex-tunnel down {name}"; }];
#                     per guest: only this guest's own instances fire it
tartarus.guests.vault.hooks.start.after = [{ command = "notify-send {name}"; }];
```

## Commands

```bash
tartarus list [-c|--vm] [-t] [--json]   # alias: ls
tartarus status [name]
tartarus start <name> [-u] [--mount HOST:GUEST]
tartarus build <name> [-u]
tartarus spawn <template> [--name N]
tartarus stop <name> [--purge]
tartarus restart <name> [-u]
tartarus mount <guest> HOST:GUEST [-r|--read-only|--overlay] [--no-idmap]
tartarus unmount <guest> GUEST        # alias: umount
tartarus mounts [guest] [--json]
tartarus logs <name>
tartarus ssh <name> [-s] [-r N] [--retry-delay SECONDS]
tartarus cid <name>          # MicroVM only
tartarus ip <name>
tartarus proxy <name>        # MicroVM only (ProxyCommand)
tartarus proxy-ip <name>     # MicroVM only (vmnet, macOS)

tartarus --container <cmd> <name>   # force the container path
```

Global flags (before the command): `-c/--container`, `--config PATH`,
`--hooks PATH`. Hook examples:

```nix
# after a start, retry until the guest answers (15 × 2 s, 20 s per attempt)
tartarus.hooks.start.after = [{ command = "rex-tunnel up {name}"; timeout = 20; retries = 15; }];
# before a stop, for one guest only (guests/kinds are forced to it)
tartarus.guests.vault.hooks.stop.before = [{ command = "rex-tunnel down {name}"; }];
```

## Lifecycle hooks

`tartarus.hooks.<event>.<phase>` (host-wide) and
`tartarus.guests.<name>.hooks.<event>.<phase>` (per guest), with events
`create`, `start`, `stop`, `remove`, `build` and phases `before`/`after`.
Tokens: `{name} {template} {kind} {id} {event} {phase}` (also `TARTARUS_*` env
vars). Defaults: `guests = ["*"]`, `kinds = ["vm" "container"]`, `timeout = 30`,
`retries = 0`, `retryDelay = 2.0`, `onFailure = "warn"`. Rendered to
`~/.config/tartarus/hooks.toml`; override the file with `--hooks PATH` or
`TARTARUS_HOOKS`.

## Common failures

| Message / symptom | Fix |
| --- | --- |
| `guest "X" is not enabled on this host` | Set `tartarus.guests.X.enable = true` and rebuild. |
| Config missing / `tartarus list` empty | Rebuild the host; confirm `~/.config/tartarus/config.toml` exists. |
| Flake evaluated without `--impure` | Add `--impure` (the contract reads `builtins.getEnv`). |
| Build seems stale after editing the flake | Re-run with `-u/--upgrade`. |
| `kind = "container"` refused on Darwin | Set `host` (or `tartarus.containers.containerHost`) to a container-host VM. |
| `internet = true` and `proxy.enable = true` | Pick one; they are mutually exclusive. |
| Runtime mount refused on macOS / for a nested container | Use a Linux VM or a native container; macOS/vfkit and nested containers are unsupported. |
| "helper or staging share missing" on `tartarus mount` | Rebuild and restart the VM once: `tartarus restart <name> -u`. |
| `tartarus mounts` shows a stale entry after a host reboot | `tartarus unmount <guest> <target>` clears the record (the host bind is already gone). |

## Paths

| What | Where |
| --- | --- |
| Generated CLI config | `~/.config/tartarus/config.toml` (schema 2) |
| Generated lifecycle hooks | `~/.config/tartarus/hooks.toml` (schema 1) |
| Per-guest runtime state | `~/.local/state/tartarus/<name>/` |
| Container registration | `/etc/nixos-containers/<name>.conf` |
| Guest proxy env | `~/.config/environment.d/10-tartarus.conf` |

More: [Usage](./usage.md) · [Configuration](./configuration.md) ·
[Getting started](./getting-started.md).

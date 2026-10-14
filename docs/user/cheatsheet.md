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
```

## Commands

```bash
tartarus list [-c|--vm] [-t] [--json]
tartarus status [name]
tartarus start <name> [-u] [--mount HOST:GUEST]
tartarus build <name> [-u]
tartarus spawn <template> [--name N]
tartarus stop <name> [--purge]
tartarus restart <name> [-u]
tartarus logs <name>
tartarus ssh <name> [-s]
tartarus cid <name>          # MicroVM only
tartarus ip <name>
tartarus proxy <name>        # MicroVM only (ProxyCommand)
tartarus proxy-ip <name>     # MicroVM only (vmnet, macOS)

tartarus --container <cmd> <name>   # force the container path
```

## Common failures

| Message / symptom | Fix |
| --- | --- |
| `guest "X" is not enabled on this host` | Set `tartarus.guests.X.enable = true` and rebuild. |
| Config missing / `tartarus list` empty | Rebuild the host; confirm `~/.config/tartarus/config.toml` exists. |
| Flake evaluated without `--impure` | Add `--impure` (the contract reads `builtins.getEnv`). |
| Build seems stale after editing the flake | Re-run with `-u/--upgrade`. |
| `kind = "container"` refused on Darwin | Set `host` (or `tartarus.containers.containerHost`) to a container-host VM. |
| `internet = true` and `proxy.enable = true` | Pick one; they are mutually exclusive. |

## Paths

| What | Where |
| --- | --- |
| Generated CLI config | `~/.config/tartarus/config.toml` |
| Per-guest runtime state | `~/.local/state/tartarus/<name>/` |
| Container registration | `/etc/nixos-containers/<name>.conf` |
| Guest proxy env | `~/.config/environment.d/10-tartarus.conf` |

More: [Usage](./usage.md) · [Configuration](./configuration.md) ·
[Getting started](./getting-started.md).

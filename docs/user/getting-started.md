# Getting started

## Who this is for

Users who have [installed Tartarus](./installation.md) and want to boot and
connect to a first guest.

## What you'll learn

- how to declare a minimal VM guest and a minimal container guest,
- how to list, start, inspect, enter and stop them,
- where the generated runtime config lives.

This walkthrough assumes the host flake is at `~/.config/nixcfg`, the host is
`myhost`, and your user is `user`. Substitute your own names.

## 1. Declare a guest

Add a guest to the host configuration (the module that imports
`inputs.tartarus.nixosModules.tartarus`):

```nix
{ pkgs, ... }: {
  tartarus.guests.vault = {
    enable = true;
    kind = "vm";
    internet = true;
    systemConfig = {
      environment.systemPackages = with pkgs; [ git curl ];
      users.users.user = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
      };
    };
  };
}
```

Only `enable = true` makes the guest part of the host: it adds the guest's
`vm-<name>` output, a host firewall rule, a CA certificate entry and a
`config.toml` entry. It does **not** build anything yet — builds stay lazy.

## 2. Rebuild the host

```bash
sudo nixos-rebuild switch --flake ~/.config/nixcfg#myhost --impure
```

At the end of the rebuild Tartarus writes `~/.config/tartarus/config.toml`:

```toml
user = "user"
home = "/home/user"
system = "x86_64-linux"
flake = "/home/user/.config/nixcfg"
# ...

[[guests]]
name = "vault"
kind = "vm"
id = 3
internet = true
# ...
proxy = { enable = false, allow_hosts = [] }
```

## 3. List guests

```bash
tartarus list
```

Every enabled guest appears, with its kind and running state. Add `--vm` or
`--container` (or `-c`) to narrow the list, and `-t/--tree` to nest nested
containers under their container-host VM.

## 4. Start it

```bash
tartarus start vault
```

`start` builds the guest if needed and launches it in the background. The first
start realises the guest closure, so it can take a while; later starts reuse the
existing build unless you pass `-u/--upgrade`.

Check it is up:

```bash
tartarus status vault
```

## 5. Connect

```bash
tartarus ssh vault
```

The host's CA signs the guest's SSH host key, so this connects with no
fingerprint prompt. If the guest is not running, add `-s/--start` to boot it
first:

```bash
tartarus ssh vault -s
```

For a VM, `tartarus cid`, `tartarus ip`, `tartarus proxy` and
`tartarus proxy-ip` report the VSOCK CID and host-reachable IP and power the
SSH `ProxyCommand`.

## 6. Watch and stop

```bash
tartarus logs vault     # console log (VMs) / journal (containers)
tartarus stop vault     # graceful shutdown
```

`tartarus stop --purge vault` also wipes the instance's state (for a VM, its
state directory; for a container, its `nixos-container` registration).

## 7. Add a container

The same shape, with `kind = "container"`:

```nix
{ pkgs, ... }: {
  tartarus.guests.box = {
    enable = true;
    kind = "container";
    internet = true;
    systemConfig = {
      environment.systemPackages = with pkgs; [ htop ];
    };
  };
}
```

Rebuild, then use the container commands. `--container` goes **before** the
subcommand:

```bash
tartarus --container start box
tartarus --container ssh box
tartarus --container stop box
```

On Linux the container runs natively on the host kernel. On macOS it runs
nested inside a container-host VM — see [container-host
VMs](../technical/container-host.md) and the `host` /
`tartarus.containers.containerHost` options.

## Where to go next

- [Usage](./usage.md) — the full CLI and common workflows.
- [Configuration](./configuration.md) — every option with defaults.
- [Cheatsheet](./cheatsheet.md) — the one-page reference.

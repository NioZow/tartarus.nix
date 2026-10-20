# Installation

## Who this is for

Users adding Tartarus to a NixOS or nix-darwin host for the first time.

## What you'll learn

- the prerequisites for each platform,
- how to add the flake input and import the host module,
- how to satisfy Tartarus's build contract in your own flake,
- what gets generated at rebuild time and how to run the CLI.

## Prerequisites

- Nix with flakes enabled, evaluated with `--impure` (see below).
- A host configuration built from a flake — NixOS or nix-darwin.
- `home-manager` on the host: Tartarus writes the CLI's `config.toml` through
  home-manager. Without it the CLI falls back to built-in defaults and warns.

Platform-specific:

- **Linux** — QEMU/KVM for VMs (your user must be able to use `/dev/kvm`) and
  `systemd-nspawn` for containers, both provided by the host module. When an
  enabled VM uses a vsock-backed host service (`sudo-auth-proxy`,
  `ssh-agent-proxy`, `clipboard-bridge`), the host module loads `vhost_vsock`
  at boot. Using those services standalone (without the host module) requires
  loading it yourself: `boot.kernelModules = [ "vhost_vsock" ];` on NixOS, or
  `modprobe vhost_vsock` (see the Debian notes below).
- **macOS** — vfkit for VMs and `nix.linux-builder` to build the Linux guest
  closures. Tartarus enables the Linux builder by default on Darwin.

### Why `--impure`?

The build contract reads a few environment variables through
`builtins.getEnv` (the instance suffix, ad-hoc shares, the invoking uid/home).
That is deliberate: the *same* flake attribute can produce a
differently-configured instance per invocation. Evaluate your flake with
`--impure` wherever Tartarus is involved.

## Add the input

```nix
# flake.nix (your host's flake)
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    tartarus.url = "github:niozow/tartarus.nix";
    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # ...
  };
}
```

## Import the host module and declare guests

Tartarus ships a single host module, `nixosModules.tartarus`, that brings in
the option surface, firewall, proxy, CA, launcher and autostart. Import it and
declare a guest:

```nix
# host configuration module
{ inputs, ... }: {
  imports = [ inputs.tartarus.nixosModules.tartarus ];

  tartarus.guests.vault = {
    enable = true;
    kind = "vm";          # or "container"
    internet = true;
    systemConfig = {
      # any NixOS configuration; this is what makes the guest useful
      environment.systemPackages = with pkgs; [ git curl ];
      users.users.user = { isNormalUser = true; extraGroups = [ "wheel" ]; };
    };
  };
}
```

See the [configuration reference](./configuration.md) for every option.

## Satisfy the build contract

Guests are built by **your** flake, so your flake must extend its outputs with
Tartarus's `mkGuests`. It reads `tartarus.guests.*` / `tartarus.proxy` from an
already-evaluated host config and returns `nixosConfigurations`, the VM runner
`packages`, and the stable `vmIds` map:

```nix
# flake.nix outputs
{
  inputs,
  self,
  nixpkgs,
  ...
}: let
  guests = inputs.tartarus.lib.mkGuests {
    inherit inputs nixpkgs;
    system = "aarch64-linux";                 # guest system (Apple silicon)
    hostSystem = builtins.currentSystem;      # builder system
    config = self.nixosConfigurations.myhost.config;
    username = "user";
  };
in {
  nixosConfigurations = self.nixosConfigurations // guests.nixosConfigurations;
  packages.<system> = basePackages // guests.packages.<system>;
  inherit (guests) vmIds;
}
```

`mkGuests` returns:

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

`mkGuests` takes `inputs`/`self` (optional — Tartarus injects its own),
`nixpkgs`, `system`, `hostSystem`, `config`, `username`, `homeDir`, `overlays`,
`pkgs` and `hostPkgs`. It defaults `system` from `TARTARUS_SYSTEM`/`hostSystem`,
`homeDir` from `HOME`, and imports nixpkgs with `allowUnfree` when no `pkgs` is
given. Full details are in the [interfaces reference](../technical/interfaces.md).

## Rebuild

Rebuild the host the usual way (`nixos-rebuild switch --flake .#myhost --impure`,
`darwin-rebuild switch ...`, or your `just`/wrapper of choice). At rebuild time
Tartarus renders `~/.config/tartarus/config.toml` — the only place the CLI
learns your flake path, runtime paths, and the enabled guest set.

## Run the CLI

The CLI is `packages.<system>.tartarus`:

```bash
nix run .#tartarus -- list      # from your flake
# or install packages.<system>.tartarus on the host
```

Verify with `tartarus --help` and `tartarus list`. If `tartarus list` is empty
or complains the config is missing, rebuild the host and confirm
`~/.config/tartarus/config.toml` exists.

## Optional: the standalone services

`sudo-auth-proxy`, `ssh-agent-proxy` and `clipboard-bridge` are also shipped as
packages and as self-contained NixOS **and** home-manager modules. They need
only their own `tartarus.<service>.*` options and can be used with no guest, no
VM and no host module at all. See their deep-dive docs and the ready-to-edit
files in [`examples/`](../../examples).

The `homeManagerModules."tartarus-ssh"` module is the client-side counterpart
for hosts that run guests: enable `tartarus.ssh.client.enable = true` and it
writes `~/.ssh/config.d/tartarus`, then adds that file to
`programs.ssh.includes`. It needs `osConfig.tartarus.instances` (so it is most
useful in a NixOS/nix-darwin home-manager configuration); standalone
home-manager can still use `tartarus.ssh.client.containerJumps` for explicit
container entries.

### Debian (and other non-NixOS hosts)

A `vsock` listener binds the host CID 2 and needs the `vhost_vsock` kernel
module; without it the service exits with `Errno 99` (`EADDRNOTAVAIL`) until a
VM happens to load the module. Load it now and persist it across reboots:

```sh
sudo modprobe vhost_vsock
printf 'vhost_vsock\n' | sudo tee /etc/modules-load.d/vhost_vsock.conf
```

`modinfo vhost_vsock` must find the module for the running kernel; if it does
not, install the matching kernel package for that kernel. Then restart the
service, for example `systemctl --user restart ssh-agent-proxy`.

Next: [run your first guest](./getting-started.md), or read the full
[configuration reference](./configuration.md).

# The build contract (PLAN.md §3.8): expand a host's `tartarus.guests.*` /
# `tartarus.proxy` into `nixosConfigurations`, VM runner `packages`, and the
# stable `vmIds` map.
#
# It is called from the *consumer's* flake outputs so the consumer's overlays,
# packages and secrets are in scope, while the engine itself stays tartarus's:
#
#   let
#     guests = tartarus.lib.mkGuests {
#       inherit inputs nixpkgs;                 # caller inputs + pinned nixpkgs
#       system = "aarch64-linux";
#       hostSystem = builtins.currentSystem;
#       config = self.nixosConfigurations.<host>.config;
#       username = "..."; homeDir = "...";
#     };
#   in {
#     nixosConfigurations = base // guests.nixosConfigurations;
#     packages.<system> = base // guests.packages.<system>;
#     inherit (guests) vmIds;
#   }
#
# `nix/default.nix` always injects `tartarusInputs`/`tartarusSelf` so a caller
# only needs to override what differs; caller-provided `inputs`/`self` win.
{
  # Tartarus's own flake inputs (always injected) and the caller's (may be {}).
  tartarusInputs ? {},
  tartarusSelf ? null,
  inputs ? {},
  self ? tartarusSelf,
  # Pinned nixpkgs. Defaults to whichever side provided one.
  nixpkgs ? null,
  # Guest system (aarch64-linux on Apple Silicon) and the host it is built from.
  system ? null,
  hostSystem ? builtins.currentSystem,
  # The host's evaluated config, exposing `tartarus.guests` / `tartarus.proxy`.
  config ? {},
  username ? "user",
  homeDir ? null,
  # Package-set inputs. `pkgs` (already overlaid) wins; otherwise nixpkgs is
  # imported for the guest system with `overlays` and allowUnfree.
  overlays ? [],
  pkgs ? null,
  hostPkgs ? null,
}: let
  allInputs = tartarusInputs // inputs;
  nixpkgs' =
    if nixpkgs != null
    then nixpkgs
    else allInputs.nixpkgs;
  lib = nixpkgs'.lib;
  ids = import ./ids.nix {inherit lib;};
  names = import ./names.nix {inherit lib;};
  nixVersion = import ../../lib/version.nix;

  resolvedSelf =
    if self != null
    then self
    else allInputs.self or null;

  # Same auto-detection the old flake used, kept here so `system` is optional.
  resolvedSystem =
    if system != null
    then system
    else let
      envSystem = builtins.getEnv "TARTARUS_SYSTEM";
    in
      if envSystem != ""
      then envSystem
      else if hostSystem == "aarch64-darwin"
      then "aarch64-linux"
      else if hostSystem == "x86_64-darwin"
      then "x86_64-linux"
      else hostSystem;

  resolvedHomeDir =
    if homeDir != null
    then homeDir
    else let
      envHome = builtins.getEnv "HOME";
    in
      if envHome != ""
      then envHome
      else "/home/${username}";

  guestPkgs =
    if pkgs != null
    then pkgs
    else
      import nixpkgs' {
        system = resolvedSystem;
        inherit overlays;
        config.allowUnfree = true;
      };

  resolvedHostPkgs =
    if hostPkgs != null
    then hostPkgs
    else
      import nixpkgs' {
        system = hostSystem;
        inherit overlays;
        config.allowUnfree = true;
      };

  enabled = lib.filterAttrs (_: guest: guest.enable) (config.tartarus.guests or {});
  vmGuests = lib.filterAttrs (_: guest: guest.kind == "vm") enabled;
  ctnGuests = lib.filterAttrs (_: guest: guest.kind == "container") enabled;

  # Effective ids: forced ones honored verbatim, the rest auto-assigned from
  # 101 (see ids.nix). The engine is then handed a concrete id.
  vmIds = ids.assignIds vmGuests;
  ctnIds = ids.assignIds ctnGuests;

  build = import ../guest/build.nix {
    inherit
      lib
      system
      hostSystem
      nixVersion
      config
      guestPkgs
      ;
    inputs = allInputs;
    self = resolvedSelf;
    homeDir = resolvedHomeDir;
    hostPkgs = resolvedHostPkgs;
  };

  vms = lib.mapAttrs (name: guest: build.mkVm name (guest // {id = vmIds.${name};})) vmGuests;
  ctns = lib.mapAttrs (name: guest: build.mkContainer name (guest // {id = ctnIds.${name};})) ctnGuests;

  nixosConfigurations =
    lib.mapAttrs' (name: cfg: lib.nameValuePair (names.namespace "vm" name) cfg) vms
    // lib.mapAttrs' (name: cfg: lib.nameValuePair (names.namespace "container" name) cfg) ctns;

  namespacedVms = lib.mapAttrs' (name: cfg: lib.nameValuePair (names.namespace "vm" name) cfg) vms;
in {
  inherit nixosConfigurations;

  # Only VMs produce a runnable package (the microvm runner script); containers
  # are built with `nixos-container create --flake`, which reads
  # `nixosConfigurations` directly.
  packages.${resolvedSystem} =
    lib.mapAttrs (_: vm: vm.config.microvm.declaredRunner) namespacedVms;

  inherit vmIds;
}

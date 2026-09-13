# macOS has no native Linux builder, but every tartarus guest is a Linux
# system. On Darwin the guest closure (and the runner's host-native binaries)
# must therefore be produced by nix-darwin's `nix.linux-builder` VM -- see
# nixcfg's docs/linux-builder.md for the full flow, performance and
# troubleshooting. Enable it by default so `tartarus start` / `nix build
# .#packages.<guest-system>.vm-<name>` work out of the box; a host may still
# override `nix.linux-builder.*` (its explicit settings win over the mkDefault
# here). This module is only imported on Darwin (see ./default.nix), because
# `nix.linux-builder` does not exist on NixOS.
{lib, ...} @ args: let
  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
in
  lib.mkIf isDarwin {
    nix.linux-builder.enable = lib.mkDefault true;
  }

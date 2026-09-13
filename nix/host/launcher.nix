# Host `.desktop` launchers for guest applications (ported from the old
# `launcher.nix` / `app-launcher.nix`). Both guest kinds share the mechanism:
# bring up the `wprsc` graphical tunnel, then exec the app on the guest's
# `wprs-0` Wayland display over SSH.
#
# SSH uses the tartarus CLI contract rather than assuming a pre-existing user
# ssh_config: `tartarus proxy %h` on Linux (VSOCK/CID) and `tartarus proxy-ip
# %h` on Darwin (vmnet ARP lookup). The guest module brings up the matching
# `wprsd` side.
{
  inputs ? {},
  tartarusPkg ? null,
}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    concatLists
    filterAttrs
    map
    mkIf
    mkMerge
    optionalString
    ;

  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
  isLinux = !isDarwin;

  guests = config.tartarus.instances.guests;
  enabled = filterAttrs (_: g: g.graphical && g.apps != []) guests;

  # The CLI comes from `default.nix` (the flake's own package output). The
  # fallback only matters if this file is imported on its own.
  tartarus =
    if tartarusPkg != null
    then tartarusPkg
    else import ../packages/tartarus.nix {inherit pkgs;};

  proxyCommand =
    if isDarwin
    then "${tartarus}/bin/tartarus proxy-ip %h"
    else "${tartarus}/bin/tartarus proxy %h";

  mkApp = kind: name: app: let
    safeName = lib.replaceStrings [" " "/"] ["-" "-"] app.name;
    displayName =
      if app.desktopName != null
      then app.desktopName
      else app.name;
    scriptName = "tartarus-app-${name}-${safeName}";
    launcher = pkgs.writeShellScriptBin scriptName ''
      set -euo pipefail
      NAME="${name}.trs"

      ${optionalString isLinux ''
        # Ensure the wprsc graphical tunnel is active before connecting.
        if ! ${pkgs.systemd}/bin/systemctl --user is-active "wprsc@$NAME" >/dev/null 2>&1; then
          ${pkgs.systemd}/bin/systemctl --user start "wprsc@$NAME" || true
          sleep 1
        fi
      ''}
      exec ${pkgs.openssh}/bin/ssh \
        -o ProxyCommand="${proxyCommand}" \
        "$NAME" "WAYLAND_DISPLAY=wprs-0 ${app.exec}"
    '';
  in
    pkgs.makeDesktopItem {
      name = "tartarus-${kind}-${name}-${safeName}";
      desktopName = displayName;
      exec = "${launcher}/bin/${scriptName}";
      icon = app.icon;
      terminal = app.terminal;
    };

  apps = concatLists (map (g: map (app: mkApp g.kind g.name app) g.apps) (lib.attrValues enabled));
in {
  config = mkMerge [
    (mkIf (apps != []) {
      environment.systemPackages = apps;
    })
    (mkIf (isLinux && apps != []) {
      environment.pathsToLink = ["/share/applications"];
    })
  ];
}

# Minimal home-manager base for every tartarus guest. It owns only the
# home-manager account essentials, the user's `userConfig`, the graphical
# transport (wprsd from the `wprs` input) and the login-shell environment
# bridge. No personal content lives here.
{
  lib,
  inputs,
  system,
  nixVersion,
  tartarusGuest,
  mkServiceHome,
  pkgs-unstable,
  self ? null,
  ...
}: let
  inherit
    (lib)
    mkDefault
    mkIf
    mkMerge
    ;
  g = tartarusGuest;
  user = g.user.name;
in {
  # The wprs input provides the `services.wprsd` NixOS module; import it always
  # so the option exists, and enable it only for graphical guests.
  imports = [inputs.wprs.nixosModules.default];

  services.wprsd.enable = g.graphical;

  environment.variables = mkIf g.graphical {
    WAYLAND_DISPLAY = "wprs-0";
    QT_QPA_PLATFORM = "wayland";
  };

  home-manager = {
    useGlobalPkgs = true;
    useUserPackages = true;
    backupFileExtension = "bak";

    extraSpecialArgs = {
      inherit inputs system nixVersion pkgs-unstable self;
      mkService = mkServiceHome;
      username = g.user.name;
      homeDir = g.user.home;
      # Let the user's home-manager imports see the source guest record.
      tartarusGuest = g;
    };

    users.${user} = mkMerge [
      {
        home.stateVersion = mkDefault nixVersion;
        home.username = g.user.name;
        home.homeDirectory = g.user.home;

        # The guest's own home-manager content, applied last so it wins.
        imports = [g.userConfig];

        # Load environment.d into interactive bash sessions. systemd/PAM
        # already apply it to user units; this covers plain ssh logins too.
        home.file.".bashrc".text = mkDefault ''
          shopt -s nullglob
          set -a
          for conf in /etc/environment.d/*.conf ~/.config/environment.d/*.conf; do
            source "$conf"
          done
          set +a
          shopt -u nullglob
        '';
        home.file.".bash_profile".text = mkDefault ''
          [ -f ~/.bashrc ] && . ~/.bashrc
        '';
      }
    ];
  };
}

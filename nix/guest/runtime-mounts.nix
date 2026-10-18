# Runtime mount helper for Linux VMs.
#
# The host stages directories under the built-in `tartarus-mounts` share
# (`/run/tartarus-mount/staging/<id>`) and asks this root helper, over a
# guest-local Unix socket, to bind/remount/overlay-mount them at validated
# targets. macOS/vfkit VMs have no runtime mounts: the module is imported only
# for Linux VMs (see ./default.nix) and self-gates as a defensive guard.
{
  config,
  lib,
  pkgs,
  tartarusGuest,
  mkServiceSystem,
  ...
}: let
  inherit
    (lib)
    mkIf
    optionals
    ;

  g = tartarusGuest;
  package = import ../packages/tartarus-mount {inherit pkgs;};

  service = mkServiceSystem {
    name = "tartarus-mount";
    description = "Runtime mount helper for tartarus guests";
    command = "${package}/bin/tartarus-mount serve";
    scope = "system";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    extraSystemdServiceConfig = {
      Restart = "on-failure";
      RuntimeDirectory = "tartarus-mount";
      RuntimeDirectoryMode = "0755";
      RuntimeDirectoryPreserve = "yes";
      Environment = [
        "TARTARUS_MOUNT_USER=${g.user.name}"
        "TARTARUS_MOUNT_GROUP=users"
      ];
    };
  };
in {
  imports = optionals (g.isVm && !g.platform.isDarwin) [service];

  config = mkIf (g.isVm && !g.platform.isDarwin) {
    # The host invokes this stable path over SSH; the service closure alone
    # does not put the binary on the guest's system PATH.
    environment.systemPackages = [package];
    systemd.tmpfiles.rules = [
      "d /run/tartarus-mount 0755 root root -"
    ];
  };
}

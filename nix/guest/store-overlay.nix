# The writable /nix/store overlay for VMs, plus registration of the booted
# system closure. Containers share the host store directly and need neither.
{
  lib,
  pkgs,
  tartarusGuest,
  mkServiceSystem,
  ...
}: let
  inherit (lib) mkIf optionals;
  g = tartarusGuest;

  nixStoreOverlay = g.vm.nixStoreOverlay;

  # microvm.nix's own registerClosure relies on boot.postBootCommands, a
  # stage-2-init.sh mechanism that never runs under the default
  # systemd-in-initrd boot. This service loads the `regInfo` the kernel booted
  # with instead. The writable overlay is required for the registration to
  # succeed (it canonicalises ownership on every path).
  registerClosureScript = pkgs.writeShellScript "register-nix-closure" ''
    if [[ "$(cat /proc/cmdline)" =~ regInfo=([^[:space:]]*) ]]; then
      ${pkgs.nix}/bin/nix-store --load-db < "''${BASH_REMATCH[1]}"
    fi
  '';
in {
  imports = optionals g.isVm [
    (mkServiceSystem {
      name = "register-nix-closure";
      description = "Register the system closure in the Nix DB";
      command = "${registerClosureScript}";
      scope = "system";
      wantedBy = ["nix-daemon.service"];
      after = ["nix-daemon.socket" "local-fs.target"];
      extraSystemdUnitConfig = {
        Before = ["nix-daemon.service"];
        Requires = ["nix-daemon.socket"];
      };
      extraSystemdServiceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
      };
    })
  ];

  config = mkIf g.isVm {
    microvm = {
      # A small writable overlay over the read-only shared store: without one,
      # Nix runs single-user against a store it can never write to, and every
      # command that registers a path (including home-manager activation)
      # fails.
      writableStoreOverlay = "/nix/.rw-store";

      volumes = [
        {
          image = "nix-store-overlay.img";
          mountPoint = "/nix/.rw-store";
          size = nixStoreOverlay.size;
          # A Nix store is overwhelmingly small files and directories, but ext4
          # defaults to one inode per 16 KiB, so the writable upper only gets 64
          # inodes per MiB (e.g. exactly 131072 for the 2048 MiB default). A
          # store accumulated across a container host's nested guests exhausts
          # those inodes long before it runs out of bytes, after which every
          # store write fails with ENOSPC and Nix reports "No space left on
          # device". Densify the inode table (one inode per 4 KiB) so bytes, not
          # inodes, are the binding limit. Applied at mkfs time, so it only
          # takes effect on a freshly created overlay image.
          mkfsExtraArgs = ["-i" "4096"];
        }
      ];
    };

    # NixOS separately re-bind-mounts /nix/store read-only by default, stacking
    # a second read-only mount on top of the writable overlay and defeating it.
    boot.nixStoreMountOpts = ["nosuid" "nodev"];

    fileSystems."/nix/var/nix/db" = {
      device = "/nix/.rw-store/var-nix-db";
      fsType = "none";
      options = ["bind"];
    };

    systemd.tmpfiles.rules = ["d /nix/.rw-store/var-nix-db 0755 root root -"];
  };
}

# Minimal, self-contained guest base shared by every tartarus guest (both
# kinds, both host platforms): state version, the guest user, sshd with a
# CA-signed host key, Nix settings and the macOS case-insensitive-store
# terminfo workaround.
#
# Nothing here depends on nixcfg. Guest *content* (packages, secrets, ...)
# arrives through `tartarusGuest.systemConfig`, composed last by default.nix.
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
    mkDefault
    mkIf
    mkMerge
    optional
    optionals
    ;
  g = tartarusGuest;

  # This Mac's Nix store volume is case-insensitive APFS. ncurses' terminfo
  # tree has directories that differ only by case (a top-level "X" bucket and a
  # separate "x" bucket) -- fine on the case-sensitive Linux builder that
  # compiles it, but Nix silently rewrites the colliding one when the finished
  # build is copied back into this case-insensitive store. Every guest shares
  # that same corrupted /nix/store, so ncurses' by-first-letter lookup can no
  # longer find e.g. xterm-256color. Recompile just the terminal types guests
  # actually use into a small tree with no case-colliding names.
  guestTerminfo = pkgs.runCommand "guest-terminfo" {nativeBuildInputs = [pkgs.ncurses];} ''
    mkdir -p $out/share/terminfo
    {
      for term in ansi dumb linux screen screen-256color tmux tmux-256color vt100 xterm xterm-256color xterm-color; do
        infocmp -x "$term"
        echo
      done
    } > combined.src
    tic -x -o $out/share/terminfo combined.src
  '';

  pubKeyFile =
    if g.isVm
    then "${g.hostHome}/.ssh/tartarus.pub"
    else "${g.hostHome}/.ssh/containers.pub";

  # sshd refuses to load a host key that is group/world readable at all, but the
  # VM key arrives over a 9p/virtiofs share (source file is group-readable on
  # the host, for the same unprivileged-qemu reason) -- stage a 0600 tmpfs copy
  # for sshd to actually use. Containers bind-mount /etc/tartarus/ssh directly
  # and read the key in place.
  hostkeyStageScript = pkgs.writeShellScript "microvm-ssh-hostkey-stage" ''
    install -d -m 0700 /run/tartarus
    install -m 0600 /etc/tartarus/ssh/ssh_host_ed25519_key /run/tartarus/ssh_host_ed25519_key
    install -m 0644 /etc/tartarus/ssh/ssh_host_ed25519_key-cert.pub /run/tartarus/ssh_host_ed25519_key-cert.pub
  '';

  hostKeyPath =
    if g.isVm
    then "/run/tartarus/ssh_host_ed25519_key"
    else "/etc/tartarus/ssh/ssh_host_ed25519_key";
in {
  imports =
    [
      # sd-boot/initrd setup that does not apply inside a systemd-nspawn
      # container.
      (mkIf (!g.isVm) {boot.isNspawnContainer = true;})
    ]
    ++ optional g.isVm (mkServiceSystem {
      name = "microvm-ssh-hostkey-stage";
      description = "Stage MicroVM CA-signed SSH host key with correct permissions";
      command = "${hostkeyStageScript}";
      scope = "system";
      wantedBy = ["sshd.service"];
      # sshd-keygen only skips generating /run/tartarus/ssh_host_ed25519_key
      # if that path is already non-empty when its own condition is checked;
      # with no ordering, systemd may run them concurrently and sshd-keygen
      # can clobber the CA-signed key. Force this service to run last.
      after = ["sshd-keygen.service"];
      extraSystemdUnitConfig.Before = ["sshd.service"];
      extraSystemdServiceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
    });

  config = mkMerge [
    {
      system.stateVersion = mkDefault g.nixVersion;

      environment.variables.TERMINFO_DIRS = ["${guestTerminfo}/share/terminfo"];

      nix = {
        settings.experimental-features = ["nix-command" "flakes"];
        gc = mkIf g.isVm {
          automatic = true;
          dates = "daily";
          options = "--max-freed 500M";
        };
      };

      users.groups.user = {};
      users.users.user =
        {
          createHome = true;
          group = "user";
          description = "${g.name} user";
          home = g.user.home;
          linger = true;
          # macOS guests are forced into a system user (host uid 501 < 1000),
          # whose NixOS-default shell is `pkgs.shadow` -> nologin. Pin an
          # interactive shell so `ssh <guest>` works on Darwin too. Low
          # priority so guest content (systemConfig) can pick e.g. zsh.
          shell = mkDefault pkgs.bashInteractive;
          extraGroups = ["wheel"];
          openssh.authorizedKeys.keys =
            optionals (builtins.pathExists pubKeyFile) [(builtins.readFile pubKeyFile)];
        }
        // (
          if g.isVm
          then {
            # See build.nix's hostUid comment: virtiofs has no host-side
            # ownership remapping, so the guest uid must match the invoking
            # host uid. NixOS forbids isNormalUser uid < 1000, hence the
            # isSystemUser escape hatch (macOS's first-user uid 501).
            isNormalUser = !g.lowHostUid;
            isSystemUser = g.lowHostUid;
            uid = mkIf (g.hostUid != null) g.hostUid;
          }
          else {isNormalUser = true;}
        );

      services.openssh = {
        enable = true;
        settings = {
          PermitRootLogin = "no";
          PasswordAuthentication = false;
        };
        hostKeys = [
          {
            path = hostKeyPath;
            type = "ed25519";
          }
        ];
        extraConfig = "HostCertificate ${hostKeyPath}-cert.pub";
      };

      # Ad-hoc guests are for interactive/debugging use -- surface service
      # failures on the serial console. home-manager-user.service also has no
      # inherent ordering against nix-daemon and can win the race on a fresh
      # boot.
      systemd.services.home-manager-user = {
        after = ["nix-daemon.socket"] ++ optional g.isVm "register-nix-closure.service";
        wants = ["nix-daemon.socket"] ++ optional g.isVm "register-nix-closure.service";
        serviceConfig.StandardOutput = "journal+console";
      };
      systemd.services.sshd.serviceConfig.StandardOutput = "journal+console";
    }

    # Containers do not mount shares; the host bind-mounts /etc/tartarus/ssh
    # and /etc/tartarus/x509 directly, so pre-create their mount points.
    (mkIf (!g.isVm) {
      systemd.tmpfiles.rules = [
        "d /etc/tartarus/ssh 0755 root root -"
        "d /etc/tartarus/x509 0755 root root -"
      ];
    })
  ];
}

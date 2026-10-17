# Host-side native `systemd-nspawn` containers.
#
# A `kind = "container"` guest with no `host` pointer runs directly on the
# Linux host kernel. The engine already derives the guest's id/address (from
# `nix/lib/ids.nix`), its CA material (`./ca.nix`) and its firewall rules
# (`./firewall.nix`), but the container itself must additionally be *declared*
# as a NixOS `containers.<name>`. That declaration is what makes activation
# write `/etc/nixos-containers/<name>.conf` -- the registration `nixos-container`
# and the `tartarus` CLI both key off (`src/tartarus/ctn.py`,
# `CTN_CONF_DIR`). Without it the CLI reports the guest as "not provisioned"
# and `tartarus start` refuses.
#
# The container system is built by the *same* guest engine as the standalone
# `ctn-<name>` flake output (`../guest/build.nix`), so the two stay in lockstep;
# only the host-level networking (bridging) and bind mounts (CA + shares) are
# added here. On Linux the host and its native containers share a system, so the
# host's `pkgs` (already carrying the consumer's overlays) is the guest pkgs.
#
# Nested containers (a `host` pointer) are declared by the container-host VM
# itself (`../guest/container-host.nix`) and have no host-side presence, so this
# module deliberately only handles `instances.container.hostSideNames`.
{
  inputs,
  self,
}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    listToAttrs
    map
    mkIf
    nameValuePair
    optionalAttrs
    ;
  ids = import ../lib/ids.nix {inherit lib;};
  binds = import ../lib/binds.nix {inherit lib;};
  nixVersion = import ../../lib/version.nix;

  # Raw module args: this nixpkgs resolves defaulted arguments through
  # `_module.args`, so a defaulted formal would be shadowed (see `./config.nix`).
  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
  isLinux = !isDarwin;
  system = args.system or builtins.currentSystem;
  username = args.username or "user";
  homeDir =
    args.homeDir
    or (
      if isDarwin
      then "/Users/${username}"
      else "/home/${username}"
    );

  instances = config.tartarus.instances;
  names = instances.container.hostSideNames;
  bridge = instances.container.bridge;

  # The guest engine, fed the host's own config so a native container's system
  # is identical to what `mkGuests` produces for `ctn-<name>`.
  build = import ../guest/build.nix {
    inherit
      lib
      inputs
      self
      system
      nixVersion
      config
      homeDir
      ;
    hostSystem = system;
    guestPkgs = pkgs;
    hostPkgs = pkgs;
  };

  sshMachines = config.tartarus.ca.ssh.machinesDir;
  x509Machines = config.tartarus.ca.x509.machinesDir;

  # The CA directories are bind-mounted read-only so the container's sshd reads
  # its CA-signed host key in place (the material is host-root-owned, so sshd
  # accepts it). `sharedFolder` and user `shares` are bind-mounted from their
  # host sources, exactly as the old hand-written container module did.
  mkBindMounts = name: g:
    {
      "/etc/tartarus/ssh" = {
        hostPath = "${sshMachines}/containers/${name}";
        isReadOnly = true;
      };
      "/etc/tartarus/x509" = {
        hostPath = "${x509Machines}/containers/${name}";
        isReadOnly = true;
      };
    }
    // optionalAttrs (g.sharedFolder or false) {
      "/home/user/shared" = {
        hostPath = "${homeDir}/shared/${name}";
        isReadOnly = false;
      };
    }
    // listToAttrs (map (s:
      nameValuePair s.mountPoint {
        hostPath = s.source;
        isReadOnly = s.readOnly or false;
        # Sources on filesystems without ID-mapped-mount support (notably
        # agenix's ramfs `/run/agenix`) must opt out: nspawn rejects `:idmap`
        # with EINVAL and the container fails to start.
        idmap = s.idmap or true;
      })
    (g.shares or []));
in {
  config = mkIf (isLinux && names != []) {
    containers = listToAttrs (map (name: let
      g = instances.guests.${name};
      attrs = build.mkContainerAttrs name (config.tartarus.guests.${name});
      # Resolve the per-guest override against the host-wide default.
      privateUsers =
        if g.privateUsers == null
        then config.tartarus.containers.privateUsers
        else g.privateUsers;
      # `privateUsers` (when it shifts UIDs) forces the CA/share binds onto
      # id-mapped `extraFlags`; otherwise they stay plain bind mounts.
      bindSpec = binds.render privateUsers (mkBindMounts name g);
    in
      nameValuePair name {
        # The CLI owns autostart: a `tartarus start` user service (`autostart.nix`)
        # provisions the container's CA material *before* starting it. Letting
        # NixOS start the container at boot would race that provisioning (the
        # CA bind mounts would be missing), so keep the native autostart off here.
        autoStart = false;
        # State lives on the host under `<stateDirectory>/containers/<name>`,
        # so it survives restarts and rebuilds.
        ephemeral = false;
        privateNetwork = true;
        privateUsers = privateUsers;
        hostBridge = bridge;
        inherit (bindSpec) bindMounts extraFlags;
        # `config` is a single NixOS module (nixos-containers.nix appends it
        # to the eval-config module list). Pin `nixpkgs.pkgs` to the host's
        # already-overlaid pkgs so the consumer's overlays survive the
        # container's own nixpkgs re-evaluation.
        config = {
          imports = attrs.modules ++ [{nixpkgs.pkgs = pkgs;}];
        };
        inherit (attrs) specialArgs;
      })
    names);
  };
}

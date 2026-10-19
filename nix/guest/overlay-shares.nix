# `overlay = true` shares: a writable overlayfs view of a host directory whose
# host source is exported read-only as the overlay lower.
#
# Imported unconditionally and self-gating on `tartarusGuest.shares`, because
# the mount lives inside the guest and applies identically to VMs, native
# containers and nested containers. `nix/guest/shares.nix` (VMs) and
# `nix/host/containers.nix` / `nix/guest/container-host.nix` (containers) only
# arrange for the host source to appear read-only at the lower mount point.
#
# Upper/work live under the guest home (`nix/lib/shares.nix` derives the paths)
# and cannot be created by `systemd-tmpfiles-setup.service`: that runs after
# `local-fs.target`, so a local-fs overlay mount would race it. A per-share
# oneshot creates them before the mount, and the mount is ordered after it via
# `x-systemd.requires`/`x-systemd.after`.
{
  lib,
  pkgs,
  tartarusGuest,
  mkServiceSystem,
  ...
}: let
  inherit
    (lib)
    concatMap
    dirOf
    filter
    hasPrefix
    mkIf
    mkMerge
    optionals
    unique
    ;
  g = tartarusGuest;
  sharePolicy = import ../lib/shares.nix {inherit lib;};

  overlayShares = filter sharePolicy.isOverlayShare g.shares;
  # Only well-formed tags can reach path interpolation; the assertion below
  # reports the malformed ones instead of letting evaluation crash.
  shares = filter (s: sharePolicy.safeOverlayTag s.tag) overlayShares;

  prepareService = s: "tartarus-overlay-prepare-${s.tag}";
  pathsFor = s: sharePolicy.overlayPaths g.user.home s;

  # Create the writable layer, and (when the mount point is under the guest
  # home) its parent user-owned so home-manager activation can still write
  # there. A single `install` invocation keeps the unit's ExecStart a plain
  # command (no shell). Non-home mount points are left to systemd's automatic
  # mount-point creation, which is root-owned.
  prepareCommand = s: let
    paths = pathsFor s;
    underHome = hasPrefix "${g.user.home}/" s.mountPoint;
  in
    "${pkgs.coreutils}/bin/install -d -m 0755 -o ${g.user.name} -g users ${paths.upper} ${paths.work}"
    + lib.optionalString underHome " ${dirOf s.mountPoint} ${s.mountPoint}";

  # Mount point parents under the home are created user-owned so home-manager
  # can still write there (a root-owned parent blocks it). tmpfiles runs after
  # local-fs (so after the overlay mount itself) but before sysinit.target, which
  # is in time for home-manager; systemd creates the mount point directory for
  # the mount unit when it is still missing.
  mountParents =
    unique (filter (d: hasPrefix "${g.user.home}/" d) (map (s: dirOf s.mountPoint) shares));

  overlayAssertions =
    concatMap (
      s: let
        paths =
          if builtins.isString s.tag
          then pathsFor s
          else {
            lower = "(invalid tag)";
            upper = "(invalid tag)";
          };
      in [
        {
          assertion = sharePolicy.safeOverlayTag s.tag;
          message = "tartarus: guest '${g.name}' has an overlay share with an unsafe `tag` (allowed: [A-Za-z0-9._-], not \".\" or \"..\").";
        }
        {
          assertion = !(sharePolicy.overlayMountConflict g.user.home s);
          message = "tartarus: guest '${g.name}' mounts overlay share '${toString s.tag}' at '${s.mountPoint}', which would hide its own lower/upper/work tree (lower '${paths.lower}', upper '${paths.upper}') or the guest home root.";
        }
      ]
    )
    overlayShares;
in {
  imports =
    optionals (shares != [])
    (map (s: mkServiceSystem {
        name = prepareService s;
        description = "Prepare overlay upper/work directories for share '${s.tag}'";
        command = prepareCommand s;
        scope = "system";
        # The overlay mount is a local-fs mount (`Before=local-fs.target`), so
        # this unit must be startable before local-fs: drop the default
        # `After=sysinit.target`/`basic.target` dependencies and order only
        # against the home and lower mounts. Without this, mounting before
        # local-fs while requiring a post-sysinit service is an ordering cycle.
        extraSystemdUnitConfig.DefaultDependencies = false;
        # The lower must be mounted before the writable layer is prepared, and
        # the home before anything under it. `RequiresMountsFor` resolves each
        # path to its mount unit and adds Requires/After. `optionals`:
        # containers get the lower as an nspawn bind, not a systemd mount unit.
        extraSystemdUnitConfig.RequiresMountsFor = [g.user.home] ++ optionals g.isVm [(pathsFor s).lower];
        extraSystemdServiceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
      })
      shares);

  config = mkMerge [
    (mkIf (shares != []) {
      fileSystems = lib.listToAttrs (map (s: let
        paths = pathsFor s;
      in {
        name = s.mountPoint;
        value = {
          device = "overlay";
          fsType = "overlay";
          options = [
            "lowerdir=${paths.lower}"
            "upperdir=${paths.upper}"
            "workdir=${paths.work}"
            # tmpfs (an ephemeral VM home) needs user xattrs for overlayfs;
            # harmless on ext4.
            "userxattr"
            "x-systemd.requires=${prepareService s}.service"
            "x-systemd.after=${prepareService s}.service"
          ];
          # A VM exports the lower as its own mount; order this mount after it.
          # A container's lower is an nspawn bind mount (performed before init),
          # so there is no mount unit to order against.
          depends = optionals g.isVm [paths.lower];
        };
      }) shares);
    })

    {
      systemd.tmpfiles.rules =
        map (d: "d ${d} 0755 ${g.user.name} users -") mountParents;
    }

    {assertions = overlayAssertions;}
  ];
}

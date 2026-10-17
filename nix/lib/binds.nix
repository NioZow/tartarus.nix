# Rendering of tartarus' `containers.<name>` bind mounts.
#
# When a container runs in a private user namespace
# (`containers.<name>.privateUsers` other than `"no"`/`"identity"`), systemd-
# nspawn shifts the container's UID range, so every host-owned bind source
# resolves to `nobody`/`nogroup` inside the container -- which breaks the
# root-owned CA host key and the guest-user-owned shares/cert material.
#
# The fix is the `idmap` mount option, which makes the source visible with its
# on-host UIDs (exactly the ownership the container saw before user
# namespacing). NixOS only emits `:idmap` for its own `/nix` binds, so tartarus
# re-expresses its own binds as raw `--bind=`/`--bind-ro=` nspawn flags (via
# `containers.<name>.extraFlags`) whenever id-mapping is in play. When it is
# not, the plain `containers.<name>.bindMounts` form is used unchanged.
{lib}: let
  # `true` when `privateUsers` shifts the container's UID range, i.e. anything
  # but `"no"` (disabled) and `"identity"` (1:1, capability isolation only).
  needsIdmap = privateUsers: privateUsers != "no" && privateUsers != "identity";

  # `bindMounts` is an attrset `mountPoint -> { hostPath, isReadOnly, idmap ? true }`,
  # as NixOS' `containers.<name>.bindMounts` expects, plus tartarus' `idmap`
  # opt-out. Returns the pair to splice into a container declaration: the plain
  # `bindMounts` when no id-mapping is needed, otherwise an empty `bindMounts`
  # plus the equivalent `extraFlags`.
  #
  # A bind can only carry `:idmap` when its source filesystem supports ID-mapped
  # mounts. Agenix's `/run/agenix` is a *ramfs* (which lacks `FS_ALLOW_IDMAP`),
  # so id-mapping such a bind makes nspawn fail with `Failed to clone ...:
  # Invalid argument`. Those shares set `idmap = false`; the bind then stays a
  # plain (read-only) bind and the container sees the files as `nobody`, which
  # is fine for world-readable secrets.
  render = privateUsers: bindMounts:
    if !(needsIdmap privateUsers)
    then {
      # `idmap` is tartarus-only; NixOS' `bindMounts` submodule does not know
      # it, so strip it on the plain-bind path.
      bindMounts = builtins.mapAttrs (_: d: builtins.removeAttrs d ["idmap"]) bindMounts;
      extraFlags = [];
    }
    else {
      bindMounts = {};
      extraFlags =
        lib.mapAttrsToList
        (mountPoint: d:
          "${
            if d.isReadOnly
            then "--bind-ro="
            else "--bind="
          }${d.hostPath}:${mountPoint}"
          + lib.optionalString (d.idmap or true) ":idmap")
        bindMounts;
    };
in {
  inherit needsIdmap render;
}

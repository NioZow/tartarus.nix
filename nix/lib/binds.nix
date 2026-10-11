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

  # `bindMounts` is an attrset `mountPoint -> { hostPath, isReadOnly }`, exactly
  # as NixOS' `containers.<name>.bindMounts` expects. Returns the pair to splice
  # into a container declaration: the plain `bindMounts` when no id-mapping is
  # needed, otherwise an empty `bindMounts` plus the equivalent `extraFlags`.
  render = privateUsers: bindMounts:
    if !(needsIdmap privateUsers)
    then {
      inherit bindMounts;
      extraFlags = [];
    }
    else {
      bindMounts = {};
      extraFlags =
        lib.mapAttrsToList
        (mountPoint: d: "${
          if d.isReadOnly
          then "--bind-ro="
          else "--bind="
        }${d.hostPath}:${mountPoint}:idmap")
        bindMounts;
    };
in {
  inherit needsIdmap render;
}

# Runtime-mount staging root. This mirrors the CLI's `state_root` convention so
# the guest's built-in virtiofs share and the host side agree on the same path.
# `TARTARUS_MOUNT_ROOT` (read impurely in `nix/guest/build.nix`) overrides it.
{lib}: rec {
  defaultRoot = {
    hostHome,
    name,
  }: "${hostHome}/.local/state/tartarus/${name}/mounts";

  resolve = {
    envValue ? "",
    hostHome,
    name,
  }:
    if envValue == ""
    then defaultRoot {inherit hostHome name;}
    else envValue;
}

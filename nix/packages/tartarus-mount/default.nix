# tartarus-mount: root guest helper for tartarus runtime mounts.
#
# Runs inside Linux VMs. The host stages a directory on the built-in
# `tartarus-mounts` share and asks this helper (over a local Unix socket) to
# bind, read-only bind or overlay-mount it at a validated guest target.
{
  pkgs,
  lib ? pkgs.lib,
}:
pkgs.writeShellApplication {
  name = "tartarus-mount";
  runtimeInputs =
    [pkgs.python3 pkgs.coreutils]
    ++ lib.optionals pkgs.stdenv.isLinux [pkgs.util-linux];
  text = ''
    exec ${pkgs.python3.interpreter} -P ${./tartarus-mount.py} "$@"
  '';
}

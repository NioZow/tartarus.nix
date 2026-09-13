# Share policies shared by the guest engine and its tests.
#
# The one non-obvious policy lives here: macOS/vfkit ignores a share's
# `readOnly` flag. vfkit's virtio-fs device has no read-only option, and
# microvm.nix does not add `ro` to the guest mount either, so a "read-only"
# share would still be writable by the guest -- and a guest that can write a
# host-owned shell/editor config gets code execution on the host the next time
# the host loads it.
#
# `needsStoreSnapshot`/`storeSnapshot` fix that by materialising the source into
# the Nix store and exporting that instead: store paths are root-owned and
# non-writable, so virtiofsd/vfkit (running as the invoking user) cannot write
# to them no matter what the guest mounts or remounts.
{lib}: let
  inherit (builtins) baseNameOf path toString;
  inherit (lib) any hasPrefix hasSuffix;

  # Sources that must never be copied into the world-readable store:
  # `/nix/store` is already immutable (and enormous), and `/run` holds runtime
  # material such as decrypted agenix secrets.
  neverSnapshotPrefixes = ["/nix/store" "/run" "/proc" "/sys" "/dev"];

  # Drop VCS metadata and zsh compiled artifacts: the former points at host
  # paths and is useless read-only, the latter is host/version specific and can
  # only get in the way in the guest.
  snapshotFilter = p: _type: let
    s = toString p;
  in
    baseNameOf p
    != ".git"
    && !(hasSuffix ".zwc" s)
    && !(hasSuffix ".zcompdump" s);
in rec {
  # Whether a share must be re-sourced from a read-only store snapshot. Only
  # macOS/vfkit needs it (Linux enforces `readOnly` at the hypervisor), and the
  # per-share `snapshot = false` opt-out or a never-snapshot prefix disables it.
  needsStoreSnapshot = platform: share:
    platform.isDarwin
    && (share.readOnly or false)
    && (share.snapshot or true)
    && !(any (prefix: hasPrefix prefix (toString share.source)) neverSnapshotPrefixes);

  # The store copy of `source`, as a string (so it drops straight into a share's
  # `source` field). Referencing it below makes the runner depend on it.
  storeSnapshot = tag: source:
    toString (path {
      path = /. + (toString source);
      name = "tartarus-share-${tag}";
      filter = snapshotFilter;
    });
}

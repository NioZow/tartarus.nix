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
  # `overlay = true` (tartarus-only; stripped before `microvm.shares`) turns a
  # share into a writable overlay view of the host directory: the host source is
  # exported read-only as the overlay `lowerdir`, and every guest write lands in
  # an upper/work pair under the guest home. The host folder is never written.
  isOverlayShare = s: (s.overlay or false) == true;

  # Overlay tags become a directory name and a systemd unit name, so keep them
  # to a conservative, path-safe alphabet. `.`/`..` are excluded even though
  # they match the character class.
  safeOverlayTag = tag:
    builtins.isString tag
    && tag != ""
    && tag != "."
    && tag != ".."
    && builtins.match "[A-Za-z0-9._-]+" tag != null;

  # The read-only lower mount point inside the guest. Deliberately under /run:
  # it is runtime material, never persisted, and it cannot collide with the
  # writable view at the share's original `mountPoint`.
  overlayLowerDir = s: "/run/tartarus/lower/${s.tag}";

  # Where the writable layer lives. Upper/work must be on the same filesystem;
  # keeping them under the guest home makes them persist with
  # `vm.persistentHome` (VMs) or the container rootfs (containers) and
  # disappear with an ephemeral VM home.
  overlayPaths = userHome: s: let
    base = "${userHome}/.local/state/tartarus/overlay-shares/${s.tag}";
  in {
    lower = overlayLowerDir s;
    upper = "${base}/upper";
    work = "${base}/work";
  };

  # A mount point that would hide its own lower/upper/work tree (or the home
  # root) cannot work: overlayfs needs to reach those directories through the
  # mount point. Checked at the host level and inside the guest.
  overlayMountConflict = userHome: s: let
    paths = overlayPaths userHome s;
  in
    s.mountPoint
    == "/"
    || s.mountPoint == userHome
    || s.mountPoint == paths.lower
    || hasPrefix "${s.mountPoint}/" paths.lower
    || s.mountPoint == paths.upper
    || hasPrefix "${s.mountPoint}/" paths.upper
    || s.mountPoint == paths.work
    || hasPrefix "${s.mountPoint}/" paths.work;

  # agenix mounts its secrets on a ramfs, which has no POSIX ACL xattr
  # support. With virtiofsd's `--posix-acl`, the guest negotiates
  # FUSE_POSIX_ACL and asks for `system.posix_acl_access`; ramfs answers
  # EOPNOTSUPP, and the guest VFS propagates that out of its permission check,
  # so every access to the share fails with "Operation not supported". Such a
  # share must not advertise ACL/xattr passthrough.
  needsNoPosixAcl = share: let
    source = toString share.source;
  in
    source
    == "/run/agenix"
    || hasPrefix "/run/agenix/" source
    || source == "/run/agenix.d"
    || hasPrefix "/run/agenix.d/" source;

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

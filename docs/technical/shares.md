# Shares and read-only enforcement

`tartarus.guests.<name>.shares` are host directories exported into a guest
(`microvm.shares` under the hood). Each entry needs at least `tag`, `source` and
`mountPoint`. `proto` defaults to `virtiofs` on both platforms: macOS/vfkit
forces it (vfkit rejects 9p), and Linux uses it too because QEMU's 9p server is
slow and mishandles symlinks that traverse `..` (readlink returns `ELOOP`, which
makes git/libgit2/Nix abort while statting a shared checkout). On Linux a share
may still opt into `proto = "9p"`.

```nix
tartarus.guests.dev.shares = [
  {
    tag = "zsh";
    source = "${homeDir}/.config/nixcfg/dotfiles/.config/zsh";
    mountPoint = "/home/user/.config/zsh";
    readOnly = true;
  }
];
```

## `readOnly` is not the same everywhere

A share with `readOnly = true` must not be writable by the guest: a guest that
can write a host-owned config file (say `~/.config/zsh`) gets code execution on
the host the next time the host loads it.

- **Linux (QEMU/KVM)** enforces it at the hypervisor: a `virtiofs` share gets
  `--readonly` on virtiofsd, and an explicit 9p share gets `readonly=on`.
- **macOS (vfkit)** ignores it. vfkit's virtio-fs device has no read-only
  option, and microvm.nix does not add `ro` to the guest mount. A guest-side
  `ro` mount is not a boundary either: a guest with root can remount it.

## What tartarus does on macOS

When the host is Darwin and a share is `readOnly = true`, the engine replaces
its `source` with a copy in the Nix store and exports *that*:

```
source = /Users/you/.config/zsh
      -> /nix/store/<hash>-tartarus-share-zsh
```

The store copy is root-owned and non-writable (`dr-xr-xr-x` / `-r--r--r--`), so
virtiofsd/vfkit — which run as **you** — cannot write to it. Writes attempted by
the guest fail on the host filesystem (`EACCES`) before they ever reach your
live files, regardless of what the guest mounts or remounts. This works because
the enforcement is host-side file ownership, not a mount flag.

The copy is content-addressed: editing the host directory produces a new store
path, so the change is picked up after the next build/start
(`tartarus start`, `tartarus build`, or a plain `nix build`).

The copy skips VCS metadata and zsh compiled artifacts (`.git`, `*.zwc`,
`.zcompdump`); the former points at host paths, the latter is host/version
specific.

## Secrets

The store is **world-readable** and GC-managed. Do not let a secret-bearing
read-only share be copied into it. Two protections apply automatically:

- Sources under `/nix/store` and `/run` (e.g. decrypted agenix secrets) are
  never snapshotted. `/nix/store` is already immutable, and `/run` is runtime
  material.
- tartarus's own key-bearing shares (`tartarus-ssh`, `tartarus-x509`) set
  `snapshot = false`.

For anything else that must stay off the store, opt out per share:

```nix
{
  tag = "sensitive";
  source = "${homeDir}/private";
  mountPoint = "/home/user/private";
  readOnly = true;
  snapshot = false; # don't copy to the store; becomes a no-op RO on macOS
}
```

`snapshot` is a tartarus-only field; it is stripped before the shares are handed
to `microvm.shares`.

## ID-mapped container binds

A `privateUsers` container gets its share (and CA) binds as id-mapped nspawn
mounts, so host ownership stays visible inside the container. The source
filesystem must support ID-mapped mounts. Agenix's `/run/agenix` is a *ramfs*
and does not, so a secret share must opt out:

```nix
{
  tag = "secrets";
  source = "/run/agenix/tartarus-litellm";
  mountPoint = "/etc/tartarus-secrets";
  readOnly = true;
  idmap = false;
}
```

Without it nspawn fails with `Failed to clone ...: Invalid argument`. With
`idmap = false` the files appear owned by `nobody`/`nogroup` in the container;
that is fine when they are world-readable (agenix secrets are `0444`).

`idmap` is a tartarus-only field, like `snapshot`; it is stripped before the
shares reach `microvm.shares`.

## Overlay shares

`overlay = true` turns a share into a **writable overlay view** of the host
directory. The guest sees a normal writable directory at `mountPoint`; the host
source is exported only as a read-only overlay lower, and every guest write
lands in an upper/work pair inside the guest.

```nix
tartarus.guests.dev.shares = [
  {
    tag = "opencode";
    source = "${homeDir}/.config/nixcfg/dotfiles/.config/opencode";
    mountPoint = "/home/user/.config/opencode";
    overlay = true;
  }
];
```

What the engine does:

- The host source is exported as a **read-only** share at
  `/run/tartarus/lower/<tag>` (`readOnly` is forced, whatever the share says).
  The share is never exported at its original `mountPoint`.
- The guest mounts an overlayfs at `mountPoint` with:
  - `lowerdir=/run/tartarus/lower/<tag>`
  - `upperdir=~/.local/state/tartarus/overlay-shares/<tag>/upper`
  - `workdir=~/.local/state/tartarus/overlay-shares/<tag>/work`
  - `userxattr` (so a tmpfs home works as the upper; harmless on ext4)
- A per-share oneshot (`tartarus-overlay-prepare-<tag>.service`) creates the
  upper/work directories owned by the guest user before the mount. It cannot be
  done with tmpfiles: `systemd-tmpfiles-setup.service` runs after
  `local-fs.target`, so the mount would race it.

The writable layer persists with the guest's home: with
`vm.persistentHome.enable` for a VM (otherwise the home is tmpfs and the layer
is ephemeral), and with the container rootfs for containers. Deleting the
upper/work directory resets the guest's view; the host folder is never touched.

`tag` must match `[A-Za-z0-9._-]+` (and must not be `.`/`..`), and `mountPoint`
must not be `/`, the guest home root, or a parent of its own lower/upper/work
tree.

### Linux only

Overlay shares are rejected at evaluation on Darwin. vfkit ignores `readOnly`,
and the macOS read-only enforcement works by exporting a root-owned store
snapshot — overlayfs cannot write through a `0444`/`0555` root-owned lower as
the guest user.

### Containers

Native containers bind the host source read-only at `/run/tartarus/lower/<tag>`
(never at the share's mount point) and run the same overlay mount inside the
container. With `privateUsers`, that bind is rendered as
`--bind-ro=<source>:/run/tartarus/lower/<tag>:idmap`, so the usual `idmap`
opt-out applies.

A nested container follows the same model inside its container-host VM: the VM
exports the source read-only under `/var/lib/tartarus-inner/<name>/shares/<tag>`
and the container binds that at `/run/tartarus/lower/<tag>`.

The overlay share's host source stays read-only to the container. The writable
layer lives in the container's own home, just like a VM's.

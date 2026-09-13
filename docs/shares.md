# Shares and read-only enforcement

`tartarus.guests.<name>.shares` are host directories exported into a guest
(`microvm.shares` under the hood). Each entry needs at least `tag`, `source` and
`mountPoint`; `proto` (`9p`/`virtiofs`) is normalized to the platform by the
engine.

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

- **Linux (QEMU/KVM)** enforces it at the hypervisor: 9p gets
  `readonly=on`, and a `virtiofs` share gets `--readonly` on virtiofsd.
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

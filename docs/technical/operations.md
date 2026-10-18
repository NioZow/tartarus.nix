# Operations

> **Optional — not required reading.** The required docs cover everything you
> need to install, use and configure Tartarus. Read this only if you operate a
> host: deploying, observing, troubleshooting and maintaining it.

## Who this is for

Operators and on-call engineers responsible for a Tartarus host and its guests.

## What you'll learn

- how to deploy and verify a host after a rebuild,
- what to observe and where the logs are,
- how to troubleshoot the common failure modes,
- how to maintain state, keys and upgrades.

## Deploy

1. Rebuild the host (`nixos-rebuild switch --flake .#myhost --impure`,
   `darwin-rebuild switch ...`, or your wrapper).
2. Confirm the generated config exists and lists the expected guests:
   `cat ~/.config/tartarus/config.toml`.
3. Confirm the SSH trust line is present in `~/.ssh/known_hosts_trs`
   (`@cert-authority *.trs ...`); if missing, run
   `systemctl --user start tartarus-ca-known-hosts`.
4. `tartarus list` should show every enabled guest and none of the disabled
   ones.

## Observe

| Signal | Where |
| --- | --- |
| CLI config | `~/.config/tartarus/config.toml` |
| Guest console log (VM) | `tartarus logs <name>` / `<state_root>/<name>/` |
| Container journal | `tartarus logs <name>` (systemd journal) |
| Proxy | `journalctl --user -u tartarus-proxy` (metadata only, no bodies) |
| Host firewall | `sudo nft list table inet tartarus_vm` / `tartarus_container` |
| Proxy listeners | `ss -ltnp \| grep :3128` (bridge addresses, never loopback) |
| Autostart | `systemctl --user status tartarus-autostart-<name>` |

On Darwin the proxy is a launchd agent: `launchctl list | grep tartarus-proxy`;
`lsof -nP -iTCP:3128 -sTCP:LISTEN` should show `192.168.64.1:3128`.

## Troubleshoot

- **A guest command refuses with "not enabled on this host".** The name is
  disabled or unknown; set `tartarus.guests.<name>.enable = true` and rebuild.
  This guard fires before any build or state change.
- **`tartarus list` is empty / config missing.** Rebuild the host; the config is
  written through home-manager and needs `home-manager` present.
- **Evaluation fails with an assertion.** Read the message — it names the guest
  and the option. See the [configuration
  reference](../user/configuration.md#assertions).
- **A guest can't reach the internet.** Check `internet` vs `proxy.enable`
  (mutually exclusive); for a proxy-only guest, confirm the host allowlist and
  that the proxy binds the bridge.
- **A share is not read-only on macOS.** vfkit ignores `readOnly`; the engine
  snapshots the source into the store. A secret-bearing share needs
  `snapshot = false`. See [Shares](./shares.md).
- **An overlay share fails to evaluate on Darwin.** That is deliberate:
  `overlay = true` is Linux-only. Move the guest to a Linux host, or drop
  `overlay` and use a plain read-only share on macOS. See
  [Overlay shares](./shares.md#overlay-shares).
- **An overlay share is empty or writes vanish.** Check that the guest is on a
  Linux host, that the tag is `[A-Za-z0-9._-]+`, and that the mount point is not
  a parent of `~/.local/state/tartarus/overlay-shares/<tag>`. On a VM without
  `vm.persistentHome.enable` the home is tmpfs, so the writable layer is
  discarded at shutdown.
- **A VM is unresponsive but RAM is high.** Free page reporting only returns
  *freed* pages; a busy VM stays resident. Use the manual balloon if needed
  (see [How it works](./how-it-works.md#memory-management)).
- **A runtime mount says the helper or staging share is missing.**
  The VM predates the runtime-mount artifacts. Rebuild and restart it once:
  `tartarus restart <name> -u`.
- **`tartarus mounts` shows a stale entry after a reboot.** Host staging binds
  vanish on reboot; the record remains. `tartarus unmount <guest> <target>`
  clears it (there is nothing left to release).
- **Staging binds remain after an unclean exit.** `tartarus start` releases them
  before launching. To inspect first, use
  `findmnt -R <state_root>/<name>/mounts`.
- **Runtime mounts are refused on macOS or for a nested container.** That is
  deliberate: macOS/vfkit has no hotplug or bind mounts, and a nested
  container's host source is not visible inside the container-host VM. Use a
  Linux VM or a native container.
- **Runtime-mount staging holds host data.** `<state_root>/<name>/mounts` is
  guest-writable; keep secrets out of it.
- **A nested container won't start.** Nested nspawn under microvm.nix is the
  [container-host](./container-host.md) path; see its runtime caveats.

For the full, platform-specific manual pass, work through the
[manual smoke list](./smoke.md).

## Maintain

- **State:** per-guest state lives under `tartarus.stateRoot`; `tartarus stop
  --purge <name>` wipes it (VM state dir / container registration).
- **Keys:** the SSH and X.509 CAs live under their `caDir`s, with per-guest
  material under `machinesDir`. Rotation is an advanced operation; see
  `nix/host/ca.nix`.
- **Upgrades:** the guest stateVersion constant is `lib/version.nix`; bump it
  deliberately alongside the host. Guest closures are only rebuilt on demand
  (`tartarus start -u`), so a host rebuild does not silently rebuild every
  guest.
- **Disk:** VM writable `/nix/store` overlays (`vm.nixStoreOverlay.size`) and
  persistent homes (`vm.persistentHome.size`) are sized per guest.
- **Runtime mounts are ephemeral.** They are not persisted or re-applied; state
  lives in `<state_root>/<name>/runtime-mounts.json` only while the mount
  exists, and stop/restart removes it.

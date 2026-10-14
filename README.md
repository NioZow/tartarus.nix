# tartarus

Ad-hoc MicroVMs and systemd-nspawn containers, built from **your** flake.

Tartarus turns a small declarative host option surface (`tartarus.guests.*`,
`tartarus.proxy`) into full NixOS guest systems, a host firewall, an SSH/X.509
CA, a filtering HTTP proxy, and a `tartarus` CLI to start, stop and inspect
them. The guests are ordinary NixOS systems produced by *your* packages,
overlays and secrets; Tartarus provides the engine, not the content.

- **Guests are full NixOS systems.** There is no home-manager-only mode.
- **Two kinds:** `vm` (QEMU/KVM on Linux, vfkit on macOS) and `container`
  (systemd-nspawn).
- **Nothing is bundled.** Everything a guest contains comes from the
  `systemConfig` / `userConfig` you pass in.
- **Filtering proxy included.** One Squid forward proxy, no MITM, per-guest
  HTTPS/443 allowlists.
- **Standalone utilities.** `sudo-auth-proxy`, `ssh-agent-proxy` and
  `clipboard-bridge` ship as packages and self-contained NixOS/home-manager
  modules usable without any VM.

## Quick start

```nix
# flake input
inputs.tartarus.url = "github:niozow/tartarus.nix";

# host module
imports = [ inputs.tartarus.nixosModules.tartarus ];
tartarus.guests.vault = {
  enable = true;
  kind = "vm";
  internet = true;
  systemConfig = { /* your NixOS config */ };
};
```

Guests are built by your flake via `inputs.tartarus.lib.mkGuests`; see
[Installation](docs/user/installation.md). Rebuild with `--impure`, then:

```bash
tartarus list
tartarus start vault
tartarus ssh vault
```

## Documentation

Full documentation lives in [`docs/`](docs/README.md).

- **Start here** — [Introduction](docs/user/introduction.md) ·
  [Installation](docs/user/installation.md) ·
  [Getting started](docs/user/getting-started.md)
- **User guide** — [Usage](docs/user/usage.md) ·
  [Configuration](docs/user/configuration.md) ·
  [Cheatsheet](docs/user/cheatsheet.md)
- **Technical** — [Architecture](docs/technical/architecture.md) ·
  [How it works](docs/technical/how-it-works.md) ·
  [Data model](docs/technical/data-model.md) ·
  [Interfaces](docs/technical/interfaces.md)
- **Optional** — [Operations](docs/technical/operations.md) ·
  [Design rationale](docs/technical/design-rationale.md) ·
  [Security model](docs/technical/security-model.md)
- **Deep dives** — [Shares](docs/technical/shares.md) ·
  [Container-host VMs](docs/technical/container-host.md) ·
  [ssh-agent-proxy](docs/technical/ssh-agent-proxy.md) ·
  [sudo-auth-proxy](docs/technical/sudo-auth-proxy.md) ·
  [Manual smoke list](docs/technical/smoke.md)

## Platform notes

- **Linux** — QEMU/KVM VMs and native systemd-nspawn containers, on the `trs0`
  and `trs1` bridges; VSOCK is the default service transport; the host owns
  nftables.
- **macOS** — vfkit guests on `vmnet-shared` NAT; no host bridge, VSOCK or
  nftables; containers run nested inside a container-host VM. Building Linux
  guests needs `nix.linux-builder` (enabled by default on Darwin).

See [How it works](docs/technical/how-it-works.md) for details.

## Tests

The eval-level suite boots nothing and builds nothing:

```bash
nix eval --impure --file tests/default.nix --json      # standalone
nix flake check --all-systems --impure --no-build      # via checks.<system>
```

The complementary manual, per-platform pass is the
[manual smoke list](docs/technical/smoke.md).

## Credits

This project and two of its components (`ssh-agent-proxy`, `sudo-auth-proxy`)
were inspired by the work of **Floriant Guilbert** and the **mofos** project
(https://github.com/synacktiv/mofos).

## License

MIT. See [LICENSE](LICENSE).

# Tartarus → Standalone Repo: Implementation Plan

`packages/tartarus/` becomes its own git repository at `./tartarus.nix/`, consumed by
nixcfg as a flake input. The goal is a **fully self-contained tartarus** that does not
depend on nixcfg, while nixcfg keeps only the *end-user* configuration (which guests,
which secrets, which dotfiles, per-host settings).

This document is the working plan. It records the decisions already made, the full
inventory of what currently couples tartarus to nixcfg, the target architecture, and the
migration order.

---

## 1. Decisions (locked in)

| Topic | Decision |
|---|---|
| Repo | New standalone repo at `./tartarus.nix/` (its own git repo). |
| Consumption | Dev phase: local path input, rebuilt with `--override-input tartarus path:$PWD/tartarus.nix` (see §4 Phase 0 — a bare `path:./tartarus.nix` does **not** survive nixcfg's `git+file://` store copy). Later: proper remote flake input. |
| Build contract | nixcfg builds guests by calling **`tartarus.lib.mkGuests`** from its own `outputs`, so the user's overlays/packages/secrets are in scope. The guest contents (templates) live in nixcfg, not tartarus. |
| Options namespace | tartarus exposes **top-level `tartarus.*`**. `custom.*` is nixcfg-only convention and is **never** used inside tartarus. |
| Python | `tartarus.py` becomes a **Python package using `uv`** (not a single file). |
| Flake resolution | `tartarus.py` locates the **user's** flake via `~/.config/tartarus/config.toml`. It never points at its own repo. |
| Guest `custom.*` tree | **Not kept.** Only `sudo-auth-proxy` (+ PAM module), `ssh-agent-proxy`, and `clipboard-bridge` move into tartarus. Everything else is user-defined in nixcfg. |
| Secrets / agenix / overlays | **Not handled by tartarus.** The user's `systemConfig`/`userConfig` supply packages, overlays, and secrets; tartarus only builds the resulting NixOS system. |
| `ssh-agent-proxy` / `sudo-auth-proxy` / `clipboard-bridge` | **Owned by tartarus**, exposed directly as NixOS + home-manager modules and packages, usable **without** tartarus VMs. nixcfg consumes them from the tartarus flake. |
| CA scripts | Migrate into tartarus and are **rewritten in Python** (`ca.py`). They run **when the `tartarus` command runs**, not at rebuild time. |
| Autostart | tartarus exposes options to auto-start some VMs as **systemd user services** invoking the tartarus python package. |
| Service wrapper (`mkService`) | Use **`github:niozow/nix-service`**. It handles services cross-platform (macOS + Linux) for **root and user** services, on **NixOS and home-manager**. All tartarus services are created with it. **Do not re-implement `service.nix`.** |
| Flake inputs | Lean: `nixpkgs`, `nixpkgs-unstable`, `home-manager`, `microvm`, `nix-service`, `wprs`. No guest-content packages, no `lib/overlays.nix`. |
| Host declaration | nixcfg enables + configures `tartarus.guests.*`; tartarus generates `~/.config/tartarus/config.toml` through Nix; the python reads it and evaluates the **user's** flake to build guests. |
| Run as user vs system | Split explicitly: tartarus is **enabled** at the system level for the privileged bits (bridge, nftables, CA key ownership), but the **guests and the CLI/services run unprivileged** as the invoking user. "Configured as root" ≠ "runs as root". |
| HTTP proxy | **Squid**, one instance, **no MITM**. Always **proxy-only** (all egress to every port is dropped unless it goes through the proxy) and always **allowlist**-filtered. Allowlisted hosts are reachable **only over HTTPS/443**. Filtering is per-guest; global settings hold only basic config (place, port, listen interface, logging) and are merged with the per-guest config. The proxy binds the **trs interface**, never loopback. |
| `internet` vs `proxy` | Mutually exclusive on a guest: `internet = true` **and** `proxy.enable = true` is an **evaluation error**. |
| Version / `stateVersion` | tartarus owns its own `lib/version.nix`. Guest `system.stateVersion` defaults from it but is **overridable per guest** (via `systemConfig`) so existing guests can pin their historical value. |
| Platform model | **No home-manager-only mode.** Guests are full NixOS systems. |
| Module ownership | **Everything under `modules/virtualisation/tartarus/` disappears** and is owned by tartarus. nixcfg imports `tartarus.nixosModules.tartarus` and keeps only end-user config. |
| `modules/services/squid.nix` | **Unrelated** to the tartarus proxy; it is an independent Squid server in nixcfg. Leave it as-is. |
| Credits | README credits **Floriant Guilbert** and the **mofos** project (https://github.com/synacktiv/mofos) as inspiration for tartarus and the two proxy services. |

---

## 2. Current coupling: what tartarus re-uses from nixcfg

Everything below is currently reached from `packages/tartarus/flake.nix` via
`repoRoot = ../..` or from `tartarus.py` via `NIXCFG_DIR`.

### 2.1 Hard-coded imports in `packages/tartarus/flake.nix`

| Path | Used for | Handling |
|---|---|---|
| `lib/version.nix` | guest `stateVersion` | Tartarus owns its own version constant; guest value is overridable. |
| `lib/overlays.nix` | guest package set verbatim (many inputs) | **Not copied.** The user's overlays stay in nixcfg and are used when nixcfg calls `tartarus.lib.mkGuests`. |
| `lib/service.nix` | `mkService` helper | **Do not copy / do not re-implement.** Consume `github:niozow/nix-service`. |
| `modules/virtualisation/tartarus/guest.nix` | the guestModule | Move into tartarus (tartarus owns the guest module shell; guest *content* comes from the user). |
| `modules/home.nix` | guest home-manager modules | **Not moved.** Personal config; supplied by the user through `userConfig`. |

**Also present and to be removed:** the old tartarus flake hardcodes an overlay input at an
absolute path (`chutes-litellm.url = "path:/Users/noah/dev/..."`). This must not migrate.

### 2.2 Runtime couplings in `tartarus.py`

| Coupling | Used for | Handling |
|---|---|---|
| `NIXCFG_DIR` (env) | locates nixcfg; build via `git+file://{NIXCFG_DIR}?submodules=1&dir=packages/tartarus` | Replace with the user's flake path from `config.toml`. |
| `TARTARUS_FLAKE_DIR = NIXCFG_DIR/packages/tartarus` | check `flake.nix` exists | Point at the user's flake root. |
| `${NIXCFG_DIR}/scripts/microvm-ssh-setup.sh` | SSH CA host key signing | Migrate to `ca.py`. |
| `${NIXCFG_DIR}/scripts/tartarus-x509-setup.sh` | X509 client cert generation | Migrate to `ca.py`. |
| `${NIXCFG_DIR}/scripts/microvm-ssh-setup-user.sh` | user SSH setup | Migrate to `ca.py`. |

### 2.3 Guest module surface referenced by templates

Templates set values against nixcfg's `custom.*` tree. The full tree a guest currently
imports (via `guest.nix` and `home.nix`):

**System modules (via `guest.nix`):**

- `modules/networking/`: `dns.nix`, `hosts.nix`, `nftables.nix`, `vpn.nix`
- `modules/security/`: `pam.nix`, `pki.nix`, `sudo.nix`, `sudo-auth-proxy.nix`, `u2f.nix`
- `modules/services/`: `pipewire.nix`, `sddm.nix`, `squid.nix`, `ssh-vpn.nix`, `ssh.nix`,
  `tailscale.nix`, `unbound.nix`, `usbguard.nix`
- `modules/virtualisation/tartarus/options.nix` (+ `types.nix`)

**Home-manager modules (via `modules/home.nix`):**

- `profiles/user/`: `ai.nix`, `chess.nix`, `core.nix`, `music.nix`,
  `desktop/{cursor,gtk,qt}.nix`, `dev/{base,bash,cpp,go,java,lua,markdown,nix,python,rust,typst,web,web3}.nix`,
  `security/{ad,crypto,pwn,web}.nix`, `workstation/{browser,fonts,social}.nix`
- `programs/user/`: `braindead.nix`, `clipboard-bridge.nix`, `direnv.nix`, `firefox.nix`,
  `ghostty.nix`, `git.nix`, `gpg.nix`, `keepassxc.nix`, `pass.nix`, `ssh.nix`,
  `thunderbird.nix`, `wordlists.nix`
- `security/user/`: `yubikey.nix`
- `services/user/`: `anki-sync-server.nix`, `caido.nix`, `clipboard-bridge-client.nix`,
  `clipboard-bridge-server.nix`, `ghostty.nix`, `gpg-agent.nix`, `litellm.nix`, `mpd.nix`,
  `noty.nix`, `ollama.nix`, `opencode.nix`, `snapclient.nix`, `ssh-agent-host.nix`,
  `ssh-agent-merge.nix`, `ssh-agent-proxy.nix`, `ssh-agent.nix`, `sudo-auth-proxy.nix`,
  `syncthing.nix`, `wayvnc.nix`, `wprsc.nix`, `wprsd.nix`, `xpra.nix`

**Handling:** only `sudo-auth-proxy` (with its PAM module), `ssh-agent-proxy`, and
`clipboard-bridge` are integrated into tartarus, each with `mkEnableOption`-style options.
Everything else is dropped and left to the user via `systemConfig`/`userConfig`. §5 records
what each dropped module did.

### 2.4 Flake inputs tartarus actually needs

Tartarus is deliberately lean. It embeds **no guest-content packages**. Its flake inputs
are only:

- **Basics:** `nixpkgs`, `nixpkgs-unstable`, `home-manager`, `microvm`.
- **`nix-service`** (`github:niozow/nix-service`) — the service wrapper used everywhere.
- **`wprs`** — the graphical transport (`wprsc` host side, `wprsd` guest side). This is
  part of tartarus's `graphical` engine, not user guest content.

Everything else a guest contains (opencode, litellm, noty, firefox, keepassxc, mpd,
snapclient, braindead, feynman, hashclash, pwndbg, agentskills, anki-sync-server, …) is
**defined in the user's own configuration** and passed in during the `mkGuests` build.

Only the tartarus-owned utilities (`sudo-auth-proxy`, `ssh-agent-proxy`,
`clipboard-bridge`) and the graphical transport (`wprs`) are built/exposed by tartarus.

### 2.5 Parent → tartarus couplings (nixcfg reaching in)

| Path | Used for | Handling |
|---|---|---|
| `modules/virtualisation/tartarus/{microvm,containers}.nix` | host-side instance provisioning; import `../../../packages/tartarus/templates` | Move into tartarus's host module. |
| `modules/virtualisation/tartarus/options.nix` | option surface | Replace with the unified `tartarus.*` options. |
| `modules/virtualisation/tartarus/types.nix` | `appType`, `idType`, … | Move into tartarus. |
| `modules/virtualisation/tartarus/ca.nix` | CA paths + `known_hosts_trs` service | Move into tartarus. |
| `modules/virtualisation/tartarus/{launcher,app-launcher}.nix` | host `.desktop` app launchers | Move into tartarus. |
| `modules/virtualisation/tartarus/nftables.nix` | host firewall rules for guests | Move into tartarus. |
| `modules/programs/user/ssh.nix` | host SSH config using `pkgs.tartarus proxy`/`proxy-ip` | Stays in nixcfg; depends on the tartarus CLI contract. |
| `modules/services/user/snapclient.nix` | host snapclient invoking `tartarus ip` | Stays in nixcfg (user-specific). |
| `modules/services/squid.nix` | independent Squid server | **Unrelated**; stays in nixcfg untouched. |
| `justfile` (`tartarus *args`, `tartarus-x509`) | CLI + cert entry points | Update to the new repo/CLI. |

**The entire `modules/virtualisation/tartarus/` directory must disappear.** nixcfg keeps only
a thin import of `tartarus.nixosModules.tartarus` plus the end-user config.
`modules/virtualisation/default.nix` drops its `./tartarus` import accordingly.

---

## 3. Target architecture

### 3.1 Repository layout

Tartarus's Nix code is **split across many small, well-named files**. Each file has one
responsibility.

```
tartarus.nix/
├── flake.nix                     # thin: inputs + outputs (modules, lib.mkGuests, packages)
├── flake.lock
├── pyproject.toml                # uv project: python package "tartarus"
├── uv.lock
├── README.md                     # + credits (Floriant Guilbert, mofos)
├── lib/
│   └── version.nix               # tartarus's own stateVersion constant
├── src/tartarus/                 # python package (uv)
│   ├── __init__.py
│   ├── cli.py                    # argparse + main (entry point tartarus.cli:main)
│   ├── config.py                 # reads ~/.config/tartarus/config.toml + env + flags
│   ├── errors.py
│   ├── output.py
│   ├── process.py
│   ├── system.py
│   ├── nix/
│   │   ├── __init__.py
│   │   ├── flake.py              # locate USER flake, flake ref
│   │   └── eval.py               # nix build/eval wrappers
│   ├── ca.py                     # SSH + X509 CA (replaces the bash scripts)
│   ├── ssh.py
│   ├── proxy.py                  # proxy endpoint resolution (host vs guest)
│   ├── vm.py
│   └── ctn.py
├── nix/
│   ├── default.nix               # flake outputs wiring only
│   ├── lib/
│   │   ├── default.nix
│   │   ├── mkGuests.nix          # THE build contract: guest defs -> nixosConfigurations
│   │   ├── ids.nix               # id assignment + IP/MAC/CID derivation (stable)
│   │   ├── names.nix             # guest naming / instance suffix logic
│   │   └── types.nix             # shared option types
│   ├── guest/
│   │   ├── default.nix           # guest module entry (system)
│   │   ├── build.nix             # mkVm / mkContainer engine (the big one)
│   │   ├── base.nix              # minimal guest base (state, users, nix store)
│   │   ├── network.nix           # Linux bridge / macOS NAT / static IP / vsock
│   │   ├── platform.nix          # explicit Linux vs Darwin behaviour
│   │   ├── shares.nix            # 9p/virtiofs, ownership fixups, persistent home
│   │   ├── store-overlay.nix     # writable /nix/store overlay + closure registration
│   │   ├── proxy.nix             # proxy client env in the guest (when enabled)
│   │   └── home.nix              # minimal home-manager base ONLY (no personal content)
│   ├── host/
│   │   ├── default.nix           # `tartarus.*` host module entry
│   │   ├── options.nix           # tartarus.guests.<name> + tartarus.proxy options
│   │   ├── instances.nix         # derive enabled guests + ids
│   │   ├── ca.nix                # CA options, known_hosts, config.toml generation
│   │   ├── firewall.nix          # nftables (host-level), internet×proxy matrix
│   │   ├── proxy.nix             # Squid config + per-guest allowlists + placement
│   │   ├── launcher.nix          # host .desktop app launchers
│   │   ├── ssh.nix               # host ssh config wiring
│   │   └── autostart.nix         # nix-service-created autostart services
│   └── packages/
│       ├── default.nix
│       ├── tartarus.nix          # the uv-built python package
│       ├── sudo-auth-proxy.nix
│       ├── ssh-agent-proxy.nix
│       └── clipboard-bridge.nix
└── tests/                        # eval-level flake checks (no VM boots)
```

There is **no `templates/` directory in tartarus**: templates define guest *content* and are
the user's configuration. nixcfg keeps them, rewritten against the `tartarus.*` API.

### 3.2 Flake outputs

```nix
inputs = {
  nixpkgs, nixpkgs-unstable, home-manager, microvm,
  nix-service,   # github:niozow/nix-service
  wprs,          # graphical transport only
};

outputs = {
  lib.mkGuests = <see §3.8>;          # the build contract, called from nixcfg's outputs

  packages.<system> = {
    tartarus         = <the uv-built python package>;
    sudo-auth-proxy  = <standalone>;
    ssh-agent-proxy  = <standalone>;
    clipboard-bridge = <standalone>;
  };

  nixosModules = {
    tartarus            = <host + guest module>;
    sudo-auth-proxy     = <standalone>;
    ssh-agent-proxy     = <standalone>;
    clipboard-bridge    = <standalone>;
  };
  homeManagerModules = {
    tartarus            = <guest home-manager base>;
    sudo-auth-proxy     = <standalone>;
    ssh-agent-proxy     = <standalone>;
    clipboard-bridge    = <standalone>;
  };
};
```

- `sudo-auth-proxy`, `ssh-agent-proxy`, and `clipboard-bridge` are exposed as **both**
  NixOS and home-manager modules, so a user can run them **without** tartarus VMs on either
  platform.
- All services are created with **`nix-service`** (root + user, NixOS + home-manager).
- nixcfg consumes tartarus as an input + module and calls `lib.mkGuests` in its own
  `outputs`. All end-user config stays in nixcfg.

### 3.3 The option surface (`tartarus.*`)

Replace flat template attrsets + the duplicated host-side instance declaration with one
uniform module:

```nix
tartarus.proxy = {                     # GLOBAL basic config only; never filtering
  enable    = true;
  location  = "host";                  # "host" | "<guest-name>" (a normal user-defined guest)
  port      = 3128;
  # Listen on the trs interface, never loopback. Derived from the enabled guest kinds
  # (10.200.0.1 for VMs, 10.201.0.1 for containers; 192.168.64.1 on Darwin). Overridable.
  listenAddresses = null;
  log       = false;                   # metadata only (client IP, CONNECT host), no MITM
};

tartarus.guests.vault = {
  enable        = true;
  kind          = "vm";                # vm | container
  id            = 3;                   # static (or auto-assigned, see ids.nix)
  graphical     = true;
  internet      = false;               # mutually exclusive with proxy.enable
  sharedFolder  = true;
  apps          = [ ... ];
  autostart     = false;
  services = {
    clipboardBridge = false;
    sshAuthProxy    = false;
    sudoAuthProxy   = true;
    disableVsock    = false;
  };
  vm = {                               # VM-only extras (ignored for containers)
    vcpu = 1;
    mem  = 768;                        # MiB
    persistentHome.enable = true;      # size in MiB, default 5120
    nixStoreOverlay.size  = 2048;      # MiB
  };
  firewall = {
    enable   = true;
    location = "host";                 # "host" (Linux privileged) | "guest" (inside guest)
    allow    = [ "10.200.0.0/24" ];    # extra host-service allowances, NOT internet egress
  };
  proxy = {                            # PER-GUEST filtering (merged with global basic config)
    enable     = true;                 # requires global tartarus.proxy.enable
    allowHosts = [ "example.com" ".example.com" ];  # HTTPS/443 only
  };
  systemConfig = { ... };              # user-defined NixOS config (packages, secrets, ...)
  userConfig   = { ... };              # user-defined home-manager config
};
```

**Assertions** (evaluation errors):

- `!(guest.internet && guest.proxy.enable)` — the two are mutually exclusive.
- `guest.proxy.enable` requires `tartarus.proxy.enable`.
- `tartarus.proxy.location` may name only an enabled `kind = "vm"` guest with `internet = true` (both Linux and Darwin).
- `firewall.location = "host"` is Linux-only.
- IDs unique within a kind and in the reserved range; auto-assignment starts at 101.

Notes:

- `kind` collapses the two code paths (`vm-`/`ctn-` prefixing, `--container`).
- Guest content (`systemConfig`/`userConfig`) is cleanly separated from host metadata
  (`id`, `graphical`, `internet`, `apps`, `autostart`) and host-enforced networking.
- `services.*` are real `mkEnableOption` options.

### 3.4 Firewall & privilege model (nftables, root vs user)

On Linux hosts, tartarus owns the guest firewall rules through **nftables**. The privilege
model keeps the boundary intact:

- **System/root level (NixOS, Linux):** bridge interface, nftables tables/chains, CA key
  ownership/permissions. These genuinely need root/`CAP_NET_ADMIN`.
- **User level:** guests and the tartarus CLI/services run unprivileged, exactly as today.

**`internet` × `proxy` matrix** (assertion forbids T×T):

| `internet` | `proxy.enable` | Guest egress |
|---|---|---|
| `true`  | `false` | NAT to the internet (today's behaviour). |
| `false` | `false` | No egress at all (except internal host services already allowed). |
| `false` | `true`  | **Proxy-only:** every port to anywhere is dropped except the proxy endpoint; host-side service allowances still apply. |
| `true`  | `true`  | **Invalid** — evaluation error. |

**Firewall/proxy integration (the current bug to fix):** the host's guest input chain has
`policy drop` at priority `-10`; a separate `squid` table at priority `0` never gets to
accept traffic because the earlier chain drops it first. The proxy `accept` rule must live
**inside the same input chain** as the guest rules, e.g.:

```
# VM bridge; same shape for trs1 / containers.
iifname "trs0" ip saddr 10.200.0.0/24 ip daddr 10.200.0.1 tcp dport 3128 counter accept
```

- The `forward` chain keeps dropping guest→non-bridge (no internet), but **must** open
  guest→proxy-VM when `proxy.location` is a guest (see §3.5).
- `firewall.allow` only adds *host-service* allowances (clipboard/ssh/sudo fallback,
  pipewire, litellm, DNS when allowed). It is **not** an internet-egress backdoor.
- The moved `modules/virtualisation/tartarus/nftables.nix` must keep generating the service
  fallback rules (clipboard 27795, ssh-proxy 65000, sudo-proxy 65001, pipewire 4713,
  litellm 27740) in addition to the new proxy rules.

On **macOS (nix-darwin)** there is no host nftables; guests are on vmnet-shared NAT. A guest
can opt into an **nftables firewall inside the guest** (`firewall.location = "guest"`),
which restricts egress for ordinary user processes. Caveat (accepted): a root process inside
the guest can bypass its own nftables. It is a practical policy, not a hard boundary.

### 3.5 HTTP proxy & per-guest egress allowlist

One **Squid** forward proxy. **No MITM.** It only ever sees host + CONNECT metadata.

**Semantics**

- **Enforcement is always on.** A proxied guest may reach *only* the proxy; **all traffic to
  any port is dropped otherwise**, including DNS (53), SSH (22), and plain HTTP (80).
- **Filtering is always an allowlist.** A destination is reachable only if its host matches
  an entry, and only over **HTTPS/443** (via CONNECT). Plain HTTP to allowlisted hosts is
  denied. There are no `mode`/`enforce`/`mitm` options.
- The proxy **resolves DNS on behalf of guests** — guests need no working resolver.
- **Per-guest filtering, global transport config.** `tartarus.proxy.*` holds only the basic
  settings (enable, `location`, port, `listenAddresses`, `log`). Filtering (`allowHosts`)
  lives on each guest. The two levels are **merged** per guest.

**Squid configuration (generated from Nix)**

- One `http_port` per listen address (the trs interface IP(s), **not loopback**).
- Per-guest `acl <guest> src <bridge IP>/32`, `acl <guest>_hosts dstdomain <allowHosts...>`.
- `acl SSL_ports port 443`, `acl CONNECT method CONNECT`.
- Per guest: `http_access allow <guest> CONNECT <guest>_hosts 443`, then `http_access deny <guest>`.
- Global tail: `http_access deny all` (unknown sources denied).
- `cache deny all`; remove the broken `never_direct allow all` (there is no `cache_peer`).
- Logging: when `log = false`, `access_log none`; when `log = true`, log only metadata
  (client IP + CONNECT host) to **journald** (viewed with `journalctl`; no rotation needed).
  No request bodies (impossible without MITM anyway).

**Placement**

- Default `location = "host"`: Squid runs as a host service bound to the trs IP.
  - Linux VMs reach `10.200.0.1:3128`; containers reach `10.201.0.1:3128` (bind both if both
    kinds are proxied).
  - Darwin guests reach the vmnet gateway `192.168.64.1:3128` (loopback is unreachable).
- `location = "<guest-name>"`: the proxy runs **inside a normal, fully user-defined guest**
  (its `systemConfig`/`userConfig` are untouched; tartarus merges `nix/guest/proxy.nix` in).
  - That guest must have `internet = true` (it is the egress point).
  - Clients reach the proxy VM over the bridge; the `forward` chain opens
    client→proxyVM:3128 and keeps dropping client→other-guest.

> **Correction on `microvm.forwardPorts`.** That option is implemented as QEMU `hostfwd`
> and asserts `hypervisor == "qemu"` **and** a `type = "user"` network interface
> (microvm `nixos-modules/microvm/asserts.nix`). It therefore **cannot** be used with
> tartarus's Linux bridge networking, with `nixos-container`, or with vfkit on Darwin — so the
> "bind on the host and forward to the proxy VM" idea is not available through it. It is
> moot here anyway: Linux uses direct routing, and Darwin uses a socat relay on the gateway
> (see below), not `forwardPorts`.

**Exposure method: direct routing (decided).** Clients connect straight to the proxy VM's
trunk IP. For same-kind clients no host involvement is needed; for cross-kind
(container→VM) the host adds a route + a `forward` accept **and** an exception from the trs
masquerade so the client's source IP survives. This keeps a **single `:3128`** and keeps the
per-guest `src`-keyed ACLs valid. A host-side userspace forwarder (`socket-proxyd`/`socat`)
would terminate the connection and hide the client IP, so it is **not** used on Linux.

**Darwin exception: the host relay.** vfkit's `--device virtio-net,nat` runs in vmnet
*shared* mode, and every `vmenet` port on the host bridge carries the `PRIVATE` flag, so
guests can reach the host/gateway but **not each other** (verified: ARP between two guests
stays `INCOMPLETE`). Direct routing is therefore impossible on macOS, and `forwardPorts` is
unavailable too (above). Instead the host runs a userspace relay — `socat
TCP-LISTEN:3128,bind=192.168.64.1,reuseaddr,fork TCP:<proxy-vm-ip>:3128` — and clients use
the gateway `192.168.64.1:3128`. The relay terminates the connection, so Squid sees the
gateway as the client and the per-guest `src` ACLs collapse into a single relay client whose
allowlist is the **union** of the guests'. Darwin egress is still enforced by the in-guest
nftables output policy (there is no host nftables on macOS), and DNS goes to the host
resolver on `192.168.64.1:53`.

**Guest-side env (automatic)**

tartarus's guest base writes `~/.config/environment.d/10-tartarus.conf` (merged by
systemd/PAM with `*.d` ordering, separate from nixcfg's `custom.environment` file) with:

```
HTTP_PROXY=http://<proxy-ip>:3128
HTTPS_PROXY=http://<proxy-ip>:3128
http_proxy=...
https_proxy=...
ALL_PROXY=...
NO_PROXY=10.200.0.0/24,10.201.0.0/24,10.200.0.1,10.201.0.1,localhost,127.0.0.1,.trs
no_proxy=...
```

`NO_PROXY` is **required** so the internal host services (clipboard/ssh/sudo/litellm) and
`*.trs` hosts are not sent to the proxy. Env vars are usability only; the firewall is the
enforcement.

### 3.6 Platform model: explicit Linux vs Darwin

Guests are **full NixOS systems**, never home-manager-only.

- **Linux host:** QEMU/KVM, `trs0`/`trs1` bridges with static IPs, VSOCK available (services
  default to VSOCK), host nftables.
- **Darwin host (nix-darwin):** vfkit, **vmnet-shared NAT** (`192.168.64.0/24`, host at
  `.1`), **no VSOCK** (all cross-boundary services forced to TCP), no host nftables. The
  vmnet bridge ports are `PRIVATE`, so guests reach the host only — never each other. A
  guest-hosted proxy is therefore exposed through a host socat relay on `192.168.64.1:3128`,
  clients target the gateway, and DNS uses the host resolver on `.1:53`. `tartarus proxy-ip`
  resolves the guest via the host ARP table (deterministic MAC).

`nix/guest/platform.nix` encodes these differences in one place; `disableVsock`, proxy bind
address, `NO_PROXY`, and service transports are all derived from it.

### 3.7 Integrated services: `sudo-auth-proxy`, `ssh-agent-proxy`, `clipboard-bridge`

- Each is exposed standalone as a **package** and as **NixOS + home-manager modules**.
- Every service is instantiated through **`nix-service`**, so the same definitions work as
  system services, user services, and home-manager services on NixOS/macOS.
- Each is wired into `tartarus.guests.<name>.services` for single-option enablement.
- Host/guest halves and PAM wiring are tartarus-owned; sensible defaults (VSOCK-vs-TCP chosen
  per platform, mTLS via the tartarus X509 CA, ports/OIDs) instead of user duplication.
  Note: `nix-service` creates the units only; PAM configuration is module code.
- All three are refactored later (separate plans); this plan relocates and option-flattens.

### 3.8 Build contract: `tartarus.lib.mkGuests`

This is the interface that was missing. Guests must be built **by nixcfg**, so the user's
overlays, custom packages, and secrets are available during evaluation.

```nix
# In nixcfg/flake.nix outputs:
let
  guests = tartarus.lib.mkGuests {
    inherit inputs nixpkgs;                           # nixcfg's inputs + pinned nixpkgs
    system = <guest system>;                          # autodetected / TARTARUS_SYSTEM
    hostSystem = builtins.currentSystem;
    config = self.nixosConfigurations.<host>.config;  # tartarus.guests.* + tartarus.proxy
    username = ...; homeDir = ...;
  };
in {
  nixosConfigurations = baseConfigs // guests.nixosConfigurations;
  packages.<system> = basePackages // guests.packages.<system>;
  inherit (guests) vmIds;
}
# guests = {
#   nixosConfigurations = { "vm-<name>" = ...; "ctn-<name>" = ...; };
#   packages.<system>   = { "vm-<name>" = <microvm.declaredRunner>; };  # VMs only
#   vmIds               = { "<name>" = <id>; };                          # static id map
# }
```

- `mkGuests` reads the host's `tartarus.guests.*` / `tartarus.proxy` and expands each guest
  through `nix/guest/*`, using the **caller's** `pkgs`/overlays and the guest's
  `systemConfig`/`userConfig`.
- **`tartarus.py` keeps working unchanged in spirit** against the *user's* flake:
  - VMs: `nix build <user-flake>#packages.<SYSTEM>.vm-<name> --impure --out-link result`
    (the runner at `result/bin/microvm-run`), exactly as today.
  - Containers: `nixos-container create <name> --flake <user-flake>#ctn-<name>` (reads
    `nixosConfigurations` directly).
  - **No per-call `nix eval` for IDs:** the id is in `config.toml`, so CID/IP/MAC are derived
    locally. `vmIds` remains exported for compatibility, not as a runtime dependency.
- The impure env interface (`MICROVM_INSTANCE_SUFFIX`, `MICROVM_ID_OVERRIDE`,
  `MICROVM_EXTRA_SHARES`, `TARTARUS_HOST_UID`, `HOME`) is read by the `mkGuests`-generated
  builders — i.e. by **tartarus's** code invoked from nixcfg, so the engine stays
  tartarus-owned while the package set stays user-owned. These impure reads must be
  documented as the deliberate instance/shares interface (see §6).
- `stateVersion` defaults to tartarus's `lib/version.nix`, overridable per guest.

---

## 4. Phases

Each phase is scoped to be implementable **with its own context**. "Read first" lists exactly
the inputs a fresh session needs. Do the phases in order; keep nixcfg building at every step.

### Phase 0 — Repo bootstrap, flake skeleton & dev input

- **Goal:** a valid empty tartarus flake with the final input set, file skeleton, and a dev
  consumption path that survives nixcfg's `git+file://` rebuild.
- **Read first:** §1, §2.1, §2.4, §3.1, §3.2.
- **Steps:**
  1. `git init ./tartarus.nix/`.
  2. Thin `flake.nix`: inputs `nixpkgs`, `nixpkgs-unstable`, `home-manager`, `microvm`,
     `nix-service`, `wprs`.
  3. Generate `flake.lock` (no overlay set, no copied `lib/overlays.nix`).
  4. Create the directory skeleton (§3.1), including `lib/mkGuests.nix` and `lib/version.nix`.
  5. Add `tartarus.url = "path:./tartarus.nix"` to nixcfg; **rebuild with
     `--override-input tartarus "path:$PWD/tartarus.nix"`** (an untracked nested repo is not
     copied into the store by `git+file://`). Alternatively make it a submodule from day one.
- **Done when:** `nix flake show --impure` succeeds and nixcfg still rebuilds.

### Phase 1 — Option surface, shared lib & assertions

- **Goal:** the unified `tartarus.guests.<name>` + `tartarus.proxy` API and shared helpers.
- **Read first:** §3.3, §3.1 (`nix/lib/`, `nix/host/options.nix`).
- **Steps:**
  1. `nix/lib/{types,names,ids}.nix` — types, naming/suffix logic, stable id→IP/MAC/CID.
     Auto-assignment starts at 101; static 3–100; lowering/removing a guest must not shift
     other IDs.
  2. `nix/host/options.nix` — typed submodule + global `tartarus.proxy` (basic config only).
  3. `nix/host/instances.nix` — `enabledNames` / `idByName` per kind.
  4. Assertions from §3.3 (internet×proxy, proxy location, host firewall on Linux, id range).
- **Done when:** a sample config declares guests; id map and assertions behave.

### Phase 2 — Guest engine & `lib.mkGuests`

- **Goal:** the guest builder (the current tartarus flake's engine) plus the `mkGuests`
  contract.
- **Read first:** §2.3, §3.6, §3.8, current `packages/tartarus/flake.nix`,
  `modules/virtualisation/tartarus/{guest,options,types}.nix`.
- **Steps:**
  1. Move the `mkVm`/`mkContainer` logic into `nix/guest/build.nix` (+ `shares.nix`,
     `store-overlay.nix`, `platform.nix`, `base.nix`, `network.nix`, `home.nix`).
  2. `nix/lib/mkGuests.nix` — expands `tartarus.guests.*` using the caller's pkgs/overlays.
  3. All guest services via `nix-service`.
- **Done when:** nixcfg with `lib.mkGuests` evaluates and builds `vm-<name>` / `ctn-<name>`.

### Phase 3 — Python package (uv)

- **Goal:** `tartarus.py` becomes a uv-built package. **Read first:** §2.2, current
  `tartarus.py`, §6.
- **Steps:** `pyproject.toml`/`uv.lock`; entry `tartarus.cli:main`; `requires-python >= 3.11`;
  split into `src/tartarus/*`; `nix/packages/tartarus.nix` via `buildPythonApplication`;
  resolve the **user's** flake from config.toml (never its own repo).
- **Done when:** `nix build .#tartarus` gives a working `tartarus --help`.

### Phase 4 — CA in Python

- **Goal:** CA scripts become Python and run on demand. **Read first:** §2.2, the three
  scripts, `tartarus.py`'s ssh helpers. Implement `src/tartarus/ca.py`; invoke before
  build/start, not at rebuild.

### Phase 5 — Host modules, Squid proxy & packages

- **Goal:** host wiring, the proxy, and the standalone utilities. **Read first:** §2.5, §3.4,
  §3.5, §3.7, current `modules/virtualisation/tartarus/{microvm,containers,ca,nftables,launcher,app-launcher}.nix`.
- **Steps:**
  1. `nix/host/{default,ca,firewall,launcher,ssh,autostart}.nix`.
  2. `nix/host/proxy.nix` — Squid config generation, per-guest `src`/`dstdomain` ACLs,
     HTTPS-only, placement (host or guest), optional metadata logging, trs bind addresses.
  3. Fold the proxy accept rule into the **same** guest input chain (fix the priority bug).
  4. Cross-kind routing for a guest-hosted proxy: host route + `forward` accept + masquerade
     exception so `trs1` clients reach a `trs0` proxy VM with their source IP intact.
  5. `nix/packages/{sudo-auth-proxy,ssh-agent-proxy,clipboard-bridge}.nix`, each also exported
     as NixOS + home-manager modules.
- **Done when:** the host evaluates; a guest can be proxy-only and restricted to an allowlist;
  each utility builds standalone.

### Phase 6 — config.toml generation & reading

- **Goal:** the Nix-generated runtime config and its Python reader. **Read first:** §6.
- **Steps:** generate `~/.config/tartarus/config.toml` (user, flake path, paths, enabled
  guests with kinds/ids, proxy endpoint, log); implement `config.py` with precedence
  CLI > env > TOML > defaults; derive CIDs/IPs locally from `id` (no per-call `nix eval`).

### Phase 7 — Wire nixcfg, migrate, then remove the old tree

- **Goal:** switch without breaking rebuilds. **Read first:** §2.5, §1, §3.1, §3.8.
- **Steps:**
  1. Add the tartarus input and import `tartarus.nixosModules.tartarus`.
  2. Migrate `hosts/*/tartarus.nix` to `tartarus.guests.*` / `tartarus.proxy` **in parallel**
     with the old `custom.virtualisation.*` tree, per host, verifying each host.
  3. Move guest *content* (former templates) into nixcfg, rewritten against `tartarus.*`,
     wired to agenix + dotfiles; wire `tartarus.lib.mkGuests` into nixcfg's outputs.
  4. Provide the `custom.virtualisation.*` → `tartarus.*` compatibility shim in nixcfg, then
     retire it once all hosts have migrated.
  5. Update `justfile` and `modules/programs/user/ssh.nix`.
  6. **Only after every host is green:** delete `modules/virtualisation/tartarus/` and drop
     its import from `modules/virtualisation/default.nix`.
- **Done when:** `just rebuild` works on every host with no old tree, and the shim removed.

### Phase 8 — Tests, docs, cleanup

- **Goal:** verification and docs. **Read first:** §3.1, §3.4, §3.5.
- **Steps:**
  1. Eval-level checks in `tests/` (no VM boots, no KVM): option types + assertions; stable
     id assignment; rendered Squid config (per-guest ACLs, HTTPS-only, deny-all tail);
     nftables rule snapshots for the internet×proxy matrix; generated `environment.d` vars;
     `mkGuests` output names.
  2. A documented **manual smoke list** per platform (Linux bridge + VSOCK; Darwin NAT + TCP;
     host proxy; guest proxy; allowlist hit/deny; DNS/SSH drop).
  3. README + credits; per-platform notes; a LICENSE file.
  4. `just check` across hosts; remove empty old directories.

---

## 5. Notes on the dropped guest modules (what they were used for)

Record only, so they can be re-created user-side. None of these move to tartarus.

| Former module | What it was used for |
|---|---|
| `profiles/user/dev`, `profiles/user/workstation.*`, `profiles/user/music`, `profiles/user/security.*`, `profiles/user/ai` | Curated package/desktop profiles for guests. |
| `programs/user/{firefox,keepassxc,pass,git,gpg,direnv,ghostty,thunderbird,braindead,wordlists,ssh}` | Interactive programs in guests. |
| `services/user/{opencode,litellm,noty,anki-sync-server,mpd,ollama,snapclient,syncthing,wayvnc,xpra,caido,ghostty,gpg-agent,ssh-agent,ssh-agent-host,ssh-agent-merge,wprsc,wprsd}` | Guest-side daemons/agents. Most are nixcfg-specific. |
| `networking/{dns,hosts,nftables,vpn}` | Guest DNS + firewall/VPN. |
| `security/{pam,pki,sudo,u2f}` | Guest security base. |
| `services/{pipewire,sddm,squid,ssh-vpn,ssh,tailscale,unbound,usbguard}` | Guest system services. |

**Integrated into tartarus instead:** `sudo-auth-proxy` (service + PAM module),
`ssh-agent-proxy`, and `clipboard-bridge`. All refactored later (separate plans).

**Also not in tartarus:** `packages/tartarus/templates/*.nix` (guest content) — nixcfg keeps
and rewrites them.

**Not to be confused with:** nixcfg's `modules/services/squid.nix`, which is an independent
Squid server and stays in nixcfg.

---

## 6. config.toml reconciliation

**Conclusion: config.toml complements the flake; it does not replace flake evaluation for
building guests.**

| Need | Mechanism |
|---|---|
| Host-runtime knobs: user, state root, **user flake path**, ssh/CA paths, enabled guests (name/kind/id), proxy endpoint, log | `~/.config/tartarus/config.toml`, generated by Nix at rebuild. |
| Actually building/starting a guest | `nix build <user-flake>#<kind>-<name> --impure` (the `mkGuests` outputs), then launch qemu/vfkit; `nixos-container create --flake`. |

- `config.toml` is the **single source for locating the user's flake**; `tartarus.py` never
  self-locates.
- **Precedence:** CLI flag > environment variable > config.toml > built-in default.
- **No per-call `nix eval` for CIDs/IPs:** the `id` is in the TOML, and CID/IP/MAC are pure
  functions of it (`ids.nix` logic mirrored in `src/tartarus/`). Evaluation is reserved for
  the actual build.
- The deliberately impure env-var interface (`MICROVM_INSTANCE_SUFFIX`,
  `MICROVM_ID_OVERRIDE`, `MICROVM_EXTRA_SHARES`, `TARTARUS_HOST_UID`, `HOME`) stays and is
  read by the `mkGuests` builders, letting one flake attribute produce a differently
  configured guest per invocation. It is documented as the instance/shares interface, not a
  config source.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| `custom.virtualisation.*` → `tartarus.*` touches every host + SSH config + autostart. | Parallel migration + compatibility shim (§4 Phase 7), removed after all hosts are green. |
| Dropping the guest `custom.*` tree breaks guests relying on its defaults. | §5 documents each module; user recreates needed bits via `systemConfig`/`userConfig`. |
| The guest *builder* is large and easy to under-scope. | §3.1/§3.8 make it a first-class artifact (`guest/build.nix`, `lib/mkGuests.nix`) owned by tartarus. |
| Dev input lost by nixcfg's `git+file://` store copy. | `--override-input tartarus path:$PWD/tartarus.nix` (or submodule from day one). |
| Proxy in a VM crosses the guest-to-guest drop / bridges. | Open question (§8); enforce same-bridge or add an explicit host route + forward accept. |
| `stateVersion` churn on migration. | tartarus owns `lib/version.nix`, but each guest's `stateVersion` is overridable so existing guests pin their historical value. |
| Secrets/agenix/overlays not owned by tartarus. | By design: the user's `systemConfig`/`userConfig` supply them during `mkGuests`; documented, not embedded. |
| System/root firewall ownership broadens privilege surface. | Strict boundary: only bridge/nftables/CA at system level; guest + CLI/services unprivileged. |
| Env vars are not enforcement; some tools ignore them. | Firewall drops all non-proxy egress; env vars are usability only. |
| `nix-service` remote misbehaves. | Use `github:niozow/nix-service`; if needed fix against `./nix-service` and upstream. Do not re-implement. |
| Submodule/worktree interactions (nixcfg AGENTS.md). | Prefer `--override-input` during dev; do not make `tartarus.nix` a submodule until stable. |

---

## 8. Open questions

All previously open questions are resolved:

- `stateVersion` defaults to tartarus's `lib/version.nix`, overridable per guest.
- `lib.mkGuests` is a plain function; `tartarus.py` builds against the **user's** flake via
  the returned `packages.<system>` (VMs) and `nixosConfigurations` (containers).
- Logging goes to journald; disabled by default.
- Internal VSOCK/TCP host services stay allowed under proxy-only; only internet egress drops.
- Squid binds both `10.200.0.1` and `10.201.0.1` on Linux when both kinds are proxied.
- A guest-hosted proxy is exposed by **direct routing** (source IP preserved, single `:3128`,
  per-guest `src` ACLs unchanged); no host forwarder.
- Guest-hosted proxies are **Linux-only**; Darwin enforces `location = "host"`.

Remaining items are implementation details for Phase 5, not open decisions:

- The cross-kind masquerade exception + `forward` accept that let a `trs1` container reach a
  `trs0` proxy VM while preserving the source IP.
- Placement of the proxy `accept` rule in the shared guest input chain (the priority bug).

---

## 9. Follow-ups (separate plans)

- **`ssh-agent-proxy` refactor** — dedicated plan.
- **`sudo-auth-proxy` refactor** — dedicated plan.
- **`clipboard-bridge` refactor** — dedicated plan.
- **`nix-service` fixes** — upstream against `./nix-service` if needed.

---

## 10. Credits

This project and two of its components (`ssh-agent-proxy`, `sudo-auth-proxy`) were
inspired by the work of **Floriant Guilbert** and the **mofos** project
(https://github.com/synacktiv/mofos). (`clipboard-bridge` is not derived from their work.)
A credits section must be added to the README.

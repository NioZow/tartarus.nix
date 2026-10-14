# Design rationale

> **Optional — not required reading.** The required docs cover everything you
> need to install, use and operate the project. Read this only if you want the
> reasoning behind the design.

## Who this is for

Curious readers and contributors who want to know *why* Tartarus is built the
way it is before changing it.

## What you'll learn

- why guests are built by the consumer's flake rather than bundled,
- why builds are lazy and the CLI reads a generated config,
- why the runtime knobs go through `builtins.getEnv` (`--impure`),
- why there are two guest kinds and where each is used.

## Engine, not content

Tartarus deliberately ships **no guest configuration**. Everything a guest
contains comes from the `systemConfig`/`userConfig` you pass in. This is the
"engine, not content" principle: the same engine serves a hardened network
appliance and a throwaway dev shell, because the content is the consumer's.

The alternative — bundling opinionated guest modules — would force every
consumer to either accept Tartarus's choices or fight them. Instead, `mkGuests`
runs in the **consumer's** flake, so the consumer's inputs, overlays, packages
and secrets are in scope during evaluation.

## Lazy, cached builds

A guest's closure can be large. Declaring a guest therefore adds a flake output
but realises nothing; the closure is built only when you ask. `start`, `build`,
`restart` and `spawn` then treat the build as a cache, reusing `state/result`
unless the flake changed since the build or you pass `--upgrade`. This keeps the
common case (start an already-built guest) fast and explicit.

## `config.toml` instead of the CLI locating the repo

The CLI is installed from the **consumer's** flake, so it cannot assume the
Tartarus repo is anywhere on disk. Instead, the host module renders the one file
the CLI needs — `~/.config/tartarus/config.toml` — through home-manager, which
is the mechanism that lands a file in the user's home on both NixOS and
nix-darwin. The CLI derives CID/IP/MAC from the recorded id locally, so it never
runs `nix eval` just to find a guest.

The "enabled guest" guard follows from this: presence in `config.toml` *is* the
"enabled on this host" predicate, because only `enable = true` guests are
written there. A disabled guest has no firewall rule, CA certificate or proxy
entry, so acting on one would be unsafe; the CLI refuses first.

## The deliberate impure interface

A few decisions genuinely depend on the invocation, not the flake: which
numbered instance is being spawned, which ad-hoc shares were passed, and which
host uid/home is invoking. Nix cannot see those at pure evaluation time, so the
engine reads them through `builtins.getEnv`. That is why the flake must be
evaluated with `--impure`. The payoff is that the *same* flake attribute can
produce a differently-configured instance per invocation without duplicating
attributes.

## Two guest kinds

A kernel boundary (`vm`) and a startup-time boundary (`container`) are different
tools. VMs give a real kernel (Docker, a graphical session, kernel-specific
code); containers give density and near-instant start. Rather than pick one,
Tartarus models both and makes the choice the `kind` field. On macOS, where
there is no host Linux kernel, containers run nested inside a container-host VM,
so the same declaration works on both platforms; `host` (or the host-wide
`tartarus.containers.containerHost`) decides where a container runs.

## Security defaults

- **mTLS or nothing.** The host/guest service channels are authenticated on both
  ends by the Tartarus X.509 CA; the `ssh`/`x509`/`signature` auth modes were
  removed so there is no weaker path to fall back to.
- **Read-only means read-only.** Because vfkit ignores a share's `readOnly`,
  macOS enforces it host-side by exporting a non-writable store snapshot, and
  Tartarus's own key-bearing shares opt out of snapshotting.
- **Proxy without MITM.** The Squid proxy does per-guest HTTPS/443 allowlisting
  without terminating TLS, so it can only ever see metadata.

See the [security model](./security-model.md) for the full picture and the
per-service threat models in [ssh-agent-proxy](./ssh-agent-proxy.md) and
[sudo-auth-proxy](./sudo-auth-proxy.md).

## Historical design notes

Two design documents capture the rationale and migrations for later changes:
[multi-transport server listeners](./design/transport-listeners.md) and
[removing the ssh-agent-proxy merge mode](./design/remove-merge-mode.md).

# Tartarus documentation

Tartarus turns a small declarative host option surface (`tartarus.guests.*`,
`tartarus.proxy`) into full NixOS guest systems — MicroVMs and systemd-nspawn
containers — built from **your** flake, plus a host firewall, an SSH/X509 CA, a
filtering HTTP proxy and a `tartarus` CLI to drive them.

This file is the single entry point. Everything else lives under
[`user/`](user/README.md) and [`technical/`](technical/README.md).

## Start here

New to Tartarus? Read these in order:

1. [Introduction](user/introduction.md) — what Tartarus is and the concepts it
   introduces.
2. [Installation](user/installation.md) — prerequisites and wiring the flake.
3. [Getting started](user/getting-started.md) — your first guest, end to end.

## User guide

- [Introduction](user/introduction.md) — concepts, guest kinds, mental model.
- [Installation](user/installation.md) — requirements, flake inputs, host module.
- [Getting started](user/getting-started.md) — configure and boot a first guest.
- [Usage](user/usage.md) — the `tartarus` CLI and common workflows.
- [Configuration](user/configuration.md) — every option, default and example.
- [Cheatsheet](user/cheatsheet.md) — one-page quick reference.

## Technical documentation

- [Technical overview](technical/README.md) — index of the technical docs.
- [Architecture](technical/architecture.md) — components, boundaries, data flow.
- [How it works](technical/how-it-works.md) — build/start/network lifecycles.
- [Data model](technical/data-model.md) — `config.toml`, ids, shares, schemas.
- [Interfaces](technical/interfaces.md) — `mkGuests`, modules, packages, CLI.

### Optional

- [Operations](technical/operations.md) — deploy, observe, troubleshoot, maintain.
- [Design rationale](technical/design-rationale.md) — why it is built this way.
- [Security model](technical/security-model.md) — trust boundaries and threats.

## Deep dives and references

Topic documents that go deeper than the guides above:

- [Shares and read-only enforcement](technical/shares.md)
- [Container-host VMs (nested nspawn)](technical/container-host.md)
- [ssh-agent-proxy](technical/ssh-agent-proxy.md)
- [sudo-auth-proxy](technical/sudo-auth-proxy.md)
- [Manual smoke list](technical/smoke.md)
- [Design notes](technical/design/) (`transport-listeners`, `remove-merge-mode`)

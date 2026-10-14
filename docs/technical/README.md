# Technical documentation

## Who this is for

Contributors, integrators and operators who need to understand **how** Tartarus
works: its components, its build and runtime lifecycles, the data it stores, and
the contracts it exposes. Read the [user documentation](../user/README.md) first
if you only want to run it.

## What you'll learn

- the components and how they fit together,
- what happens from `tartarus start` to a running guest,
- the `config.toml` schema, id assignment and share model,
- the public interfaces (`mkGuests`, NixOS/home-manager modules, packages, CLI).

## Required reading

- [Architecture](architecture.md) — components, boundaries, data flow.
- [How it works](how-it-works.md) — build, start and networking lifecycles.
- [Data model](data-model.md) — `config.toml`, ids, shares, TOML schemas.
- [Interfaces](interfaces.md) — `mkGuests`, modules, packages, CLI contract.

## Optional

- [Operations](operations.md) — deploy, observe, troubleshoot, maintain.
- [Design rationale](design-rationale.md) — why the design is the way it is.
- [Security model](security-model.md) — trust boundaries and threat landscape.

## Deep dives

- [Shares and read-only enforcement](shares.md) — `readOnly`, snapshots, secrets.
- [Container-host VMs](container-host.md) — nested nspawn, macOS container model.
- [ssh-agent-proxy](ssh-agent-proxy.md) — architecture, security, threat model.
- [sudo-auth-proxy](sudo-auth-proxy.md) — architecture, security, threat model.
- [Manual smoke list](smoke.md) — the per-platform manual test pass.
- [Design notes](design/) — `transport-listeners`, `remove-merge-mode`.

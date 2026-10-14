# User documentation

## Who this is for

People who want to **run** Tartarus: install it, declare guests in their own
flake, and use the `tartarus` CLI day to day. No knowledge of the internals is
assumed.

## What you'll learn

- what Tartarus is and the model behind it,
- how to install it and wire it into a NixOS/nix-darwin host,
- how to declare, start, and connect to your first guest,
- the full option surface and the everyday commands.

## Reading order

1. [Introduction](introduction.md) — concepts and vocabulary.
2. [Installation](installation.md) — prerequisites and flake wiring.
3. [Getting started](getting-started.md) — a first guest, end to end.
4. [Usage](usage.md) — the CLI and common workflows.
5. [Configuration](configuration.md) — every option, its default and an example.
6. [Cheatsheet](cheatsheet.md) — the one-page reference to keep open.

Working examples for the standalone services live in
[`examples/`](../../examples). The internals for contributors and operators are
in the [technical documentation](../technical/README.md).

# Design notes

## Who this is for

Contributors who want the reasoning and migration history behind two later
changes to Tartarus.

## What you'll learn

- how the multi-transport server listeners were designed and migrated,
- why the `ssh-agent-proxy` merge mode was removed and what replaced it.

## Documents

- [Multi-transport server listeners](transport-listeners.md) — the
  `listeners`/`listenerDefaults` schema shared by the sudo-auth-proxy and
  ssh-agent-proxy servers.
- [Removing the ssh-agent-proxy merge mode](remove-merge-mode.md) — why merge
  mode was removed and the replacement recipe.

See also the runtime-facing [ssh-agent-proxy](../ssh-agent-proxy.md) and
[sudo-auth-proxy](../sudo-auth-proxy.md) references.

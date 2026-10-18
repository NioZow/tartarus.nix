# Usage

## Who this is for

Users who have a working guest and want the day-to-day workflows: listing,
building, starting, entering, sharing and shutting down guests.

## What you'll learn

- the full `tartarus` command set and which commands are kind-specific,
- how the build cache and `--upgrade` behave,
- how to spawn extra instances, add ad-hoc shares and order startup,
- how the "enabled guest" guard protects you from acting on unknown guests.

## Inspecting guests

```bash
tartarus list                 # every enabled guest (VMs + containers)
tartarus list --vm            # only MicroVMs
tartarus list -c              # only containers (also: tartarus -c list)
tartarus list -t              # nest nested containers under their host VM
tartarus list --json          # machine-readable; -t adds a `children` list
tartarus status               # detailed status for all guests
tartarus status vault         # detailed status for one guest
```

Every JSON entry carries a `kind` field (`"vm"` or `"container"`), so scripts
can tell the two apart:

```bash
# ssh-reachable running guests: MicroVMs as <name>.trs, containers by name
tartarus list --json \
  | jq -r '.[] | select(.status=="running")
           | if .kind=="vm" then .name+".trs" else .name end'
```

## Building and starting

```bash
tartarus build vault          # build without starting (reuses an existing build)
tartarus start vault          # build if needed, then launch in the background
tartarus restart vault        # stop, then start
tartarus stop vault           # graceful shutdown
tartarus stop --purge vault   # ... and wipe the instance's state
```

`start`, `restart`, `spawn` and `build` treat a guest's build as a cache: they
reuse the existing `result` when it is valid, without re-evaluating or
re-realising the flake. Pass `-u/--upgrade` to force a fresh build; supplying
`--mount` also forces one, as does a missing or garbage-collected result. When a
reuse finds the flake changed since the build (its git `HEAD`, dirty tracked
files, or `flake.lock`), Tartarus prints a single line suggesting `--upgrade`.

## Entering a guest

```bash
tartarus ssh vault            # connect to a running guest
tartarus ssh vault -s         # ... starting it first if needed
tartarus logs vault           # console log (VM) / journal (container)
```

A guest that has just started may not have sshd listening yet (`socat ...
Connection reset by peer`). `ssh` therefore retries connection failures (ssh
exit status 255) 5 times, 2 seconds apart. Tune it per invocation with
`--retry N` / `--retry-delay SECONDS`, or persistently with
`tartarus.ssh.retries` / `tartarus.ssh.retryDelay` (rendered to `[ssh]` in
`config.toml`). Retries do not apply to authentication failures or to a remote
command's exit status.

For a MicroVM, the SSH helpers resolve the transport:

```bash
tartarus cid vault            # VSOCK CID (resolves running or not)
tartarus ip vault             # host-reachable IP (VM; native container)
tartarus proxy vault          # ProxyCommand helper (VSOCK)
tartarus proxy-ip vault       # ProxyCommand helper (vmnet IP, macOS)
```

`cid`, `proxy` and `proxy-ip` are **MicroVM-only** (VSOCK/vmnet) and have no
container equivalent. `ip` works for VMs and native containers; a nested
container has no host-reachable address and is refused.

## Extra instances

`spawn` launches an additional, independent instance of a template:

```bash
tartarus spawn vault          # auto-named vault-1, vault-2, ...
tartarus spawn vault --name scratch
```

Numbered instances (`vault-2`) and the `.trs` SSH suffix resolve back to their
base template, so every command accepts either name.

## Ad-hoc shares at launch

MicroVMs accept repeatable `--mount HOST_PATH:GUEST_PATH` shares at launch time:

```bash
tartarus start vault --mount ~/src:/home/user/src
```

`--mount` changes the generated derivation, so it forces a rebuild, and the
share is fixed at boot.

## Runtime mounts

To attach a host folder to an **already-running** guest without rebuilding or
restarting it, use `tartarus mount`:

```bash
tartarus mount dev ~/src:/home/user/src
tartarus mount dev ~/src:/home/user/src --read-only
tartarus mount dev ~/.config/foo:/home/user/.config/foo --overlay
tartarus unmount dev /home/user/src        # alias: umount
tartarus mounts                            # all guests
tartarus mounts dev --json
```

| Mode | Flag | Effect |
| --- | --- | --- |
| `rw` (default) | — | Read-write bind of the host folder. |
| read-only | `-r` / `--read-only` | Guest writes fail. |
| overlay | `--overlay` | Writable guest-local layer over a read-only host folder; the host folder is never written. The layer lives under `/run` (tmpfs), so it is runtime-only. |

`--read-only` and `--overlay` are mutually exclusive. Runtime mounts are
**runtime-only**: they disappear on stop/restart and are not persisted or
re-applied. `restart` drops both launch-time and runtime mounts.

Runtime mounts work for Linux MicroVMs and native containers. They are
**refused** for macOS/vfkit MicroVMs (vfkit has no device hotplug or bind
mounts) and for nested containers (the host source is not visible inside the
container-host VM). The first use on an existing VM needs one rebuild/restart
to install the guest helper and staging share:

```bash
tartarus restart <name> -u
```

For containers, `--no-idmap` forces a plain bind instead of an idmapped mount;
ownership may then appear as `nobody`/`nogroup` inside the container.

The spec is `HOST_PATH:GUEST_PATH`, split on the first colon (colons in paths
are therefore unsupported). The host path must be an existing directory; `~/`
on either side expands, but on the guest side `~` means the guest home
(`/home/user`), not the host user's home. The guest path must be absolute
after expansion (or start with `~/`) and may not be `/`, `/proc`, `/sys`,
`/dev` or `/run/tartarus-mount`. The host staging directory lives under
`<state_root>/<name>/mounts` and is guest-writable — do not put secrets there.
See [Shares](../technical/shares.md#runtime-mount-staging-share) for the
mechanism.

## Dependencies and autostart

A guest can require others, and Tartarus starts dependencies first:

```nix
tartarus.guests.app = {
  enable = true;
  requires = [ "db" ];      # `db` must also be an enabled guest
};
```

`requires` must be acyclic and reference enabled guests; `tartarus start app`
starts `db` first. Set `autostart = true` on a guest to start it on login via a
tartarus user service:

```bash
systemctl --user status tartarus-autostart-<name>
```

## Proxy-only guests

A guest can route all egress through the host proxy instead of the NAT, with a
per-guest HTTPS/443 allowlist:

```nix
{
  tartarus.proxy.enable = true;             # global transport config
  tartarus.guests.locked = {
    enable = true;
    internet = false;                       # mutually exclusive with the proxy
    proxy = {
      enable = true;                        # requires the global enable
      allowHosts = [ "example.com" ];
    };
  };
}
```

The guest gets `http_proxy`/`https_proxy`/`all_proxy` (upper and lower case) in
`~/.config/environment.d/10-tartarus.conf`. DNS (53), SSH (22) and plain HTTP
(80) are dropped for a proxy-only guest; the allowlist is HTTPS/443 only. See
the [configuration reference](./configuration.md#tartarusproxy) for
`tartarus.proxy.location` (host- or guest-hosted).

## The "enabled guest" guard

Every command that names a guest first checks that the name is an enabled guest
on this host, before any build, state-dir creation or SSH. A disabled or unknown
name fails cleanly:

```
error: guest "ghost" is not enabled on this host; set `tartarus.guests.ghost.enable = true` (kind = "vm") in your configuration and rebuild (tartarus rebuild / darwin-rebuild / nixos-rebuild).
```

The CLI learns the guest set from the generated `config.toml`, which contains
only guests with `enable = true`. This guard exists because a disabled guest has
no host firewall rules, CA certificate or proxy entries.

## Containers

Commands that name a guest infer its kind from `config.toml`, so no flag is
needed:

```bash
tartarus start box            # routed to the container path automatically
```

Use the global `--container` flag when a command is ambiguous, or for the
kind-specific `list` filter:

```bash
tartarus --container start box
tartarus --container ssh box
```

A few commands behave differently for nested containers (a container running
inside a container-host VM): `ssh` jumps through the host VM, `start`/`build`
delegate to it, and `stop`/`restart`/`logs`/`spawn` refuse with guidance. See
[container-host VMs](../technical/container-host.md).

## Standalone service helpers

`sudo-auth-proxy`, `ssh-agent-proxy` and `clipboard-bridge` can be driven
without any guest — see their deep-dive docs and
[`examples/`](../../examples). They are wired into a guest automatically when it
sets the matching `services.*` flag (for example `services.sshAgentProxy =
true`).

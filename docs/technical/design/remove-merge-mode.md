# Design: remove the `ssh-agent-proxy` merge mode

Status: proposed · Scope: `packages/tartarus.nix` (the `tartarus` submodule)
Touches: `nix/packages/ssh-agent-proxy/*`, `nix/guest/default.nix`, `tests/*`,
`examples/*`, `docs/*`, `README.md`

This document is a technical specification, not code. It is written so that
independently assignable engineer tasks (§7) can implement it in parallel with
disjoint file ownership.

---

## 1. Summary & motivation

`ssh-agent-proxy` ships two things that overlap:

- a **proxy server** (`mode = "proxy"`) that binds one or more listeners, owns
  the real agent sockets, applies per-key/per-identity `rule` policy and asks
  the human before a key is used;
- a separate **merge mode** (`mode = "merge"`, historically `--merge`/`--listen`)
  that binds a single local AF_UNIX socket and, with **no** policy, fans several
  upstream agent sockets into it allow-all.

Merge is therefore a degenerate proxy: it is the proxy with no identity, no
rules, no dialog, several upstream `agent_sockets`, one `unix` listener, and
"allow everything". Maintaining a second code path (`MergeHandler`,
`run_merge`, `_merge_upstream_paths`, `_peer_env_socket`, `MERGE_UPSTREAM_TIMEOUT`,
`merge_sockets`) duplicates identity enumeration, de-duplication and forwarding
logic that the proxy already implements, and it adds a mode whose semantics
diverge subtly from the proxy's.

**Goal.** Remove merge mode entirely and document merging as a normal **proxy
server** configuration: a local `unix` listener plus `settings.agent_sockets`
plus a wildcard `rule` that allows everything. The user-facing recipe becomes
"run a proxy whose transport is a local socket and whose rule allows all".

Keeping merge only for a niche "merge two static agents on one host" use case
costs a whole mode, its CLI, its Nix role and its docs; the proxy already does
it.

---

## 2. Decisions

### D1 — Remove **merge mode only** (resolved)

Keep `mode` with the values `"proxy"` and `"client"`. Only the `"merge"` value,
the merge-specific CLI flags and the merge Nix role are removed. The client's
`listen_socket` stays (it is the bridge's listen path), and the client
`--listen` deprecation shim is removed with the merge flags.

### D2 — Merge-only features: directory scan & per-session resolution (per-listener, opt-in)

Merge has two behaviours the proxy does not have:

1. **Directory scanning.** A `merge.sockets` entry may be a *directory*; it is
   scanned non-recursively **on every client connection** for socket files, so
   per-session forwarded sockets are picked up as they appear without a
   restart. This is the only mode on macOS and the fallback on Linux
   (`_merge_upstream_paths`, `ssh-agent-proxy.py:2094`).
2. **Per-session resolution (`SSH_AUTH_PROXY_SOCK`).** On Linux, for an
   `AF_UNIX` peer, merge reads the connecting process's pid/uid via
   `SO_PEERCRED`, requires the same uid, then reads `SSH_AUTH_PROXY_SOCK` from
   `/proc/<pid>/environ` and uses that **exact** socket — only this session's
   forward. When resolved, directory entries are not scanned (the exact socket
   replaces the broad union). macOS exposes only a uid (`getpeereid`), so there
   is no `/proc` equivalent and it relies on the directory scan
   (`_peer_env_socket`, `ssh-agent-proxy.py:2053`).

Neither exists in the proxy: `settings.agent_sockets` is resolved once at
config load (`ssh-agent-proxy.py:570`) and connected directly in
`Handle.handle` (`ssh-agent-proxy.py:1683`); a directory entry simply fails to
`connect()`.

> Note: the Nix option `settings.agent_sockets` already *claims* "A directory
> entry is scanned per connection" (`nix/packages/ssh-agent-proxy/default.nix:380`),
> but the proxy does not implement that — the claim is currently false and is a
> documentation/spec bug regardless of this decision.

#### Challenges if we **port** these into the proxy

1. **Global policy vs a local-only mechanism.** `agent_sockets` is shared by
   *every* listener (vsock/tcp/unix). Directory scanning across sessions is only
   safe for a same-uid local AF_UNIX listener; applying it to a `vsock`/`tcp`
   listener would union sockets across guests, which is exactly the
   over-collection risk the old threat model flagged (T24/R5). Porting therefore
   needs a **per-listener** flag (e.g. `scanDirectories`/`resolveAgentSockets`),
   not a blanket `agent_sockets` behaviour — otherwise the "merge" semantics leak
   into the general server and widen exposure.
2. **Identity coupling.** The `/proc/<pid>/environ` read is a same-uid,
   host-local primitive; a vsock/tcp peer has no pid. The merge handler is
   deliberately policy-free, whereas `Handle` resolves identity *first*
   (`ssh-agent-proxy.py:1590`) and only then builds `allowed_sockets`
   (`ssh-agent-proxy.py:1617`). Grafting per-connection resolution means
   re-ordering `Handle.setup`/`handle` and deciding how a per-session upstream
   interacts with rule matching (identity is `None` on a local `unix + none`
   listener, so wildcard-only matching still holds).
3. **De-duplication & routing semantics differ.** The proxy de-dups identities by
   `(blob, comment)` and routes a sign request back to the key's origin socket
   (`real_agents.get(k_cfg.socket)`, `ssh-agent-proxy.py:1818`). Merge de-dups by
   `realpath` and relays a non-identities request to the first upstream that
   answers non-`FAILURE`. A port must preserve the proxy's per-key routing and
   not silently break the origin-socket association when upstreams are resolved
   dynamically.
4. **macOS asymmetry.** `_peer_env_socket` is Linux-only; macOS needs the
   directory path. Any port must keep both and stay testable on both.
5. **Test surface.** `_merge_upstream_paths` has two focused tests
   (`tests/test_ssh_agent_proxy.py:281,298`) plus the short merge timeout
   constant (`MERGE_UPSTREAM_TIMEOUT`, `ssh-agent-proxy.py:151`). Porting needs
   new per-connection/ambiguity tests; dropping removes them.

#### What `/proc/<pid>/environ` is for

`_peer_env_socket` exists to answer **"which upstream does *this* connection
want?"** on the `unix` transport. There, the host `ssh` forwards the server
socket into the guest with a **per-session, per-connection** path
(`/run/ssh-agent-proxy/<token>.sock`) and exports that path as
`SSH_AUTH_PROXY_SOCK` via `SetEnv`. A static `agent_sockets` list cannot name
that token. So, on Linux, merge looks up the connecting client's pid/uid with
`SO_PEERCRED`, then reads `SSH_AUTH_PROXY_SOCK` out of `/proc/<pid>/environ` and
uses **that exact socket** — the client's own session forward, and nothing else.
It is a same-uid host-local selector, not an authentication primitive.

macOS cannot do this (`getpeereid` returns only a uid, there is no `/proc`), so
macOS always uses the directory scan; on Linux the scan is only the fallback for
when the peer environment cannot be read.

#### Does it solve the challenges?

Partly — it is a replacement for **directory scanning in the common case**, but
it does not make the general proxy safe or complete:

- It resolves the *right* upstream for a **same-uid local Linux AF_UNIX** peer,
  so a per-session forward no longer needs a directory scan.
- It is only ever relevant on a **local AF_UNIX** listener. Merge was *always* a
  local unix socket, so this is not a gap in the feature: the point is that the
  flag must be rejected on `vsock`/`tcp` so a mixed-listener proxy cannot apply
  it there (see the scoping problem below).
- On **macOS** the directory scan still works and is the only mechanism; it is
  the `/proc` *selector* that is Linux-only. So macOS is served by
  `scanAgentSocketDirs`, not by `resolveSessionSocket`.
- It does **not** cover a socket that appears/disappears between sessions and is
  not named in the caller's environment — that is still the directory scan.
- It keeps merge's R6 caveat: a same-uid process can point at another socket,
  and a pid reused between `accept()` and the `/proc` read can yield a stale
  path. It is a convenience selector, not a boundary.

So `/proc/<pid>/environ` is a per-connection *selector*, not a substitute for
the per-listener scoping the challenge is about.

#### The scoping problem, precisely

`settings.agent_sockets` is a **global** (server-wide) list, shared by every
listener of the one proxy process. But directory scanning / the peer-env
selector only make sense for a **same-uid local AF_UNIX** listener. A single
proxy process may bind a `vsock` listener *and* a `unix` listener at once; if
the scan/session behaviour were attached to the global `agent_sockets` list, a
`vsock`/`tcp` client would also receive the expanded union of every socket in the
directory — over-collection across guests, i.e. the T24/R5 risk. Hence the
*list* stays in `settings`, but the *resolution strategy* (`scanAgentSocketDirs` /
`resolveSessionSocket`) is attached to the individual `unix` listener and
defaults off. That is all "scoping" means.

#### When is directory scanning done?

From `_merge_upstream_paths` (`nix/packages/ssh-agent-proxy/ssh-agent-proxy.py:2094`),
**per client connection**, not at startup:

- An entry in the upstream list is a **directory** → it is scanned
  (non-recursive) for socket files *now*; non-socket children are ignored; an
  absent entry contributes nothing.
- …**and** no authoritative per-session socket was found. If
  `_peer_env_socket` resolved the caller's `$SSH_AUTH_PROXY_SOCK` (Linux,
  same-uid), that exact socket is added first and **directories are not
  scanned** — the exact socket replaces the broad union
  (`ssh-agent-proxy.py:2133-2141`).
- On macOS there is no peer-env selector, so the directory scan is the **only**
  path whenever a directory entry is present.
- A literal socket path is used as-is; only directories are scanned.

#### Recommended design: a per-listener opt-in

Make the local-only behaviour explicit and **off by default**, scoped to the
listener that wants it:

```nix
transports = [{
  type = "unix";
  socket = "%t/ssh-agent-merged";
  resolution = "none";
  # New, both default false, only meaningful for `type = "unix"`.
  scanAgentSocketDirs = true;   # expand directory entries in agent_sockets per connection
  resolveSessionSocket = true;  # Linux only: prefer the peer's $SSH_AUTH_PROXY_SOCK
  security = {transportEncryption = "none"; clientAuth = "none"; serverAuth = "none";};
}];
```

- `scanAgentSocketDirs` ports `_merge_upstream_paths` (directory expansion,
  realpath de-dup, absent entries skipped) into `Handle`'s upstream resolution,
  **per connection**, and only for listeners that set it. A `vsock`/`tcp`
  listener defaults to `false`, so the T24 over-collection risk never leaks into
  the general server.
- `resolveSessionSocket` ports `_peer_env_socket` (Linux, same-uid,
  `SO_PEERCRED` + `/proc/<pid>/environ`) and takes precedence over the directory
  scan, exactly as merge did. It is a no-op on `vsock`/`tcp`/macOS (logged, not
  fatal).
- The `unix` listener is the default (and only sensible) owner; enabling either
  flag on a non-`unix` listener is rejected at eval time and at load.

This keeps the feature for the standalone/SSH-forwarded case while removing the
"one global mode" duplication and the false `agent_sockets` docstring. The plan
below is written for this **per-listener opt-in** (Phase 1b/2/5).

### D3 — Legacy configs fail loudly (recommended)

A config or CLI that still requests merge must fail with an actionable error
pointing at the proxy recipe, consistent with the repo's "fail loudly rather
than bind the wrong transport" convention
(`docs/technical/ssh-agent-proxy.md` §11). Concretely: `mode = "merge"`, a `merge_sockets`
key, or `--merge`/`--listen` produce a hard error; they are not silently mapped.

---

## 3. Replacement recipe (what the docs will tell users)

Merging N agents = a proxy server that binds one local socket and allows all
keys without prompting. `auth = "allow"` is silent (`ssh-agent-proxy.py:1813`);
`data_signing = "allow"` matches merge's blind forwarding; `notify = false`
avoids a notification per use.

### 3.1 Standalone TOML (`examples/ssh-agent-proxy-merge.toml`)

```toml
# Merge several agents into one local socket: a proxy server whose transport is
# a local unix socket and whose rule allows everything (no identity, no dialog).
mode = "proxy"

# Upstream agents to fan in. No key/rule needs to pre-list them: sockets named
# here are probed and their identities admitted opportunistically.
agent_sockets = ["%t/ssh-agent", "%t/gnupg/S.gpg-agent.ssh"]

# Allow all keys, for auth and data signing, without a prompt.
[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
notify = false

[[transports]]
type = "unix"
socket = "%t/ssh-agent-merged"
resolution = "none"

[transports.security]
transport_encryption = "none"   # local socket, same uid -> identity is unset
client_auth = "none"
server_auth = "none"
```

Then:

```sh
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/ssh-agent-merged"
```

### 3.2 home-manager (host or guest)

```nix
tartarus.ssh-agent-proxy.server = {
  enable = true;
  settings = {
    agent_sockets = ["%t/ssh-agent" "%t/gnupg/S.gpg-agent.ssh"];
    rule = [{key = "*"; auth = "allow"; data_signing = "allow"; notify = false;}];
  };
  transports = [{
    type = "unix";
    socket = "%t/ssh-agent-merged";
    resolution = "none";
    security = {transportEncryption = "none"; clientAuth = "none"; serverAuth = "none";};
  }];
  setSshAuthSock = true;   # new option, see Phase 2
};
```

### 3.3 Guest wiring (what `nix/guest/default.nix` does internally)

The guest merges its local agent (`%t/ssh-agent`) with the host-forwarded bridge
(`%t/ssh-agent-host`) and points `SSH_AUTH_SOCK` at the merged socket. That is
exactly the §3.2 config with those two paths.

---

## 4. Current merge surface (for reference)

Python (`nix/packages/ssh-agent-proxy/ssh-agent-proxy.py`):
`MERGE_UPSTREAM_TIMEOUT` (143-151), `Config.merge_sockets` (375, 494),
`_peer_env_socket` (2053), `_merge_upstream_paths` (2094), `MergeHandler` (2157),
`run_merge` (2492), `--mode` `"merge"` choice (2700), `--merge`/`--listen`
(2705-2714) and their handling (2720-2731, 2742-2748); module/`AgentIO`
docstrings (22, 1473).

Of these, `_peer_env_socket` and `_merge_upstream_paths` are **ported** (kept,
generalized and reused by the proxy behind the per-listener flags), not deleted.

Nix (`nix/packages/ssh-agent-proxy/default.nix`):
header comment (1-13), `merge = { … }` options (586-612), `merge = cfg.merge`
(870), `mergeSockets`/`mergeListen`/`mergeEnv` (961-983), `mkIf merge.enable`
service (1042-1049).

Wiring: `nix/guest/default.nix:167-173`.

Docs: `docs/technical/ssh-agent-proxy.md` §7 (288-314), TOC (17), roles table (63),
§2/§3 mentions (135, 197), threats T10/T24 (370, 384), residuals R5/R6
(401-408), standalone contract (425-427), compatibility (448), glossary (470);
`README.md:339,426-431`; `docs/technical/smoke.md:241`;
`docs/design/transport-listeners.md:343,820,1176`.

Tests: `tests/test_ssh_agent_proxy.py:19-20,271-315`.

---

## 5. Work breakdown

Independently assignable tasks; file ownership is disjoint per task.

### Phase 1 — Python (`nix/packages/ssh-agent-proxy/ssh-agent-proxy.py`)
1. Remove `"merge"` from `--mode` choices (2700); remove `--merge` (2705) and
   `--listen` (2710); remove the `args.merge`/`args.listen` block (2720-2731) and
   the `if mode == "merge"` branch (2742-2748).
2. Remove `Config.merge_sockets` (375, 494). Keep the short upstream connect
   timeout, renamed `MERGE_UPSTREAM_TIMEOUT` → `UPSTREAM_TIMEOUT` (143-151), now
   used by the proxy's per-connection resolution.
3. Remove `MergeHandler` (2157-…) and `run_merge` (2492-…).
4. Update the module docstring (22) and the `AgentIO` docstring (1473) that
   mention merge.
5. (D3) Reject a legacy `mode = "merge"` or a `merge_sockets` key in `load()`
   with an error naming the proxy recipe; ensure `--merge`/`--listen` are gone
   (argparse then rejects them with a usage error).

### Phase 1b — Port the merge-only resolution into the proxy (per-listener)
1. Generalize `_merge_upstream_paths` (2094-…) into
   `_resolve_agent_sockets(entries, *, scan_dirs, session_socket)` and reuse it
   from `Handle`; keep `_peer_env_socket` (2053-…) as the Linux selector.
2. Add `ListenerConfig.scan_agent_socket_dirs` / `resolve_session_socket`
   (default `false`), parsed in `_parse_listener`/`_parse_listener_from_flat`,
   and reject them on a non-`unix` listener.
3. In `Handle.handle` (1683), replace the static `allowed_sockets` upstream loop
   with a per-connection call to `_resolve_agent_sockets(self.config.agent_sockets,
   scan_dirs=…, session_socket=… when resolve_session_socket)`, falling back to
   the static list when both flags are off. Preserve the proxy's per-key
   origin-socket routing (`real_agents.get(k_cfg.socket)`, 1818).

### Phase 2 — Nix module (`nix/packages/ssh-agent-proxy/default.nix`)
1. Delete the `merge = { … }` options (586-612), `merge = cfg.merge` (870),
   `mergeSockets`/`mergeListen`/`mergeEnv` (961-983) and the `mkIf merge.enable`
   service (1042-1049); update the header comment (1-13).
2. Add `server.setSshAuthSock` (bool, default `false`), mirroring the bridge
   option, and emit an `environment.d` file pointing `SSH_AUTH_SOCK` at the
   server's listener socket when enabled. Needed so a local allow-all proxy can
   replace merge's `setSshAuthSock` in the guest.
3. Add the per-listener opts to `sshListenerOptions`: `scanAgentSocketDirs` and
   `resolveSessionSocket` (bool, default `false`), documented as `unix`-only, and
   add an eval assertion rejecting them on a `vsock`/`tcp` listener. Reword the
   `settings.agent_sockets` description (374-384) to point at
   `scanAgentSocketDirs` instead of claiming the scan is always on.

### Phase 3 — Guest wiring (`nix/guest/default.nix:167-173`)
Replace `merge = {...}` with a local `tartarus.ssh-agent-proxy.server` (§3.3):
`agent_sockets = ["%t/ssh-agent" "%t/ssh-agent-host"]`, the allow-all rule, one
`unix` listener `%t/ssh-agent-merged`, and `setSshAuthSock = true`. Set a
distinct `server.configPath` (e.g. `~/.config/ssh-agent-proxy/server.toml`) so it
does not collide with the bridge's default `…/config.toml`.

### Phase 4 — Docs + example
1. Rewrite `docs/technical/ssh-agent-proxy.md` §7 as "Merging agents with a local proxy
   server" using §3; update the TOC (17), roles table (63), §2/§3 mentions (135,
   197), threats T10/T24 (370, 384), residuals R5/R6 (401-408), standalone
   contract (425-427), aliases/compatibility (448) and glossary (470). Reword
   T24/R5/R6 to say the scan/session resolution applies "only when enabled on a
   `unix` listener" instead of describing a global mode.
2. `README.md`: change the module cell "(server, bridge, agent, merge)" →
   "(server, bridge, agent)" (339); add the merge-via-proxy snippet to the
   standalone paragraph (426-431); reference the new example.
3. `docs/technical/smoke.md:241`: drop `merge` from the module list.
4. `docs/design/transport-listeners.md`: update the "`run_merge`/`.merge.*`
   unchanged" notes (343, 820, 1176).
5. Add `examples/ssh-agent-proxy-merge.toml` (§3.1) and reference it in README.

### Phase 5 — Tests
1. Retarget the merge bullet (`tests/test_ssh_agent_proxy.py:19-20`) and
   `test_merge_upstream_paths_*` (281-315) at the new
   `_resolve_agent_sockets(scan_dirs=…)` API (directory scan, non-socket
   children ignored, absent entries skipped, realpath de-dup, session socket
   short-circuit).
2. Add a proxy test proving allow-all merge semantics: an AF_UNIX proxy listener
   with two upstream fake agents, `agent_sockets = [a, b]`, a wildcard
   `auth="allow"`/`data_signing="allow"` rule → `REQUEST_IDENTITIES` returns the
   union and a `SIGN_REQUEST` succeeds with no dialog.
3. Add a test that `scanAgentSocketDirs`/`resolveSessionSocket` expand upstreams
   per connection on a `unix` listener, and that they are rejected on a
   `vsock`/`tcp` listener (eval + load).
4. Add a test that `mode="merge"` (and a `merge_sockets` key) is rejected.
5. Add a shipped-example test that `examples/ssh-agent-proxy-merge.toml` loads.
6. `tests/suite.nix`: add/extend an eval check that the new guest local-proxy
   config evaluates and that the `.merge.*` option no longer exists.

---

## 6. Verification

- `uv run pytest tests/test_ssh_agent_proxy.py -q`, then the full suite.
- `nix build .#ssh-agent-proxy`; run the flake `checks` if present.
- Eval the guest system (Nix eval suite) — the guest must still expose both the
  local agent's and the host-forwarded keys via the merged socket.
- `rg -i 'merge_sockets|mode.*merge|--merge|MergeHandler|run_merge|ssh-agent-merge|\.merge\.' nix/ src/ tests/ examples/ README.md docs/technical/ssh-agent-proxy.md docs/technical/smoke.md`
  returns only unrelated "deep-merge" hits (exclude `docs/design/` — this file
  names them on purpose).

---

## 7. Risks / regressions

- **Directory scan + per-session `SSH_AUTH_PROXY_SOCK` become opt-in** (D2). The
  behaviour is retained behind the per-listener `scanAgentSocketDirs` /
  `resolveSessionSocket` flags (default off, `unix` only); T24/R5/R6 are reworded
  to say "only when enabled on a `unix` listener" instead of describing a global
  mode.
- **Guest local proxy is a full proxy process** with rules, not the policy-free
  merge handler. Verify no dialog appears (`auth="allow"` + `notify=false`) and
  that per-key sign routing still reaches the correct upstream.
- **Config-path collision**: bridge and server both default to
  `…/ssh-agent-proxy/config.toml`; the guest must keep them distinct (Phase 3).
- **Legacy configs break by design** (D3) and must fail with a migration pointer.

---

## 8. Acceptance criteria

1. No merge mode remains: the `rg` in §6 returns no functional hits.
2. The standalone TOML example parses and merges two agents over a local socket
   with no prompts.
3. The guest's merged `SSH_AUTH_SOCK` still exposes both the local agent's and
   the host-forwarded keys.
4. `README.md` and `docs/technical/ssh-agent-proxy.md` document "merge = allow-all local
   proxy"; the module table no longer lists `merge`.
5. Tests and flake checks pass.

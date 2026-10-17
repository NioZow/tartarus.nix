# ssh-agent-proxy — Architecture, Security Model & Threat Model

This document is the threat-model companion to the service implemented in
`nix/packages/ssh-agent-proxy/`. It mirrors the structure of
[`sudo-auth-proxy.md`](./sudo-auth-proxy.md) and shares its authentication
model: **mTLS is the only cryptographic authentication mechanism**, and the
same `[security]`/`[mtls]` shape is used.

## Table of contents

1. [Introduction and scope](#1-introduction-and-scope)
2. [Roles and topologies](#2-roles-and-topologies)
3. [Transports](#3-transports)
4. [The `unix` transport in detail](#4-the-unix-transport-in-detail)
5. [Identity = resolution](#5-identity--resolution)
6. [The `[security]` model](#6-the-security-model)
7. [Merging several agents](#7-merging-several-agents)
8. [Socket and file permissions](#8-socket-and-file-permissions)
9. [Threat model](#9-threat-model)
10. [Standalone contract](#10-standalone-contract)
11. [Compatibility and aliases](#11-compatibility-and-aliases)
12. [Glossary](#12-glossary)

---

## 1. Introduction and scope

### 1.1 What it does

`ssh-agent-proxy` is a single-process agent *broker*. One config lists both
**listeners** (inbound sockets peers connect to) and **upstreams** (outbound key
sources). It owns the real agent sockets, applies a per-key/per-identity policy
and asks the human before a key is used. Guests reach it over one of three
transports (below). There is **no `mode`** and no client/server split: an
upstream may be a local AF_UNIX agent (`unix`) *or* a remote proxy reached over
`vsock`/`tcp`, so merging several agents -- including one reached remotely --
into one local socket is a normal proxy configuration: bind a local `unix`
listener and list the sources in `[[upstream]]` (§7). The old guest-side
*bridge* is exactly "a local `unix` listener + one remote upstream".

### 1.2 Goals

- Expose selected host identities to selected guests, by public-key identity and
  by per-guest identity, with an explicit human decision by default.
- Work **standalone** with only the package and plain `ssh -R` — no tartarus,
  no nixcfg, no state directory.
- Never silently weaken: an mTLS transport cannot fall back to plaintext, and an
  unauthenticated peer can only ever match wildcard rules.

### 1.3 Non-goals

- It is not a general-purpose key manager; it forwards the agent protocol.
- It does not authenticate *host* users to the guest; it forwards identities
  the host already has.
- It does not provide per-*service* certificate isolation (see §6.3, the OID
  caveat inherited from `ca.py`).

---

## 2. Roles and topologies

One process is a broker; its config has two kinds of endpoint:

| Kind | Direction | What it is |
| ---- | --------- | ---------- |
| *listener* (`[[listeners]]`) | inbound | an accepted socket (`vsock`/`tcp`/`unix`); the peer has an *identity* and `rule`s decide what it may do |
| *upstream* (`[[upstream]]`) | outbound | a key source the process dials (a unix agent socket, or a remote proxy over `vsock`/`tcp`); its identities are merged for every connection |

Every historical role is a special case of this (there is no `mode`):

| Role | Endpoints |
| ---- | --------- |
| Server | several listeners + local unix upstreams |
| Bridge (deprecated) | one unix listener + one remote upstream, allow-all |
| Merge | one unix listener + N unix upstreams, allow-all |
| Agent | the real `ssh-agent` (a unix upstream) |

A guest can reach the server two ways:

- **callback** (`vsock`, `tcp`): the guest dials the host. A source address
  (CID or IP) exists, so an external name resolver (`tartarus`/`mofos`) or a
  static table can name the peer.
- **host-dials-guest** (`unix`): the host `ssh` carries an
  `ssh -R` RemoteForward of the server's AF_UNIX listener socket into the guest.
  No address exists on the host socket.

The server may expose **several listeners at once** — one per `listeners` entry
(§3) — so a single host can offer callback to a container and `unix` to a remote
guest at the same time. It may also dial **several upstreams at once** (of any
transport), which is what lets one guest-side process merge its own local agent
with the host's agent reached over vsock (§7) — no separate bridge service.

---

## 3. Transports

Each **listener** is an entry in `tartarus.ssh-agent-proxy.server.listeners`;
its `type` selects the transport, and the server binds one listener per entry —
any mix, any number. Every entry is **self-contained**: a field it omits falls
back to the built-in default (there is no `[listener_defaults]` block).

| `type` | direction | listener binds | guest side | identity sources |
| ------ | --------- | -------------- | ---------- | ---------------- |
| `vsock` | guest → host | AF_VSOCK port | `upstream` (dialed) | `none`/`certificate`/`tartarus`/`mofos` |
| `tcp` | guest → host | TCP host:port | `upstream` (dialed) | `none`/`certificate`/`tartarus`/`mofos` |
| `unix` | host → guest | AF_UNIX socket | forwarded socket or `upstream` | `none`/`certificate` only |

No listener names a guest: identity comes from the listener's `resolution` (and
only `certificate`/`none` are meaningful on `unix`), never from the socket path.
Multiple listeners of the same `type` are allowed (e.g. two `unix` listeners with
different `socket` paths).

The same three transports describe an **upstream** (`[[upstream]]` entries share
the listener transport/`[security]`/`[mtls]` fields): a `unix` upstream dials a
local agent socket, while a `vsock`/`tcp` upstream dials a *remote* proxy
listener and merges its identities. An upstream has no inbound identity of its
own — it only supplies keys.

### 3.1 Multiple listeners and the shared policy

Unlike the bridge, the server binds a **list** of listeners in one process:

```nix
tartarus.ssh-agent-proxy.server = {
  enable = true;
  settings = { /* vm, tcp_vm, key, rule, agent_sockets, ... -- global */ };
  listeners = [
    { type = "vsock"; cid = 2; resolution = "tartarus";
      security = {transportEncryption = "none";
                  clientAuth = "none"; serverAuth = "none";}; }
    { type = "unix";  socket = "%t/ssh-agent-proxy/server.sock";
      resolution = "certificate";
      security = {transportEncryption = "mtls";
                  clientAuth = "transport"; serverAuth = "transport";}; }
  ];
};
```

- `resolution` is **per listener**: `certificate` for a `unix` listener, and
  `tartarus`/`mofos` only for the callback types. An unset listener defaults to
  `certificate` when it is mTLS and `none` otherwise.
- The `settings` freeform (the `vm`/`tcp_vm` id maps, `key`, `rule`,
  `agent_sockets`, `known_hosts_files`,
  `libvirt_uri`) stays **global** — shared policy parsed once by the Python, not
  per listener. `settings.vm` / `settings.tcp_vm` are **always emitted** (even
  for a `unix`-only server): a server may carry a `vsock`/`tcp` listener
  alongside the `unix` one, so the CID/IP maps must always be present for the
  callback listeners to resolve names.
- Binding is all-or-nothing: every listener is bound (and every mTLS context
  built) before any serves; a failure exits non-zero and no listener serves.
  Runtime failures stay per listener.

`unix` has two sub-modes:

- **`unix + transport_encryption = "none"`** — transparent: the guest's
  `SSH_AUTH_SOCK` points straight at the forwarded socket (or at a local
  allow-all proxy that merges it with others). No crypto. Identity is **unset**,
  so only wildcard rules match.
- **`unix + transport_encryption = "mtls"`** — the guest's proxy server dials the
  forwarded socket as a `unix` **upstream** and wraps the stream in TLS; the host
  server terminates it. Identity is the verified client-certificate CN, so
  per-guest `machine` rules keep working.

### 3.2 Listeners and their names

Terminology: a **listener** is (a bind to) a socket — an AF_UNIX path, an AF_VSOCK
port, or a TCP `host:port`. A listener's `type` is its **transport** (the "how");
the listener itself is the "where". Each `[[listeners]]` entry is one listener,
and a legacy flat `mode`+`transport` document is one implicit listener.

A listener **may** be given a `name`:

```nix
tartarus.ssh-agent-proxy.server.listeners = [
  { type = "unix"; name = "merge";        socket = "%t/ssh-agent-merged"; ... }
  { type = "unix"; name = "remote-guest"; socket = "%t/…/server.sock";     ... }
  { type = "vsock"; cid = 2; resolution = "tartarus"; }  # unnamed
];
```

Names are optional but must be unique across the server. A named listener can be
selected by a rule with `match.listeners` (§5.3); an **unnamed** listener matches
only a rule whose listener selector is empty or made exclusively of `*` patterns.
Names are labels only: they never affect the bind target or the identity.

---

## 4. The `unix` transport in detail

### 4.1 `unix + none` — transparent

```
guest: client (ssh/git) ──▶ /run/ssh-agent-proxy/<tok>.sock   (AF_UNIX)
                                    │  guest sshd, as guest user, from -R
                                    ▼
                             SSH channel (host→guest)
                                    │
host:                        ssh ──▶ %t/ssh-agent-proxy/server.sock
                                          │ (the unix listener's socket, all sessions)
                                          ▼
                                     server (resolution = none)
```

The host binds `%t/ssh-agent-proxy/server.sock`, mode `0600` in a `0700`
directory. `StreamLocalBindUnlink` replaces a stale forwarded socket; a
per-session random token in the guest path keeps two sessions from stealing each
other's forward (harmless if it collides: all forwards reach the same host
server, and identity is never derived from the path). No port is opened, so
there is no firewall change.

### 4.2 `unix + mtls` — TLS inside the SSH tunnel

`ssh` speaks the raw agent protocol and will never do TLS, so the guest's
ssh-agent-proxy **server** performs the handshake as an outbound `unix` upstream;
the host server performs the other end. The layering is **TLS over the SSH
channel** — no separate bridge process.

```
guest: client (ssh/git) ─connect─▶ %t/ssh-agent-merged (local unix listener)
                                        │ guest server merges the local agent
                                        │ with the host upstream
                                        ▼
                                  forwarded socket (sshd-created, plain)
                                        │  unix upstream, TLS client-side
                                        ▼  SSH channel (host→guest)
host:                            ssh ─connect─▶ %t/ssh-agent-proxy/server.sock
                                                  │ server wraps TLS (server_side)
                                                  ▼
                                             mTLS handshake: client CN = identity
```

Steps:

1. Host server: `transport = "unix"`, `transport_encryption = "mtls"`,
   `[mtls]` with the host server cert, `resolution = "certificate"`. It accepts
   AF_UNIX and wraps each connection server-side.
2. The operator runs `ssh -R <guest_sock>:%t/ssh-agent-proxy/server.sock` (plus
   `StreamLocalBindUnlink`, `ExitOnForwardFailure`, and
   `SetEnv=SSH_AGENT_PROXY_SOCK=<guest_sock>`).
3. Guest server: a `[[upstream]]` with `transport = "unix"`, no `socket`
   (it falls back to `$SSH_AUTH_PROXY_SOCK` at connect time),
   `transport_encryption = "mtls"`, `[mtls]` with the guest client cert, plus a
   local unix listener. `SSH_AUTH_SOCK` points at that listener, which merges
   the upstream with the guest-local agent. Identity = client CN → `machine`
   rules work.

### 4.3 ControlMaster is safe

Multiplexed sessions (`ControlMaster auto` + `ControlPath`) share the master's
`-R` and `SetEnv`. Because identity comes from a certificate (or nothing), and
never from per-connection process/port state, multiplexed sessions present the
same guest cert and are handled identically. The host keeps `ControlMaster`,
`ControlPath`, `StreamLocalBindUnlink` and `ExitOnForwardFailure` unchanged.

---

## 5. Identity = resolution

`resolution` is the single place a connecting peer is turned into an identity.

| `resolution`  | identity used for `machine` matching | valid transports | self-contained? |
| ------------- | ------------------------------------- | ---------------- | --------------- |
| `none`        | **unset** (wildcard rules only)       | all              | yes |
| `certificate` | verified mTLS peer CN                 | all (needs mTLS) | yes |
| `tartarus`    | local VM bookkeeping by CID/IP        | `vsock`/`tcp`    | needs state dir |
| `mofos`       | `mofos ls --json` by CID/`ipv4_address` | `vsock`/`tcp`  | needs `mofos` binary |

Defaults (per listener): `certificate` when mTLS is on, else `none`.

### 5.1 Display label vs matching identity

The two are deliberately separate:

- the **display label** is always a non-empty human string used in
  logs/dialogs/notifications (`unknown-cid-7`, `unknown-ip-1.2.3.4`, `local`);
- the **matching identity** is `Optional[str]` and is `None` whenever no identity
  was established.

### 5.2 Wildcard-only rule for `none`

`Rule.matches_machine(None)` returns true **only** when the selector is empty or every
pattern is `*`. A specific `machine` pattern can never match an unauthenticated
peer. This makes `unix + none` (and any unresolved peer) safe by construction:
it can only use keys whose rules are deliberately world-scoped.

`tartarus`/`mofos` are rejected at load on `unix` — there is no CID or IP to map.

### 5.3 Rules, listeners and `match.listeners`

A `[[rule]]` matches a (key, identity, listener) triple — the key selector
(`key`), the VM selector (`match.machine`) and the listener selector
(`match.listeners`). Rules are evaluated in file order; the first match wins and
fully defines the policy (no merging).

`match.listeners` is a name pattern (or list of `fnmatch` patterns) matched
against the accepting listener's `name` (§3.2):

- an **empty** selector matches every listener, named or unnamed;
- a **specific** pattern (`["merge"]`) matches only a listener named so, and
  never an unnamed listener;
- a selector made **exclusively of `*`** matches any listener, including an
  unnamed one (the same wildcard-only rule as `match.machine` under an
  unauthenticated peer, §5.2).

```nix
settings.rule = [
  # the local allow-all merge socket: silent, everything allowed
  { key = "*"; match.listeners = ["merge"]; auth = "allow";
    data_signing = "allow"; add = "allow"; remove = "allow"; notify = false; }
  # the SSH-forwarded remote guest: prompt, any named peer
  { key = "*"; match.listeners = ["remote-guest"]; match.machine = ["*"];
    auth = "ask"; }
  # everything else, including the unnamed callback listener, is denied
  { key = "*"; auth = "deny"; data_signing = "deny"; }
];
```

### 5.4 Per-operation policy

A rule carries four independent policies, each `"deny" | "ask" | "allow"`:

| field | governs |
| ----- | ------- |
| `auth` | `SSH_AGENTC_SIGN_REQUEST` used for SSH authentication (default `ask`) |
| `data_signing` | `SSH_AGENTC_SIGN_REQUEST` for arbitrary data (default `deny`) |
| `add` | `SSH_AGENTC_ADD_IDENTITY` / `_CONSTRAINED` — `ssh-add` (default `deny`) |
| `remove` | `SSH_AGENTC_REMOVE_IDENTITY` / `REMOVE_ALL_IDENTITIES` — `ssh-add -d`/`-D` (default `deny`) |

`add`/`remove` are matched against the mutated key's id: a configured `key`
entry's id when the public blob is known, else the key's comment (or, for
`REMOVE_ALL_IDENTITIES`, the wildcard selector `*`). The proxy stores no keys:
an authorized add is forwarded to the **first connected `agent_sockets` entry**
(the documented default agent), which holds the private key in memory for the
session; removal is forwarded to the same target. `SSH_AGENTC_ADD_IDENTITY`
transmits the private key over the agent socket — the client reads it from disk,
the upstream agent keeps it in RAM. Both default to `deny`, so a key can never
be injected into (or removed from) an agent unless a rule explicitly allows it.

---

## 6. The `[security]` model

Each **listener** has its own `[security]` block with three knobs plus bounds,
identical in shape to sudo-auth-proxy:

| key | values | meaning |
| --- | ------ | ------- |
| `transport_encryption` | `auto`/`none`/`mtls` | channel crypto; `auto` = tcp→mtls, vsock/unix→none |
| `client_auth` | `transport`/`none` | server authenticating the requester |
| `server_auth` | `transport`/`none` | client authenticating the server |

Bounds: `connect_timeout`, `handshake_timeout`, `decision_timeout`.

### 6.1 No downgrade

- `mtls.enable = true` is the legacy alias for
  `transport_encryption = "mtls"`; a config that sets both inconsistently is
  rejected at load (and, for the Nix modules, at evaluation).
- Under mTLS both auth knobs are forced to `transport`; a `transport` auth
  without mTLS is rejected.
- `create_ssl_context` decides from the resolved `transport_encryption`, never
  from `mtls.enable` alone, so a misconfigured transport cannot silently return
  a plaintext socket.
- The fail-closed pairing is asserted at eval (Nix) and re-validated at load
  (Python).

### 6.2 Per-transport defaults

| transport | default `transport_encryption` |
| --------- | ------------------------------ |
| `unix` | `none` |
| `vsock` | `none` |
| `tcp` | `mtls` (an explicit `[security]`; a legacy config with no `[security]` stays plaintext) |

### 6.3 EKU OIDs

OIDs (private enterprise number 99999) separate the server role from the client
role, not one service from another: `ca.py` mints the host cert with all three
server OIDs and a guest client cert with all three client OIDs. `socket`/`unix`
deployments use `1.3.6.1.4.1.99999.2.1` (server) and `...2.2` (client). The
`scripts/tartarus-certs.sh` tooling mirrors this and can restrict to a single
service with `--service`.

---

## 7. Merging several agents

Merging N agents into one local socket is a normal proxy configuration, not a
mode: bind a local `unix` listener, list the sources in `[[upstream]]` (or the
legacy `agent_sockets` string list), and allow everything with a wildcard rule.

```toml
mode = "proxy"
agent_sockets = ["%t/ssh-agent", "%t/gnupg/S.gpg-agent.ssh"]

[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"   # matches the old merge's blind forwarding
add = "allow"            # ssh-add through the merged socket (default deny)
remove = "allow"         # ssh-add -d / -D through the merged socket
notify = false

[[listeners]]
type = "unix"
socket = "%t/ssh-agent-merged"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
```

Then `export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/ssh-agent-merged"`. The
home-manager equivalent (`settings.rule`, one `listeners` entry,
`setSshAuthSock = true`) is the guest wiring in §3.3 of the design doc; the
single shipped example, `examples/ssh-agent-proxy-server.toml`, includes this
merge socket as its `"merge"` listener.

`ssh-add` through the merged socket needs `add = "allow"` (and `remove` for
`ssh-add -d`/`-D`) on the wildcard rule — both default to `deny` (§5.4). The
added key is forwarded to the first upstream (the real `ssh-agent`); the merge
proxy itself stores nothing, so the key lives in that agent's memory and is gone
when the agent restarts.

### 7.1 Merging a *remote* agent (no client/server split)

An upstream may also be a **remote** proxy reached over `vsock`/`tcp`, so one
process can merge its own local agent with the host's agent — the case the old
`mode = "client"` bridge needed a second service for. There is still no bridge:
it is one `[[listeners]]` entry plus two `[[upstream]]` entries.

```toml
[[upstream]]
transport = "unix"
socket = "%t/ssh-agent"

[[upstream]]
transport = "vsock"
cid = 2
port = 65000

[upstream.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
add = "allow"
remove = "allow"
notify = false

[[listeners]]
type = "unix"
name = "merge"
socket = "%t/ssh-agent-merged"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
```

A `unix` upstream is dialed per client connection (so per-session forwarded
sockets keep resolving); a `vsock`/`tcp` upstream is a single pooled connection
(one handshake, reused, transparently reconnected on drop). `mode = "client"` is still
accepted but deprecated (§11), and is translated to exactly this shape: one unix
listener + one remote upstream + an allow-all rule.

In `unix` mode a per-session host socket cannot be named by a static list, so the
identity enumeration is resolved **per client connection** when the `unix`
listener opts in:

- **`resolveSessionSocket` (Linux only): the session's own socket.** The
  connecting process's pid/uid is read from `SO_PEERCRED`, the uid must match,
  then `SSH_AUTH_PROXY_SOCK` is read from `/proc/<pid>/environ` and that exact
  socket is used. Only this session's forward is merged.
- **`scanAgentSocketDirs`: directory scan (macOS always; Linux fallback).** A
  `settings.agent_sockets` entry that is a directory is scanned (non-recursively)
  on every connection, so sockets that appear/disappear between sessions are
  tracked without a restart. Non-socket children are ignored; absent entries are
  skipped.

Both flags default to `false` and are rejected on a non-`unix` listener (there is
no same-uid local peer and the union would span guests). When the session socket
is resolved it is added first and directories are not scanned (the exact socket
replaces the broad union). Deduplication is by resolved real path (a socket
reached via both a directory and a literal entry is connected once) and by
public-key blob (a sign request is relayed to the first upstream that answers
non-`FAILURE`).

`SSH_AUTH_PROXY_SOCK` serves double duty: it is the selector the standalone
single-socket case exports (`SSH_AUTH_SOCK=$SSH_AUTH_PROXY_SOCK`) and the variable
`resolveSessionSocket` reads. No per-session merge daemon and no login hook are
needed.

Platform note: an AF_UNIX peer on macOS exposes only a uid (`getpeereid`), no
pid, so there is no `/proc` equivalent — macOS relies on the directory scan.

---

## 8. Socket and file permissions

- The host server socket is `0600` in a `0700` directory owned by the host user.
  The umask is held at `0177` across `bind()`, then the mode is set explicitly
  and verified; a symlink or a non-socket/foreign-owned bind target is refused,
  and only a socket we own is unlinked.
- A same-uid local process can reach the socket; same-uid is the approver,
  accepted as in sudo's model (the `0600` socket is the real guard).
- On `unix`, an accepted peer's uid is checked (`SO_PEERCRED` on Linux,
  `getpeereid`/`LOCAL_PEERCRED` on macOS) as defence-in-depth. Linux fails closed
  on a foreign uid; macOS degrades to the socket mode/ownership guarantee when no
  uid can be read. No `/proc`, no peer-process attestation, no guest identity is
  ever derived from the OS.
- Private keys are `0600`; certificates are `0644`.

---

## 9. Threat model

### 9.1 Assets

- **A1** The host's SSH private keys (never leave the host agent).
- **A2** The authority to sign an SSH authentication or data-signing request.
- **A3** The approver's attention and the integrity of a decision.
- **A4** The confidentiality of the agent protocol contents.

### 9.2 Adversaries

- **ADV1** A malicious guest user with no host access.
- **ADV2** A malicious or compromised guest root (owns the guest's key material
  and the guest-side proxy).
- **ADV3** A different local host user (blocked by the `0700`/`0600` paths and
  the peer-uid check).
- **ADV4** A network attacker on a callback transport (blocked by mTLS when
  enabled; the callback channel is otherwise private by construction).
- **ADV5** A same-uid local process on the host (accepted; it is the approver).
- **ADV6** A confused-deputy/retarget attempt (a same-uid process redirecting a
  client to a different legitimate tunnel).

### 9.3 Threats and mitigations

| # | Threat | Mitigation |
| - | ------ | ---------- |
| T1 | Forged sign response from a guest | mTLS server auth, or private callback transport |
| T2 | Session-bind replay | Bind signatures are verified against the host key/CA and matched per session id |
| T3 | Key theft via guest root | Keys never leave the host; only signatures cross |
| T4 | Unauthorized key exposure | Identity + `rule` matching; auto-registered keys default to `DEFAULT_RULE` (ask) |
| T5 | Host-key allow-list bypass | `allowed_host_keys` only accepts verified session-binds; fail closed |
| T6 | Dialog flood / attention exhaustion | Notification on refusal; no anti-fatigue (documented residual, §9.5) |
| T7 | Unauthenticated peer using a specific rule | **Wildcard-only rule**: identity is `None`, specific `machine` never match |
| T8 | mTLS downgrade to plaintext | `transport_encryption` resolves once; `create_ssl_context` cannot return plaintext under mTLS |
| T9 | Foreign local user reaching the socket | `0700` dir + `0600` socket + peer-uid check |
| T10 | Malicious `agent_sockets` union (allow-all merge) | The merge is allow-all by design; dedup by realpath; no rules to bypass |
| T11 | Path traversal via `%t`/`~` expansion | Placeholders expanded explicitly; bind targets checked |
| T12 | Oversized agent message | Length cap (`MAX_AGENT_MSG_LEN`) before allocation |
| T13 | Slowloris / hung upstream | Connect/handshake/decision timeouts; short upstream identity timeout |
| T14 | Certificate role confusion | EKU OID check per side (server vs client) |
| T15 | Guest path stealing another session's forward | Per-session random token; identity never from the path |
| T16 | Stale socket reuse | `StreamLocalBindUnlink`; only a socket we own is unlinked |
| T17 | ControlMaster identity confusion | Identity from cert/none, never per-connection state |
| T18 | Tampering with the forwarded stream | TLS over the SSH channel (`unix + mtls`) |
| T19 | Downgrade by omitting `[security]` | Lenient only for legacy plaintext callback; never for an explicit mTLS transport |
| T20 | Signing arbitrary data | `data_signing` defaults to `deny` |
| T21 | Misconfigured transport silently insecure | Asserted at eval and re-validated at load |
| T22 | Peer name spoofing | `tartarus`/`mofos` are cosmetic, never gate; `certificate` is verified |
| T23 | Host-key confusion via a cert | The cert's embedded CA is the trust blob; signature verified against the per-host key |
| T24 | Directory scan over-collection | Only an allow-all `unix` listener opts in; for one host user all forwarded sockets reach the same server, and the broader union is still allow-all |
| T25 | macOS without a uid credential | Degrade to mode/ownership; do not treat "unavailable" as allowed |
| T26 | Enumeration of identities | Only ruled/forwarded keys are listed |
| T27 | Replay of a forwarded socket | Per-session token + SSH channel binding |
| T28 | Tampering with the human dialog | The dialog shows display labels only; the decision is on verified material |
| T29 | Key injection into a host agent (`ssh-add` from a guest) | `rule.add` defaults to `deny`; only an explicit `allow`/`ask` rule for the verified identity + listener forwards the add to the default agent |
| T30 | Key removal / agent state tampering (`ssh-add -d`/`-D`) | `rule.remove` defaults to `deny`; only an explicit rule forwards the removal |

### 9.4 Residual risks (accepted)

- **R1** A same-uid host process can reach the `0600` server socket (accepted:
  same-uid is the approver).
- **R2** `tartarus`/`mofos` are best-effort cosmetic lookups, never gates.
- **R3** `unix + none` is session-bound (no tunnel ⇒ no agent) and wildcard-only:
  any guest reaching the forward can use any wildcard-allowed key. Use
  `unix + mtls` (or a callback transport with `tartarus`/`mofos`/`certificate`)
  when per-guest isolation is required.
- **R4** `unix + mtls` needs two guest sockets — the local listener that
  `SSH_AUTH_SOCK` points at, and the forwarded socket it dials as a `unix`
  upstream; the host binds one `unix` listener socket for that transport.
- **R5** A directory scan on a `unix` listener scans all sockets in the directory
  at connect time; if a directory mixed sockets pointing at different servers the
  union would span them (still allow-all, but broader than one session). Only a
  listener that opts into `scanAgentSocketDirs` is affected.
- **R6** Linux peer attribution (`SO_PEERCRED` pid → `/proc/<pid>/environ`) is a
  same-uid lookup; a same-uid process can point at another socket, and a pid
  reused between `accept()` and the read could yield a stale path. The merge is
  allow-all and the directory fallback is no narrower, so this is not a
  boundary.
- **R7** No dialog anti-fatigue/rate-limiting (an approver may be worn down).
- **R8** EKU OIDs do not isolate services from one another (inherited from
  `ca.py`, §6.3).

---

## 10. Standalone contract

`ssh-agent-proxy` works with only the package and plain `ssh`:

- Server: `mode = "proxy"`, `transport = "unix"`,
  `socket = "%t/ssh-agent-proxy/server.sock"`, `resolution = "none"` (or
  `certificate` + `[security]`/`[mtls]`), `agent_sockets`, `key`/`rule`.
- Guest: `ssh -R /run/ssh-agent-proxy/<tok>.sock:%t/ssh-agent-proxy/server.sock`,
  then either set `SSH_AUTH_SOCK` to the forwarded path (`none`), or run the proxy
  server with a `unix` **upstream** (no `socket`, so it reads
  `$SSH_AUTH_PROXY_SOCK`) and `transport_encryption = "mtls"`.
- Merging: a local `unix` listener with `agent_sockets = ["%t/ssh-agent",
  "%t/ssh-agent-proxy"]` (local agent + the forwarded-socket directory) and a
  wildcard `rule`; set `scanAgentSocketDirs` (and/or `resolveSessionSocket` on
  Linux) to pick up the session's own socket per connection.
- `resolution = "tartarus"`/`"mofos"` are the only tartarus/mofos-coupled bits
  and are optional; on `unix` they are rejected by design.

The server may instead declare a `[[listeners]]` list (one self-contained entry
per listener, §3.1); a flat `mode`+`transport` document is kept as one implicit
listener for compatibility. The deprecated
`mode = "client"` bridge is still accepted (it is translated to one `unix`
listener plus one remote `[[upstream]]`), but the guest side is now just a
`[[upstream]]` on an ordinary server.

Binding a `vsock` listener on the host requires the `vhost_vsock` module. Without
it, the bind to host CID 2 fails with `EADDRNOTAVAIL` (errno 99) until a VM
starts and loads it. The tartarus NixOS host module loads `vhost_vsock`
automatically when an enabled VM requests a vsock host service. On a standalone
NixOS host, load it at boot with `boot.kernelModules = [ "vhost_vsock" ];`. On a
Debian host, load it now with `sudo modprobe vhost_vsock` and persist it with
`printf 'vhost_vsock\n' | sudo tee /etc/modules-load.d/vhost_vsock.conf`.

See `examples/ssh-agent-proxy-server.toml`.

---

## 11. Compatibility and aliases

**Nix (server).** The flat server options are **removed with no aliases**:
`tartarus.ssh-agent-proxy.server.{transport,host,port,cid,socket,socketDirMode,
socketMode,connectTimeout,handshakeTimeout,decisionTimeout,resolution,security,
mtls}` are gone. Migrate to `server.listeners = [ { type = …; … } ]`, each entry
**self-contained** (a field it omits falls back to the built-in default); a
partially-migrated config fails evaluation loudly rather than binding the wrong
transport. The bridge/agent options are unchanged (one transport each). The
**merge role is removed**: the `tartarus.ssh-agent-proxy.merge.*` options and
the `mode = "merge"` / `merge_sockets` / `--merge` / `--listen` CLI are gone and
now fail loudly; use the allow-all local proxy of §7 instead. The
`transports`/`transport_defaults` keys were renamed to `listeners` and now fail
loudly too, and the removed `[listener_defaults]` block is refused as well.

**Python (legacy config).** Existing `config.toml`s keep working: a document
with no `listeners` array is read as one implicit listener.

- `vsock_port` / `tcp_bind` → derive `transport` (`vsock`/`tcp`) and log a
  deprecation warning.
- `mtls.*` → alias onto `[security] transport_encryption = "mtls"` + `[mtls]`.
- `bridge.vsockCid` / `vsockPort` / `host` / `port` keep working;
  `bridge.connectSocket` is the new `unix` dial path.
- `agent_sockets` (a list of unix socket strings, or tables) stays valid and is
  the legacy spelling of the `[[upstream]]` array; `[[upstream]]` entries are
  ordered first, then `agent_sockets`.
- `mode = "client"` still loads but is **deprecated** and logged: it is
  translated to a local `unix` listener + one remote `[[upstream]]` + an
  allow-all rule (§7.1). `mode = "proxy"` (or no `mode`) is the unified form.
- The Python schema accepts the legacy keys.

---

## 12. Glossary

- **callback transport** — the guest dials the host (`vsock`, `tcp`).
- **listener** — one bound socket the server accepts on (an AF_UNIX path, an
  AF_VSOCK port, or a TCP `host:port`); one `[[listeners]]` entry. Its `type`
  is its transport. Optionally named, for `rule.match.listeners`.
- **host-dials-guest** — the host `ssh` forwards its socket into the guest
  (`unix`), so the server dials the guest through SSH.
- **upstream** — one outbound key source the broker dials; one `[[upstream]]`
  entry. A `unix` upstream is a local agent socket; a `vsock`/`tcp` upstream is a
  remote proxy listener (its identities are merged). `agent_sockets` is the
  legacy spelling.
- **bridge** — DEPRECATED: `mode = "client"`, now expressed as a local `unix`
  listener + one remote upstream (+ an allow-all rule); still accepted and
  translated (§7.1, §11).
- **merge** — an allow-all local proxy: a `unix` listener whose upstreams list
  several agents and whose wildcard rule allows every key (§7).
- **resolution** — how a connecting peer is named / identified.
- **display label** — the human string shown in logs/dialogs.
- **matching identity** — the `Optional[str]` used for rule matching (`None` when
  unset).

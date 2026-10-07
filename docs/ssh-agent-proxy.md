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
7. [The merge proxy](#7-the-merge-proxy)
8. [Socket and file permissions](#8-socket-and-file-permissions)
9. [Threat model](#9-threat-model)
10. [Standalone contract](#10-standalone-contract)
11. [Compatibility and aliases](#11-compatibility-and-aliases)
12. [Glossary](#12-glossary)

---

## 1. Introduction and scope

### 1.1 What it does

`ssh-agent-proxy` brokers the host's SSH identities to guests. The host side
(the *server*, `mode = "proxy"`) owns the real agent sockets, applies a
per-key/per-identity policy and asks the human before a key is used. Guests
reach it over one of three transports (below), optionally through a guest-side
*bridge* (`mode = "client"`) that terminates mTLS inside the SSH tunnel. A
separate allow-all *merge* mode (`--merge`) fans several agent sockets into one
local socket.

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

| Role | Process | Where |
| ---- | ------- | ----- |
| Server | `ssh-agent-proxy` `mode = "proxy"` | host (owns the keys) |
| Bridge | `ssh-agent-proxy` `mode = "client"` | guest (`unix + mtls`) |
| Merge | `ssh-agent-proxy --merge` | guest (or host) |
| Agent | `ssh-agent` | host and/or guest |

A guest can reach the server two ways:

- **callback** (`vsock`, `tcp`): the guest dials the host. A source address
  (CID or IP) exists, so an external name resolver (`tartarus`/`mofos`) or a
  static table can name the peer.
- **host-dials-guest** (`unix`): the host `ssh` carries an
  `ssh -R` RemoteForward of the server's single AF_UNIX socket into the guest.
  No address exists on the host socket.

---

## 3. Transports

| `transport` | direction | host listens on | guest side | identity sources |
| ----------- | --------- | --------------- | ---------- | ---------------- |
| `vsock` | guest → host | AF_VSOCK port | bridge | `none`/`certificate`/`tartarus`/`mofos` |
| `tcp` | guest → host | TCP host:port | bridge | `none`/`certificate`/`tartarus`/`mofos` |
| `unix` | host → guest | **one** AF_UNIX socket | forwarded socket or bridge | `none`/`certificate` only |

There is exactly **one host server socket in every mode**. No listener names a
guest: identity comes from `resolution` (and only `certificate`/`none` are
meaningful on `unix`).

`unix` has two sub-modes:

- **`unix + transport_encryption = "none"`** — transparent: the guest's
  `SSH_AUTH_SOCK` points straight at the forwarded socket (or at a merge proxy
  that includes it). No bridge, no crypto. Identity is **unset**, so only
  wildcard rules match.
- **`unix + transport_encryption = "mtls"`** — the guest runs the bridge, which
  wraps the forwarded stream in TLS; the server terminates it. Identity is the
  verified client-certificate CN, so per-guest `vm_names` rules keep working.

---

## 4. The `unix` transport in detail

### 4.1 `unix + none` — one socket, transparent

```
guest: client (ssh/git) ──▶ /run/ssh-agent-proxy/<tok>.sock   (AF_UNIX)
                                    │  guest sshd, as guest user, from -R
                                    ▼
                             SSH channel (host→guest)
                                    │
host:                        ssh ──▶ %t/ssh-agent-proxy/server.sock
                                          │ (one socket, all sessions)
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

`ssh` speaks the raw agent protocol and will never do TLS, so the guest **bridge**
performs the handshake; the host server performs the other end. The layering is
**TLS over the SSH channel**.

```
guest: ssh ─connect─▶ bridge.listen (%t/ssh-agent-host, plain)     [socket 1]
                            │ bridge = ssh-agent-proxy --mode client
                            ▼
                      forwarded socket (sshd-created, plain)       [socket 2]
                            │
                            ▼  SSH channel (host→guest)
host:                 ssh ─connect─▶ %t/ssh-agent-proxy/server.sock
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
3. Guest bridge: `transport = "unix"`, `connect_socket` = the forwarded path (or
   `$SSH_AGENT_PROXY_SOCK`), `listen_socket = %t/ssh-agent-host`,
   `transport_encryption = "mtls"`, `[mtls]` with the guest client cert.
4. `SSH_AUTH_SOCK` points at the bridge listener (or a merge that includes it).
   Identity = client CN → `vm_names` rules work.

### 4.3 ControlMaster is safe

Multiplexed sessions (`ControlMaster auto` + `ControlPath`) share the master's
`-R` and `SetEnv`. Because identity comes from a certificate (or nothing), and
never from per-connection process/port state, multiplexed sessions present the
same guest cert and are handled identically. The host keeps `ControlMaster`,
`ControlPath`, `StreamLocalBindUnlink` and `ExitOnForwardFailure` unchanged.

---

## 5. Identity = resolution

`resolution` is the single place a connecting peer is turned into an identity.

| `resolution`  | identity used for `vm_names` matching | valid transports | self-contained? |
| ------------- | ------------------------------------- | ---------------- | --------------- |
| `none`        | **unset** (wildcard rules only)       | all              | yes |
| `certificate` | verified mTLS peer CN                 | all (needs mTLS) | yes |
| `tartarus`    | local VM bookkeeping by CID/IP        | `vsock`/`tcp`    | needs state dir |
| `mofos`       | `mofos ls --json` by CID/`ipv4_address` | `vsock`/`tcp`  | needs `mofos` binary |

Defaults: `certificate` when mTLS is on, else `none`.

### 5.1 Display label vs matching identity

The two are deliberately separate:

- the **display label** is always a non-empty human string used in
  logs/dialogs/notifications (`unknown-cid-7`, `unknown-ip-1.2.3.4`, `local`);
- the **matching identity** is `Optional[str]` and is `None` whenever no identity
  was established.

### 5.2 Wildcard-only rule for `none`

`Rule.matches_vm(None)` returns true **only** when the selector is empty or every
pattern is `*`. A specific `vm_names` pattern can never match an unauthenticated
peer. This makes `unix + none` (and any unresolved peer) safe by construction:
it can only use keys whose rules are deliberately world-scoped.

`tartarus`/`mofos` are rejected at load on `unix` — there is no CID or IP to map.

---

## 6. The `[security]` model

`[security]` has three knobs plus bounds, identical in shape to sudo-auth-proxy:

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

## 7. The merge proxy

The merge proxy (`--merge`) aggregates several upstream agent sockets into one
allow-all local socket. In `unix` mode the host socket is per-session, so a
static list cannot name it; upstreams are resolved **per client connection**:

- **Linux (preferred): the session's own socket.** `_peer_env_socket` takes the
  connecting process's pid/uid from `SO_PEERCRED`, requires the same uid, then
  reads `SSH_AUTH_PROXY_SOCK` from `/proc/<pid>/environ` and uses that exact
  socket. Only this session's forward is merged.
- **Directory scan (macOS always; Linux fallback).** A `merge.sockets` entry that
  is a directory is scanned (non-recursively) on every connection, so sockets
  that appear/disappear between sessions are tracked without a restart.
  Non-socket children are ignored; absent entries are skipped.

When the Linux session socket is resolved it is added first and directories are
not scanned (the exact socket replaces the broad union). Deduplication is by
resolved real path (a socket reached via both a directory and a literal entry is
connected once) and by public-key blob (a sign request is relayed to the first
upstream that answers non-`FAILURE`).

`SSH_AUTH_PROXY_SOCK` serves double duty: it is the selector the standalone
no-merge case exports (`SSH_AUTH_SOCK=$SSH_AUTH_PROXY_SOCK`) and the variable the
Linux resolution reads. No per-session merge daemon and no login hook are needed.

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
  and the bridge).
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
| T7 | Unauthenticated peer using a specific rule | **Wildcard-only rule**: identity is `None`, specific `vm_names` never match |
| T8 | mTLS downgrade to plaintext | `transport_encryption` resolves once; `create_ssl_context` cannot return plaintext under mTLS |
| T9 | Foreign local user reaching the socket | `0700` dir + `0600` socket + peer-uid check |
| T10 | Malicious `merge.sockets` union | The merge is allow-all by design; dedup by realpath; no rules to bypass |
| T11 | Path traversal via `%t`/`~` expansion | Placeholders expanded explicitly; bind targets checked |
| T12 | Oversized agent message | Length cap (`MAX_AGENT_MSG_LEN`) before allocation |
| T13 | Slowloris / hung upstream | Connect/handshake/decision timeouts; short merge identity timeout |
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
| T24 | Directory merge over-collection | For one host user all forwarded sockets reach the same server; broader union is still allow-all |
| T25 | macOS without a uid credential | Degrade to mode/ownership; do not treat "unavailable" as allowed |
| T26 | Enumeration of identities | Only ruled/forwarded keys are listed |
| T27 | Replay of a forwarded socket | Per-session token + SSH channel binding |
| T28 | Tampering with the human dialog | The dialog shows display labels only; the decision is on verified material |

### 9.4 Residual risks (accepted)

- **R1** A same-uid host process can reach the `0600` server socket (accepted:
  same-uid is the approver).
- **R2** `tartarus`/`mofos` are best-effort cosmetic lookups, never gates.
- **R3** `unix + none` is session-bound (no tunnel ⇒ no agent) and wildcard-only:
  any guest reaching the forward can use any wildcard-allowed key. Use
  `unix + mtls` (or a callback transport with `tartarus`/`mofos`/`certificate`)
  when per-guest isolation is required.
- **R4** `unix + mtls` still has two guest sockets (bridge listener + forwarded);
  the host has exactly one.
- **R5** A directory merge scans all sockets in the directory at connect time; if
  a directory mixed sockets pointing at different servers the merge would union
  them (still allow-all, but broader than one session).
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
  `certificate` + `[security]`/`[mtls]`), `forward_sockets`, `key`/`rule`.
- Guest: `ssh -R /run/ssh-agent-proxy/<tok>.sock:%t/ssh-agent-proxy/server.sock`,
  and either set `SSH_AUTH_SOCK` to the forwarded path (`none`) or run the bridge
  with `connect_socket` = that path and `transport_encryption = "mtls"`.
- Merging: `merge_sockets = ["%t/ssh-agent", "%t/ssh-agent-proxy"]` (local agent
  + the forwarded-socket directory); the boot-time merge picks up the session's
  socket per connection.
- `resolution = "tartarus"`/`"mofos"` are the only tartarus/mofos-coupled bits
  and are optional; on `unix` they are rejected by design.

See `examples/ssh-agent-proxy-server.toml` and
`examples/ssh-agent-proxy-client.toml`.

---

## 11. Compatibility and aliases

Nothing breaks at evaluation or in existing `config.toml`s:

- `vsock_port` / `tcp_bind` → derive `transport` (`vsock`/`tcp`) and log a
  deprecation warning.
- `mtls.*` → alias onto `[security] transport_encryption = "mtls"` + `[mtls]`.
- `bridge.vsockCid` / `vsockPort` / `host` / `port` keep working;
  `bridge.connectSocket` is the new `unix` dial path.
- The Python schema accepts the legacy keys.

---

## 12. Glossary

- **callback transport** — the guest dials the host (`vsock`, `tcp`).
- **host-dials-guest** — the host `ssh` forwards its socket into the guest
  (`unix`), so the server dials the guest through SSH.
- **bridge** — the guest-side `mode = "client"` process that relays the agent
  protocol and (with mTLS) terminates the TLS handshake.
- **merge** — the allow-all aggregator (`--merge`).
- **resolution** — how a connecting peer is named / identified.
- **display label** — the human string shown in logs/dialogs.
- **matching identity** — the `Optional[str]` used for rule matching (`None` when
  unset).

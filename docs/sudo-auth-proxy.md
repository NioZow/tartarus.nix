# sudo-auth-proxy — Architecture, Security Model & Threat Model

**Status:** design document (reviewed by `audit` and `challenger` before
implementation; see `plans/sudo-auth-proxy-redesign.md`).
**Audience:** operators of tartarus guests/hosts and reviewers of this service.

> This document is the **source of truth** for *what* `sudo-auth-proxy` is and
> *how it is expected to work*. The companion
> [`plans/sudo-auth-proxy-redesign.md`](plans/sudo-auth-proxy-redesign.md)
> describes *how* the redesign is implemented and in what order.

> **⚠️ Default posture: a soft gate, not a hard gate.** In the default
> configuration a human `deny` and an `unavailable` transport both *fall
> through* to the next PAM method. If the guest also offers a local password, a
> user can enter it after a deny and still elevate. The proxy is **never** a hard
> gate unless every other auth method is disabled — and even then, `pam_exec.so`
> cannot distinguish a deliberate `deny` from `unavailable`, so a truly
> non-ignorable deny needs the native PAM module of §17. See §10.3 for the full
> discussion. Do not deploy this as a sole control.

---

## Table of contents

1. [Introduction and scope](#1-introduction-and-scope)
2. [Roles and topologies](#2-roles-and-topologies)
3. [Transports, and the two call directions](#3-transports-and-the-two-call-directions)
4. [The SSH-forwarded Unix transport in detail](#4-the-ssh-forwarded-unix-transport-in-detail)
5. [Identity model](#5-identity-model)
6. [Protocol and envelope](#6-protocol-and-envelope)
7. [Cryptography](#7-cryptography)
8. [Authorization model (who is allowed to use the mechanism)](#8-authorization-model-who-is-allowed-to-use-the-mechanism)
9. [Socket and file permissions](#9-socket-and-file-permissions)
10. [PAM integration](#10-pam-integration)
11. [Confirmation dialogs](#11-confirmation-dialogs)
12. [Threat model](#12-threat-model)
13. [Failure modes and troubleshooting](#13-failure-modes-and-troubleshooting)
14. [Compatibility and migration](#14-compatibility-and-migration)
15. [Operations guide (setting it up)](#15-operations-guide-setting-it-up)
16. [Audit and hardening checklist](#16-audit-and-hardening-checklist)
17. [Future work](#17-future-work)
18. [Glossary](#18-glossary)

---

## 1. Introduction and scope

### 1.1 What it does

`sudo-auth-proxy` forwards a privilege-elevation request from a **guest**
(a MicroVM, container, or remote machine) to a **host** where a human can approve
or deny it with a graphical dialog. The guest's PAM stack calls the client; the
client asks the host; the host answers `allow` or `deny`; the guest's `sudo`
succeeds or fails.

This lets a headless guest (which has no local password or console) elevate
privilege with an explicit, human-approved decision made on the operator's
machine.

### 1.2 Supported clients only

**The only supported client is the `sudo-auth-proxy` client shipped in this
repository.** Other implementations are *not* supported and there is **no
compatibility guarantee** for third-party clients. The protocol is documented so
that a future, deliberately-designed client can be added, but doing so requires a
review against this document. In particular, a client must not be assumed to be
trustworthy merely because it speaks the wire format; trust comes from the
transport identity and the authorization model (§5, §8).

### 1.3 Terminology

| Term | Meaning |
|---|---|
| **Guest** | The machine where privilege is being elevated (VM, container, remote box). Runs the **client**. |
| **Host** | The machine where a human approves (usually the operator's desktop). Runs the **server**. |
| **Server** | Host-side process that shows the dialog and answers. |
| **Client** | Guest-side process invoked by PAM on each `sudo`/`su`/`login`. |
| **Reuse proxy** | Optional guest-side daemon that keeps a warm connection so each `sudo` does not pay a fresh handshake. |
| **Transport** | How client and server bytes travel: `vsock`, `tcp`, or `unix`. |
| **Callback** | Guest dials the host (`vsock`, `tcp`). |
| **Tunnel** | Host dials the guest over SSH and forwards a Unix socket into it (`unix`). |
| **Approver** | The human who answers the dialog; identified by the host user running the server. |
| **Principal** | A verified identity used by the ACL (a guest name and/or a guest login user). |

### 1.4 Goals and non-goals

**Goals**

- Let a headless guest elevate privilege only with explicit human approval on the host.
- Support a callback direction (`vsock`, `tcp`) for local/high-speed use **and** a
  host→guest SSH-forwarded Unix-socket direction (`unix`) that needs no host
  address and opens no network port.
- Isolate multiple people so one person never answers another person's prompts.
- Authenticate decisions so a local guest process cannot forge an "allow".
- Restrict *who may use the mechanism* (not everyone). This ACL gates the
  **proxy**, not `sudo` itself: other PAM methods still apply if enabled (§8,
  §10.3).
- Fail fast and stay optional in the PAM stack. **This is a security property,
  not only an availability one:** by default a human `deny` falls through, so
  the mechanism is explicitly *not* a sole gate (see the warning at the top of
  this document and §10.3).
- Be auditable and simple to reason about.

**Non-goals**

- Mandatory use: the PAM module is an *optional* authentication path (§10.3).
- A host-side tunnel daemon: the tunnel lives only as long as an SSH session (§4.4).
- Copying the host's `sudoers` policy into the guest; this service only decides
  *whether to allow*, the guest's own PAM/sudo policy still applies.
- Protecting against a compromised host or a compromised guest kernel.
- Third-party client interoperability (§1.2).

---

## 2. Roles and topologies

### 2.1 Client (guest side)

- Installed as a standalone binary (`sudo-auth-proxy`).
- Invoked by `pam_exec.so` as the **first** auth rule for `sudo`, `login`, `su`.
- Reads the guest-side config (`/etc/sudo-auth-proxy/config.toml`).
- Resolves the transport target (§3), builds a request (§6), waits for the
  decision, verifies it (§7.4), and exits.
- The helper runs in the PAM authentication context. The repo's existing comment
  says this is the invoking user, but under `sudo` it may retain `euid = 0`
  (setuid root); the exact real/effective UID is a **verified assumption, not an
  assertion** (review log F4, §19.5 gate 2). Either way the client must not rely
  on an OS-level privilege boundary.

### 2.2 Server (host side)

- A per-host-user service (`systemd --user` on Linux, launchd user agent on
  macOS). It must be tied to the approver's login session because it needs that
  user's GUI to show the dialog.
- Listens on one or more sockets (per guest in `unix` mode; one socket in
  `tcp`/`vsock` mode).
- Authenticates the peer (§5), authorizes it (§8), shows the dialog (§11),
  returns a signed decision (§7.4).
- Never elevates privilege itself; it only reports a decision.

### 2.3 Reuse proxy (optional; **not used for `unix`**)

- A guest-side daemon (`mode = "proxy"`) that holds one warm connection and
  relays local PAM requests over it. Its only motivation is that **mTLS
  handshakes are expensive per `sudo`**: a persistent, already-handshaked
  connection amortises them.
- **Decision (review log F3): the proxy is removed for the `unix` transport.**
  In `unix` mode the SSH channel already provides confidentiality, integrity and
  authentication, so mTLS defaults **off** and there is **no per-`sudo` TLS
  handshake to amortise**. A fresh local Unix-socket connect plus a new SSH
  channel is cheap; adding a daemon, a socket and a wire relay would cost
  maintenance for no measured gain.
- **Retained for `vsock`/`tcp`**, where mTLS is the transport security and the
  per-invocation handshake cost is real.
- **Caveat — mTLS on top of `unix`.** If an operator explicitly enables mTLS over
  `unix` as defence in depth (§7.2), per-connection handshakes return. The proxy
  could then help, but only after being rewritten as a **length-framed raw
  relay** (the current `readline()` relay cannot carry the envelope). This is not
  the default posture.
- If the proxy is used at all, its socket must be `0600`/`0660`, never the
  historic `0666`.

### 2.4 Topologies

**T1 — single operator, several local guests.** One host user owns the server
and the guests. `vsock` for local Linux VMs (fast), `unix` for anything remote.

**T2 — shared host, several people, different Unix accounts.** Each has their own
server (per host user), their own SSH config, their own socket directory. The
kernel enforces isolation via socket ownership/`SO_PEERCRED`.

**T3 — shared host, several people, the *same* Unix account.** They share a
server and a socket directory. They are, by construction, the same principal at
the OS level; see §5.6 and §12.6 (residual risk).

**T4 — shared guest login account, several host people.** Different host users
connect to the *same* guest login user. Routing is by **host-side identity**
(per-session / per-person socket, selected in-guest by an environment
variable), so each person answers their own sessions (§4.3).

---

## 3. Transports, and the two call directions

The transport is selected with `transport = "vsock" | "tcp" | "unix"`. It also
determines the **call direction**.

| Transport | Direction | Address | Typical use |
|---|---|---|---|
| `vsock` | Callback: guest → host | `(CID, port)` | Local Linux MicroVMs: no IP stack, fast, no firewall port. |
| `tcp` | Callback: guest → host | `(host, port)` | Containers, machines without VSOCK, networks where the guest can dial the host. |
| `unix` | Tunnel: host → guest | Local Unix socket inside the guest | Remote machines / real networks, and any case where the guest should not know or reach the host address. |

All three end in the same request/response exchange; only the byte path differs.
Adding `unix` is additive and does **not** change `vsock`/`tcp` behavior.

> **`unix` is a *different* trade, not a strictly more secure one** (review log
> C4, §19.6). It opens no network port and the guest does not need the host's
> address, but it only exists while a live SSH session is up: when the session
> ends the tunnel disappears and the mechanism becomes unavailable (§4.4). The
> callback transports have the opposite profile (an always-listening port, but
> no session dependency). Choose per workload; do not assume `unix` is "more
> secure".

### 3.1 Callback transports (`vsock`, `tcp`)

- The guest knows where the host is (CID, IP or `_gateway`).
- The host listens on a port; the guest connects.
- Security relies on **mTLS** (§7.2) plus, optionally, a firewall rule limiting
  the source to the guest subnet (`nix/host/firewall.nix`).
- Advantage: works with no active session on either side. Disadvantage: requires
  the guest to know an address and a reachable port (the "hardcoded IP" problem).

### 3.2 Tunnel transport (`unix`) — the direction we added

- The host already has SSH access to the guest (CA-signed host keys,
  `~/.ssh/tartarus`, `tartarus proxy %h`).
- When the host user opens an SSH session to the guest, the SSH client config
  adds a **remote forward** and an **environment variable**:

  ```ssh-config
  Host vault.trs
      # guest listens here; connections are forwarded to the host server socket
      RemoteForward /run/sudo-auth-proxy/<user>@<host>-<session-token>.sock %t/sudo-auth-proxy/guests/vault.sock
      SetEnv SUDO_AUTH_PROXY_SOCK=/run/sudo-auth-proxy/<user>@<host>-<session-token>.sock
      StreamLocalBindUnlink yes
      ExitOnForwardFailure yes
  ```

- The guest's PAM client connects to the **local** socket path named by
  `SUDO_AUTH_PROXY_SOCK`. It never needs the host's address.
- `<session-token>` is an unpredictable random value generated per SSH
  invocation by the host-side wrapper, which injects the same value into both
  `RemoteForward` and `SetEnv`. Randomising the basename prevents a same-UID
  guest process from predicting and racing the bind (review log NF7; residual
  R9).
- Because SSH already authenticates and encrypts the channel, mTLS defaults off
  here and **no reuse proxy is used** (§2.3).
- No TCP port is opened; the `65001` firewall rule is unnecessary for `unix`.
- The tunnel exists only while the SSH session is alive (§4.4). When it does not
  exist, the client fails fast and PAM falls through (§10).

---

## 4. The SSH-forwarded Unix transport in detail

### 4.1 Forward setup

The host is the SSH **client**; the guest is the SSH **server**. Therefore the
correct primitive is `ssh -R` (remote forward), whose arguments are
`bind_socket:connect_socket`:

- `bind_socket` is created **on the guest** (the SSH server side) by the guest's
  `sshd`, running as the guest login user.
- `connect_socket` is the host's server socket, connected **on the host** by the
  SSH client process, running as the host user.
- The bind is performed by the **guest's `sshd`**, so the guest must allow it and
  unlink stale sockets: `AllowStreamLocalForwarding yes` and
  `StreamLocalBindUnlink yes` in the guest `sshd` config (the guest module sets
  these, as it already does for GPG forwarding). The client-side
  `StreamLocalBindUnlink`/`ExitOnForwardFailure` only govern the host's `ssh`.

```
guest: PAM → client ──connect──▶ /run/.../<user>@<host>-<token>.sock
                                          │  (sshd, as guest user)
                                          ▼
                                   SSH channel (host→guest)
                                          │
host:                             ssh (as host user) ──connect──▶ %t/.../guests/<guest>.sock
                                                                        │
                                                                        ▼
                                                                   server → dialog
```

Because the host's SSH client makes the host-side connection, the server socket
sees a peer that is the `ssh` process **run by the host user**. That is the basis
of the host-side identity check (`SO_PEERCRED`, §9).

### 4.2 Socket naming and per-person isolation

Two problems must be solved:

1. **Guest-side collision.** If two host users forward to the *same* guest socket
   path, with `StreamLocalBindUnlink=yes` the second session silently steals the
   first's socket. Person B's tunnel would then serve person A's requests. This
   is unacceptable.
2. **Host-side ambiguity.** If every guest forwarded to one host socket, the
   server could not tell which guest a request came from.

The design resolves both by naming:

- The **guest bind path** is unique per *session*:
  `/run/sudo-auth-proxy/<host-user>@<host-hostname>-<session-token>.sock`,
  where `<session-token>` is an unpredictable random value generated per SSH
  invocation by the host-side wrapper and injected into the guest in the same
  `SetEnv` that carries the path. The parent directory is still a literal from
  Nix; only the basename token is per-session. Randomising it closes a
  predictable-path race: without the token a same-UID guest process could
  pre-bind or race the name `RemoteForward` is about to use (review log NF7;
  residual **R9**).
- The **host server socket** uniquely per *guest*:
  `%t/sudo-auth-proxy/guests/<guest>.sock`.
  The server binds one socket per guest, so "which guest" is host-enforced and
  cannot be claimed by the guest.

A guest connecting to `/run/.../alice@laptop-<token>.sock` therefore reaches
*Alice's* server, on *Alice's* session, and the server knows the guest from the
socket it accepted on. Bob's tunnel uses a different guest path (and a different
token) and cannot interfere. On teardown the guest module removes the exact
path named by the session's `$SUDO_AUTH_PROXY_SOCK` (see §4.3).

### 4.3 Session/pty routing (why the environment variable exists)

Topology T4 has different people logging into the **same guest account**
(e.g. all as `user`). At the OS level inside the guest they are
indistinguishable. But each person's SSH session carries a *different* value of
`SUDO_AUTH_PROXY_SOCK` (set by their own host's SSH config to their own socket).
`sshd` accepts that variable (`AcceptEnv SUDO_AUTH_PROXY_SOCK`), so every process
in that session — including the shell, `sudo`, and its `pam_exec` child —
inherits it. The PAM client resolves its target socket in this order:

1. `$SUDO_AUTH_PROXY_SOCK` from the process environment. **This must be
   guaranteed, not hoped for.** `sudo`'s default `env_reset` would otherwise
   strip an unknown variable, which would silently break per-person routing. The
   guest Nix module therefore deploys
   `Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"` **and**
   `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` (the recursion guard, §10.4)
   into `sudoers`. Relying on ambient `sudo` behaviour is explicitly rejected
   (review log C1/B2).
2. `/proc/$PPID/environ` (the parent `sudo` process's environment) as a
   **best-effort, Linux-only fallback**. It is unreadable under some `hidepid`
   configurations and does not exist on macOS; it is never the primary mechanism.
3. The static `socket` from `/etc/sudo-auth-proxy/config.toml`.
4. Otherwise: **fast-fail** (§10.2) and let PAM continue.
   Before even starting the client, the PAM wrapper checks that the selected
   socket exists; if it does not, it exits immediately (zero-cost fallthrough,
   §10.2).

> **Implementation gap (review log C1).** The order above is the *intended*
> order. The current `run_client` reads only the static `socket` from
> `/etc/sudo-auth-proxy/config.toml` and never consults
> `$SUDO_AUTH_PROXY_SOCK`; making the environment the first source is **new work
> for Phase 2**, not a description of today's code.

> **`sudoers.d` fragility (review log C1).** The `env_keep` entries are deployed
> as one fragment under `/etc/sudoers.d/`. `sudoers` evaluates fragments in
> lexical order and later lines can override or negate earlier ones (a stray
> `Defaults env_reset` in another fragment would undo the `env_keep`). Deploy the
> entries where they cannot be shadowed, and assert in an integration test that
> both variables survive (Phase 2 exit criterion).

This is exactly the "resolve the pty/session" requirement: the session's
environment selects the socket, so the request is delivered to the approver who
owns *that* session. The pty (`PAM_TTY`) is additionally recorded in the request
and signed, so an approval can never be reused across sessions (§6.5).

> **Hard dependency.** The `sudoers env_keep` entries above
> (`SUDO_AUTH_PROXY_SOCK` and `SUDO_AUTH_PROXY_ACTIVE`) are required for the
> `unix` transport's per-person isolation and for the recursion guard. They are
> deployed by the guest Nix module, not left to the operator, and are a Phase 2
> exit criterion. On macOS guests there is no `/proc` fallback, so the
> `env_keep` path is the *only* supported mechanism there.
>
> **Stale-socket hygiene (corrected, review log NF4).** A socket left behind by
> a crashed/aborted session must be cleaned up; `ExitOnForwardFailure` covers a
> *failed bind*, not a stale file from a previous session. The guest module adds
> an explicit cleanup on session teardown (and `StreamLocalBindUnlink` on the
> client covers the same-connection case), removing the exact tokenised path
> named by the session's `$SUDO_AUTH_PROXY_SOCK`. Until the cleanup runs, a
> stale socket does **not** produce a fast connection failure: `connect()` to a
> bound-but-unlistened Unix socket succeeds, and the client would then block on
> `read()`. The receive/response timeout of §10.2 (`SO_RCVTIMEO`, ~500 ms) turns
> that into a bounded failure so PAM still falls through.

### 4.4 Lifecycle (no host-side tunnel daemon)

The forward exists only for the lifetime of the SSH connection that created it.
Consequences:

- While a person is logged into a guest, their `sudo` prompts can be approved.
- With no SSH session, there is no tunnel, so the client fails fast and PAM falls
  through to other methods (§10.3). This is intended: the mechanism is an option,
  not a requirement.
- **Background / automation consequence:** work not attached to a live session
  (cron, a `nohup` job, Ansible/Terraform, a detached `tmux` after the SSH client
  exits) has no tunnel and is therefore **not proxied**. Use a callback transport
  (`vsock`/`tcp`) for those workloads. (Review log Rank 5; residual R7.)
- **Availability trade (review log C4).** The session-bound nature is the flip
  side of "opens no network port": `unix` is *not* strictly more secure than the
  callback transports; it trades a listening port for a session dependency. A
  workload that must be approvable when nobody is logged in needs `vsock`/`tcp`
  (§3).
- `ExitOnForwardFailure=yes` makes a failed bind kill the SSH session loudly,
  rather than silently running without a tunnel.
- A `ControlMaster` may be used so several sessions share one connection and one
  forward (avoids self-collision for the same host user).

### 4.5 Sequence

```
  guest user            guest client            guest sshd            host ssh               host server            approver
      │  sudo                 │                     │                    │                       │                     │
      │─────────────────────▶│                     │                    │                       │                     │
      │                read SUDO_AUTH_PROXY_SOCK   │                    │                       │                     │
      │                      │──connect unix──▶    │                    │                       │                     │
      │                      │                     │──SSH channel──────▶│                       │                     │
      │                      │                     │                    │──connect unix──────▶ │                     │
      │                      │  request{nonce,user,tty,cmd,digest}      │                       │──show dialog───────▶│
      │                      │                     │                    │                       │◀────allow/deny──────│
      │                      │◀──response{nonce,digest,decision,sig}────┼───────────────────────│                     │
      │                      │ verify sig + nonce  │                    │                       │                     │
      │◀──exit 0 / 1─────────│                     │                    │                       │                     │
```

---

## 5. Identity model

The service must answer four questions. Each has a defined, trusted source.

| Question | Source | Trusted because |
|---|---|---|
| **Which host person approves?** | The uid that connected to the host server socket (`SO_PEERCRED`), or equivalently the per-user server/socket. | Kernel-enforced; a user cannot connect as another uid. |
| **Which guest sent it?** | In `unix`: the per-guest socket the host server accepted on. In `vsock`/`tcp`: the verified mTLS certificate CN/EKU. | Host-configured / CA-verified. |
| **Which guest login user / session / tty?** | `PAM_*` environment + the session's `SUDO_AUTH_PROXY_SOCK` for socket selection; `PAM_TTY` for session binding. | Guest-provided but scoped to the session; bound into the signed request. |
| **Which command / cwd?** | `/proc/$PPID/cmdline` of the `sudo` process, plus `PWD`. | Guest-provided; bound into the signed request and shown in the dialog. |

### 5.1 Host person (approver)

- In `unix` mode, the host's SSH config is per host user; the server listens in
  that user's runtime dir. The accepted connection comes from that user's `ssh`
  process, and the server verifies the peer uid (§9.3).
- In `tcp`/`vsock` mode, the server is one host user's service; the approver is
  that user.
- The approver's identity is **not** claimed by the guest; it is where the server
  runs.

### 5.2 Guest identity

- `unix`: the per-guest host socket. The host generated the SSH forward mapping
  `<guest>.trs → guests/<guest>.sock`, so a connection on that socket is from
  that guest (the host connected to it over the SSH session that terminates at
  that guest). The guest cannot create a connection on another guest's socket
  because it has no access to the host's socket directory.
- `tcp`/`vsock`: the mTLS peer certificate, verified against the shared CA and
  the role's EKU OID; the CN (or SAN) names the guest. The ACL (§8) decides
  whether that guest is allowed.

### 5.3 Guest login user and session

- `PAM_USER` is the account being authenticated (for `sudo`, usually `root`).
- `PAM_RUSER` / `SUDO_USER` is the invoking user.
- `PAM_TTY` identifies the terminal; it distinguishes concurrent sessions.
- These are provided by the guest and are **not independently verifiable by the
  host**; their role is to (a) be shown to the approver and (b) be bound into the
  signed request so an approval cannot be reused for a different session. Where
  enforcement matters (ACL on guest users, §8), the socket-per-user or
  per-guest-user design is the enforcement mechanism, not the string.

### 5.4 Command

At PAM-authentication time the `sudo` process's argv is the requested command
(`/proc/$PPID/cmdline`). The client records its SHA-256 digest and, for display,
a sanitised form (§11). The digest is signed back by the host, binding the
approval to the exact request.

> **Best-effort, not trusted.** `cmdline` is guest-controlled (a process can even
> rewrite its own argv via `prctl(PR_SET_MM_ARG_START)`), and for `login`/`su`
> the parent is not `sudo`, so the string is not the target command. It is used
> for **display and binding only**, never as an authorization input. The dialog
> defaults to program + digest and labels the field "best effort / unverified".
> (If the command cannot be determined, the request is still bound to
> user+tty+nonce, and the dialog says so.)

### 5.5 Trust boundaries

1. **Guest kernel / guest root** is trusted for the guest's own PAM path only.
2. **Network / channel** between client and server is untrusted; it is protected
   by mTLS (callback) or SSH (tunnel), and by the signed envelope end-to-end.
3. **Host user process space** is trusted to run the server, but any host
   process can connect to the server socket if it can reach it; §9.3 constrains
   this.
4. **The CA private keys** (SSH CA, X.509 CA, signing key) are trusted roots;
   their compromise is catastrophic and is handled by rotation (§7.7) and by
   keeping them off guests.

### 5.6 Shared-account caveat

Two people sharing one **host** Unix account are one principal to the OS: they
share the server, the runtime dir, and the ability to answer each other's
prompts. This cannot be fixed by cryptography and is accepted as a residual risk
(§12.6). Two people sharing one **guest** login account are supported, because
routing uses the distinct host-side sockets/env (§4.3).

---

## 6. Protocol and envelope

### 6.1 Framing

All new messages are length-framed and versioned:

```
magic (4 bytes: "SAP\x01") | version (u16) | length (u32, big-endian) | payload
```

- Maximum payload size is enforced before allocation (guards against a malicious
  length prefix).
- Parsing is strict: unknown versions, trailing bytes, or malformed fields are
  rejected and fail closed.
- **`protocol` defaults to `"envelope"`** in new configurations. The legacy
  protocol (`auth\n` → `1\n`, which is unsigned and therefore unauthenticated)
  is retained for backward compatibility but is **opt-in** (`protocol =
  "legacy"`). Byte-sniffing auto-detection (`protocol = "auto"`) exists only as
  an explicit migration bridge and is **never** the default, so a peer cannot
  downgrade the exchange to the unauthenticated legacy response.

### 6.2 Request fields (client → server)

| Field | Purpose |
|---|---|
| `nonce` | 16+ random bytes; correlates request and response; replay defence. |
| `pam_service` | `sudo` / `su` / `login`. |
| `target_user` | `PAM_USER` (account being authenticated). |
| `invoking_user` | `PAM_RUSER` / `SUDO_USER`. |
| `rhost` | `PAM_RHOST` (origin, if any). |
| `tty` | `PAM_TTY`. |
| `command_digest` | SHA-256 of the requested command (from `/proc/$PPID/cmdline`). |
| `command_display` | Sanitised, length-capped command for the dialog (optional). |
| `cwd` | Current working directory. |
| `client_version` | Protocol/client version. |
| `guest_hint` | Optional self-reported name (never authoritative; for logs). |

The request is **not** trusted merely because it is well-formed; it is scoped by
the transport identity (§5) and the ACL (§8).

### 6.3 Response fields (server → client)

| Field | Purpose |
|---|---|
| `nonce` | Echo of the request nonce. |
| `request_digest` | SHA-256 over the canonical request. |
| `decision` | `allow` / `deny`. |
| `issued_at`, `expires_at` | Freshness window. |
| `approver` | The host uid/name that answered. Signed, for non-repudiation and post-hoc misrouting detection (review log Q5). |
| `alg` | Signature algorithm identifier (e.g. `ed25519`, `rsa-sha256`). Part of the signed transcript so it cannot be substituted. |
| `key_id` | Identifier of the signing key used. The client pins the expected value and rejects any signature whose `alg` is unknown or absent (review log NF1). |
| `signature` | Host signature over the domain-separated transcript (§7.4). |

### 6.4 Canonicalisation and digest

The request digest is computed over a **canonical serialisation** (fixed field
order, explicit lengths, no locale/formatting dependence), not over the raw
wire bytes, so both sides agree regardless of encoder quirks. The signature
covers:

```
"SAP-v1" || alg || key_id || nonce || request_digest || decision || approver || issued_at || expires_at
```

The `"SAP-v1"` label is **domain separation**: the signing key cannot be tricked
into signing something meaningful in another protocol. `alg` and `key_id` are
inside the transcript so a peer cannot substitute the algorithm or swap keys; the
client pins the expected `key_id` and **rejects an unknown or absent `alg`**
rather than guessing (review log NF1).

### 6.5 Nonce, freshness and replay

- The client rejects any response whose `nonce` or `request_digest` does not
  match the request it sent, or whose signature does not verify, or which is
  expired. This prevents a stale "allow" from being replayed into a later session
  and prevents cross-talk between concurrent requests.
- **The primary replay defence is client-side and single-use:** the client
  accepts at most one response for the nonce it generated. The server cache is
  **defence in depth** (it matters on the shared/reuse-proxy paths), not the
  load-bearing control (review log C3).
- The server keeps a bounded, time-limited cache of recently seen nonces and
  rejects duplicates. Concrete limits are fixed at implementation time and
  documented in code: **max 4096 entries, 120 s TTL, LRU eviction**. **On
  overflow the server evicts the oldest entry and raises an alert** rather than
  silently dropping new entries, so a nonce flood cannot silently disable
  duplicate detection for a legitimate entry; under sustained pressure the server
  may be configured to **fail closed** (refuse new requests) instead of
  degrading (review log C3; residual **R10**).
- Expiry is short; clock skew is tolerated within a configured window. Because
  the binding is `nonce + digest`, a correct decision is valid regardless of
  clock as long as the client accepts it once.

### 6.6 Errors and exit codes

The client exits `0` on a verified allow and non-zero otherwise. It distinguishes,
for logging and for the PAM control decision:

- `denied` — a valid decision of `deny`.
- `unavailable` — transport unreachable, timeout, parse/verify failure
  (including an unknown, absent, or unexpected signature algorithm/key, §7.4).

> **Limitation.** `pam_exec.so` collapses a non-zero exit to a generic failure;
> PAM cannot branch on `denied` vs `unavailable` via the exit code alone. Both
> therefore take the same control path in the default configuration
> (`[success=done default=ignore]`, §10.3). This is documented rather than
> hidden; a strict mode requires a native PAM module and is **not implementable
> with `pam_exec`** (§17).

---

## 7. Cryptography

### 7.1 Why cryptography is needed (the short answer)

Two different security properties are involved, and it is worth separating them
because it answers "is crypto really needed if the identity model is clean?":

1. **Authentication of the requester** — "who is allowed to ask?". This can be
   provided by the transport identity: the SSH tunnel plus socket ownership
   (`unix`), or mTLS (`tcp`/`vsock`). The identity model alone can be sufficient
   here.
2. **Integrity of the decision** — "may the guest trust this `allow`?". The
   transport carries the decision back to the guest, but the guest process is
   spawned fresh by `pam_exec` and reads a local socket. A local process in the
   guest (same account, or a fake listener racing `sshd`) could inject `allow`.
   **The identity model does not stop that.** Only a decision the guest can
   *cryptographically verify as coming from the host* stops it. That is the
   signing key's job.

So yes: if you drop cryptography you still have "authentication" for who may ask,
but you no longer have a trustworthy "yes". Anyone able to write to the client's
socket could cause `sudo` to succeed. Cryptography is kept.

### 7.2 mTLS (callback transports)

- Both sides present certificates from the shared X.509 CA (`tartarus`).
- The server verifies the client cert against the CA and requires the configured
  **EKU OID**; the client verifies the server cert and its EKU OID.
- Hostname verification is intentionally disabled for callback transports because
  the peer address is a CID/DHCP lease, not a hostname; identity is the
  certificate, not the address.
- mTLS is **optional** on `unix` (the SSH channel already authenticates and
  encrypts). It can still be enabled as defence in depth, at a small cost.

### 7.3 EKU OIDs

Each service uses private-enterprise-number OIDs so a certificate minted for one
service cannot be used for another:

| Service | Server OID (client must see in server cert) | Client OID (server must see in client cert) |
|---|---|---|
| sudo-auth-proxy | `1.3.6.1.4.1.99999.1.1` | `1.3.6.1.4.1.99999.1.2` |
| ssh-agent-proxy | `1.3.6.1.4.1.99999.2.1` | `1.3.6.1.4.1.99999.2.2` |
| clipboard-bridge | `1.3.6.1.4.1.99999.3.1` | `1.3.6.1.4.1.99999.3.2` |

### 7.4 Decision signing (host → guest)

The **case** where a key is needed: signing the server's decision so the guest
can verify it.

- The host holds a private signing key. The guest holds only the corresponding
  **public** key. Public keys are not secrets: distributing them widely (even
  world-readable) is fine.
- **Distribution trust.** The public key reaches the guest through the same
  build/9p mechanism as `ca.crt`, so it inherits the Nix store's trust: a
  compromised build/flake input could substitute a rogue key. This is the same
  supply-chain surface as every other trust root here; it is called out so the
  key is treated as sensitive-as-CA when reviewing build inputs (review log
  Rank 6). Key rotation therefore implies a guest rebuild unless a keyring
  directory is added.
- The host signs the full §6.4 transcript
  `"SAP-v1" || alg || key_id || nonce || request_digest || decision || approver || issued_at || expires_at`
  (review log B1: this corrects an earlier shorthand that omitted `approver` and
  disagreed with §6.4). The guest verifies with the trusted public key. A local
  attacker cannot forge the signature and therefore cannot fabricate an `allow`.
- **Algorithm agility and key pinning (review log NF1).** `alg` and `key_id` are
  part of the signed transcript, so a peer cannot substitute the algorithm or
  swap signing keys. The client pins the expected `key_id` and **rejects
  unknown or absent `alg`**; it does not fall back to trying whatever algorithms
  a key might support.
- A local attacker also cannot *change* the command shown to the approver: the
  digest the host signs is the digest of the request the guest will act on, so a
  channel that modified the request yields a digest mismatch at verification.

### 7.5 Which signing key? (options and recommendation)

This is the question of *what process may use which key material*:

- **Reuse the SSH user key** (`~/.ssh/tartarus`, Ed25519): the guest already
  trusts its public half via `authorized_keys`. Convenient, but mixes SSH-host
  authentication with application signing; rotation is coupled.
- **Reuse the X.509 host server key**: already distributed to guests via `ca.crt`
  / server cert. Convenient, but the key is an RSA-2048 TLS key; reusing a TLS
  key for application signatures is a role-mixing smell.
- **Dedicated signing key (recommended)**: a separate keypair whose public half
  is distributed to guests exactly like `ca.crt`. Clean separation, independent
  rotation, and a natural place to later move to TPM/HSM.

**Recommendation:** dedicated signing key, Ed25519 by default, RSA supported
(configurable). The algorithm is inferred from the key; RSA remains fully
supported because it "still works" and may be forced for compatibility. Every
signature declares `alg` + `key_id` (§6.4) and the client rejects any algorithm
it does not know (review log NF1).

### 7.6 Algorithms

- **Ed25519** preferred for the signing key and, where the toolchain allows, for
  X.509 certificates (smaller, faster, modern).
- **RSA** supported (current leaves are RSA-2048, CA RSA-4096). If RSA keys are
  used for signing, use a modern hash (SHA-256/512) and PKCS#1 v1.5 or PSS.
- **Algorithm agility (review log NF1).** Signatures declare `alg` and `key_id`
  inside the signed transcript (§6.4). The client accepts only the algorithms it
  was built with (Ed25519; RSA with the configured hash and padding) and
  **rejects unknown or absent `alg`**, then pins the expected `key_id`; it never
  guesses.
- Symmetric MACs, if ever used, must use a constant-time comparison
  (`hmac.compare_digest`). Signatures are preferred because they need no shared
  secret and give non-repudiation.

### 7.7 Key lifecycle and rotation

- The existing CA tooling (`src/tartarus/ca.py`) already generates CA and leaf
  material on demand and can be extended to generate the signing keypair.
- Verification should be **CA/keyring-based**, not pinned to one leaf: rotating a
  signing key should require only distributing a new public key (guests trust a
  directory of trusted keys, or the CA), not re-provisioning every guest. The
  client still **pins the expected `key_id`** (review log NF1): a keyring is a
  finite set of trusted keys and `key_id` selects one, so the server cannot name
  a key the guest does not already trust.
- Short-lived certificates + `just rekey` make rotation routine.
- If a CA or signing key is suspected compromised: regenerate (stop guests, delete
  the material, restart to regenerate), then re-distribute. Because the CA is
  shared across services, rotating it invalidates every certificate — plan a
  maintenance window.

### 7.8 Key and file permissions

- **Never** ship a private key world-readable. The historic client key was
  `0644`; see §9.2 and §12.5 for the fix and the nuance (per-guest isolation).
  The fix must be made **in the CA generation code** (`src/tartarus/ca.py`,
  `_ensure_x509_client_cert`), not only in runtime checks, so newly minted
  certs are never world-readable (review log F12).
- Under `unix`, a client private key is not needed for authentication or
  verification (only public keys), so it should not be exposed to the guest at
  all where avoidable.
- Host signing private key: `0600`, owned by the host user (or root), stored
  under the host's tartarus X.509 directory.

---

## 8. Authorization model (who is allowed to use the mechanism)

**Principle: nobody is allowed by default; a request is eligible only if it
matches the configured policy, evaluated *before* the dialog is shown.**

This ACL governs **access to the proxy mechanism**, not access to `sudo`: an
unlisted principal can still elevate through any other PAM method the guest
offers. To make the proxy a sole gate, the other methods must be disabled *and*
a non-ignorable `deny` enforced — which is **not implementable with `pam_exec`**
and requires the native PAM module of §17 (see §10.3). This distinction is
deliberate (review log Rank 10).

### 8.1 Modes

Server config `[acl]`:

| `mode` | Meaning |
|---|---|
| `"ca"` | Accept a peer whose certificate is signed by the shared CA, carries the correct EKU OID, and whose guest name matches `allowed_guests`. **An empty `allowed_guests` denies every guest**; allowing any CA-signed peer requires an explicit `["*"]` entry. |
| `"list"` | Accept only explicitly listed principals (guest names and/or pinned public-key fingerprints), independent of CA membership. |
| `"both"` | Require **both** a valid CA certificate **and** an explicit listing/pin. Strongest; recommended for shared hosts. |

### 8.2 What can be matched

- **Guest name** (`allowed_guests`, glob patterns) — from the host-enforced
  per-guest socket (`unix`) or the mTLS CN (`tcp`/`vsock`).
- **Guest login user** (`allowed_users`) — `PAM_RUSER`/`PAM_USER`; primarily a
  user-experience/least-privilege control (see §5.3 on enforceability).
- **Host user** (`allowed_host_users`, optional) — for `tcp`/`vsock` where a
  single server might be reached by several host users.
- **Pinned key** — the SHA-256 SPKI fingerprint of the peer's certificate.
  Pinning defeats a stolen-CA scenario (an attacker with a CA-signed cert for a
  different principal still fails the pin). **Under `unix` there is no mTLS by
  default**, so a pin must name something the tunnel actually presents: either
  (a) the **SSH host public-key fingerprint** of the tunnel (the guest's
  known-host key), or (b) `mtls = true` on `unix`, in which case the ordinary
  certificate-SPKI pin applies. With neither configured, `list`/`both` pinning
  cannot be evaluated and the request is rejected (fail closed) — review log
  NF6.
- **User + guest combination** — e.g. only `user` on guest `vault`.

### 8.3 Client-side prefilter

The client can carry an optional `allowed_users` list and refuse locally (fast)
before contacting the server, so a non-allowed user does not even generate
network traffic or a prompt. This is convenience, not security; the server always
re-checks.

### 8.4 Defaults and fail-closed

- Default is deny. Empty allow lists mean "no one" for `list`/`both`, and an
  empty `allowed_guests` under `ca` also **denies everyone**; a wildcard allow
  requires an explicit `["*"]` entry.
- Under `unix`, `list`/`both` pinned mode has nothing to pin unless `mtls = true`
  or an SSH-host-key pin is configured (§8.2). With neither, the request fails
  closed rather than vacuously matching an empty pin set.
- Unknown/unresolvable principals are rejected and logged, never prompted.
- A request that fails ACL is answered with a signed `deny` (or not answered at
  all), never silently ignored.

### 8.5 Worked examples

```toml
# Only CA-signed guests named vault or dev-* may use the mechanism.
[acl]
mode = "ca"
allowed_guests = ["vault", "dev-*"]

# To accept ANY CA-signed guest you must say so explicitly; an empty list
# denies all (mode = "ca", allowed_guests = [] accepts nobody).
[acl]
mode = "ca"
allowed_guests = ["*"]

# Strictest: CA + explicit pin + only user "user".
[acl]
mode = "both"
allowed_guests = ["vault"]
allowed_users  = ["user"]
pinned_keys = ["SHA256:AbCdEf...="]
```

---

## 9. Socket and file permissions

Permissions are part of the security model, not an afterthought.

### 9.1 Host side

- Server runtime directory: `0700`, owned by the host user
  (`RuntimeDirectoryMode=0700` on systemd; the correct per-user temp dir on
  macOS).
- Server socket: created with `umask 0177` and then explicitly `0600`.
- Before binding: `lstat` the path; refuse symlinks or files not owned by the
  server user; unlink stale sockets safely. This check is **best-effort** — it is
  not atomic with `bind()`, so on Linux prefer `O_PATH | O_NOFOLLOW` semantics
  where feasible and accept the TOCTOU window for same-UID peers (review log F6).
- On accept: verify the peer uid with `SO_PEERCRED` (Linux) or
  `LOCAL_PEERCRED`/`getpeereid` (macOS/Darwin), and require it to be the server
  user (rejecting other local users).
- Because the host server socket is per guest and private, a guest cannot reach
  another guest's server socket.

### 9.2 Guest side

- Socket directory: `0700`, owned by the guest login user; the guest's `sshd`
  (running as that user) creates the socket there.
- Socket: `0600`.
- Client config directory `/etc/sudo-auth-proxy`: `0750 root <guest-login-group>`
  (not the historic `0755`), so filenames and any future key material are not
  world-readable while the PAM helper can still read the config.
- **Listeners and links.** The client `lstat`s the socket and refuses symlinks or
  paths not owned by the expected user before connecting. This is best-effort
  (the check and `connect()` are not atomic); see the residual-risk note below.
- **Two distinct properties.** Do not conflate them (review log F1/F2):
  - *Decision authenticity*: the host signature prevents a forged `allow`. A
    fake listener has no signing key and does not know the nonce.
  - *Routing integrity*: the socket path/ownership and, on Linux, a
    post-connect `SO_PEERCRED` → `/proc/<peer_pid>/exe` check that the peer is
    the system `sshd` prevent a same-UID attacker from *redirecting* the client
    to a **different legitimate** tunnel (misrouting is not forgery, and a
    signature does not prevent it). This peer-process check is Linux-only;
    macOS relies on socket-path integrity.
- **Residual risk:** when the **guest login account is shared** by several people,
  anyone with that UID can unlink/replace the socket in the `0700` directory
  (subject to the check above, which raises the bar but is not atomic). This is
  captured in §12.6 R6; the robust fix is per-person guest accounts.
- **Reuse-proxy socket:** the historic `0666` is unacceptable; if the reuse proxy
  is used it must be `0600` (or `0660` with a dedicated group).
- Private keys: never `0644`. Under `unix`, no client private key is exposed.
  Under mTLS, keep the key `0600`/`0640` and rely on per-guest isolation; the
  per-guest X.509 generation must stop emitting `0644` (review log F12). Note
  that users of the *same guest* share that guest's mTLS identity (acceptable
  within a guest's trust domain).

### 9.3 Attack surface and races

| Situation | Control |
|---|---|
| Host process of another user connects to the server socket | `0700` dir + `SO_PEERCRED` uid check. |
| Host process of the *same* user connects | It is the same approver/principal; prompts are rate-limited and logged. No cross-user escalation. |
| Guest process races the tunnel listener | Host signature verification prevents forged allows; socket `lstat` + (Linux) `SO_PEERCRED`→`/proc/<pid>/exe` limits misrouting. |
| Same guest UID redirects a socket to another legitimate tunnel | **Residual risk (R6)**; only fully fixed by per-person guest accounts. |
| Stale socket after crash | Unlink + ownership check before bind; `StreamLocalBindUnlink`; receive timeout (§10.2) bounds the bound-but-unlistened read hang. |
| Socket path guessable/raceable | Random per-session token in the path (NF7, R9) + `0700` dir; path secrecy is not relied upon, permissions and signatures are. |
| macOS: no `/proc`, `getpeereid` uid/gid only | Linux peer-process check unavailable; rely on path/ownership + token + host signature (R11, §12.5 T25). |

---

## 10. PAM integration

### 10.1 Stack placement

The client is inserted as the first auth rule:

```
auth [success=done default=ignore] pam_exec.so /run/wrappers/bin/sudo-auth-proxy-client
```

- `success=done` — a verified allow finishes authentication.
- `default=ignore` — anything else is ignored and the stack continues.

### 10.2 Timeouts and fast-fail

Three distinct timeouts:

- **Connect/handshake timeout** (`connect_timeout`, default **≤200 ms**): if the
  peer cannot be reached, give up *fast* so other PAM methods are tried
  promptly. This is a hard requirement: a `sudo` must not hang for minutes on a
  dead tunnel. The PAM wrapper additionally checks socket existence *before*
  spawning the Python client (zero-cost fallthrough when the tunnel is absent),
  because the hook fires on **every** `sudo` and a latency tax on the fallthrough
  path is unacceptable (review log Rank 5).
- **Decision timeout** (`decision_timeout`): how long to wait for the human to
  answer once connected. Bounded or `0` (wait) depending on policy.
- **Receive/response timeout** (`recv_timeout`, default **≤500 ms** for the
  first bytes of the response): `connect()` to a bound-but-unlistened Unix socket
  succeeds immediately, so a stale socket is **not** a fast connection failure.
  Without this bound the client would block on `read()` until
  `decision_timeout`. Implemented with `SO_RCVTIMEO` (or a non-blocking read +
  poll) so the fallthrough path stays sub-second (review log NF4).

Additional fast-fail rules:

- Never block on DNS for an address that is already numeric; for `unix`, connect
  is immediate (but see the receive timeout above: an immediate connect to a
  stale socket can still stall the read).
- Sample the environment and socket existence before attempting a slow path.
- On any parse/verify failure, exit immediately (fail closed).

### 10.3 Fallback semantics and their security implications

The mechanism is **optional**: on `denied` or `unavailable` the PAM stack
continues (default `default=ignore`). This means:

- The proxy is an *additional* authentication path, useful for headless guests
  where no other method exists.
- If the guest also has a local password, a user can still authenticate with it
  after a deny, unless the operator disables password auth for that account. The
  proxy does **not** override the guest's own policy.
- Therefore "only whitelisted people can elevate *through this mechanism*" holds
  (§8), but the mechanism is not a hard gate over the whole account unless the
  other methods are disabled. This trade-off is deliberate and must be understood
  before relying on the proxy as a sole factor.
- **There is no strict mode with `pam_exec`.** `pam_exec.so` collapses every
  non-zero exit to the same generic failure, so the stack cannot distinguish
  `deny` from `unavailable`; no PAM control flag can implement a non-ignorable
  deny on top of it (§6.6). A strict mode therefore **requires the native PAM
  module of §17** and is not available with the current `pam_exec` integration.
- **Explicit warning:** in the default configuration a deliberate human `deny`
  is *indistinguishable* from `unavailable` and therefore falls through. If a
  local password (or any other PAM method) is enabled, the approver's "no" can be
  bypassed by entering that password. The proxy is never a hard gate unless the
  other methods are disabled — and even then a non-ignorable `deny` needs the
  future native PAM module (§17), because `pam_exec` cannot distinguish `deny`
  from `unavailable` (review log F5, §19.6 C1/§17).

### 10.4 Recursive and stacked authentication

- A guard environment variable (e.g. `SUDO_AUTH_PROXY_ACTIVE=1`) should be set
  while the helper runs and checked on entry, so `sudo` inside `sudo`, `su`
  inside `sudo`, etc. do not loop or double-prompt. Like the socket selector, it
  must survive `sudo`'s `env_reset`: deploy
  `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` (§4.3). Without the `env_keep`
  entry the guard is silently stripped and stops working (review log B2).
- `login`/`su` set different `PAM_SERVICE` values; the request records the
  service so the approver sees which path triggered it.

### 10.5 Example

```nix
tartarus.sudo-auth-proxy = {
  enable = true;
  transport = "unix";              # host→guest tunnel (new)
  socketEnv = "SUDO_AUTH_PROXY_SOCK";
  socket = "/run/sudo-auth-proxy/client.sock";  # fallback
  connectTimeout = 1.0;
  decisionTimeout = 120;
};
```

---

## 11. Confirmation dialogs

### 11.1 Fields shown

The dialog should let the approver answer with full context:

- **Guest** (e.g. `vault`).
- **Invoking user → target user** (e.g. `user → root`).
- **Service** (`sudo` / `su` / `login`).
- **TTY** (`/dev/pts/3`) and **rhost** if any.
- **Command** (program + arguments, or program + digest by default).
- **Working directory**.
- **Request id** (short prefix of the nonce) and **timestamp/transport**.

### 11.2 Sanitisation

All fields are attacker-influenced and must be treated as untrusted:

- **Unicode-normalise first** (NFC) so visually identical sequences collapse
  before any further processing.
- **Allow-list, don't deny-list.** After normalisation keep only
  `[A-Za-z0-9_.:/@-]` and a single space, replacing every other code point with
  `?`. This removes control characters, bidi overrides, newlines and markup in
  one step.
- Apply that sanitiser to **every** attacker-influenced field, not just the
  command: `guest_hint`, `invoking_user`, `target_user`, `tty`,
  `command_display`, `cwd` (and `rhost`).
- Cap lengths.
- **zenity**: use `--no-markup`.
- **osascript**: JSON-encode the message (prevents quoting/injection).
- **swiftDialog**: escape its markup (`* [ ] ( )`) *after* the allow-list pass —
  the allow-list removes most of it, but these are the characters swiftDialog
  still interprets. The current code interpolates `{peer}` directly into a
  swiftDialog markdown string (`sources/sudo-auth-proxy.py:179`) with no
  escaping; that is the concrete bug this replaces (review log NF2).
- **Logging (review log NF8).** The same sanitiser (at minimum the allow-list
  pass) is applied to `guest_hint` and every other field **before it is logged**,
  so a crafted field cannot forge log lines, inject ANSI/control sequences, or
  split records. Never log the raw request bytes.
- Never build a shell command from a field.

### 11.3 Anti-fatigue

- **Rate-limit prompts: max 3 prompts / 60 s / guest.**
- **Exponential backoff starting at 5 s** after each denied/ignored prompt for
  that guest (5 s, 10 s, 20 s, … up to the circuit-breaker threshold).
- **Circuit breaker: opens after 10 denials within 60 s and stays open for
  300 s.** While open, new requests for that guest are auto-denied (signed
  `deny`) without showing a dialog.
- **State lives in server memory with a 10-minute TTL**, keyed by guest (and
  reset when the server restarts). It is best-effort anti-fatigue, not a security
  boundary.
- Coalesce or auto-deny on a flood; never train the approver to click through.
- One pending dialog per approver at a time (or a clearly ordered queue).
- Optional "remember this exact request for N seconds" scoped strictly to the
  same `(guest, user, tty, command digest)`.

---

## 12. Threat model

### 12.1 Assets

- **A1** The ability to make `sudo` succeed in a guest (privilege elevation).
- **A2** The confidentiality/integrity of the request contents (command, users).
- **A3** The approver's attention and the integrity of the decision.
- **A4** The CA and signing private keys.
- **A5** The availability of the approval path.

### 12.2 Adversaries

- **ADV1 — Malicious unprivileged process in a guest** (malware in the VM).
  Wants sudo without approval; can read world-readable files, bind sockets,
  replay, race.
- **ADV2 — A different guest** trying to impersonate another guest or obtain its
  decisions.
- **ADV3 — A different local host user** trying to answer or inject another
  user's prompts.
- **ADV4 — A network attacker** (relevant only if a callback transport is
  exposed beyond a trusted path).
- **ADV5 — The approver's user error** (prompt fatigue / social engineering).
- **ADV6 — A compromised CA/signing key holder.**

### 12.3 Trust boundaries

See §5.5. In short: guest kernel/root is trusted for its own PAM path; network is
untrusted; host user space is trusted but not other host users; CA keys are roots.

### 12.4 Assumptions

- **A1** The host's SSH access to the guest is trusted (host key + `~/.ssh/tartarus`).
- **A2** The guest's `sshd` and the host's `ssh` are not compromised.
- **A3** The guest's PAM stack invokes the shipped client and not something else.
- **A4** The host approver's machine/desktop is not compromised.
- **A5** The helper's privilege context under `sudo` (real vs. effective UID) is
  **not assumed** — it is verified per platform in §19.5 gate 2 (review log F4).
  The design does not depend on the client being unprivileged, and any future
  sandbox must account for the actual uid/euid. Whether the helper can read
  `/proc/$PPID/environ` or root-owned material depends on that verified context;
  the design deliberately does not rely on it (it uses `env_keep`, §4.3).
- **A6** The selector (`SUDO_AUTH_PROXY_SOCK`) and the recursion guard
  (`SUDO_AUTH_PROXY_ACTIVE`) are delivered by `SetEnv`/`AcceptEnv` **and
  guaranteed by `sudoers env_keep` entries** (`Defaults env_keep +=
  "SUDO_AUTH_PROXY_SOCK"` and `... "SUDO_AUTH_PROXY_ACTIVE"`, §4.3, §10.4). The
  `/proc/$PPID/environ` fallback is best-effort and Linux-only, and is not
  assumed on macOS. The multi-fragment `sudoers.d` shadowing risk is called out
  in §4.3 (review log C1).
- **A7** Private keys are protected per §7.8/§9.

### 12.5 Threats and mitigations

| # | Threat | Adversary | Mitigation |
|---|---|---|---|
| T1 | Forge an `allow` into the guest's PAM client | ADV1 | Host-signed, nonce-bound decision envelope; client verifies signature + nonce + digest. (§7.4, §6.5) |
| T2 | Replay an old `allow` | ADV1 | Client **single-use nonce** + request digest + expiry (primary); server nonce cache is defence in depth, evict-oldest + alert on overflow, optional fail-closed. (§6.5, R10) |
| T3 | Change the command shown vs. executed | ADV1/ADV2 | Command digest captured at auth time, signed back; verification fails on mismatch. (§6.4, §5.4) |
| T4 | Guest B impersonates guest A | ADV2 | Per-guest host socket (host-enforced); in callback mode, CA + EKU + ACL guest match. (§5.2) |
| T5 | Person B receives/answers person A's prompt (different host users) | ADV3 | Per-host-user server and socket dir; `SO_PEERCRED` uid check. (§4.2, §9.3) |
| T6 | Person B receives person A's prompt (same guest account, different host users) | ADV3 | Per-host-user guest socket + `SUDO_AUTH_PROXY_SOCK` (guaranteed by `sudoers env_keep`) selects the session owner's socket. Same-UID redirection remains R6. (§4.2, §4.3) |
| T7 | A non-whitelisted user triggers elevation | ADV1 | Server ACL evaluated before the dialog, default deny. (§8) |
| T8 | Network attacker MITM on a callback transport | ADV4 | mTLS with EKU + CA (§7.2); signed envelope end-to-end. |
| T9 | Socket pre-creation / listener race in the guest | ADV1 | Host signature defeats forgery; `lstat` + Linux peer-process check limit redirection. Redirection to a real tunnel remains R6. (§9.2) |
| T10 | Another local host process connects to the server socket | ADV3 | `0700` dir, `0600` socket, `SO_PEERCRED` uid check. (§9.1) |
| T11 | Prompt fatigue / dialog flood | ADV1/ADV5 | Rate limit, coalesce, circuit breaker, single pending prompt, sanitised and detailed context. (§11.3) |
| T12 | Injection into the dialog / spoofed text | ADV1 | Sanitisation per backend, length caps, no markup. (§11.2) |
| T13 | Private key exposure enables impersonation | ADV1 | No `0644` keys; under `unix`, no client key exposed; per-guest isolation for mTLS. (§7.8, §9.2) |
| T14 | CA/signing key compromise | ADV6 | Rotation tooling, short-lived certs, CA-verified keyring; TPM/HSM future work. (§7.7) |
| T15 | DoS: make the tunnel unavailable to force fallback | ADV1 | Fallback is by design; document that the proxy is not a sole factor unless other auth is disabled. (§10.3) |
| T16 | Cross-session decision reuse | ADV1 | Decision bound to nonce + request digest (includes tty); client single-use. (§6.5) |
| T17 | Secret leakage via the dialog/logs | ADV1/ADV5 | Show program + digest by default; never log full argv; opt-in full command. (§11.1) |
| T18 | Recursive/stacked prompts confuse the approver | ADV5 | Guard env var; service shown in the dialog. (§10.4) |
| T19 | Stale socket/ownership tricks | ADV1 | `lstat` + ownership/symlink checks + unlink before bind; receive timeout bound (§10.2) prevents a bound-but-unlistened socket from hanging the client. (§9) |
| T20 | Downgrade to the legacy protocol | ADV4 | `protocol = "envelope"` is the default; legacy/auto are opt-in only. (§6.1) |
| T21 | Same guest UID redirects the client socket to **another person's legitimate tunnel** (valid signature, wrong approver) | ADV1 | `lstat`/no-symlink; Linux `SO_PEERCRED`→`/proc/<pid>/exe` = `sshd`; **residual R6**; per-person guest accounts is the full fix. (§9.2) |
| T22 | `sudo` strips the selector env var → request lands on a shared/wrong socket | ADV1/ADV3 | Mandatory `sudoers env_keep += "SUDO_AUTH_PROXY_SOCK"` deployed by the guest module; static fallback; fast-fail. (§4.3) |
| T23 | Rogue signing key substituted via build/supply chain, then signs forged allows | ADV6 | Distributed like `ca.crt`; treat as CA-sensitive for build-input review; keyring + rotation. (§7.4, §7.7) |
| T24 | Stale guest socket after a crashed session → silent degradation / spoof target | ADV1 | Session-teardown cleanup (exact tokenised path) + `StreamLocalBindUnlink`; receive timeout (§10.2) bounds the read hang; best-effort path checks. (§4.3, §9.2) |
| T25 | **macOS** peer verification is weaker: no `/proc`, and `getpeereid` returns only uid/gid (no pid), so a same-UID process cannot be distinguished from `sshd` | ADV1 | Linux `SO_PEERCRED`→`/proc/<pid>/exe` check does not exist on macOS; rely on socket-path integrity/ownership, the random path token (NF7), and the host signature. Accepted residual **R11**; per-person guest accounts are the full fix. (§9.2, §19.2 F12) |

### 12.6 Residual risks (accepted)

- **R1** Two people sharing one **host** Unix account are one principal (§5.6).
- **R2** A compromised guest **root** can do anything within the guest, including
  reading any guest-held material; the host signature still prevents it from
  fabricating an `allow`, but it can consume approvals and act after a legitimate
  one.
- **R3** Fallback to other PAM methods means the proxy is not a sole gate unless
  other auth is disabled (§10.3).
- **R4** `pam_exec` cannot distinguish `deny` from `unavailable` via exit codes
  (§6.6).
- **R5** The approver's machine or the CA keys being compromised defeats the
  model (out of scope; §12.4/§12.5 T14).
- **R6** **Socket misrouting with a shared guest login account.** A process with
  the shared guest UID can point its own socket path at another person's
  legitimate tunnel (unlink/symlink), causing a *valid, correctly signed*
  approval to be issued by the wrong approver. The signature proves authenticity,
  not *which* tunnel the request traveled; path checks and the Linux
  peer-process check raise the bar but are not atomic. Fix: per-person guest
  accounts (review log F1/F2).
- **R7** **Fallthrough latency tax.** The PAM hook runs on every `sudo`; when no
  tunnel exists the client must fail in ≤200 ms (or skip via the socket-existence
  pre-check) or interactive/automation use degrades (review log Rank 5).
- **R8** **Command field is best-effort.** `/proc/$PPID/cmdline` is
  guest-controlled and wrong for `login`/`su`; it is display/binding only
  (§5.4).
- **R9** **Predictable/raceable guest socket path.** Without the per-session
  random token (NF7) a same-UID guest process could predict and race the
  `RemoteForward` bind path. The token makes the name unguessable, but the bind
  is still not atomic with the peer check; accepted (review log NF7; §4.2).
- **R10** **Nonce-cache behaviour under sustained flood.** On overflow the
  server evicts the oldest entry and alerts (and may be configured to fail
  closed), so a flood cannot *silently* disable duplicate detection; it can
  still add load. The client's single-use nonce remains the primary replay
  defence (review log C3; §6.5).
- **R11** **macOS peer-verification gap.** There is no `/proc` and `getpeereid`
  returns only uid/gid, so the Linux peer-process check (that the connector is
  `sshd`) cannot run on macOS. The platform relies on socket-path
  integrity/ownership, the random path token, and the host signature; same-UID
  misrouting is not fully ruled out (review log C8; §9.2, §12.5 T25).

### 12.7 Non-goals of the threat model

- Protecting against a compromised host OS or host desktop.
- Protecting against a compromised hypervisor.
- Preventing a guest from running the client; the ACL decides whether it may.

---

## 13. Failure modes and troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `sudo` hangs | Long connect timeout / DNS, or a stale socket blocking the read | Ensure `connect_timeout` is small and `recv_timeout` is set (§10.2); use numeric/Unix targets. |
| `sudo` falls through immediately | Tunnel/socket unavailable | Check the SSH session is open, `SUDO_AUTH_PROXY_SOCK` is set, the guest sshd accepts it, and the socket exists. |
| "Peer certificate missing required EKU OID" | Cert minted for another service | Re-issue with the sudo-auth-proxy EKU (CA tooling). |
| Prompt appears on the wrong user's screen | Guest socket path collision / shared account | Use per-session socket names (§4.2); confirm `SetEnv` reached the session. |
| Fake/forged allow suspected | Envelope not enforced | Verify the client verifies the host signature; check `protocol`/signing config. |
| Names show as ids | Guest resolution fallback | Check ACL guest match / mTLS CN / per-guest socket mapping. |
| Reuse proxy reconnecting | Server closes per request or tunnel flapping | Check tunnel health and server loop behavior. |

---

## 14. Compatibility and migration

- **Config:** existing `transport = "vsock" | "tcp"`, mTLS, `mode`, and option
  names are unchanged. `unix` and the new options are additive.
- **Wire:** the legacy line protocol is retained; new peers negotiate the
  envelope. Turning off the legacy path is an explicit option.
- **Firewall:** the `65001` TCP allowance is only needed while a guest uses
  `tcp`/`vsock`; `unix` needs none. Remove it when no guest uses a callback
  transport.
- **Keys:** mTLS material keeps working; the signing key is new and additive.
- **Migration of a guest from `tcp` to `unix`:** enable the SSH forward options on
  the host for that guest, switch the guest transport to `unix`, and rebuild.
  Verify with a test `sudo` while logged in.

---

## 15. Operations guide (setting it up)

### 15.1 Host

1. Ensure the host's SSH config reaches the guest (existing tartarus setup).
2. Enable the server and the signing key.
3. Enable SSH forwarding for the chosen host patterns, e.g.:

   ```nix
   custom.programs.ssh.sudoAuthProxy = {
     enable = true;
     hosts = ["vault.trs" "dev-*.trs"];   # or ["*.trs"] for all
     remoteSocket = "/run/sudo-auth-proxy/%u@%H.sock";  # wrapper appends a random per-session token
   };
   ```

4. Ensure the server socket directory is `0700` and sockets `0600`.

### 15.2 Guest

1. Set `transport = "unix"` (or keep a callback transport).
2. Ensure `/run/sudo-auth-proxy` exists, owned by the guest login user, `0700`.
3. Ensure the guest sshd accepts the selector env var
   (`AcceptEnv SUDO_AUTH_PROXY_SOCK`) **and** that `sudoers` keeps the selector
   and the recursion guard (`Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"` and
   `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"`). Both are deployed by the
   guest module; the `env_keep` entries are what make per-person routing
   deterministic and keep the recursion guard working (§4.3, §10.4).
4. Keep the PAM rule optional (`[success=done default=ignore]`).

### 15.3 Verifying

- Log into the guest, confirm `SUDO_AUTH_PROXY_SOCK` is set and the socket exists.
- Run `sudo true`; the dialog should appear on the correct host session.
- Deny, and confirm `sudo` fails (or falls through, per policy).
- Test with two host users on a shared guest account: each should only see their
  own prompts.
- Enable debug logging and check timings: connect should be fast; the only slow
  part should be the human.

---

## 16. Audit and hardening checklist

**Identity & auth**
- [ ] ACL is evaluated before any dialog; default deny.
- [ ] `ca` mode with an empty `allowed_guests` denies all (`["*"]` to allow any).
- [ ] `unix` pinned modes require `mtls = true` or an SSH-host-key pin; otherwise fail closed.
- [ ] `unix`: per-guest host socket; guest identity cannot be forged.
- [ ] `tcp`/`vsock`: mTLS CA + EKU verified; CN matched against ACL.
- [ ] Host user verified via `SO_PEERCRED`/`getpeereid`.

**Decisions**
- [ ] Response signature verified; nonce and request digest bound.
- [ ] Expiry enforced; replay cache present.
- [ ] Domain separation label present.
- [ ] `alg`/`key_id` present in the transcript; unknown/absent `alg` rejected.
- [ ] No path where an unsigned decision is accepted.

**Sockets/files**
- [ ] Directories `0700`, sockets `0600`, `umask` set before bind.
- [ ] Ownership/symlink checks; stale socket handling.
- [ ] No world-readable private keys; no client private key under `unix`.

**PAM**
- [ ] Fast connect timeout; no long DNS/hang.
- [ ] Receive/response timeout bounds a bound-but-unlistened socket (§10.2).
- [ ] Fallback semantics documented and intentional (`deny` and `unavailable`
      both fall through; strict mode is not available with `pam_exec`).
- [ ] Recursion guard present **and preserved by `env_keep`**.

**UI**
- [ ] All fields sanitised (allow-list + NFC); `--no-markup`/JSON escaping.
- [ ] Rich context shown; rate limiting present (3/60 s, backoff from 5 s,
      breaker 10/60 s → 300 s).
- [ ] Fields sanitised before logging.

**Docs**
- [ ] Threat model matches the implementation.
- [ ] Third-party client warning present (§1.2).

---

## 17. Future work

- Third-party client support (requires a compatibility statement and review).
- TPM/HSM-backed host signing key.
- Two-person approval and command allow/deny policies (reuse the
  `ssh-agent-proxy` rule engine).
- Out-of-band approval (phone/push) for headless approvers.
- Distinguishing `deny` from `unavailable` in the PAM return path (required for
  any non-ignorable `deny`/strict mode; not implementable with `pam_exec`).
- Signed, append-only audit ledger of approvals.

---

## 18. Glossary

| Term | Definition |
|---|---|
| **Envelope** | The versioned, length-framed message carrying a request or a signed decision. |
| **Nonce** | A random per-request value that binds request and response. |
| **Request digest** | SHA-256 over the canonical request, signed back by the host. |
| **EKU OID** | Extended Key Usage object identifier distinguishing service roles. |
| **Tunnel** | The host→guest SSH `RemoteForward` that carries the Unix socket. |
| **ACL** | The authorization policy (§8) deciding who may use the mechanism. |
| **Callback** | Guest dials host (`vsock`/`tcp`). |
| **Approver** | The host user who answers the dialog. |

---

## 19. Design review log

Review **v1** findings (first `audit` + `challenger` pass) are in §19.1–§19.5;
review **v2** findings (second pass, after the revisions) are in §19.6. The
inline edits above reference these IDs. No code is written until the
"must-fix before coding" items are resolved in the design (they now are).

### 19.1 Critical / must-fix before coding

| ID | Finding | Disposition |
|---|---|---|
| F1/F2 | Host signature guarantees *authenticity*, not *routing*. With a shared guest login UID, an attacker can unlink/symlink the socket to another person's legitimate tunnel, and the signer (wrong approver) still produces a valid `allow`. The doc conflated the two. | §9.2 now separates authenticity vs. routing; added Linux `SO_PEERCRED`→`/proc/<pid>/exe` peer check, `lstat`/no-symlink; recorded as residual risk **R6**; recommended per-person guest accounts for strict isolation. |
| Rank 1 | The `SetEnv` → `sudo` → `pam_exec` selector chain is fragile: `sudo`'s `env_reset` can strip `SUDO_AUTH_PROXY_SOCK`, and `/proc/$PPID/environ` may not help (same reset). Silent loss of per-person isolation. | **Fixed in design:** guest Nix module deploys `Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"`. The `/proc` fallback is demoted to best-effort/Linux-only. §4.3, §12.4 A6, §15.2. **Extended by B2 (§19.6)** to also preserve `SUDO_AUTH_PROXY_ACTIVE`. |
| F3 | The reuse proxy relays by `readline()` (newline-delimited); the binary envelope has no guaranteed newline, so it would hang/misframe. | **Decided:** proxy **removed for `unix`** (no TLS handshake to amortise; SSH is the transport security), retained only for `vsock`/`tcp` (§2.3). A length-framed relay is needed only if mTLS-on-`unix` is enabled. |
| F12 | The current CA code mints the guest client key world-readable (`0644`). | §7.8/§9.2: fix in `ca.py`, not just at runtime; Phase 5. |
| F4 | `pam_exec` under `sudo` runs with euid 0, not "as an unprivileged invoking user". | §12.4 A5 corrected; client must not rely on an OS privilege boundary. |

### 19.2 High / medium (fixed in design or explicitly accepted)

| ID | Finding | Disposition |
|---|---|---|
| F5 | A human `deny` is indistinguishable from `unavailable` and falls through, so a local password can bypass the "no". | §6.6/§10.3 warn explicitly; strict mode is **not implementable with `pam_exec`** and requires the native PAM module (§17). Refined by **§19.6 C1**. |
| F6 | `lstat` + `bind`/`connect` is TOCTOU. | Accepted for same-UID peers; noted in §9.1; `O_PATH\|O_NOFOLLOW` suggested. |
| F7 | `/proc/$PPID/cmdline` is spoofable and wrong for `login`/`su`. | §5.4 now labels it best-effort, display/binding only. |
| F8 | Nonce cache bounds unspecified. | §6.5 specifies max 4096 / 120 s TTL / LRU. **Overflow policy revised by §19.6 C3:** evict-oldest + alert (optional fail-closed), not silent drop-new. |
| F9 | Guest config dir is `0755`. | §9.2 now `0750 root <group>`. |
| F10 | Legacy/envelope auto-detection aids downgrade. | §6.1: `protocol = "envelope"` is the default; legacy and auto are opt-in. |
| F11 | `/proc` is Linux-only. | §4.3/§12.4 A6 note macOS has no `/proc` fallback; `env_keep` is the only supported path there. |
| F12 | macOS `getpeereid` returns uid/gid only (no pid). | §9.2: peer-process check is Linux-only; macOS relies on path integrity. |
| Rank 4 | Two people on the same **host** account are one principal; cross-guest within one account is a shared approval pool. | Accepted; documented in §5.6/R1/R6. |
| Rank 5 | Fallthrough adds latency on every `sudo`. | §10.2: connect timeout ≤200 ms + socket-existence pre-check; residual **R7**. |
| Q5 | Signed response should include the approver identity. | §6.3/§6.4 now sign the `approver` field. |
| Rank 10 | "Only whitelisted can elevate" is only true *through this mechanism*. | Goal wording tightened (§1.4, §8); §10.3 warns the ACL gates the proxy, not `sudo`. |
| Rank 6 | Signing public key distribution inherits Nix-store trust. | §7.4 now calls this out explicitly. |

### 19.3 Confirmed sound

- `ssh -R` streamlocal semantics, `StreamLocalBindUnlink`, `ExitOnForwardFailure`,
  `AcceptEnv` necessity (`ssh -G` verified `%C` expansion in `RemoteForward`).
- `SO_PEERCRED` (Linux) / `getpeereid` (macOS, uid/gid only).
- Per-guest host socket enforcing guest identity in `unix` mode.
- Dedicated Ed25519 signing key recommendation (role separation).
- Domain-separation label `"SAP-v1"`; nonce/digest binding; default deny ACL.
- Current `client.key` `0644` and reuse-proxy socket `0666` are confirmed present
  in today's code and are fixed by this design.

### 19.4 Alternatives considered (from the challenger) and disposition

| Alternative | Disposition |
|---|---|
| Back the selector with `sudoers env_keep` and drop reliance on ambient `sudo` behaviour | **Adopted** — deterministic and testable (§4.3); `/proc` kept only as best-effort/Linux. |
| Derive the socket path from `PAM_TTY` (host `ssh` writes guest-side pty metadata) instead of an environment variable | **Deferred** — needs the host `ssh` to write guest-side metadata and a pty→file mapping; more complex than `env_keep`. Revisit if `env_keep` is unworkable. |
| Use `PermitListen` (OpenSSH 8.2+) | **Rejected** — does not remove the client's need to know the socket path; adds sshd config. |
| Remove the reuse proxy for `unix` | **Adopted (decided)** — no TLS handshake to amortise under SSH, and it cannot carry the envelope; kept only for `vsock`/`tcp` (§2.3, plan Phase 1). |
| Show only the program name in the dialog, never the full command | **Partially adopted** — default is program + digest, labelled best-effort; full command is opt-in with a warning (§11.1). |

### 19.5 Empirical verification gates (Phase 2)

Before relying on the `unix` transport in production, verify on each target
platform:

1. `sudo sh -c 'printenv SUDO_AUTH_PROXY_SOCK'` shows the selector (with
   `env_keep` deployed) — and still shows it with `env_reset` defaults.
2. The PAM helper's real/effective uids (`id -u` / `id -ru` from the helper).
3. `/proc/$PPID/environ` readability under the actual `hidepid` setting.
4. `SO_PEERCRED` / `getpeereid` return the expected uid for the connecting `ssh`
   process (macOS is blocking for `unix`).
5. A stale guest socket is cleaned up on session teardown (no silent
   degradation), and a bound-but-unlistened socket is bounded by the
   receive timeout of §10.2 rather than hanging.

### 19.6 Design review log (v2)

A second `audit` + `challenger` pass reviewed the revised design. Two
consistency blockers and a set of follow-up findings came out of this pass; each
is fixed inline and mapped below. Every item here is also bound to a phase in the
`plans/sudo-auth-proxy-redesign.md` **Phase 0.5** fix-mapping table.

| ID | Finding | Disposition |
|---|---|---|
| B1 | §7.4 showed `"SAP-v1"` then nonce, request_digest, decision, times — omitting `approver` and disagreeing with §6.4. | §7.4 now quotes the full §6.4 transcript including `approver`; `alg` + `key_id` added (see NF1). |
| B2 | `SUDO_AUTH_PROXY_ACTIVE` (§10.4) is not preserved by `sudoers env_keep`, so default `env_reset` strips it and the recursion guard silently fails. | `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` mandated wherever the socket selector is (§4.3, §12.4 A6, §15.2). |
| NF1 | Signature algorithm/key were not bound and there was no agility story. | `alg` + `key_id` added to the signed transcript (§6.4, §6.3); the client pins the expected `key_id` and rejects unknown/absent `alg` (§7.4, §7.6). |
| NF2 | Dialog fields (especially swiftDialog markdown) can be injected; the current code interpolates `{peer}` unescaped (`sources/sudo-auth-proxy.py:179`). | §11.2 defines NFC normalisation plus an allow-list `[A-Za-z0-9_.:/@-]` for every attacker-influenced field, with swiftDialog `* [ ] ( )` escaping. |
| NF4 | A stale bound-but-unlistened Unix socket does **not** fail fast: `connect()` succeeds and the client then hangs on `read()`. | §4.3 wording corrected; §10.2 adds a receive/response timeout (`SO_RCVTIMEO`, ~500 ms); T19/T24 updated. |
| NF5 | Rate-limit/backoff/circuit-breaker requirements were vague. | §11.3 fixed to max 3 prompts / 60 s / guest; exponential backoff from 5 s; breaker 10 denials / 60 s → open for 300 s; state in server memory with a 10-minute TTL. |
| NF6 | `list`/`both` pin the mTLS SPKI, but `unix` has no mTLS by default, so the pin had nothing to match. | §8.2/§8.4 define `unix` pinning as the SSH host-key fingerprint or require `mtls = true`; with neither, fail closed. |
| NF7 | The guest socket path is predictable and raceable with the `RemoteForward` bind. | §4.2 adds an unpredictable per-session token to the basename, carried in `SetEnv`; cleanup removes the exact path. Accepted residual **R9**. |
| NF8 | Fields could inject into log records. | §11.2 applies the same sanitiser to `guest_hint` (and all fields) before logging. |
| C1 | Env-resolution order was not stated; `run_client` reads only `config.toml`; `sudoers.d` fragment ordering is fragile. | §4.3 documents `$SUDO_AUTH_PROXY_SOCK` → `config.toml`, flags the code gap as Phase 2 work, and warns a later fragment can negate `env_keep`. |
| C3 | Nonce cache "drop new" on overflow could silently disable duplicate detection under flood. | §6.5 makes the client single-use nonce the primary defence; overflow now evicts oldest + alerts (optional fail-closed). Accepted residual **R10**. |
| C4 | `unix` was framed as more secure than `vsock`/`tcp`. | §3/§4.4 state plainly that it is a *different* trade (no open port, but session-bound availability risk), not strictly more secure. |
| C8 | The macOS limitation (`getpeereid` uid/gid only, no `/proc`) lived only in §19. | Surfaced in the §12.5 threat table (T25) and recorded as residual **R11**. |

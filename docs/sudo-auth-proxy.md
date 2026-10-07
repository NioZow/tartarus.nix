# sudo-auth-proxy — Architecture, Security Model & Threat Model

**Status:** design document (reviewed by `audit` and `challenger` before
implementation; see `plans/sudo-auth-proxy-redesign.md`).
**Audience:** operators of tartarus guests/hosts and reviewers of this service.

> This document is the **source of truth** for _what_ `sudo-auth-proxy` is and
> _how it is expected to work_. The companion
> [`plans/sudo-auth-proxy-redesign.md`](plans/sudo-auth-proxy-redesign.md)
> describes _how_ the redesign is implemented and in what order.

> **⚠️ Authentication is mTLS or nothing.** The service once supported SSH-key,
> ssh-agent and application-layer X.509 request signatures plus host-signed
> responses. All of that was **removed**: mTLS is the only authentication
> mechanism left, and `transport_encryption = "none"` now means literally *no*
> authentication of either peer (§7). Configs that rely on the removed methods
> must migrate (§14).

> **⚠️ Default posture: a soft gate, not a hard gate.** In the default
> configuration a human `deny` and an `unavailable` transport both _fall
> through_ to the next PAM method. If the guest also offers a local password, a
> user can enter it after a deny and still elevate. The proxy is **never** a hard
> gate unless every other auth method is disabled — and even then, `pam_exec.so`
> cannot distinguish a deliberate `deny` from `unavailable`, so a truly
> non-ignorable deny needs the native PAM module of §17. See §10.3 for the full
> discussion. Do not deploy this as a sole control.

---

## Table of contents

1. [Introduction and scope](#1-introduction-and-scope)
2. [Roles and topologies](#2-roles-and-topologies)
3. [Transports, call direction and transport security](#3-transports-call-direction-and-transport-security)
4. [The SSH-forwarded Unix transport in detail](#4-the-ssh-forwarded-unix-transport-in-detail)
5. [Identity model](#5-identity-model)
6. [Protocol and envelope (JSON)](#6-protocol-and-envelope-json)
7. [Authentication, transport security and cryptography](#7-authentication-transport-security-and-cryptography)
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
repository.** Other implementations are _not_ supported and there is **no
compatibility guarantee** for third-party clients. The protocol is documented so
that a future, deliberately-designed client can be added, but doing so requires a
review against this document. In particular, a client must not be assumed to be
trustworthy merely because it speaks the wire format; trust comes from the
cryptographic credential it can prove and the authorization model (§5, §8).

### 1.3 Terminology

| Term                      | Meaning                                                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Guest**                 | The machine where privilege is being elevated (VM, container, remote box). Runs the **client**.                              |
| **Host**                  | The machine where a human approves (usually the operator's desktop). Runs the **server**.                                    |
| **Server**                | Host-side process that shows the dialog and answers.                                                                         |
| **Client**                | Guest-side process invoked by PAM on each `sudo`/`su`/`login`.                                                               |
| **Transport**             | How client and server bytes travel: `vsock`, `tcp`, or `unix`.                                                               |
| **Callback**              | Guest dials the host (`vsock`, `tcp`).                                                                                       |
| **Tunnel**                | Host dials the guest over SSH and forwards a Unix socket into it (`unix`).                                                   |
| **Transport encryption**  | Whether the byte stream itself is encrypted/authenticated: `mtls` or `none`.                                                 |
| **Server authentication** | How the **client** verifies it is talking to the real server: `transport` (mTLS) or `none`.                                  |
| **Client authentication** | How the **server** verifies who is asking: `transport` (mTLS) or `none`.                                                     |
| **Approver**              | The human who answers the dialog; identified by the host user running the server.                                            |
| **Principal**             | A verified cryptographic identity used by the ACL (a trusted public key or certificate, never a socket path or address).     |

### 1.4 Goals and non-goals

**Goals**

- Let a headless guest elevate privilege only with explicit human approval on the host.
- Support a callback direction (`vsock`, `tcp`) for local/high-speed use **and** a
  host→guest SSH-forwarded Unix-socket direction (`unix`) that needs no host
  address and opens no network port.
- Isolate multiple people so one person never answers another person's prompts.
- **Authenticate the server** so a local process cannot make the
  client act on a forged `allow`, and **authenticate the requester** so a
  process cannot make the approver rule on a request it did not send.
  Authentication is cryptographic and independent of the socket path, address
  or any other connection metadata (§7). Both come from the same place now —
  mTLS — so "authenticate by default" means "use `mtls`"; a transport that
  turns it off has to say so on all three knobs.
- Restrict _who may use the mechanism_ (not everyone) by matching **only
  cryptographic credentials** (CA-signed mTLS certificates and their SPKI
  fingerprints).
  This ACL gates the **proxy**, not `sudo` itself: other PAM methods still apply
  if enabled (§8, §10.3).
- Expose exactly **one listening socket per transport** (one callback
  `vsock`/`tcp` endpoint, one host Unix socket), so the transport layer has the
  same shape in every mode (§3).
- Fail fast and stay optional in the PAM stack. **This is a security property,
  not only an availability one:** by default a human `deny` falls through, so
  the mechanism is explicitly _not_ a sole gate (see the warning at the top of
  this document and §10.3).
- Be auditable and simple to reason about.

**Non-goals**

- Mandatory use: the PAM module is an _optional_ authentication path (§10.3).
- A host-side tunnel daemon: the tunnel lives only as long as an SSH session (§4.4).
- Copying the host's `sudoers` policy into the guest; this service only decides
  _whether to allow_, the guest's own PAM/sudo policy still applies.
- Protecting against a compromised host or a compromised guest kernel.
- Third-party client interoperability (§1.2).
- A connection-reuse proxy or any other handshake-caching daemon (§2.3).
- Any insecure fallback: the client never guesses a socket, never reads a
  static path when the session selector is absent, and never downgrades to an
  unauthenticated/legacy protocol (§4.3, §6.1).

---

## 2. Roles and topologies

### 2.1 Client (guest side)

- Installed as a standalone binary (`sudo-auth-proxy`).
- Invoked by `pam_exec.so` as the **first** auth rule for `sudo`, `login`, `su`.
- Reads the guest-side config (`/etc/sudo-auth-proxy/config.toml`).
- Resolves the transport target (§3), builds a request (§6), waits for the
  decision, verifies the server's authentication (§7.2), and exits.
- The helper runs in the PAM authentication context. The repo's existing comment
  says this is the invoking user, but under `sudo` it may retain `euid = 0`
  (setuid root); the exact real/effective UID is a **verified assumption, not an
  assertion** (review log F4, §19.5 gate 2). Either way the client must not rely
  on an OS-level privilege boundary.

### 2.2 Server (host side)

- A per-host-user service (`systemd --user` on Linux, launchd user agent on
  macOS). It must be tied to the approver's login session because it needs that
  user's GUI to show the dialog.
- Listens on **exactly one socket per transport**: one `vsock` or `tcp` endpoint,
  or one Unix socket (`%t/sudo-auth-proxy/server.sock`) for `unix`. There is no
  per-guest socket (review log S1, §19.7) — the guest is identified
  cryptographically, not by the socket it connected to.
- Authenticates the requester (§7.3) and the channel (§7.4), authorizes the
  credential (§8), shows the dialog (§11), and relies on the mTLS channel for
  its own response authentication (§7.2) — or sends the response
  unauthenticated when `server_auth = "none"` is set explicitly.
- Never elevates privilege itself; it only reports a decision.

### 2.3 Reuse proxy — **removed**

The connection-reuse proxy (`mode = "proxy"`) is **removed from the design
entirely** (review log S2, §19.7). It existed only to amortise a per-`sudo` mTLS
handshake, but:

- Under `unix` the SSH channel already provides confidentiality, integrity and
  authentication, so there is no per-`sudo` TLS handshake to amortise.
- A persistent relay adds a daemon, a socket, a raw length-framed relay (the old
  `readline()` relay could not carry the framed protocol at all) and another
  place for identity/routing bugs, for no measured gain.
- Reframing the protocol as newline-delimited JSON (§6) removes the last
  technical reason to keep it.

The client therefore opens a fresh connection per PAM invocation on every
transport. Any `proxy_socket`/`mode = "proxy"` configuration is invalid (§14).

### 2.4 Topologies

**T1 — single operator, several local guests.** One host user owns the server
and the guests. `vsock` for local Linux VMs (fast), `unix` for anything remote.

**T2 — shared host, several people, different Unix accounts.** Each has their own
server (per host user) listening on their own single socket in their own runtime
directory, their own SSH config and their own trust roots. The kernel enforces
isolation via directory/socket ownership and `SO_PEERCRED`.

**T3 — shared host, several people, the _same_ Unix account.** They share a
server and a socket directory. They are, by construction, the same principal at
the OS level; see §5.6 and §12.6 (residual risk).

**T4 — shared guest login account, several host people.** Different host users
connect to the _same_ guest login user. The guest-side bind path is per session
and is selected in-guest by an environment variable, so each person's `sudo`
normally reaches their own approver, and each host user's server independently
authenticates the requester's credential (§4.3, §7.3). Because the selector is
carried in the environment, a multiplexer that outlives (or predates) the SSH
session can pin a stale selector; see §4.6 for the exact behaviour and its
fail-closed rule. Per-person guest accounts remain the only full fix for the
shared-account case (§12.6 R6).

---

## 3. Transports, call direction and transport security

The transport is selected with `transport = "vsock" | "tcp" | "unix"`. It also
determines the **call direction**. In every mode the server exposes **exactly
one listening endpoint**; there is no per-guest or per-session server socket
(review log S1, §19.7).

| Transport | Direction              | Server endpoint (one)                                | Encryption default                                    | Typical use                                                                                              |
| --------- | ---------------------- | ---------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `vsock`   | Callback: guest → host | `(CID, port)`                                        | `none` (point-to-point)                               | Local Linux MicroVMs: no IP stack, fast, no firewall port.                                               |
| `tcp`     | Callback: guest → host | `(host, port)`                                       | `mtls` (recommended; `none` allowed but **insecure**) | Containers, machines without VSOCK, networks where the guest can dial the host.                          |
| `unix`    | Tunnel: host → guest   | `%t/sudo-auth-proxy/server.sock` (one per host user) | `none` (SSH already protects it)                      | Remote machines / real networks, and any case where the guest should not know or reach the host address. |

All three end in the same JSON request/response exchange; only the byte path
differs.

> **`unix` is a _different_ trade, not a strictly more secure one** (review log
> C4, §19.6). It opens no network port and the guest does not need the host's
> address, but it only exists while a live SSH session is up: when the session
> ends the tunnel disappears and the mechanism becomes unavailable (§4.4). The
> callback transports have the opposite profile (an always-listening port, but
> no session dependency). Choose per workload; do not assume `unix` is "more
> secure".

### 3.1 Callback transports (`vsock`, `tcp`)

- The guest knows where the host is (CID, IP or `_gateway`).
- The host listens on a single port; the guest connects.
- **`tcp` defaults to `transport_encryption = "mtls"`, but `none` is allowed**
  (§7.4). Plaintext TCP is MITM-able, so with `none` the stream is neither
  confidential nor protected from an active attacker: with mTLS off there is
  nothing authenticating the decision, because mTLS is the only authentication
  mechanism this service has (§7). Use `none` on `tcp` only over a network you
  control end to end, and prefer `mtls`.
- With `mtls`, the certificate is the requester's identity (§7.3) and the server
  is authenticated by the same handshake (§7.2).
- **`vsock` defaults to `transport_encryption = "none"`**: a vsock connection is
  point-to-point between a guest and the host, with no network path to MITM.
  `mtls` remains available as defence in depth.
- Advantage: works with no active session on either side. Disadvantage: requires
  the guest to know an address and a reachable port (the "hardcoded IP" problem).

### 3.2 Tunnel transport (`unix`) — the direction we added

- The host already has SSH access to the guest (CA-signed host keys,
  `~/.ssh/tartarus`, `tartarus proxy %h`).
- When the host user opens an SSH session to the guest, the SSH client config
  adds a **remote forward** (to the host's single server socket) and an
  **environment variable**:

  ```ssh-config
  Host vault.trs
      # guest listens here; connections are forwarded to the host's single server socket
      RemoteForward /run/sudo-auth-proxy/<user>@<host>-<session-token>.sock %t/sudo-auth-proxy/server.sock
      SetEnv SUDO_AUTH_PROXY_SOCK=/run/sudo-auth-proxy/<user>@<host>-<session-token>.sock
      StreamLocalBindUnlink yes
      ExitOnForwardFailure yes
  ```

- The guest's PAM client connects to the **local** socket path named by
  `SUDO_AUTH_PROXY_SOCK`. It never needs the host's address. The host server
  socket is a _single_ file; every session of that host user forwards to it.
- The snippet above is illustrative: OpenSSH cannot generate a random value, so
  the real mechanism is the `custom.programs.ssh.sudoAuthProxy` **wrapper**
  (§15.1), not a static `Host` block. The wrapper runs the real `ssh` with
  `-o "RemoteForward=<guest_sock> <host_sock>"`, `-o
  "SetEnv=SUDO_AUTH_PROXY_SOCK=<guest_sock>"`, `-o StreamLocalBindUnlink=yes` and
  `-o ExitOnForwardFailure=yes`. It resolves `%r` (the login user) and `%h` (the
  destination as typed) itself, expands `%t` (OpenSSH silently drops `%t` in the
  `RemoteForward` remote field) and substitutes a literal host path.
- The wrapper is installed as **`sudo-auth-proxy-ssh`**, not as `ssh`. A plain
  `ssh <guest>` does **not** carry the forward unless the operator opts in with
  `shadowSsh = true`, which additionally installs an identical `ssh` wrapper that
  shadows the system `ssh` on the user's PATH (§15.1). With the default
  `shadowSsh = false`, use `sudo-auth-proxy-ssh <guest>` (audit N7).
- `<session-token>` is an unpredictable random value generated per SSH
  invocation by the wrapper (`od -An -N16 -tx1 /dev/urandom`), inserted before the
  `.sock` suffix and injected into both `RemoteForward` and `SetEnv`. Randomising
  the basename prevents two sessions of the same host user from clobbering each
  other and stops a same-UID guest process from predicting and racing the bind
  (review log NF7; residual R9). Only the basename is random; the parent directory
  is a literal from Nix.
- Because SSH already authenticates and encrypts the channel, mTLS defaults off
  here. There is no reuse proxy anywhere (§2.3).
- No TCP port is opened; the `65001` firewall rule is unnecessary for `unix`.
- The tunnel exists only while the SSH session is alive (§4.4). When it does not
  exist, the client fails fast and PAM falls through (§10).

### 3.3 Authentication and encryption by transport

Confidentiality/authentication of the byte stream is **separate** from
identification of the principals. mTLS is the only mechanism that does either
(§7); when it is off, the transport must be private by construction or nothing
is authenticated at all. The full rules are in §7; in brief:

- `tcp` → `mtls` by default, `none` allowed but insecure. With `mtls` the TLS
  channel authenticates both peers and is the requester's identity; with `none`
  a network MITM can both read the metadata and forge a decision.
- `vsock` → `none` by default. Nothing authenticates anything; the security
  argument is entirely that a vsock connection is point-to-point between the
  guest and its hypervisor. Set `transport_encryption = "mtls"` for defence in
  depth.
- `unix` → mTLS is the shipped configuration for this transport: the SSH tunnel
  carries the bytes, and mTLS inside it authenticates both ends. `none` is
  possible but then the tunnel is the only protection, which says nothing about
  the guest's right to ask.

There is **no downgrade path**: a transport configured for mTLS refuses to fall
back to plaintext, and a config that turns authentication off must say so
literally on all three knobs (§7.5). Choosing `none` is an explicit operator
decision, never a runtime fallback.

---

## 4. The SSH-forwarded Unix transport in detail

### 4.1 Forward setup

The host is the SSH **client**; the guest is the SSH **server**. Therefore the
correct primitive is `ssh -R` (remote forward), whose arguments are
`bind_socket:connect_socket`:

- `bind_socket` is created **on the guest** (the SSH server side) by the guest's
  `sshd`, running as the guest login user.
- `connect_socket` is the host's **single** server socket
  (`%t/sudo-auth-proxy/server.sock`), connected **on the host** by the SSH client
  process, running as the host user.
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
host:                             ssh (as host user) ──connect──▶ %t/sudo-auth-proxy/server.sock
                                                                        │  (one socket, all sessions)
                                                                        ▼
                                                                   server → dialog
```

Because the host's SSH client makes the host-side connection, the server sees a
peer that is the `ssh` process **run by the host user**. That is the basis of the
host-side `SO_PEERCRED` check (§9.1). It is _not_ how the guest is identified:
with a single socket, the guest identity comes solely from the requester's
cryptographic credential (`client_auth`, §7.3).

### 4.2 Socket naming and per-person isolation

Two problems must be solved:

1. **Guest-side collision.** If two sessions of the same host user forward to the
   _same_ guest socket path, with `StreamLocalBindUnlink=yes` the second session
   silently steals the first's socket. This is unacceptable.
2. **Host-side ambiguity.** One host socket receives connections from every
   session. The server must know which guest and which requester sent a request
   without relying on the socket path.

The design resolves both **without** any per-guest server socket:

- The **guest bind path** is unique per _session_:
  `/run/sudo-auth-proxy/<login-user>@<dest-as-typed>-<session-token>.sock`,
  i.e. `%r@%h` with the wrapper's token appended before `.sock` (default
  `remoteSocket = "/run/sudo-auth-proxy/%r@%h.sock"`, §15.1). `<session-token>`
  is an unpredictable random value generated per SSH invocation by the host-side
  wrapper and injected into the guest in the same `SetEnv` that carries the path.
  The parent directory is a literal from Nix; only the basename token is
  per-session. Randomising it closes a predictable-path race: without the token a
  same-UID guest process could pre-bind or race the name `RemoteForward` is about
  to use (review log NF7; residual **R9**).
- The **host server socket is a single socket for the whole host user**
  (`%t/sudo-auth-proxy/server.sock`), exactly like the one callback endpoint.
  Its identity is therefore irrelevant to routing: the server learns **who is
  asking** from the requester's cryptographic credential and the **approver**
  from the socket's owner (`SO_PEERCRED`, §9.1). A guest cannot claim another
  guest's identity by choosing a socket, because no socket carries identity any
  more.

A `sudo` in `/run/.../alice@laptop-<token>.sock` therefore reaches _Alice's_
server, on _Alice's_ session; the server independently verifies the requester's
key/certificate against its trust roots and applies the ACL (§8). Bob's session
uses a different guest path (and a different token) and cannot interfere. There
is **no explicit teardown hook** (audit A8): the guest's `sshd` removes its own
stream-local forward when the session ends, and `StreamLocalBindUnlink` handles
a same-name re-bind; a stale path can never be _reused_ because each session's
basename is random (see §4.3 and T24).

### 4.3 Session/pty routing (why the environment variable exists)

Topology T4 has different people logging into the **same guest account** (e.g.
all as `user`). At the OS level inside the guest they are indistinguishable, so
the routing key is the session's **selector**: each person's SSH session carries
a _different_ value of `SUDO_AUTH_PROXY_SOCK`, set by their own host's SSH config
to their own socket. `sshd` accepts that variable
(`AcceptEnv SUDO_AUTH_PROXY_SOCK`), so every process in that session — including
the shell, `sudo`, and its `pam_exec` child — inherits it.

The client resolves its target socket from **`$SUDO_AUTH_PROXY_SOCK` and nothing
else** (review log S3/S4, §19.7). The old `/proc/$PPID/environ` fallback and the
static `socket` path are **removed**: a fallback is both a downgrade (an
attacker who strips the variable selects the path) and a source of routing
confusion. If the variable is absent, or the named socket does not exist, the
client **fast-fails** (§10.2) and PAM continues. `sudo`'s default `env_reset`
would strip the unknown variable, which is why the guest Nix module deploys
`Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"` **and**
`Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` (the recursion guard, §10.4)
into `sudoers`. Relying on ambient `sudo` behaviour is explicitly rejected
(review log C1/B2).

> **Implemented (was review log C1).** `run_client` now reads the target socket
> from `$SUDO_AUTH_PROXY_SOCK` **only** and fails closed when it is unset; the
> static config `socket` key and the `/proc/$PPID/environ` fallback are gone. The
> config `socket` key names the **server's** bind path and is ignored by the
> client. This paragraph describes shipped behaviour, not a planned change.

> **Guest directory ownership (answering "can `sshd` even write there?").** The
> `RemoteForward` bind is executed by the guest's `sshd` **as the guest login
> user**, so the parent directory must be writable by that user. A root-owned
> `/run/sudo-auth-proxy` would make every bind fail (loudly, because of
> `ExitOnForwardFailure`). The guest module therefore creates
> `/run/sudo-auth-proxy` **owned by the guest login user with mode `0700`** (via
> `systemd.tmpfiles.rules`, or under that user's `RuntimeDirectory`) — never
> `0755 root:root`. If several people share the login account they share this
> directory; the per-session token still prevents collisions.

> **`sudoers.d` fragility (review log C1) — resolved.** The guest module deploys
> the `env_keep` entries in `security.sudo.extraConfig`, which nixpkgs appends as
> the **tail of `/etc/sudoers`** (verified: this nixpkgs emits no `@includedir`),
> so a later `/etc/sudoers.d/` fragment cannot negate them. `sudoers` still
> evaluates any hand-added fragments in lexical order, so do not shadow these
> entries; an integration test asserts both variables survive.

This is exactly the "resolve the pty/session" requirement: the session's
environment selects the socket, so the request is delivered to the approver who
owns _that_ session. The **requester's identity is not taken from the selector,
the socket path or any other connection metadata**: it comes only from the
cryptographic credential the client presents (§7.3, §8). The pty (`PAM_TTY`) is
recorded in the request and covered by the request digest, so a decision is
bound to the session and cannot be replayed into another one (§6.4).

> **Hard dependency.** The `sudoers env_keep` entries above
> (`SUDO_AUTH_PROXY_SOCK` and `SUDO_AUTH_PROXY_ACTIVE`) are required for the
> `unix` transport's per-session routing and for the recursion guard. They are
> deployed by the guest Nix module, not left to the operator, and are a Phase 2
> exit criterion.
>
> **Stale-socket hygiene (corrected, review logs NF4 and audit A8).** A socket
> left behind by a crashed/aborted session is cleaned up by the guest's `sshd`
> (which removes the stream-local forward it created when the session ends), and
> `StreamLocalBindUnlink` covers a same-name re-bind; `ExitOnForwardFailure`
> covers a _failed bind_, not a stale file from a previous session. There is **no
> explicit, module-deployed teardown hook** — the earlier revision claimed one,
> but none exists in `nix/guest/base.nix`/`default.nix` (audit A8), and this
> paragraph now states the shipped reality. Stale paths cannot collide because the
> per-session basename is random (§4.2). A stale socket does **not** produce a
> fast connection failure: `connect()` to a bound-but-unlistened Unix socket
> succeeds, and the client would then block on `read()`. The first-frame receive
> bound of §10.2 (`recv_timeout`) turns that into a bounded failure so PAM still
> falls through; with the `auth_pending` sentinel that bound no longer competes
> with the human wait.

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
  side of "opens no network port": `unix` is _not_ strictly more secure than the
  callback transports; it trades a listening port for a session dependency. A
  workload that must be approvable when nobody is logged in needs `vsock`/`tcp`
  (§3).
- `ExitOnForwardFailure=yes` makes a failed bind kill the SSH session loudly,
  rather than silently running without a tunnel.
- A `ControlMaster` may be used so several sessions share one connection and one
  forward. Those sessions then share one selector value, which is safe: the
  requester is authenticated cryptographically per request, not by the socket.
  Without `ControlMaster`, each session gets its own tokenised forward as
  described above.

### 4.5 Sequence

```
  guest user        guest client            guest sshd        host ssh            host server             approver
      │  sudo             │                      │               │                     │                     │
      │─────────────────▶│                      │               │                     │                     │
      │      read SUDO_AUTH_PROXY_SOCK           │               │                     │                     │
      │                  │──connect unix──▶     │               │                     │                     │
      │                  │                      │──SSH channel─▶│                     │                     │
      │                  │                      │               │──connect unix──────▶│                     │
      │                  │ request JSON {nonce,user,tty, client_auth=transport|none}  │                     │
      │                  │                      │               │                     │──verify credential──│
      │                  │                      │               │                     │──show dialog───────▶│
      │                  │                      │               │                     │◀────allow/deny──────│
      │                  │◀──response JSON {nonce,decision, request_digest, window} ───────────────────────│
      │                  │ verify digest/window │               │                     │                     │
      │◀──exit 0 / 1─────│                      │               │                     │                     │
```

> `host ssh` in the sequence is the **`sudo-auth-proxy-ssh` wrapper**, which is
> what carries the `RemoteForward`/`SetEnv`; plain `ssh` only does so when
> `shadowSsh = true` is opted into (§3.2, §15.1; audit N7).

### 4.6 Multiplexers (tmux, zellij) and the fail-closed rule

A multiplexer is a long-lived process. Panes are children of the multiplexer
**server**, so they inherit the selector the multiplexer server was started with,
not the selector of the SSH session that attaches later. Consequences:

- If the multiplexer server is started inside an SSH session, all its panes route
  to that session's approver. A later `ssh` that attaches to the same multiplexer
  does **not** change that.
- On a shared guest account, attaching to a multiplexer started by another person
  would route your `sudo` to _that_ person's approver. This is the shared-account
  residual risk R6/R12, not a new property of multiplexers.

Rules that keep every method equally strong (no downgrade):

1. **Never add a fallback.** The client does not re-derive the socket from
   `/proc`, from a fixed path, or from "the newest socket in the directory". A
   wrong or attacker-influenced guess is worse than a clean failure (§4.3).
2. The selector is the only source; a process without one fails closed and PAM
   continues.
3. The request is still cryptographically bound to
   `(credential, invoking user, tty, nonce)` and the client still authenticates
   the server before acting, so a misrouted request is visible to the approver
   and cannot be turned into a forged `allow`.
4. There is exactly **one** routing method; no mode is "less secure". Full
   isolation for the shared-account case is per-person guest accounts (§12.6
   R6/R12).

---

## 5. Identity model

The service must answer four questions. Each has a defined, trusted source.
Identity always comes from cryptography or from the kernel — **never** from a
socket path, a network address, or a self-reported string.

| Question                        | Source                                                                                                                                               | Trusted because                                                           |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Which host person approves?** | The uid that is the accepted peer of the host server socket (`SO_PEERCRED`), i.e. the user running the server.                                       | Kernel-enforced; a process cannot connect as another uid.                 |
| **Which requester sent it?**    | The verified `client_auth` credential: the mTLS peer certificate, or nothing when authentication is explicitly off. | Cryptographic; the server holds the trust roots.                          |
| **Which session / tty?**        | The selector (`$SUDO_AUTH_PROXY_SOCK`) for delivery, and `PAM_TTY` for binding.                                                                      | Selector guaranteed in-session by `env_keep`; tty bound into the request. |
| **Which working directory?**    | `PWD`/`cwd` of the `sudo` process.                                                                                                                   | Guest-provided metadata; shown to the approver and bound to the request.  |

### 5.1 Host person (approver)

- Every mode: the server is one host user's service. In `unix`, the accepted
  connection comes from that user's `ssh` process, and the server verifies the
  peer uid (§9.1). In `tcp`/`vsock`, the approver is the user running the server.
- The approver's identity is **not** claimed by the guest; it is where the server
  runs.

### 5.2 Requester identity (guest / user)

- `client_auth = "transport"`: the mTLS peer certificate authenticates the
  requester; the identity is its leaf SPKI fingerprint (and its CN).
- `client_auth = "none"`: **no identity at all.** The server has nothing to
  verify, so the ACL must be the matching `mode = "none"` and every request is
  authorized by construction (§7.3, §8). The dialog renders this as
  "Unauthenticated requester" rather than an empty field.
- The ACL (§8) matches **only** these cryptographic identities.

### 5.3 Guest login user and session

- `PAM_USER` is the account being authenticated (for `sudo`, usually `root`).
- `PAM_RUSER` / `SUDO_USER` is the invoking user.
- `PAM_TTY` identifies the terminal; it distinguishes concurrent sessions.
- These are provided by the guest and are **not independently verifiable by the
  host**. Their role is to (a) be shown to the approver and (b) be bound into the
  request digest so an approval cannot be replayed onto a different request.
  They are **not** authorization inputs; enforcement is on the credential (§8).

### 5.4 Working directory and command

- `cwd` is recorded and shown as metadata, and is covered by the request digest.
- The **command/argv is not shown in the dialog** (review log S5, §19.7). It is
  guest-controlled and spoofable (`/proc/$PPID/cmdline` can be rewritten with
  `prctl(PR_SET_MM_ARG_START)`, and for `login`/`su` the parent is not `sudo`),
  so displaying it would be misleading while making the prompt noisy. It is
  never an authorization input. The request binds `service + invoking user +
tty + cwd + nonce` instead (through the request digest, §6.4).

### 5.5 Trust boundaries

1. **Guest kernel / guest root** is trusted for the guest's own PAM path only.
2. **Network / channel** between client and server is untrusted; it is protected
   by mTLS (`tcp`, and optionally `vsock`/`unix`) or by the SSH tunnel (`unix`)
   alone when mTLS is switched off. When it is off, nothing authenticates the
   decision end to end (§7.1).
3. **Host user process space** is trusted to run the server, but any host process
   of the same uid can connect to the single server socket. The requester's
   credential (§7.3) and the approver's judgement constrain what such a process
   can cause to appear; §9.1 constrains other uids.
4. **The trust roots** (the X.509 CA, and the certificate keys signed by it) are
   trusted; their compromise is catastrophic and is handled by rotation (§7.8)
   and by keeping private keys off guests.

### 5.6 Shared-account caveat

Two people sharing one **host** Unix account are one principal to the OS: they
share the server, the runtime dir, and the ability to answer each other's
prompts. This cannot be fixed by cryptography and is accepted as a residual risk
(§12.6 R1). Two people sharing one **guest** login account are supported by
per-session routing and cryptographic requester authentication, subject to the
multiplexer caveat of §4.6 and the residual R6/R12.

---

## 6. Protocol and envelope (JSON)

### 6.1 Framing

Messages are **newline-delimited compact JSON** (NDJSON): exactly one JSON
object per line, terminated by `\n`. JSON is chosen over a raw binary structure
because it is simpler to maintain and natural in Python (review log S6, §19.7).
JSON encodes any newline inside a string as `\n`, so the line delimiter is
unambiguous; every string field is still length-capped and sanitised before
display/logging (§11).

- One `\n`-terminated UTF-8 object per message; no pretty-printing on the wire.
- Maximum message size (64 KiB) enforced before parsing; a longer line is
  rejected and the connection closed.
- Parsing is strict. An unknown `v` or `type`, a missing required field, a
  malformed auth block, or trailing data after the object is rejected and fails
  closed. Unknown top-level keys are ignored for forward compatibility.
- `v` is the protocol version (integer, currently `1`).
- There is **no legacy protocol and no auto-detection**. Peers only ever speak
  this JSON protocol, so a peer cannot downgrade the exchange to an unauthenticated or
  differently-shaped message (review log S7; supersedes v1 F10).

### 6.2 Request (`type: "auth_request"`)

| Field            | Purpose                                                               |
| ---------------- | --------------------------------------------------------------------- |
| `v`              | Protocol version (`1`).                                               |
| `type`           | `"auth_request"`.                                                     |
| `nonce`          | 16+ random bytes, base64; correlates request/response; single-use.    |
| `service`        | `sudo` / `su` / `login`.                                              |
| `target_user`    | `PAM_USER` (account being authenticated).                             |
| `invoking_user`  | `PAM_RUSER` / `SUDO_USER`.                                            |
| `rhost`          | `PAM_RHOST` (origin, if any).                                         |
| `tty`            | `PAM_TTY`.                                                            |
| `cwd`            | Current working directory.                                            |
| `client_version` | Protocol/client version.                                              |
| `guest_hint`     | Optional self-reported label (never authoritative; display/log only). |
| `client_auth`    | Authentication block (§6.5).                                          |

```json
{
  "v": 1,
  "type": "auth_request",
  "nonce": "k5X...==",
  "service": "sudo",
  "target_user": "root",
  "invoking_user": "user",
  "rhost": "",
  "tty": "/dev/pts/3",
  "cwd": "/home/user",
  "client_version": "1.0",
  "guest_hint": "vault",
  "client_auth": {
    "method": "transport"
  }
}
```

(Shown pretty-printed for readability; on the wire it is one compact line.)
With `client_auth = "none"` the block is `{"method": "none"}` and carries no
credential at all.

The request is **not** trusted merely because it is well-formed: the `client_auth`
credential must verify against the server's trust roots (§7.3) and the ACL (§8)
must accept the resulting identity. There is no `command`/`command_display`
field; the command is deliberately absent (§5.4).

### 6.2a Pre-dialog acknowledgement (`type: "auth_pending"`)

Once a request has been **authenticated and authorized** — but before the
confirmation dialog is raised — the server sends exactly one acknowledgement
frame:

| Field   | Purpose                              |
| ------- | ------------------------------------ |
| `v`     | Protocol version (`1`).              |
| `type`  | `"auth_pending"`.                    |
| `nonce` | Echo of the request `nonce`.         |

```json
{"v":1,"type":"auth_pending","nonce":"k5X...=="}
```

The frame exists so the client can keep a short **first-frame** bound
(`recv_timeout`) as the stale/unlistened-socket fast-fail of review log NF4,
while bounding the human wait separately with `decision_timeout`: the ack
arrives promptly (authentication and authorization are already done) and the
final `auth_response` is read afterwards (§10.2). It carries **no decision and
is not authenticated**; trust in the final decision still rests entirely on
`server_auth`/mTLS (§7). Its only validation is a strict envelope and a matching
`nonce`: an unknown, missing or mismatched `auth_pending` is a fail-closed
`ProtocolError` and the client exits `unavailable`.

A request that is authenticated but **not** authorized is denied without a
dialog and therefore **without** an ack; its first and only frame is the
`auth_response`. A pre-`auth_pending` server likewise sends only the response.
The client accepts either shape: if the first frame is `auth_pending` it reads
the response next, otherwise it treats the first frame as the response. The
frame is a v1 frame type; peers must be upgraded together (§14.1).

### 6.3 Response (`type: "auth_response"`)

| Field                     | Purpose                                                                                                                     |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `v`                       | Protocol version (`1`).                                                                                                     |
| `type`                    | `"auth_response"`.                                                                                                          |
| `nonce`                   | Echo of the request nonce.                                                                                                  |
| `request_digest`          | SHA-256 over the canonical request (including `client_auth`).                                                               |
| `decision`                | `allow` / `deny`.                                                                                                           |
| `approver`                | The host user that answered (informational).                                                                                |
| `issued_at`, `expires_at` | Freshness window.                                                                                                           |

There is **no** `server_auth` field: the response is authenticated by the mTLS
channel when `server_auth = "transport"`, and not at all when it is `"none"`
(§6.5).

### 6.4 Canonicalisation and request digest

mTLS is the only authentication mechanism (§7), so the wire protocol carries no
signature and no domain-separation label: there is nothing to sign. What
remains is the **request digest**, which still binds a response to the exact
request it answers:

- The **request digest** (`request_digest`) is the **lowercase hexadecimal**
  encoding of SHA-256 over the canonical serialisation of the request object
  (keys sorted, UTF-8, no insignificant whitespace): 64 hex characters, e.g.
  `9f2c…`. The implementation computes
  `hashlib.sha256(canonical_bytes(request)).hexdigest()`; nothing is stripped
  from the object first, because there is no `signature` field to strip.
- The digest is checked unconditionally by the client, whether or not the
  channel is authenticated, so a response cannot be re-pointed at a different
  request (or replayed onto a re-sent one).

> **Removed:** `client_auth`/`server_auth` signatures, the `alg`/`key_id`
> fields, the SSH wire-blob key encoding, the `signing_payload` transcript and
> the `tartarus/sudo-auth-proxy/v1` domain-separation label (review log S8).
> They belonged to the `ssh`/`x509`/`signature` mechanisms, which no longer
> exist.

### 6.5 Authentication blocks

`client_auth` is a one-field marker naming the mechanism (all values are
strings):

| `method`      | Fields present | Meaning                                                                                                       |
| ------------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| `"transport"` | _(none)_       | mTLS only. No `alg`/`key_id`/`signature`: the channel certificate is the credential.                            |
| `"none"`      | _(none)_       | No credential is carried at all; accepted only when the server is configured the same way, with `acl.mode = "none"`. |

A `client_auth.method` that does not match the server's configured
`client_auth` is rejected outright, as is a missing block.

`server_auth` has **no wire representation**: the response is authenticated by
the mTLS channel when `server_auth = "transport"`, and not at all when it is
`"none"`. The response still carries `nonce`, `request_digest` and the freshness
window, which the client checks unconditionally.

### 6.6 Nonce, freshness and replay

- The client generates a fresh nonce per request and accepts **at most one**
  response for it. A response whose `nonce` or `request_digest` does not match,
  or which is expired, is rejected. This is the entire replay defence; **there
  is no server-side nonce cache** (review log S9, §19.7). Because each
  `pam_exec` invocation opens a fresh connection with a fresh nonce, a captured
  old `allow` can never match a new request.
- Expiry is short; clock skew is tolerated within a configured window. The
  binding is `nonce + request_digest`, so a correct decision is valid regardless
  of clock as long as the client accepts it once.

### 6.7 Errors and exit codes

The client exits `0` on a verified allow and non-zero otherwise. It distinguishes,
for logging:

- `denied` — a valid decision of `deny`.
- `unavailable` — transport unreachable, timeout, parse/verify failure
  (including a `client_auth` method the server is not configured for, §7.3).

> **Limitation.** `pam_exec.so` collapses a non-zero exit to a generic failure;
> PAM cannot branch on `denied` vs `unavailable` via the exit code alone. Both
> therefore take the same control path in the default configuration
> (`[success=done default=ignore]`, §10.3). This is documented rather than
> hidden; a strict mode requires a native PAM module and is **not implementable
> with `pam_exec`** (§17).

### 6.8 Implementation conventions (wire details, pinned)

This subsection fixes the exact conventions the shipped implementation chose and
that §6.1–§6.7 leave implicit. A future client written against this document must
reproduce these byte-for-byte; it exists so no one has to read the source to write
one. Source of truth: `nix/packages/sudo-auth-proxy/sudo-auth-proxy.py`.

**Framing**

- One compact JSON object per `\n`-terminated UTF-8 line (NDJSON). The encoder
  uses compact separators `(",", ":")` and `ensure_ascii=False`, so non-ASCII
  characters travel as UTF-8 bytes and are **not** `\uXXXX`-escaped. There is no
  pretty-printing, no leading whitespace and no trailing whitespace before the
  `\n`. JSON escapes any newline inside a string, so the delimiter is
  unambiguous.
- `v` is the JSON integer `1`. The check is `type(v) is int`, so `true`/`false`
  are **not** accepted as `0`/`1`. `type` is exactly one of `"auth_request"`,
  `"auth_response"` or `"auth_pending"` (`"auth_pending"` is the pre-dialog ack
  of §6.2a, sent only between the request and the response).
- The frame cap is exactly `64 * 1024 = 65536` bytes, applied to the raw bytes
  **before** UTF-8 decoding and JSON parsing, and also enforced before sending. A
  line that reaches the cap without a `\n` is rejected.
- Parsing is strict: invalid UTF-8, invalid JSON, trailing bytes after the object
  on the same line (`json.loads` rejects them), a non-object top level, an
  unknown `v`, an unknown `type`, a missing required field, or a malformed auth
  block is fail-closed (`ProtocolError`). **Unknown top-level keys are ignored**
  for forward compatibility.
- Required request fields (all must be strings): `nonce`, `service`,
  `target_user`, `invoking_user`, `rhost`, `tty`, `cwd`, `client_version`.
  `guest_hint` is optional (string). `nonce` is standard base64 (validated with
  `validate=True`) decoding to **at least 16** bytes; the shipped client sends 32.
- An unexpected `type` is rejected by both peers; a request and a response are
  never multiplexed on one frame.

**Canonicalisation**

- Canonical form is
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
  encoded as UTF-8. Keys are sorted at **every** level; there is no insignificant
  whitespace.
- The **wire frame itself is not key-sorted** — it is the producer's dict
  insertion order with compact separators. Canonicalisation is recomputed by the
  verifier from the parsed object, so wire key order is irrelevant to the digest.
- The digest is taken over the message **as it is**; there is no signature field
  to strip any more (§6.4).
- `request_digest` is the **lowercase hex** SHA-256 (64 chars) of the canonical
  request object. The client recomputes it and rejects any mismatch.

**Credential fingerprints (mTLS only)**

- `key_id` format: `SHA256:` + base64(SHA-256 of the DER
  **SubjectPublicKeyInfo**) of the peer leaf certificate, base64 padding
  stripped. The same string appears in `[acl].trusted_fingerprints`.
- Fingerprint lists accept the padded or unpadded form and normalise to the
  unpadded one.
- There is no `alg`/`signature`/`public_key`/`cert` field anywhere in the
  protocol: the credential is the TLS certificate, which `ssl` has already
  validated by the time any JSON is parsed.

**Response freshness**

- `issued_at` and `expires_at` are Unix-epoch **integers** (seconds);
  `expires_at = issued_at + [security].response_ttl` (default 30) and
  `expires_at` must be greater than `issued_at`.
- The client accepts a response from `issued_at - [security].clock_skew` to
  `expires_at + [security].clock_skew` (default skew 5 s), and rejects a second
  response for the same nonce.
- `approver` is optional and informational.

**Client transport selector and dialog rendering**

- `unix` client: the target is read from `$SUDO_AUTH_PROXY_SOCK` **only**. There
  is no config-`socket` fallback, no `/proc` lookup and no "newest socket"
  heuristic. If it is unset, or the path is not a socket, is a symlink, or is not
  owned by the expected user, the client exits non-zero (fail closed, §4.3).
  `vsock`/`tcp` take their address from `transport`/`host`/`cid`/`port`.
- The per-session token in the guest socket basename is generated by the host
  wrapper (`od -An -N16 -tx1 /dev/urandom`, 32 hex characters) and placed before
  the `.sock` suffix; the same value is injected into the `RemoteForward` bind and
  the `SetEnv` selector. Only the basename is random (§3.2, §4.2).
- After a `unix` connect, Linux additionally resolves the peer's executable
  (`SO_PEERCRED` → `/proc/<pid>/exe`), rejects a kernel-marked `" (deleted)"`
  target, requires the basename to be `sshd`, and — unless an explicit allow-list
  of real `sshd` paths is configured — requires the target to be a regular file
  **owned by root (uid 0) and not by the peer uid**, and not writable by the
  peer's gid or the world. Because the real `sshd` binary is root-owned while the
  forwarding process runs as the guest user, a same-UID attacker's own read-only
  copy named `sshd` (`chmod 0555`) is rejected — the Round 2 A7 bypass. This
  raises the bar on misrouting but is **not** a kernel-attested `sshd` identity;
  the same-UID selector-race residuals R6/R9 remain accepted. The check is
  unavailable on macOS, which relies on path/ownership and server authentication
  (§9.2, R11).
- Dialog rendering is per-backend and never builds a shell string: `zenity` uses
  separate argv entries with `--no-markup`; `osascript` embeds a
  `json.dumps`-encoded message in the script source; `swiftDialog` applies
  `escape_swiftdialog_markup` after the allow-list pass (§11.2).

The `[security]` and `[acl]` tables the implementation actually parses are
listed in §7.9 and §8.5.

---

## 7. Authentication, transport security and cryptography

### 7.1 What must be proven

**mTLS is the only authentication mechanism this service has.** Two questions
have to be answered, and `transport_encryption = "mtls"` answers both at once:

1. **Requester authenticity** — "who is asking?". Without it, any process that
   can reach the socket (a same-uid guest process, or a hostile guest that
   reaches a callback endpoint) can make the approver rule on requests it did
   not send. Provided by the mTLS client certificate
   (`client_auth = "transport"`).
2. **Channel confidentiality, integrity and server authenticity** — "can anyone
   read or modify the bytes, and may the client trust this `allow`?". Without
   it, a process that can bind the client's socket (a fake listener racing
   `sshd` in the guest) could answer `allow`. Provided by the same handshake
   (`server_auth = "transport"`).

There is deliberately **no message-level cryptography left**. The earlier
designs signed each request (SSH or X.509 key) and each response (host key), and
carried a domain-separation label; all of that was removed. Two consequences
follow, and both are stated rather than hidden:

- Layering a message signature on top of the TLS certificate is no longer
  possible. The mTLS identity _is_ the credential.
- With `transport_encryption = "none"` **nothing is authenticated** — neither
  the requester nor the response. The service still runs (that is what makes
  `vsock`/`unix` usable), but the entire security argument becomes "this
  transport is private by construction". §7.5 therefore requires the operator to
  write that decision down on all three knobs; it can never happen implicitly.

### 7.2 Server authentication method (`server_auth`)

How the **client** can trust the server's decision. Exactly one value:

| Value         | Meaning                                                                                                                                                                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"transport"` | The server is authenticated by the mTLS handshake (its certificate, CA-verified plus EKU). Requires `transport_encryption = "mtls"` and is then the **only** allowed value.                                                                                            |
| `"none"`      | **Not recommended.** Nothing authenticates the response, so the client trusts whatever answered on the socket. Acceptable only where the socket can be bound solely by the legitimate server (`0600` in the server user's `0700` runtime dir, or a private vsock link). **Strongly discouraged on `tcp`** (a network MITM could impersonate the server). |

The former `"signature"` value — the host signing every response with Ed25519/RSA
and the client verifying it against a pinned keyring — is **removed**. mTLS is
the replacement; there is no configuration in which a response is signed.

### 7.3 Client (requester) authentication (`client_auth`)

How the **server** knows who is asking. Exactly one value:

| Value         | Meaning                                                                                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"transport"` | **Client authentication is delegated to the transport:** the mTLS peer certificate authenticates the requester (CA chain + EKU), with no separate request signature. Requires `transport_encryption = "mtls"`. |
| `"none"`      | **No requester authentication.** The request carries a `{"method": "none"}` marker and nothing else. Only accepted when the `[acl]` is the matching `mode = "none"` (a fail-closed XOR, §8.3), and the service warns loudly at startup.        |

The former `"ssh"` (SSH-key or ssh-agent signatures, verified against a
`trusted_keys` fingerprint list) and `"x509"` (an application-layer certificate
plus a request signature) methods are **removed**, together with everything that
existed to serve them: the `ssh_signing_key`/`ssh_agent`/`ssh_agent_socket`/
`ssh_key`/`client_cert`/`client_key`/`ca_file`/`client_required_oid`/
`trusted_server_keys`/`server_signing_key`/`trusted_keys` configuration keys, the
signature algorithm allow-lists, the SSH wire-blob key encoding, the ssh-agent
protocol client, and the `[acl].trusted_keys` SSH fingerprint list.

> **What this costs.** An SSH-key or X.509 credential could be used _without_
  paying for a TLS handshake per `sudo`, and it identified the requester
  independently of the channel. Under mTLS on a callback transport the requester
  identity is now only as strong as the channel, and the requester must hold a
  certificate the server's CA trusts. One CA-issued identity per guest remains
  the model (§7.6).

### 7.4 Transport encryption (`transport_encryption`)

Whether the byte stream itself is encrypted, integrity-protected **and**
mutually authenticated:

| Value    | Allowed for                                     | Effect                                                                                                                                                                                                                                                                                                                                                       |
| -------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"none"` | `unix`, `vsock`; `tcp` **allowed but insecure** | Plain JSON, and **no authentication of either peer**. Legitimate only when the transport is private and MITM-free by construction: the SSH tunnel, a vsock connection, or a local Unix socket reachable only by the server user. On `tcp` the channel is MITM-able and nothing authenticates the decision, so the only real use is a network you control end to end. |
| `"mtls"` | `tcp` (default), `vsock`/`unix` (optional)      | A TLS channel with certificates from the shared X.509 CA. It provides confidentiality, integrity **and** mutual authentication, which is why it forces **both** `client_auth = "transport"` and `server_auth = "transport"` — the only allowed pair.                                                                                                                  |

A transport configured for `mtls` **refuses to start** if it cannot establish
TLS; it never silently falls back to plaintext. Choosing `none` is an explicit
operator decision (see the next section).

### 7.5 Valid combinations and no-downgrade rules

| `transport` | `transport_encryption` | `client_auth`   | `server_auth`   | Authenticated by |
| ----------- | ---------------------- | --------------- | --------------- | ---------------- |
| `tcp`       | `mtls`                 | `transport`     | `transport` (**only**) | the TLS channel |
| `tcp`       | `none` (**insecure**)  | `none` (**only**) | `none` (**only**) | nothing — explicitly switched off |
| `vsock`     | `none`                 | `none` (**only**) | `none` (**only**) | nothing — explicitly switched off |
| `vsock`     | `mtls`                 | `transport`     | `transport` (**only**) | the TLS channel |
| `unix`      | `none`                 | `none` (**only**) | `none` (**only**) | the SSH tunnel only (not the requester) |
| `unix`      | `mtls`                 | `transport`     | `transport` (**only**) | the TLS channel inside the SSH tunnel |

Validation rules (all fail closed, no runtime downgrade):

- Under `mtls`, **both** `client_auth` and `server_auth` must be `"transport"`.
  An explicit different value is rejected rather than silently overridden, and
  `mtls.enable = true` conflicts with `transport_encryption = "none"`.
- With `transport_encryption = "none"`, a **missing** `client_auth` or
  `server_auth` is an **error**, not a silent `"none"`:

  > `transport_encryption = 'none'` requires an explicit `client_auth = 'none'`
  > and `server_auth = 'none'` (refusing to disable authentication implicitly;
  > use `transport_encryption = 'mtls'` to authenticate)

  This is the one place where the removed mechanisms left a gap: previously an
  unset knob defaulted to the working `ssh`/`signature` pair. There is no
  working pair to default to any more, and defaulting to "no authentication"
  would be a silent security downgrade, so the operator must say it.
- `client_auth`/`server_auth` may not be a list or a `+`-joined string: asking
  for more than one method is rejected rather than resolved.
- The Nix modules turn all of the above into **evaluation-time assertions**, so a
  bad combination fails the build instead of failing inside PAM (where
  `pam_exec.so` would collapse it into a silent fall-through).
- `tcp` + `none` is permitted but warns that the channel is insecure **and**
  nothing authenticates the decision.

### 7.6 EKU OIDs

The design assigns each service a private-enterprise-number OID pair. **However,
per-service isolation is not implemented today (audit A4):** the CA (`ca.py`)
mints the host certificate with **all three server OIDs** and a guest client
certificate with **all three client OIDs**. The OIDs therefore separate the
_server_ role from the _client_ role, but they do **not** prevent a certificate
minted for one service from being used for another. In particular, under
`acl.mode = "ca"` any guest's tartarus client certificate (which carries
`1.3.6.1.4.1.99999.1.2`) authorizes sudo-auth-proxy, clipboard-bridge and
ssh-agent-proxy alike. This is one CA-issued identity per guest; per-service
issuance is future work. The table below records the intended mapping:

| Service          | Server OID (client must see in server cert) | Client OID (server must see in client cert) |
| ---------------- | ------------------------------------------- | ------------------------------------------- |
| sudo-auth-proxy  | `1.3.6.1.4.1.99999.1.1`                     | `1.3.6.1.4.1.99999.1.2`                     |
| ssh-agent-proxy  | `1.3.6.1.4.1.99999.2.1`                     | `1.3.6.1.4.1.99999.2.2`                     |
| clipboard-bridge | `1.3.6.1.4.1.99999.3.1`                     | `1.3.6.1.4.1.99999.3.2`                     |

The implementation enforces the _client_ OID on the leaf for mTLS, but because
every client cert carries every client OID that check is not discriminating.
Tightening this requires issuing one certificate per service (or narrowing
`ca.py` to a per-service OID and provisioning separate certs).

### 7.7 Algorithms and keys

There are **no signing keys any more**. The only cryptographic material the
service touches is the mTLS set, and all of it is configured under `[mtls]`:

| Material           | Where                          | Notes                                                                                                                              |
| ------------------ | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| CA certificate     | `[mtls].ca_file` (both sides)  | Trust root for the peer chain; also `acl.ca_file` in `mode = "ca"`.                                                                 |
| Peer certificate   | `[mtls].cert_file`             | The identity the other side verifies.                                                                                              |
| Peer private key   | `[mtls].key_file`              | `0600`, owned by the user running the process (§9.2). Never in the Nix store.                                                       |
| Required EKU OID   | `[mtls].required_oid`          | Must be present in the **local** certificate; checked at startup before the socket is opened.                                       |
| Peer EKU OID       | `[mtls].peer_required_oid`     | Must be present in the **peer** certificate; checked after the handshake, on both ends.                                             |

Because identity comes from the certificate, the peer is never authenticated by
hostname or address (a VSOCK CID or a DHCP lease is not a name): the EKU OID is
the real trust check. Chain verification is the same explicit, linear,
single-tier-capable walk used everywhere else in this repository (validity
window, `BasicConstraints: CA`, `keyCertSign`, `digitalSignature`, unrecognized
critical extensions rejected).

### 7.8 Key distribution, lifecycle, rotation and permissions

- `ca.py` (invoked by the tartarus CLI) mints the CA, the host server
  certificate and the per-guest client certificate, and writes the private keys
  `0600` (review log F12). The guest module copies them to
  `/etc/tartarus/x509/{ca.crt,client.crt,client.key}`; the host keeps its own
  under the same root.
- Rotation is a re-issue plus a service restart: the CA is read on every use
  rather than cached, so replacing `ca.crt` takes effect without a rebuild.
- **Nothing is copied into the Nix store except public material.** Private keys
  are referenced by path and written by `ca.py` at runtime; the store is
  world-readable.
- The requester's certificate is what `[acl] mode = "list"` pins (its leaf SPKI
  fingerprint) and what `mode = "ca"` chains to the CA.

### 7.9 `[security]` table as parsed

The implementation reads exactly these keys, and the whole file is validated
against an **exact schema**: every key, at every level, must be one the service
reads. A typo (`max_connection`) and a key on the wrong side of a `[table]`
header are both startup errors that name the offending key — nothing is silently
ignored. That rejects the keys that belonged to the removed mechanisms
(§7.2, §7.3): a config that still sets `ssh_signing_key` or `server_signing_key`
**refuses to start** rather than running without the setting its operator
believes is in force.

The placement rule is the one worth spelling out, because TOML is what makes it
tricky: a key belongs to the **nearest preceding `[table]` header**. The three
knobs below are therefore only `[security]` keys when they sit *under*
`[security]`; written above it they are top-level keys, the service sees no
`[security]` values at all, and the error says so:

> `'client_auth' must be written in [security], but it is written at the top
> level (TOML assigns a key to the nearest preceding [table] header)`

That distinction matters because the alternative — "unknown keys are ignored" —
turned exactly that config into `transport_encryption = 'none' requires an
explicit client_auth = 'none'`, which names the one thing the operator *had*
written and never mentions where it went. The exact schema is what makes the
failure diagnosable in one line, and it is fail-closed in the same direction as
everything else here: an unread key is refused, never assumed.

The accepted names are: top level `mode`, `transport`, `cid`, `host`, `port`,
`socket`, `socket_dir_mode`, `socket_mode`, `connect_timeout`,
`decision_timeout`, `recv_timeout`, `max_connections`, `server_read_timeout`,
`dialog_program`, `resolution`, `debug`, `approver`, `client_version`,
`guest_hint`; the tables `[security]`, `[acl]` and `[mtls]`; and the keys listed
for each in this section, §8.5 and §7.7. `[acl].labels` is the one free-form
table (fingerprint → display label). Values are still typed where they are used,
so the schema checks *names*; `examples/sudo-auth-proxy-server.toml` is checked
against it by the test suite.

| Key                   | Used by | Type / values                 | Notes                                                                                                     |
| --------------------- | ------- | ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `transport_encryption` | both    | `"none"` \| `"mtls"`          | Default `tcp → "mtls"`, `vsock`/`unix` → `"none"`. `mtls.enable = true` is treated as `"mtls"`. Never a runtime fallback. |
| `client_auth`         | both    | `"transport"` \| `"none"`     | Forced to `"transport"` under mTLS. With `transport_encryption = "none"` it must be written explicitly.     |
| `server_auth`         | both    | `"transport"` \| `"none"`     | Forced to `"transport"` under mTLS. With `transport_encryption = "none"` it must be written explicitly.     |
| `response_ttl`        | both    | int seconds (default `30`)    | `expires_at = issued_at + response_ttl`.                                                                   |
| `clock_skew`          | both    | int seconds (default `5`)     | Tolerance in both directions when checking the freshness window.                                            |

The `[mtls]` table (`enable`, `ca_file`, `cert_file`, `key_file`,
`required_oid`, `peer_required_oid`) carries the certificate material and the
EKU checks; `enable = true` is equivalent to `transport_encryption = "mtls"`, and
under mTLS both auth knobs are forced to `"transport"`. Paths inside `[mtls]` are
resolved relative to the **config file's directory**, and a leading `~/` is
expanded.

## 8. Authorization model (who is allowed to use the mechanism)

**Principle: nobody is allowed by default; a request is eligible only if its
cryptographically verified credential matches the configured policy, evaluated
_before_ the dialog is shown.**

This ACL governs **access to the proxy mechanism**, not access to `sudo`: an
unlisted requester can still elevate through any other PAM method the guest
offers. To make the proxy a sole gate, the other methods must be disabled _and_ a
non-ignorable `deny` enforced — which is **not implementable with `pam_exec`**
and requires the native PAM module of §17 (see §10.3). This distinction is
deliberate (review log Rank 10).

The ACL matches **only cryptographic material** — CA-signed client certificates
and their fingerprints, or a deliberate "no credential at all". It deliberately
does **not** match the transport, the destination, the socket path, the network
address, or a self-reported guest name (review log S11, §19.7). Those are
metadata: they cross transports badly and can be spoofed, so they are never an
authorization input.

### 8.1 Modes

Server config `[acl]`:

| `mode`   | Meaning                                                                                                                |
| -------- | ------------------------------------------------------------------------------------------------------------------------ |
| `"ca"`   | Accept any mTLS credential that chains to a configured trusted CA and carries the service EKU OID.                       |
| `"list"` | Accept only credentials whose **leaf SPKI fingerprint** is explicitly listed. An empty list denies everyone.              |
| `"none"` | Authorize **every** request, because `client_auth = "none"` leaves no credential to authorize. Accepted only when the configured `client_auth` is also `"none"` (a fail-closed XOR) and no trust material is set. |

### 8.2 What is matched

- **Certificate SPKI fingerprint** — `SHA256:...`, the mTLS leaf's
  SubjectPublicKeyInfo hash (`trusted_fingerprints`, for `mode = "list"`; an
  optional extra pin in `mode = "ca"`).
- **CA chain + EKU** — for `mode = "ca"`, the leaf must chain to `ca_file` and
  carry `required_oid`.
- An optional **label** attached to a trusted credential, used only to name it in
  the dialog/log. It is not an authorization input and is never accepted from the
  requester.
- **Not matched:** `PAM_USER`, `PAM_RUSER`, `PAM_TTY`, `rhost`, socket path, IP,
  CID, or `guest_hint`. The former SSH-key fingerprint list (`trusted_keys`) is
  **gone** along with `client_auth = "ssh"` (§7.3).

### 8.3 Defaults and fail-closed

- Default is deny. Empty trust lists allow nobody; there is no wildcard shortcut.
- An unknown or unverifiable credential is rejected and logged, never prompted.
- `mode = "none"` and `client_auth = "none"` must agree: the pair is an XOR.
  `client_auth = "none"` without the ACL (and vice versa) is a startup error,
  never a silent decision.
- A request that fails the ACL is answered with a `deny` (authenticated by mTLS
  when `server_auth = "transport"`), or not answered — never silently ignored.
- `resolution = "none"` (or an unresolved peer) yields **no matching identity**
  (§11.5): the resolved name is display-only, so only a `"*"`/empty `identity`
  selector can match. Never authorize an unauthenticated peer by a specific
  display-name pattern.

### 8.4 Worked examples

```toml
# Any credential that chains to the tartarus CA with the client EKU
# (the shipped configuration for the `unix` transport).
[acl]
mode = "ca"
ca_file = "./ca.crt"
required_oid = "1.3.6.1.4.1.99999.1.2"

# Or pin specific mTLS leaf SPKI fingerprints.
[acl]
mode = "list"
trusted_fingerprints = ["SHA256:AbCdEf...", "SHA256:GhIjKl..."]

# Unauthenticated callback transport: authorizes every request on purpose.
[acl]
mode = "none"
```

### 8.5 `[acl]` table as parsed

The server reads exactly these keys; the client never sees this table.

| Key                    | Mode         | Type / values                                     | Notes                                                                                                      |
| ---------------------- | ------------ | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `mode`                 | both         | `"list"` (default) \| `"ca"` \| `"none"`          | Exactly one mode; there is no `ca` + `list` combination. A missing table is a valid **deny-all** `"list"` policy. |
| `trusted_fingerprints` | `list`, `ca` | list of `SHA256:...` mTLS leaf SPKI fingerprints  | In `list`, the allow-list. In `ca`, an **optional** additional leaf-SPKI pin on top of the CA chain.        |
| `ca_file`              | `ca`         | path (PEM)                                        | Trusted CA. Required in `ca`; forbidden in `list`. Resolved against the config directory.                   |
| `required_oid`         | `ca`         | OID string                                        | EKU the requester certificate must carry. Required in `ca`; forbidden in `list`.                            |
| `labels`               | all but `none` | table: `SHA256:...` → string                    | Display/log label for a credential. **Not** an authorization input and never accepted from the requester.   |
| `rule`                 | all          | array of tables (`[[acl.rule]]`)                  | Optional approval rules (§8.6); first match wins, no match means `ask`. Accepted under every mode.          |

Validation rules (all fail closed, at startup):

- A fingerprint entry must start with `SHA256:` and decode to exactly 32 bytes;
  padding is accepted and normalised away.
- `mode = "ca"` requires `ca_file` and `required_oid`, and the CA file must be
  readable at load time.
- `mode = "list"` forbids `ca_file`/`required_oid` (use `mode = "ca"`).
- `mode = "none"` forbids **all** trust material (`trusted_fingerprints`,
  `ca_file`, `required_oid`): a pin the operator believes is enforced must never
  be silently ignored.

> **mTLS chain limitation (audit A12).** `acl.mode = "ca"` rebuilds the chain
> from the peer **leaf DER only** (`ssl` exposes the peer certificate, not the
> sent chain). A single-tier CA — the tartarus CA — validates correctly; a
> **multi-tier** mTLS CA would need its intermediate certificates passed to the
> ACL verifier. `ca.py` is single-tier today, so this is latent. Use
> `mode = "list"` (leaf SPKI pins) for a multi-tier mTLS deployment until the
> chain is plumbed through.

The Nix home-manager module exposes the same table as
`tartarus.sudo-auth-proxy.server.acl.{mode, trustedFingerprints, caFile,
requiredOid, rule}`; `labels` is currently only reachable through the free-form
`extraSettings`/`settings` escape hatch. The shipped host module defaults the
whole table to `mode = "ca"` with the tartarus CA and the sudo client OID (audit
A1), so a configured guest is authorized without an operator-maintained
fingerprint list.

### 8.6 Approval rules (`[[acl.rule]]`)

The ACL above is the **authorization gate**: it decides whether a credential may
use the mechanism at all. The optional `[[acl.rule]]` list is a second,
**approval** refinement evaluated only *after* `authorize_request` accepts the
credential. Rules can therefore never grant access the ACL denied; they only
decide how an already-authorized request is answered:

| `policy` | Effect                                                      |
| -------- | ----------------------------------------------------------- |
| `allow`  | reply `allow` immediately, without a dialog                 |
| `ask`    | show the confirmation dialog (the default when nothing matches) |
| `deny`   | reply `deny` immediately, without a dialog                  |

Rules are evaluated in file order and the **first match wins** — there is no
merging, exactly like `ssh-agent-proxy`'s rule list. Each rule has these
`fnmatch` glob selectors; `*` (or an omitted selector) matches anything:

| Key             | Matched against                                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------------------------------- |
| `identity`      | Any requester name the server holds: the `resolution` friendly name (`mofos` VM name, certificate CN, tartarus name), the ACL `labels` entry, and the verified credential (`SHA256:...` or `none`). |
| `target_user`   | The effective target account (`root` for a plain `sudo`; see §11.1).                                                 |
| `invoking_user` | The invoking user.                                                                                                  |
| `service`       | The PAM service (`sudo`, `su`, `login`).                                                                            |
| `policy`        | `allow` \| `ask` \| `deny` (default `ask`).                                                                          |

Worked example — auto-allow a known guest, prompt for everything else:

```toml
[acl]
mode = "ca"
ca_file = "./ca.crt"
required_oid = "1.3.6.1.4.1.99999.1.2"

[[acl.rule]]
identity = "template-nixos"   # the mofos name from `resolution = "mofos"`
target_user = "root"
service = "sudo"
policy = "allow"

[[acl.rule]]
identity = "*"
policy = "ask"
```

Because `identity` also matches the ACL label and the verified fingerprint, a
rule can pin a credential directly (`identity = "SHA256:AbCdEf..."`) or target a
friendly name. An unknown key, a non-string selector or a `policy` other than
`allow`/`ask`/`deny` is a startup error (fail closed, like the rest of the
schema). Rules are accepted under every ACL mode, including `none`, because they
inspect only display/approval metadata — never the credential the ACL is
responsible for.

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
- There is **one server socket per host user**, not one per guest (review log
  S1, §19.7). It therefore does not identify the guest: the requester's
  credential (§7.3) does. This is why a same-uid host process that connects is
  not silently trusted — it must still present a trusted credential (§12.5 T26).
- `server_auth = "none"` is only defensible on this socket because it is `0600`
  inside a `0700` runtime directory owned by the server user; anyone who can
  replace it is already that user.

### 9.2 Guest side

- Socket directory: `0700`, **owned by the guest login user** — not root. The
  guest's `sshd`, running as that user, must be able to create the forward there
  (§4.3), so a root-owned `0755` directory would break every bind. This is
  created by the guest module (`systemd.tmpfiles.rules` or the user's
  `RuntimeDirectory`).
- Socket: `0600`.
- Client config directory `/etc/sudo-auth-proxy`: `0750 root <guest-login-group>`
  (not the historic `0755`), so filenames and any key material are not
  world-readable while the PAM helper can still read the config.
- **Listeners and links.** The client `lstat`s the socket and refuses symlinks or
  paths not owned by the expected user before connecting. This is best-effort
  (the check and `connect()` are not atomic); see the residual-risk note below.
- **Two distinct properties.** Do not conflate them (review log F1/F2):
  - _Decision authenticity_: the mTLS channel (`server_auth = "transport"`)
    prevents a forged `allow`: a fake listener holds no certificate the client's
    CA trusts, and does not know the nonce. With `server_auth = "none"` this
    protection is absent and a same-uid fake listener could answer `allow` —
    which is why `"none"` is not recommended.
  - _Routing integrity_: the selector-only resolution (no fallback), socket
    ownership, and — on Linux — a post-connect `SO_PEERCRED` →
    `/proc/<peer_pid>/exe` check that the peer's executable is `sshd` and is
    root-owned but not peer-owned (so a same-UID read-only copy named `sshd` is
    rejected; audit A7) raise the bar against a same-uid attacker redirecting the
    client to a **different legitimate** tunnel. This is a path/ownership
    heuristic, not a kernel-attested process identity: misrouting is not forgery,
    and no authentication mechanism prevents it; the same-UID selector race remains
    accepted as residual **R6** (bounded by the per-session token, R9). The
    peer-process check is Linux-only; macOS relies on socket-path integrity.
- **Residual risk:** when the **guest login account is shared** by several people,
  anyone with that UID can unlink/replace the socket in the `0700` directory
  (subject to the check above, which raises the bar but is not atomic). This is
  captured in §12.6 R6; the robust fix is per-person guest accounts.
- **No reuse proxy.** The historic `0666` proxy socket is gone with the proxy
  itself (§2.3); there is no second local socket to leak.
- Private keys: never `0644`. The only requester private key left is the mTLS
  client key (`[mtls].key_file`), which `ca.py` writes `0600` and which must stay
  owned by the user running the client (review log F12). Users of the _same
  guest_ share that guest's mTLS identity; that is acceptable within a guest's
  trust domain, and per-person guest accounts are the full fix (§12.6 R6).

### 9.3 Attack surface and races

| Situation                                                      | Control                                                                                                                                                                                                       |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host process of another user connects to the server socket     | `0700` dir + `SO_PEERCRED` uid check.                                                                                                                                                                         |
| Host process of the _same_ user connects                       | It is the same approver at the OS level, but it must still present a trusted mTLS credential or the ACL rejects it; otherwise it can only cause a prompt, which is logged. No cross-user escalation. |
| Guest process races the tunnel listener                        | mTLS prevents forged allows; socket `lstat` + (Linux) `SO_PEERCRED`→`/proc/<pid>/exe` limits misrouting.                                                                                                 |
| Fake server on a `server_auth = "none"` socket                 | **Not mitigated**; that is exactly why `"none"` is not recommended and is strongly discouraged on `tcp` (T26, §7.2).                                                                                          |
| Same guest UID redirects a socket to another legitimate tunnel | **Residual risk (R6)**; only fully fixed by per-person guest accounts.                                                                                                                                        |
| Stale socket after crash                                       | Unlink + ownership check before bind; `StreamLocalBindUnlink`; receive timeout (§10.2) bounds the bound-but-unlistened read hang.                                                                             |
| Socket path guessable/raceable                                 | Random per-session token in the path (NF7, R9) + `0700` dir; selector-only resolution means no guessed fallback; path secrecy is not relied upon.                                                             |
| macOS: no `/proc`, `getpeereid` uid/gid only                   | Linux peer-process check unavailable; rely on path/ownership + token + server authentication (R11, §12.5 T25).                                                                                                |

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

Three independent bounds are configured. With the pre-dialog acknowledgement
(§6.2a) they bound distinct parts of one client exchange.

| Key                | Default | Applied where                                                              | `0` means        |
| ------------------ | ------- | -------------------------------------------------------------------------- | ---------------- |
| `connect_timeout`  | `0.2 s` | transport `connect()` **and** the TLS handshake (every transport)           | _(not special)_  |
| `recv_timeout`     | `0.5 s` | the wait for the **first frame** (the `auth_pending` ack, or a direct deny) | _(not special)_  |
| `decision_timeout` | `120 s` | the wait for the final `auth_response` — the human decision                 | wait indefinitely |

The **server** has its own two pre-authentication resource bounds (audit A3/N2),
exposed as the server options `maxConnections` / `serverReadTimeout` and emitted
into the generated server TOML as `max_connections` / `server_read_timeout`
(audit N5). Their defaults match the Python constants.

| Server key            | Default | Applied where                                                  | Invalid value     |
| --------------------- | ------- | -------------------------------------------------------------- | ----------------- |
| `server_read_timeout` | `10 s`  | accepted socket: TLS handshake **and** pre-auth request read   | falls back to `10 s` |
| `max_connections`     | `64`    | concurrent handler threads; over-cap connections are refused   | falls back to `64`   |

- **Server read timeout** (`server_read_timeout`, default **10 s**): bounds each
  accepted connection before authentication. It covers the TLS handshake — which
  runs in the per-connection handler thread, **not** the single `serve_forever`
  accept loop, so a stalled handshake cannot block other accepts (audit N2) — and
  the pre-auth request read. The wait is capped by `max_connections`, not by the
  accept loop.
- **Max connections** (`max_connections`, default **64**): the semaphore cap on
  concurrent handler threads. A connection offered over the cap is closed before
  a thread is spawned, so a pre-auth flood cannot create unbounded threads
  (audit A3). A malformed or non-positive value falls back to the default rather
  than disabling the bound.

- **Connect/handshake timeout** (`connect_timeout`, default **200 ms**): if the
  peer cannot be reached, give up _fast_ so other PAM methods are tried promptly.
  This is a hard requirement: a `sudo` must not hang for minutes on a dead
  tunnel. It covers connect and the TLS handshake only; once the connection is
  up the socket is returned to blocking mode and the frame bounds take over.
- **First-frame timeout** (`recv_timeout`): bounds the first frame. Because the
  server writes the `auth_pending` ack as soon as the request is authenticated
  and authorized, that frame arrives promptly, so a short bound gives the
  stale/unlistened-socket fast-fail of review log NF4 **without** bounding the
  human. It also bounds a direct denial, which is answered without a dialog.
- **Decision timeout** (`decision_timeout`): bounds the final `auth_response`,
  i.e. the human wait; `0` restores blocking mode (wait indefinitely).

> **Accepted residual (audit N3).** The `auth_pending` ack is validated only by
> the request nonce and carries no decision, so a peer that can reach the socket
> can echo the nonce and then send nothing, holding the client for the full
> `decision_timeout` (default 120 s) instead of the short `recv_timeout`. This is
> an approval-delay DoS local to a peer that already won the socket/peer checks
> (R6/R9/R11); it is **not** forgery — mTLS
> channel still defeats a forged `allow`. Bounding the _total_ exchange would
> re-couple the two bounds the sentinel deliberately separated; the residual is
> therefore accepted and named in §12.6 R14.

**What bounds the human wait (implementation).** With the ack in place the first
frame is _not_ the human's answer: it is the sentinel the server sends before
`prompt_for_confirmation` (§6.2a). Only the final `auth_response` carries the
decision, and it is read under `decision_timeout`. A human who takes minutes is
therefore not cut off, while a dead socket still fails in `recv_timeout`. This is
the §17 sentinel, now implemented.

Consequences:

- `recvTimeout` no longer needs to be the human window: the shipped `0.5 s` is
  correct (it bounds only the ack). Set `decisionTimeout` to the maximum time you
  are willing to wait for a human (default `120`; `0` = wait indefinitely).
- The PAM wrapper pre-checks `[ -S "$SUDO_AUTH_PROXY_SOCK" ]` for `unix` before
  spawning the Python client, so the common no-tunnel path is a zero-cost
  fallthrough that does not depend on any timeout.
- Never block on DNS for an address that is already numeric; `_gateway` is
  resolved from `/proc/net/route`, not DNS.
- On any parse/verify failure, or on any of the three bounds expiring, the client
  exits non-zero immediately (fail closed).

> **Documentation correction (post-A2).** The previous revision stated that the
> first response byte _was_ the human's answer and therefore that `recv_timeout`
> had to be raised to the human window. That was true before the `auth_pending`
> frame; with the sentinel it is not. `recv_timeout` now bounds the ack and
> `decision_timeout` the human. The §10.5 example has been updated accordingly.

### 10.3 Fallback semantics and their security implications

The mechanism is **optional**: on `denied` or `unavailable` the PAM stack
continues (default `default=ignore`). This means:

- The proxy is an _additional_ authentication path, useful for headless guests
  where no other method exists.
- If the guest also has a local password, a user can still authenticate with it
  after a deny, unless the operator disables password auth for that account. The
  proxy does **not** override the guest's own policy.
- Therefore "only whitelisted people can elevate _through this mechanism_" holds
  (§8), but the mechanism is not a hard gate over the whole account unless the
  other methods are disabled. This trade-off is deliberate and must be understood
  before relying on the proxy as a sole factor.
- **There is no strict mode with `pam_exec`.** `pam_exec.so` collapses every
  non-zero exit to the same generic failure, so the stack cannot distinguish
  `deny` from `unavailable`; no PAM control flag can implement a non-ignorable
  deny on top of it (§6.7). A strict mode therefore **requires the native PAM
  module of §17** and is not available with the current `pam_exec` integration.
- **Explicit warning:** in the default configuration a deliberate human `deny`
  is _indistinguishable_ from `unavailable` and therefore falls through. If a
  local password (or any other PAM method) is enabled, the approver's "no" can be
  bypassed by entering that password. The proxy is never a hard gate unless the
  other methods are disabled — and even then a non-ignorable `deny` needs the
  future native PAM module (§17), because `pam_exec` cannot distinguish `deny`
  from `unavailable` (review log F5, §19.6 C1/§17).

### 10.4 Recursive and stacked authentication

- **Reality (audit A5): the guard does not propagate into the elevated shell.**
  The client checks `SUDO_AUTH_PROXY_ACTIVE` on entry and sets it in its **own**
  process while it runs (`activate_recursion_guard`). The elevated shell is a
  child of `sudo`, not of the PAM helper, so that assignment never reaches it;
  the mandated `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` (§4.3) preserves
  a variable that is not present in the invoking environment in the first
  place. Net effect: the guard covers the helper process (and would suppress a
  re-entry if the variable ever were present) but a `sudo` run _from inside_ an
  already-elevated session opens a second dialog. This is approver fatigue, not
  an elevation bypass.
- A working session/pty-scoped stamp that survives into the elevated context
  remains future work; until then, do not rely on the guard for nested
  elevations.
- `login`/`su` set different `PAM_SERVICE` values; the request records the
  service so the approver sees which path triggered it.

### 10.5 Example

A working interactive configuration. Note the timeout arrangement from §10.2:
`recvTimeout` bounds the `auth_pending` ack (which arrives before the dialog),
and `decisionTimeout` is the human window.

```nix
tartarus.sudo-auth-proxy = {
  enable = true;
  transport = "unix";          # host→guest tunnel
  connectTimeout = 0.2;        # connect + TLS handshake only (fast-fail)
  recvTimeout = 0.5;           # first frame is the auth_pending ack (fast)
  decisionTimeout = 120;       # the human window; 0 also works (wait forever)
  security = {
    transportEncryption = "mtls";  # the only authentication mechanism (§7)
    serverAuth = "transport";      # forced under mTLS; stated for clarity
    clientAuth = "transport";      # identity = the mTLS client certificate
  };
  mtls = {                     # the tartarus CA + this guest's client cert
    enable = true;
    caFile = "/etc/tartarus/x509/ca.crt";
    certFile = "/etc/tartarus/x509/client.crt";
    keyFile = "/etc/tartarus/x509/client.key";
    requiredOid = "1.3.6.1.4.1.99999.1.2";
    peerOid = "1.3.6.1.4.1.99999.1.1";
  };
};
```

This is exactly what the tartarus guest module emits for a guest that sets
`services.sudoAuthProxyTransport = "unix"`, and the mirror image of what the host
module configures for its server (`acl.mode = "ca"` with the same CA and client
OID). For a callback transport (`vsock`/`tcp`) the shipped configuration is the
opposite trade: `transport_encryption = "none"`, `serverAuth = "none"`,
`clientAuth = "none"` and `acl.mode = "none"`, because the tartarus-internal
channel is private by construction. The MOFOS guest
(`hosts/nixos/mofos/default.nix` in nixcfg) uses that form on `vsock` port 65012.

> `recvTimeout` bounds the `auth_pending` ack, which the server writes before it
> raises the dialog; the human wait lives in `decisionTimeout` (§6.2a, §10.2).
> The shipped defaults are therefore already interactive-safe.
>
> There is **no `socketEnv` option**. The selector variable is fixed to
> `SUDO_AUTH_PROXY_SOCK`; the client reads only that variable and the host
> wrapper's `envVar` defaults to it. Do not set a `socket` key on the client
> expecting it to be used (§15).

For reference, the three security knobs and their allowed values are §7.2–§7.5.
For `tcp`, `transportEncryption` defaults to `"mtls"` (recommended); `"none"` is
permitted but insecure, and there is no message signing left to fall back on, so
use it only where the network path is trusted end to end.

---

## 11. Confirmation dialogs

### 11.1 Fields shown

The prompt is **deliberately condensed** — see §11.4 for the two-line summary and
the expandable detail block. Everything below is *context*, and most of it is not
needed to answer:

- **Requester identity** — the verified credential (mTLS leaf SPKI, or its
  configured label; "Unauthenticated requester" when `client_auth = "none"`).
- **Invoking user → target user** (e.g. `user → root`). The target is the
  effective account: `sudo` runs its PAM `auth` stack as the *invoking* user (so
  `PAM_USER` repeats the invoking user there), and the target is therefore
  normalised to `root` for a plain `sudo`; `su`/`login` report `PAM_USER`
  verbatim. `sudo -u <other>` is not distinguishable in the auth phase.
- **Service** (`sudo` / `su` / `login`).
- **TTY** (`/dev/pts/3`) and **rhost** if any.
- **Working directory**.
- **Request id** (short prefix of the nonce) and **timestamp/transport**.

The **command/argv is deliberately not shown** (review log S5, §19.7): it is
guest-controlled and spoofable, so it would be misleading, and it clutters the
UI. The request is bound to `service + user + tty + cwd + nonce` through the
request digest instead (§5.4, §6.4).

### 11.2 Sanitisation

All fields are attacker-influenced and must be treated as untrusted:

- **Unicode-normalise first** (NFC) so visually identical sequences collapse
  before any further processing.
- **Allow-list, don't deny-list.** After normalisation keep only
  `[A-Za-z0-9_.:/@-]` and a single space, replacing every other code point with
  `?`. This removes control characters, bidi overrides, newlines and markup in
  one step.
- Apply that sanitiser to **every** attacker-influenced field:
  `guest_hint`, `invoking_user`, `target_user`, `tty`, `cwd` (and `rhost`), and
  to the credential label before it is rendered.
- Cap lengths.
- **zenity**: use `--no-markup`.
- **osascript**: JSON-encode the message (prevents quoting/injection).
- **swiftDialog**: escape its markup (`* [ ] ( )`) _after_ the allow-list pass —
  the allow-list removes most of it, but these are the characters swiftDialog
  still interprets. The shipped `escape_swiftdialog_markup` is applied to the
  fully rendered message (review log NF2).
- **Logging (review log NF8).** The same sanitiser (at minimum the allow-list
  pass) is applied to `guest_hint` and every other field **before it is logged**,
  so a crafted field cannot forge log lines, inject ANSI/control sequences, or
  split records. Never log the raw request bytes.
- Never build a shell command from a field.

### 11.3 No anti-fatigue / rate-limiting

Anti-fatigue machinery (rate limits, exponential backoff, circuit breakers and
"remember this request") is **removed** (review log S12, §19.7). It was
best-effort state with real downsides: it could lock out a legitimate approver,
added server memory and failure modes, and was never a security boundary.
Instead:

- Only credentialed requesters can reach a dialog at all (§7.3, §8), which
  bounds who can generate prompts.
- Concurrent requests are each handled in their own server thread, but the
  confirmation prompt is guarded by a process-global lock, so **one dialog is
  shown at a time**; a second request's dialog waits for the first to close
  (audit A13). This is a UI guarantee, not a security boundary (only
  credentialed requesters reach a dialog).
- Denying is always explicit and is logged; there is no auto-deny state machine.

---

### 11.4 Prompt shape: condensed summary, expandable detail

The prompt is intentionally small. A two-line summary is shown by default, and
the full field block of §11.1 is one interaction away:

```
Unauthenticated requester requests root via sudo
on 127.0.0.1 (vsock)
```

Line 1 is `<requester> requests <target_user> via <service>`; line 2 is
`on <peer> (<transport>)`, with ` (from <rhost>)` appended when `rhost` is set
and different from the peer. An unauthenticated request says so literally rather
than printing an empty identity or the internal `none` sentinel.

The detailed block is a labelled field list (`Requester`, `Identity`, `Request`,
`Peer`, `Transport`, then optional `Remote`/`TTY`/`CWD`, then `Request id …`).

How it is reached depends on the backend, and the difference is deliberate:

| Backend       | Summary | Detail                                                                                                                                    |
| ------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `swiftdialog` | `--message` | `--info` + `--infobuttontext Details`: an info button that reveals the block.                                                          |
| `osascript`   | dialog text | A third **Details** button; pressing it runs a _second_ dialog with the block, and only an explicit **Authorize** in that second dialog allows. The pressed button is read from stdout, so **Details** can never be mistaken for a decision. |
| `zenity`      | `--text` | A **Details** extra button (`--extra-button`), when the installed zenity accepts one (probed once per process; §11.4). Pressing it runs a _second_ dialog with the block, and only an explicit **Authorize** there allows. The press is identified by the label zenity prints on **stdout** — its exit code for an extra button is the _cancellation_ code (1), which is why the pairing is easy to get wrong. Without `--extra-button` the prompt stays the summary alone and the block is only in the server log (`debug = true`). |

Nothing is lost either way: the log always gets the sanitised field block (and
never the command, §11.1), and the approval decision is unchanged. On every
backend **Details** is a request to see more context, never a decision — it
cannot turn "show me more" into either an allow or a deny.

Both dialogs are given an **explicit width** (`520 px`, matching the swiftDialog
layout on macOS) and no height, so they grow sideways and fit their content
vertically. That is not cosmetic on zenity: its own default wraps the label at 60
characters (`gtk_label_set_max_width_chars (text, 60)`), which turns the summary
and the field block into a narrow column that is taller than it is wide. A field
that is longer than the width still wraps, which is the only way to show all of
it without truncating (`--ellipsize` would hide the value being inspected).

### 11.5 Peer name resolution (`resolution`)

The `<peer>` shown in the summary is a display/log label derived from the
transport. The server-side `resolution` key chooses how to make it friendlier;
it never gates anything and is sanitised like every other field.

| `resolution`  | Name shown                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------ |
| `none`        | The transport's raw label (`cid N` for VSOCK, the address for TCP, `local` for unix).            |
| `certificate` | The verified mTLS peer certificate CN (or first `DNS` SAN). Needs mTLS.                         |
| `tartarus`    | The local tartarus VM bookkeeping (`~/.local/state/tartarus/<name>/cid`), matched by CID/IP.     |
| `mofos`       | `mofos ls --json`, matching the peer's VSOCK CID or `ipv4_address` to the VM `name`.             |

`mofos` shells out to `mofos ls --json`, caches the listing for 30 seconds, and
degrades to the raw label when the binary is missing, exits non-zero, or returns
malformed JSON — resolution is cosmetic and must never delay or fail a prompt.
The Nix module exposes it as
`tartarus.sudo-auth-proxy.server.resolution`; unset defaults to `certificate`
when `mtls` is enabled and `tartarus` otherwise. The resolved name is one of the
candidates an `[[acl.rule]]` `identity` selector matches (§8.6).

**`resolution = "none"` is wildcard-only.** The resolved name is a *display*
label, never a matching identity: with `none` the identity is unset, so only an
empty `identity` selector or `"*"` can match. A specific `identity` pattern can
never authorize an unauthenticated peer (it would be name spoofing by label).
This is enforced in ssh-agent-proxy by a dedicated `matches_vm(None)` rule
(see `docs/ssh-agent-proxy.md` §5.2) and is the model the `[[acl.rule]]`
matching must follow: match cryptographic material, never a display string. The
`mofos` resolver is available here at parity with ssh-agent-proxy.

---

## 12. Threat model

### 12.1 Assets

- **A1** The ability to make `sudo` succeed in a guest (privilege elevation).
- **A2** The confidentiality/integrity of the request contents (command, users).
- **A3** The approver's attention and the integrity of the decision.
- **A4** The CA and the mTLS private keys.
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
- **ADV6 — A compromised CA / certificate-key holder.**

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
  sandbox must account for the actual uid/euid.
- **A6** The selector (`SUDO_AUTH_PROXY_SOCK`) and the recursion guard
  (`SUDO_AUTH_PROXY_ACTIVE`) are delivered by `SetEnv`/`AcceptEnv` **and
  guaranteed by `sudoers env_keep` entries** (`Defaults env_keep +=
"SUDO_AUTH_PROXY_SOCK"` and `... "SUDO_AUTH_PROXY_ACTIVE"`, §4.3, §10.4). The
  selector is the **only** source; there is no `/proc` or static fallback. The
  multi-fragment `sudoers.d` shadowing risk is called out in §4.3 (review log
  C1).
- **A7** The mTLS certificate private keys are protected per §7.8/§9.

### 12.5 Threats and mitigations

| #   | Threat                                                                                                                 | Adversary | Mitigation                                                                                                                                                                                |
| --- | ---------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | Forge an `allow` into the client                                                                                       | ADV1      | mTLS (`server_auth = "transport"`); the TLS channel authenticates the responder, and the client verifies nonce + request digest. With `server_auth = "none"` this is **not** mitigated (§7.2, §6.6) |
| T2  | Replay an old `allow`                                                                                                  | ADV1      | Client **single-use nonce** + request digest + expiry; no server-side cache needed. (§6.6)                                                                                                |
| T3  | Change request fields between approval and execution                                                                   | ADV1/ADV2 | `request_digest` recomputed by the client and bound to the nonce; mismatch rejected. (§6.4)                                                                                                |
| T4  | Guest/user B impersonates A                                                                                            | ADV2      | The mTLS client certificate is verified against the server's trust roots and the ACL; the single socket carries no identity. **Caveat A4:** the service EKU OIDs do not isolate services today — a guest's tartarus client certificate is valid for every tartarus service (§7.6). With `client_auth = "none"` there is nothing to verify at all (§7.3, §8) |
| T5  | Person B receives/answers person A's prompt (different host users)                                                     | ADV3      | Per-host-user server and single socket in the owner's runtime dir; `SO_PEERCRED` uid check. (§4.2, §9.1)                                                                                  |
| T6  | Person B receives person A's prompt (same guest account, different host users)                                         | ADV3      | Per-session guest bind path + `SUDO_AUTH_PROXY_SOCK` (guaranteed by `sudoers env_keep`) selects the session owner. Same-UID redirection remains R6; multiplexer caveat §4.6.              |
| T7  | A non-whitelisted requester triggers elevation                                                                         | ADV1      | Cryptographic ACL evaluated before the dialog, default deny. (§8)                                                                                                                         |
| T8  | Network attacker MITM on a callback transport                                                                          | ADV4      | `tcp` defaults to mTLS (EKU + CA), `vsock` optional. `tcp` + `none` is allowed but leaves both confidentiality *and* authentication to the network: a MITM can forge a decision. (§7.4) |
| T9  | Socket pre-creation / listener race in the guest                                                                       | ADV1      | mTLS defeats forgery (with `server_auth = "none"` it does not); selector-only resolution (no fallback) plus `lstat`/peer-process check (`sshd`, root-owned, not peer-owned — audit A7) limit redirection. Redirection to a real tunnel remains R6. (§9.2) |
| T10 | Another local host process connects to the single server socket                                                        | ADV3      | `0700` dir, `0600` socket, `SO_PEERCRED` uid check, **and** it must still present a trusted credential (§8). (§9.1)                                                                       |
| T11 | Dialog flood                                                                                                           | ADV1/ADV5 | Only credentialed requesters reach a dialog; a process-global lock shows one dialog at a time (A13); deny is explicit. No anti-fatigue state. Pre-auth availability residual R14 (audit N3). (§11.3, §10.2) |
| T12 | Injection into the dialog / spoofed text                                                                               | ADV1      | Sanitisation (allow-list + NFC) per backend, length caps, no markup. (§11.2)                                                                                                              |
| T13 | Private key exposure enables impersonation                                                                             | ADV1      | No `0644` keys; the mTLS client/server keys are `0600` (`ca.py` writes them that way). (§7.8, §9.2)                                                                                        |
| T14 | CA compromise                                                                                                         | ADV6      | Re-issue + restart (the CA is read per use, so rotation needs no rebuild); shorten certificate lifetimes; known-but-unprocessed critical X.509 extensions are accepted residual R15 (audit N4); TPM/HSM future work. (§7.8) |
| T15 | DoS: make the tunnel unavailable to force fallback                                                                     | ADV1      | Fallback is by design; document that the proxy is not a sole factor unless other auth is disabled. The TLS handshake now runs off the accept loop (A3/N2) and the ack-stall residual is R14. (§10.2, §10.3) |
| T16 | Cross-session decision reuse                                                                                           | ADV1      | Decision bound to nonce + request digest (includes tty); client single-use. (§6.6)                                                                                                        |
| T17 | Secret leakage via the dialog/logs                                                                                     | ADV1/ADV5 | The command is never shown or logged; fields sanitised before logging; never log raw bytes. (§11.1, §11.2)                                                                                |
| T18 | Recursive/stacked prompts confuse the approver                                                                         | ADV5      | **Partial (A5):** the helper checks `SUDO_AUTH_PROXY_ACTIVE` on entry, but the variable is set only in the helper process and cannot propagate into the elevated shell, so a `sudo` _inside_ an elevated session re-prompts. The service is shown in the dialog. (§10.4) |
| T19 | Stale socket/ownership tricks                                                                                          | ADV1      | `lstat` + ownership/symlink checks + unlink before bind; receive timeout bound. (§9, §10.2)                                                                                               |
| T20 | Downgrade to an unauthenticated or legacy protocol                                                                     | ADV4      | No legacy protocol and no auto-detection; no insecure fallback; mTLS config refuses plaintext, and with `transport_encryption = "none"` the auth knobs must be written out explicitly. (§6.1, §7.5, §4.3) |
| T21 | Same guest UID redirects the client socket to **another person's legitimate tunnel** (valid credential, wrong approver) | ADV1      | `lstat`/no-symlink; Linux `SO_PEERCRED`→`/proc/<pid>/exe` = `sshd`, root-owned and not peer-owned (A7); **residual R6**; per-person guest accounts is the full fix. (§9.2) |
| T22 | `sudo` strips the selector env var → request lands on a shared/wrong socket                                            | ADV1/ADV3 | Mandatory `sudoers env_keep += "SUDO_AUTH_PROXY_SOCK"`; selector is the only source; otherwise fast-fail. (§4.3)                                                                          |
| T23 | Rogue CA/trust root substituted via build/supply chain                                                                 | ADV6      | Distributed like `ca.crt`; treat as CA-sensitive for build-input review; rotate by re-issuing and restarting. (§7.8)                                                                        |
| T24 | Stale guest socket after a crashed session → silent degradation / spoof target                                         | ADV1      | **No explicit teardown hook (A8):** `sshd` removes its own forward on session close and `StreamLocalBindUnlink` handles a same-name re-bind; a stale path is never reused (per-session token) and the first-frame receive timeout bounds a bound-but-unlistened read. (§4.3, §9.2) |
| T25 | **macOS** peer verification is weaker: no `/proc`, and `getpeereid` returns only uid/gid (no pid)                      | ADV1      | Linux peer-process check unavailable; rely on socket-path integrity/ownership, the random path token (NF7), and server authentication. Accepted residual **R11**. (§9.2, §12.6)           |
| T26 | A fake server answers on a `server_auth = "none"` socket                                                               | ADV1      | **Not mitigated**; `"none"` is not recommended and is strongly discouraged on `tcp`. (§7.2, §12.6 R13)                                                                                    |
| T27 | A same-uid host process connects to the single server socket and generates prompts                                     | ADV3      | It must present a trusted `client_auth` credential or the ACL rejects it; otherwise it can only cause a (logged) prompt. No cross-user escalation. (§8, §9.1)                             |
| T28 | A multiplexer pins a stale/foreign selector                                                                            | ADV3      | Selector-only resolution + fail-closed + cryptographic request binding; per-person guest accounts are the full fix. Accepted residual **R12**. (§4.6)                                     |

### 12.6 Residual risks (accepted)

- **R1** Two people sharing one **host** Unix account are one principal (§5.6).
- **R2** A compromised guest **root** can do anything within the guest, including
  reading the mTLS client key; mTLS still prevents it from fabricating an
  `allow` (unless `server_auth = "none"`), but it can consume approvals and act
  after a legitimate one (it _is_ the principal whose credential it holds).
- **R3** Fallback to other PAM methods means the proxy is not a sole gate unless
  other auth is disabled (§10.3).
- **R4** `pam_exec` cannot distinguish `deny` from `unavailable` via exit codes
  (§6.7).
- **R5** The approver's machine or the trust roots being compromised defeats the
  model (out of scope; §5.5/§12.5 T14).
- **R6** **Socket misrouting with a shared guest login account.** A process with
  the shared guest UID can point its own socket path at another person's
  legitimate tunnel (unlink/symlink), causing a _valid, correctly authenticated_
  approval to be issued by the wrong approver. The credential proves who sent
  it, not _which_ tunnel the request traveled; path checks and the Linux
  peer-process check raise the bar but are not atomic. Fix: per-person guest
  accounts (review log F1/F2).
- **R7** **Fallthrough latency tax.** The PAM hook runs on every `sudo`; when no
  tunnel exists the client must fail in ≤200 ms (or skip via the socket-existence
  pre-check) or interactive/automation use degrades (review log Rank 5).
- **R8** **Metadata fields are unverifiable.** `invoking_user`, `target_user`,
  `tty`, `rhost` and `cwd` are guest-provided. They are shown and bound but are
  not authorization inputs; the ACL matches only the credential (§8).
- **R9** **Predictable/raceable guest socket path.** Without the per-session
  random token (NF7) a same-UID guest process could predict and race the
  `RemoteForward` bind path. The token makes the name unguessable, but the bind
  is still not atomic with the peer check; accepted (review log NF7; §4.2).
- **R10** **Retired.** The former nonce-cache residual no longer applies: the
  server keeps no nonce cache and the client's single-use nonce is the entire
  replay defence (§6.6).
- **R11** **macOS peer-verification gap.** There is no `/proc` and `getpeereid`
  returns only uid/gid, so the Linux peer-process check (that the connector is
  `sshd`) cannot run. The platform relies on socket-path integrity/ownership,
  the random path token, and mTLS authentication (§9.2, §12.5 T25).
- **R12** **Multiplexer selector staleness.** A multiplexer server carries the
  selector of the SSH session that started it, so a later attach can route to a
  different approver on a shared guest account. The client fails closed rather
  than guessing, and requests remain cryptographically bound; per-person guest
  accounts are the full fix (§4.6).
- **R13** **`server_auth = "none"`.** On a socket a same-uid process can replace
  (or any transport that is not integrity-protected), a fake server can answer
  `allow`. `"none"` is not recommended and is strongly discouraged on `tcp`.
  This is the shipped setting on the vsock callback transport, where the
  assumption is that nothing else can reach CID 2 port 65012 (§7.2).
- **R14** **Pre-dialog ack stall (audit N3).** The unauthenticated `auth_pending`
  sentinel can be echoed by any peer that reaches the socket and then followed by
  silence, holding the client for the full `decision_timeout` (default 120 s)
  instead of the short `recv_timeout`. This is a local approval-delay
  denial-of-service, not forgery (mTLS still defeats a forged `allow`); it is the
  accepted cost of separating the first-frame bound from the human wait (§6.2a,
  §10.2). Reachability is bounded by R6/R9/R11.
- **R15** **Known-but-unprocessed critical X.509 extensions (audit N4).** The
  chain verifier rejects an _unknown_ critical extension (audit A6) but ignores
  critical extensions it recognises and does not itself enforce (e.g. critical
  `SubjectAltName`, `NameConstraints`, `PolicyConstraints`). The trusted CA is
  self-hosted (`mode = "ca"`), so this is latent (a CA holder could issue a
  constrained-but-ignored certificate); enforcing the full RFC 5280
  critical-extension set is future work.

### 12.7 Non-goals of the threat model

- Protecting against a compromised host OS or host desktop.
- Protecting against a compromised hypervisor.
- Preventing a guest from running the client; the ACL decides whether it may.

---

## 13. Failure modes and troubleshooting

| Symptom                                     | Likely cause                                                    | Action                                                                                                          |
| ------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `sudo` hangs                                | Long connect timeout / DNS, or a stale socket blocking the read | Ensure `connect_timeout` is small and a first-frame `recv_timeout` is set (§10.2); use numeric/Unix targets.    |
| `sudo` falls through immediately            | Tunnel/socket unavailable                                       | Check the SSH session is open, `SUDO_AUTH_PROXY_SOCK` is set, the guest sshd accepts it, and the socket exists. |
| Prompt appears, then `unavailable` after a fraction of a second | `recv_timeout` too small: it bounds the first frame (the `auth_pending` ack), so the server did not acknowledge in time | Ensure the server is reachable and healthy; raise `recvTimeout` only if the ack is genuinely slow. The human wait is `decisionTimeout` (§6.2a, §10.2). |
| Dialog answers are ignored / `unavailable` after ~0.5 s **on a pre-sentinel build** | Old server/client pair without `auth_pending` | Upgrade client and server together (§14.1). |
| SSH session aborts with a `RemoteForward` bind failure (`ExitOnForwardFailure`) | Guest `/run/sudo-auth-proxy` is missing, not `0700`, or not owned by the guest login user | Create it via the guest module's `systemd.tmpfiles.rules` / `RuntimeDirectory`; never `root`-owned (§4.3, §9.2, §15.2). |
| "Peer certificate missing required EKU OID" | Cert minted for another service                                 | Re-issue with the sudo-auth-proxy EKU (CA tooling).                                                             |
| Prompt appears on the wrong user's screen   | Multiplexer pinned a stale selector, or shared account          | Restart the multiplexer inside the correct SSH session; use per-person guest accounts (§4.6, R12).              |
| Fake/forged allow suspected                 | `server_auth = "none"`, so nothing authenticated the responder | Set `transport_encryption = "mtls"` (which forces `server_auth = "transport"`); there is no signing fallback (§7.2). |
| Request rejected as unauthorized            | Credential not trusted                                          | Add the mTLS leaf SPKI to `[acl].trusted_fingerprints`, or the CA/EKU for `mode = "ca"` (§8.5).                        |
| Plaintext-`tcp` warning                     | `transport_encryption = "none"` on `tcp`                        | Expected on a trusted network; prefer mTLS. Nothing authenticates the request or the response (§7.4).          |
| `transport_encryption = 'none' requires an explicit client_auth = 'none' …` | A config that turns authentication off without saying so | Write `client_auth = "none"` and `server_auth = "none"` explicitly, or use `mtls` (§7.5).                             |
| `'client_auth' must be written in [security], but it is written at the top level` | The `[security]` keys were written **above** the `[security]` header, so TOML made them top-level keys and the service saw no `[security]` table at all (§7.9) | Move those lines under `[security]`. The error names the key and the table it belongs to.                      |
| `unknown key 'max_connection' at the top level` | A typo (or a key removed with a mechanism, §14.3) | Fix the spelling — the error suggests the real key when one is close — or drop the setting. Unknown keys are never ignored. |

---

## 14. Compatibility and migration

### 14.1 Wire protocol (breaking)

- The protocol is newline-delimited JSON (§6). The legacy `auth\n` → `1\n` line
  protocol and byte-sniffing auto-detection are **removed**; there is no
  downgrade path and no compatibility mode. Client and server must be upgraded
  **together**.
- A peer that speaks the old protocol fails the strict NDJSON parse and the
  exchange fails closed (the PAM stack falls through); it is never answered as if
  the new protocol had been negotiated.

### 14.2 Features removed

- **Reuse proxy.** `mode = "proxy"` and `proxy_socket` are gone on every
  transport (§2.3). The client opens a fresh connection per PAM invocation. A
  config carrying `mode = "proxy"` or `proxy_socket` is invalid.
- **Static client socket fallback.** The client no longer reads `socket` from
  `/etc/sudo-auth-proxy/config.toml`; that key now names the **server's** bind
  path. The `/proc/$PPID/environ` fallback is also gone. The client resolves the
  `unix` target from `$SUDO_AUTH_PROXY_SOCK` **only**, and fast-fails when it is
  unset (§4.3).
- **Anti-fatigue / rate-limiting** (rate limiter, backoff, circuit breaker,
  "remember this request") is removed; only credentialed requesters reach a
  dialog and a deny is always explicit (§11.3).
- **Command/argv display** is removed; it was never trustworthy and is not in the
  protocol (§5.4, §11.1).
- **Every authentication method except mTLS** (§7). `client_auth = "ssh"`
  (SSH-key and ssh-agent request signatures), `client_auth = "x509"`
  (application-layer certificate signatures) and `server_auth = "signature"`
  (host-signed responses) are gone, along with their wire fields
  (`alg`/`key_id`/`public_key`/`cert`/`signature`), the signature algorithm
  allow-lists, the SSH wire-blob encoding, the ssh-agent client, the
  domain-separation label and the whole keyring/key-distribution story. A client
  or server built before this change cannot exchange a single request with an
  upgraded peer (§14.1) — and cannot be *misconfigured* into accepting one
  either.

### 14.3 Configuration

- `transport` gains `"unix"` alongside `"vsock"`/`"tcp"`.
- The `[security]` model (`transport_encryption`, `server_auth`, `client_auth`)
  replaces the loose `mtls`/`protocol` options. `mtls.enable = true` is still
  accepted as `transport_encryption = "mtls"`. A `tcp` config defaults to `mtls`
  (recommended); `none` is accepted explicitly but **insecure** and emits a
  warning. `server_auth = "none"` is accepted but not recommended and is strongly
  discouraged on `tcp` (§7.2, §7.4, §7.5).
- New keys: the `[acl]` authorization table (§8.5), `socket`, `socket_dir_mode`,
  `socket_mode`, `recv_timeout`, `response_ttl`, `clock_skew` (§7.9, §8.5).
- **Every signing/auth key is gone.** `[security].ssh_signing_key`,
  `ssh_agent`, `ssh_agent_socket`, `ssh_key`, `client_cert`, `client_key`,
  `ca_file`, `client_required_oid`, `trusted_server_keys`, `server_signing_key`
  and `trusted_keys` are no longer read or emitted, and the corresponding Nix
  options (`security.sshSigningKey`, `sshAgent`, `sshAgentSocket`, `sshKey`,
  `clientCert`, `clientKey`, `caFile`, `clientRequiredOid`,
  `trustedServerKeys`, `serverSigningKey`, `acl.trustedKeys`) were removed from
  the module — a leftover setting in a Nix config is now an evaluation error,
  which is the intent. `[acl].trustedFingerprints` remains, now meaning mTLS
  leaf SPKI fingerprints only. See §14.2 and §7.2/§7.3.
- **The config is validated against an exact schema (§7.9).** This is a breaking
  change for hand-written files: an unknown key — including one of the removed
  keys above — now aborts startup instead of being ignored, and a key written on
  the wrong side of a `[table]` header is reported as the placement error it is
  rather than as a missing knob. Files generated by the module are unaffected;
  `extraSettings` entries that the Python does not read are not, by design.
  `examples/sudo-auth-proxy-server.toml` is validated by the test suite.
- The guest config directory mode changed from `0755` to `0750 root <group>`
  (§9.2); the guest module sets the group to the guest login group.

### 14.4 Keys, sockets and the guest

- The only credential material is the mTLS set under `[mtls]` (§7.7). The
  `unix` transport, which used to authenticate with an application-layer X.509
  client certificate and signed responses, now runs mTLS inside the SSH tunnel:
  `transport_encryption = "mtls"`, `client_auth = "transport"`,
  `server_auth = "transport"`, and `acl.mode = "ca"` with the tartarus CA and
  the sudo client OID. The host module and the guest module both ship that
  configuration.
- The guest must have `/run/sudo-auth-proxy` `0700` **owned by the guest login
  user**, and `sshd` must `AcceptEnv SUDO_AUTH_PROXY_SOCK` and
  `AcceptEnv SUDO_AUTH_PROXY_ACTIVE`, with both `env_keep` entries in `sudoers`
  (§4.3, §9.2, §15.2). The guest module deploys all of this.
- **Timeout migration:** a pre-`auth_pending` deployment that raised
  `recv_timeout` to the human window should be moved back to the shipped
  `recvTimeout = 0.5` and give `decisionTimeout` the human window (default
  `120`). `recv_timeout` now bounds only the `auth_pending` ack, so keeping it
  large merely delays stale-socket fast-fail (§6.2a, §10.2). A mixed-version
  pair (new server, old client) fails closed; upgrade both together (§14.1).

### 14.5 Firewall and transport migration

- The `65001` TCP allowance is only needed while a guest uses `tcp`; `unix` needs
  none. Remove it when no guest uses `tcp`.
- **Guest `tcp` → `unix`:** enable `custom.programs.ssh.sudoAuthProxy` on the
  host for that guest with the guest in `hosts` (§15.1), set the guest transport
  to `unix`, set `transport_encryption = "mtls"` with the tartarus client
  certificate, and rebuild. Verify with a test `sudo` while logged in (§15.3).
  The host side must be switched at the same time (`acl.mode = "ca"` with the
  CA + client OID, `mtls.enable = true`); the shipped modules do this for you.

### 14.6 Third-party clients

**Only the `sudo-auth-proxy` client shipped in this repository is supported**
(§1.2). The protocol is now specified precisely enough in §6 and §6.8 that a
future client could be written deliberately, but there is **no compatibility
guarantee** for any third-party client, and a peer is not trusted merely because
it speaks the wire format — trust comes from the credential it proves and the ACL
(§5, §8). Any third-party client requires a design review against this document.

### 14.7 Unauthenticated transports (`client_auth = "none"`)

A new `client_auth = "none"` mode disables **requester authentication and
authorization** for a transport that is private by construction (VSOCK, an SSH
`RemoteForward` tunnel, a local Unix socket). It is deliberately awkward to
enable and fails closed:

- `client_auth = "none"` is rejected when `transport_encryption = "mtls"` (mTLS
  already forces `client_auth = "transport"`) and emits a warning that any
  process able to reach the socket may trigger a prompt.
- The client sends `client_auth = {"method": "none"}` and proves nothing.
- The server requires the matching `[acl] mode = "none"` (an explicit
  allow-any); `mode = "none"` refuses to carry any trust material
  (`trusted_fingerprints`, `ca_file`, `required_oid`).
- The Python enforces the **XOR** between the two knobs: `client_auth = "none"`
  with a non-`none` ACL raises, and `acl.mode = "none"` with a non-`none`
  `client_auth` raises. Disabling auth is therefore always a conscious choice on
  both sides.

The shipped tartarus guest/host default for the callback transport
(`vsock`/`tcp`) is now `transport_encryption = "none"`, `client_auth = "none"`,
`server_auth = "none"`, `[acl] mode = "none"`: the MicroVM channel is private by
construction and runs with no crypto (`server_auth = "none"` warns
accordingly). Either all three knobs are written out, or the process refuses to
start.

### 14.8 A second server instance (`extraServer`)

A host can run one additional, independent server alongside the legacy
`server`. The home-manager option
`tartarus.sudo-auth-proxy.extraServer` has its own `transport`, `security`,
`acl`, `mtls`, settings and `name`; it runs as the unit
`sudo-auth-proxy-<name>` with the config file
`~/.config/sudo-auth-proxy/<name>.toml` (and its own runtime directory). This is
what lets one host serve its tartarus guests on the callback transport **and** a
remote host over the SSH-forwarded `unix` transport in a single home-manager
configuration. (It is modelled as a plain nested option set, not an
`attrsOf (submodule)`: reading the latter inside the same module graph forces
the root config and recurses.)

---

## 15. Operations guide (setting it up)

### 15.1 Host

#### NixOS / nix-darwin (the shipped path)

1. Ensure the host's SSH config reaches the guest (existing tartarus setup).
2. Enable the server and its trust roots: the `[acl]` policy and the `[mtls]`
   certificate material. **The shipped tartarus host module derives all of this
   (audit A1):** `nix/host/services.nix` emits a usable `[acl]` (`mode = "ca"`
   with the tartarus CA + the sudo client OID), selects one server transport from
   the guests' `services.sudoAuthProxyTransport` markers (mixing transports
   across the guests of one host is an evaluation error), and turns mTLS on for
   the `unix` path. Set these options by hand only when not using the tartarus
   host module.
3. Enable the SSH-forward wrapper for the chosen host patterns. The guest-side
   path template uses `%r` (resolved login user) and `%h` (destination as typed);
   the wrapper expands them, expands `%t` for the host socket itself, and appends
   the per-session random token before `.sock`. OpenSSH cannot do this, which is
   why it is a wrapper rather than a `programs.ssh.settings` block (§3.2):

   ```nix
   custom.programs.ssh.sudoAuthProxy = {
     # Defaults to true when a guest requests the `unix` transport (audit A1).
     enable = true;
     hosts = ["vault.trs" "dev-*.trs"];   # shell patterns; or ["*.trs"] for all
     remoteSocket = "/run/sudo-auth-proxy/%r@%h.sock";  # wrapper appends -<token>.sock
     # hostSocket = "%t/sudo-auth-proxy/server.sock";   # default: the single host server socket
     # envVar = "SUDO_AUTH_PROXY_SOCK";                 # default; must match sshd AcceptEnv + sudoers
     # shadowSsh = false;  # opt in to also install the wrapper as `ssh`
   };
   ```

   `hosts` defaults to the VMs (`<name>.trs`) and containers (`<name>`) of every
   enabled guest whose `services.sudoAuthProxyTransport = "unix"`.
   `%t/sudo-auth-proxy/server.sock` is the single host server socket every
   session forwards to; there is no per-guest socket. With an empty `hosts` the
   wrapper is a pure pass-through.

   The wrapper is installed as **`sudo-auth-proxy-ssh`**; it does not shadow
   plain `ssh` unless `shadowSsh = true` (off by default). So a plain
   `ssh <guest>` carries no forward by default — open the session with
   `sudo-auth-proxy-ssh <guest>` (audit N7). Only with `shadowSsh = true` does
   `ssh <guest>` become transparent, at the cost of shadowing the system `ssh`
   for every connection.

4. Ensure the server runtime directory is `0700` and the socket `0600`.
5. Set the security knobs (§7.5): `transport_encryption = "mtls"` with
   `client_auth = "transport"` and `server_auth = "transport"` for the `unix`
   path; or `transport_encryption = "none"` with **both** auth knobs written as
   `"none"` for a callback transport whose channel is private by construction
   (the module asserts this combination at evaluation time).
6. Set the timeouts for interactive use (§10.2/§10.5): `recvTimeout` bounds the
   `auth_pending` ack (the shipped `0.5` is fine) and `decisionTimeout` is the
   human window (`120` by default; `0` waits); `connectTimeout` small
   (default `0.2`).

#### Standalone (a host without Nix — e.g. the MOFOS VM's host)

The server is a single Python script, so a machine that runs neither NixOS nor
home-manager can still host it. `examples/` in the tartarus repository carries a
ready-to-edit pair:

| File                                | Purpose                                                        |
| ----------------------------------- | -------------------------------------------------------------- |
| `examples/sudo-auth-proxy-server.toml` | Annotated `~/.config/sudo-auth-proxy/config.toml` for a `vsock` server with no encryption and no authentication. |
| `examples/sudo-auth-proxy.service`  | A systemd **user** unit that runs it inside the approver's graphical session. |

1. Install the script and its one dependency:

   ```sh
   pip install --user cryptography                              # or python3-cryptography
   install -Dm755 sudo-auth-proxy.py ~/.local/bin/sudo-auth-proxy
   install -Dm644 examples/sudo-auth-proxy-server.toml \
       ~/.config/sudo-auth-proxy/config.toml
   ```

2. Check the port and the transport agree with the guest. The example binds
   `cid = 2` (VMADDR_CID_HOST) on port **65012**, which is what the MOFOS guest
   in nixcfg uses on its side (`tartarus.sudo-auth-proxy.port`). Both ends must
   match, and the matching server-side requirement of `client_auth = "none"` is
   the `[acl] mode = "none"` in the same file.
3. Make sure VSOCK is available: the host kernel needs `vhost_vsock` (or
   `vmw_vsock_virtio_transport` under VMware), and the VM must be started with a
   vsock device and a CID. `modprobe vhost_vsock` and `lsmod | grep vsock`
   confirm it. A guest that cannot reach CID 2 gets a fast `unavailable` and the
   PAM stack continues — that is the intended fail-fast behaviour, not a hang.
4. Make sure a dialog backend exists and can reach the desktop:
   `zenity` (Linux) or `osascript`/`swiftDialog` (macOS), with `DISPLAY` or
   `WAYLAND_DISPLAY` set in the unit's environment (§11.4).
5. Enable it:

   ```sh
   install -Dm644 examples/sudo-auth-proxy.service \
       ~/.config/systemd/user/sudo-auth-proxy.service
   systemctl --user daemon-reload
   systemctl --user enable --now sudo-auth-proxy.service
   journalctl --user -u sudo-auth-proxy -f
   ```

6. Verify from the guest with a test `sudo` (§15.3). The server logs every
   connection, and with `debug = true` also the sanitised request fields and the
   full detail block the dialog summarises.

> `examples/sudo-auth-proxy-server.toml` is a validated configuration: it is
> parsed and resolved by the same `load_config` + `build_security` path the
> service uses, and it resolves to `transport = "vsock"`, `cid = 2`,
> `port = 65012`, `transport_encryption = "none"`, `client_auth = "none"`,
> `server_auth = "none"`, `acl.mode = "none"`.

### 15.2 Guest

1. Set `transport` (`"unix"` for the SSH tunnel, or a callback transport) and
   the matching `[security]` values: mTLS (`transport`/`transport` plus the
   `[mtls]` block) when the channel must authenticate anything, or the explicit
   `none`/`none` pair on a private callback transport.
2. **Guest `/run` ownership (hard requirement).** `/run/sudo-auth-proxy` must
   exist, be mode `0700`, and be **owned by the guest login user** — not root.
   The `RemoteForward` bind runs as that user (the guest `sshd`), and the host
   sets `ExitOnForwardFailure=yes`, so a root-owned (or missing) directory makes
   every session fail loudly at bind time. The guest module deploys the
   equivalent of `d /run/sudo-auth-proxy 0700 <login-user> <login-group> -`
   (§4.3, §9.2).
3. Ensure the guest sshd accepts the selector env var
   (`AcceptEnv SUDO_AUTH_PROXY_SOCK`) **and** the recursion guard
   (`AcceptEnv SUDO_AUTH_PROXY_ACTIVE`), **and** that `sudoers` keeps both
   (`Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"` and
   `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"`). The guest module deploys
   them in `security.sudo.extraConfig` (the tail of `/etc/sudoers`), where a
   later `sudoers.d` fragment cannot negate them. The `env_keep` entries are what
   make per-session routing deterministic and keep the recursion guard working
   (§4.3, §10.4).
4. For mTLS, provision the guest's certificate and key `0600` and register the
   trust root on the host: the CA + EKU for `acl.mode = "ca"`, or the leaf SPKI
   in `[acl].trusted_fingerprints` for `mode = "list"`. Setting
   `services.sudoAuthProxyTransport = "unix"` makes the tartarus guest module
   wire the tartarus client certificate automatically (audit A1).
5. Keep the PAM rule optional (`[success=done default=ignore]`).
6. Leave `recvTimeout` at the shipped `0.5` (it bounds the `auth_pending` ack)
   and set `decisionTimeout` to the human window (§10.2).

### 15.3 Verifying

- Log into the guest, confirm `SUDO_AUTH_PROXY_SOCK` is set and the socket exists
  (`printf '%s\n' "$SUDO_AUTH_PROXY_SOCK"; ls -l "$SUDO_AUTH_PROXY_SOCK"`).
- Confirm `ls -ld /run/sudo-auth-proxy` shows the **guest login user** as owner
  and mode `0700` (§4.3).
- Run `sudo true`; the dialog should appear on the correct host session.
- Deny, and confirm `sudo` fails (or falls through, per policy).
- Test with two host users on a shared guest account: each should only see their
  own prompts.
- Test the multiplexer caveat (§4.6): a `tmux`/`zellij` server started in one SSH
  session keeps that session's selector, so a `sudo` from a pane created later
  still routes to the session that started the multiplexer. This is expected;
  restart the multiplexer inside the desired session or use per-person guest
  accounts.
- Enable debug logging and check timings: connect should be fast; the only slow
  part should be the human. If the client reports `unavailable` after a fraction
  of a second, `recvTimeout` is too small (§10.2).

### 15.4 Permission pre-flight (quick)

| Path / object                          | Required                                                      | Reference |
| -------------------------------------- | ------------------------------------------------------------- | --------- |
| Host server runtime dir                | `0700`, owned by the server user (`RuntimeDirectoryMode=0700`) | §9.1      |
| Host server socket                     | `0600`, owned by the server user                               | §9.1      |
| Guest `/run/sudo-auth-proxy`           | `0700`, owned by the **guest login user**                     | §4.3, §9.2 |
| Guest config `/etc/sudo-auth-proxy`    | `0750 root <guest-login-group>`                               | §9.2      |
| mTLS client key (`[mtls].key_file`)    | `0600`, owned by the user running the client                  | §7.8, §9.2 |
| mTLS server key (`[mtls].key_file`)    | `0600`, owned by the server user                              | §7.8, §9.2 |

---

## 16. Audit and hardening checklist

**Identity & auth**

- [ ] Exactly one listening socket per transport; no per-guest server socket.
- [ ] `tcp` + `none` is warned as insecure (no confidentiality, no authentication).
- [ ] `transport_encryption = "mtls"` ⇒ **both** `client_auth` and `server_auth` are `"transport"`.
- [ ] `client_auth`/`server_auth` are each exactly `"transport"` or `"none"` — no other value is accepted anywhere in the code.
- [ ] With `transport_encryption = "none"`, both auth knobs are written **explicitly** as `"none"` (a missing one is a startup error, never a silent default).
- [ ] ACL matches only credentials (mTLS leaf SPKI, or a CA chain), never metadata.
- [ ] ACL is evaluated before any dialog; default deny; `acl.mode = "none"` and `client_auth = "none"` agree (XOR).
- [ ] The requester credential is the mTLS peer certificate validated by `ssl` against a root-owned CA, with the peer EKU OID enforced after the handshake.
- [ ] Host user verified via `SO_PEERCRED`/`getpeereid`.

**Decisions**

- [ ] `server_auth = "transport"` ⇒ the decision arrives over the authenticated TLS channel; nothing weaker is accepted.
- [ ] `server_auth = "none"` is warned about at startup and is only used where the socket is private by construction.
- [ ] Expiry enforced; the client rejects any second response for a nonce.
- [ ] No signature fields, algorithm allow-lists or domain label exist anywhere in the wire format or the code (removed, §6.4).
- [ ] `request_digest` is the lowercase-hex SHA-256, recomputed by the client and compared.

**Sockets/files**

- [ ] Directories `0700` (host runtime dir, guest `/run/sudo-auth-proxy` owned by the login user), sockets `0600`.
- [ ] Ownership/symlink checks; stale socket handling.
- [ ] No world-readable private keys; mTLS keys `0600` (written that way by `ca.py`).
- [ ] No fallback socket resolution: `$SUDO_AUTH_PROXY_SOCK` only.

**PAM**

- [ ] Fast connect timeout; no long DNS/hang.
- [ ] `recv_timeout` bounds the first frame (the `auth_pending` ack); `decision_timeout` bounds the human decision. A bound-but-unlistened socket is bounded by `recv_timeout` (§6.2a, §10.2).
- [ ] Fallback semantics documented and intentional (`deny` and `unavailable`
      both fall through; strict mode is not available with `pam_exec`).
- [ ] Recursion guard present **and preserved by `env_keep`** — and understood
      to cover only the helper process, not the elevated shell (A5, §10.4).

**UI**

- [ ] All fields sanitised (allow-list + NFC); `--no-markup`/JSON escaping.
- [ ] The command/argv is never shown or logged.
- [ ] Verified requester identity + context shown; one dialog at a time; no anti-fatigue state.
- [ ] Fields sanitised before logging.
- [ ] The prompt is the condensed summary; the detail block is reachable (swiftDialog `--info`, osascript and zenity **Details**) or logged when the backend offers no extra button (zenity) — never dumped by default (§11.4).

**Docs**

- [ ] Threat model matches the implementation.
- [ ] Third-party client warning present (§1.2).

---

## 17. Future work

- Third-party client support (requires a compatibility statement and review).
- ~~A server sentinel/ack byte before the dialog.~~ **Implemented (audit A2):**
  the server sends an `auth_pending` frame before the dialog, so the short
  first-frame `recv_timeout` gives stale-socket fast-fail while the human wait is
  bounded by `decision_timeout` (§6.2a, §10.2).
- Per-service X.509 certificates (one OID each) so a credential minted for one
  tartarus service is not valid for another (audit A4; today all services share
  one CA-issued identity, §7.6).
- A session/pty-scoped recursion guard that survives into the elevated context
  (audit A5; today the guard covers only the helper process, §10.4).
- TPM/HSM-backed certificate keys.
- ~~Identity-based approval rules.~~ **Implemented (§8.6):** `[[acl.rule]]`
  auto-allows/auto-denies or prompts by resolved identity. Still future work:
  two-person approval and command allow/deny policies (the command is not in the
  protocol; §5.4).
- Out-of-band approval (phone/push) for headless approvers.
- Distinguishing `deny` from `unavailable` in the PAM return path (required for
  any non-ignorable `deny`/strict mode; not implementable with `pam_exec`).
- Signed, append-only audit ledger of approvals.

---

## 18. Glossary

| Term                                  | Definition                                                              |
| ------------------------------------- | ----------------------------------------------------------------------- |
| **Envelope**                          | The newline-delimited JSON message carrying a request or a response.    |
| **Nonce**                             | A random per-request value that binds request and response; single-use. |
| **Request digest**                    | SHA-256 over the canonical request, echoed back by the server.          |
| **Server authentication**             | How the client verifies the server (`server_auth`, §7.2).               |
| **Client / requester authentication** | How the server verifies who is asking (`client_auth`, §7.3).            |
| **Transport encryption**              | Whether the byte stream is encrypted (`transport_encryption`, §7.4).    |
| **mTLS**                              | Mutual TLS: the transport encryption that is also the only authentication mechanism. |
| **EKU OID**                           | Extended Key Usage object identifier distinguishing service roles.      |
| **Tunnel**                            | The host→guest SSH `RemoteForward` that carries the Unix socket.        |
| **ACL**                               | The authorization policy (§8) deciding who may use the mechanism.       |
| **Callback**                          | Guest dials host (`vsock`/`tcp`).                                       |
| **Approver**                          | The host user who answers the dialog.                                   |

---

## 19. Design review log

Review **v1** findings (first `audit` + `challenger` pass) are in §19.1–§19.5;
review **v2** findings (second pass, after the revisions) are in §19.6. The
inline edits above reference these IDs. No code is written until the
"must-fix before coding" items are resolved in the design (they now are).

### 19.1 Critical / must-fix before coding

| ID     | Finding                                                                                                                                                                                                                                                             | Disposition                                                                                                                                                                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F1/F2  | Host signature guarantees _authenticity_, not _routing_. With a shared guest login UID, an attacker can unlink/symlink the socket to another person's legitimate tunnel, and the signer (wrong approver) still produces a valid `allow`. The doc conflated the two. | §9.2 now separates authenticity vs. routing; added Linux `SO_PEERCRED`→`/proc/<pid>/exe` peer check, `lstat`/no-symlink; recorded as residual risk **R6**; recommended per-person guest accounts for strict isolation.                               |
| Rank 1 | The `SetEnv` → `sudo` → `pam_exec` selector chain is fragile: `sudo`'s `env_reset` can strip `SUDO_AUTH_PROXY_SOCK`, and `/proc/$PPID/environ` may not help (same reset). Silent loss of per-person isolation.                                                      | **Fixed in design:** guest Nix module deploys `Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"`. The `/proc` fallback is demoted to best-effort/Linux-only. §4.3, §12.4 A6, §15.2. **Extended by B2 (§19.6)** to also preserve `SUDO_AUTH_PROXY_ACTIVE`. |
| F3     | The reuse proxy relays by `readline()` (newline-delimited); the binary envelope has no guaranteed newline, so it would hang/misframe.                                                                                                                               | **Superseded by v3 S2:** the proxy is **removed on every transport** (the v2 decision to keep it for `vsock`/`tcp` no longer holds). §2.3.                                                                                                            |
| F12    | The current CA code mints the guest client key world-readable (`0644`).                                                                                                                                                                                             | §7.8/§9.2: fix in `ca.py`, not just at runtime; Phase 5.                                                                                                                                                                                             |
| F4     | `pam_exec` under `sudo` runs with euid 0, not "as an unprivileged invoking user".                                                                                                                                                                                   | §12.4 A5 corrected; client must not rely on an OS privilege boundary.                                                                                                                                                                                |

### 19.2 High / medium (fixed in design or explicitly accepted)

| ID      | Finding                                                                                                              | Disposition                                                                                                                                           |
| ------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| F5      | A human `deny` is indistinguishable from `unavailable` and falls through, so a local password can bypass the "no".   | §6.6/§10.3 warn explicitly; strict mode is **not implementable with `pam_exec`** and requires the native PAM module (§17). Refined by **§19.6 C1**.   |
| F6      | `lstat` + `bind`/`connect` is TOCTOU.                                                                                | Accepted for same-UID peers; noted in §9.1; `O_PATH\|O_NOFOLLOW` suggested.                                                                           |
| F7      | `/proc/$PPID/cmdline` is spoofable and wrong for `login`/`su`.                                                       | §5.4 now labels it best-effort, display/binding only.                                                                                                 |
| F8      | Nonce cache bounds unspecified.                                                                                      | §6.5 specifies max 4096 / 120 s TTL / LRU. **Overflow policy revised by §19.6 C3:** evict-oldest + alert (optional fail-closed), not silent drop-new. |
| F9      | Guest config dir is `0755`.                                                                                          | §9.2 now `0750 root <group>`.                                                                                                                         |
| F10     | Legacy/envelope auto-detection aids downgrade.                                                                       | §6.1: `protocol = "envelope"` is the default; legacy and auto are opt-in.                                                                             |
| F11     | `/proc` is Linux-only.                                                                                               | §4.3/§12.4 A6 note macOS has no `/proc` fallback; `env_keep` is the only supported path there.                                                        |
| F12     | macOS `getpeereid` returns uid/gid only (no pid).                                                                    | §9.2: peer-process check is Linux-only; macOS relies on path integrity.                                                                               |
| Rank 4  | Two people on the same **host** account are one principal; cross-guest within one account is a shared approval pool. | Accepted; documented in §5.6/R1/R6.                                                                                                                   |
| Rank 5  | Fallthrough adds latency on every `sudo`.                                                                            | §10.2: connect timeout ≤200 ms + socket-existence pre-check; residual **R7**.                                                                         |
| Q5      | Signed response should include the approver identity.                                                                | §6.3/§6.4 now sign the `approver` field.                                                                                                              |
| Rank 10 | "Only whitelisted can elevate" is only true _through this mechanism_.                                                | Goal wording tightened (§1.4, §8); §10.3 warns the ACL gates the proxy, not `sudo`.                                                                   |
| Rank 6  | Certificate/key distribution inherits Nix-store trust.                                                                | §7.8 now calls this out explicitly.                                                                                                                   |

### 19.3 Confirmed sound

- `ssh -R` streamlocal semantics, `StreamLocalBindUnlink`, `ExitOnForwardFailure`,
  `AcceptEnv` necessity (`ssh -G` verified `%C` expansion in `RemoteForward`).
- `SO_PEERCRED` (Linux) / `getpeereid` (macOS, uid/gid only).
- Per-guest host socket enforcing guest identity in `unix` mode.
- Nonce/digest binding; default deny ACL.
- Current `client.key` `0644` and reuse-proxy socket `0666` are confirmed present
  in today's code and are fixed by this design.

### 19.4 Alternatives considered (from the challenger) and disposition

| Alternative                                                                                                          | Disposition                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Back the selector with `sudoers env_keep` and drop reliance on ambient `sudo` behaviour                              | **Adopted** — deterministic and testable (§4.3); `/proc` kept only as best-effort/Linux.                                                                    |
| Derive the socket path from `PAM_TTY` (host `ssh` writes guest-side pty metadata) instead of an environment variable | **Deferred** — needs the host `ssh` to write guest-side metadata and a pty→file mapping; more complex than `env_keep`. Revisit if `env_keep` is unworkable. |
| Use `PermitListen` (OpenSSH 8.2+)                                                                                    | **Rejected** — does not remove the client's need to know the socket path; adds sshd config.                                                                 |
| Remove the reuse proxy for `unix`                                                                                    | **Superseded by v3 S2** — the proxy is removed on **every** transport; there is no daemon and no second socket. (§2.3, plan Phase 1).                         |
| Show only the program name in the dialog, never the full command                                                     | **Superseded (audit N6).** The command/argv is **never** shown, read or logged: it is not part of the protocol, so it cannot be displayed. The earlier "program + digest / full command opt-in" disposition was never implemented and is void (§5.4, §11.1). |

### 19.5 Empirical verification gates (Phase 2)

Before relying on the `unix` transport in production, verify on each target
platform:

1. `sudo sh -c 'printenv SUDO_AUTH_PROXY_SOCK'` shows the selector (with
   `env_keep` deployed) — and still shows it with `env_reset` defaults.
2. The PAM helper's real/effective uids (`id -u` / `id -ru` from the helper).
3. ~~`/proc/$PPID/environ` readability~~ **(retired in v3 — the fallback was
   removed; the selector must come from the process environment, §4.3).**
4. `SO_PEERCRED` / `getpeereid` return the expected uid for the connecting `ssh`
   process (macOS is blocking for `unix`).
5. A stale guest socket is cleaned up on session teardown (no silent
   degradation), and a bound-but-unlistened socket is bounded by the
   receive timeout of §10.2 rather than hanging.
6. `/run/sudo-auth-proxy` is owned by the guest login user and the
   `RemoteForward` bind succeeds; with the selector absent the client fast-fails
   without reading any fallback path (§4.3).

### 19.6 Design review log (v2)

A second `audit` + `challenger` pass reviewed the revised design. Two
consistency blockers and a set of follow-up findings came out of this pass; each
is fixed inline and mapped below. Every item here is also bound to a phase in the
`plans/sudo-auth-proxy-redesign.md` **Phase 0.5** fix-mapping table.

| ID  | Finding                                                                                                                                               | Disposition                                                                                                                                                         |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1  | §7.4 showed `"SAP-v1"` then nonce, request_digest, decision, times — omitting `approver` and disagreeing with §6.4.                                   | §7.4 now quotes the full §6.4 transcript including `approver`; `alg` + `key_id` added (see NF1).                                                                    |
| B2  | `SUDO_AUTH_PROXY_ACTIVE` (§10.4) is not preserved by `sudoers env_keep`, so default `env_reset` strips it and the recursion guard silently fails.     | `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` mandated wherever the socket selector is (§4.3, §12.4 A6, §15.2).                                                   |
| NF1 | Signature algorithm/key were not bound and there was no agility story.                                                                                | `alg` + `key_id` added to the signed transcript (§6.4, §6.3); the client pins the expected `key_id` and rejects unknown/absent `alg` (§7.4, §7.6).                  |
| NF2 | Dialog fields (especially swiftDialog markdown) can be injected; the current code interpolates `{peer}` unescaped (`nix/packages/sudo-auth-proxy/sudo-auth-proxy.py`). | §11.2 defines NFC normalisation plus an allow-list `[A-Za-z0-9_.:/@-]` for every attacker-influenced field, with swiftDialog `* [ ] ( )` escaping.                  |
| NF4 | A stale bound-but-unlistened Unix socket does **not** fail fast: `connect()` succeeds and the client then hangs on `read()`.                          | §4.3 wording corrected; §10.2 adds a receive/response timeout (`SO_RCVTIMEO`, ~500 ms); T19/T24 updated.                                                            |
| NF5 | Rate-limit/backoff/circuit-breaker requirements were vague.                                                                                           | §11.3 fixed to max 3 prompts / 60 s / guest; exponential backoff from 5 s; breaker 10 denials / 60 s → open for 300 s; state in server memory with a 10-minute TTL. |
| NF6 | `list` pins the mTLS SPKI, but `unix` has no mTLS by default, so the pin had nothing to match.                                                       | §8.2/§8.4 define `unix` pinning as the SSH host-key fingerprint or require `mtls = true`; with neither, fail closed.                                                |
| NF7 | The guest socket path is predictable and raceable with the `RemoteForward` bind.                                                                      | §4.2 adds an unpredictable per-session token to the basename, carried in `SetEnv`; cleanup removes the exact path. Accepted residual **R9**.                        |
| NF8 | Fields could inject into log records.                                                                                                                 | §11.2 applies the same sanitiser to `guest_hint` (and all fields) before logging.                                                                                   |
| C1  | Env-resolution order was not stated; `run_client` reads only `config.toml`; `sudoers.d` fragment ordering is fragile.                                 | §4.3 documents `$SUDO_AUTH_PROXY_SOCK` → `config.toml`, flags the code gap as Phase 2 work, and warns a later fragment can negate `env_keep`.                       |
| C3  | Nonce cache "drop new" on overflow could silently disable duplicate detection under flood.                                                            | §6.5 makes the client single-use nonce the primary defence; overflow now evicts oldest + alerts (optional fail-closed). Accepted residual **R10**.                  |
| C4  | `unix` was framed as more secure than `vsock`/`tcp`.                                                                                                  | §3/§4.4 state plainly that it is a _different_ trade (no open port, but session-bound availability risk), not strictly more secure.                                 |
| C8  | The macOS limitation (`getpeereid` uid/gid only, no `/proc`) lived only in §19.                                                                       | Surfaced in the §12.5 threat table (T25) and recorded as residual **R11**.                                                                                          |

### 19.7 Design review log (v3) — single-socket + cryptographic-auth revision

A third pass applied the operator's review of the transport and authentication
model. The **single host socket** replaces per-guest sockets; authentication
becomes an explicit three-knob model; and several insecure or awkward features
are removed. Inline edits above carry these IDs.

| ID  | Change                                                                                                                                                                                  | Where                     |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| S1  | Host listens on **one** socket per transport (one `server.sock`), not one per guest; guest identity no longer comes from the socket.                                                    | §2.2, §3, §4.1–§4.2, §9.1 |
| S2  | **Reuse proxy removed entirely**, on every transport.                                                                                                                                   | §2.3                      |
| S3  | Client resolves the socket from `$SUDO_AUTH_PROXY_SOCK` **only**; the `/proc/$PPID/environ` fallback is removed.                                                                        | §4.3                      |
| S4  | Static `socket` fallback removed; absence of the selector fast-fails.                                                                                                                   | §4.3, §15                 |
| S5  | Command/argv removed from the dialog (spoofable) and never logged.                                                                                                                      | §5.4, §11.1               |
| S6  | Protocol is newline-delimited **JSON** instead of a raw framed structure.                                                                                                               | §6                        |
| S7  | Legacy protocol and byte-sniffing auto-detection removed; no downgrade.                                                                                                                 | §6.1, §14                 |
| S8  | Domain-separation label changed from `"SAP-v1"` to `"tartarus/sudo-auth-proxy/v1"`.                                                                                                     | §6.4                      |
| S9  | Server-side nonce cache removed; the client's single-use nonce is the whole replay defence.                                                                                             | §6.6, §12.6 R10           |
| S10 | `client_auth` is exactly one of `ssh`/`x509` (`transport` under mTLS); never the two together.                                                                                          | §7.3, §7.5                |
| S11 | ACL matches **only** cryptographic credentials, never destination/metadata.                                                                                                             | §8                        |
| S12 | Anti-fatigue machinery (rate limit/backoff/breaker) removed.                                                                                                                            | §11.3                     |
| S13 | `server_auth`/`client_auth`/`transport_encryption` knobs defined; `tcp` defaults to mTLS but `none` is permitted (insecure); `client_auth = "transport"` delegates client auth to mTLS. | §7.2–§7.5                 |
| S14 | Guest `/run/sudo-auth-proxy` must be owned by the login user (answers the bind-writability question).                                                                                   | §4.3, §9.2, §15.2         |
| S15 | Multiplexer (tmux/zellij) selector behaviour documented, fail-closed, no weaker fallback.                                                                                               | §4.6, R12                 |

Superseded findings: v1 F3 (reuse-proxy framing), v2 NF5 (anti-fatigue) and v2
C3/R10 (nonce cache) are resolved **by removal**; v2 NF6 (unix pinning) is
resolved by the credential-based ACL; the v1 per-guest-socket identity model no
longer applies.

The following entries in §19.1/§19.2 are also superseded by v3 (§19.7) and must
not be read as describing the shipped build:

- **F8** (nonce cache bounds) and **C3** (cache overflow): the server has **no**
  nonce cache; the client's single-use nonce is the whole replay defence (§6.6).
- **F10** (legacy/envelope auto-detection): there is **no** legacy protocol and
  **no** auto-detection; the wire is NDJSON only (§6.1).
- **v1 "Confirmed sound"** items that name `"SAP-v1"`, a per-guest host socket, or
  the reuse proxy are historical and do not apply.

Where this review log conflicts with §1–§18, the normative sections win.

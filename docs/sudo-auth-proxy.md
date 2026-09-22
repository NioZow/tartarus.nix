# sudo-auth-proxy — Architecture, Security Model & Threat Model

**Status:** design document (reviewed by `audit` and `challenger` before
implementation; see `plans/sudo-auth-proxy-redesign.md`).
**Audience:** operators of tartarus guests/hosts and reviewers of this service.

> This document is the **source of truth** for _what_ `sudo-auth-proxy` is and
> _how it is expected to work_. The companion
> [`plans/sudo-auth-proxy-redesign.md`](plans/sudo-auth-proxy-redesign.md)
> describes _how_ the redesign is implemented and in what order.

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
| **Server authentication** | How the **client** verifies it is talking to the real server: `signature`, `transport` (mTLS), or `none`.                    |
| **Client authentication** | How the **server** verifies who is asking: `ssh` (SSH-key signature), `x509` (CA-signed certificate), or `transport` (mTLS). |
| **Approver**              | The human who answers the dialog; identified by the host user running the server.                                            |
| **Principal**             | A verified cryptographic identity used by the ACL (a trusted public key or certificate, never a socket path or address).     |

### 1.4 Goals and non-goals

**Goals**

- Let a headless guest elevate privilege only with explicit human approval on the host.
- Support a callback direction (`vsock`, `tcp`) for local/high-speed use **and** a
  host→guest SSH-forwarded Unix-socket direction (`unix`) that needs no host
  address and opens no network port.
- Isolate multiple people so one person never answers another person's prompts.
- **Authenticate the server by default** so a local process cannot make the
  client act on a forged `allow`, and **authenticate the requester** so a
  process cannot make the approver rule on a request it did not send.
  Authentication is cryptographic and independent of the socket path, address
  or any other connection metadata (§7).
- Restrict _who may use the mechanism_ (not everyone) by matching **only
  cryptographic credentials** (trusted public keys / CA-signed certificates).
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
  unsigned/legacy protocol (§4.3, §6.1).

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
  credential (§8), shows the dialog (§11), and authenticates its own response
  according to `server_auth` (§7.2) — a signature by default, or the mTLS
  channel when `transport_encryption = "mtls"`.
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
  confidential nor protected from an active attacker at the network layer. It is
  still _authentic_ if message signing is used: the requester signs the request
  and the server signs the response, so a MITM cannot forge or alter a decision
  (only read the metadata). Use `none` on `tcp` only over a trusted network and
  prefer `mtls`.
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
authentication of the principals at the application layer. The full rules are in
§7; in brief:

- `tcp` → `mtls` by default, `none` allowed but insecure → with `mtls` the TLS
  channel authenticates both peers and no message signatures are used; with
  `none` the requester/response signatures carry authenticity and integrity
  (§7.3, §7.2) but confidentiality is lost.
- `vsock` → `none` by default → the requester signs the request (`client_auth`)
  and the server signs the response (`server_auth = "signature"`), unless the
  operator opts into mTLS.
- `unix` → `none` by default → same as vsock, with the SSH tunnel providing the
  channel protection. mTLS is optional defence in depth.

There is **no downgrade path**: a transport configured for mTLS refuses to fall
back to plaintext, and a client configured for `server_auth = "signature"`
rejects an unsigned response (§6.1, §7.5). Choosing `none` is an explicit
operator decision, never a runtime fallback.

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
a same-name re-bind; a stale path can never be *reused* because each session's
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
recorded in the request and covered by the client's signature, so a decision is
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
      │                  │ request JSON {nonce,user,tty,digest, client_auth=ssh|x509} │                     │
      │                  │                      │               │                     │──verify credential──│
      │                  │                      │               │                     │──show dialog───────▶│
      │                  │                      │               │                     │◀────allow/deny──────│
      │                  │◀──response JSON {nonce,decision, server_auth=signature|transport} ─────────────────│
      │                  │ verify server auth   │               │                     │                     │
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
| **Which requester sent it?**    | The verified `client_auth` credential: an SSH-key signature over the request, or an X.509 certificate plus signature (or the mTLS peer certificate). | Cryptographic; the server holds the trust roots.                          |
| **Which session / tty?**        | The selector (`$SUDO_AUTH_PROXY_SOCK`) for delivery, and `PAM_TTY` for binding.                                                                      | Selector guaranteed in-session by `env_keep`; tty bound into the request. |
| **Which working directory?**    | `PWD`/`cwd` of the `sudo` process.                                                                                                                   | Guest-provided metadata; shown to the approver and bound to the request.  |

### 5.1 Host person (approver)

- Every mode: the server is one host user's service. In `unix`, the accepted
  connection comes from that user's `ssh` process, and the server verifies the
  peer uid (§9.1). In `tcp`/`vsock`, the approver is the user running the server.
- The approver's identity is **not** claimed by the guest; it is where the server
  runs.

### 5.2 Requester identity (guest / user)

- `client_auth = "ssh"`: the requester signs the canonical request with an
  SSH key; the server verifies it against `trusted_keys` (root-owned, **not** a
  guest-writable `authorized_keys`, §7.3). Identity is the key's SHA-256
  fingerprint.
- `client_auth = "x509"`: the requester presents a certificate and signs the
  request; the server verifies the chain to the trusted CA, the service EKU, and
  the signature. Identity is the certificate SPKI fingerprint (and its CN).
- `client_auth = "transport"`: the mTLS peer certificate, when
  `transport_encryption = "mtls"`.
- The ACL (§8) matches **only** these cryptographic identities.

### 5.3 Guest login user and session

- `PAM_USER` is the account being authenticated (for `sudo`, usually `root`).
- `PAM_RUSER` / `SUDO_USER` is the invoking user.
- `PAM_TTY` identifies the terminal; it distinguishes concurrent sessions.
- These are provided by the guest and are **not independently verifiable by the
  host**. Their role is to (a) be shown to the approver and (b) be bound into the
  signed request so an approval cannot be reused for a different session. They
  are **not** authorization inputs; enforcement is on the credential (§8).

### 5.4 Working directory and command

- `cwd` is recorded and shown as metadata, and is covered by the client's
  signature.
- The **command/argv is not shown in the dialog** (review log S5, §19.7). It is
  guest-controlled and spoofable (`/proc/$PPID/cmdline` can be rewritten with
  `prctl(PR_SET_MM_ARG_START)`, and for `login`/`su` the parent is not `sudo`),
  so displaying it would be misleading while making the prompt noisy. It is
  never an authorization input. The request binds `service + invoking user +
tty + cwd + nonce` instead.

### 5.5 Trust boundaries

1. **Guest kernel / guest root** is trusted for the guest's own PAM path only.
2. **Network / channel** between client and server is untrusted; it is protected
   by mTLS (`tcp`, and optionally `vsock`/`unix`), by the SSH tunnel (`unix`), and
   — when `server_auth = "signature"` — by the signed response end-to-end.
3. **Host user process space** is trusted to run the server, but any host process
   of the same uid can connect to the single server socket. The requester's
   credential (§7.3) and the approver's judgement constrain what such a process
   can cause to appear; §9.1 constrains other uids.
4. **The trust roots** (X.509 CA, host signing key, trusted requester keys) are
   trusted roots; their compromise is catastrophic and is handled by rotation
   (§7.8) and by keeping them off guests.

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
  this JSON protocol, so a peer cannot downgrade the exchange to an unsigned or
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
    "method": "ssh",
    "alg": "ssh-ed25519",
    "key_id": "SHA256:AbCd...=",
    "signature": "..."
  }
}
```

(Shown pretty-printed for readability; on the wire it is one compact line.)

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
is not signed**; trust in the final decision still rests entirely on
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
| `approver`                | The host user that answered (informational; bound when signed).                                                             |
| `issued_at`, `expires_at` | Freshness window.                                                                                                           |
| `server_auth`             | Authentication block (§6.5): present for `server_auth = "signature"`; omitted for `mtls` (channel-authenticated) or `none`. |

### 6.4 Canonicalisation, digest and domain separation

- The **request digest** (`request_digest`) is the **lowercase hexadecimal**
  encoding of SHA-256 over the canonical serialisation of the request object
  with `client_auth.signature` removed (keys sorted, UTF-8, no insignificant
  whitespace): 64 hex characters, e.g. `9f2c…`. It is a bare digest and does
  **not** include the domain label — the label is only inside the signed
  transcript below. The same rule (with `server_auth.signature` removed) applies
  to any digest computed over the response. The implementation computes
  `hashlib.sha256(canonical_bytes(without_signature(request, "client_auth"))).hexdigest()`
  (§6.8).
- The **client signature** covers
  `"tartarus/sudo-auth-proxy/v1" || 0x00 || <canonical request>`.
- The **server signature** covers
  `"tartarus/sudo-auth-proxy/v1" || 0x00 || <canonical response>`.
- `"tartarus/sudo-auth-proxy/v1"` is the **domain separation** label (review log
  S8, §19.7). It replaces the retired `"SAP-v1"` label (SAP is a well-known
  product; the label must name this project and service).
- `alg` and `key_id` are inside the signed auth block, so a peer cannot
  substitute the algorithm or swap keys. The verifier pins the expected
  `key_id`/trust root and **rejects an unknown or absent `alg`** rather than
  guessing (review log NF1).

### 6.5 Authentication blocks

`client_auth` (exact fields; all values are strings):

| `method`    | Fields present                                                                 | Meaning                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `"ssh"`     | `alg`, `key_id`, `public_key`, `signature`                                     | SSH-key signature. `public_key` is the base64 of the key's OpenSSH wire blob (see §6.8); the server recomputes `key_id` from it.           |
| `"x509"`    | `alg`, `key_id`, `cert`, `signature`                                           | X.509 signature. `cert` is the base64 of a PEM bundle, leaf first; `key_id` is the leaf SPKI fingerprint.                                   |
| `"transport"` | *(none)*                                                                     | Under mTLS only. No `alg`/`key_id`/`signature`: the channel certificate is the credential.                                                 |

- `alg` is **required for `ssh`/`x509`** and must be in the allow-list of §6.8;
  an absent or unknown `alg` is rejected, never guessed.
- `key_id` is the credential fingerprint (SSH-blob or SPKI form, §6.8);
  the verifier pins it to the key/certificate it actually verified.
- `signature` covers the canonical request (§6.4); it is the only field removed
  when reconstructing the signed body.

`server_auth` (present when `server_auth = "signature"`):

- `method`: `"signature"`.
- `alg`: an SSH-named algorithm (the host keyring is an OpenSSH keyring) —
  `ssh-ed25519`, `rsa-sha2-256` or `rsa-sha2-512`.
- `key_id`: the SSH fingerprint of the host signing key.
- `signature`: over the canonical response (§6.4).

Under `transport_encryption = "mtls"` or `server_auth = "none"` the whole block
is omitted (§7.5); the response still carries `request_digest` and the freshness
window, which the client checks unconditionally.

When `transport_encryption = "mtls"`, the TLS channel authenticates both peers
and integrity-protects the stream, so **no message signatures are used** and the
`server_auth` block is omitted; `nonce` is optional and used only as a
correlation id (§7.5).

### 6.6 Nonce, freshness and replay

- The client generates a fresh nonce per request and accepts **at most one**
  response for it. A response whose `nonce` or `request_digest` does not match,
  whose `server_auth` does not verify (when required), or which is expired is
  rejected. This is the entire replay defence; **there is no server-side nonce
  cache** (review log S9, §19.7). Because each `pam_exec` invocation opens a
  fresh connection with a fresh nonce, a captured old `allow` can never match a
  new request.
- Expiry is short; clock skew is tolerated within a configured window. The
  binding is `nonce + request_digest`, so a correct decision is valid regardless
  of clock as long as the client accepts it once.

### 6.7 Errors and exit codes

The client exits `0` on a verified allow and non-zero otherwise. It distinguishes,
for logging:

- `denied` — a valid decision of `deny`.
- `unavailable` — transport unreachable, timeout, parse/verify failure
  (including an unknown, absent, or unexpected signature algorithm/key, §7.2).

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
one. Source of truth: `nix/packages/sources/sudo-auth-proxy.py`.

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
  verifier from the parsed object, so wire key order is irrelevant to the digest
  or the signature.
- Every digest and signature is computed over the message with **that message's
  own `signature` field removed** — `client_auth.signature` for a request,
  `server_auth.signature` for a response. Removing an absent field is a no-op, so
  the same construction works while signing (before the field exists) and while
  verifying (after it is stripped).
- The signed transcript is:
  `"tartarus/sudo-auth-proxy/v1" || 0x00 || canonical(body-without-signature)`,
  where the label is the literal UTF-8 bytes `tartarus/sudo-auth-proxy/v1` and
  `0x00` is one NUL byte.
- `request_digest` is the **lowercase hex** SHA-256 (64 chars) of the canonical
  `request-without-client_auth.signature`; it does **not** carry the domain label
  (the label appears only inside the signed transcripts). The client recomputes it
  and rejects any mismatch.

**Signature algorithms and fingerprints**

- `alg` allow-lists (anything else, including `ssh-rsa`/SHA-1, is rejected):
  - `client_auth = "ssh"` and `server_auth = "signature"`:
    `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`.
  - `client_auth = "x509"`: `ed25519`, `rsa-sha2-256`, `rsa-sha2-512`.
- RSA **signing** uses PKCS#1 v1.5 with SHA-256; RSA **verification** accepts
  SHA-256 or SHA-512. RSA-PSS is not implemented.
- `key_id` formats:
  - SSH: `SHA256:` + base64(SHA-256 of the **decoded OpenSSH wire blob**), with
    base64 padding stripped. This is exactly the value `ssh-keygen -lf` prints.
  - X.509 (leaf, or mTLS peer): `SHA256:` + base64(SHA-256 of the DER
    **SubjectPublicKeyInfo**), padding stripped.
  - Fingerprint lists accept the padded or unpadded form and normalise to the
    unpadded one.
- `method = "ssh"` carries `public_key`, the base64 of the key's OpenSSH wire
  blob. The server loads it, recomputes the fingerprint, requires it to equal
  `key_id`, then verifies the signature with that key. `public_key` is inside the
  signed transcript (the signature covers the whole block minus `signature`), so
  it cannot be swapped after signing. There is **no keyring fallback**: a
  request without `public_key` fails closed.

**Response freshness**

- `issued_at` and `expires_at` are Unix-epoch **integers** (seconds);
  `expires_at = issued_at + [security].response_ttl` (default 30) and
  `expires_at` must be greater than `issued_at`.
- The client accepts a response from `issued_at - [security].clock_skew` to
  `expires_at + [security].clock_skew` (default skew 5 s), and rejects a second
  response for the same nonce.
- `approver` is optional and informational; when present it is inside the signed
  transcript.

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

Three independent questions, one config knob each (§7.2–§7.4):

1. **Requester authenticity** — "who is asking?". Without it, any process that
   can reach the socket (a same-uid guest process, or a hostile guest that
   reaches a callback endpoint) can make the approver rule on requests it did
   not send. Provided by **`client_auth`** — either a request signature
   (`ssh`/`x509`) or, when `transport_encryption = "mtls"`, delegated to the
   transport's client certificate (`client_auth = "transport"`).
2. **Server authenticity** — "may the client trust this `allow`?". Without it, a
   process that can bind the client's socket (a fake listener racing `sshd` in
   the guest) could answer `allow`. Provided by **`server_auth`** (a signature)
   or by an authenticated channel (`transport_encryption = "mtls"`).
3. **Channel confidentiality and integrity** — "can anyone read or modify the
   bytes?". Provided by **`transport_encryption = "mtls"`**, or accepted as
   already satisfied when the transport is private and MITM-free by construction
   (SSH tunnel, vsock, a local Unix socket; §7.4).

Cryptography is not optional in general: (2) cannot be replaced by the identity
model, because a fresh `pam_exec` process reading a local socket cannot tell a
genuine `allow` from one injected by a same-uid attacker unless the server
authenticates it. The only case where message-level crypto is dropped is when
the transport already provides it (mTLS).

### 7.2 Server authentication method (`server_auth`)

How the **client** authenticates the server's messages. Exactly one value, no
combination:

| Value                       | Meaning                                                                                                                                                                                                                                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"signature"` **(default)** | The server signs every response with the host signing key; the client verifies against its trusted keyring and pins `key_id`. Used on every transport **except** mTLS.                                                                                                                                                                      |
| `"transport"`               | The server is authenticated by the mTLS handshake (its certificate, CA-verified plus EKU). Requires `transport_encryption = "mtls"` and is then the **only** allowed value; responses carry no signature.                                                                                                                                   |
| `"none"`                    | **Not recommended.** The server sends unsigned responses; the client trusts the socket. Acceptable only when the socket can be bound solely by the legitimate server (e.g. `0600` in the server user's `0700` runtime dir) and the transport is MITM-free. **Strongly discouraged on `tcp`** (a network MITM could impersonate the server). |

### 7.3 Client (requester) authentication (`client_auth`)

How the **server** authenticates who is asking. Exactly one method — **never
`ssh` + `x509` together** (nonsensical and a pure performance loss, review log
S10):

| Value         | Meaning                                                                                                                                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"ssh"`       | The requester signs the canonical request with an SSH key; the server verifies against a root-owned `trusted_keys` list.                                                                                                                |
| `"x509"`      | The requester presents an X.509 certificate and signs the request; the server verifies the chain to the trusted CA, the service EKU OID, and the signature. RSA **or** Ed25519 — the algorithm only has to be trusted by the CA (§7.7). |
| `"transport"` | **Client authentication is delegated to the transport:** the mTLS peer certificate authenticates the requester (CA chain + EKU), with no separate request signature. Requires `transport_encryption = "mtls"`.                          |

Under `transport_encryption = "mtls"`, client authentication is performed by the
TLS certificate, so `client_auth` **must** be `"transport"`. An SSH signature —
including one produced through `ssh-agent` — is **not** allowed on top of mTLS:
the mTLS identity is reused directly, and layering an SSH signature would be the
forbidden TLS-CA + SSH mix.

#### 7.3.1 The SSH key is a service key, not an `authorized_keys` entry

The trust decision lives entirely on the **server**, against a root-owned list
of trusted public keys (`trusted_keys`) or a CA. It is deliberately independent
of:

- the SSH connection that carries a `unix` tunnel (SSH authenticates host→guest,
  which says nothing about the guest's right to ask the host), and
- the guest user's `~/.ssh/authorized_keys`, which that user can rewrite and
  which therefore must never be the trust store.

The key used by the requester **may be, but need not be, the SSH connection's
key**; a dedicated requester key is recommended. Either way the server checks its
own trusted copy, not `authorized_keys`.

### 7.4 Transport encryption (`transport_encryption`)

Whether the byte stream itself is encrypted and integrity-protected:

| Value    | Allowed for                                     | Effect                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"none"` | `unix`, `vsock`; `tcp` **allowed but insecure** | Plain JSON. Legitimate when the transport is private and MITM-free by construction: the SSH tunnel, a vsock connection, or a local Unix socket reachable only by the server user. On `tcp` the channel is MITM-able, so `none` gives no confidentiality — use it only on a trusted network. Message-level `client_auth`/`server_auth` still apply and preserve authenticity/integrity.                          |
| `"mtls"` | `tcp` (default), `vsock`/`unix` (optional)      | A TLS channel with certificates from the shared X.509 CA. It provides confidentiality, integrity **and** mutual authentication, so **both** `client_auth = "transport"` and `server_auth = "transport"` — that is the only allowed pair, the mTLS identity is reused directly, and **no message signatures are used** (in particular, no SSH or ssh-agent signature is accepted on top of the TLS certificate). |

A transport configured for `mtls` **refuses to start** if it cannot establish
TLS; it never silently falls back to plaintext. Choosing `none` is an explicit
operator decision (§7.5).

### 7.5 Valid combinations and no-downgrade rules

| `transport` | `transport_encryption` | `client_auth`   | `server_auth`             | Message signatures           |
| ----------- | ---------------------- | --------------- | ------------------------- | ---------------------------- |
| `tcp`       | `mtls`                 | `transport`     | `transport` (**only**)    | none (channel; no signature) |
| `tcp`       | `none` (**insecure**)  | `ssh` or `x509` | `signature` (or `none`\*) | request (+ response)         |
| `vsock`     | `none`                 | `ssh` or `x509` | `signature` (or `none`\*) | request (+ response)         |
| `vsock`     | `mtls`                 | `transport`     | `transport` (**only**)    | none (channel; no signature) |
| `unix`      | `none`                 | `ssh` or `x509` | `signature` (or `none`\*) | request (+ response)         |
| `unix`      | `mtls`                 | `transport`     | `transport` (**only**)    | none (channel; no signature) |

\* `server_auth = "none"` is only for sockets that the legitimate server alone
can bind (or a transport already trusted) and is never recommended; it is
strongly discouraged on `tcp`.

Config validation: under `mtls`, **both** `client_auth` and `server_auth` must be
`"transport"` — the mTLS channel is reused directly and nothing is layered on
top. `server_auth = "signature"` is rejected under mTLS, and an SSH or
**ssh-agent** signature is not accepted as a substitute for the TLS identity
(this is the forbidden TLS-CA + SSH mix). No `ssh`+`x509` mix anywhere. `tcp` +
`none` is **permitted** (with a warning that the channel is insecure and must
keep message signing). No configuration downgrades at runtime: `none` is only
ever an explicit setting.

### 7.6 EKU OIDs

The design assigns each service a private-enterprise-number OID pair. **However,
per-service isolation is not implemented today (audit A4):** the CA (`ca.py`)
mints the host certificate with **all three server OIDs** and a guest client
certificate with **all three client OIDs**. The OIDs therefore separate the
*server* role from the *client* role, but they do **not** prevent a certificate
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

The implementation enforces the *client* OID on the leaf for `x509`/mTLS, but
because every client cert carries every client OID that check is not
discriminating. Tightening this requires issuing one certificate per service
(or narrowing `ca.py` to a per-service OID and provisioning separate certs).

### 7.7 Algorithms and keys

- **Server signing key:** dedicated keypair by default — Ed25519 preferred, RSA
  supported (SHA-256/512, PKCS#1 v1.5; RSA-PSS is **not** implemented — §6.8).
  Reusing the X.509 host key is allowed but not the default (role-mixing). The
  shipped host wiring (`nix/host/services.nix`) defaults
  `serverSigningKey` to the host's tartarus SSH identity (`~/.ssh/tartarus`)
  because it is already `0600`, always generated, and already trusted by the
  guests; this is role-mixing and an operator who wants a dedicated key simply
  sets `tartarus.sudo-auth-proxy.security.serverSigningKey` (and provisions the
  matching `trustedServerKeys` on the guests).
- **Requester `ssh`:** Ed25519 SSH signatures preferred; RSA (`rsa-sha2-256/512`)
  supported. Keys are listed in `trusted_keys`.
- **Requester `x509` / mTLS:** certificates from the tartarus CA; RSA or
  Ed25519, whichever the CA trusts. Hostname verification is disabled for
  callback transports because the peer address is a CID/DHCP lease, not a
  hostname; identity is the certificate.
- **Algorithm agility (review log NF1).** Every auth block declares `alg` and
  `key_id`; the verifier rejects an unknown or absent `alg` and pins the expected
  `key_id`/trust root — it never guesses.
- Symmetric MACs, if ever used, must use constant-time comparison
  (`hmac.compare_digest`); signatures are preferred (no shared secret,
  non-repudiation).

### 7.8 Key distribution, lifecycle, rotation and permissions

- The host signing public key and the trusted requester keys/certs reach their
  peers through the same build/9p mechanism as `ca.crt`, inheriting the Nix
  store's trust: a compromised build/flake input could substitute a rogue root.
  Treat them as **sensitive-as-CA** for build-input review (review log Rank 6).
  Prefer a keyring (a directory of trusted keys) over a single pinned leaf, so
  rotation needs no rebuild.
- Rotation: regenerate the key/cert, redistribute the trust root, restart.
  Short-lived certificates (X.509) and a new `trusted_keys` entry (SSH) make this
  routine. Rotating the shared CA invalidates every certificate — plan a window.
- **Never** ship a private key world-readable. The historic `0644` client key is
  a bug to fix in the CA generation code (`src/tartarus/ca.py`,
  `_ensure_x509_client_cert`), not only at runtime (review log F12). Host signing
  key: `0600`.
- The requester signing key on the guest (`ssh` or `x509`) is `0600`, owned by
  the requester/login user; it is a private key and is never world-readable.
  Under `unix` with `client_auth = "ssh"` no X.509 client key is needed.

### 7.9 `[security]` table as parsed

The implementation reads exactly these keys. Paths in `[security]` are resolved
like every other path: a leading `~/` is expanded and a relative path is resolved
against the **config file's directory** (not the process CWD).

| Key                    | Used by        | Type / values                          | Notes                                                                                                                        |
| ---------------------- | -------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `transport_encryption`  | both           | `"none"` \| `"mtls"`                   | Default `tcp → "mtls"`, `vsock`/`unix` → `"none"`. `mtls.enable = true` is treated as `"mtls"`. Never a runtime fallback.     |
| `server_auth`          | both           | `"signature"` \| `"transport"` \| `"none"` | Default `"signature"`, or `"transport"` under mTLS. `"transport"` requires `transport_encryption = "mtls"`.                    |
| `client_auth`          | both           | `"ssh"` \| `"x509"` \| `"transport"`   | Default `"ssh"`, or `"transport"` under mTLS. Exactly one value; `"transport"` requires mTLS.                                  |
| `response_ttl`         | both           | int seconds (default `30`)             | `expires_at = issued_at + response_ttl`.                                                                                      |
| `clock_skew`           | both           | int seconds (default `5`)              | Tolerance in both directions when checking the freshness window.                                                             |
| `server_signing_key`   | server         | path                                   | Required when `server_auth = "signature"`. Dedicated host signing **private** key (OpenSSH or PEM), `0600`.                  |
| `ca_file`              | server         | path (PEM)                             | Required when `client_auth = "x509"`. Trusted CA that requester chains must reach.                                            |
| `client_required_oid`  | server         | OID string                             | Required when `client_auth = "x509"`. EKU OID the requester certificate must carry.                                           |
| `ssh_signing_key`      | client         | path                                   | Required when `client_auth = "ssh"`. Requester **private** key, `0600`.                                                       |
| `client_cert`          | client         | path (PEM)                             | Required when `client_auth = "x509"`. Requester certificate chain.                                                            |
| `client_key`           | client         | path                                   | Required when `client_auth = "x509"`. Requester private key; must match `client_cert`.                                        |
| `trusted_server_keys` | client         | keyring list                           | Required (non-empty) when `server_auth = "signature"`. Trusted host signing **public** keys.                                  |

Keyring entries (`trusted_server_keys`) may each be: an inline OpenSSH public-key
line (any entry containing a space is treated as one), a path to a file of
OpenSSH public-key lines, or a path to a directory of `*.pub` files. A bare
`SHA256:...` entry is **rejected** with an explicit error: a fingerprint cannot
verify a signature, and fingerprint pinning belongs in `[acl]`.

> **`[security].trusted_keys` does not authorize.** The key still exists and
> parses (and the Nix option is retained for source compatibility), but the server
> no longer reads it and it is no longer emitted. Authorization moved to
> `[acl].trusted_keys` (fingerprints, §8.5). Requester authentication now uses the
> `public_key` the client presents in the signed request, so the server needs no
> requester keyring at all.

> **There is no `signing_key_file` key.** The host signing key is
> `server_signing_key` and the requester key is `ssh_signing_key`; a config using
> `signing_key_file` is ignored. This is stated because the name has circulated in
> design notes.

The legacy `[mtls]` table (`enable`, `ca_file`, `cert_file`, `key_file`,
`required_oid`, `peer_required_oid`) is still parsed for the certificate material
and EKU checks; `enable = true` is equivalent to `transport_encryption = "mtls"`.
Under mTLS both `client_auth` and `server_auth` must be `"transport"`.

---

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

The ACL matches **only cryptographic material** — trusted public keys and
CA-signed certificates (and their fingerprints). It deliberately does **not**
match the transport, the destination, the socket path, the network address, or a
self-reported guest name (review log S11, §19.7). Those are metadata: they cross
transports badly and can be spoofed, so they are never an authorization input.

### 8.1 Modes

Server config `[acl]`:

| `mode`   | Meaning                                                                                                                |
| -------- | ---------------------------------------------------------------------------------------------------------------------- |
| `"ca"`   | Accept any requester credential that chains to a configured trusted CA and carries the service EKU OID.                |
| `"list"` | Accept only credentials whose fingerprint is explicitly listed (SSH-key fingerprint, or certificate SPKI fingerprint). |

### 8.2 What is matched

- **SSH key fingerprint** (`trusted_keys`, for `mode = "list"`) —
  `SHA256:...`, as produced by `ssh-keygen -lf`.
- **Certificate SPKI fingerprint**, or **CA chain + EKU** (for
  `mode = "ca"`) — `SHA256:...`.
- An optional **label** attached to a trusted credential, used only to name it in
  the dialog/log. It is not an authorization input and is never accepted from the
  requester.
- **Not matched:** `PAM_USER`, `PAM_RUSER`, `PAM_TTY`, `rhost`, socket path, IP,
  CID, or `guest_hint`.

### 8.3 Defaults and fail-closed

- Default is deny. Empty trust lists allow nobody; there is no wildcard shortcut.
- An unknown or unverifiable credential is rejected and logged, never prompted.
- A request that fails the ACL is answered with a `deny` (signed when
  `server_auth = "signature"`), or not answered — never silently ignored.

### 8.4 Worked examples

```toml
# Only these requester SSH keys may use the mechanism.
[acl]
mode = "list"
trusted_keys = ["SHA256:AbCdEf...=", "SHA256:GhIjKl...="]

# Any credential that chains to the tartarus CA with the client EKU.
[acl]
mode = "ca"
ca_file = "./ca.crt"
required_oid = "1.3.6.1.4.1.99999.1.2"
```

### 8.5 `[acl]` table as parsed

The server reads exactly these keys; the client never sees this table.

| Key                   | Mode      | Type / values                                        | Notes                                                                                                                          |
| --------------------- | --------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `mode`                | both      | `"list"` (default) \| `"ca"`                         | Exactly one mode; there is no `ca` + `list` combination. A missing table is a valid **deny-all** `"list"` policy.             |
| `trusted_keys`        | `list`    | list of `SHA256:...` SSH fingerprints                | SSH requesters allowed to use the mechanism; empty denies every SSH requester.                                                 |
| `trusted_fingerprints`| `list`, `ca` | list of `SHA256:...` X.509/mTLS SPKI fingerprints | In `list`, the allow-list for `x509`/`transport`. In `ca`, an **optional** additional leaf-SPKI pin on top of the CA chain.     |
| `ca_file`             | `ca`      | path (PEM)                                           | Trusted CA. Required in `ca`; forbidden in `list`. Resolved against the config directory.                                      |
| `required_oid`        | `ca`      | OID string                                           | EKU the requester certificate must carry. Required in `ca`; forbidden in `list`.                                               |
| `labels`              | both      | table: `SHA256:...` → string                         | Display/log label for a credential. **Not** an authorization input and never accepted from the requester.                      |

Validation rules (all fail closed, at startup):

- A fingerprint entry must start with `SHA256:` and decode to exactly 32 bytes;
  padding is accepted and normalised away.
- `mode = "ca"` requires `ca_file` and `required_oid`, forbids `trusted_keys`
  (no `ca` + `list`), and the CA file must be readable at load time.
- `mode = "list"` forbids `ca_file`/`required_oid` (use `mode = "ca"`).
- `mode = "ca"` cannot be combined with `client_auth = "ssh"` (SSH keys never
  chain to a CA), and SSH credentials are never authorized in `ca` mode.

> **mTLS chain limitation (audit A12).** Under `transport_encryption = "mtls"`,
> `acl.mode = "ca"` rebuilds the chain from the peer **leaf DER only**
> (`ssl` exposes the peer certificate, not the sent chain). A single-tier CA —
> the tartarus CA — validates correctly; a **multi-tier** mTLS CA would need its
> intermediate certificates passed to the ACL verifier. `ca.py` is single-tier
> today, so this is latent. Use `mode = "list"` (leaf SPKI pins) for a
> multi-tier mTLS deployment until the chain is plumbed through.

The Nix home-manager module exposes the same table as
`tartarus.sudo-auth-proxy.server.acl.{mode, trustedKeys, trustedFingerprints,
caFile, requiredOid}`; `labels` is currently only reachable through the
free-form `extraSettings`/`settings` escape hatch. The shipped host module
defaults the whole table to `mode = "ca"` with the tartarus CA and the sudo
client OID (audit A1), so a configured guest is authorized without an
operator-maintained fingerprint list.

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
  - _Decision authenticity_: `server_auth = "signature"` (or the mTLS channel)
    prevents a forged `allow`. A fake listener has no signing key and does not
    know the nonce. With `server_auth = "none"` this protection is absent and a
    same-uid fake listener could answer `allow` — which is why `"none"` is not
    recommended.
  - _Routing integrity_: the selector-only resolution (no fallback), socket
    ownership, and — on Linux — a post-connect `SO_PEERCRED` →
    `/proc/<peer_pid>/exe` check that the peer's executable is `sshd` and is
    root-owned but not peer-owned (so a same-UID read-only copy named `sshd` is
    rejected; audit A7) raise the bar against a same-uid attacker redirecting the
    client to a **different legitimate** tunnel. This is a path/ownership
    heuristic, not a kernel-attested process identity: misrouting is not forgery,
    a signature does not prevent it, and the same-UID selector race remains
    accepted as residual **R6** (bounded by the per-session token, R9). The
    peer-process check is Linux-only; macOS relies on socket-path integrity.
- **Residual risk:** when the **guest login account is shared** by several people,
  anyone with that UID can unlink/replace the socket in the `0700` directory
  (subject to the check above, which raises the bar but is not atomic). This is
  captured in §12.6 R6; the robust fix is per-person guest accounts.
- **No reuse proxy.** The historic `0666` proxy socket is gone with the proxy
  itself (§2.3); there is no second local socket to leak.
- Private keys: never `0644`. The requester signing key (`ssh` or `x509`) is
  `0600`, owned by the requester/login user. The per-guest/per-user X.509
  generation must stop emitting `0644` (review log F12). Users of the _same
  guest_ share that guest's requester identity unless per-user keys are
  provisioned; that is acceptable within a guest's trust domain, and per-person
  guest accounts are the full fix (§12.6 R6).

### 9.3 Attack surface and races

| Situation                                                      | Control                                                                                                                                                                                                       |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host process of another user connects to the server socket     | `0700` dir + `SO_PEERCRED` uid check.                                                                                                                                                                         |
| Host process of the _same_ user connects                       | It is the same approver at the OS level, but it must still present a trusted `client_auth` credential or the ACL rejects it; otherwise it can only cause a prompt, which is logged. No cross-user escalation. |
| Guest process races the tunnel listener                        | `server_auth = "signature"` (or mTLS) prevents forged allows; socket `lstat` + (Linux) `SO_PEERCRED`→`/proc/<pid>/exe` limits misrouting.                                                                     |
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
| `connect_timeout`  | `0.2 s` | transport `connect()` **and** the TLS handshake (every transport)           | *(not special)*  |
| `recv_timeout`     | `0.5 s` | the wait for the **first frame** (the `auth_pending` ack, or a direct deny) | *(not special)*  |
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
> (R6/R9/R11); it is **not** forgery — `server_auth = "signature"` or the mTLS
> channel still defeats a forged `allow`. Bounding the *total* exchange would
> re-couple the two bounds the sentinel deliberately separated; the residual is
> therefore accepted and named in §12.6 R14.

**What bounds the human wait (implementation).** With the ack in place the first
frame is *not* the human's answer: it is the sentinel the server sends before
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
> first response byte *was* the human's answer and therefore that `recv_timeout`
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
  re-entry if the variable ever were present) but a `sudo` run *from inside* an
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
    transportEncryption = "none";  # SSH already protects the channel
    serverAuth = "signature";      # default; client verifies every response
    clientAuth = "ssh";            # requester signs with a trusted SSH key
  };
};
```

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
permitted but insecure, so keep message signing enabled on such a transport.

---

## 11. Confirmation dialogs

### 11.1 Fields shown

The dialog should let the approver answer with context that is trustworthy:

- **Requester identity** — the verified credential (SSH key fingerprint, or
  certificate subject/SPKI, or mTLS CN) and its configured label.
- **Invoking user → target user** (e.g. `user → root`).
- **Service** (`sudo` / `su` / `login`).
- **TTY** (`/dev/pts/3`) and **rhost** if any.
- **Working directory**.
- **Request id** (short prefix of the nonce) and **timestamp/transport**.

The **command/argv is deliberately not shown** (review log S5, §19.7): it is
guest-controlled and spoofable, so it would be misleading, and it clutters the
UI. The request is bound to `service + user + tty + cwd + nonce` instead (§5.4).

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
  sandbox must account for the actual uid/euid.
- **A6** The selector (`SUDO_AUTH_PROXY_SOCK`) and the recursion guard
  (`SUDO_AUTH_PROXY_ACTIVE`) are delivered by `SetEnv`/`AcceptEnv` **and
  guaranteed by `sudoers env_keep` entries** (`Defaults env_keep +=
"SUDO_AUTH_PROXY_SOCK"` and `... "SUDO_AUTH_PROXY_ACTIVE"`, §4.3, §10.4). The
  selector is the **only** source; there is no `/proc` or static fallback. The
  multi-fragment `sudoers.d` shadowing risk is called out in §4.3 (review log
  C1).
- **A7** Private keys are protected per §7.8/§9.

### 12.5 Threats and mitigations

| #   | Threat                                                                                                                 | Adversary | Mitigation                                                                                                                                                                                |
| --- | ---------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | Forge an `allow` into the client                                                                                       | ADV1      | `server_auth = "signature"` (or mTLS); client verifies signature + nonce + request digest. (§7.2, §6.6)                                                                                   |
| T2  | Replay an old `allow`                                                                                                  | ADV1      | Client **single-use nonce** + request digest + expiry; no server-side cache needed. (§6.6)                                                                                                |
| T3  | Change request fields between approval and execution                                                                   | ADV1/ADV2 | `request_digest` computed and covered by both signatures; mismatch rejected. (§6.4)                                                                                                       |
| T4  | Guest/user B impersonates A                                                                                            | ADV2      | `client_auth` credential verified against the server's trust roots; the single socket carries no identity. **Caveat A4:** the service EKU OIDs do not isolate services today — a guest's tartarus client certificate is valid for every tartarus service (§7.6). (§7.3, §8) |
| T5  | Person B receives/answers person A's prompt (different host users)                                                     | ADV3      | Per-host-user server and single socket in the owner's runtime dir; `SO_PEERCRED` uid check. (§4.2, §9.1)                                                                                  |
| T6  | Person B receives person A's prompt (same guest account, different host users)                                         | ADV3      | Per-session guest bind path + `SUDO_AUTH_PROXY_SOCK` (guaranteed by `sudoers env_keep`) selects the session owner. Same-UID redirection remains R6; multiplexer caveat §4.6.              |
| T7  | A non-whitelisted requester triggers elevation                                                                         | ADV1      | Cryptographic ACL evaluated before the dialog, default deny. (§8)                                                                                                                         |
| T8  | Network attacker MITM on a callback transport                                                                          | ADV4      | `tcp` defaults to mTLS (EKU + CA), `vsock` optional; `tcp` + `none` is allowed but leaves confidentiality to the network — message signatures still prevent forgery or alteration. (§7.4) |
| T9  | Socket pre-creation / listener race in the guest                                                                       | ADV1      | Server authentication defeats forgery; selector-only resolution (no fallback) plus `lstat`/peer-process check (`sshd`, root-owned, not peer-owned — audit A7) limit redirection. Redirection to a real tunnel remains R6. (§9.2) |
| T10 | Another local host process connects to the single server socket                                                        | ADV3      | `0700` dir, `0600` socket, `SO_PEERCRED` uid check, **and** it must still present a trusted credential (§8). (§9.1)                                                                       |
| T11 | Dialog flood                                                                                                           | ADV1/ADV5 | Only credentialed requesters reach a dialog; a process-global lock shows one dialog at a time (A13); deny is explicit. No anti-fatigue state. Pre-auth availability residual R14 (audit N3). (§11.3, §10.2) |
| T12 | Injection into the dialog / spoofed text                                                                               | ADV1      | Sanitisation (allow-list + NFC) per backend, length caps, no markup. (§11.2)                                                                                                              |
| T13 | Private key exposure enables impersonation                                                                             | ADV1      | No `0644` keys; requester key `0600`; fix `ca.py` generation. (§7.8, §9.2)                                                                                                                |
| T14 | CA/signing-key compromise                                                                                              | ADV6      | Rotation tooling, keyring, short-lived certs; known-but-unprocessed critical X.509 extensions are accepted residual R15 (audit N4); TPM/HSM future work. (§7.8) |
| T15 | DoS: make the tunnel unavailable to force fallback                                                                     | ADV1      | Fallback is by design; document that the proxy is not a sole factor unless other auth is disabled. The TLS handshake now runs off the accept loop (A3/N2) and the ack-stall residual is R14. (§10.2, §10.3) |
| T16 | Cross-session decision reuse                                                                                           | ADV1      | Decision bound to nonce + request digest (includes tty); client single-use. (§6.6)                                                                                                        |
| T17 | Secret leakage via the dialog/logs                                                                                     | ADV1/ADV5 | The command is never shown or logged; fields sanitised before logging; never log raw bytes. (§11.1, §11.2)                                                                                |
| T18 | Recursive/stacked prompts confuse the approver                                                                         | ADV5      | **Partial (A5):** the helper checks `SUDO_AUTH_PROXY_ACTIVE` on entry, but the variable is set only in the helper process and cannot propagate into the elevated shell, so a `sudo` *inside* an elevated session re-prompts. The service is shown in the dialog. (§10.4) |
| T19 | Stale socket/ownership tricks                                                                                          | ADV1      | `lstat` + ownership/symlink checks + unlink before bind; receive timeout bound. (§9, §10.2)                                                                                               |
| T20 | Downgrade to an unsigned or legacy protocol                                                                            | ADV4      | No legacy protocol and no auto-detection; no insecure fallback; mTLS config refuses plaintext. (§6.1, §7.5, §4.3)                                                                         |
| T21 | Same guest UID redirects the client socket to **another person's legitimate tunnel** (valid signature, wrong approver) | ADV1      | `lstat`/no-symlink; Linux `SO_PEERCRED`→`/proc/<pid>/exe` = `sshd`, root-owned and not peer-owned (A7); **residual R6**; per-person guest accounts is the full fix. (§9.2) |
| T22 | `sudo` strips the selector env var → request lands on a shared/wrong socket                                            | ADV1/ADV3 | Mandatory `sudoers env_keep += "SUDO_AUTH_PROXY_SOCK"`; selector is the only source; otherwise fast-fail. (§4.3)                                                                          |
| T23 | Rogue signing/trust root substituted via build/supply chain                                                            | ADV6      | Distributed like `ca.crt`; treat as CA-sensitive for build-input review; keyring + rotation. (§7.8)                                                                                       |
| T24 | Stale guest socket after a crashed session → silent degradation / spoof target                                         | ADV1      | **No explicit teardown hook (A8):** `sshd` removes its own forward on session close and `StreamLocalBindUnlink` handles a same-name re-bind; a stale path is never reused (per-session token) and the first-frame receive timeout bounds a bound-but-unlistened read. (§4.3, §9.2) |
| T25 | **macOS** peer verification is weaker: no `/proc`, and `getpeereid` returns only uid/gid (no pid)                      | ADV1      | Linux peer-process check unavailable; rely on socket-path integrity/ownership, the random path token (NF7), and server authentication. Accepted residual **R11**. (§9.2, §12.6)           |
| T26 | A fake server answers on a `server_auth = "none"` socket                                                               | ADV1      | **Not mitigated**; `"none"` is not recommended and is strongly discouraged on `tcp`. (§7.2, §12.6 R13)                                                                                    |
| T27 | A same-uid host process connects to the single server socket and generates prompts                                     | ADV3      | It must present a trusted `client_auth` credential or the ACL rejects it; otherwise it can only cause a (logged) prompt. No cross-user escalation. (§8, §9.1)                             |
| T28 | A multiplexer pins a stale/foreign selector                                                                            | ADV3      | Selector-only resolution + fail-closed + cryptographic request binding; per-person guest accounts are the full fix. Accepted residual **R12**. (§4.6)                                     |

### 12.6 Residual risks (accepted)

- **R1** Two people sharing one **host** Unix account are one principal (§5.6).
- **R2** A compromised guest **root** can do anything within the guest, including
  reading the requester signing key; server authentication still prevents it from
  fabricating an `allow`, but it can consume approvals and act after a legitimate
  one (it _is_ the principal whose credential it holds).
- **R3** Fallback to other PAM methods means the proxy is not a sole gate unless
  other auth is disabled (§10.3).
- **R4** `pam_exec` cannot distinguish `deny` from `unavailable` via exit codes
  (§6.7).
- **R5** The approver's machine or the trust roots being compromised defeats the
  model (out of scope; §5.5/§12.5 T14).
- **R6** **Socket misrouting with a shared guest login account.** A process with
  the shared guest UID can point its own socket path at another person's
  legitimate tunnel (unlink/symlink), causing a _valid, correctly signed_
  approval to be issued by the wrong approver. The signature proves authenticity,
  not _which_ tunnel the request traveled; path checks and the Linux
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
  the random path token, and server authentication (§9.2, §12.5 T25).
- **R12** **Multiplexer selector staleness.** A multiplexer server carries the
  selector of the SSH session that started it, so a later attach can route to a
  different approver on a shared guest account. The client fails closed rather
  than guessing, and requests remain cryptographically bound; per-person guest
  accounts are the full fix (§4.6).
- **R13** **`server_auth = "none"`.** On a socket a same-uid process can replace
  (or any transport that is not integrity-protected), a fake server can answer
  `allow`. `"none"` is not recommended and is strongly discouraged on `tcp`
  (§7.2).
- **R14** **Pre-dialog ack stall (audit N3).** The unauthenticated `auth_pending`
  sentinel can be echoed by any peer that reaches the socket and then followed by
  silence, holding the client for the full `decision_timeout` (default 120 s)
  instead of the short `recv_timeout`. This is a local approval-delay
  denial-of-service, not forgery (`server_auth = "signature"` / mTLS still defeat
  a forged `allow`); it is the accepted cost of separating the first-frame bound
  from the human wait (§6.2a, §10.2). Reachability is bounded by R6/R9/R11.
- **R15** **Known-but-unprocessed critical X.509 extensions (audit N4).** The
  chain verifier rejects an *unknown* critical extension (audit A6) but ignores
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
| Fake/forged allow suspected                 | `server_auth` is `"none"` or the client did not verify          | Set `server_auth = "signature"` (or mTLS); check the client rejects unsigned/unknown responses (§7.2).          |
| Request rejected as unauthorized            | Credential not trusted                                          | Add the SSH fingerprint to `[acl].trusted_keys` (or the cert/SPKI to `trusted_fingerprints`), or the CA/EKU for `mode = "ca"` (§8.5). |
| Plaintext-`tcp` warning                     | `transport_encryption = "none"` on `tcp`                        | Expected on a trusted network; prefer mTLS. Message signing still authenticates the request/response (§7.4).    |

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

### 14.3 Configuration

- `transport` gains `"unix"` alongside `"vsock"`/`"tcp"`.
- The `[security]` model (`transport_encryption`, `server_auth`, `client_auth`)
  replaces the loose `mtls`/`protocol` options. `mtls.enable = true` is still
  accepted as `transport_encryption = "mtls"`. A `tcp` config defaults to `mtls`
  (recommended); `none` is accepted explicitly but **insecure** and emits a
  warning. `server_auth = "none"` is accepted but not recommended and is strongly
  discouraged on `tcp` (§7.2, §7.4, §7.5).
- New keys: the `[acl]` authorization table (§8.5), `server_signing_key`,
  `ssh_signing_key`, `ca_file`, `client_required_oid`, `trusted_server_keys`,
  `socket`, `socket_dir_mode`, `socket_mode`, `recv_timeout`, `response_ttl`,
  `clock_skew` (§7.9, §8.5).
- **`trustedKeys` no longer authorizes.** `[security].trustedKeys` is parsed for
  source compatibility but is not read by the server and is no longer emitted.
  Requester authorization moved to `[acl].trusted_keys` **as `SHA256:...`
  fingerprints** (not public keys). Requester authentication now uses the
  `public_key` the client presents in the signed request, so the server needs no
  requester keyring. Migrate each old entry to the fingerprint `ssh-keygen -lf`
  prints.
- The guest config directory mode changed from `0755` to `0750 root <group>`
  (§9.2); the guest module sets the group to the guest login group.

### 14.4 Keys, sockets and the guest

- A dedicated host signing key (`[security].server_signing_key`) is the default
  for `server_auth = "signature"`; distribute its public key to clients via the
  `[security].trusted_server_keys` keyring. The X.509 CA and mTLS still work,
  now as `transport_encryption = "mtls"`.
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
  to `unix`, keep `transport_encryption = "none"`, set `client_auth = "ssh"` or
  `"x509"`, and rebuild. Verify with a test `sudo` while logged in (§15.3).

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
  (`trusted_keys`, `trusted_fingerprints`, `ca_file`, `required_oid`).
- The Python enforces the **XOR** between the two knobs: `client_auth = "none"`
  with a non-`none` ACL raises, and `acl.mode = "none"` with a non-`none`
  `client_auth` raises. Disabling auth is therefore always a conscious choice on
  both sides.

The shipped tartarus guest/host default for the callback transport
(`vsock`/`tcp`) is now `transport_encryption = "none"`, `client_auth = "none"`,
`server_auth = "none"`, `[acl] mode = "none"`: the MicroVM channel is private by
construction and runs with no crypto. `server_auth = "none"` was already
supported and warns accordingly.

### 14.8 SSH-agent requester signing (`client_auth = "ssh"`)

With `client_auth = "ssh"` the requester may sign the canonical request through
a running SSH agent instead of a private-key file. Under `[security]`:

- `ssh_agent = true` selects agent signing (`ssh_signing_key` still wins when
  both are set).
- `ssh_agent_socket` overrides the agent path; otherwise `$SSH_AUTH_SOCK` is
  used, and if neither is present the client refuses to start.
- `ssh_key` (required in agent mode) is the OpenSSH **public** key naming the
  identity to use; the agent identity is selected by that key's `SHA256:`
  fingerprint, so a different loaded key can never be substituted.

RSA identities are asked for `rsa-sha2-256`; an agent answering with the SHA-1
`ssh-rsa` algorithm is refused. The private key never enters the client process.
On the host-side PAM client the agent socket is reached through the
`SSH_AUTH_SOCK` kept by `security.sudo.extraConfig` (see §15.1).

### 14.9 A second server instance (`extraServer`)

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

1. Ensure the host's SSH config reaches the guest (existing tartarus setup).
2. Enable the server, the signing key, and the trust roots: the host signing
   `server_signing_key`, the client-side `trusted_server_keys` keyring, and the
   `[acl]` (`trusted_keys` fingerprints, or the X.509 CA for `x509`/mTLS).
   **The shipped tartarus host module derives all of this (audit A1):**
   `nix/host/services.nix` emits a usable `[acl]` (`mode = "ca"` with the
   tartarus CA + the sudo client OID), selects one server transport from the
   guests' `services.sudoAuthProxyTransport` markers (mixing transports across
   the guests of one host is an evaluation error), and, on the `unix` path,
   defaults `serverSigningKey` to `~/.ssh/tartarus`. Set these options by hand
   only when not using the tartarus host module.
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
5. Set the security knobs (§7.5): for `unix`, `transport_encryption = "none"`,
   `server_auth = "signature"`, and `client_auth = "x509"` (the guest presents
   its tartarus client certificate) or `"ssh"`; for a callback transport the
   defaults force mTLS.
6. Set the timeouts for interactive use (§10.2/§10.5): `recvTimeout` bounds the
   `auth_pending` ack (the shipped `0.5` is fine) and `decisionTimeout` is the
   human window (`120` by default; `0` waits); `connectTimeout` small
   (default `0.2`).

### 15.2 Guest

1. Set `transport = "unix"` (or keep a callback transport) and the matching
   `[security]` values.
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
4. Provision the requester signing key (`ssh` key or `x509` cert/key) `0600` and
   register its trust root on the host: its `SHA256:` fingerprint in
   `[acl].trusted_keys` (SSH), or the CA + EKU for `x509`/mTLS. The client needs
   the host signing public key in `[security].trusted_server_keys`. Setting
   `services.sudoAuthProxyTransport = "unix"` makes the tartarus guest module
   wire the `x509` client and read the host signing public key automatically
   (audit A1).
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
| Requester signing key (`ssh_signing_key` / `client_key`) | `0600`, owned by the requester/login user      | §7.8, §9.2 |
| Host signing key (`server_signing_key`) | `0600`, owned by the server user                             | §7.8      |

---

## 16. Audit and hardening checklist

**Identity & auth**

- [ ] Exactly one listening socket per transport; no per-guest server socket.
- [ ] `tcp` + `none` is warned as insecure (no confidentiality) and still uses message signing.
- [ ] `transport_encryption = "mtls"` ⇒ **both** `client_auth` and `server_auth` are `"transport"` and nothing is layered on top (no SSH/ssh-agent signature).
- [ ] `client_auth` is one of `ssh`/`x509` (never both) when the transport is not mTLS.
- [ ] ACL matches only credentials (key/SPKI fingerprints), never metadata.
- [ ] ACL is evaluated before any dialog; default deny.
- [ ] Requester credential verified against root-owned trust roots (not `authorized_keys`); SSH identity is the fingerprint recomputed from the signed `public_key` and matched to `key_id`.
- [ ] Host user verified via `SO_PEERCRED`/`getpeereid`.

**Decisions**

- [ ] `server_auth = "signature"` ⇒ response signature verified; nonce and request digest bound.
- [ ] No path where an unsigned decision is accepted when `server_auth = "signature"`.
- [ ] Expiry enforced; the client rejects any second response for a nonce.
- [ ] Domain separation label `tartarus/sudo-auth-proxy/v1` present.
- [ ] `alg`/`key_id` present in the auth block; unknown/absent `alg` rejected; the `alg` allow-list excludes `ssh-rsa`.
- [ ] `request_digest` is the lowercase-hex SHA-256 and is recomputed and compared.

**Sockets/files**

- [ ] Directories `0700` (host runtime dir, guest `/run/sudo-auth-proxy` owned by the login user), sockets `0600`.
- [ ] Ownership/symlink checks; stale socket handling.
- [ ] No world-readable private keys; requester key `0600`; `ca.py` fixed.
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
- TPM/HSM-backed host signing key.
- Two-person approval and command allow/deny policies (reuse the
  `ssh-agent-proxy` rule engine).
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
| **Request digest**                    | SHA-256 over the canonical request, signed back by the server.          |
| **Server authentication**             | How the client verifies the server (`server_auth`, §7.2).               |
| **Client / requester authentication** | How the server verifies who is asking (`client_auth`, §7.3).            |
| **Transport encryption**              | Whether the byte stream is encrypted (`transport_encryption`, §7.4).    |
| **Domain separation**                 | The `tartarus/sudo-auth-proxy/v1` label prepended to signed data.       |
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
| Rank 6  | Signing public key distribution inherits Nix-store trust.                                                            | §7.4 now calls this out explicitly.                                                                                                                   |

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
| NF2 | Dialog fields (especially swiftDialog markdown) can be injected; the current code interpolates `{peer}` unescaped (`sources/sudo-auth-proxy.py:179`). | §11.2 defines NFC normalisation plus an allow-list `[A-Za-z0-9_.:/@-]` for every attacker-influenced field, with swiftDialog `* [ ] ( )` escaping.                  |
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

# clipboard-bridge — Architecture, Configuration & Security Model

This document is the **source of truth** for `clipboard-bridge` as it is
configured and run in `nix/packages/clipboard-bridge/`. It follows the same
model as [`ssh-agent-proxy.md`](./ssh-agent-proxy.md) and
[`sudo-auth-proxy.md`](./sudo-auth-proxy.md): **one server process binds N
self-contained listeners**, every listener carries its own transport, security,
mTLS material and identity resolution, and clients keep a single transport.
There is **no shared secret anywhere**: a peer is authenticated by mTLS or by
the same-user Unix boundary (a `none` callback listener relies on the transport
being private by construction), and authorization is the ordered `[[rule]]`
list.

The implementation plan is
[`design/clipboard-bridge-parity.md`](./design/clipboard-bridge-parity.md).

## Table of contents

1. [Purpose and architecture](#1-purpose-and-architecture)
2. [Server configuration](#2-server-configuration)
3. [Listeners](#3-listeners)
4. [Security, mTLS and resolution](#4-security-mtls-and-resolution)
5. [Admin listeners and rules](#5-admin-listeners-and-rules)
6. [Client and admin client configuration](#6-client-and-admin-client-configuration)
7. [Default tartarus host wiring](#7-default-tartarus-host-wiring)
8. [Security model](#8-security-model)
9. [Protocol actions](#9-protocol-actions)
10. [CLI usage](#10-cli-usage)
11. [Verification and tests](#11-verification-and-tests)
12. [Removed configuration](#12-removed-configuration)
13. [Glossary](#13-glossary)

---

## 1. Purpose and architecture

`clipboard-bridge` moves clipboard content between a host and its guests (VMs,
containers, remote machines) and exposes the host's view of every connected
guest to a local **admin** CLI.

One server process owns one clipboard store and binds **every** entry in
`[[listeners]]`:

```
guest (VM)        ──vsock/tcp──▶  listener "tartarus-vsock"  ─┐
guest (container) ──tcp/mTLS───▶  listener "tartarus-tcp-*"   ─┼─▶ one clipboard store
admin CLI         ──unix───────▶  listener "admin" (admin)    ─┘
```

Three properties define the model:

- **Listeners are self-contained.** A `[[listeners]]` entry carries its own
  bind target, `[listeners.security]`, optional `[listeners.mtls]`,
  `resolution`, socket modes and bounds. Nothing is inherited from a document
  level and there is no `[listener_defaults]` block.
- **Clients dial exactly one transport.** A guest client (or the local admin
  client) has one `transport` and one `[security]` block; it never enumerates
  listeners.
- **Guest and admin are distinct listener roles.** A listener marked
  `admin = true` serves the control plane (`clients`, targeted `get`/`set`,
  `--json`); every other listener is a guest listener and serves only the
  guest actions (`set`/`get` on the caller's own slot, `register`,
  `subscribe`). A connection cannot change roles: the role is the listener's.

Binding is **all-or-nothing**: every listener is bound, and every per-listener
SSL context built, before any of them serves. A bind or TLS failure exits
non-zero and no listener serves. Runtime failures stay per listener.

---

## 2. Server configuration

### 2.1 Full document

This is the target server shape (the full reference document); CIDs, IPs and
names are host-specific:

```toml
mode = "server"

[[vm]]
cid = 7
name = "dev"

[[tcp_vm]]
ip = "10.201.0.10"
name = "notes"

[[listeners]]
type = "vsock"
name = "tartarus-vsock"
cid = 2
port = 27795
resolution = "tartarus"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "tcp"
name = "tartarus-tcp"
host = "10.201.0.1"
port = 27795
resolution = "tartarus"

[listeners.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[listeners.mtls]
enable = true
ca_file = "..."
cert_file = "..."
key_file = "..."
required_oid = "1.3.6.1.4.1.99999.3.1"
peer_required_oid = "1.3.6.1.4.1.99999.3.2"

[[listeners]]
type = "unix"
name = "admin"
socket = "%t/clipboard-bridge-admin.sock"
admin = true
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[rule]]
match.listeners = ["admin"]
policy = "allow"
```

`mode = "server"` is required. A server **must** have a non-empty
`[[listeners]]` array; the flat form described in §12 is rejected.

### 2.2 Global keys

Only these keys are global; everything else belongs to a listener or a rule:

| Key | Meaning |
| --- | --- |
| `mode` | `"server"`. |
| `[[vm]]` | `cid` → `name` map used by `resolution = "tartarus"` for VSOCK peers. |
| `[[tcp_vm]]` | `ip` → `name` map used by `resolution = "tartarus"` for TCP peers. |
| `[[listeners]]` | The listeners this process binds (§3). |
| `[[rule]]` | The ordered authorization rules (§5.2). |

`[[vm]]`/`[[tcp_vm]]` are the maps `resolution = "tartarus"` reads: a VSOCK
peer is named by CID, a TCP peer by IP. A server with a `vsock`/`tcp` listener
carries the maps for the guests it can name; a `unix`-only server can omit them.

---

## 3. Listeners

### 3.1 Fields

| Key | Applies to | Meaning |
| --- | --- | --- |
| `type` | all | `"vsock"`, `"tcp"` or `"unix"`. Required. |
| `name` | all | Optional label, unique across the server. Used by `match.listeners`; it never affects the bind target or identity. |
| `cid` | `vsock` | Local CID to bind (the host side is `2`). |
| `port` | `vsock`, `tcp` | Port to bind. |
| `host` | `tcp` | Address to bind. |
| `socket` | `unix` | Socket path; `%t` expands to the per-user runtime directory. |
| `socket_dir_mode` | `unix` | Mode of the created parent directory (default `0700`). |
| `socket_mode` | `unix` | Mode of the socket itself (default `0600`). |
| `admin` | all | Mark the listener as an admin/control-plane listener (§5.1). Default `false`. |
| `resolution` | all | How the peer is named (§4.3). |
| `connect_timeout` | all | Bound on accepting/connecting before the request is read. |
| `handshake_timeout` | all | Bound on the TLS handshake when the listener is mTLS. |
| `max_connections` | all | Maximum concurrently served connections for **this** listener. |
| `server_read_timeout` | all | Bound on reading a request frame. |
| `[listeners.security]` | all | Per-listener security (§4.1). |
| `[listeners.mtls]` | mTLS listeners | Per-listener certificate material (§4.2). |

Every bounded field falls back to the module's built-in default when omitted;
the shipped host wiring sets the bind target explicitly and leaves the bounds
at their defaults.

### 3.2 Self-containment rules

- No document-level `[listeners.security]` inheritance, no shared defaults, no
  `[listener_defaults]` table. An unknown key in a listener is rejected.
- Multiple listeners of the same `type` are allowed (for example two `unix`
  listeners with different sockets and different security).
- Listener `name`s must be unique; duplicate socket paths are a runtime bind
  error, not a schema error.
- `socket_dir_mode`/`socket_mode` are applied when the socket directory and
  socket are created: the parent is `0700`, the socket `0600`, by default.
- A listener that is not `admin` is a **guest** listener. The role is fixed at
  configuration time, not negotiated.

---

## 4. Security, mTLS and resolution

### 4.1 `[listeners.security]`

```toml
[listeners.security]
transport_encryption = "none"   # auto | none | mtls
client_auth = "none"            # transport | none
server_auth = "none"            # transport | none
```

`transport_encryption` selects the channel protection:

| Value | Resolution |
| --- | --- |
| `auto` | `tcp` → `mtls`; `vsock` → `none`; `unix` → `none` |
| `none` | No channel crypto. Requires `client_auth = server_auth = "none"`. |
| `mtls` | TLS on any transport, including `unix`. Forces both auth knobs to `transport`. |

Rules, asserted at evaluation and re-validated at load:

- `transport_encryption = "none"` is accepted only with **both** `client_auth`
  and `server_auth` set to `"none"`; those two auth knobs must be explicit.
  `transport_encryption` itself may be `"auto"` or omitted as long as the
  resolved transport is `none` (the two auth knobs still gate it).
- `client_auth = "transport"` or `server_auth = "transport"` without mTLS is
  rejected (there is no transport credential to check).
- mTLS never falls back to plaintext. The SSL context is built from the
  **resolved** `transport_encryption`, never from `mtls.enable` alone.
- The `auto` resolution is a default, not a downgrade: a `tcp` listener that
  omits the block still gets `mtls`.

### 4.2 `[listeners.mtls]`

```toml
[listeners.mtls]
enable = true
ca_file = "/etc/tartarus/x509/ca.crt"
cert_file = "/etc/tartarus/x509/host.crt"
key_file = "/etc/tartarus/x509/host.key"
required_oid = "1.3.6.1.4.1.99999.3.1"       # our own certificate's EKU
peer_required_oid = "1.3.6.1.4.1.99999.3.2"  # the peer certificate's EKU
```

- The peer certificate must chain to `ca_file` **and** carry
  `peer_required_oid`; a chain-valid certificate with the wrong EKU is
  rejected.
- Relative paths are resolved against the configuration file's directory.
- A listener whose resolved transport encryption is `mtls` needs this block
  (and an admin mTLS listener needs the admin peer OID, §5.3).

### 4.2a `pubkey` (no CA): self-signed certificate pinning

The CA is optional. Each side can present a **self-signed** leaf and whitelist
the peer's leaf; the trust anchor is the peer certificate itself, so there is no
CA key. The Nix modules expose this as `pubkey`, mutually exclusive with `mtls`,
on every server listener and on the client / admin client:

```nix
# server listener
{ type = "tcp"; host = "10.201.0.1"; port = 27795;
  resolution = "certificate";
  pubkey = {
    certFile = ./server.crt;
    keyFile = "/etc/clipboard-bridge/server.key";
    trustedPeerCerts = [ ./guest.crt ];   # one or more peer certs
    # requiredOid / peerOid default to 3.1 / 3.2 for the server role
  };
}

# guest client
tartarus.clipboard-bridge.client = {
  enable = true; transport = "tcp"; host = "10.201.0.1";
  pubkey = {
    certFile = ./client.crt;
    keyFile = "/etc/clipboard-bridge/client.key";
    trustedPeerCerts = [ ./athena.crt ];
    # requiredOid / peerOid default to 3.2 / 3.1 for the client role
  };
};

# admin client: requiredOid defaults to 3.3 (the admin EKU),
# peerOid to 3.1 (the server EKU)
tartarus.clipboard-bridge.adminClient = {
  enable = true; transport = "tcp"; host = "127.0.0.1";
  pubkey = {
    certFile = ./admin.crt;
    keyFile = "/etc/clipboard-bridge/admin.key";
    trustedPeerCerts = [ ./athena.crt ];
  };
};
```

Setting `pubkey` forces the effective transport to mTLS and both auth knobs to
`"transport"`, exactly like `mtls.enable`. The emitted TOML still uses the
internal `[listeners.mtls]` / `[mtls]` tables, but `ca_file` is now a Nix-built
concatenation of `trustedPeerCerts` (the whitelist; a world-readable store
file), not a CA. `pubkey` + `mtls`
on one listener/client, or an empty/missing `trustedPeerCerts`, fails
evaluation. An admin client still pins `required_oid` to the admin EKU, and an
admin listener still requires `peer_required_oid = …3.3`.

Mint the material (no CA is created) with:

```sh
# server
tartarus-certs selfsigned --role server --cn athena \
  --service clipboard-bridge \
  --key /etc/clipboard-bridge/server.key \
  --cert /etc/clipboard-bridge/server.crt \
  --pub /etc/clipboard-bridge/server.pub

# guest client
tartarus-certs selfsigned --role client --cn guest \
  --service clipboard-bridge \
  --key /etc/clipboard-bridge/client.key \
  --cert /etc/clipboard-bridge/client.crt \
  --pub /etc/clipboard-bridge/client.pub

# admin client
tartarus-certs selfsigned --role client --cn admin \
  --service clipboard-admin \
  --key /etc/clipboard-bridge/admin.key \
  --cert /etc/clipboard-bridge/admin.crt \
  --pub /etc/clipboard-bridge/admin.pub
```

The certificate must carry the standard EKU **plus** the service OID
(`serverAuth,<server OID>` / `clientAuth,<client OID>`), `basicConstraints =
critical,CA:FALSE`, `keyUsage = critical,digitalSignature,keyEncipherment` (RSA),
and `subjectAltName = DNS:<name>` on the server. Without the standard EKU the
self-signed leaf fails the handshake with `unsuitable certificate purpose`; the
`selfsigned` command always adds both. Keep private keys local (never in the
Nix store or git) and commit only the `.crt`/`.pub`.

### 4.3 `resolution`

`resolution` is per listener and is the only place a connecting peer becomes an
identity used by `match.machine`.

| Value | Identity | Valid on |
| --- | --- | --- |
| `none` | unset (`None`); only an **empty** `match.machine` selector matches — `["*"]` does not | all |
| `certificate` | verified mTLS peer certificate CN | all (requires mTLS) |
| `tartarus` | local VM bookkeeping by CID (`[[vm]]`) or IP (`[[tcp_vm]]`) | `vsock`, `tcp` |
| `mofos` | `mofos ls --json` lookup by CID / `ipv4_address` | `vsock`, `tcp` |

The clipboard-only `qemu` mode is **removed**; `tartarus`/`mofos` are rejected
on `unix` (there is no CID or IP to map). An unauthenticated admin identity is
`None`; `certificate`, `tartarus` and `mofos` all supply `match.machine`.

---

## 5. Admin listeners and rules

### 5.1 `admin = true`

A listener marked `admin = true` is a normal listener with a different
**role**:

- It accepts the admin actions `clients`, targeted `get`/`set` and `--json`
  (§9).
- It rejects the guest-only actions `register`/`subscribe`.
- Every request it receives is evaluated by the ordered `[[rule]]` engine
  (§5.2), using the listener's name and, when available, the resolved
  `machine`.

Unmarked listeners are guest listeners: they serve `set`/`get` on the caller's
own slot, `register` and `subscribe`, and reject every admin action.

The default admin listener is Unix, unencrypted and certificate-less. It is
authenticated by the filesystem/UID boundary (§8.1), not by a password and not
by a certificate. Certificate-auth admin is supported by configuring an mTLS
listener instead (§5.3); issuing that certificate is optional.

### 5.2 `[[rule]]`

```toml
[[rule]]
match.listeners = ["admin"]          # listener name patterns
match.machine = ["dev"]              # resolved identity patterns
match.action = ["get", "set"]        # protocol action names
match.target = ["*"]                 # admin target client ids
policy = "allow"                     # allow | deny
```

- Rules are evaluated in file order; **the first match wins** and fully defines
  the outcome. There is no merging and no fallthrough to a later rule.
- A selector that is omitted or empty matches every value; a selector is a list
  of `fnmatch` patterns.
- `policy` is `allow` or `deny`. There is **no `ask`**: clipboard has no
  approval dialog, so a request is either authorized or refused.
- **A request that matches no rule is denied.** The default is fail-closed.
- The host wiring ships one allow-all rule for the local admin listener
  (`match.listeners = ["admin"]`), so the default local admin path behaves as
  "allow everything". Guest listeners do **not** evaluate `[[rule]]` at all:
  they have a fixed guest policy (own-slot `set`/`get`, `register`,
  `subscribe`). Rules authorize admin listeners.

### 5.3 Certificate-auth admin listener

An admin listener may instead authenticate with mTLS. It must use the **admin**
EKU OID as `peer_required_oid` so a guest certificate cannot act as an admin:

```toml
[[listeners]]
type = "tcp"
name = "admin-tls"
host = "127.0.0.1"
port = 27796
admin = true
resolution = "certificate"

[listeners.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[listeners.mtls]
enable = true
ca_file = "..."
cert_file = "..."
key_file = "..."
required_oid = "1.3.6.1.4.1.99999.3.1"
peer_required_oid = "1.3.6.1.4.1.99999.3.3"  # admin client EKU

[[rule]]
match.listeners = ["admin-tls"]
match.machine = ["admin"]
match.action = ["clients", "get", "set"]
policy = "allow"
```

Issuing that certificate is optional because the default host admin path is
the local Unix socket (§11).

---

## 6. Client and admin client configuration

A client document names exactly one transport:

```toml
mode = "client"
transport = "unix"
socket = "%t/clipboard-bridge-admin.sock"

[security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
```

| Key | Meaning |
| --- | --- |
| `mode` | `"client"`. |
| `transport` | `vsock`, `tcp` or `unix` — one only. |
| `host`, `port`, `cid`, `socket` | Bind target for the chosen transport. |
| `[security]` | Same three knobs as a listener, for this one transport. |
| `[mtls]` | Optional; needed whenever the resolved transport encryption is mTLS, including over `unix`. Holds the client certificate and `peer_required_oid` for the server's EKU. |
| `[acl].trusted_fingerprints` | Pins the server leaf certificate's fingerprint (or a set). |
| `[acl].trusted_names` | Pins accepted server certificate names. |
| `register` | Advertise this client at startup so it appears in `clients`. |
| `proxy_socket` | Local socket for the connection-reuse proxy, when enabled. |
| `connect_timeout`, `handshake_timeout`, read bound | Bounds on dialing, the TLS handshake, and reading the reply. |

The `[acl]` is enforced **after** the TLS handshake: the client refuses a
server whose certificate does not match the pinned fingerprint/name. TLS over
Unix is supported when configured (mTLS on a `unix` listener/client is a
normal option); the default host wiring uses a plaintext Unix socket for the
admin socket, but `[mtls]`/`[acl]` are not TCP-only.

Guest clients use the same shape with their single callback transport:

- `vsock` → `transport = "vsock"`, `[security]` all `none`, no `[mtls]`.
- `tcp` → `transport = "tcp"`, `[security]` `mtls`/`transport`/`transport`,
  `[mtls]` with the guest client certificate
  (`peer_required_oid = "1.3.6.1.4.1.99999.3.1"`).

The admin client points at the admin Unix socket with all three security knobs
`none`: no password, no certificate, no TLS.

---

## 7. Default tartarus host wiring

`nix/host/services.nix` emits three listeners and one rule:

| Listener | Type | Bind | Security | Role |
| --- | --- | --- | --- | --- |
| `tartarus-vsock` | `vsock` | `cid = 2`, `port = 27795`, `resolution = "tartarus"` | `none` / `none` / `none` (`client_auth = "none"`) | guest (VMs) |
| `tartarus-tcp-<host>` | `tcp` | bridge address, `port = 27795`, `resolution = "tartarus"` | `mtls` / `transport` / `transport` | guest (containers) |
| `admin` | `unix` | `%t/clipboard-bridge-admin.sock`, `admin = true`, `resolution = "none"` | `none` / `none` / `none`, no TLS | admin |

- The VSOCK listener is the private-by-construction path: no crypto, no
  certificate, `client_auth = "none"`.
- The TCP listener is mTLS with the **guest** certificate: `required_oid` is
  the clipboard server OID and `peer_required_oid` is the guest client OID
  (`1.3.6.1.4.1.99999.3.2`). Its name is suffixed with the bind address
  (`tartarus-tcp-<host>`) because a host with both a `disableVsock` VM on the
  VM bridge and a container on the container bridge binds two TCP listeners,
  and listener names must be unique.
- The admin listener binds a same-user Unix socket: socket `0600`, parent
  directory `0700`, `resolution = "none"`, no TLS. It uses the listener's
  `admin = true` flag — there is no `admin_socket` option.
- The generated rules include the allow-all rule for that listener:
  `match.listeners = ["admin"]` → `policy = "allow"`.
- The host's `adminClient` points at the same socket with `transport = "unix"`
  and all security knobs `none`.

A mixed host therefore serves VSOCK VMs, mTLS TCP containers and the local
admin CLI from **one** server process, with one clipboard store.

---

## 8. Security model

### 8.1 The Unix admin socket

The default admin path is authenticated by the **same-user filesystem/UID
boundary**: the socket is `0600` inside a `0700` directory owned by the user
running the server, so only processes of that user can connect. This is
explicitly not a network authentication mechanism: any process running as that
user can already read and write the user's clipboard, so granting it the admin
CLI adds no authority it did not already have.

### 8.2 Callback listeners with `none`

`security = none` on a guest listener is safe only because the transport is
**private by construction** — VSOCK between a guest and its hypervisor, or the
container bridge/VMM boundary. Such a listener must be switched to mTLS if the
transport can be reached by an untrusted party. `none` is an explicit operator
decision, never a runtime fallback.

### 8.3 mTLS listeners

An mTLS listener authenticates both peers with the tartarus CA chain (or, in
no-CA `pubkey` mode, by pinning the peer's self-signed certificate — §4.2a)
plus EKU OIDs:

| OID | Role |
| --- | --- |
| `1.3.6.1.4.1.99999.3.1` | clipboard-bridge server certificate |
| `1.3.6.1.4.1.99999.3.2` | guest client certificate |
| `1.3.6.1.4.1.99999.3.3` | **admin** client certificate |

The admin OID isolates admin from guest certificates: an admin mTLS listener
requires `peer_required_oid = …3.3`, so a guest certificate (which carries
`…3.2`) cannot open an admin listener, and admin certificates must never be
issued to guests. A chain-valid peer with the wrong EKU is rejected before the
rule engine runs.

### 8.4 No shared secret

The old `secret` / `secret_file` model is **gone**, together with the generated
secret, the `secret` protocol field and the clipboard agenix secret. There is
no password path and no replayable bearer token: a peer is authorized by its
listener role (guest vs admin), by the certificate it can prove (mTLS
listeners), and by the ordered `[[rule]]` list. The local Unix admin socket
relies on the UID boundary described in §8.1.

### 8.5 Certificate admin tooling (optional)

Certificate-auth admin is **optional**: the default host admin path is the
local Unix socket (§8.1), which needs no certificate. Only an mTLS admin
listener (§5.3) needs admin certificate material.

Two equivalent tools mint it:

```bash
# through the tartarus CLI (uses the configured X509 CA directory)
tartarus ca admin

# standalone shell counterpart (no Nix, no tartarus)
tartarus-certs issue-admin --out DIR [--days N] [--bits N] [--force]
```

Both write the same layout under the X509 CA root:

```text
x509/machines/host/admin/client.crt   # 0644, CA-signed admin certificate
x509/machines/host/admin/client.key   # 0600, 2048-bit RSA private key
x509/machines/host/admin/ca.crt       # 0644, copy of the CA certificate
```

The admin certificate carries **only** `clientAuth` plus the admin EKU OID
`1.3.6.1.4.1.99999.3.3`. It never carries the guest client OIDs
(`…3.2`) or any server OID (`…3.1`), and guest certificates never carry the
admin OID. A certificate-auth admin listener therefore sets
`peer_required_oid = "1.3.6.1.4.1.99999.3.3"`, which rejects a guest
certificate even though both are signed by the same CA.

Both commands are idempotent: an existing key/cert is reused (unless
`--force`), a missing certificate is signed from the existing key, and the
private key mode is re-applied on every run.

For a **no-CA** deployment (§4.2a) mint a self-signed admin leaf instead; no CA
is created and the server/guest whitelist the admin certificate directly:

```sh
tartarus-certs selfsigned --role client --cn admin \
  --service clipboard-admin \
  --key /etc/clipboard-bridge/admin.key \
  --cert /etc/clipboard-bridge/admin.crt \
  --pub /etc/clipboard-bridge/admin.pub
```

---

## 9. Protocol actions

The wire protocol is newline-delimited JSON: one object per line carrying an
`action`, optional `data`, and the admin-only `target` / `json` fields. There
is no credential field.

| Action | Guest listener | Admin listener | Notes |
| --- | --- | --- | --- |
| `set` | yes — writes the caller's own slot | yes — requires `target` | A guest `set` with `target` is **denied**; it can only write its own slot. |
| `get` | yes — returns the caller's own slot | yes — requires `target` or `json` | `json = true` without `target` returns every client slot (base64) keyed by client id; with `target` it returns only that target. |
| `register` | yes | **no** | Advertises the guest at startup so it appears in `clients`. |
| `subscribe` | yes | **no** | Long-lived stream for host-initiated pushes. |
| `clients` | **no** | yes | Lists connected clients (`id`, `name`, `updated`). |

Admin semantics:

- `target` names another client's slot (a client id or a resolvable friendly
  name). It is meaningful only on an admin listener; a guest listener **denies**
  a request that carries it (or `json`) rather than ignoring it.
- `json` (admin `get`) is admin-only. Without `target` it returns every client
  slot in one response; with `target` it returns a one-entry map for the
  resolved target (or `{}` when the target has no slot), so a target-scoped rule
  cannot leak other clients.
- A friendly name is resolved against registered clients first, then the
  listener document's `[[vm]]`/`[[tcp_vm]]` maps, then used as a raw slot key.
  Direct ids (`vsock:…`, `tcp:…`, `unix:…`) are always exact matches.
- `target` is a `match.target` input for the rule engine, so an admin rule can
  allow `clients` while denying `set`, or restrict which targets may be
  written. `match.target` sees the requested string (a name or a direct id),
  not the id it resolves to; use one spelling consistently in rules and
  requests.
- A guest listener rejects every admin action with an authorization error; the
  error names the listener/rule decision, never a "secret mismatch".

---

## 10. CLI usage

Config files are selected automatically, so `-c` is only needed for a
non-default location:

| Command | Default file |
| --- | --- |
| `serve` | `~/.config/clipboard-bridge/server.toml` |
| `clients`, `push --target`, `pull --target`, `pull --json` | `~/.config/clipboard-bridge/admin.toml` |
| `push`, `pull`, `register`, `client`, `proxy` | `~/.config/clipboard-bridge/client.toml` |

If the preferred file is absent, the other client file is used. A host admin
command therefore works with only `admin.toml`, and a guest command works with
only `client.toml`, without spelling out `--config` anywhere.

Admin over the local Unix socket — no password, no certificate:

```bash
# list connected clients
clipboard-bridge clients

# read one client's clipboard, or all of them
clipboard-bridge pull --target dev
clipboard-bridge pull --json

# write to a specific client
echo "hello" | clipboard-bridge push --target dev
```

Guest push/pull over its single transport (`vsock` or `tcp`):

```bash
echo "hello" | clipboard-bridge push      # write the guest's own slot
clipboard-bridge pull --stdout            # read the guest's own slot
clipboard-bridge register                 # advertise at startup
```

Certificate-auth admin listener (optional; point `-c` at a client document
that selects the `admin-tls` transport and `[mtls]` block):

```bash
clipboard-bridge -c ~/.config/clipboard-bridge/admin-tls.toml clients
clipboard-bridge -c ~/.config/clipboard-bridge/admin-tls.toml pull --target dev
```

`serve` starts the server and binds every `[[listeners]]` entry:

```bash
clipboard-bridge serve
```

---

## 11. Verification and tests

| Area | Where |
| --- | --- |
| Config contract (listeners required, flat/`secret` rejected, per-listener security, admin rules, no-password behavior) | `tests/test_clipboard_bridge.py` |
| Host/guest wiring and TOML shape | `tests/suite.nix` eval fixtures, `tartarus-clipboard-bridge-toml-shape` |
| Certificate tooling | `tartarus ca admin` / `tartarus-certs issue-admin`, `OID_CLIPBOARD_ADMIN = "1.3.6.1.4.1.99999.3.3"` in `src/tartarus/ca.py` |

Commands (from `packages/tartarus.nix`):

```bash
python -m pytest tests/test_clipboard_bridge.py -v
nix eval --impure --file tests/default.nix --json
```

Runtime checks on a mixed host: `clients` over the Unix admin socket with no
password or certificate; `push`/`pull` from a container over TCP mTLS; from a
VM over VSOCK with no TLS; a certificate-admin listener accepting the admin
certificate and rejecting a guest certificate; and an old config carrying
`secret` or a flat server transport failing loudly.

---

## 12. Removed configuration

This is a hard break; none of the following has a compatibility shim, an alias
or a Python fallback.

| Removed | Replacement |
| --- | --- |
| Server `transport` / `host` / `port` | A `[[listeners]]` entry with `type` and its bind target. |
| `admin_socket` | A normal `[[listeners]]` entry with `admin = true`. |
| `secret`, `secret_file` | Nothing: authentication is mTLS or the same-user Unix boundary. |
| Global `mtls` | Per-listener `[listeners.mtls]`. |
| Global `resolution` | Per-listener `resolution`. |
| `resolution = "qemu"` | `none`, `certificate`, `tartarus` or `mofos`. |
| Clipboard agenix secret (`secrets/clipboard-bridge.age`) | Deleted. |

`load_config` rejects these keys by name and requires `[[listeners]]` on a
server; the Nix module no longer offers them, so a partially migrated
configuration fails loudly instead of silently binding the wrong thing.

---

## 13. Glossary

- **listener** — one bound socket (AF_UNIX path, AF_VSOCK port, or TCP
  `host:port`); one `[[listeners]]` entry. Self-contained and optionally named.
- **guest listener** — a listener without `admin = true`; serves guest actions
  only.
- **admin listener** — a listener with `admin = true`; serves the control plane
  and is evaluated by the rule engine.
- **self-contained** — a listener's fields are its own; omitting one falls back
  to the built-in default, never to a document-level value.
- **resolution** — how a connecting peer is turned into an identity.
- **rule** — an ordered `[[rule]]` entry matching `listeners`/`machine`/
  `action`/`target` with `allow`/`deny`; first match wins, default deny.
- **matching identity** — the `Optional[str]` used by `match.machine`; `None`
  when unauthenticated.

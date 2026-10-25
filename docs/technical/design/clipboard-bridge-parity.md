# Design: clipboard-bridge parity with the proxy services

Status: proposed · Scope: `packages/tartarus.nix` (the `tartarus` submodule)
Touches: `nix/packages/clipboard-bridge/*`, `nix/host/services.nix`,
`nix/guest/default.nix`, `tests/*`, `examples/*`, `docs/*`, `README.md`,
`src/tartarus/ca.py`, `src/tartarus/cli.py`, `scripts/tartarus-certs.sh`, and
nixcfg host/secret wiring.

This document is the implementation plan. It is intentionally breaking.

---

## 1. Goals

Make `clipboard-bridge` evolve to the same configuration and runtime model as
`ssh-agent-proxy` and `sudo-auth-proxy`:

- one server process binds **N self-contained listeners**;
- each listener has its own transport, security, mTLS material, resolution,
  socket modes, timeouts and pre-auth bounds;
- clients keep a single transport;
- guest clients and admin/control-plane clients are distinct listener roles;
- admin authorization is **certificate-based** when configured, never a shared
  password;
- the default tartarus host uses a same-user Unix admin socket with no
  certificate, and that socket's identity model is explicit.

### Non-goals

- No compatibility layer for the old flat server config.
- No `secret` / `secret_file` support anywhere.
- No separate server process (`extraServer`): multiple listeners in one process
  cover the use cases. A second process can be added later if a genuinely
  separate runtime directory/config is required.

---

## 2. Locked decisions

1. **Per-listener security.** Every `[[listeners]]` entry is self-contained:
   `type`, bind target, `security`, optional `[mtls]`, `resolution`, timeouts,
   and socket modes. There is no document-level `[listeners.security]`
   inheritance and no shared defaults block.
2. **Transport defaults mirror the other services.**
   `security.transportEncryption = "auto"` resolves to:
   - `tcp` → `mtls`
   - `vsock` → `none`
   - `unix` → `none`

   The tartarus host wiring makes the resolved values explicit in generated
   TOML.
3. **Client auth policy.**
   - Default tartarus VSOCK guest listener: `client_auth = "none"`.
   - Default tartarus TCP container listener: mTLS with the guest certificate.
   - Every listener can still be configured `none` or `mtls` independently.
4. **Admin transport.**
   - Default tartarus admin listener: `type = "unix"`, no TLS, no certificate.
   - It is a normal listener marked `admin = true`, not a separate
     `admin_socket` option.
   - Access is authorized by same-user Unix permissions: socket `0600`, parent
     directory `0700`.
   - Certificate-auth admin is supported by configuring an mTLS listener
     (`admin = true`, `security.clientAuth = "transport"`, `resolution =
     "certificate"`, admin EKU OID).
5. **Admin rules.**
   - Ordered `[[rule]]` entries, first match wins.
   - Match selectors: `listeners`, `machine`, `action`, `target`.
   - Policies: `allow` / `deny`. There is no `ask` because clipboard has no
     approval dialog.
   - No matching rule denies by default.
   - The host-generated config includes an allow-all rule for the local Unix
     admin listener, so the default local admin path behaves as “allow all”.
6. **Resolution is per listener.**
   Modes: `none`, `certificate`, `tartarus`, `mofos`. The clipboard-only `qemu`
   mode is removed. `tartarus`/`mofos` are rejected on `unix`.
7. **Hard break.**
   - Server `transport`/`host`/`port`, `admin_socket`, `secret`, `secret_file`,
     and global `mtls`/`resolution` are removed from both Nix and Python.
   - `load_config` rejects the old keys and requires `[[listeners]]` on a
     server.
   - The clipboard agenix secret is deleted.

---

## 3. Target configuration

### 3.1 Server

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

### 3.2 Certificate-auth admin listener

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

### 3.3 Client / admin client

```toml
mode = "client"
transport = "unix"
socket = "%t/clipboard-bridge-admin.sock"

[security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
```

Guest clients use the same shape with their single callback transport and, for
TCP, an `[mtls]` block.

---

## 4. Implementation phases

### Phase 0 — Contract and failing tests

- Add `docs/technical/clipboard-bridge.md` as the source of truth.
- Update `docs/technical/design/transport-listeners.md`:
  - clipboard has no legacy flat server fallback;
  - the admin Unix socket is a listener with `admin = true`, not `admin_socket`.
- Rewrite `tests/test_clipboard_bridge.py` around the new contract:
  - flat config and `secret` are rejected;
  - per-listener security resolution;
  - admin listener/rule authorization;
  - no-password behavior.
- Add eval fixtures in `tests/suite.nix` for the new host/guest shapes.

### Phase 1 — Python config and security foundation

Files: `nix/packages/clipboard-bridge/clipboard-bridge.py`

- Replace `listener_views` with strict parsing:
  - require `[[listeners]]`;
  - reject `admin_socket`, `secret`, `secret_file`, and legacy server
    `transport`/`host`/`port`;
  - validate unknown keys.
- Add shared helpers matching the other two services:
  - `resolve_listener_security`;
  - per-listener `[mtls]` loading;
  - client `[acl]` (`trusted_fingerprints`, `trusted_names`);
  - `mode` validation.
- Remove `generate_secret`, `get_client_secret`, and `check_admin`.
- Add listener bounds and socket options:
  - `connect_timeout`
  - `handshake_timeout`
  - `max_connections`
  - `server_read_timeout`
  - `socket_dir_mode`
  - `socket_mode`

### Phase 2 — Python server/client behavior

Files: `nix/packages/clipboard-bridge/clipboard-bridge.py`

- Build one SSL context per listener, including `unix + mtls`. Remove the
  unconditional “unix is never TLS” shortcut on both server and client.
- Bind all listeners all-or-nothing; create Unix socket directories with the
  configured modes.
- Add `admin = true` handling:
  - admin actions (`clients`, targeted `get`/`set`, `--json`) are allowed only
    on admin listeners;
  - `register`/`subscribe` are allowed only on guest listeners;
  - admin requests are evaluated by the ordered rule engine;
  - an unauthenticated admin identity is `None`; `certificate`, `tartarus`, and
    `mofos` supply `match.machine`.
- Add rule matching for `listeners`, `machine`, `action`, `target`.
- Enforce client `[acl]` server pinning after the TLS handshake.
- Change CLI errors from “secret mismatch” to “not authorized by
  listener/rule”.
- Keep `proxy` and `register` semantics, but remove secrets.

### Phase 3 — Nix module rewrite

Files: `nix/packages/clipboard-bridge/default.nix`

- Mirror `ssh-agent-proxy`/`sudo-auth-proxy` option builders:
  - `mkSecurityOptions`
  - `mkMtlsOptions`
  - `mkListenerOptions`
  - `mkClientOptions`
  - `mkAclOptions`
  - `mkRuleType`
- New server options:
  - `mode`, `listeners`, `settings` (`vm`, `tcp_vm`, `labels`), `rule`,
    `extraSettings`, `debug`, `configPath`
  - listener fields: `type`, `name`, `admin`, `port`, `cid`, `host`, `socket`,
    `socketDirMode`, `socketMode`, `resolution`, `security`, `mtls`, bounds
- Remove server `transport`, `host`, `port`, `adminSocket`, `secretFile`,
  global `mtls`, global `resolution`.
- New client/admin options:
  - transport fields, `security`, `mtls`, `acl`, timeouts, `extraSettings`,
    `register`, `proxy`, `debug`
  - `adminClient` reuses the client submodule with its own enable/config path.
- Add eval assertions:
  - enabled server requires listeners;
  - unique listener names;
  - plaintext requires explicit `none` auth on both knobs;
  - mTLS forces `transport` auth;
  - `tartarus`/`mofos` resolution rejected on `unix`;
  - admin mTLS listener requires an mtls block and admin peer OID.
- Add `X-Restart-Triggers` to server/client/proxy units.
- Add a TOML-shape eval check (`tartarus-clipboard-bridge-toml-shape`) like the
  sudo-auth-proxy check.

### Phase 4 — Host/guest wiring and secret removal

Files:
- `nix/host/services.nix`
- `nix/guest/default.nix`
- `hosts/nixos/zeus/default.nix`
- `hosts/macos/athena/default.nix`
- `hosts/nixos/{hera,mofos}/default.nix`
- `hosts/home/{linux,tinyvm}/default.nix`
- `secrets/agenix-rules.nix`
- `secrets/clipboard-bridge.age`

Tasks:

- `nix/host/services.nix`:
  - emit guest callback listeners with explicit security (`vsock` none, `tcp`
    mTLS);
  - append the Unix admin listener (`admin = true`, `resolution = "none"`,
    no TLS);
  - emit the allow-all admin rule;
  - point `adminClient` at the admin Unix socket; drop secret/mTLS from the
    admin client;
  - remove the old global `server.mtls` block.
- `nix/guest/default.nix`:
  - set client `security` per transport (`vsock` none, `tcp` mTLS);
  - emit client `[mtls]` only for TCP;
  - remove all secret references.
- Delete `age.secrets."clipboard-bridge"` and all `secretFile` usage from
  zeus/athena.
- Remove the agenix rule and delete `secrets/clipboard-bridge.age`.
- Keep client-only host configs unchanged except for the new security shape.

### Phase 5 — Optional certificate admin tooling

Files:
- `src/tartarus/ca.py`
- `src/tartarus/cli.py`
- `scripts/tartarus-certs.sh`
- tests/docs

Tasks:

- Add `OID_CLIPBOARD_ADMIN = "1.3.6.1.4.1.99999.3.3"`.
- Add admin cert issuance at
  `x509/machines/host/admin/{client.crt,client.key,ca.crt}`.
- Add `tartarus ca admin` and `tartarus-certs issue-admin` (or
  `issue-client --kind host --name admin --service clipboard-admin`).
- The admin cert carries only `clientAuth` + the admin OID. Guest certificates
  must not carry it.
- Document that certificate admin is optional because the default host admin
  path is the local Unix socket.

### Phase 6 — Docs and examples

- Add `examples/clipboard-bridge-server.toml` and
  `examples/clipboard-bridge-client.toml`.
- Update:
  - `README.md` (remove shared-secret / “no admin certificate required”
    wording);
  - `packages/tartarus.nix/README.md`;
  - `docs/technical/security-model.md`;
  - `docs/technical/architecture.md`;
  - `docs/technical/interfaces.md`;
  - `docs/user/configuration.md`;
  - `docs/technical/smoke.md`;
  - `docs/technical/design/transport-listeners.md`.
- Document the security model:
  - local admin socket is authenticated by same-user Unix permissions;
  - callback `none` is only for private-by-construction transports;
  - mTLS listeners use the CA chain + EKU;
  - the admin cert OID isolates admin from guest certificates.

### Phase 7 — Verification

- Python: `cd packages/tartarus.nix && python -m pytest tests/test_clipboard_bridge.py -v`
- Eval: run the suite / `just check` with the required `--impure` overrides.
- Build: `nixos-rebuild build` and `home-manager build` for affected hosts.
- Runtime on zeus:
  - admin `clipboard-bridge clients` over Unix with no password/certificate;
  - `notes` container push/pull over TCP mTLS;
  - `dev` VM push/pull over VSOCK with no TLS;
  - certificate-admin listener: admin certificate succeeds, guest certificate
    is denied, missing/wrong rule is denied;
  - old config with `secret` / flat server transport fails loudly.
- After commit, `just rebuild` and re-check live guests.

---

## 5. Test matrix

| Area | Test |
| --- | --- |
| Config | `[[listeners]]` required; flat server config rejected; `secret` rejected |
| Security | `auto` resolves tcp→mtls, vsock/unix→none; no downgrade |
| Listeners | Mixed vsock+tcp+unix bind in one process; all-or-nothing failure |
| Unix | Socket parent `0700`, socket `0600`; TLS over unix when configured |
| Admin | Guest listener rejects `clients`; admin listener accepts |
| Admin rules | `listeners`/`machine`/`action`/`target` matching; first match; default deny |
| Resolution | `certificate`, `tartarus`, `mofos`; unix rejects tartarus/mofos |
| Certificates | Guest cert accepted on guest mTLS listener; admin cert accepted only on admin listener |
| ACL | Server fingerprint/name pinning; wrong server rejected |
| Secrets | No generated secret; no secret field in protocol/config |
| Host wiring | Mixed host has vsock none + tcp mtls + admin unix allow-all |
| Guest wiring | VSOCK client no mtls; TCP client mtls |
| Cert tooling | Admin cert has admin OID; guest cert does not |

---

## 6. Security notes

- The default admin socket is authenticated by the host user's filesystem/UID
  boundary. Any process running as that user can administer the clipboard, just
  as it can already read/write the user's clipboard. This is documented
  explicitly, not treated as a network authentication mechanism.
- Callback listeners with `security = none` rely on the tartarus transport
  being private by construction (VSOCK, container bridge, VMM boundary). They
  must be switched to mTLS if the transport is not trusted.
- Certificate-auth admin listeners must use the admin EKU OID so a guest
  certificate cannot act as an admin.
- Removing the shared secret removes a replayable bearer token; there is no
  password path left.

---

## 7. Sequencing notes

- The current worktree already contains the multi-listener MVP. Fold it into
  Phases 1–2 rather than rewriting from scratch.
- Commit `packages/tartarus.nix` changes first, then bump the submodule pointer
  in nixcfg; `just rebuild` only sees committed submodule content.
- This is intentionally breaking: old server TOML, Nix options, and the
  clipboard agenix secret are removed, not deprecated.

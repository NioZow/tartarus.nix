# Design: multi-transport server listeners

Status: implemented · Scope: `packages/tartarus.nix` (the `tartarus` submodule)
Touches: `nix/host/services.nix`, `nix/packages/sudo-auth-proxy/*`,
`nix/packages/ssh-agent-proxy/*`, `tests/*`, `examples/*`, `docs/*`, `README.md`

This document is a technical specification, not code. It is written so that
independently assignable engineer tasks (§9) can implement it in parallel with
disjoint file ownership.

> **Update: the shared defaults block was removed after implementation.** The
> original design carried a `listenerDefaults` Nix option and a
> `[listener_defaults]` TOML block deep-merged into every entry. That block is
> gone: **every `[[listeners]]` entry is self-contained**, so a field it omits
> falls back to the built-in default and the Python refuses a
> `listener_defaults` table at load time. The sections below have been updated
> to the final shape; `listenerDefaults` should be read everywhere as "gone".

---

## 1. Summary & motivation

Today each host-side server of `sudo-auth-proxy` and `ssh-agent-proxy` binds
**exactly one** transport. The host wiring module `nix/host/services.nix`
collapses every enabled guest's requested transport into a single value
(`sudoTransport`/`sshTransport`). Two failure modes follow:

1. **Mixed callback transports (`vsock` + `tcp`).** `sudoTransport`/`sshTransport`
   cannot pick one, so they emit a non-fatal `lib.warn` and silently default to
   `vsock`:

   ```
   evaluation warning: tartarus: the enabled guests requesting sudo-auth-proxy use
   mixed callback transports (vsock, tcp); defaulting to `vsock` ... The `tcp` guests
   are not reachable until services.sudoAuthProxyTransport is unified.
   ```

   The `tcp` guests are simply unreachable.

2. **`unix` mixed with a callback transport.** Because `unix` is
   host-dials-guest (one `AF_UNIX` socket over an SSH `RemoteForward`) while
   `vsock`/`tcp` are guest-dials-host, the server "binds a single socket with one
   direction" and the module raises a hard `throw`:

   ```
   tartarus: the enabled guests requesting sudo-auth-proxy mix the SSH-forwarded
   `unix` transport with a callback transport (unix, vsock); the server exposes a
   single socket and the two call directions are incompatible. ...
   ```

**Goal.** Make **one server process bind multiple listeners at once**, each
listener independently configurable (transport kind, address/port/socket,
security, mTLS, ACL, timeouts). The mixed-transport `warn` and the
`unix`+callback `throw` both disappear: a Linux host can serve a `vsock` VM, a
`tcp` container, and an SSH-forwarded `unix` guest simultaneously. Multiple
listeners of the same kind are allowed (two `unix` listeners with different ACLs
for different hosts).

**Invariants (locked):**

- Applies to the **server** of `sudo-auth-proxy` and `ssh-agent-proxy` only.
  `clipboard-bridge` and every guest-side **client/bridge** keep a single
  transport and are **unchanged**.
- The guest client still dials exactly one transport.
- The server option surface becomes a **list** (`listeners`) of **self-contained
  entries**; a field an entry omits falls back to the built-in default.
- The **old flat server options are removed outright** — no deprecated aliases —
  for both the default `server` and the `extraServer` instance.
- The generated server TOML is an array of listener tables. The **Python
  resolves each entry on its own** and spawns one listener per entry inside the
  single server process.
- The Python additionally keeps accepting a **legacy flat server config** as a
  single implicit listener (documented compatibility fallback, **not** a Nix
  option).

---

## 2. Nix option schema

All options keep the repo conventions already in use: `lib.mkEnableOption`,
`lib.mkOption`, `types.*`, `types.submodule`. These are `tartarus.*` options
(this is the tartarus submodule; `custom.*` is nixcfg, not here).

### 2.1 Shared helpers and the listener option builder

The reusable builders are kept local to each service module.

```nix
# Reusable `[security]` builder. Every knob carries its real default, so a
# `listeners` entry that omits it is self-contained.
mkSecurityOptions = {lib}: let
  inherit (lib) mkOption types;
in {
  transportEncryption = mkOption {
    type = types.enum ["auto" "none" "mtls"];
    default = "auto";
    description = ''
      Whether the byte stream is encrypted and integrity-protected. `auto`
      follows the listener's `type`: `tcp` → `mtls`, `vsock`/`unix` → `none`.
    '';
  };
  clientAuth  = mkOption { type = types.enum ["transport" "none"]; default = "transport"; };
  serverAuth  = mkOption { type = types.enum ["transport" "none"]; default = "transport"; };
  responseTtl = mkOption { type = types.int; default = 30; };
  clockSkew   = mkOption { type = types.int; default = 5; };
};
```

```nix
# Reusable `[mtls]` builder for one listener. Every field carries its real
# default so the listener is self-contained.
mkMtlsOptions = {lib, requiredOid, peerOid}: let
  inherit (lib) mkOption types;
in {
  enable    = mkOption { type = types.bool; default = false; };
  caFile    = mkOption { type = types.str; default = "./ca.crt"; };
  certFile  = mkOption { type = types.str; default = "./server.crt"; };
  keyFile   = mkOption { type = types.str; default = "./server.key"; };
  requiredOid = mkOption { type = types.str; default = requiredOid; };
  peerOid     = mkOption { type = types.str; default = peerOid; };
};
```

The per-listener option set is one builder used for the `listeners` array:

```nix
mkListenerOptions = {lib, pkgs, requiredOid, peerOid}: let
  inherit (lib) mkOption types;
in {
  type = mkOption {
    type = types.enum ["vsock" "tcp" "unix"];
    description = "Transport this listener binds (required for every entry).";
  };
  name = mkOption { type = types.nullOr types.str; default = null; };
  # Address / bind target. Each is meaningful only for its own `type`, but all
  # are accepted on every listener (the old flat options had the same shape).
  port        = mkOption { type = types.port; default = 65001; };
  cid         = mkOption { type = types.int; default = 2; };
  host        = mkOption { type = types.str; default = "127.0.0.1"; };
  socket      = mkOption { type = types.str; default = "%t/sudo-auth-proxy/server.sock"; };
  socketDirMode = mkOption { type = types.str; default = "0700"; };
  socketMode    = mkOption { type = types.str; default = "0600"; };
  # Timeouts and pre-auth resource bounds.
  connectTimeout   = mkOption { type = types.float; default = 0.2; };
  decisionTimeout  = mkOption { type = types.int; default = 120; };
  recvTimeout      = mkOption { type = types.float; default = 0.5; };
  maxConnections   = mkOption { type = types.ints.positive; default = 64; };
  serverReadTimeout = mkOption { type = types.float; default = 10.0; };
  # Per-listener identity resolution (`unix` cannot do tartarus/mofos).
  resolution = mkOption {
    type = types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"]);
    default = null;
  };
  # Per-listener security / mTLS. There is no per-listener ACL: the
  # document-level `[[rule]]` list scopes itself with `match.listeners`.
  security = mkSecurityOptions {inherit lib;};
  mtls     = mkMtlsOptions {inherit lib requiredOid peerOid;};
};
# `listeners` = types.listOf (types.submodule {
#     options = mkListenerOptions {inherit lib pkgs requiredOid peerOid;};
#   });
```

> Note on `null`: only `name` and `resolution` are `nullOr`; every other field
> has a real default. The TOML emitter still prunes `null` fields before
> generation (§3.3).

### 2.2 `sudo-auth-proxy` server schema (`mkServerOptions`)

`mkServerOptions` becomes transport-agnostic (no `withSecurity` distinction:
both the default `server` and `extraServer` carry their own listeners now):

```nix
mkServerOptions = {lib, pkgs}: let
  inherit (lib) mkEnableOption mkOption types;
  tomlFormat = pkgs.formats.toml {};
  requiredOid = "1.3.6.1.4.1.99999.1.1";   # sudo server cert EKU
  peerOid     = "1.3.6.1.4.1.99999.1.2";   # sudo client cert EKU
in {
  enable = mkEnableOption "the sudo-auth-proxy server (host side)";

  # ---- genuinely non-transport, global options (unchanged) ----
  configPath    = mkOption { type = types.nullOr types.str; default = null; };
  dialogProgram = mkOption { type = types.enum ["swiftdialog" "osascript" "zenity"]; default = …; };
  debug         = mkOption { type = types.bool; default = false; };
  extraSettings = mkOption { type = types.attrs; default = {}; };

  # ---- the listeners (each self-contained) ----
  listeners = mkOption {
    type = types.listOf (types.submodule {
      options = mkListenerOptions {inherit lib pkgs requiredOid peerOid;};
    });
    default = [];
    description = ''
      One entry per transport this server binds, all in the single server
      process. Each entry is self-contained (a field it omits uses the built-in
      default). Multiple entries of the same `type` are allowed (e.g. two `unix`
      listeners). Empty means the server binds nothing and the module rejects
      the configuration (see the assertion in §2.4).
    '';
  };
};
```

Field defaults (so an out-of-the-box server is byte-identical in *effective*
terms to the historical single-listener defaults): `port = 65001`,
`connectTimeout = 0.2`, `decisionTimeout = 120`, `recvTimeout = 0.5`,
`maxConnections = 64`, `serverReadTimeout = 10.0`, `resolution = null`,
`cid = 2`, `host = "127.0.0.1"`,
`socket = "%t/sudo-auth-proxy/server.sock"`, `socketDirMode = "0700"`,
`socketMode = "0600"`, `security = mkSecurityOptions {…}` (defaults as today),
`mtls = mkMtlsOptions {…}` (defaults as today).

`extraServer` = `mkServerOptions {inherit lib pkgs;} // { name = mkOption {type = types.str; default = "extra";}; }`.
The old `withSecurity` parameter and the `extraServer.security` block are gone.

### 2.3 `ssh-agent-proxy` server schema

The ssh server gets the same shape, with these differences:

- No ACL table (ssh has no `[acl]`). `mkListenerOptions` for ssh omits `acl`.
- No `resolution` defaulting from `mtls`; `resolution` is per listener exactly as
  today's `resolution` option.
- The ssh `settings` freeform stays **global** (top-level TOML keys) and is
  *not* per-listener: it carries the VM id maps (`vm`, `tcp_vm`), `key`, `rule`,
  `agent_sockets`, `known_hosts_files`,
  `libvirt_uri`. Those are policy shared by every listener; only `resolution`
  and the bind/security fields are per-listener.
- `connectTimeout`/`handshakeTimeout`/`decisionTimeout` live at the **listener**
  level (`connect_timeout`/`handshake_timeout`/`decision_timeout`), matching
  where `Config.load` reads them. (Today the Nix emitter nests them under
  `[security]`, where `Config.load` never reads them — dead keys. This spec
  fixes that placement; see §6.)

```nix
server = {
  enable = mkEnableOption "the ssh-agent-proxy server (host side)";
  configPath = mkOption { type = types.nullOr types.str; default = null; };
  dialogProgram = mkOption { type = types.enum ["swiftdialog" "osascript" "zenity"]; default = …; };
  debug = mkOption { type = types.bool; default = false; };
  settings = mkOption { type = types.submodule { freeformType = tomlFormat.type; options = { … }; }; default = {}; };
  listeners = mkOption { type = types.listOf (types.submodule { options = sshListenerOptions {inherit lib;}; }); default = []; };
};
```

`sshListenerOptions` is the per-listener builder (no ACL table). Its fields and
built-in defaults:

| Nix option | TOML key | default |
| --- | --- | --- |
| `type` | `type` | *(entry only)* |
| `port` | `port` | `65000` |
| `cid` | `cid` | `2` |
| `host` | `host` | `"127.0.0.1"` |
| `socket` | `socket` | `"%t/ssh-agent-proxy/server.sock"` |
| `socketDirMode` | `socket_dir_mode` | `"0700"` |
| `socketMode` | `socket_mode` | `"0600"` |
| `connectTimeout` | `connect_timeout` | `10.0` |
| `handshakeTimeout` | `handshake_timeout` | `10.0` |
| `decisionTimeout` | `decision_timeout` | `120` |
| `resolution` | `resolution` | `null` |
| `security` | `[security]` | `mkSecurityOptions` defaults |

### 2.4 Removed options, assertions, `extraServer`

**Removed outright (no aliases) from the server shape of both services:**
`transport`, `host`, `port`, `cid`, `socket`, `socketDirMode`, `socketMode`,
`connectTimeout`, `decisionTimeout`, `recvTimeout`, `maxConnections`,
`serverReadTimeout`, `resolution` (the flat ones), `security`, `mtls`, `acl`, and
(for sudo) the `mtls`/`acl`/`security` sub-options of `extraServer`. The flat
client options of `tartarus.sudo-auth-proxy.*` and
`tartarus.ssh-agent-proxy.bridge.*` are **untouched** (see §2.5).

**`extraServer`** keeps only its `name` option on top of the same
`mkServerOptions`, exactly as today, but with the `listeners` shape. There is no
`extraServer.security` any more; a second instance configures its own
`listeners`.

**Assertions.** The existing eval-time assertions that reference the flat
transport/security are rewritten per listener:

- sudo, for every entry, the eval-time guard
  `effectiveTransportEncryption != "none" || (clientAuth == "none" && serverAuth == "none")`
  is evaluated per entry. Concretely:
  ```nix
  assertions = map (entry: {
    assertion =
      effectiveEncryption entry != "none"
      || (effectiveClientAuth entry == "none" && effectiveServerAuth entry == "none");
    message = "tartarus.sudo-auth-proxy.server.listeners: transport_encryption = \"none\" requires client_auth = server_auth = \"none\" (entry type = ${entry.type}).";
  }) server.listeners
  # plus: at least one listener when the server is enabled
  ++ lib.optional (server.enable && server.listeners == []) {
    assertion = false;
    message = "tartarus.sudo-auth-proxy.server.enable = true requires at least one entry in server.listeners.";
  };
  ```
  where `effectiveEncryption`/`effectiveClientAuth`/`effectiveServerAuth` resolve
  an entry from the entry itself (`mtls.enable` → mtls; `auto` → mtls on `tcp`
  else none; mtls forces both auths to `transport`), so the assertion sees the
  same effective values the Python will.
- ssh: `mtls.enable` vs explicit `transportEncryption` conflict and the
  `unix`+`resolution` restriction are **per-entry**. No `transport` list means
  no conflict at all.

### 2.5 Client and bridge options are untouched

- `tartarus.sudo-auth-proxy.{transport,host,port,cid,socket,socketDirMode,socketMode,connectTimeout,decisionTimeout,recvTimeout,configPath,configDirMode,configDirGroup,mtls,security,settings,debug}`
  stay exactly as they are (the PAM/guest client). The `pamNixosModule` is
  unchanged.
- `tartarus.ssh-agent-proxy.bridge.*`, `.agent.*` are unchanged.
  `bridge` still has a single `transport`/`host`/`port`/`connectSocket`/…
- The guest wiring in `nix/guest/default.nix` is unchanged: it sets a single
  client transport (`sapUnix`/`sshUnix`) on the client/bridge, never on the
  server. `nix/guest/build.nix` normalization and `nix/lib/types.nix` markers are
  unchanged (the markers still select the guest client transport and feed the
  host wiring's listener derivation, §5).

---

## 3. Generated TOML schema

### 3.1 Shape

Both services emit, for a server:

```toml
mode = "server"                 # ssh: mode = "proxy"
dialog_program = "zenity"
debug = true                    # omitted when false (existing behaviour)

[[listeners]]
type = "vsock"
cid = 2
resolution = "mofos"            # only when non-null
connect_timeout = 0.2
decision_timeout = 120
recv_timeout = 0.5
max_connections = 64
server_read_timeout = 10.0

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "tcp"
host = "10.200.0.1"
port = 65001

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "unix"
socket = "%t/sudo-auth-proxy/server.sock"
resolution = "certificate"

[listeners.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[listeners.mtls]
enable = true
ca_file = "/etc/tartarus/x509/ca.crt"
cert_file = "/etc/tartarus/x509/host.crt"
key_file = "/etc/tartarus/x509/host.key"
required_oid = "1.3.6.1.4.1.99999.1.1"
peer_required_oid = "1.3.6.1.4.1.99999.1.2"
```

Every entry is self-contained; a field it omits is simply absent from the
emitted TOML and the Python applies its built-in default. There is no
`[listener_defaults]` block. There is no per-listener `[acl]` either: the
document-level `[[rule]]` list scopes itself with `match.listeners`.

Top-level keys for the **ssh** server additionally include the global `settings`
freeform keys (`vm`, `tcp_vm`, `libvirt_uri`, `agent_sockets`,
`known_hosts_files`, `key`, `rule`) emitted at the top level
after `mode`/`dialog_program`/`debug`, as today. These stay global because the
Python parses them once on the shared `Config`, not per listener.

**Emission algorithm (Nix).** Define a recursive `pruneNulls` and a
`renderListener` that renders one self-contained entry:

```nix
renderListener = lib: entry: let
  prune = v:
    if builtins.isAttrs v then lib.mapAttrs (_: prune) (lib.filterAttrs (_: x: x != null) v)
    else if builtins.isList v then map prune v else v;
  security = renderSecurity (resolveTransportEncryption entry);  # resolved per entry
  mtls     = lib.optionalAttrs (resolvesToMtls entry) (renderMtls entry.mtls);
in prune ({
  type = entry.type;
  name = entry.name;
  port = entry.port; cid = entry.cid; host = entry.host;
  socket = entry.socket; socket_dir_mode = entry.socketDirMode; socket_mode = entry.socketMode;
  connect_timeout = entry.connectTimeout; decision_timeout = entry.decisionTimeout;
  recv_timeout = entry.recvTimeout; max_connections = entry.maxConnections;
  server_read_timeout = entry.serverReadTimeout; resolution = entry.resolution;
} // {security = security;}
  // lib.optionalAttrs (mtls != null)  {mtls = mtls;});

serverToml = {
  mode = "server";
  dialog_program = server.dialogProgram;
  debug = lib.optionalAttrs server.debug true;
  listeners = map renderListener server.listeners;
} // server.extraSettings;
configFile = tomlFormat.generate "…" (pruneNulls serverToml);
```

Every entry renders its own values; only `name`/`resolution` (which are `nullOr`)
are pruned when unset.

### 3.2 TOML subtleties (verified)

`pkgs.formats.toml` is `pkgs.formats.json // { generate = json2toml; }` (nixpkgs
`pkgs/pkgs-lib/formats.nix`): it serialises the Nix attrset to JSON via
`builtins.toJSON` (which sorts keys alphabetically) then runs `remarshal`'s
`json2toml`. Running that exact pipeline on a representative value produced
(verbatim):

```toml
mode = "server"

[[listeners]]
cid = 2
type = "vsock"

[[listeners]]
host = "10.200.0.1"
type = "tcp"

[listeners.security]
client_auth = "none"
server_auth = "none"
transport_encryption = "none"

[[listeners]]
socket = "%t/x.sock"
type = "unix"

[listeners.security]
client_auth = "transport"
server_auth = "transport"
transport_encryption = "mtls"

[listeners.mtls]
ca_file = "/etc/tartarus/x509/ca.crt"
enable = true
```

Consequences the implementation relies on:

1. **`null` is fatal.** `json2toml` refuses any `null` ("Cannot convert data to
   TOML (null values are not supported)"). `name`/`resolution` (the only
   `nullOr` fields) and `extraSettings` must be pruned before generation.
2. **Sub-tables attach to the last array element.** `[listeners.security]` /
   `[listeners.mtls]` after a `[[listeners]]` bind to that element, exactly as
   intended, and the next `[[listeners]]` starts a fresh element. remarshal
   emits an element's scalar keys **before** its sub-tables even though JSON key
   order is alphabetical, so the result is always valid TOML.
3. **Ordering is deterministic.** remarshal emits top-level scalars first, so
   `mode`/`dialog_program`/`debug` precede the `[[listeners]]` array. A golden
   test (§7) pins this.
4. **Key order inside a table is alphabetical** (e.g. `cid` before `type`,
   `security` before `mtls`). No code may depend on field order.

### 3.3 Python detection of legacy vs new

The Python parses with `tomllib` (`load_config` already does). Detection is
purely structural:

```
new_schema  := isinstance(config.get("listeners"), list) and len(config["listeners"]) > 0
legacy_flat := not new_schema
```

- `new_schema`: expand `len(listeners)` listeners, each entry self-contained
  (§4.1). The top-level document must not also carry the flat
  transport/security keys (rejected — §4.6).
- `legacy_flat`: the whole parsed top-level dict is the single implicit
  listener, exactly as today. This makes a hand-written flat config keep working
  with zero edits.

A config with BOTH `listeners` and flat `transport`/`security`/`mtls` at the top
level is rejected (ambiguous), and a `listener_defaults` block is refused
outright.

---

## 4. Python algorithm

Both services import no new dependencies; `tomllib` and `threading` are already
available (Python ≥ 3.11).

### 4.1 Shared helpers

```
GLOBAL_KEYS = ("mode", "dialog_program", "debug", "approver", "client_version", "guest_hint")

def listener_views(config: dict) -> list[dict]:
    """Flat, legacy-shaped per-listener configs, or [config] for a flat config.

    Each view carries the entry's own fields; a field the entry omits is simply
    absent and the flat readers apply their built-in default.
    """
    entries = config.get("listeners")
    if not isinstance(entries, list) or not entries:
        return [config]                       # legacy fallback: one implicit listener
    views = []
    for index, entry in enumerate(entries):
        view = dict(entry)
        # `type` is the wire key; downstream code reads `transport`.
        if "type" in view:
            view["transport"] = view["type"]
            del view["type"]
        for key in GLOBAL_KEYS:               # Handler/transport read these globally
            if key in config:
                view.setdefault(key, config[key])
        view["_listener_index"] = index        # for log lines / tests
        views.append(view)
    return views
```

Each `view` is exactly the shape `validate_config_schema`,
`make_transport`, `build_security`, `create_ssl_context`, `get_resolution_mode`
and `resolve_read_timeouts` already accept. No transport/security code changes.

### 4.2 sudo `run_server`

`Handler` already reads `self.server._transport`, `self.server._config` and
`self.server._security` (confirmed: `sudo-auth-proxy.py` `Handler.handle`
lines ~3305–3320). `Transport.listen` already attaches `_config` (the view it
was constructed with) and `_transport` to the dynamic server class. So only two
things change: bind **all** listeners first, and attach `_security` per server.

```
def run_server(config: dict) -> None:
    set_debug(config)
    if isinstance(config.get("listeners"), list):
        validate_document_schema(config)      # §4.6
    views = listener_views(config)
    bound: list[tuple[BaseServer, Transport, SecurityConfig]] = []
    try:
        for view in views:
            validate_config_schema(view)      # the flat per-listener schema
            security = build_security(view, "server")
            if not acl_allows_any(security.acl):
                print("… WARNING: [acl] allows nobody …", file=sys.stderr)
            transport = make_transport(view)
            server = transport.listen(Handler)          # binds; raises on failure
            setattr(server, "_security", security)      # dynamic class attribute
            bound.append((server, transport, security))
    except BaseException:
        # Fail the WHOLE server before serving a single request.
        for server, transport, _ in bound:
            _close_listener(server, transport)
        raise

    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s, _, _ in bound]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass
    finally:
        for server, transport, _ in bound:
            _close_listener(server, transport)

def _close_listener(server, transport) -> None:
    with contextlib.suppress(Exception):
        server.shutdown()
    with contextlib.suppress(Exception):
        server.server_close()
    transport.cleanup()          # unix unlinks the socket it bound, by inode
```

Details:

- `transport.listen(Handler)` returns the threaded server whose `_config` is the
  per-listener `view` (via `Transport.config`), and `_transport` is the
  per-listener `Transport`. Each listener therefore has its own
  `max_connections` semaphore, `server_read_timeout`, TLS context and handler
  config. `Handler.handle` needs no change.
- Each `UnixTransport` tracks its own `_bound_ino`, so two unix listeners with
  different `socket` paths unlink exactly their own socket on cleanup.
- Binding is strictly sequential and all-or-nothing: if listener *k* fails
  (unknown transport, address in use, `AF_VSOCK` unavailable, cert error), the
  already-bound listeners are closed and the process exits non-zero. No listener
  ever serves while another is half-initialised.
- `debug`/`dialog_program` are carried into each view, so `Handler.handle`'s
  `config.get("dialog_program")` works unchanged.
- `KeyboardInterrupt` and normal exit both run the same cleanup.

### 4.3 sudo `Handler` — confirmed, no change

`Handler.setup` reads `getattr(self.server, "ssl_context", None)`;
`Handler.handle` reads `_config`, `_transport`, `_security` from `self.server`.
Because `run_server` creates one dynamic server class **per view**, these are
already per-listener. The only behavioural difference is that `_security` is
built per view instead of once; `Handler.handle`'s `if security is None:`
fallback remains for direct-invocation tests.

### 4.4 ssh-agent-proxy: `Config` + `ListenerConfig`

The client/bridge path is unchanged. Proxy mode gains a listener list.

```
@dataclass
class ListenerConfig:
    """One server listener: bind target + resolved security + per-listener identity."""
    transport: str                 # "vsock" | "tcp" | "unix"
    host: str
    port: int
    cid: int
    socket: Optional[str]
    socket_dir_mode: str
    socket_mode: str
    connect_timeout: float
    handshake_timeout: float
    decision_timeout: int
    resolution: Optional[str]
    transport_encryption: Optional[str]
    client_auth: Optional[str]
    server_auth: Optional[str]
    mtls_enable: bool
    mtls_ca_file: Optional[str]
    mtls_cert_file: Optional[str]
    mtls_key_file: Optional[str]
    mtls_required_oid: Optional[str]
    mtls_peer_required_oid: Optional[str]
```

`Config.__init__` adds `self.listeners: list[ListenerConfig] = []`. `Config.load`
keeps parsing the global policy exactly as today (transport-independent keys,
`vm`, `tcp_vm`, `key`, `rule`, `agent_sockets`, …), then branches at the point
where it currently resolves the single `self.transport`:

```
raw_listeners = data.get("listeners")
if isinstance(raw_listeners, list) and raw_listeners:
    self.listeners = [
        self._parse_listener(entry, resolve) for entry in raw_listeners
    ]
else:
    self.listeners = [self._parse_listener_from_flat(data)]   # legacy fallback
```

`_parse_listener(data)`:

- `transport = data.get("type") or data.get("transport")`; validate
  `in ("vsock", "tcp", "unix")`.
- Resolve `(transport_encryption, client_auth, server_auth) =
  validate_security_config(data, transport)` — **per listener**.
- Resolve `resolution`: explicit, else `"certificate" if mtls else "none"`;
  reject `tartarus`/`mofos` on `unix` (per listener).
- Resolve `mtls_*` from `data.get("mtls", {})`; resolve relative paths against
  the config dir (reuse the existing `resolve` closure).
- Build the `ListenerConfig`. `_parse_listener_from_flat(data)` builds the same
  object from the already-parsed flat `self.*` fields (legacy).

`create_ssl_context` is unchanged in body but now receives a `ListenerConfig`
(server) or the client `Config`; it reads the same `transport_encryption` /
`mtls_*` attributes via `getattr`, so both types satisfy it. `run_client` still
passes its `Config`.

### 4.5 ssh-agent-proxy: `run_proxy` + `Handler`

```
def _bind_listener(listener: ListenerConfig, ssl_ctx) -> TCPServer:
    if listener.transport == "unix":
        path = _expand_socket_path(listener.socket or DEFAULT_SOCKET)
        _prepare_unix_socket(path, _parse_mode(listener.socket_dir_mode, DEFAULT_SOCKET_DIR_MODE))
        old = umask(0o177)
        try:
            server = ThreadedUnixServer(path, Handler)
        finally:
            umask(old)
        Path(path).chmod(_parse_mode(listener.socket_mode, DEFAULT_SOCKET_MODE))
    elif listener.transport == "tcp":
        server = ThreadedTcpServer((listener.host, listener.port), Handler)
    else:
        server = ThreadedVsockServer((HOST_CID, listener.port), Handler)
    server.app_config = config                 # shared policy
    server.listener_config = listener          # per-listener identity/security
    server.ssl_context = ssl_ctx
    server._mtls_config = {"peer_required_oid": listener.mtls_peer_required_oid}
    return server

def run_proxy(config: Config) -> None:
    bound = []
    try:
        for listener in config.listeners:
            ssl_ctx = create_ssl_context(listener, server=True)   # exit(1) on failure
            bound.append((_bind_listener(listener, ssl_ctx), listener))
    except BaseException:
        for server, _ in bound:
            with contextlib.suppress(Exception):
                server.server_close()
            _unlink_listener_socket(...)      # best effort, per listener
        raise
    threads = [Thread(target=s.serve_forever, daemon=True) for s, _ in bound]
    for t in threads: t.start()
    try:
        for t in threads: t.join()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        for server, listener in bound:
            with contextlib.suppress(Exception):
                server.shutdown()
            with contextlib.suppress(Exception):
                server.server_close()
            _unlink_listener_socket(listener)
```

`Handler.setup` changes minimally: the shared policy stays
`self.config = self.server.app_config`; the two per-listener reads become

```
resolution = self.server.listener_config.resolution
```

while `address_family` (from the server class), `ssl_context` and
`_mtls_config` were already per-server. `resolve_peer(resolution, ssl_ctx,
self.request, static_name, unknown_label, peer)` is unchanged. `self.config`
still supplies `vm_by_cid`/`vm_by_ip`/`libvirt_uri`/keys/rules/agent_sockets.

`run_client`, `ClientHandler` and `RemoteConnection` are unchanged.

### 4.6 Schema validation

**sudo.** `validate_config_schema` stays the **flat** validator (reused for each
expanded view). A new `validate_document_schema(config)` wraps it:

```
def validate_document_schema(config: dict, *, source=None) -> None:
    if "listener_defaults" in config:
        raise SecurityConfigError(
            "'[listener_defaults]' was removed: every [[listeners]] entry is "
            "self-contained")
    if "listeners" in config:
        # New schema: the top level may only carry the global keys plus
        # `listeners`. A flat transport/security/mtls key alongside `listeners`
        # is ambiguous and rejected.
        allowed = {"mode", "dialog_program", "debug", "approver", "client_version",
                   "guest_hint", "listeners"}
        reject_unknown(config, allowed, where="at the top level")   # existing machinery
        if not isinstance(config["listeners"], list) or not config["listeners"]:
            raise SecurityConfigError("'listeners' must be a non-empty array of tables")
        for i, entry in enumerate(config["listeners"]):
            validate_listener_table(entry, where=f"listeners[{i}]")   # per-listener keys
        return
    # Legacy flat schema, unchanged (also reached for every expanded view).
    validate_config_schema(config, source=source)
```

- `validate_listener_table` accepts the per-listener key set
  (`type`, `name`, `port`, `cid`, `host`, `socket`, `socket_dir_mode`,
  `socket_mode`, `connect_timeout`, `decision_timeout`, `recv_timeout`,
  `max_connections`, `server_read_timeout`, `resolution`, `security`, `mtls`)
  and reuses the existing table/`did-you-mean` machinery for nested
  `[security]`/`[mtls]`. It requires `type` for every entry.
- Duplicate **types are allowed** (two unix listeners). Duplicate **socket
  paths** are a runtime bind error (the second bind unlinks/fails), not a schema
  error.

**ssh.** ssh has no exact-schema validator today; add minimal validation in
`Config.load`:
- `listeners` present ⇒ each entry must be a dict with a valid `type`; entries
  may repeat a type.
- `listeners` present together with a top-level `transport`/`tcp_bind`/
  `vsock_port` is ambiguous ⇒ `ValueError`.

### 4.7 Failure semantics

- **Bind failure of any listener fails the whole server** before it serves:
  all listeners are bound before any `serve_forever()` starts; a `raise` on
  listener *k* closes/cleans listeners `0..k-1` and exits non-zero.
- **Security failure of any listener fails the whole server**: `build_security`
  and `create_ssl_context` run for every listener up front; a bad `[security]`
  or missing cert aborts startup (sudo prints and `sys.exit(1)`; ssh `exit(1)`).
- **Per-listener isolation at runtime**: a crash in one `serve_forever` thread
  does not stop the others; a rejected/denied request on listener A never
  affects listener B. Handler-level failures are per connection as today.

---

## 5. Host wiring algorithm (`nix/host/services.nix`)

The single-transport collapse (`mkTransport`, `sudoTransport`, `sshTransport`),
the `lib.warn` and the `throw` are **removed**. `transportOf`, `mkTcpHost`,
`guestId`, `guestIP`, `enabled`, `requester` and the stand-in-VM logic stay.

```
# ---- sudo-auth-proxy ----
# One listener per distinct transport the requesting guests ask for.
sapGuestTransport = g: if sapMarker g == "unix" then "unix" else transportOf g;
sudoKinds = lib.unique (map (e: sapGuestTransport e.g) (listOf sudoReq));

sudoVsockListener = { type = "vsock"; cid = 2; security = callbackSecurity; };
sudoTcpListener   = { type = "tcp"; host = mkTcpHost sudoReq; port = 65001;
                      security = callbackSecurity; };
sudoUnixListener  = { type = "unix"; socket = "%t/sudo-auth-proxy/server.sock";
                      security = unixSecurity;
                      mtls = { enable = true; caFile = x509Ca; certFile = x509HostCert; keyFile = x509HostKey;
                               requiredOid = "1.3.6.1.4.1.99999.1.1"; peerOid = sudoClientOid; }; };

sudoListeners =
  lib.optional (builtins.elem "vsock" sudoKinds) sudoVsockListener
  ++ lib.optional (builtins.elem "tcp"   sudoKinds) sudoTcpListener
  ++ lib.optional (builtins.elem "unix"  sudoKinds) sudoUnixListener;

# homepage config:
tartarus.sudo-auth-proxy.server = {
  enable = mkDefault true;
  listeners = mkDefault sudoListeners;         # {type,…} per listener, self-contained
};
```

with

```nix
callbackSecurity = {
  transportEncryption = "none";
  clientAuth = "none";
  serverAuth = "none";
};
unixSecurity = {
  transportEncryption = "mtls";
  clientAuth = "transport";
  serverAuth = "transport";
};
```

- `lib.unique` dedupes the kinds; **order** is `vsock`, `tcp`, `unix` (stable
  and deterministic). Two guests asking the same kind ⇒ one listener. There is
  never a warning or a throw for a mix.
- `unix` + callback **coexist**: `sudoKinds` may be `["unix" "vsock"]` and both
  listeners are emitted.
- The `unix` listener always binds `%t/sudo-auth-proxy/server.sock` (unchanged
  path); a future "two unix listeners with different ACLs" case would be two
  entries with distinct `socket` values (the *server* option list supports it;
  the automatic host wiring emits one canonical unix listener).
- `x509Ca`/`x509HostCert`/`x509HostKey`/`sudoClientOid` are read from
  `config.tartarus.ca.x509` and the existing constant, exactly as today.

```
# ---- ssh-agent-proxy (mirrors the sudo block) ----
sshGuestTransport = g: if sshMarker g == "unix" then "unix" else transportOf g;
sshKinds = lib.unique (map (e: sshGuestTransport e.g) (listOf sshReq));

sshListener type = { inherit type; resolution = …; security = …; mtls = …; };
```

- `vsock` entry: `{ type = "vsock"; cid = 2; resolution = "tartarus";
  security = callbackSecurity; }`.
- `tcp` entry: `{ type = "tcp"; host = mkTcpHost sshReq; port = 65000;
  resolution = "tartarus"; security = callbackSecurity; }`.
- `unix` entry: `{ type = "unix"; socket = "%t/ssh-agent-proxy/server.sock";
  resolution = "certificate"; security = unixSecurity;
  mtls = { enable = true; caFile = x509Ca; certFile = x509HostCert;
  keyFile = x509HostKey; requiredOid = "1.3.6.1.4.1.99999.2.1";
  peerOid = "1.3.6.1.4.1.99999.2.2"; }; }`.

- `settings.vm`/`settings.tcp_vm` move from "omit on unix" to **always emitted**
  at the server level: a server can now have a `unix` listener *and* a
  `vsock`/`tcp` listener, so the CID/IP maps must always be present. The
  `lib.removeAttrs`-on-unix hack disappears.
- `resolution` is per listener (`certificate` for unix, `tartarus` otherwise),
  matching today's single-transport values.

**Container-host stand-in VMs.** `enabled` includes each stand-in VM (with
`disableVsock = true`) whose `services` are the union of its own and its inner
containers' requests. `transportOf` returns `tcp` for it (kind `vm` but
`disableVsock`), so it contributes a `tcp` listener exactly as a container
would; the inner containers are `kind = "container"` → also `tcp`. A stand-in
host therefore yields a single `tcp` listener (no vsock), unchanged from
today's behaviour. If the same host also has a native VM guest, both listeners
are emitted. `mkTcpHost` is kept verbatim (it already mixes hasVm/hasCtN to pick
the gateway), so the tcp bind address is unchanged.

**Firewall / NAT.** `nix/host/firewall.nix` already derives its rules from the
per-guest markers and `kind`; emitting both a tcp and a vsock listener does not
require a firewall change. The tcp listener may now exist where previously the
collapse picked vsock, so the firewall/NAT task must re-verify that the tcp
service port is opened/DNAT-ed whenever a tcp listener is present (it already
opens the port when a `tcp` guest is present; the mixed case is the same set of
guests). This is a cross-check task (§9 T9), not a code change expected here.

---

## 6. Compatibility & migration

**Nix.**

- The flat server options are removed with **no aliases** (locked). Any consumer
  that set `tartarus.sudo-auth-proxy.server.transport` / `.security` / `.mtls` /
  `.acl` / `.host` / `.port` / `.cid` / `.socket*` / timeouts, or
  `tartarus.ssh-agent-proxy.server.transport` / `.security` / `.mtls` /
  `.resolution`, must migrate to `server.listeners = [ { type = …; … } ]`, each
  entry **self-contained**. This is a deliberate hard break: a partially-migrated
  config should fail evaluation loudly, not silently bind the wrong transport.
- The automatic host wiring (`nix/host/services.nix`) is updated in the same
  change, so `nixcfg` and any tartarus-managed host need no action.
- Consumer `nixosModules`/`homeManagerModules` imports are unchanged.

**Python.**

- The Python keeps accepting a **legacy flat server config** as one implicit
  listener (top-level `mode` + `transport`/`cid`/`host`/`port`/`socket*` +
  `[security]`/`[mtls]`/`[acl]`). `examples/sudo-auth-proxy-server.toml`,
  `examples/ssh-agent-proxy-server.toml`, hand-written configs, and the
  standalone package therefore keep working unchanged. This fallback is a
  **Python** compatibility rule only; there is no Nix option for it.
- The ssh `[security].connect_timeout`/`handshake_timeout`/`decision_timeout`
  keys emitted by the current Nix module are dead (the Python reads them at the
  top level). The new schema emits them at the listener level so they take
  effect. This is a small, intentional behaviour change (configured timeouts are
  now honoured) and is noted in the docs.

---

## 7. Tests plan

All Python tests run from the package root:
`python -m pytest tests/test_sudo_auth_proxy.py tests/test_ssh_agent_proxy.py -q`.

### 7.1 `tests/test_sudo_auth_proxy.py` (extend)

New tests (helpers `_transport_server` etc. already exist):

- `test_listener_views_keep_each_entry_self_contained` — each view carries only
  the entry's own fields; a field the entry omits is absent (the flat readers
  apply their built-in default).
- `test_listener_views_map_type_to_transport` — each view has `transport` set
  from `type` and no `type` key; globals (`dialog_program`) are carried.
- `test_legacy_flat_config_is_single_listener` — a flat server config yields one
  view equal to itself.
- `test_schema_rejects_flat_key_alongside_listeners` — a document with both
  `listeners` and top-level `transport` raises `SecurityConfigError`.
- `test_schema_rejects_unknown_listener_key` — an unknown key inside a
  `listeners` entry is named, with the did-you-mean hint.
- `test_run_server_binds_two_unix_listeners_with_distinct_acls` — start a server
  with two `unix` entries whose ACLs differ; a request authorized on listener A
  is denied on listener B. (AF_UNIX works on every CI platform.)
- `test_run_server_binds_tcp_and_unix_together` — `tcp` + `unix` listeners in
  one process; both accept a connection; the `unix` one is cleaned up on
  shutdown.
- `test_any_listener_bind_failure_is_fatal` — the second listener's bind fails
  (e.g. reuse an already-bound `unix` path); the first is closed and `run_server`
  raises/exits non-zero.
- `test_per_listener_security_isolation` — two listeners resolve different
  `transport_encryption` (one `none`, one `mtls` with test certs); each server's
  `_security.transport_encryption` matches its listener.
- `test_shipped_multi_listener_example_parses` — the shipped
  `examples/sudo-auth-proxy-server.toml` (see §8) loads, expands to 3
  listeners, and passes `validate_document_schema`.

### 7.2 `tests/test_ssh_agent_proxy.py` (extend)

- `test_load_builds_listeners_from_listeners` — `Config.load` on a
  `listeners`-bearing file yields `len(config.listeners)` matching the entries,
  with the right `transport`/`resolution`/`security` per listener.
- `test_load_legacy_flat_single_listener` — a flat proxy config yields one
  `ListenerConfig` equal to the parsed flat values.
- `test_load_listeners_with_flat_transport_is_rejected` — ambiguous config
  raises.
- `test_duplicate_transport_types_allowed` — two `unix` entries both load.
- `test_listener_resolution_is_per_listener` — `unix` → `certificate`, `vsock` →
  `tartarus`; `unix` + `tartarus` rejected.
- `test_run_proxy_binds_two_unix_listeners` — real AF_UNIX round-trip on each
  listener; both are cleaned up on shutdown.
- `test_create_ssl_context_is_per_listener` — a `none` listener gets `None`, an
  `mtls` listener gets a context, in the same `Config`.

### 7.3 Eval tests — `tests/suite.nix` (+ `tests/default.nix` runner)

Add fixtures and checks (all pure evaluation; no builds):

- `hostSudoMixedTransports` — two enabled host guests requesting
  `sudoAuthProxy`: one `vsock` (Linux VM), one `tcp` (a `disableVsock`/container
  guest). Check
  `(config.home-manager.users.user.tartarus.sudo-auth-proxy.server.listeners)`
  contains both `type = "vsock"` and `type = "tcp"`, and that evaluation
  succeeds (no throw, no warn is structurally observable — the absence of the
  `throw` is the check).
- `hostSudoUnixPlusCallback` — one guest `sudoAuthProxyTransport = "unix"` and
  one default `vsock`; assert `listeners` contains both `unix` and `vsock`
  entries (the old `throw` case now evaluates).
- `hostSshMixedTransports` / `hostSshUnixPlusCallback` — the ssh analogues on
  `tartarus.ssh-agent-proxy.server.listeners`.
- `hostStandInTcpOnly` — a stand-in VM (container-host with an inner container
  requesting sudo) yields exactly one `tcp` listener (regression guard for §5).
- `standalone/hm-sudo-auth-proxy-listeners` — a standalone HM config sets
  `server.listeners = [ {type="unix"; socket="…";} {type="tcp"; host="127.0.0.1"; port=65001;} ]`
  and evaluates (`hmDrvOk`).
- `standalone/hm-ssh-agent-proxy-listeners` — the ssh analogue
  (`hmDrvOk`).
- `standalone/nixos-ssh-agent-proxy-listeners` — a standalone NixOS config with
  a `listeners` list (`nixosDrvOk`).
- `server-requires-a-listener` — `server.enable = true` with
  `listeners = []` fails evaluation (the assertion in §2.4).
- Update the existing `standalone/nixos-ssh-agent-proxy-*` fixtures
  (`-unix`, `-mtls-conflict`, `-unix-bad-resolution`) to the `listeners` shape;
  their intent (standalone eval, mTLS conflict, unix+bad-resolution) is
  preserved per-listener.

Golden TOML shape check (build-forcing, outside the pure eval suite): the
`checks.<system>."tartarus-sudo-auth-proxy-toml-shape"` derivation in
`nix/default.nix` builds a standalone HM config's generated
`sudo-auth-proxy-server.toml` and asserts two `[[listeners]]` headers, no
`[listener_defaults]` block, and both `transport_encryption = "mtls"` and
`"none"`. (Equivalently, a Python test that re-renders the same attrset via
`pkgs.formats.toml`; the Nix check is preferred because it pins exactly what the
module emits.)

### 7.4 Commands

- Python: `python -m pytest tests/test_sudo_auth_proxy.py tests/test_ssh_agent_proxy.py -q`
  (and the full `python -m pytest -q`).
- Eval suite: `nix eval --impure --file tests/default.nix --json`.
- Whole flake: `nix flake check --all-systems --impure`.

---

## 8. Docs plan

- **`docs/technical/sudo-auth-proxy.md`** — §3 (Transports, call direction) gains a
  "multiple listeners" subsection; §7.9 (schema keys) lists the self-contained
  `listeners` entries and their keys; §14 (compatibility & migration) documents
  the flat-option removal and the Python legacy fallback; §15 (operations)
  examples show a `listeners` array. The old "single socket / mixed transports"
  language is removed.
- **`docs/technical/ssh-agent-proxy.md`** — the server section describes
  self-contained `listeners` entries, per-listener `resolution`, and the
  always-present `vm`/`tcp_vm` maps; the bridge section is unchanged.
- **`README.md`** — §"Standalone use of the services" server row mentions
  `server.listeners` (a list) instead of a single `transport`; the packaging
  example gains a two-listener snippet; a note that the mixed-transport warning
  is gone.
- **`examples/`** — one complete multi-listener
  `examples/sudo-auth-proxy-server.toml` (vsock + tcp + unix) and one
  `examples/ssh-agent-proxy-server.toml`; entries are self-contained and the
  legacy flat form still works (single implicit listener) for hand-written
  configs.
- Option-description strings in both `default.nix` files are part of the docs
  surface and must be updated with the options.

---

## 9. Task breakdown

Each task owns disjoint files and is independently assignable. Dependencies are
listed; parallel groups are noted. Acceptance commands are exact.

### T1 — sudo-auth-proxy Python multi-listener
- **Owns:** `nix/packages/sudo-auth-proxy/sudo-auth-proxy.py`,
  `tests/test_sudo_auth_proxy.py`.
- **Depends on:** none.
- **Work:** implement `listener_views`, `validate_document_schema`, the new
  `run_server` (bind-all-then-serve, `_close_listener`), and path resolution for
  `listeners[*].mtls` in `load_config`; keep
  `make_transport`/`build_security`/`create_ssl_context`/`Handler` as described.
  Add the §7.1 tests.
- **Acceptance:** `python -m pytest tests/test_sudo_auth_proxy.py -q` passes;
  the existing single-listener and legacy tests still pass; the new
  multi-listener tests pass.

### T2 — ssh-agent-proxy Python multi-listener
- **Owns:** `nix/packages/ssh-agent-proxy/ssh-agent-proxy.py`,
  `tests/test_ssh_agent_proxy.py`.
- **Depends on:** none.
- **Work:** add `ListenerConfig`, `Config.listeners`, `_parse_listener` /
  `_parse_listener_from_flat`, `_bind_listener`, the multi-listener `run_proxy`,
  and the `Handler.setup` per-listener `resolution` read; leave
  `run_client` untouched. Add the §7.2 tests.
- **Acceptance:** `python -m pytest tests/test_ssh_agent_proxy.py -q` passes,
  including the existing client/bridge tests (byte-for-byte behaviour).

### T3 — sudo-auth-proxy Nix schema + emission
- **Owns:** `nix/packages/sudo-auth-proxy/default.nix`.
- **Depends on:** none (schema-only; the Python reads the emitted TOML).
- **Work:** add `mkMtlsOptions`, add `mkListenerOptions` and `mkServerOptions`
  (`listeners`), remove the flat server options and `withSecurity`, update both
  `mkServerFiles`/`homeManagerModule` TOML emission to self-contained
  `[[listeners]]` entries with `pruneNulls`, update the assertions per §2.4.
- **Acceptance:** `nix eval --impure --file tests/default.nix --json` evaluates
  the updated standalone HM fixture (T6, if landed) — until then, a local
  `nix eval` of the module renders the expected TOML. The generated TOML parses
  with `python -c 'import tomllib,sys; tomllib.load(open(sys.argv[1],"rb"))'`.

### T4 — ssh-agent-proxy Nix schema + emission
- **Owns:** `nix/packages/ssh-agent-proxy/default.nix`.
- **Depends on:** none.
- **Work:** same as T3 for ssh (`sshListenerOptions`, no ACL), keep `settings`
  global, emit `connect_timeout`/`handshake_timeout`/`decision_timeout` at the
  listener level, update `mkServerSettings` to a per-listener renderer, fix the
  NixOS + HM emitters, update assertions per entry.
- **Acceptance:** local `nix eval` of the module renders the expected TOML;
  generated TOML parses with `tomllib`; existing standalone ssh fixtures (after
  T6) still evaluate.

### T5 — host wiring
- **Owns:** `nix/host/services.nix`.
- **Depends on:** T3, T4 (the option names it sets must exist).
- **Work:** remove `mkTransport`/`sudoTransport`/`sshTransport`/the warn/the
  throw; build `listeners` lists from `sudoKinds`/`sshKinds`; keep
  `transportOf`/`mkTcpHost`/`guestId`/`guestIP`/stand-in logic; always emit
  `settings.vm`/`settings.tcp_vm`.
- **Acceptance:** the T6 eval fixtures pass; no `lib.warn`/`throw` for a mixed
  transport set; a stand-in VM still yields a single `tcp` listener.

### T6 — eval tests
- **Owns:** `tests/suite.nix`, `tests/default.nix`.
- **Depends on:** T3, T4, T5.
- **Work:** add the fixtures and checks in §7.3; update the existing ssh
  standalone fixtures to `listeners`.
- **Acceptance:** `nix eval --impure --file tests/default.nix --json` lists the
  new checks in `passed` and fails otherwise.

### T7 — examples + golden TOML
- **Owns:** `examples/sudo-auth-proxy-server.toml`,
  `examples/ssh-agent-proxy-server.toml`, and the golden-shape derivation in
  `nix/default.nix`.
- **Depends on:** T1, T2, T3, T4.
- **Work:** write the new multi-listener examples (self-contained entries); add
  the `checks.<system>."tartarus-sudo-auth-proxy-toml-shape"` derivation; add
  `test_shipped_multi_listener_example_parses` cross-references.
- **Acceptance:** the example configs load in Python (T1/T2 tests) and the
  golden check finds two `[[listeners]]` headers and no `[listener_defaults]`.

### T8 — documentation
- **Owns:** `docs/technical/sudo-auth-proxy.md`, `docs/technical/ssh-agent-proxy.md`, `README.md`,
  the option descriptions.
- **Depends on:** T3, T4, T5, T7 (to document the final shape).
- **Work:** apply §8.
- **Acceptance:** docs describe self-contained `listeners` entries and the
  Python legacy fallback; no remaining "single socket / mixed transport" claims
  and no `listener_defaults` presented as current.

### T9 — verification
- **Owns:** none (read-only + reports).
- **Depends on:** T1–T8.
- **Work:** run the full gates; trace every acceptance criterion in this spec to
  a test or a checked command; explicitly verify that (a) the warn and throw are
  gone, (b) mixed `vsock`+`tcp` and `unix`+callback hosts evaluate, (c) two unix
  listeners with different `[[rule]]` scope run in one process, (d) the legacy
  flat Python config still serves, (e) client/bridge behaviour is unchanged, and
  (f)
  `nix/host/firewall.nix` still opens the tcp port for a tcp listener.
- **Acceptance:**
  `python -m pytest -q` **and**
  `nix eval --impure --file tests/default.nix --json` **and**
  `nix flake check --all-systems --impure` all pass; the verification report
  lists each criterion with its evidence.

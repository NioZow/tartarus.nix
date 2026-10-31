# clipboard-bridge: a secure clipboard bridge. Exposed as a standalone package
# plus a NixOS module (server as a system service) and a home-manager module
# (server, guest-side client and ad-hoc admin client). Units use `nix-service`.
#
# The server mirrors `sudo-auth-proxy` / `ssh-agent-proxy`: one process binds N
# self-contained `[[listeners]]`, each with its own transport, security, mTLS
# material, identity resolution, socket modes and resource bounds. Clients keep
# a single transport. There is no shared secret and no flat server form.
#
#   tartarus.clipboard-bridge.server       server (host side)
#   tartarus.clipboard-bridge.client       guest-side client + CLI config
#   tartarus.clipboard-bridge.adminClient  ad-hoc admin CLI config (host side)
{inputs}: let
  # Clipboard EKU OIDs (sudo-auth-proxy subtree convention).
  clipboardServerOid = "1.3.6.1.4.1.99999.3.1";
  clipboardClientOid = "1.3.6.1.4.1.99999.3.2";
  clipboardAdminOid = "1.3.6.1.4.1.99999.3.3";

  mkPackage = {
    pkgs,
    lib ? pkgs.lib,
  }: let
    pythonEnv = pkgs.python3.withPackages (ps: [ps.cryptography]);
  in
    pkgs.writeShellApplication {
      name = "clipboard-bridge";
      runtimeInputs =
        [pythonEnv]
        ++ lib.optionals pkgs.stdenv.isLinux [pkgs.wl-clipboard];
      text = ''
        exec ${pythonEnv.interpreter} -P ${./clipboard-bridge.py} "$@"
      '';
    };

  # nix-service's factory, built from an external `system` signal (see the
  # sudo-auth-proxy module for why it must not derive isDarwin from `pkgs`).
  mkServiceFor = {
    lib,
    isDarwin,
    username,
    homeManager,
  }:
    inputs.nix-service.lib.mkService {
      inherit lib isDarwin username homeManager;
    };

  # Reusable `[security]` option set. A server listener and a client (single
  # transport) share this exact shape; every knob carries its real default, so
  # a listener entry that omits it is self-contained.
  mkSecurityOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
    transportEncryption = mkOption {
      type = types.enum ["auto" "none" "mtls"];
      default = "auto";
      description = ''
        Whether the byte stream is encrypted and integrity-protected. `auto`
        (default) follows the transport type: `tcp` → `mtls`, `vsock`/`unix` →
        `none`. An explicit `mtls` is never a runtime fallback.
      '';
    };
    clientAuth = mkOption {
      type = types.enum ["transport" "none"];
      default = "transport";
      description = ''
        How the server authenticates the requester. `transport` comes from the
        mTLS handshake and is forced whenever the transport is mTLS; `none`
        disables requester authentication entirely and is only appropriate on a
        transport that is private by construction (vsock, local Unix socket).
        With `transport_encryption = "none"` both auth knobs must be `none`
        explicitly: authentication is never disabled implicitly.
      '';
    };
    serverAuth = mkOption {
      type = types.enum ["transport" "none"];
      default = "transport";
      description = ''
        How the client authenticates the server's messages. `transport`
        requires `transport_encryption = "mtls"` (and is then forced); `none`
        means nothing authenticates the response and is only accepted alongside
        `clientAuth = "none"`.
      '';
    };
  };

  # Reusable `[mtls]` option set for one listener (or one client transport).
  # `certType` selects the local certificate defaults (server vs client); every
  # field carries its real default so the entry is self-contained.
  mkMtlsOptions = {
    lib,
    requiredOid,
    peerOid,
    certType ? "server",
  }: let
    inherit (lib) mkOption types;
    isClient = certType == "client";
  in {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable mutual TLS for this listener/client. Equivalent to `security.transportEncryption = \"mtls\"`.";
    };
    caFile = mkOption {
      type = types.str;
      default = "./ca.crt";
      description = "Path to the CA certificate. Relative to the config file directory.";
    };
    certFile = mkOption {
      type = types.str;
      default =
        if isClient
        then "./client.crt"
        else "./server.crt";
      description =
        if isClient
        then "Path to this client's certificate. Relative to the config file directory."
        else "Path to the server certificate. Relative to the config file directory.";
    };
    keyFile = mkOption {
      type = types.str;
      default =
        if isClient
        then "./client.key"
        else "./server.key";
      description =
        if isClient
        then "Path to this client's private key. Relative to the config file directory."
        else "Path to the server private key. Relative to the config file directory.";
    };
    requiredOid = mkOption {
      type = types.str;
      default = requiredOid;
      description = "EKU OID the local certificate must contain.";
    };
    peerOid = mkOption {
      type = types.str;
      default = peerOid;
      description = "EKU OID the peer certificate must contain.";
    };
  };

  # Reusable `pubkey` (no-CA) option set. Each side presents a self-signed
  # leaf; `trustedPeerCerts` is concatenated into the emitted `[mtls] ca_file`
  # trust bundle, so the peer certificate is the trust anchor and no CA exists.
  # Mutually exclusive with `mtls`; forces mTLS.
  mkPubkeyOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
    certFile = mkOption {
      type = types.path;
      description = "This side's self-signed certificate (public; usually a Nix store path).";
    };
    keyFile = mkOption {
      type = types.path;
      description = "This side's private key (local or /etc; never in the Nix store).";
    };
    trustedPeerCerts = mkOption {
      type = types.nonEmptyListOf types.path;
      description = "One or more peer self-signed certificates to whitelist; concatenated into the `ca_file` trust bundle.";
    };
    requiredOid = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "EKU OID the local certificate must contain. Defaults to the role's OID.";
    };
    peerOid = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "EKU OID the peer certificate must contain. Defaults to the role's OID.";
    };
  };

  # The client-side `[acl]`: which server certificate the client trusts. Crypto
  # material only (never request metadata); enforced after the TLS handshake.
  mkAclOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
    trustedFingerprints = mkOption {
      type = types.listOf types.str;
      default = [];
      description = ''
        Server leaf SubjectPublicKeyInfo fingerprints (`SHA256:...`) the client
        will accept. A match is authoritative on its own.
      '';
    };
    trustedNames = mkOption {
      type = types.listOf types.str;
      default = [];
      description = ''
        `fnmatch` patterns matched against the server certificate's CN/DNS SAN.
        A match is authoritative on its own.
      '';
    };
  };

  # Ordered `[[rule]]` authorization rules. First match wins, there is no
  # merging, and no match denies (fail-closed). `policy` defaults to `deny`.
  mkRuleType = lib:
    lib.types.listOf (lib.types.submodule {
      options = {
        match = lib.mkOption {
          type = lib.types.submodule {
            options = {
              listeners = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [];
                description = ''
                  Listener name patterns (fnmatch). Empty matches every
                  listener; an unnamed listener matches only an empty selector
                  or one made exclusively of `*` patterns.
                '';
              };
              machine = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [];
                description = "Resolved peer identity patterns (fnmatch). Empty matches any identity.";
              };
              action = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [];
                description = "Protocol action patterns (fnmatch), e.g. `clients`, `get`, `set`.";
              };
              target = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [];
                description = "Admin target client-id patterns (fnmatch). Empty matches any target.";
              };
            };
          };
          default = {};
        };
        policy = lib.mkOption {
          type = lib.types.enum ["allow" "deny"];
          default = "deny";
          description = ''
            Decision for a matching admin request. Rules are evaluated in order
            and the first match wins; no match denies by default.
          '';
        };
      };
    });

  # One per-listener option set. Every entry is self-contained (there is no
  # `[listener_defaults]` block); `type` is required and `name` is the optional
  # label `rule.*.match.listeners` selects on.
  mkListenerOptions = {
    lib,
    requiredOid,
    peerOid,
  }: let
    inherit (lib) mkOption types;
  in {
    type = mkOption {
      type = types.enum ["vsock" "tcp" "unix"];
      description = "Transport this listener binds (required for every entry).";
    };
    name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Optional name for this listener, unique across the server.
        `rule.*.match.listeners` selects listeners by this name.
      '';
    };
    admin = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Mark this listener as an admin/control-plane listener. It accepts
        `clients`, targeted `get`/`set` and `--json`, rejects
        `register`/`subscribe`, and authorizes every request through the
        ordered `[[rule]]` engine.
      '';
    };
    port = mkOption {
      type = types.port;
      default = 27795;
      description = "Port the listener binds. Used with tcp/vsock.";
    };
    cid = mkOption {
      type = types.int;
      default = 2;
      description = "VSOCK context ID to bind to (2 = host). Only used with vsock.";
    };
    host = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "TCP address to bind to. Only used with tcp.";
    };
    socket = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Unix socket the listener binds. Required when type is `unix`.";
    };
    socketDirMode = mkOption {
      type = types.str;
      default = "0700";
      description = "Mode of the unix socket's parent directory.";
    };
    socketMode = mkOption {
      type = types.str;
      default = "0600";
      description = "Mode of the unix server socket.";
    };
    resolution = mkOption {
      type = types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"]);
      default = null;
      description = ''
        How to resolve a connecting peer's name for `match.machine`: `none`,
        `certificate` (verified peer cert CN/SAN), `tartarus` (local VM
        bookkeeping via `[[vm]]`/`[[tcp_vm]]`), or `mofos` (`mofos ls --json`).
        `tartarus`/`mofos` are rejected on a `unix` listener.
      '';
    };
    connectTimeout = mkOption {
      type = types.float;
      default = 5.0;
      description = "Seconds to wait for the transport connect before failing fast.";
    };
    handshakeTimeout = mkOption {
      type = types.float;
      default = 10.0;
      description = "Seconds to wait for the TLS handshake before failing fast.";
    };
    maxConnections = mkOption {
      type = types.ints.positive;
      default = 100;
      description = "Maximum number of concurrently served connections for this listener.";
    };
    serverReadTimeout = mkOption {
      type = types.float;
      default = 60.0;
      description = "Seconds an accepted connection may stall before it is dropped.";
    };
    security = mkSecurityOptions {inherit lib;};
    mtls = mkMtlsOptions {
      inherit lib requiredOid peerOid;
      certType = "server";
    };
    pubkey = mkOption {
      type = types.nullOr (types.submodule {options = mkPubkeyOptions {inherit lib;};});
      default = null;
      description = ''
        No-CA trust mode: a self-signed server certificate whose peer is
        whitelisted by certificate. Mutually exclusive with `mtls`; setting it
        forces the effective transport to mTLS.
      '';
    };
  };

  # Reusable client option set. `client` and `adminClient` both use it; only
  # `enable`/`configPath` differ. `registerDefault` is false for the admin
  # client because an admin listener rejects `register`.
  mkClientOptions = {
    lib,
    registerDefault ? true,
    requiredOid ? clipboardClientOid,
    peerOid ? clipboardServerOid,
    proxySocketDefault ? "%t/clipboard-bridge-proxy",
  }: let
    inherit (lib) mkEnableOption mkOption types;
  in {
    waylandDisplay = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Wayland display to use; unset to inherit the session's.";
    };
    autostart = mkOption {
      type = types.bool;
      default = true;
      description = "Autostart the client daemon at login.";
    };
    transport = mkOption {
      type = types.enum ["tcp" "vsock" "unix"];
      default = "tcp";
      description = "Transport to connect over.";
    };
    host = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "TCP host to connect to. Only used when transport is tcp.";
    };
    port = mkOption {
      type = types.port;
      default = 27795;
      description = "Port to connect to. Used with tcp/vsock.";
    };
    vsockCid = mkOption {
      type = types.int;
      default = 2;
      description = "VSOCK CID to connect to. Only used when transport is vsock.";
    };
    socket = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Unix socket path. Only used when transport is unix.";
    };
    security = mkSecurityOptions {inherit lib;};
    mtls = mkMtlsOptions {
      inherit lib requiredOid peerOid;
      certType = "client";
    };
    pubkey = mkOption {
      type = types.nullOr (types.submodule {options = mkPubkeyOptions {inherit lib;};});
      default = null;
      description = ''
        No-CA trust mode: a self-signed client certificate whose server is
        whitelisted by certificate. Mutually exclusive with `mtls`.
      '';
    };
    acl = mkAclOptions {inherit lib;};
    connectTimeout = mkOption {
      type = types.float;
      default = 5.0;
      description = "Seconds to wait for the transport connect before failing fast.";
    };
    handshakeTimeout = mkOption {
      type = types.float;
      default = 10.0;
      description = "Seconds to wait for the TLS handshake before failing fast.";
    };
    recvTimeout = mkOption {
      type = types.float;
      default = 60.0;
      description = "Seconds to wait for the first response bytes.";
    };
    register = mkOption {
      type = types.bool;
      default = registerDefault;
      description = "Advertise this client at startup so it appears in `clients`.";
    };
    proxy = {
      enable = mkEnableOption ''
        a persistent local connection-reuse proxy: a background service holds
        one already-authenticated connection to the server and ad-hoc CLI
        invocations connect to it over a local unix socket
      '';
      socketPath = mkOption {
        type = types.str;
        default = proxySocketDefault;
        description = "Local unix socket the proxy listens on.";
      };
    };
    debug = mkOption {
      type = types.bool;
      default = false;
      description = "Log connection/handshake/request timing to stderr.";
    };
    extraSettings = mkOption {
      type = types.attrs;
      default = {};
      description = "Extra top-level keys merged into the generated TOML configuration.";
    };
  };

  mkVmType = lib:
    lib.types.listOf (lib.types.submodule {
      options = {
        cid = lib.mkOption {
          type = lib.types.int;
          description = "The guest's VSOCK context ID (CID).";
        };
        name = lib.mkOption {
          type = lib.types.str;
          description = "VM name, matched against rule.match.machine.";
        };
      };
    });

  mkTcpVmType = lib:
    lib.types.listOf (lib.types.submodule {
      options = {
        ip = lib.mkOption {
          type = lib.types.str;
          description = "Guest source IP address, e.g. 10.200.0.3.";
        };
        name = lib.mkOption {
          type = lib.types.str;
          description = "VM name, matched against rule.match.machine.";
        };
      };
    });

  # Recursively drop `null` attributes. Needed because `pkgs.formats.toml`
  # (json2toml) refuses `null`, and a listener's `name`/`resolution` are
  # optional (`nullOr`).
  mkPruneNulls = lib: let
    prune = v:
      if builtins.isAttrs v
      then lib.mapAttrs (_: prune) (lib.filterAttrs (_: x: x != null) v)
      else if builtins.isList v
      then map prune v
      else v;
  in
    prune;

  # Resolve the effective (transport_encryption, client_auth, server_auth)
  # triple. This mirrors the Python exactly: `mtls.enable` forces mTLS; `auto`
  # follows the type (tcp → mtls else none); mTLS forces both auths to
  # "transport".
  resolveSecurity = {
    type,
    security,
    mtlsEnabled,
  }: let
    effectiveTransportEncryption =
      if mtlsEnabled
      then "mtls"
      else if security.transportEncryption != "auto"
      then security.transportEncryption
      else if type == "tcp"
      then "mtls"
      else "none";
    forceTransportAuth = effectiveTransportEncryption == "mtls";
    effectiveClientAuth =
      if forceTransportAuth
      then "transport"
      else security.clientAuth;
    effectiveServerAuth =
      if forceTransportAuth
      then "transport"
      else security.serverAuth;
  in {
    inherit
      effectiveTransportEncryption
      effectiveClientAuth
      effectiveServerAuth
      ;
  };

  # Resolve one listener entry from the entry alone, exactly as the server
  # renderer and the Python do.
  resolveListener = entry:
    resolveSecurity {
      type = entry.type;
      security = entry.security;
      mtlsEnabled = entry.mtls.enable || entry.pubkey != null;
    };

  # Resolve one client document from the client alone (a client has a single
  # `transport` in place of a listener `type`).
  resolveClient = client:
    resolveSecurity {
      type = client.transport;
      security = client.security;
      mtlsEnabled = client.mtls.enable || client.pubkey != null;
    };

  # One self-contained `[[listeners]]` entry: bind target, socket modes,
  # timeouts, resolved `[security]` and, when it resolves to mTLS, its own
  # `[mtls]` block.
  renderListener = {
    lib,
    pkgs,
    entry,
  }: let
    prune = mkPruneNulls lib;
    resolved = resolveListener entry;
    security = {
      transport_encryption = resolved.effectiveTransportEncryption;
      client_auth = resolved.effectiveClientAuth;
      server_auth = resolved.effectiveServerAuth;
    };
    mtlsSection = lib.optionalAttrs (resolved.effectiveTransportEncryption == "mtls") {
      mtls =
        if entry.pubkey != null
        then {
          enable = true;
          ca_file = pkgs.concatText "trusted-peer-certs.pem" entry.pubkey.trustedPeerCerts;
          cert_file = entry.pubkey.certFile;
          key_file = entry.pubkey.keyFile;
          required_oid =
            if entry.pubkey.requiredOid != null
            then entry.pubkey.requiredOid
            else entry.mtls.requiredOid;
          peer_required_oid =
            if entry.pubkey.peerOid != null
            then entry.pubkey.peerOid
            else entry.mtls.peerOid;
        }
        else {
          enable = true;
          ca_file = entry.mtls.caFile;
          cert_file = entry.mtls.certFile;
          key_file = entry.mtls.keyFile;
          required_oid = entry.mtls.requiredOid;
          peer_required_oid = entry.mtls.peerOid;
        };
    };
  in
    prune (
      {type = entry.type;}
      // lib.optionalAttrs (entry.name != null) {name = entry.name;}
      // lib.optionalAttrs entry.admin {admin = true;}
      // lib.optionalAttrs (entry.type == "tcp") {
        host = entry.host;
        port = entry.port;
      }
      // lib.optionalAttrs (entry.type == "vsock") {
        cid = entry.cid;
        port = entry.port;
      }
      // lib.optionalAttrs (entry.type == "unix") {
        socket = entry.socket;
        socket_dir_mode = entry.socketDirMode;
        socket_mode = entry.socketMode;
      }
      // {
        connect_timeout = entry.connectTimeout;
        handshake_timeout = entry.handshakeTimeout;
        max_connections = entry.maxConnections;
        server_read_timeout = entry.serverReadTimeout;
      }
      // lib.optionalAttrs (entry.resolution != null) {resolution = entry.resolution;}
      // {security = security;}
      // mtlsSection
    );

  # One `[[rule]]` entry: `match` carries only the selectors that are set,
  # plus the policy. Emitted document-level, never per listener.
  renderRule = {
    lib,
    rule,
  }: {
    match =
      lib.optionalAttrs (rule.match.listeners != []) {listeners = rule.match.listeners;}
      // lib.optionalAttrs (rule.match.machine != []) {machine = rule.match.machine;}
      // lib.optionalAttrs (rule.match.action != []) {action = rule.match.action;}
      // lib.optionalAttrs (rule.match.target != []) {target = rule.match.target;};
    policy = rule.policy;
  };

  # The whole server TOML document: `mode`, the global VM maps, one
  # self-contained `[[listeners]]` per listener, optional rules and debug, then
  # `extraSettings`.
  renderServerToml = {
    lib,
    pkgs,
    server,
  }: let
    prune = mkPruneNulls lib;
    document =
      {mode = server.mode;}
      // lib.optionalAttrs (server.settings.vm != []) {vm = server.settings.vm;}
      // lib.optionalAttrs (server.settings.tcp_vm != []) {tcp_vm = server.settings.tcp_vm;}
      // lib.optionalAttrs (server.settings.labels != {}) {labels = server.settings.labels;}
      // lib.optionalAttrs server.debug {debug = true;}
      // lib.optionalAttrs (server.rule != []) {rule = map (rule: renderRule {inherit lib rule;}) server.rule;}
      // {listeners = map (entry: renderListener {inherit lib pkgs entry;}) server.listeners;}
      // server.extraSettings;
  in
    prune document;

  # The whole client TOML document: one transport, the resolved `[security]`
  # triple, an optional `[mtls]` block, an optional `[acl]`, the connection
  # bounds and `extraSettings`.
  renderClientToml = {
    lib,
    pkgs,
    client,
  }: let
    prune = mkPruneNulls lib;
    resolved = resolveClient client;
    security = {
      transport_encryption = resolved.effectiveTransportEncryption;
      client_auth = resolved.effectiveClientAuth;
      server_auth = resolved.effectiveServerAuth;
    };
    connection =
      {transport = client.transport;}
      // lib.optionalAttrs (client.transport == "tcp") {
        host = client.host;
        port = client.port;
      }
      // lib.optionalAttrs (client.transport == "vsock") {
        cid = client.vsockCid;
        port = client.port;
      }
      // lib.optionalAttrs (client.transport == "unix" && client.socket != null) {
        socket = client.socket;
      };
    mtlsSection = lib.optionalAttrs (resolved.effectiveTransportEncryption == "mtls") {
      mtls =
        if client.pubkey != null
        then {
          enable = true;
          ca_file = pkgs.concatText "trusted-peer-certs.pem" client.pubkey.trustedPeerCerts;
          cert_file = client.pubkey.certFile;
          key_file = client.pubkey.keyFile;
          required_oid =
            if client.pubkey.requiredOid != null
            then client.pubkey.requiredOid
            else client.mtls.requiredOid;
          peer_required_oid =
            if client.pubkey.peerOid != null
            then client.pubkey.peerOid
            else client.mtls.peerOid;
        }
        else {
          enable = true;
          ca_file = client.mtls.caFile;
          cert_file = client.mtls.certFile;
          key_file = client.mtls.keyFile;
          required_oid = client.mtls.requiredOid;
          peer_required_oid = client.mtls.peerOid;
        };
    };
    aclSection = lib.optionalAttrs (client.acl.trustedFingerprints != [] || client.acl.trustedNames != []) {
      acl = {
        trusted_fingerprints = client.acl.trustedFingerprints;
        trusted_names = client.acl.trustedNames;
      };
    };
    document =
      {mode = "client";}
      // connection
      // {security = security;}
      // mtlsSection
      // aclSection
      // lib.optionalAttrs client.register {register = true;}
      // lib.optionalAttrs client.proxy.enable {proxy_socket = client.proxy.socketPath;}
      // lib.optionalAttrs client.debug {debug = true;}
      // {
        connect_timeout = client.connectTimeout;
        handshake_timeout = client.handshakeTimeout;
        recv_timeout = client.recvTimeout;
      }
      // client.extraSettings;
  in
    prune document;

  # Per-listener assertions for one server instance. Every entry must satisfy
  # `transport_encryption = "none" ⇒ client_auth = server_auth = "none"`,
  # resolving the auths from the entry itself so one that only sets
  # `transportEncryption = "none"` fails loudly. Enabled servers need listeners;
  # names must be unique; `tartarus`/`mofos` are invalid on `unix`; an admin
  # mTLS listener must use the admin peer OID.
  mkServerAssertions = {
    lib,
    server,
    topLevelEnable ? false,
  }: let
    enabled = topLevelEnable || server.enable;
    namedListeners = lib.filter (n: n != null) (map (e: e.name) server.listeners);
    duplicateNames = lib.unique (
      lib.filter (n: lib.count (m: m == n) namedListeners > 1) namedListeners
    );
    perEntry = entry: let
      resolved = resolveListener entry;
      # The peer OID actually emitted under `[mtls]`: an explicit pubkey peer
      # OID wins, otherwise the mtls (role-default) value is used.
      effectivePeerOid =
        if entry.pubkey != null && entry.pubkey.peerOid != null
        then entry.pubkey.peerOid
        else entry.mtls.peerOid;
    in [
      {
        assertion =
          resolved.effectiveTransportEncryption
          != "none"
          || (resolved.effectiveClientAuth == "none" && resolved.effectiveServerAuth == "none");
        message = ''
          tartarus.clipboard-bridge.server.listeners: transport_encryption = "none"
          requires client_auth = server_auth = "none" (entry type = ${entry.type}).
        '';
      }
      {
        assertion =
          resolved.effectiveTransportEncryption
          != "mtls"
          || (resolved.effectiveClientAuth == "transport" && resolved.effectiveServerAuth == "transport");
        message = ''
          tartarus.clipboard-bridge.server.listeners: mTLS forces
          client_auth = server_auth = "transport" (entry type = ${entry.type}).
        '';
      }
      {
        assertion =
          !(entry.type == "unix" && (entry.resolution == "tartarus" || entry.resolution == "mofos"));
        message = "tartarus.clipboard-bridge.server.listeners: the unix listener only supports resolution = \"none\" or \"certificate\" (entry type = \"unix\").";
      }
      {
        assertion =
          !(entry.resolution == "certificate" && resolved.effectiveTransportEncryption != "mtls");
        message = ''
          tartarus.clipboard-bridge.server.listeners: resolution = "certificate"
          requires transport_encryption = "mtls" (entry type = ${entry.type}).
        '';
      }
      {
        assertion =
          !(entry.mtls.enable && entry.security.transportEncryption == "none");
        message = ''
          tartarus.clipboard-bridge.server.listeners: mtls.enable = true
          conflicts with security.transportEncryption = "none"; remove the
          explicit "none" or disable mTLS (entry type = ${entry.type}).
        '';
      }
      {
        assertion =
          !(entry.type == "unix" && (entry.socket == null || entry.socket == ""));
        message = "tartarus.clipboard-bridge.server.listeners: a unix listener requires a non-empty socket path.";
      }
      {
        assertion =
          !(entry.admin
            && resolved.effectiveTransportEncryption == "mtls"
            && effectivePeerOid != clipboardAdminOid);
        message = ''
          tartarus.clipboard-bridge.server.listeners: an admin listener that
          resolves to mTLS must use the admin peer OID ${clipboardAdminOid}.
        '';
      }
      {
        assertion = !(entry.pubkey != null && entry.mtls.enable);
        message = "tartarus.clipboard-bridge.server.listeners: pubkey and mtls are mutually exclusive (entry type = ${entry.type}).";
      }
    ];
  in
    lib.concatMap perEntry server.listeners
    ++ lib.optional (enabled && server.listeners == []) {
      assertion = false;
      message = "tartarus.clipboard-bridge.server.enable = true requires at least one entry in server.listeners.";
    }
    ++ lib.optional (duplicateNames != []) {
      assertion = false;
      message = "tartarus.clipboard-bridge.server.listeners: duplicate listener name(s): ${lib.concatStringsSep ", " duplicateNames}.";
    };

  # The client-side no-implicit-auth-disable rule plus the transport-specific
  # invariants, for either client. The admin client additionally pins its own
  # required EKU to the admin OID, so a Nix-rendered certificate admin cannot
  # silently default to the guest certificate OID.
  mkClientAssertions = {
    lib,
    client,
    admin ? false,
  }: let
    resolved = resolveClient client;
    # The required OID actually emitted under `[mtls]`: an explicit pubkey OID
    # wins, otherwise the mtls (role-default) value is used.
    effectiveRequiredOid =
      if client.pubkey != null && client.pubkey.requiredOid != null
      then client.pubkey.requiredOid
      else client.mtls.requiredOid;
  in
    [
      {
        assertion =
          resolved.effectiveTransportEncryption
          != "none"
          || (client.security.clientAuth == "none" && client.security.serverAuth == "none");
        message = ''
          tartarus.clipboard-bridge client: transport_encryption = "none" requires
          security.clientAuth = "none" and security.serverAuth = "none".
          Authentication is never disabled implicitly; set both explicitly, or use
          transport_encryption = "mtls".
        '';
      }
      {
        assertion =
          !(client.mtls.enable && client.security.transportEncryption == "none");
        message = ''
          tartarus.clipboard-bridge client: mtls.enable = true conflicts with
          security.transportEncryption = "none"; remove the explicit "none" or
          disable mTLS.
        '';
      }
      {
        assertion =
          !(client.transport == "unix" && (client.socket == null || client.socket == ""));
        message = ''
          tartarus.clipboard-bridge client: transport = "unix" requires a
          non-empty socket path (a missing socket never silently dials TCP).
        '';
      }
      {
        assertion = !(client.pubkey != null && client.mtls.enable);
        message = "tartarus.clipboard-bridge client: pubkey and mtls are mutually exclusive; use one trust mode.";
      }
    ]
    ++ lib.optional
    (admin && resolved.effectiveTransportEncryption == "mtls" && effectiveRequiredOid != clipboardAdminOid) {
      assertion = false;
      message = ''
        tartarus.clipboard-bridge.adminClient: mTLS requires requiredOid =
        ${clipboardAdminOid} (the admin EKU); ${effectiveRequiredOid} would
        reject the admin certificate.
      '';
    };

  optionsModule = {
    config,
    lib,
    pkgs,
    ...
  }: let
    inherit
      (lib)
      mkEnableOption
      mkOption
      types
      ;
  in {
    options.tartarus.clipboard-bridge = {
      enable = mkEnableOption "the clipboard-bridge service (server role)";

      server = {
        enable = mkEnableOption "the clipboard-bridge server (host side)";

        mode = mkOption {
          type = types.enum ["server"];
          default = "server";
          description = "Configuration role. A server document always declares `mode = \"server\"`.";
        };

        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the generated server config. Defaults to `~/.config/clipboard-bridge/server.toml` (`/etc/clipboard-bridge/server.toml` on NixOS).";
        };

        listeners = mkOption {
          type = types.listOf (types.submodule {
            options = mkListenerOptions {
              inherit lib;
              requiredOid = clipboardServerOid;
              peerOid = clipboardClientOid;
            };
          });
          default = [];
          description = ''
            One entry per transport this server binds, all in the single server
            process. Every entry is self-contained, so there is no shared
            `[listener_defaults]` block. Multiple entries of the same `type` are
            allowed. Empty means the server binds nothing and, when enabled,
            the module rejects the configuration.
          '';
        };

        settings = mkOption {
          type = types.submodule {
            options = {
              vm = mkOption {
                type = mkVmType lib;
                default = [];
                description = "Static CID -> VM name map used by `resolution = \"tartarus\"` for VSOCK peers.";
              };
              tcp_vm = mkOption {
                type = mkTcpVmType lib;
                default = [];
                description = "Static peer IP -> VM name map used by `resolution = \"tartarus\"` for TCP peers.";
              };
              labels = mkOption {
                type = types.attrsOf types.str;
                default = {};
                description = "Fingerprint (`SHA256:...`) -> display-label map. Display/log only, never an authorization input.";
              };
            };
          };
          default = {};
          description = "Global (non-transport) contents of the server TOML: the `[[vm]]`/`[[tcp_vm]]` resolution maps and `[labels]`.";
        };

        rule = mkOption {
          type = mkRuleType lib;
          default = [];
          description = ''
            Ordered authorization rules (`[[rule]]`), evaluated against every
            listener; the first matching rule wins and no match denies. A rule
            scopes itself to a listener with `match.listeners`.
          '';
        };

        extraSettings = mkOption {
          type = types.attrs;
          default = {};
          description = "Extra top-level keys merged into the generated TOML configuration.";
        };

        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
      };

      client =
        {
          enable = mkEnableOption "the clipboard-bridge client (guest side)";
          configPath = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Path to the generated client config. Defaults to `~/.config/clipboard-bridge/client.toml`.";
          };
        }
        // mkClientOptions {inherit lib;};

      adminClient =
        {
          enable = mkEnableOption "an ad-hoc admin client config at the CLI's default admin path";
          configPath = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Path to the generated admin config. Defaults to `~/.config/clipboard-bridge/admin.toml`.";
          };
        }
        // mkClientOptions {
          inherit lib;
          registerDefault = false;
          requiredOid = clipboardAdminOid;
          peerOid = clipboardServerOid;
          proxySocketDefault = "%t/clipboard-bridge-admin-proxy";
        };
    };
  };
in {
  package = mkPackage;
  inherit optionsModule;

  nixosModule = {
    config,
    lib,
    pkgs,
    username ? "tartarus",
    ...
  }: let
    inherit (lib) mkIf mkMerge;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = false;
      homeManager = false;
    };
    cfg = config.tartarus.clipboard-bridge;
    server = cfg.server;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};
    configPath =
      if server.configPath != null
      then server.configPath
      else "/etc/clipboard-bridge/server.toml";
    configFile = tomlFormat.generate "clipboard-bridge-server.toml" (renderServerToml {inherit lib pkgs server;});
  in {
    imports = [optionsModule];

    config = mkIf (cfg.enable || server.enable) (mkMerge [
      {
        assertions = mkServerAssertions {
          inherit lib server;
          topLevelEnable = cfg.enable;
        };
      }
      (mkService {
        name = "clipboard-bridge-server";
        description = "Clipboard bridge server";
        command = "${package}/bin/clipboard-bridge --config ${configPath} serve --no-notify";
        scope = "system";
        # The server reads its config once at startup; restart it when the
        # generated document changes.
        extraSystemdUnitConfig = {
          X-Restart-Triggers = [configFile];
        };
      })
      {
        environment.etc."clipboard-bridge/server.toml".source = configFile;
        environment.systemPackages = [package];
      }
    ]);
  };

  homeManagerModule = {
    config,
    lib,
    pkgs,
    ...
  } @ args: let
    inherit
      (lib)
      mkIf
      mkMerge
      optionalAttrs
      ;
    system = args.system or builtins.currentSystem;
    username = config.home.username;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = lib.hasSuffix "-darwin" system;
      homeManager = true;
    };
    cfg = config.tartarus.clipboard-bridge;
    server = cfg.server;
    client = cfg.client;
    admin = cfg.adminClient;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};
    home = config.home.homeDirectory;

    serverConfigPath =
      if server.configPath != null
      then server.configPath
      else "${home}/.config/clipboard-bridge/server.toml";
    clientConfigPath =
      if client.configPath != null
      then client.configPath
      else "${home}/.config/clipboard-bridge/client.toml";
    adminConfigPath =
      if admin.configPath != null
      then admin.configPath
      else "${home}/.config/clipboard-bridge/admin.toml";

    serverConfigFile = tomlFormat.generate "clipboard-bridge-server.toml" (renderServerToml {inherit lib pkgs server;});
    clientConfigFile = tomlFormat.generate "clipboard-bridge-client.toml" (renderClientToml {inherit lib pkgs client;});
    adminConfigFile = tomlFormat.generate "clipboard-bridge-admin.toml" (renderClientToml {
      inherit lib pkgs;
      client = admin;
    });
  in {
    imports = [optionsModule];

    config = mkMerge [
      (mkIf (cfg.enable || server.enable || client.enable || admin.enable) {
        home.packages = [package];
      })

      (mkIf (cfg.enable || server.enable) (mkMerge [
        {
          assertions = mkServerAssertions {
            inherit lib server;
            topLevelEnable = cfg.enable;
          };
        }
        (mkService {
          name = "clipboard-bridge-server";
          description = "Clipboard bridge server";
          command = "${package}/bin/clipboard-bridge --config ${serverConfigPath} serve --no-notify";
          # The server reads its config once at startup; restart it when the
          # generated `[[listeners]]`/`security`/`[[rule]]` document changes.
          extraSystemdUnitConfig = {
            X-Restart-Triggers = [serverConfigFile];
          };
        })
        {home.file.${serverConfigPath}.source = serverConfigFile;}
      ]))

      (mkIf client.enable (mkMerge [
        {
          assertions = mkClientAssertions {inherit lib client;};
          home.file.".config/environment.d/70-tartarus-clipboard.conf".text = "CLIPBOARD_BRIDGE=1\n";
          home.file.${clientConfigPath}.source = clientConfigFile;
        }
        (mkService {
          name = "clipboard-bridge-client";
          description = "Clipboard bridge client";
          command = "${package}/bin/clipboard-bridge --config ${clientConfigPath} client";
          wantedBy =
            if client.autostart
            then null
            else [];
          environment =
            optionalAttrs (client.waylandDisplay != null) {
              WAYLAND_DISPLAY = client.waylandDisplay;
            }
            // {
              XDG_RUNTIME_DIR = "/run/user/%U";
            };
          extraSystemdUnitConfig = {
            X-Restart-Triggers = [clientConfigFile];
          };
        })
        (mkIf client.proxy.enable (mkService {
          name = "clipboard-bridge-proxy";
          description = "Clipboard bridge connection-reuse proxy";
          command = "${package}/bin/clipboard-bridge --config ${clientConfigPath} proxy";
          extraSystemdUnitConfig = {
            X-Restart-Triggers = [clientConfigFile];
          };
        }))
      ]))

      (mkIf admin.enable (mkMerge [
        {
          assertions = mkClientAssertions {
            inherit lib;
            client = admin;
            admin = true;
          };
          home.file.${adminConfigPath}.source = adminConfigFile;
        }
        (mkIf admin.proxy.enable (mkService {
          name = "clipboard-bridge-admin-proxy";
          description = "Clipboard bridge admin connection-reuse proxy";
          command = "${package}/bin/clipboard-bridge --config ${adminConfigPath} proxy";
          extraSystemdUnitConfig = {
            X-Restart-Triggers = [adminConfigFile];
          };
        }))
      ]))
    ];
  };
}

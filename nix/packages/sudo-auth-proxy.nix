# sudo-auth-proxy: a PAM client (guest side) that asks a remote server to
# confirm privilege elevation, plus the server itself (host side).
#
# Flattened from nixcfg's `modules/security/sudo-auth-proxy.nix` (PAM client)
# and `modules/services/user/sudo-auth-proxy.nix` (server). Exposed as a
# standalone package plus a NixOS module (PAM client) and a home-manager module
# (server). Every unit is created with `nix-service` (PLAN.md §3.7).
#
# Standalone exposure:
#   nixosModules."sudo-auth-proxy"       PAM client (legacy name, kept for nixcfg)
#   nixosModules."sudo-auth-proxy-pam"   same PAM client under an explicit name
#   homeManagerModules."sudo-auth-proxy" server (host side)
# Both NixOS outputs are the identical `pamNixosModule`; neither requires the
# tartarus host module or a tartarus guest.
#
#   tartarus.sudo-auth-proxy          PAM client (NixOS / guest)
#   tartarus.sudo-auth-proxy.server   server      (home-manager / host)
{inputs}: let
  # The standalone binary. `-P` keeps Python from scanning the store root for
  # the script's own directory (a multi-second listdir otherwise); see nixcfg's
  # packages/sudo-auth-proxy/default.nix for the original rationale.
  mkPackage = {
    pkgs,
    lib ? pkgs.lib,
  }: let
    pythonEnv = pkgs.python3.withPackages (ps: [ps.cryptography]);
  in
    pkgs.writeShellApplication {
      name = "sudo-auth-proxy";
      runtimeInputs =
        [pythonEnv]
        ++ lib.optionals (!pkgs.stdenv.isDarwin) [
          # zenity is the Linux dialog; macOS uses swiftDialog (not packaged
          # here) or osascript.
          pkgs.zenity
        ];
      text = ''
        exec ${pythonEnv.interpreter} -P ${./sources/sudo-auth-proxy.py} "$@"
      '';
    };

  # nix-service's factory. It must be built from an *external* platform signal
  # (`system`), never from `pkgs`: the unit schema (systemd vs launchd) is part
  # of the module's option shape, so deriving it from `pkgs` would recurse
  # through `_module.args`. For NixOS the platform is Linux by definition.
  mkServiceFor = {
    lib,
    isDarwin,
    username,
    homeManager,
  }:
    inputs.nix-service.lib.mkService {
      inherit lib isDarwin username homeManager;
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
    tomlFormat = pkgs.formats.toml {};
  in {
    options.tartarus.sudo-auth-proxy = {
      enable = mkEnableOption "the sudo-auth-proxy PAM client (guest side)";

      transport = mkOption {
        type = types.enum ["vsock" "tcp" "unix"];
        default = "tcp";
        description = "Transport to connect to the authentication proxy server.";
      };

      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "TCP host to connect to. Only used when transport is tcp.";
      };

      port = mkOption {
        type = types.port;
        default = 65001;
        description = "Port to connect to.";
      };

      cid = mkOption {
        type = types.int;
        default = 2;
        description = "VSOCK CID to connect to. Only used when transport is vsock.";
      };

      socket = mkOption {
        type = types.str;
        default = "%t/sudo-auth-proxy/server.sock";
        description = ''
          Unix socket the *server* binds. The client ignores this key: in
          `unix` transport it connects only to `$SUDO_AUTH_PROXY_SOCK` (the
          SSH RemoteForward selector) and fails closed when that is unset.
        '';
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

      connectTimeout = mkOption {
        type = types.float;
        default = 0.2;
        description = "Seconds to wait for the transport connect before failing fast.";
      };

      decisionTimeout = mkOption {
        type = types.int;
        default = 120;
        description = "Seconds to wait for the human decision (0 = wait indefinitely).";
      };

      recvTimeout = mkOption {
        type = types.float;
        default = 0.5;
        description = "Seconds to wait for the first response bytes.";
      };

      configPath = mkOption {
        type = types.str;
        default = "/etc/sudo-auth-proxy/config.toml";
        description = "Path to the client configuration file passed to the binary.";
      };

      configDirMode = mkOption {
        type = types.str;
        default = "0750";
        description = ''
          Mode of the `/etc/sudo-auth-proxy` client config directory (doc §9.2).
          `0750` with `configDirGroup` set to the guest login group lets the PAM
          helper (which runs as the invoking user) traverse the directory and
          read the config, while keeping filenames and key material off the
          world. The historical value was `0755`.
        '';
      };

      configDirGroup = mkOption {
        type = types.str;
        default = "root";
        description = ''
          Group owning the `/etc/sudo-auth-proxy` client config directory (doc
          §9.2). Standalone configs default to `root`; the guest module sets the
          guest login user's group so the PAM helper can read the config.
        '';
      };

      mtls = {
        enable = mkEnableOption "mutual TLS authentication";
        caFile = mkOption {
          type = types.str;
          default = "./ca.crt";
          description = "Path to the CA certificate. Relative to the config file directory.";
        };
        certFile = mkOption {
          type = types.str;
          default = "./client.crt";
          description = "Path to the client certificate. Relative to the config file directory.";
        };
        keyFile = mkOption {
          type = types.str;
          default = "./client.key";
          description = "Path to the client private key. Relative to the config file directory.";
        };
        requiredOid = mkOption {
          type = types.str;
          default = "1.3.6.1.4.1.99999.1.2";
          description = "EKU OID the local client certificate must contain.";
        };
        peerOid = mkOption {
          type = types.str;
          default = "1.3.6.1.4.1.99999.1.1";
          description = "EKU OID the peer (server) certificate must contain.";
        };
      };

      # Shared `[security]` group (doc §7.2–§7.5). The three knobs are resolved
      # per transport: `transport = tcp` defaults to mTLS, `vsock`/`unix`
      # default to none; setting `mtls.enable = true` is equivalent to
      # `transportEncryption = "mtls"`. Under mTLS both auth methods are forced
      # to "transport" and nothing is layered on top. The key/keyring paths are
      # the Phase 3 plumbing (doc §7.7–§7.8); unreferenced options are simply
      # not emitted into the generated TOML.
      security = {
        transportEncryption = mkOption {
          type = types.enum ["auto" "none" "mtls"];
          default = "auto";
          description = ''
            Whether the byte stream is encrypted and integrity-protected (doc
            §7.4). `auto` (default) follows the transport: `tcp` → `mtls`,
            `vsock`/`unix` → `none`. `mtls` is an explicit choice and never a
            runtime fallback.
          '';
        };
        serverAuth = mkOption {
          type = types.enum ["signature" "transport" "none"];
          default = "signature";
          description = ''
            How the client authenticates the server's messages (doc §7.2).
            `transport` requires `transportEncryption = "mtls"` (and is then
            forced).
          '';
        };
        clientAuth = mkOption {
          type = types.enum ["ssh" "x509" "transport"];
          default = "ssh";
          description = ''
            How the server authenticates the requester (doc §7.3). Exactly one
            method; `transport` requires `transportEncryption = "mtls"` (and is
            then forced). Never `ssh` + `x509`.
          '';
        };
        sshSigningKey = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            Requester SSH private key the client signs requests with
            (`client_auth = "ssh"`, doc §7.3). Never an `authorized_keys` entry;
            the server trusts its fingerprint via `server.acl.trustedKeys`.
            This is a **private key** and must be `0600` and owned by the
            requester/login user (doc §9.2); the file is referenced by path and
            is never copied into the Nix store (the store is world-readable).
          '';
        };
        trustedKeys = mkOption {
          type = types.listOf types.str;
          default = [];
          description = ''
            Deprecated and no longer emitted: the server authorizes requester
            SSH keys through `server.acl.trustedKeys` (fingerprints), and
            authentication uses the key material the client presents in the
            signed request (doc §8.2; redesign Phase 4). Retained only so
            existing configurations keep evaluating; migrate entries to
            `server.acl.trustedKeys` as `SHA256:...` fingerprints.
          '';
        };
        trustedServerKeys = mkOption {
          type = types.listOf types.str;
          default = [];
          description = ''
            Client trust root for `server_auth = "signature"`: a keyring of
            trusted host signing public keys (doc §7.2, §7.8). Prefer a keyring
            so rotation needs no rebuild.
          '';
        };
        serverSigningKey = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            Dedicated host signing private key used for `server_auth =
            "signature"` (Ed25519 preferred, RSA supported). Treat as
            CA-sensitive (doc §7.7–§7.8) and keep it `0600`, owned by the
            server user. It is referenced by path, never copied into the
            world-readable Nix store.
          '';
        };
        clientCert = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Requester X.509 certificate chain for `client_auth = \"x509\"`.";
        };
        clientKey = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            Requester X.509 private key matching `clientCert`. `ca.py` generates
            it `0600` (doc §9.2; review log F12); a hand-provisioned key must be
            `0600` and owned by the requester/login user.
          '';
        };
        caFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Trusted CA certificate used to verify an X.509 requester (`client_auth = \"x509\"`).";
        };
        clientRequiredOid = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "EKU OID an X.509 requester certificate must carry (doc §7.6).";
        };
        responseTtl = mkOption {
          type = types.int;
          default = 30;
          description = "Seconds a signed response remains valid (doc §6.6).";
        };
        clockSkew = mkOption {
          type = types.int;
          default = 5;
          description = "Clock-skew allowance, in seconds, when checking response freshness.";
        };
      };

      settings = mkOption {
        type = types.submodule {freeformType = tomlFormat.type;};
        default = {};
        description = "Extra settings merged into the generated TOML configuration.";
      };

      debug = mkOption {
        type = types.bool;
        default = false;
        description = "Log connection/handshake/request timing to stderr for latency debugging.";
      };

      server = {
        enable = mkEnableOption "the sudo-auth-proxy server (host side)";

        transport = mkOption {
          type = types.enum ["vsock" "tcp" "unix"];
          default = "tcp";
          description = "Transport the server listens on.";
        };

        host = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "TCP address to bind to. Only used with tcp.";
        };

        port = mkOption {
          type = types.port;
          default = 65001;
          description = "Port the server listens on.";
        };

        cid = mkOption {
          type = types.int;
          default = 2;
          description = "VSOCK context ID to bind to (2 = host). Only used with vsock.";
        };

        socket = mkOption {
          type = types.str;
          default = "%t/sudo-auth-proxy/server.sock";
          description = ''
            Unix socket the server binds. There is exactly one server socket
            per host user; guest identity comes from the request credentials,
            never the socket path.
          '';
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

        connectTimeout = mkOption {
          type = types.float;
          default = 0.2;
          description = "Seconds to wait for the transport connect before failing fast.";
        };

        decisionTimeout = mkOption {
          type = types.int;
          default = 120;
          description = "Seconds to wait for the human decision (0 = wait indefinitely).";
        };

        recvTimeout = mkOption {
          type = types.float;
          default = 0.5;
          description = "Seconds to wait for the first response bytes.";
        };

        maxConnections = mkOption {
          type = types.ints.positive;
          default = 64;
          description = ''
            Maximum number of handler threads the server runs at once (audit
            A3). An over-cap connection is refused before a handler thread is
            spawned; the cap also bounds stalled TLS handshakes, which run in
            the handler thread (audit N2). Emitted as `max_connections`; the
            default matches the Python `DEFAULT_MAX_CONNECTIONS`.
          '';
        };

        serverReadTimeout = mkOption {
          type = types.float;
          default = 10.0;
          description = ''
            Seconds an accepted connection may stall before authentication --
            the TLS handshake and the pre-auth request read -- before it is
            dropped (audit A3/N2). Emitted as `server_read_timeout`; the default
            matches the Python `DEFAULT_SERVER_READ_TIMEOUT`.
          '';
        };

        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the server configuration file. Defaults to `~/.config/sudo-auth-proxy/config.toml`.";
        };

        dialogProgram = mkOption {
          type = types.enum ["swiftdialog" "osascript" "zenity"];
          default =
            if pkgs.stdenv.hostPlatform.isDarwin
            then "swiftdialog"
            else "zenity";
          description = "Program used to show the privilege-elevation confirmation prompt.";
        };

        mtls = {
          enable = mkEnableOption "mutual TLS authentication for incoming connections";
          caFile = mkOption {
            type = types.str;
            default = "./ca.crt";
            description = "Path to the CA certificate. Relative to the config file directory.";
          };
          certFile = mkOption {
            type = types.str;
            default = "./server.crt";
            description = "Path to the server certificate. Relative to the config file directory.";
          };
          keyFile = mkOption {
            type = types.str;
            default = "./server.key";
            description = "Path to the server private key. Relative to the config file directory.";
          };
          requiredOid = mkOption {
            type = types.str;
            default = "1.3.6.1.4.1.99999.1.1";
            description = "EKU OID the local server certificate must contain.";
          };
          peerOid = mkOption {
            type = types.str;
            default = "1.3.6.1.4.1.99999.1.2";
            description = "EKU OID the peer (client) certificate must contain.";
          };
        };

        extraSettings = mkOption {
          type = types.attrs;
          default = {};
          description = "Extra settings merged into the generated TOML configuration.";
        };

        resolution = mkOption {
          type = types.enum ["none" "certificate" "tartarus"];
          default =
            if config.tartarus.sudo-auth-proxy.server.mtls.enable
            then "certificate"
            else "tartarus";
          description = ''
            How to resolve a connecting client's name shown in the elevation
            dialog: `none`, `certificate` (verified peer cert CN), or
            `tartarus` (local VM id/name bookkeeping).
          '';
        };

        # Authorization policy (doc §8; redesign Phase 4). Emitted as the
        # server's `[acl]` table only; the client never receives it. The ACL
        # matches ONLY cryptographically verified credentials -- never
        # `PAM_USER`, `PAM_TTY`, `rhost`, socket path, IP or `guest_hint`
        # (review log S11). Defaults are deny-all: an empty list authorizes
        # nobody, and there is no wildcard.
        acl = {
          mode = mkOption {
            type = types.enum ["list" "ca"];
            default = "list";
            description = ''
              How requester credentials are authorized (doc §8.1). Exactly one
              mode; there is no `ca`+`list` combination. `list` accepts only
              credentials whose fingerprint is explicitly listed; `ca` accepts
              any credential that chains to `caFile` with `requiredOid`.
            '';
          };
          trustedKeys = mkOption {
            type = types.listOf types.str;
            default = [];
            description = ''
              `mode = "list"`: SSH requester key fingerprints (`SHA256:...`,
              as produced by `ssh-keygen -lf`) allowed to use the mechanism.
              These are FINGERPRINTS, not public keys: the client presents its
              key in the signed request and the server recomputes the
              fingerprint. An empty list denies every SSH requester.
            '';
          };
          trustedFingerprints = mkOption {
            type = types.listOf types.str;
            default = [];
            description = ''
              `mode = "list"`: X.509 / mTLS leaf SubjectPublicKeyInfo
              fingerprints (`SHA256:...`) allowed to use the mechanism. In
              `mode = "ca"` it optionally additionally pins the leaf SPKI on
              top of the CA chain. An empty list pins nothing.
            '';
          };
          caFile = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              `mode = "ca"`: trusted CA certificate (PEM) the requester chain
              must reach. Defaults to `security.caFile` when that is set.
              Relative paths resolve against the config file directory.
            '';
          };
          requiredOid = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              `mode = "ca"`: EKU OID the requester certificate must carry.
              Defaults to `security.clientRequiredOid` when that is set.
            '';
          };
        };

        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr for latency debugging.";
        };
      };
    };
  };

  # The guest-side PAM client: installs the client config and wires
  # `pam_exec.so` into the `sudo`/`login`/`su` stacks. It is self-contained
  # (only its own `tartarus.sudo-auth-proxy.*` options, `pkgs`, `lib` and the
  # nix-service library) and needs neither the tartarus host module nor a
  # guest VM. There is no reuse proxy any more (redesign Phase 1, review log
  # S2); the client opens a fresh connection per invocation.
  #
  # Exposed both as the legacy `nixosModules."sudo-auth-proxy"` (what nixcfg
  # imports) and under the explicit `nixosModules."sudo-auth-proxy-pam"` so a
  # third-party config can depend on just the PAM side by name.
  pamNixosModule = {
    config,
    lib,
    pkgs,
    username ? "tartarus",
    ...
  }: let
    inherit
      (lib)
      filterAttrs
      genAttrs
      mkIf
      optionalAttrs
      recursiveUpdate
      ;
    cfg = config.tartarus.sudo-auth-proxy;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};

    # Resolve the three knobs for this transport. `mtls.enable` is the legacy
    # spelling of `transport_encryption = "mtls"`; `auto` follows the transport
    # (tcp → mtls, vsock/unix → none). Under mTLS both auths are forced to
    # "transport" so the Python layer's no-downgrade rules are satisfied
    # without a build-time contradiction.
    effectiveTransportEncryption =
      if cfg.mtls.enable
      then "mtls"
      else if cfg.security.transportEncryption != "auto"
      then cfg.security.transportEncryption
      else if cfg.transport == "tcp"
      then "mtls"
      else "none";
    forceTransportAuth = effectiveTransportEncryption == "mtls";
    effectiveClientAuth =
      if forceTransportAuth
      then "transport"
      else cfg.security.clientAuth;
    effectiveServerAuth =
      if forceTransportAuth
      then "transport"
      else cfg.security.serverAuth;

    securitySettings =
      {
        transport_encryption = effectiveTransportEncryption;
        server_auth = effectiveServerAuth;
        client_auth = effectiveClientAuth;
        response_ttl = cfg.security.responseTtl;
        clock_skew = cfg.security.clockSkew;
      }
      // optionalAttrs (cfg.security.sshSigningKey != null) {
        ssh_signing_key = cfg.security.sshSigningKey;
      }
      // optionalAttrs (cfg.security.trustedServerKeys != []) {
        trusted_server_keys = cfg.security.trustedServerKeys;
      }
      // optionalAttrs (cfg.security.clientCert != null) {
        client_cert = cfg.security.clientCert;
      }
      // optionalAttrs (cfg.security.clientKey != null) {
        client_key = cfg.security.clientKey;
      }
      // optionalAttrs (cfg.security.caFile != null) {
        ca_file = cfg.security.caFile;
      }
      // optionalAttrs (cfg.security.clientRequiredOid != null) {
        client_required_oid = cfg.security.clientRequiredOid;
      };

    connectionSettings =
      {
        transport = cfg.transport;
        port = cfg.port;
      }
      // optionalAttrs (cfg.transport == "vsock") {cid = cfg.cid;}
      // optionalAttrs (cfg.transport == "tcp") {host = cfg.host;}
      // optionalAttrs (effectiveTransportEncryption == "mtls") {
        mtls = {
          enable = true;
          ca_file = cfg.mtls.caFile;
          cert_file = cfg.mtls.certFile;
          key_file = cfg.mtls.keyFile;
          required_oid = cfg.mtls.requiredOid;
          peer_required_oid = cfg.mtls.peerOid;
        };
      };

    settings =
      recursiveUpdate
      ({
          mode = "client";
          socket = cfg.socket;
          socket_dir_mode = cfg.socketDirMode;
          socket_mode = cfg.socketMode;
          connect_timeout = cfg.connectTimeout;
          decision_timeout = cfg.decisionTimeout;
          recv_timeout = cfg.recvTimeout;
          security = securitySettings;
          debug =
            if cfg.debug
            then true
            else null;
        }
        // connectionSettings)
      cfg.settings;
    cleanSettings = filterAttrs (_: v: v != null) settings;
    configFile = tomlFormat.generate "sudo-auth-proxy-client.toml" cleanSettings;

    # The PAM hook fires on *every* `sudo`, so the no-tunnel path must be
    # effectively free. Two zero-cost guards run here, before spawning Python:
    # the recursion guard (mirroring the Python's `recursion_guard_active()`)
    # and, for the `unix` transport, the selector + socket-existence check
    # (doc §10.2; review log Rank 5/R7). Both exit non-zero and PAM continues.
    #
    # Fall-through semantics (doc §10.3; review log F5). The control flag is
    # `[success=done default=ignore]`: an `allow` (exit 0) finishes the stack,
    # while *every* non-zero exit is ignored so the next method runs. Critically,
    # `pam_exec.so` collapses any non-zero exit to one generic failure, so PAM
    # cannot tell a human `deny` from `unavailable`; both therefore fall
    # through. Consequences, stated plainly:
    #   - the proxy is an *additional, optional* authentication path, not a
    #     hard gate over the account;
    #   - if any other auth method is enabled (e.g. a local password), a
    #     deliberate `deny` can be bypassed by using it;
    #   - a non-ignorable `deny` is **not implementable with `pam_exec`** and
    #     requires the native PAM module (future work, doc §17). There is
    #     deliberately no "strict mode" option here and no fake enforcement.
    #
    # The connect/handshake bound lives in the Python client
    # (`connect_timeout`), and the receive and decision bounds (`recv_timeout`,
    # `decision_timeout`) are now implemented there too (Phase 6), so a stale
    # bound-but-unlistened socket cannot hang the read.
    clientScript = pkgs.writeShellScript "sudo-auth-proxy-pam-client" ''
      # Recursion guard: the same `SUDO_AUTH_PROXY_ACTIVE` check the Python
      # enforces on entry (doc §10.4). A nested `sudo`/`su` exits non-zero
      # immediately -- no second dialog -- so PAM falls through. It survives
      # `sudo` only because the guest mandates
      # `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` (doc §10.4); without
      # that entry `env_reset` strips it and this guard is a no-op.
      [ -n "''${SUDO_AUTH_PROXY_ACTIVE:-}" ] && exit 1
      ${lib.optionalString (cfg.transport == "unix") ''
        [ -n "''${SUDO_AUTH_PROXY_SOCK:-}" ] || exit 1
        [ -S "$SUDO_AUTH_PROXY_SOCK" ] || exit 1
      ''}
      exec ${package}/bin/sudo-auth-proxy --config ${cfg.configPath}
    '';
  in {
    imports = [optionsModule];

    config = mkIf cfg.enable {
      # `pam_exec.so` runs this PAM helper as the invoking user, which must be
      # able to read the config and the mTLS cert/key paths it references. The
      # directory is `0750 root <group>` (doc §9.2), not the historic
      # world-readable `0755`: the guest module sets `configDirGroup` to the
      # guest login group so the helper keeps working while filenames and key
      # material stay off the world.
      systemd.tmpfiles.rules = [
        "d /etc/sudo-auth-proxy ${cfg.configDirMode} root ${cfg.configDirGroup} -"
      ];

      environment.etc."sudo-auth-proxy/config.toml".source = configFile;

      # The first auth rule: a verified `allow` (exit 0) finishes the stack
      # (`success=done`); every non-zero exit -- including a human `deny` and
      # an `unavailable` -- is ignored and the stack continues
      # (`default=ignore`). `pam_exec` cannot distinguish the two, so this is
      # an optional path, not a hard gate (doc §10.3; review log F5).
      security.pam.services = genAttrs ["sudo" "login" "su"] (_: {
        rules.auth.sudo-auth-proxy = {
          order = -1000;
          control = "[success=done default=ignore]";
          modulePath = "pam_exec.so";
          args = ["${clientScript}"];
        };
      });
    };
  };

  homeManagerModule = {
    config,
    lib,
    pkgs,
    ...
  } @ args: let
    inherit
      (lib)
      filterAttrs
      mkIf
      mkMerge
      optionalAttrs
      recursiveUpdate
      ;
    system = args.system or builtins.currentSystem;
    username = config.home.username;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = lib.hasSuffix "-darwin" system;
      homeManager = true;
    };
    cfg = config.tartarus.sudo-auth-proxy;
    server = cfg.server;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};

    configPath =
      if server.configPath != null
      then server.configPath
      else "${config.home.homeDirectory}/.config/sudo-auth-proxy/config.toml";

    # Resolve the three knobs for the listener transport (see the client
    # module). Under mTLS both auths are forced to "transport".
    effectiveTransportEncryption =
      if server.mtls.enable
      then "mtls"
      else if cfg.security.transportEncryption != "auto"
      then cfg.security.transportEncryption
      else if server.transport == "tcp"
      then "mtls"
      else "none";
    forceTransportAuth = effectiveTransportEncryption == "mtls";
    effectiveClientAuth =
      if forceTransportAuth
      then "transport"
      else cfg.security.clientAuth;
    effectiveServerAuth =
      if forceTransportAuth
      then "transport"
      else cfg.security.serverAuth;

    securitySettings =
      {
        transport_encryption = effectiveTransportEncryption;
        server_auth = effectiveServerAuth;
        client_auth = effectiveClientAuth;
        response_ttl = cfg.security.responseTtl;
        clock_skew = cfg.security.clockSkew;
      }
      // optionalAttrs (cfg.security.serverSigningKey != null) {
        server_signing_key = cfg.security.serverSigningKey;
      }
      # `cfg.security.trustedKeys` is intentionally NOT emitted any more: the
      # server authorizes through `server.acl.trustedKeys` (fingerprints), and
      # authentication now uses the key material presented in the signed
      # request (doc §8.2; redesign Phase 4). The option is kept for source
      # compatibility only.
      // optionalAttrs (cfg.security.caFile != null) {
        ca_file = cfg.security.caFile;
      }
      // optionalAttrs (cfg.security.clientRequiredOid != null) {
        client_required_oid = cfg.security.clientRequiredOid;
      };

    # The server's authorization table (doc §8). `mode` is always emitted, so
    # the deny-all default is explicit rather than an absent table. The CA
    # fields fall back to the `[security]` x509 trust roots for convenience.
    aclCaFile =
      if server.acl.caFile != null
      then server.acl.caFile
      else cfg.security.caFile;
    aclRequiredOid =
      if server.acl.requiredOid != null
      then server.acl.requiredOid
      else cfg.security.clientRequiredOid;
    aclSettings =
      {
        mode = server.acl.mode;
      }
      // optionalAttrs (server.acl.trustedKeys != []) {
        trusted_keys = server.acl.trustedKeys;
      }
      // optionalAttrs (server.acl.trustedFingerprints != []) {
        trusted_fingerprints = server.acl.trustedFingerprints;
      }
      // optionalAttrs (server.acl.mode == "ca" && aclCaFile != null) {
        ca_file = aclCaFile;
      }
      // optionalAttrs (server.acl.mode == "ca" && aclRequiredOid != null) {
        required_oid = aclRequiredOid;
      };

    settings =
      recursiveUpdate
      ({
          mode = "server";
          transport = server.transport;
          port = server.port;
          socket = server.socket;
          socket_dir_mode = server.socketDirMode;
          socket_mode = server.socketMode;
          connect_timeout = server.connectTimeout;
          decision_timeout = server.decisionTimeout;
          recv_timeout = server.recvTimeout;
          # Server-side pre-auth resource bounds (audit A3/N2/N5). The Python
          # defaults match; emitting them makes the knobs explicit in the
          # generated TOML rather than relying on the in-code fallbacks.
          max_connections = server.maxConnections;
          server_read_timeout = server.serverReadTimeout;
          dialog_program = server.dialogProgram;
          resolution = server.resolution;
          security = securitySettings;
          acl = aclSettings;
          debug =
            if server.debug
            then true
            else null;
        }
        // optionalAttrs (server.transport == "vsock") {cid = server.cid;}
        // optionalAttrs (server.transport == "tcp") {host = server.host;}
        // optionalAttrs (effectiveTransportEncryption == "mtls") {
          mtls = {
            enable = true;
            ca_file = server.mtls.caFile;
            cert_file = server.mtls.certFile;
            key_file = server.mtls.keyFile;
            required_oid = server.mtls.requiredOid;
            peer_required_oid = server.mtls.peerOid;
          };
        })
      server.extraSettings;
    cleanSettings = filterAttrs (_: v: v != null) settings;
    configFile = tomlFormat.generate "sudo-auth-proxy-server.toml" cleanSettings;
  in {
    imports = [optionsModule];

    config = mkIf (cfg.enable || server.enable) (mkMerge [
      (mkService {
        name = "sudo-auth-proxy";
        description = "sudo authentication proxy server (${server.transport})";
        command = "${package}/bin/sudo-auth-proxy --config ${configPath}";
        # The server binds `%t/sudo-auth-proxy/server.sock`, so the per-user
        # runtime directory must be `0700` and owned by the server user (doc
        # §9.1). systemd creates and owns it for the user unit; on macOS
        # `extraSystemdServiceConfig` is a no-op (nix-service ignores Linux-only
        # params) and the Python creates the directory itself. The Python also
        # re-creates/chmods it, so a nix-service version that drops this key
        # cannot widen it silently.
        extraSystemdServiceConfig = {
          RuntimeDirectory = "sudo-auth-proxy";
          RuntimeDirectoryMode = "0700";
        };
      })
      {
        home.packages = [package];
        home.file.${configPath}.source = configFile;
      }
    ]);
  };
in {
  package = mkPackage;
  inherit homeManagerModule pamNixosModule;
  # `sudo-auth-proxy` is a backwards-compatible alias for the PAM client
  # module; `pamNixosModule` is the canonical, explicitly-named export.
  nixosModule = pamNixosModule;
}

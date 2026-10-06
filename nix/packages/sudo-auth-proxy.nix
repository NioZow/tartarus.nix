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

  # Reusable `[security]` option set. The legacy top-level
  # `tartarus.sudo-auth-proxy.security` and the extra server instance
  # (`tartarus.sudo-auth-proxy.extraServer.security`) share this exact shape
  # (doc §7). Extracted so the option shapes can never drift apart.
  #
  # mTLS is the ONLY authentication/signature mechanism (doc §7). The removed
  # `ssh` / `x509` requester methods and the `signature` host-signing method
  # took every key reference with them: there is no `sshSigningKey`,
  # `sshAgent`, `sshKey`, `trustedKeys`, `trustedServerKeys`,
  # `serverSigningKey`, `clientCert`, `clientKey`, `caFile` or
  # `clientRequiredOid` left. mTLS carries its own `[mtls]` section and the ACL
  # carries its own `caFile`/`requiredOid`, so nothing is shared or defaulted
  # from here any more.
  mkSecurityOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
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
    clientAuth = mkOption {
      type = types.enum ["transport" "none"];
      default = "transport";
      description = ''
        How the server authenticates the requester (doc §7.3). `transport`
        means the identity comes from the mTLS handshake; `none` disables
        requester authentication entirely: it is an explicit, warned choice
        that the Python only accepts when the server pairs it with
        `acl.mode = "none"` (fail-closed XOR), and is rejected under
        `transportEncryption = "mtls"`. Use it only on a transport that is
        private by construction (vsock, SSH tunnel, local Unix socket).
        Setting it to `none` is required — with `transport_encryption =
        "none"` the Python refuses to run without an explicit `none` on both
        auth knobs rather than silently disabling authentication.
      '';
    };
    serverAuth = mkOption {
      type = types.enum ["transport" "none"];
      default = "transport";
      description = ''
        How the client authenticates the server's messages (doc §7.2).
        `transport` requires `transportEncryption = "mtls"` (and is then
        forced); `none` means nothing authenticates the response and is only
        accepted alongside `clientAuth = "none"`.
      '';
    };
    responseTtl = mkOption {
      type = types.int;
      default = 30;
      description = "Seconds a response remains valid (doc §6.6).";
    };
    clockSkew = mkOption {
      type = types.int;
      default = 5;
      description = "Clock-skew allowance, in seconds, when checking response freshness.";
    };
  };

  # Reusable `server` option set. The legacy `tartarus.sudo-auth-proxy.server`
  # instantiates it with `withSecurity = false` and reads the shared top-level
  # `security`; the `tartarus.sudo-auth-proxy.extraServer` instance instantiates
  # it with `withSecurity = true` and carries its own nested `security`.
  mkServerOptions = {
    lib,
    pkgs,
    withSecurity,
  }: let
    inherit (lib) mkEnableOption mkOption optionalAttrs types;
  in
    {
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
        description = "Path to the server configuration file. Defaults to `~/.config/sudo-auth-proxy/config.toml` (`~/.config/sudo-auth-proxy/<name>.toml` for `extraServer`).";
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
        type = types.nullOr (types.enum ["none" "certificate" "tartarus"]);
        default = null;
        description = ''
          How to resolve a connecting client's name shown in the elevation
          dialog: `none`, `certificate` (verified peer cert CN), or
          `tartarus` (local VM id/name bookkeeping). When unset it defaults to
          `"certificate"` when `mtls` is enabled and `"tartarus"` otherwise.
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
          type = types.enum ["list" "ca" "none"];
          default = "list";
          description = ''
            How requester credentials are authorized (doc §8.1). Exactly one
            mode; there is no `ca`+`list` combination. `list` accepts only
            credentials whose SPKI fingerprint is explicitly listed; `ca`
            accepts any credential that chains to `caFile` with
            `requiredOid`. `none` deliberately authorizes every request
            because there is no credential to authorize; it is accepted only
            when paired with `security.clientAuth = "none"` (fail-closed XOR
            enforced by the Python) and must not carry any trust material
            (`trustedFingerprints`, `caFile`, `requiredOid`).
          '';
        };
        trustedFingerprints = mkOption {
          type = types.listOf types.str;
          default = [];
          description = ''
            `mode = "list"`: mTLS leaf SubjectPublicKeyInfo fingerprints
            (`SHA256:...`) allowed to use the mechanism. In `mode = "ca"` it
            optionally additionally pins the leaf SPKI on top of the CA chain.
            An empty list pins nothing.
          '';
        };
        # `mode = "ca"` needs a readable CA; it is no longer defaulted from
        # `security.caFile` (that option belonged to the removed x509
        # requester method), so it must be set here explicitly.
        caFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            `mode = "ca"`: trusted CA certificate (PEM) the requester chain
            must reach. Relative paths resolve against the config file
            directory.
          '';
        };
        requiredOid = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            `mode = "ca"`: EKU OID the requester certificate must carry.
          '';
        };
      };

      debug = mkOption {
        type = types.bool;
        default = false;
        description = "Log connection/handshake/request timing to stderr for latency debugging.";
      };
    }
    // optionalAttrs withSecurity {
      security = mkSecurityOptions {inherit lib;};
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
      # not emitted into the generated TOML. The option set is defined once in
      # `mkSecurityOptions`, also instantiated as `extraServer.security`.
      security = mkSecurityOptions {inherit lib;};

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

      server = mkServerOptions {
        inherit lib pkgs;
        withSecurity = false;
      };

      # A second, independent server instance. It has its own transport,
      # `security` (transport/auth knobs and keys), `acl`, `mtls`, settings and
      # config file, and runs as a unit named `sudo-auth-proxy-<name>`; the
      # legacy `server` above stays the default instance and keeps reading the
      # top-level `security`. This lets one host run, for example, the tartarus
      # guest callback server alongside an SSH-forwarded `unix` server for a
      # remote host.
      #
      # Modelled as a plain nested option set (like `server`) rather than an
      # `attrsOf (submodule)`: reading an `attrsOf submodule` value inside the
      # same module graph forces the root config and recurses, whereas a nested
      # option set resolves like `server.enable` does.
      extraServer =
        mkServerOptions {
          inherit lib pkgs;
          withSecurity = true;
        }
        // {
          name = mkOption {
            type = types.str;
            default = "extra";
            description = ''
              Instance name. Used for the service unit
              (`sudo-auth-proxy-<name>`), the runtime directory and the default
              config path (`~/.config/sudo-auth-proxy/<name>.toml`).
            '';
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

    # No key/keyring paths are emitted under `[security]` any more: mTLS reads
    # its own `[mtls]` section, and the removed ssh/x509/signature methods took
    # every `ssh_signing_key` / `trusted_server_keys` / `client_cert` /
    # `server_signing_key` / `ca_file` / `client_required_oid` key with them.
    securitySettings = {
      transport_encryption = effectiveTransportEncryption;
      server_auth = effectiveServerAuth;
      client_auth = effectiveClientAuth;
      response_ttl = cfg.security.responseTtl;
      clock_skew = cfg.security.clockSkew;
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
      # Fail at evaluation time, not inside PAM. With `transport_encryption =
      # "none"` there is no authentication mechanism left to fall back on, and
      # the `clientAuth`/`serverAuth` defaults are the secure `"transport"`
      # value: emitting that combination would make the Python refuse to start
      # at `sudo` time, which `pam_exec` turns into a silent fall-through.
      # Requiring the explicit `"none"` here keeps the decision visible in the
      # config (doc §7.5).
      assertions = [
        {
          assertion =
            effectiveTransportEncryption != "none"
            || (cfg.security.clientAuth == "none" && cfg.security.serverAuth == "none");
          message = ''
            tartarus.sudo-auth-proxy: transport_encryption = "none" requires
            security.clientAuth = "none" and security.serverAuth = "none".
            Authentication is never disabled implicitly; set both explicitly, or
            use transport_encryption = "mtls".
          '';
        }
      ];

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

      # The `unix` transport is an SSH `RemoteForward`, so the peer's ssh
      # delivers the session selector and the recursion guard with `SetEnv`;
      # this machine's `sshd` forwards them into the session only if it accepts
      # them (doc §4.3, §10.4). The tartarus guest module sets the same in
      # `nix/guest/base.nix`; the standalone PAM module must not depend on it.
      # `mkAfter` (not a plain assignment) so the sshd default `AcceptEnv`
      # entries (`LANG`, `LC_*`) stay in effect; the two selectors are appended.
      services.openssh.settings.AcceptEnv = mkIf (cfg.transport == "unix") (
        lib.mkAfter ["SUDO_AUTH_PROXY_SOCK" "SUDO_AUTH_PROXY_ACTIVE"]
      );

      # `sudo`'s default `env_reset` strips the selector and the recursion
      # guard before the `pam_exec` helper runs. Append the `env_keep` lines to
      # the tail of `/etc/sudoers` with `mkAfter`, exactly as the guest module
      # does, so a later `sudoers.d` fragment cannot negate them (doc §4.3,
      # §10.4). Nothing else needs keeping: signer keys and agent sockets went
      # with the removed ssh/x509 methods.
      security.sudo.extraConfig = mkIf (cfg.transport == "unix") (lib.mkAfter ''
        Defaults env_keep += "SUDO_AUTH_PROXY_SOCK"
        Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"
      '');

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

  # Emits the extra server instance (`tartarus.sudo-auth-proxy.extraServer`).
  # It lives in its own module, referenced from `homeManagerModule.imports`,
  # because it reads `config.tartarus.sudo-auth-proxy` from its own `config` to
  # build the unit; doing the same inside the module that also declares those
  # options (and reads them in its `let`) trips an infinite recursion in the
  # module fixpoint.
  namedServersModule = {
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
    cfg = config.tartarus.sudo-auth-proxy;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = lib.hasSuffix "-darwin" system;
      homeManager = true;
    };

    # Build the settings + generated config file for one named instance.
    mkServerFiles = {
      name,
      server,
      security,
    }: let
      configPath =
        if server.configPath != null
        then server.configPath
        else "${config.home.homeDirectory}/.config/sudo-auth-proxy/${name}.toml";

      effectiveTransportEncryption =
        if server.mtls.enable
        then "mtls"
        else if security.transportEncryption != "auto"
        then security.transportEncryption
        else if server.transport == "tcp"
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

      # The extra server instance carries its own `security`; the ACL uses its
      # own `caFile`/`requiredOid` (no `security.caFile` fallback any more).
      securitySettings = {
        transport_encryption = effectiveTransportEncryption;
        server_auth = effectiveServerAuth;
        client_auth = effectiveClientAuth;
        response_ttl = security.responseTtl;
        clock_skew = security.clockSkew;
      };

      aclSettings =
        {
          mode = server.acl.mode;
        }
        // optionalAttrs (server.acl.trustedFingerprints != []) {
          trusted_fingerprints = server.acl.trustedFingerprints;
        }
        // optionalAttrs (server.acl.mode == "ca" && server.acl.caFile != null) {
          ca_file = server.acl.caFile;
        }
        // optionalAttrs (server.acl.mode == "ca" && server.acl.requiredOid != null) {
          required_oid = server.acl.requiredOid;
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
            max_connections = server.maxConnections;
            server_read_timeout = server.serverReadTimeout;
            dialog_program = server.dialogProgram;
            resolution =
              if server.resolution != null
              then server.resolution
              else if server.mtls.enable
              then "certificate"
              else "tartarus";
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
    in {
      inherit configPath;
      configFile = tomlFormat.generate "sudo-auth-proxy-server-${name}.toml" cleanSettings;
    };

    instance =
      {
        name = "sudo-auth-proxy-${cfg.extraServer.name}";
        runtimeDir = "sudo-auth-proxy-${cfg.extraServer.name}";
        server = cfg.extraServer;
      }
      // (mkServerFiles {
        name = cfg.extraServer.name;
        server = cfg.extraServer;
        security = cfg.extraServer.security;
      });
  in {
    config = mkIf cfg.extraServer.enable (mkMerge [
      {home.packages = [package];}
      (mkService {
        name = instance.name;
        description = "sudo authentication proxy server (${instance.server.transport})";
        command = "${package}/bin/sudo-auth-proxy --config ${instance.configPath}";
        # Its own runtime dir, matching the `sudo-auth-proxy-<name>` unit; the
        # Python re-creates/chmods it regardless (doc §9.1).
        extraSystemdServiceConfig = {
          RuntimeDirectory = instance.runtimeDir;
          RuntimeDirectoryMode = "0700";
        };
      })
      {
        home.file.${instance.configPath}.source = instance.configFile;
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

    # No key/keyring paths are emitted under `[security]` any more (see the
    # client module); the ACL reads its own `caFile`/`requiredOid`.
    securitySettings = {
      transport_encryption = effectiveTransportEncryption;
      server_auth = effectiveServerAuth;
      client_auth = effectiveClientAuth;
      response_ttl = cfg.security.responseTtl;
      clock_skew = cfg.security.clockSkew;
    };

    # The server's authorization table (doc §8). `mode` is always emitted, so
    # the deny-all default is explicit rather than an absent table.
    aclSettings =
      {
        mode = server.acl.mode;
      }
      // optionalAttrs (server.acl.trustedFingerprints != []) {
        trusted_fingerprints = server.acl.trustedFingerprints;
      }
      // optionalAttrs (server.acl.mode == "ca" && server.acl.caFile != null) {
        ca_file = server.acl.caFile;
      }
      // optionalAttrs (server.acl.mode == "ca" && server.acl.requiredOid != null) {
        required_oid = server.acl.requiredOid;
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
    imports = [optionsModule namedServersModule];

    config = mkIf (cfg.enable || server.enable) (mkMerge [
      # Fail at evaluation time, not inside the server. With
      # `transport_encryption = "none"` the `clientAuth`/`serverAuth` defaults
      # are the secure `"transport"` value, which the Python rejects under
      # `none`; requiring the explicit `"none"` here keeps the decision visible
      # in the config instead of on the server's stderr (doc §7.5).
      {
        assertions = [
          {
            assertion =
              effectiveTransportEncryption != "none"
              || (cfg.security.clientAuth == "none" && cfg.security.serverAuth == "none");
            message = ''
              tartarus.sudo-auth-proxy.server: transport_encryption = "none"
              requires security.clientAuth = "none" and
              security.serverAuth = "none". Authentication is never disabled
              implicitly; set both explicitly, or use
              transport_encryption = "mtls".
            '';
          }
        ];
      }
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

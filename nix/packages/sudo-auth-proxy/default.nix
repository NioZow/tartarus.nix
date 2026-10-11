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
        exec ${pythonEnv.interpreter} -P ${./sudo-auth-proxy.py} "$@"
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

  # A field option that is `null` by default in the sparse (entry) variant and
  # carries its real default in the defaults variant. `pkgs.formats.toml`
  # cannot serialise `null`, so sparse entries are pruned before generation
  # (`mkPruneNulls`, below). Reused by every listener field option.
  nullableOpt = {
    lib,
    nullable,
  }: type: default: {
    type =
      if nullable
      then lib.types.nullOr type
      else type;
    default =
      if nullable
      then null
      else default;
  };

  # Reusable `[security]` option set. The client's top-level
  # `tartarus.sudo-auth-proxy.security` and every server listener share this
  # exact shape (doc §7). `nullable = true` yields the sparse entry variant used
  # inside `transports`: every knob defaults to `null` and is pruned before TOML
  # generation, so an entry only overrides what it sets and the Python
  # deep-merges the defaults block into the rest (including `response_ttl`/
  # `clock_skew`).
  #
  # mTLS is the ONLY authentication/signature mechanism (doc §7). The removed
  # `ssh` / `x509` requester methods and the `signature` host-signing method
  # took every key reference with them; mTLS carries its own `[mtls]` section and
  # the ACL carries its own `caFile`/`requiredOid`.
  mkSecurityOptions = {
    lib,
    nullable ? false,
  }: let
    inherit (lib) mkOption types;
    o = nullableOpt {inherit lib nullable;};
  in {
    transportEncryption = mkOption ((o (types.enum ["auto" "none" "mtls"]) "auto")
      // {
        description = ''
          Whether the byte stream is encrypted and integrity-protected (doc
          §7.4). `auto` (default) follows the listener's `type`: `tcp` → `mtls`,
          `vsock`/`unix` → `none`. `mtls` is an explicit choice and never a
          runtime fallback.
        '';
      });
    clientAuth = mkOption ((o (types.enum ["transport" "none"]) "transport")
      // {
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
      });
    serverAuth = mkOption ((o (types.enum ["transport" "none"]) "transport")
      // {
        description = ''
          How the client authenticates the server's messages (doc §7.2).
          `transport` requires `transportEncryption = "mtls"` (and is then
          forced); `none` means nothing authenticates the response and is only
          accepted alongside `clientAuth = "none"`.
        '';
      });
    responseTtl = mkOption ((o types.int 30)
      // {
        description = "Seconds a response remains valid (doc §6.6).";
      });
    clockSkew = mkOption ((o types.int 5)
      // {
        description = "Clock-skew allowance, in seconds, when checking response freshness.";
      });
  };

  # Reusable `[mtls]` option set (extracted from the old inline server block so
  # it can be instantiated in both `transportDefaults` and each `transports`
  # entry). `requiredOid`/`peerOid` carry the sudo-specific EKU OIDs.
  mkMtlsOptions = {
    lib,
    nullable ? false,
    requiredOid,
    peerOid,
  }: let
    inherit (lib) mkOption types;
    o = nullableOpt {inherit lib nullable;};
  in {
    enable = mkOption ((o types.bool false)
      // {
        description = "Enable mutual TLS for this listener. Equivalent to `security.transportEncryption = \"mtls\"`.";
      });
    caFile = mkOption ((o types.str "./ca.crt")
      // {
        description = "Path to the CA certificate. Relative to the config file directory.";
      });
    certFile = mkOption ((o types.str "./server.crt")
      // {
        description = "Path to the server certificate. Relative to the config file directory.";
      });
    keyFile = mkOption ((o types.str "./server.key")
      // {
        description = "Path to the server private key. Relative to the config file directory.";
      });
    requiredOid = mkOption ((o types.str requiredOid)
      // {
        description = "EKU OID the local server certificate must contain.";
      });
    peerOid = mkOption ((o types.str peerOid)
      // {
        description = "EKU OID the peer (client) certificate must contain.";
      });
  };

  # Reusable `[acl]` option set — server-only, so it exists only in the sudo
  # module. `rule` reuses the old `[[acl.rule]]` submodule verbatim. Emitted
  # only in the generated server TOML; the client never receives it. The ACL
  # matches ONLY cryptographically verified credentials (review log S11).
  mkAclOptions = {
    lib,
    nullable ? false,
  }: let
    inherit (lib) mkOption types;
    o = nullableOpt {inherit lib nullable;};
  in {
    mode = mkOption ((o (types.enum ["list" "ca" "none"]) "list")
      // {
        description = ''
          How requester credentials are authorized (doc §8.1). Exactly one mode;
          there is no `ca`+`list` combination. `list` accepts only credentials
          whose SPKI fingerprint is explicitly listed; `ca` accepts any credential
          that chains to `caFile` with `requiredOid`. `none` deliberately
          authorizes every request because there is no credential to authorize; it
          is accepted only when paired with `security.clientAuth = "none"`
          (fail-closed XOR enforced by the Python) and must not carry any trust
          material.
        '';
      });
    trustedFingerprints = mkOption ((o (types.listOf types.str) [])
      // {
        description = ''
          `mode = "list"`: mTLS leaf SubjectPublicKeyInfo fingerprints
          (`SHA256:...`) allowed to use the mechanism. In `mode = "ca"` it
          optionally additionally pins the leaf SPKI on top of the CA chain.
        '';
      });
    caFile = mkOption ((o (types.nullOr types.str) null)
      // {
        description = ''
          `mode = "ca"`: trusted CA certificate (PEM) the requester chain must
          reach. Relative paths resolve against the config file directory.
        '';
      });
    requiredOid = mkOption ((o (types.nullOr types.str) null)
      // {
        description = "`mode = \"ca\"`: EKU OID the requester certificate must carry.";
      });
    rule = mkOption ((o (types.listOf (types.submodule {
        options = {
          identity = mkOption {
            type = types.str;
            default = "*";
            description = ''
              Glob pattern matched against the requester's resolved names: the
              friendly name produced by `resolution`, the ACL display label and
              the verified credential fingerprint. `*` matches anything.
            '';
          };
          targetUser = mkOption {
            type = types.str;
            default = "*";
            description = "Glob pattern matched against the target (PAM) user.";
          };
          invokingUser = mkOption {
            type = types.str;
            default = "*";
            description = "Glob pattern matched against the invoking user.";
          };
          service = mkOption {
            type = types.str;
            default = "*";
            description = "Glob pattern matched against the PAM service name (sudo/su/login).";
          };
          policy = mkOption {
            type = types.enum ["allow" "ask" "deny"];
            default = "ask";
            description = ''
              Approval policy for a matching request: `allow` replies
              immediately without a dialog, `deny` replies immediately without a
              dialog, `ask` shows the confirmation prompt. Rules are evaluated
              in order and the first match wins; no match means `ask`.
            '';
          };
        };
      })) [])
      // {
        description = ''
          Ordered approval rules (`[[acl.rule]]`), evaluated after the ACL
          authorizes the credential; the first matching rule wins.
        '';
      });
  };

  # One per-listener option set, instantiated twice:
  #   `nullable = false; withType = false` → the `transportDefaults` block (real
  #                                          defaults, no `type`);
  #   `nullable = true;  withType = true`  → a `transports` entry (requires
  #                                          `type`; every other field is a
  #                                          sparse `nullOr` override).
  mkListenerOptions = {
    lib,
    pkgs,
    nullable,
    withType,
    requiredOid,
    peerOid,
  }: let
    inherit (lib) mkOption types;
    o = nullableOpt {inherit lib nullable;};
  in
    {
      # Address / bind target. Each is meaningful only for its own `type`, but
      # all are accepted on every listener (the old flat options had the same
      # shape), so one entry can be retargeted without knowing the `type`.
      port = mkOption ((o types.port 65001)
        // {
          description = "Port the listener binds. Used with tcp/vsock.";
        });
      cid = mkOption ((o types.int 2)
        // {
          description = "VSOCK context ID to bind to (2 = host). Only used with vsock.";
        });
      host = mkOption ((o types.str "127.0.0.1")
        // {
          description = "TCP address to bind to. Only used with tcp.";
        });
      socket = mkOption ((o types.str "%t/sudo-auth-proxy/server.sock")
        // {
          description = ''
            Unix socket the listener binds. Guest identity comes from the request
            credentials, never the socket path.
          '';
        });
      socketDirMode = mkOption ((o types.str "0700")
        // {
          description = "Mode of the unix socket's parent directory.";
        });
      socketMode = mkOption ((o types.str "0600")
        // {
          description = "Mode of the unix server socket.";
        });
      # Timeouts and pre-auth resource bounds.
      connectTimeout = mkOption ((o types.float 0.2)
        // {
          description = "Seconds to wait for the transport connect before failing fast.";
        });
      decisionTimeout = mkOption ((o types.int 120)
        // {
          description = "Seconds to wait for the human decision (0 = wait indefinitely).";
        });
      recvTimeout = mkOption ((o types.float 0.5)
        // {
          description = "Seconds to wait for the first response bytes.";
        });
      maxConnections = mkOption ((o types.ints.positive 64)
        // {
          description = ''
            Maximum number of handler threads the listener runs at once (audit
            A3). An over-cap connection is refused before a handler thread is
            spawned; the cap also bounds stalled TLS handshakes. Emitted as
            `max_connections`; the default matches the Python
            `DEFAULT_MAX_CONNECTIONS`.
          '';
        });
      serverReadTimeout = mkOption ((o types.float 10.0)
        // {
          description = ''
            Seconds an accepted connection may stall before authentication --
            the TLS handshake and the pre-auth request read -- before it is
            dropped (audit A3/N2). Emitted as `server_read_timeout`; the default
            matches the Python `DEFAULT_SERVER_READ_TIMEOUT`.
          '';
        });
      # Per-listener identity resolution (`unix` cannot do tartarus/mofos).
      resolution = mkOption ((o (types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"])) null)
        // {
          description = ''
            How to resolve a connecting client's name shown in the elevation
            dialog and offered to the `[[acl.rule]]` identity selector:
            `none` (no resolution), `certificate` (verified peer cert CN/SAN),
            `tartarus` (local VM id/name bookkeeping via the state directory), or
            `mofos` (`mofos ls --json`, matching the peer's VSOCK CID or
            `ipv4_address` to a VM name). `null` (the default) leaves the choice
            to the Python's per-listener fallback.
          '';
        });
      # Per-listener security / mTLS / ACL.
      security = mkSecurityOptions {inherit lib nullable;};
      mtls = mkMtlsOptions {inherit lib nullable requiredOid peerOid;};
      acl = mkAclOptions {inherit lib nullable;};
    }
    // lib.optionalAttrs withType {
      type = mkOption {
        type = types.enum ["vsock" "tcp" "unix"];
        description = "Transport this listener binds (required for every entry).";
      };
    };

  # Reusable `server` option set. `transportDefaults` is deep-merged
  # (Python-side) into every `transports` entry; the genuinely non-transport
  # options stay flat. The old flat transport/host/port/... options are removed
  # outright: a partially-migrated config fails evaluation loudly rather than
  # binding the wrong transport.
  mkServerOptions = {
    lib,
    pkgs,
  }: let
    inherit (lib) mkEnableOption mkOption types;
    requiredOid = "1.3.6.1.4.1.99999.1.1"; # sudo server cert EKU
    peerOid = "1.3.6.1.4.1.99999.1.2"; # sudo client cert EKU
  in {
    enable = mkEnableOption "the sudo-auth-proxy server (host side)";

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

    debug = mkOption {
      type = types.bool;
      default = false;
      description = "Log connection/handshake/request timing to stderr for latency debugging.";
    };

    extraSettings = mkOption {
      type = types.attrs;
      default = {};
      description = "Extra top-level keys merged into the generated TOML configuration.";
    };

    transportDefaults = mkOption {
      type = types.submodule {
        options = mkListenerOptions {
          inherit lib pkgs requiredOid peerOid;
          nullable = false;
          withType = false;
        };
      };
      default = {};
      description = "Default values deep-merged into every entry of `transports`.";
    };

    transports = mkOption {
      type = types.listOf (types.submodule {
        options = mkListenerOptions {
          inherit lib pkgs requiredOid peerOid;
          nullable = true;
          withType = true;
        };
      });
      default = [];
      description = ''
        One entry per transport this server binds, all in the single server
        process. Multiple entries of the same `type` are allowed (e.g. two
        `unix` listeners with different ACLs). Empty means the server binds
        nothing and, when enabled, the module rejects the configuration.
      '';
    };
  };

  # Recursively drop `null` attributes (the spec's `pruneNulls`). Needed because
  # `pkgs.formats.toml` (json2toml) refuses `null`, and every sparse
  # `transports` entry carries `null` for the fields it does not override.
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
  # triple for one listener entry, using the entry's own `type` and the
  # `transportDefaults` fallback. This mirrors the Python exactly: the defaults
  # are `recursiveUpdate`d under the entry *after* the entry's nulls are pruned
  # (otherwise every sparse entry would clobber the defaults with `null`).
  # `mtls.enable` forces mTLS; `auto` follows the type (tcp → mtls else none);
  # and mTLS forces both auths to "transport".
  mkResolveSecurity = {
    lib,
    defaults,
  }: prune: entry: let
    merged = lib.recursiveUpdate defaults (prune entry);
    requested = merged.security.transportEncryption;
    effectiveTransportEncryption =
      if merged.mtls.enable
      then "mtls"
      else if requested != "auto"
      then requested
      else if (entry.type or null) == "tcp"
      then "mtls"
      else "none";
    forceTransportAuth = effectiveTransportEncryption == "mtls";
    effectiveClientAuth =
      if forceTransportAuth
      then "transport"
      else merged.security.clientAuth;
    effectiveServerAuth =
      if forceTransportAuth
      then "transport"
      else merged.security.serverAuth;
  in {
    inherit
      effectiveTransportEncryption
      effectiveClientAuth
      effectiveServerAuth
      ;
  };

  # Render the whole server TOML document for one server instance:
  # `mode`/`dialog_program`/`debug`, the fully-rendered `[transport_defaults]`
  # block, then a sparse `[[transports]]` entry per listener. `pkgs.formats.toml`
  # is fed the already-pruned attrset (json2toml is fatal on `null`).
  renderServerToml = {
    lib,
    server,
  }: let
    prune = mkPruneNulls lib;
    defaults = server.transportDefaults;
    resolve = mkResolveSecurity {inherit lib defaults;} prune;

    # One listener (or the defaults block). `isEntry = false` renders the
    # defaults fully: every field has a real value and the `[mtls]` paths are
    # emitted even with `enable = false`, because the Python needs them when an
    # entry resolves to mTLS via `auto` on `tcp`.
    renderListener = {
      entry,
      isEntry,
    }: let
      resolved = resolve entry;

      securityValues =
        if isEntry
        then {
          transport_encryption = resolved.effectiveTransportEncryption;
          client_auth = resolved.effectiveClientAuth;
          server_auth = resolved.effectiveServerAuth;
        }
        else {
          transport_encryption = defaults.security.transportEncryption;
          client_auth = defaults.security.clientAuth;
          server_auth = defaults.security.serverAuth;
        };
      security = prune (securityValues
        // {
          response_ttl = entry.security.responseTtl;
          clock_skew = entry.security.clockSkew;
        });

      # Emit `[mtls]` for the defaults block always; for an entry only when it
      # resolves to mTLS. An entry always advertises `enable = true` (as the old
      # emitter did); the defaults block carries the literal `enable` value.
      mtls =
        if isEntry && resolved.effectiveTransportEncryption != "mtls"
        then null
        else
          prune {
            enable =
              if isEntry
              then true
              else entry.mtls.enable;
            ca_file = entry.mtls.caFile;
            cert_file = entry.mtls.certFile;
            key_file = entry.mtls.keyFile;
            required_oid = entry.mtls.requiredOid;
            peer_required_oid = entry.mtls.peerOid;
          };

      acl = prune (
        {mode = entry.acl.mode;}
        // lib.optionalAttrs (entry.acl.trustedFingerprints != [] && entry.acl.trustedFingerprints != null) {
          trusted_fingerprints = entry.acl.trustedFingerprints;
        }
        // lib.optionalAttrs (entry.acl.caFile != null) {ca_file = entry.acl.caFile;}
        // lib.optionalAttrs (entry.acl.requiredOid != null) {required_oid = entry.acl.requiredOid;}
        // lib.optionalAttrs (entry.acl.rule != [] && entry.acl.rule != null) {
          rule =
            map (r: {
              identity = r.identity;
              target_user = r.targetUser;
              invoking_user = r.invokingUser;
              service = r.service;
              policy = r.policy;
            })
            entry.acl.rule;
        }
      );

      scalars = {
        port = entry.port;
        cid = entry.cid;
        host = entry.host;
        socket = entry.socket;
        socket_dir_mode = entry.socketDirMode;
        socket_mode = entry.socketMode;
        connect_timeout = entry.connectTimeout;
        decision_timeout = entry.decisionTimeout;
        recv_timeout = entry.recvTimeout;
        max_connections = entry.maxConnections;
        server_read_timeout = entry.serverReadTimeout;
        resolution = entry.resolution;
      };
    in
      prune (
        (
          if isEntry
          then {type = entry.type;}
          else {}
        )
        // scalars
        // lib.optionalAttrs (security != {}) {security = security;}
        // lib.optionalAttrs (mtls != null && mtls != {}) {mtls = mtls;}
        // lib.optionalAttrs (acl != {}) {acl = acl;}
      );

    document =
      {
        mode = "server";
        dialog_program = server.dialogProgram;
      }
      // lib.optionalAttrs server.debug {debug = true;}
      // {
        transport_defaults = renderListener {
          entry = defaults;
          isEntry = false;
        };
        transports = map (entry:
          renderListener {
            inherit entry;
            isEntry = true;
          })
        server.transports;
      }
      // server.extraSettings;
  in
    prune document;

  # Per-listener assertions for one server instance (doc §2.4). Every entry must
  # satisfy `transport_encryption = "none" ⇒ client_auth = server_auth = "none"`,
  # resolving the auths from the merged defaults so a sparse entry that only
  # sets `transportEncryption = "none"` fails loudly instead of silently
  # disabling authentication. An enabled server with no listeners is rejected.
  mkServerAssertions = {
    lib,
    server,
  }: let
    prune = mkPruneNulls lib;
    defaults = server.transportDefaults;
    resolve = mkResolveSecurity {inherit lib defaults;} prune;
  in
    map (entry: {
      assertion = let
        resolved = resolve entry;
      in
        resolved.effectiveTransportEncryption
        != "none"
        || (resolved.effectiveClientAuth == "none" && resolved.effectiveServerAuth == "none");
      message = ''
        tartarus.sudo-auth-proxy.server.transports: transport_encryption = "none"
        requires client_auth = server_auth = "none" (entry type = ${entry.type}).
      '';
    })
    server.transports
    ++ lib.optional (server.enable && server.transports == []) {
      assertion = false;
      message = "tartarus.sudo-auth-proxy.server.enable = true requires at least one entry in server.transports.";
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

      server = mkServerOptions {inherit lib pkgs;};

      # A second, independent server instance. It has its own `transports` /
      # `transportDefaults` listeners and config file, and runs as a unit named
      # `sudo-auth-proxy-<name>`; the `server` above stays the default instance.
      # This lets one host run, for example, the tartarus guest callback server
      # alongside an SSH-forwarded `unix` server for a remote host.
      #
      # Modelled as a plain nested option set (like `server`) rather than an
      # `attrsOf (submodule)`: reading an `attrsOf submodule` value inside the
      # same module graph forces the root config and recurses, whereas a nested
      # option set resolves like `server.enable` does.
      extraServer =
        mkServerOptions {inherit lib pkgs;}
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
            effectiveTransportEncryption
            != "none"
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
      concatStringsSep
      mkIf
      mkMerge
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

    # Build the config path + generated TOML for one named server instance.
    mkServerFiles = {
      name,
      server,
    }: let
      configPath =
        if server.configPath != null
        then server.configPath
        else "${config.home.homeDirectory}/.config/sudo-auth-proxy/${name}.toml";
    in {
      inherit configPath;
      configFile = tomlFormat.generate "sudo-auth-proxy-server-${name}.toml" (renderServerToml {inherit lib server;});
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
      });
  in {
    config = mkIf cfg.extraServer.enable (mkMerge [
      {
        assertions = mkServerAssertions {
          inherit lib;
          server = cfg.extraServer;
        };
      }
      {home.packages = [package];}
      (mkService {
        name = instance.name;
        description = "sudo authentication proxy server (${concatStringsSep "," (map (t: t.type) instance.server.transports)})";
        command = "${package}/bin/sudo-auth-proxy --config ${instance.configPath}";
        # Its own runtime dir, matching the `sudo-auth-proxy-<name>` unit; the
        # Python re-creates/chmods it regardless (doc §9.1).
        extraSystemdServiceConfig = {
          RuntimeDirectory = instance.runtimeDir;
          RuntimeDirectoryMode = "0700";
        };
        # The server reads its config once at startup, so a changed
        # `[[transports]]`/`security`/`acl` document must restart the unit.
        # `home-manager switch` only diffs the *unit*, not the files it reads;
        # pinning the generated config path into `X-Restart-Triggers` makes the
        # unit change whenever the config content does, so sd-switch restarts it.
        extraSystemdUnitConfig = {
          X-Restart-Triggers = [instance.configFile];
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
      concatStringsSep
      mkIf
      mkMerge
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

    # The generated server TOML: `[transport_defaults]` + `[[transports]]`, one
    # listener per entry in `server.transports`. See `renderServerToml`.
    configFile = tomlFormat.generate "sudo-auth-proxy-server.toml" (renderServerToml {inherit lib server;});
  in {
    imports = [optionsModule namedServersModule];

    config = mkIf (cfg.enable || server.enable) (mkMerge [
      # Fail at evaluation time, not inside the server (doc §7.5). Every
      # listener must not disable authentication without saying so explicitly,
      # and an enabled server needs at least one listener.
      {
        assertions = mkServerAssertions {
          inherit lib server;
        };
      }
      (mkService {
        name = "sudo-auth-proxy";
        description = "sudo authentication proxy server (${concatStringsSep "," (map (t: t.type) server.transports)})";
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
        # Restart the server when its generated config changes; see the
        # `extraServer` instance above for why `home-manager switch` needs this.
        extraSystemdUnitConfig = {
          X-Restart-Triggers = [configFile];
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

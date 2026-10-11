# ssh-agent-proxy: a host-side agent proxy (VSOCK or TCP) that selectively
# forwards the host's SSH identities to guests, plus the guest-side pieces:
# a bridge to the host proxy, the local ssh-agent and an allow-all merge proxy.
#
# Flattened from nixcfg's `services/user/{ssh-agent-proxy,ssh-agent-host,
# ssh-agent,ssh-agent-merge}.nix` and exposed as a standalone package plus a
# NixOS module (server as a system service) and a home-manager module (server,
# bridge, agent and merge as user services). Units use `nix-service` (§3.7).
#
#   tartarus.ssh-agent-proxy.server   proxy server (host side)
#   tartarus.ssh-agent-proxy.bridge   guest-side bridge to the host proxy
#   tartarus.ssh-agent-proxy.agent    guest-local ssh-agent
#   tartarus.ssh-agent-proxy.merge    guest-local allow-all merge proxy
{inputs}: let
  mkPackage = {
    pkgs,
    lib ? pkgs.lib,
  }: let
    pythonEnv = pkgs.python3.withPackages (ps:
      [ps.cryptography]
      ++ lib.optionals (!pkgs.stdenv.isDarwin) [
        # D-Bus notifications and libvirt (dynamic VSOCK CID -> VM-name
        # resolution) are Linux-only.
        ps.dbus-python
        ps.libvirt
      ]);
  in
    pkgs.writeShellApplication {
      name = "ssh-agent-proxy";
      runtimeInputs =
        [pythonEnv]
        ++ lib.optionals (!pkgs.stdenv.isDarwin) [pkgs.zenity];
      text = ''
        exec ${pythonEnv.interpreter} -P ${./ssh-agent-proxy.py} "$@"
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

  # `home.file` fragment writing one environment.d file (later filenames win
  # under systemd's ordering, giving us a clean override chain).
  mkEnvFile = {lib}: name: attrs: {
    home.file.".config/environment.d/${name}".text = lib.concatStrings (
      lib.mapAttrsToList (k: v: "${k}=${v}\n") attrs
    );
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

    # A field that is `null` by default in the sparse (entry) variant of a
    # listener and carries its real default in the `transportDefaults`
    # variant. `pkgs.formats.toml` cannot serialize `null`, so sparse entries
    # are pruned before generation (see `pruneNulls`).
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

    # Reusable `[security]` option set, shared by the server listeners and the
    # client bridge. `mtls.enable` remains the legacy alias for
    # `transportEncryption = "mtls"`; the Python layer resolves `auto` from the
    # listener type (tcp → mtls, vsock/unix → none) and never downgrades.
    # `nullable = true` yields the sparse entry variant used inside
    # `transports`; `nullable = false` the defaults variant.
    mkSecurityOptions = {
      lib,
      nullable ? false,
      # The client/bridge reads the connect/handshake/decision timeouts off its
      # `[security]` table; server listeners carry them at the listener level
      # instead (see `mkListenerOptions`), so they are opt-in here.
      withTimeouts ? false,
    }: let
      inherit (lib) mkOption types;
      o = nullableOpt {inherit lib nullable;};
    in
      {
        transportEncryption = mkOption ((o (types.enum ["auto" "none" "mtls"]) "auto")
          // {
            description = ''
              Whether the byte stream is encrypted and integrity-protected.
              `auto` (default) follows the listener's `type`: `tcp` → `mtls`,
              `vsock`/`unix` → `none`. `mtls` is an explicit choice and never a
              runtime fallback.
            '';
          });
        clientAuth = mkOption ((o (types.enum ["transport" "none"]) "transport")
          // {
            description = ''
              How the server authenticates the requester. `transport` means the
              identity comes from the mTLS handshake and is forced whenever the
              listener is mTLS; `none` disables requester authentication entirely
              (an explicit, warned choice only appropriate on a private-by-
              construction transport).
            '';
          });
        serverAuth = mkOption ((o (types.enum ["transport" "none"]) "transport")
          // {
            description = ''
              How the client authenticates the server's messages. `transport`
              requires `transportEncryption = "mtls"` (and is then forced).
            '';
          });
      }
      // lib.optionalAttrs withTimeouts {
        connectTimeout =
          mkOption ((o types.float 10.0)
            // {description = "Seconds to wait for the transport connect before failing fast.";});
        handshakeTimeout =
          mkOption ((o types.float 10.0)
            // {description = "Seconds to wait for the TLS handshake before failing fast.";});
        decisionTimeout =
          mkOption ((o types.int 120)
            // {description = "Seconds to wait for the human decision (0 = wait indefinitely).";});
      };

    # Reusable `[mtls]` option set for one listener. Extracted so it can be
    # instantiated in both `transportDefaults` and every `transports` entry.
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
          description = "Enable mutual TLS for this listener.";
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

    # One listener's option set, instantiated twice: `withType = false` for
    # the `transportDefaults` block (real defaults, no `type`) and
    # `withType = true` for a `transports` entry (requires `type`; every other
    # field is a sparse `nullOr` override). All address fields are accepted on
    # every listener; each is only meaningful for its own `type`.
    sshListenerOptions = {
      lib,
      nullable,
      withType,
      requiredOid,
      peerOid,
    }: let
      inherit (lib) mkOption types;
      o = nullableOpt {inherit lib nullable;};
    in
      {
        port = mkOption ((o types.port 65000)
          // {
            description = "Port the listener binds (tcp and vsock).";
          });
        cid = mkOption ((o types.int 2)
          // {
            description = "VSOCK context ID to bind to (2 = host). Only used with type = \"vsock\".";
          });
        host = mkOption ((o types.str "127.0.0.1")
          // {
            description = "TCP address to bind to. Only used with type = \"tcp\".";
          });
        socket = mkOption ((o types.str "%t/ssh-agent-proxy/server.sock")
          // {
            description = ''
              Unix socket the listener binds (type = "unix"). Identity comes from
              the mTLS certificate or is unset, never the socket path.
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
        connectTimeout = mkOption ((o types.float 10.0)
          // {
            description = "Seconds to wait for the transport connect before failing fast.";
          });
        handshakeTimeout = mkOption ((o types.float 10.0)
          // {
            description = "Seconds to wait for the TLS handshake before failing fast.";
          });
        decisionTimeout = mkOption ((o types.int 120)
          // {
            description = "Seconds to wait for the human decision (0 = wait indefinitely).";
          });
        resolution = mkOption ((o (types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"])) null)
          // {
            description = ''
              How to resolve a connecting VM's name: `none`, `certificate`
              (verified peer cert CN), `tartarus` (local VM bookkeeping), or
              `mofos` (`mofos ls --json`). When unset it resolves to `certificate`
              when the listener is mTLS and `none` otherwise. `tartarus`/`mofos`
              are rejected on the `unix` type (no CID/IP exists there).
            '';
          });
        security = mkSecurityOptions {inherit lib nullable;};
        mtls = mkMtlsOptions {inherit lib nullable requiredOid peerOid;};
      }
      // lib.optionalAttrs withType {
        type = mkOption {
          type = types.enum ["vsock" "tcp" "unix"];
          description = "Transport this listener binds (required for every entry).";
        };
      };

    tcpVmType = types.listOf (types.submodule {
      options = {
        ip = mkOption {
          type = types.str;
          description = "Guest source IP address, e.g. 10.200.0.3.";
        };
        name = mkOption {
          type = types.str;
          description = "VM name, matched against rule.match.vm_names.";
        };
      };
    });
    vmType = types.listOf (types.submodule {
      options = {
        cid = mkOption {
          type = types.ints.positive;
          description = "The guest's VSOCK context ID (CID).";
        };
        name = mkOption {
          type = types.str;
          description = "VM name, matched against rule.match.vm_names.";
        };
      };
    });
    keyType = types.listOf (types.submodule {
      options = {
        id = mkOption {
          type = types.str;
          description = "Human-readable identifier for the key.";
        };
        pubkey = mkOption {
          type = types.str;
          description = "SSH public key string (type + base64 blob).";
        };
        socket = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Optional path to the agent socket for this key.";
        };
      };
    });
    ruleType = types.listOf (types.submodule {
      options = {
        key = mkOption {
          type = types.str;
          default = "*";
          description = "Key id to match (fnmatch), or '*' for any key.";
        };
        match = mkOption {
          type = types.submodule {
            options.vm_names = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "VM name patterns (fnmatch) this rule applies to.";
            };
          };
          default = {};
        };
        auth = mkOption {
          type = types.enum ["deny" "ask" "allow"];
          default = "ask";
          description = "Policy for SSH authentication requests.";
        };
        data_signing = mkOption {
          type = types.enum ["deny" "ask" "allow"];
          default = "deny";
          description = "Policy for data signing requests (defaults to deny).";
        };
        notify = mkOption {
          type = types.bool;
          default = true;
          description = "Send a desktop notification when the key is used.";
        };
        allowed_host_keys = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "Allowed destination host keys/hostnames/patterns.";
        };
      };
    });
  in {
    options.tartarus.ssh-agent-proxy = {
      enable = mkEnableOption "the ssh-agent-proxy service (server role)";
      server = {
        enable = mkEnableOption "the ssh-agent-proxy server (host side)";

        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the generated proxy config. Defaults to `~/.config/ssh-agent-proxy/config.toml`.";
        };

        # Genuinely global (non-transport) policy. The `settings` freeform is
        # the shared VM/key/rule policy the Python parses once; it is never
        # per listener.
        settings = mkOption {
          type = types.submodule {
            freeformType = tomlFormat.type;
            options = {
              vm = mkOption {
                type = vmType;
                default = [];
                description = "Static CID -> VM name mapping, checked first.";
              };
              libvirt_uri = mkOption {
                type = types.nullOr types.str;
                default = null;
                example = "qemu:///system";
                description = "libvirt connection URI used to resolve a VM name from its CID.";
              };
              tcp_vm = mkOption {
                type = tcpVmType;
                default = [];
                description = "Static peer IP -> VM name mapping for TCP listeners.";
              };
              default_agent_socket_path = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Default SSH agent socket. Null uses `$SSH_AUTH_SOCK` at runtime.";
              };
              known_hosts_files = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "known_hosts files for host-key lookup.";
              };
              forward_sockets = mkOption {
                type = types.nullOr (types.listOf types.str);
                default = null;
                description = "Agent sockets whose identities are auto-forwarded to every VM.";
              };
              key = mkOption {
                type = keyType;
                default = [];
                description = "SSH keys to expose through the proxy.";
              };
              rule = mkOption {
                type = ruleType;
                default = [];
                description = "Policy rules evaluated in order; first match wins.";
              };
            };
          };
          default = {};
          description = "Global (non-transport) contents of the ssh-agent-proxy TOML config file.";
        };

        # Defaults deep-merged into every `transports` entry by the Python.
        transportDefaults = mkOption {
          type = types.submodule {
            options = sshListenerOptions {
              inherit lib;
              nullable = false;
              withType = false;
              requiredOid = serverRequiredOid;
              peerOid = serverPeerOid;
            };
          };
          default = {};
          description = "Default values for every field of every entry in `transports`.";
        };

        # The listeners, all bound by the single server process.
        transports = mkOption {
          type = types.listOf (types.submodule {
            options = sshListenerOptions {
              inherit lib;
              nullable = true;
              withType = true;
              requiredOid = serverRequiredOid;
              peerOid = serverPeerOid;
            };
          });
          default = [];
          description = ''
            One entry per transport this server binds, all in the single server
            process. Multiple entries of the same `type` are allowed (e.g. two
            `unix` listeners with different sockets). Empty means the server
            binds nothing and the module rejects the configuration when
            `enable = true`.
          '';
        };

        dialogProgram = mkOption {
          type = types.enum ["swiftdialog" "osascript" "zenity"];
          default =
            if pkgs.stdenv.hostPlatform.isDarwin
            then "swiftdialog"
            else "zenity";
          description = "Program used to show the key-use confirmation prompt.";
        };

        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
      };

      bridge = {
        enable = mkEnableOption "the guest-side bridge to the host's ssh-agent-proxy";

        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the client config. Defaults to `~/.config/ssh-agent-proxy/config.toml`.";
        };

        listenSocket = mkOption {
          type = types.str;
          default = "%t/ssh-agent-host";
          description = "Unix socket path the bridge listens on inside the guest.";
        };

        setSshAuthSock = mkOption {
          type = types.bool;
          default = true;
          description = "Point SSH_AUTH_SOCK at this bridge's local socket.";
        };

        transport = mkOption {
          type = types.enum ["vsock" "tcp" "unix"];
          default = "tcp";
          description = "Transport used to reach the host's ssh-agent-proxy.";
        };

        connectSocket = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            AF_UNIX path to dial on the `unix` transport. Null falls back to the
            `$SSH_AUTH_PROXY_SOCK` selector exported by the SSH session.
          '';
        };

        vsockCid = mkOption {
          type = types.int;
          default = 2;
          description = "Deprecated alias: VSOCK CID of the host (2). Only used with vsock.";
        };

        vsockPort = mkOption {
          type = types.port;
          default = 65000;
          description = "Deprecated alias: VSOCK port the host's proxy listens on.";
        };

        host = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "Host address of the host's proxy. Only used when transport is tcp.";
        };

        port = mkOption {
          type = types.port;
          default = 65000;
          description = "Port the host's proxy listens on. Used when transport is tcp or vsock.";
        };

        security = mkSecurityOptions {
          inherit lib;
          withTimeouts = true;
        };

        mtls = {
          enable = mkEnableOption "mutual TLS authentication for the client connection";
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
            default = "1.3.6.1.4.1.99999.2.2";
            description = "EKU OID the local client certificate must contain.";
          };
          peerOid = mkOption {
            type = types.str;
            default = "1.3.6.1.4.1.99999.2.1";
            description = "EKU OID the peer (server) certificate must contain.";
          };
        };

        extraSettings = mkOption {
          type = types.attrs;
          default = {};
          description = "Extra settings merged into the generated TOML configuration.";
        };

        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
      };

      agent = {
        enable = mkEnableOption "the guest-local ssh-agent";

        useKeychain = mkOption {
          type = types.bool;
          default = false;
          description = "macOS only: run Apple's keychain-aware ssh-agent and preload identities.";
        };

        socketDir = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Absolute directory the agent socket lives in (macOS only).";
        };

        socketName = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Filename of the agent socket (defaults to `ssh-agent`).";
        };
      };

      merge = {
        enable = mkEnableOption "the guest-local allow-all agent merge proxy";

        sockets = mkOption {
          type = types.listOf types.str;
          default = [];
          example = ["%t/openssh_agent" "%t/gnupg/S.gpg-agent.ssh"];
          description = ''
            Upstream agent sockets to merge, in priority order. A directory is
            also accepted: it is scanned for sockets on every client connection,
            so per-session forwarded sockets are picked up as they appear.
          '';
        };

        listenSocket = mkOption {
          type = types.str;
          default = "";
          description = "Unix socket the merge proxy creates and listens on.";
        };

        setSshAuthSock = mkOption {
          type = types.bool;
          default = false;
          description = "Point SSH_AUTH_SOCK at the merged socket (overrides agent/bridge).";
        };
      };
    };
  };

  # pkgs.formats.toml cannot serialize `null` anywhere in the tree, and both
  # sparse `transports` entries and submodule defaults carry nulls once
  # realized, so strip them recursively through attrsets and lists.
  lib0 = inputs.nixpkgs.lib;
  pruneNulls = v:
    if builtins.isAttrs v
    then lib0.mapAttrs (_: pruneNulls) (lib0.filterAttrs (_: x: x != null) v)
    else if builtins.isList v
    then map pruneNulls v
    else v;

  # The effective value of one listener: `transportDefaults` with the entry's
  # explicitly-set (non-null) fields merged on top, exactly like the Python's
  # `_deep_merge(defaults, entry)`.
  effectiveListener = {
    lib,
    defaults,
    entry,
  }:
    lib.recursiveUpdate (pruneNulls defaults) (pruneNulls entry);

  # `auto` follows the listener type exactly as `validate_security_config`:
  # `mtls.enable` wins, an explicit `transport_encryption` is honoured,
  # otherwise `tcp` is mTLS and `vsock`/`unix` are plaintext.
  resolveTransportEncryption = {
    type,
    mtlsEnabled,
    requested,
  }:
    if mtlsEnabled
    then "mtls"
    else if requested != "auto"
    then requested
    else if type == "tcp"
    then "mtls"
    else "none";

  # The generated server TOML (`mode = "proxy"`): global scalars plus the
  # global `settings`, the `[transport_defaults]` block and one `[[transports]]`
  # table per listener. `connect_timeout`/`handshake_timeout`/
  # `decision_timeout` live at the listener level, where `Config.load` reads
  # them (the previous [`security`] placement was dead config).
  mkServerToml = {lib}: server: let
    inherit (lib) optionalAttrs;

    renderSecurity = transportEncryption: {
      transport_encryption = transportEncryption;
      # mTLS forces both auths to `transport`; plaintext requires both `none`.
      client_auth =
        if transportEncryption == "mtls"
        then "transport"
        else "none";
      server_auth =
        if transportEncryption == "mtls"
        then "transport"
        else "none";
    };

    renderMtls = mtls: {
      enable = mtls.enable;
      ca_file = mtls.caFile;
      cert_file = mtls.certFile;
      key_file = mtls.keyFile;
      required_oid = mtls.requiredOid;
      peer_required_oid = mtls.peerOid;
    };

    # `transportDefaults` is instantiated with `nullable = false`, so its
    # fields carry real defaults and render in full.
    renderDefaults = defaults:
      {
        port = defaults.port;
        cid = defaults.cid;
        host = defaults.host;
        socket = defaults.socket;
        socket_dir_mode = defaults.socketDirMode;
        socket_mode = defaults.socketMode;
        connect_timeout = defaults.connectTimeout;
        handshake_timeout = defaults.handshakeTimeout;
        decision_timeout = defaults.decisionTimeout;
        security = {
          transport_encryption = defaults.security.transportEncryption;
          client_auth = defaults.security.clientAuth;
          server_auth = defaults.security.serverAuth;
        };
        mtls = renderMtls defaults.mtls;
      }
      // optionalAttrs (defaults.resolution != null) {resolution = defaults.resolution;};

    # A `transports` entry is a sparse override: only the fields it actually
    # set render. `security` is always resolved (and emitted) so no entry has
    # to rely on the defaults' `client_auth`/`server_auth` under plaintext,
    # which the Python rejects; `mtls` is emitted only for an mTLS listener.
    renderEntry = entry: let
      merged = effectiveListener {
        inherit lib;
        defaults = server.transportDefaults;
        inherit entry;
      };
      transportEncryption = resolveTransportEncryption {
        type = entry.type;
        mtlsEnabled = merged.mtls.enable;
        requested = merged.security.transportEncryption;
      };
      fields = {
        type = entry.type;
        port = entry.port;
        cid = entry.cid;
        host = entry.host;
        socket = entry.socket;
        socket_dir_mode = entry.socketDirMode;
        socket_mode = entry.socketMode;
        connect_timeout = entry.connectTimeout;
        handshake_timeout = entry.handshakeTimeout;
        decision_timeout = entry.decisionTimeout;
        resolution = entry.resolution;
      };
    in
      pruneNulls (
        fields
        // {security = renderSecurity transportEncryption;}
        // optionalAttrs (transportEncryption == "mtls") {mtls = renderMtls merged.mtls;}
      );
  in
    {
      mode = "proxy";
      dialog_program = server.dialogProgram;
    }
    // optionalAttrs server.debug {debug = true;}
    // pruneNulls server.settings
    // {
      transport_defaults = renderDefaults server.transportDefaults;
      transports = map renderEntry server.transports;
    };

  # Eval-time guards, evaluated per listener (each sees the same effective
  # values the Python will after its own deep-merge).
  serverAssertions = {lib}: server: let
    inherit (lib) optional;
    perEntry = entry: let
      merged = effectiveListener {
        inherit lib;
        defaults = server.transportDefaults;
        inherit entry;
      };
      requested = merged.security.transportEncryption;
      transportEncryption = resolveTransportEncryption {
        type = entry.type;
        mtlsEnabled = merged.mtls.enable;
        requested = requested;
      };
      resolution =
        if (merged.resolution or null) != null
        then merged.resolution
        else if transportEncryption == "mtls"
        then "certificate"
        else "none";
    in [
      {
        assertion =
          !(merged.mtls.enable
            && requested != "auto"
            && requested != "mtls");
        message = "tartarus.ssh-agent-proxy.server.transports: mtls.enable = true conflicts with security.transportEncryption = \"${requested}\" (entry type = \"${entry.type}\"); refusing to downgrade.";
      }
      {
        assertion =
          !(entry.type == "unix" && (resolution == "tartarus" || resolution == "mofos"));
        message = "tartarus.ssh-agent-proxy.server.transports: the unix listener only supports resolution = \"none\" or \"certificate\" (entry type = \"unix\").";
      }
    ];
  in
    lib.concatMap perEntry server.transports
    ++ optional (server.enable && server.transports == []) {
      assertion = false;
      message = "tartarus.ssh-agent-proxy.server.enable = true requires at least one entry in server.transports.";
    };

  serverRequiredOid = "1.3.6.1.4.1.99999.2.1";
  serverPeerOid = "1.3.6.1.4.1.99999.2.2";
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
    inherit (lib) mkIf;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = false;
      homeManager = false;
    };
    cfg = config.tartarus.ssh-agent-proxy;
    server = cfg.server;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};
    configPath =
      if server.configPath != null
      then server.configPath
      else "/etc/ssh-agent-proxy/config.toml";
    configFile = tomlFormat.generate "ssh-agent-proxy.toml" (pruneNulls (mkServerToml {inherit lib;} server));
  in {
    imports = [optionsModule];

    config = mkIf (cfg.enable || server.enable) (lib.mkMerge [
      (mkService {
        name = "ssh-agent-proxy";
        description = "SSH agent proxy via its configured listeners";
        command = "${package}/bin/ssh-agent-proxy --config ${configPath}${lib.optionalString server.debug " --debug"}";
        scope = "system";
        environment = lib.optionalAttrs (server.settings.default_agent_socket_path == null) {
          SSH_AUTH_SOCK = "/run/ssh-agent-proxy/ssh-agent";
        };
      })
      {
        environment.etc."ssh-agent-proxy/config.toml".source = configFile;
        environment.systemPackages = [package];
      }
      {
        assertions = serverAssertions {inherit lib;} server;
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
      optionalString
      replaceStrings
      ;
    system = args.system or builtins.currentSystem;
    username = config.home.username;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = lib.hasSuffix "-darwin" system;
      homeManager = true;
    };
    cfg = config.tartarus.ssh-agent-proxy;
    server = cfg.server;
    bridge = cfg.bridge;
    agent = cfg.agent;
    merge = cfg.merge;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};
    isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

    home = config.home.homeDirectory;
    serverConfigPath =
      if server.configPath != null
      then server.configPath
      else "${home}/.config/ssh-agent-proxy/config.toml";
    bridgeConfigPath =
      if bridge.configPath != null
      then bridge.configPath
      else "${home}/.config/ssh-agent-proxy/config.toml";

    serverConfigFile = tomlFormat.generate "ssh-agent-proxy.toml" (pruneNulls (mkServerToml {inherit lib;} server));

    bridgeTransportEncryption =
      if bridge.mtls.enable
      then "mtls"
      else if bridge.security.transportEncryption != "auto"
      then bridge.security.transportEncryption
      else if bridge.transport == "tcp"
      then "mtls"
      else "none";
    bridgeForceTransportAuth = bridgeTransportEncryption == "mtls";
    bridgeSecurity = {
      transport_encryption = bridgeTransportEncryption;
      client_auth =
        if bridgeForceTransportAuth
        then "transport"
        else "none";
      server_auth =
        if bridgeForceTransportAuth
        then "transport"
        else "none";
      connect_timeout = bridge.security.connectTimeout;
      handshake_timeout = bridge.security.handshakeTimeout;
      decision_timeout = bridge.security.decisionTimeout;
    };
    bridgeConnection =
      {
        transport = bridge.transport;
        listen_socket = bridge.listenSocket;
        port =
          if bridge.transport == "vsock"
          then bridge.vsockPort
          else bridge.port;
        security = bridgeSecurity;
      }
      // optionalAttrs (bridge.transport == "vsock") {cid = bridge.vsockCid;}
      // optionalAttrs (bridge.transport == "tcp") {host = bridge.host;}
      // optionalAttrs (bridge.transport == "unix") {connect_socket = bridge.connectSocket;}
      // optionalAttrs bridgeForceTransportAuth {
        mtls = {
          enable = true;
          ca_file = bridge.mtls.caFile;
          cert_file = bridge.mtls.certFile;
          key_file = bridge.mtls.keyFile;
          required_oid = bridge.mtls.requiredOid;
          peer_required_oid = bridge.mtls.peerOid;
        };
      };
    bridgeConfigFile = tomlFormat.generate "ssh-agent-host.toml" (
      pruneNulls (lib.recursiveUpdate ({mode = "client";} // bridgeConnection) bridge.extraSettings)
    );

    # ---- agent ----
    socketName =
      if agent.socketName != null
      then agent.socketName
      else "ssh-agent";
    socketDir =
      if agent.socketDir != null
      then agent.socketDir
      else if isDarwin
      then "$(getconf DARWIN_USER_TEMP_DIR)"
      else "$XDG_RUNTIME_DIR";
    socketPath = "${socketDir}/${socketName}";
    darwinLaunch = pkgs.writeShellScript "ssh-agent-launch" ''
      set -e
      mkdir -p ${lib.escapeShellArg socketDir}
      export SSH_AUTH_SOCK=${lib.escapeShellArg socketPath}
      /usr/bin/ssh-agent -D -a "${socketPath}" &
      AGENT_PID=$!
      ${optionalString agent.useKeychain ''
        /usr/bin/ssh-add -A < /dev/null || true
      ''}
      wait "$AGENT_PID"
    '';

    # ---- merge ----
    mergeSockets =
      if merge.sockets != []
      then merge.sockets
      else if isDarwin
      then [
        "__APPLE_SSH_AUTH_SOCK__"
        "${home}/.gnupg/S.gpg-agent.ssh"
      ]
      else [
        "%t/${config.services.ssh-agent.socket}"
        "%t/gnupg/S.gpg-agent.ssh"
      ];
    mergeListen =
      if merge.listenSocket != ""
      then merge.listenSocket
      else if isDarwin
      then "${home}/.ssh/.ssh-agent-merged.sock"
      else "%t/ssh-agent-merged";
    mergeEnv =
      if isDarwin
      then mergeListen
      else replaceStrings ["%t"] ["$XDG_RUNTIME_DIR"] mergeListen;

    envFile = mkEnvFile {inherit lib;};
  in {
    imports = [optionsModule];

    config = mkMerge [
      (mkIf (cfg.enable || server.enable) (mkMerge [
        (mkService {
          name = "ssh-agent-proxy";
          description = "SSH agent proxy via its configured listeners";
          command = "${package}/bin/ssh-agent-proxy --config ${serverConfigPath}${optionalString server.debug " --debug"}";
          environment = optionalAttrs (server.settings.default_agent_socket_path == null) {
            SSH_AUTH_SOCK = "%t/ssh-agent";
          };
        })
        {
          home.packages = [package];
          home.file.${serverConfigPath}.source = serverConfigFile;
        }
        {
          assertions = serverAssertions {inherit lib;} server;
        }
      ]))

      (mkIf bridge.enable (mkMerge [
        (mkService {
          name = "ssh-agent-host";
          description = "SSH agent host bridge (${bridge.transport})";
          command = "${package}/bin/ssh-agent-proxy --config ${bridgeConfigPath}${optionalString bridge.debug " --debug"}";
          extraSystemdServiceConfig = {
            StandardOutput = "journal";
            StandardError = "journal";
          };
        })
        (lib.mkIf bridge.setSshAuthSock (envFile "50-tartarus-ssh-agent-host.conf" {
          SSH_AUTH_SOCK = replaceStrings ["%t"] ["$XDG_RUNTIME_DIR"] bridge.listenSocket;
        }))
        {
          home.packages = [package];
          home.file.${bridgeConfigPath}.source = bridgeConfigFile;
        }
      ]))

      (mkIf agent.enable (mkMerge [
        (mkIf isDarwin (mkService {
          name = "ssh-agent";
          description = "SSH agent (macOS)";
          command = darwinLaunch;
        }))
        (mkIf (!isDarwin) {
          services.ssh-agent = {
            enable = true;
            socket = socketName;
          };
        })
        (envFile "40-tartarus-ssh-agent.conf" {SSH_AUTH_SOCK = socketPath;})
      ]))

      (mkIf merge.enable (mkMerge [
        (mkService {
          name = "ssh-agent-merge";
          description = "SSH agent merge proxy (allow-all, no VSOCK)";
          command = "${package}/bin/ssh-agent-proxy --merge ${lib.concatMapStringsSep " " lib.escapeShellArg mergeSockets} --listen ${lib.escapeShellArg mergeListen}";
        })
        (lib.mkIf merge.setSshAuthSock (envFile "60-tartarus-ssh-agent-merge.conf" {SSH_AUTH_SOCK = mergeEnv;}))
      ]))
    ];
  };
}

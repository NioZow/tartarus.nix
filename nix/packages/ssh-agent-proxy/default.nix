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

    # Reusable `[security]` option set (plan §1.3), shared by the server and
    # the bridge. `mtls.enable` remains the legacy alias for
    # `transportEncryption = "mtls"`; the Python layer resolves `auto` from the
    # transport (tcp → mtls, vsock/unix → none) and never downgrades.
    mkSecurityOptions = {
      transportEncryption = mkOption {
        type = types.enum ["auto" "none" "mtls"];
        default = "auto";
        description = ''
          Whether the byte stream is encrypted and integrity-protected.
          `auto` (default) follows the transport: `tcp` → `mtls`,
          `vsock`/`unix` → `none`. `mtls` is an explicit choice and never a
          runtime fallback.
        '';
      };
      clientAuth = mkOption {
        type = types.enum ["transport" "none"];
        default = "transport";
        description = ''
          How the server authenticates the requester. `transport` means the
          identity comes from the mTLS handshake; `none` disables requester
          authentication entirely (an explicit, warned choice only appropriate
          on a private-by-construction transport).
        '';
      };
      serverAuth = mkOption {
        type = types.enum ["transport" "none"];
        default = "transport";
        description = ''
          How the client authenticates the server's messages. `transport`
          requires `transportEncryption = "mtls"` (and is then forced).
        '';
      };
      connectTimeout = mkOption {
        type = types.float;
        default = 10.0;
        description = "Seconds to wait for the transport connect before failing fast.";
      };
      handshakeTimeout = mkOption {
        type = types.float;
        default = 10.0;
        description = "Seconds to wait for the TLS handshake before failing fast.";
      };
      decisionTimeout = mkOption {
        type = types.int;
        default = 120;
        description = "Seconds to wait for the human decision (0 = wait indefinitely).";
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

        transport = mkOption {
          type = types.nullOr (types.enum ["vsock" "tcp" "unix"]);
          default = null;
          description = ''
            Transport the server listens on. Null derives it from the legacy
            `settings.tcp_bind`/`settings.vsock_port` (tcp if `tcp_bind` is set,
            else vsock). `unix` binds the single host socket `socket`.
          '';
        };

        host = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "TCP address to bind to. Only used with transport tcp.";
        };

        port = mkOption {
          type = types.port;
          default = 65000;
          description = "Port the server listens on (TCP and VSOCK).";
        };

        cid = mkOption {
          type = types.int;
          default = 2;
          description = "VSOCK context ID to bind to (2 = host). Only used with transport vsock.";
        };

        socket = mkOption {
          type = types.str;
          default = "%t/ssh-agent-proxy/server.sock";
          description = ''
            Unix socket the server binds (transport unix). There is exactly one
            server socket per host user; guest identity comes from the mTLS
            certificate or is unset, never the socket path.
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

        security = mkSecurityOptions;

        settings = mkOption {
          type = types.submodule {
            freeformType = tomlFormat.type;
            options = {
              vsock_port = mkOption {
                type = types.nullOr types.int;
                default = null;
                description = "Deprecated: use `server.port` with `server.transport = \"vsock\"`.";
              };
              tcp_bind = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Deprecated: use `server.host`/`server.port` with `server.transport = \"tcp\"`.";
              };
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
                description = "Static peer IP -> VM name mapping for the TCP listener.";
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
          description = "Contents of the ssh-agent-proxy TOML config file.";
        };

        dialogProgram = mkOption {
          type = types.enum ["swiftdialog" "osascript" "zenity"];
          default =
            if pkgs.stdenv.hostPlatform.isDarwin
            then "swiftdialog"
            else "zenity";
          description = "Program used to show the key-use confirmation prompt.";
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
            default = "1.3.6.1.4.1.99999.2.1";
            description = "EKU OID the local server certificate must contain.";
          };
          peerOid = mkOption {
            type = types.str;
            default = "1.3.6.1.4.1.99999.2.2";
            description = "EKU OID the peer (client) certificate must contain.";
          };
        };

        resolution = mkOption {
          type = types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"]);
          default = null;
          description = ''
            How to resolve a connecting VM's name: `none`, `certificate`
            (verified peer cert CN), `tartarus` (local VM bookkeeping), or
            `mofos` (`mofos ls --json`). When unset it resolves to `certificate`
            when the transport is mTLS and `none` otherwise. `tartarus`/`mofos`
            are rejected on the `unix` transport (no CID/IP exists there).
          '';
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

        security = mkSecurityOptions;

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

  # Shared settings assembly for the server (mode = "proxy"). The three
  # `[security]` knobs are resolved from the transport and the legacy
  # `mtls.enable` alias here, exactly as the Python layer re-validates them.
  mkServerSettings = {lib}: cfg: let
    inherit (lib) optionalAttrs;
    effectiveTransport =
      if cfg.transport != null
      then cfg.transport
      else if cfg.settings.tcp_bind != null
      then "tcp"
      else if cfg.settings.vsock_port != null
      then "vsock"
      else "tcp";
    effectiveTransportEncryption =
      if cfg.mtls.enable
      then "mtls"
      else if cfg.security.transportEncryption != "auto"
      then cfg.security.transportEncryption
      else if effectiveTransport == "tcp"
      then "mtls"
      else "none";
    forceTransportAuth = effectiveTransportEncryption == "mtls";
    effectiveResolution =
      if cfg.resolution != null
      then cfg.resolution
      else if forceTransportAuth
      then "certificate"
      else "none";
    security = {
      transport_encryption = effectiveTransportEncryption;
      # Under `none` the only valid auth value is `none` (`transport` requires
      # mTLS); under mTLS both are forced to `transport`.
      client_auth = if forceTransportAuth then "transport" else "none";
      server_auth = if forceTransportAuth then "transport" else "none";
      connect_timeout = cfg.security.connectTimeout;
      handshake_timeout = cfg.security.handshakeTimeout;
      decision_timeout = cfg.security.decisionTimeout;
    };
    connection =
      {
        transport = effectiveTransport;
        port = cfg.port;
      }
      // optionalAttrs (effectiveTransport == "vsock") {cid = cfg.cid;}
      // optionalAttrs (effectiveTransport == "tcp") {host = cfg.host;}
      // optionalAttrs (effectiveTransport == "unix") {
        socket = cfg.socket;
        socket_dir_mode = cfg.socketDirMode;
        socket_mode = cfg.socketMode;
      }
      // optionalAttrs forceTransportAuth {
        mtls = {
          enable = true;
          ca_file = cfg.mtls.caFile;
          cert_file = cfg.mtls.certFile;
          key_file = cfg.mtls.keyFile;
          required_oid = cfg.mtls.requiredOid;
          peer_required_oid = cfg.mtls.peerOid;
        };
      };
    extraSettings =
      lib.removeAttrs cfg.settings (
        if effectiveTransport == "unix"
        then ["vm" "tcp_vm"]
        else []
      );
  in
    {
      mode = "proxy";
      dialog_program = cfg.dialogProgram;
      resolution = effectiveResolution;
      security = security;
    }
    // connection
    // extraSettings;

  # pkgs.formats.toml cannot serialize `null` anywhere in the tree, and
  # submodule list items carry their null defaults once realized, so strip
  # nulls recursively through attrsets and lists.
  lib0 = inputs.nixpkgs.lib;
  cleanNulls = v:
    if builtins.isAttrs v
    then lib0.mapAttrs (_: cleanNulls) (lib0.filterAttrs (_: x: x != null) v)
    else if builtins.isList v
    then map cleanNulls v
    else v;
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
    settings = mkServerSettings {inherit lib;} server;
    configFile = tomlFormat.generate "ssh-agent-proxy.toml" (cleanNulls settings);
  in {
    imports = [optionsModule];

    config = mkIf (cfg.enable || server.enable) (lib.mkMerge [
      (mkService {
        name = "ssh-agent-proxy";
        description = "SSH agent proxy via VSOCK, TCP or unix socket";
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
        assertions = [
          {
            assertion =
              !(server.mtls.enable
                && server.security.transportEncryption != "auto"
                && server.security.transportEncryption != "mtls");
            message = "tartarus.ssh-agent-proxy.server: mtls.enable = true conflicts with security.transportEncryption (refusing to downgrade).";
          }
          {
            assertion =
              server.transport != "unix"
              || server.resolution == null
              || server.resolution == "none"
              || server.resolution == "certificate";
            message = "tartarus.ssh-agent-proxy.server: the unix transport only supports resolution = \"none\" or \"certificate\" (there is no CID/IP).";
          }
        ];
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

    serverConfigFile = tomlFormat.generate "ssh-agent-proxy.toml" (cleanNulls (mkServerSettings {inherit lib;} server));

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
      client_auth = if bridgeForceTransportAuth then "transport" else "none";
      server_auth = if bridgeForceTransportAuth then "transport" else "none";
      connect_timeout = bridge.security.connectTimeout;
      handshake_timeout = bridge.security.handshakeTimeout;
      decision_timeout = bridge.security.decisionTimeout;
    };
    bridgeConnection =
      {
        transport = bridge.transport;
        listen_socket = bridge.listenSocket;
        port = if bridge.transport == "vsock" then bridge.vsockPort else bridge.port;
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
      cleanNulls (lib.recursiveUpdate ({mode = "client";} // bridgeConnection) bridge.extraSettings)
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
          description = "SSH agent proxy via VSOCK or TCP";
          command = "${package}/bin/ssh-agent-proxy --config ${serverConfigPath}${optionalString server.debug " --debug"}";
          environment = optionalAttrs (server.settings.default_agent_socket_path == null) {
            SSH_AUTH_SOCK = "%t/ssh-agent";
          };
        })
        {
          home.packages = [package];
          home.file.${serverConfigPath}.source = serverConfigFile;
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

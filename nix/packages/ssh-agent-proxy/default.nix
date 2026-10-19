# ssh-agent-proxy: a single-process agent broker. Every listener (inbound) and
# every upstream (outbound key source) lives in one config and one service, so
# merging several agents -- a local ssh-agent, a gpg-agent, a *remote* agent
# reached over VSOCK/TCP -- is a normal proxy-server configuration, not a mode.
# There is no client/server split: a "bridge" is just a local unix listener plus
# one remote [[upstream]].
#
# Flattened from nixcfg's `services/user/{ssh-agent-proxy,ssh-agent-host,
# ssh-agent}.nix` and exposed as a standalone package plus a
# NixOS module (server as a system service) and a home-manager module (server
# and agent as user services; `bridge` is a deprecated shorthand for a server
# whose config is just a local unix listener + one remote upstream).
# Units use `nix-service` (§3.7).
#
#   tartarus.ssh-agent-proxy.server   proxy server (listeners + upstreams)
#   tartarus.ssh-agent-proxy.bridge   DEPRECATED guest-side forwarder
#   tartarus.ssh-agent-proxy.agent    guest-local ssh-agent
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

    # Reusable `[security]` option set, shared by the server listeners and the
    # client bridge. `mtls.enable` remains the legacy alias for
    # `transportEncryption = "mtls"`; the Python layer resolves `auto` from the
    # listener type (tcp → mtls, vsock/unix → none) and never downgrades. Every
    # knob carries its real default, so a listener is self-contained.
    mkSecurityOptions = {
      lib,
      # The client/bridge reads the connect/handshake/decision timeouts off its
      # `[security]` table; server listeners carry them at the listener level
      # instead (see `sshListenerOptions`), so they are opt-in here.
      withTimeouts ? false,
    }: let
      inherit (lib) mkOption types;
    in
      {
        transportEncryption = mkOption {
          type = types.enum ["auto" "none" "mtls"];
          default = "auto";
          description = ''
            Whether the byte stream is encrypted and integrity-protected.
            `auto` (default) follows the listener's `type`: `tcp` → `mtls`,
            `vsock`/`unix` → `none`. `mtls` is an explicit choice and never a
            runtime fallback.
          '';
        };
        clientAuth = mkOption {
          type = types.enum ["transport" "none"];
          default = "transport";
          description = ''
            How the server authenticates the requester. `transport` means the
            identity comes from the mTLS handshake and is forced whenever the
            listener is mTLS; `none` disables requester authentication entirely
            (an explicit, warned choice only appropriate on a private-by-
            construction transport).
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
      }
      // lib.optionalAttrs withTimeouts {
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

    # Reusable `[mtls]` option set for one listener. Every field carries its real
    # default so a listener is self-contained.
    mkMtlsOptions = {
      lib,
      requiredOid,
      peerOid,
    }: let
      inherit (lib) mkOption types;
    in {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable mutual TLS for this listener.";
      };
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
        default = requiredOid;
        description = "EKU OID the local server certificate must contain.";
      };
      peerOid = mkOption {
        type = types.str;
        default = peerOid;
        description = "EKU OID the peer (client) certificate must contain.";
      };
    };

    # One listener's option set. Every entry is **self-contained**: each field
    # carries its real default (so there is no `[listener_defaults]` block),
    # `type` is required and `name` is the optional rule selector. All address
    # fields are accepted on every listener; each is only meaningful for its own
    # `type`.
    sshListenerOptions = {
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
          `settings.rule.*.match.listeners` selects listeners by this name; an
          unnamed listener matches only an empty listener selector (or one
          made exclusively of `*` patterns).
        '';
      };
      port = mkOption {
        type = types.port;
        default = 65000;
        description = "Port the listener binds (tcp and vsock).";
      };
      cid = mkOption {
        type = types.int;
        default = 2;
        description = "VSOCK context ID to bind to (2 = host). Only used with type = \"vsock\".";
      };
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "TCP address to bind to. Only used with type = \"tcp\".";
      };
      socket = mkOption {
        type = types.str;
        default = "%t/ssh-agent-proxy/server.sock";
        description = ''
          Unix socket the listener binds (type = "unix"). Identity comes from
          the mTLS certificate or is unset, never the socket path.
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
      resolution = mkOption {
        type = types.nullOr (types.enum ["none" "certificate" "tartarus" "mofos"]);
        default = null;
        description = ''
          How to resolve a connecting VM's name: `none`, `certificate`
          (verified peer cert CN), `tartarus` (local VM bookkeeping), or
          `mofos` (`mofos ls --json`). When unset it resolves to `certificate`
          when the listener is mTLS and `none` otherwise. `tartarus`/`mofos`
          are rejected on the `unix` type (no CID/IP exists there).
        '';
      };
      security = mkSecurityOptions {inherit lib;};
      mtls = mkMtlsOptions {inherit lib requiredOid peerOid;};
      scanAgentSocketDirs = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Unix listeners only. Expand a **directory** entry in the global
          `settings.agent_sockets` list by scanning it (non-recursively) for
          sockets on every client connection, so per-session `ssh -R`
          forwarded sockets are picked up as they appear. Off by default;
          rejected on a `vsock`/`tcp` listener (there is no same-uid local
          peer, and the union would span guests).
        '';
      };
      resolveSessionSocket = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Unix listeners only, Linux only. Prefer the connecting peer's own
          per-session socket (`$SSH_AUTH_PROXY_SOCK`, read from
          `/proc/<pid>/environ` after a same-uid `SO_PEERCRED` check) for
          this connection. When resolved it takes precedence over
          `scanAgentSocketDirs`. A no-op (logged) where it cannot apply.
          Off by default.
        '';
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
          description = "VM name, matched against rule.match.machine.";
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
          description = "VM name, matched against rule.match.machine.";
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
            options = {
              machine = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "Machine name patterns (fnmatch) this rule applies to.";
              };
              listeners = mkOption {
                type = types.listOf types.str;
                default = [];
                description = ''
                  Listener name patterns (fnmatch) this rule applies to. Empty
                  matches every listener; an unnamed listener matches only an
                  empty selector or one made exclusively of `*` patterns.
                '';
              };
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
        add = mkOption {
          type = types.enum ["deny" "ask" "allow"];
          default = "deny";
          description = ''
            Policy for adding keys to an upstream agent
            (`SSH_AGENTC_ADD_IDENTITY`/`_CONSTRAINED`, i.e. `ssh-add`). The key
            is forwarded to the first connected `agent_sockets` entry, which
            holds the private key in memory; the proxy stores nothing. Matched
            against the added key's id (a configured key id, else its comment).
            Defaults to deny.
          '';
        };
        remove = mkOption {
          type = types.enum ["deny" "ask" "allow"];
          default = "deny";
          description = ''
            Policy for removing keys from an upstream agent
            (`SSH_AGENTC_REMOVE_IDENTITY`/`REMOVE_ALL_IDENTITIES`, i.e.
            `ssh-add -d`/`-D`). Forwarded to the first connected `agent_sockets`
            entry. Defaults to deny.
          '';
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
              agent_sockets = mkOption {
                type = types.nullOr (types.listOf types.str);
                default = null;
                description = ''
                  Upstream agent sockets whose identities are forwarded to every
                  VM. The first entry is the default socket for `key` entries
                  without an explicit `socket`. Null uses `$SSH_AUTH_SOCK` at
                  runtime.

                  A directory entry is only expanded per connection when the
                  owning `unix` listener sets `scanAgentSocketDirs` (and, unless
                  `resolveSessionSocket` supplies the session's exact socket);
                  otherwise a directory entry simply contributes nothing.
                '';
              };
              known_hosts_files = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "known_hosts files for host-key lookup.";
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
          description = ''
            Global (non-transport) contents of the ssh-agent-proxy TOML config
            file. Besides the typed options here this freeform table carries any
            passthrough key, notably `upstream` -- a list of outbound key
            sources (`{ transport = "unix"; socket = ...; }` or
            `{ transport = "vsock"; cid = ...; port = ...; }`), so one server
            can merge local agents *and* a remote agent reached over VSOCK/TCP.
            `agent_sockets` (a list of unix socket strings) remains the legacy
            shorthand for unix upstreams.
          '';
        };

        # The listeners, all bound by the single server process. Every entry is
        # self-contained (its fields carry real defaults), so there is no
        # `[listener_defaults]` block.
        listeners = mkOption {
          type = types.listOf (types.submodule {
            options = sshListenerOptions {
              inherit lib;
              requiredOid = serverRequiredOid;
              peerOid = serverPeerOid;
            };
          });
          default = [];
          description = ''
            One entry per listener this server binds (a listener is a socket;
            its `type` is its transport), all in the single server process.
            Multiple entries of the same `type` are allowed (e.g. two `unix`
            listeners with different sockets). Empty means the server binds
            nothing and the module rejects the configuration when `enable = true`.
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

        setSshAuthSock = mkOption {
          type = types.bool;
          default = false;
          description = "Point SSH_AUTH_SOCK at this server's local (unix) listener socket (overrides agent/bridge).";
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
    };
  };

  # pkgs.formats.toml cannot serialize `null` anywhere in the tree, and both
  # sparse `listeners` entries and submodule defaults carry nulls once
  # realized, so strip them recursively through attrsets and lists.
  lib0 = inputs.nixpkgs.lib;
  pruneNulls = v:
    if builtins.isAttrs v
    then lib0.mapAttrs (_: pruneNulls) (lib0.filterAttrs (_: x: x != null) v)
    else if builtins.isList v
    then map pruneNulls v
    else v;

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
  # global `settings` and one self-contained `[[listeners]]` table per listener.
  # `connect_timeout`/`handshake_timeout`/`decision_timeout` live at the
  # listener level, where `Config.load` reads them (the previous [`security`]
  # placement was dead config).
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

    # One self-contained `[[listeners]]` entry: its own bind target and
    # timeouts, the resolved `[security]` and, when it resolves to mTLS, its own
    # `[mtls]` block.
    renderListener = entry: let
      transportEncryption = resolveTransportEncryption {
        type = entry.type;
        mtlsEnabled = entry.mtls.enable;
        requested = entry.security.transportEncryption;
      };
      fields = {
        type = entry.type;
        name = entry.name;
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
        scan_agent_socket_dirs = entry.scanAgentSocketDirs;
        resolve_session_socket = entry.resolveSessionSocket;
      };
    in
      pruneNulls (
        fields
        // {security = renderSecurity transportEncryption;}
        // optionalAttrs (transportEncryption == "mtls") {mtls = renderMtls entry.mtls;}
      );
  in
    {
      mode = "proxy";
      dialog_program = server.dialogProgram;
    }
    // optionalAttrs server.debug {debug = true;}
    // pruneNulls server.settings
    // {listeners = map renderListener server.listeners;};

  # Eval-time guards, evaluated per listener from the entry itself (each sees
  # the same values the Python resolves).
  serverAssertions = {lib}: server: let
    inherit (lib) optional;
    namedListeners = lib.filter (n: n != null) (map (e: e.name) server.listeners);
    duplicateNames = lib.unique (
      lib.filter (n: lib.count (m: m == n) namedListeners > 1) namedListeners
    );
    perEntry = entry: let
      requested = entry.security.transportEncryption;
      transportEncryption = resolveTransportEncryption {
        type = entry.type;
        mtlsEnabled = entry.mtls.enable;
        requested = requested;
      };
      resolution =
        if entry.resolution != null
        then entry.resolution
        else if transportEncryption == "mtls"
        then "certificate"
        else "none";
    in [
      {
        assertion =
          !(entry.mtls.enable
            && requested != "auto"
            && requested != "mtls");
        message = "tartarus.ssh-agent-proxy.server.listeners: mtls.enable = true conflicts with security.transportEncryption = \"${requested}\" (entry type = \"${entry.type}\"); refusing to downgrade.";
      }
      {
        assertion =
          !(entry.type == "unix" && (resolution == "tartarus" || resolution == "mofos"));
        message = "tartarus.ssh-agent-proxy.server.listeners: the unix listener only supports resolution = \"none\" or \"certificate\" (entry type = \"unix\").";
      }
      {
        assertion =
          !(entry.type != "unix"
            && (entry.scanAgentSocketDirs || entry.resolveSessionSocket));
        message = "tartarus.ssh-agent-proxy.server.listeners: scanAgentSocketDirs/resolveSessionSocket are only valid on a unix listener (entry type = \"${entry.type}\").";
      }
    ];
  in
    lib.concatMap perEntry server.listeners
    ++ optional (server.enable && server.listeners == []) {
      assertion = false;
      message = "tartarus.ssh-agent-proxy.server.enable = true requires at least one entry in server.listeners.";
    }
    ++ optional (server.setSshAuthSock && !(lib.any (e: e.type == "unix") server.listeners)) {
      assertion = false;
      message = "tartarus.ssh-agent-proxy.server.setSshAuthSock = true requires a listener with type = \"unix\".";
    }
    ++ optional (duplicateNames != []) {
      assertion = false;
      message = "tartarus.ssh-agent-proxy.server.listeners: duplicate listener name(s): ${lib.concatStringsSep ", " duplicateNames}.";
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
        environment = lib.optionalAttrs (server.settings.agent_sockets == null) {
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

    # The socket `setSshAuthSock` points at: the first unix listener's socket
    # (each entry is self-contained, so its `socket` always carries a value).
    # `setSshAuthSock` without a unix listener is rejected by `serverAssertions`.
    serverUnixSocket = let
      unixEntry = lib.findFirst (e: e.type == "unix") null server.listeners;
    in
      if unixEntry != null
      then unixEntry.socket
      else "%t/ssh-agent-proxy/server.sock";

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

    envFile = mkEnvFile {inherit lib;};
  in {
    imports = [optionsModule];

    config = mkMerge [
      (mkIf (cfg.enable || server.enable) (mkMerge [
        (mkService {
          name = "ssh-agent-proxy";
          description = "SSH agent proxy via its configured listeners";
          command = "${package}/bin/ssh-agent-proxy --config ${serverConfigPath}${optionalString server.debug " --debug"}";
          # `auth = "ask"` rules raise a zenity/swiftDialog prompt, so the unit
          # must start inside the approver's graphical session to inherit the
          # compositor's DISPLAY/WAYLAND_DISPLAY (imported into the systemd user
          # manager after default.target). Darwin ignores these Linux-only keys.
          after = ["graphical-session.target"];
          partOf = ["graphical-session.target"];
          wantedBy = ["graphical-session.target"];
          environment = optionalAttrs (server.settings.agent_sockets == null) {
            SSH_AUTH_SOCK = "%t/ssh-agent";
          };
        })
        {
          home.packages = [package];
          home.file.${serverConfigPath}.source = serverConfigFile;
        }
        (lib.mkIf server.setSshAuthSock (envFile "60-tartarus-ssh-agent-server.conf" {
          SSH_AUTH_SOCK = replaceStrings ["%t"] ["$XDG_RUNTIME_DIR"] serverUnixSocket;
        }))
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
    ];
  };
}

# clipboard-bridge: a secure clipboard bridge. Exposed as a standalone package
# plus a NixOS module (server as a system service) and a home-manager module
# (server, guest-side client and ad-hoc admin client). Units use `nix-service`.
#
# Flattened from nixcfg's `programs/user/clipboard-bridge.nix`,
# `services/user/clipboard-bridge-client.nix` and
# `services/user/clipboard-bridge-server.nix`.
#
#   tartarus.clipboard-bridge.server       server (host side)
#   tartarus.clipboard-bridge.client       guest-side client + CLI config
#   tartarus.clipboard-bridge.adminClient  ad-hoc admin CLI config (host side)
{inputs}: let
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
        exec ${pythonEnv.interpreter} -P ${./sources/clipboard-bridge.py} "$@"
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

  mtlsModule = {
    certType,
    oidType,
  }: {lib, ...}: let
    inherit
      (lib)
      mkEnableOption
      mkOption
      types
      ;
    isClient = certType == "client";
  in {
    options = {
      enable = mkEnableOption "mutual TLS" // {default = false;};
      caFile = mkOption {
        type = types.str;
        default = "./ca.crt";
        description = "Path to CA certificate.";
      };
      certFile = mkOption {
        type = types.str;
        default = "";
        description =
          if isClient
          then "Path to this client's certificate."
          else "Path to the server certificate.";
      };
      keyFile = mkOption {
        type = types.str;
        default = "";
        description =
          if isClient
          then "Path to this client's private key."
          else "Path to the server private key.";
      };
      requiredOid = mkOption {
        type = types.str;
        default =
          if oidType == "client"
          then "1.3.6.1.4.1.99999.3.2"
          else "1.3.6.1.4.1.99999.3.1";
        description = "EKU OID required in the local certificate.";
      };
      peerOid = mkOption {
        type = types.str;
        default =
          if oidType == "client"
          then "1.3.6.1.4.1.99999.3.1"
          else "1.3.6.1.4.1.99999.3.2";
        description = "EKU OID required in peer certificates.";
      };
    };
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
    mtlsClient = mtlsModule {
      certType = "client";
      oidType = "client";
    };
    mtlsServer = mtlsModule {
      certType = "server";
      oidType = "server";
    };
  in {
    options.tartarus.clipboard-bridge = {
      enable = mkEnableOption "the clipboard-bridge service (server role)";
      server = {
        enable = mkEnableOption "the clipboard-bridge server (host side)";
        secretFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to a file containing the clipboard bridge secret.";
        };
        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the generated server config. Defaults to `~/.config/clipboard-bridge/server.toml`.";
        };
        transport = mkOption {
          type = types.enum ["tcp" "vsock"];
          default = "tcp";
          description = "Transport to serve on.";
        };
        host = mkOption {
          type = types.str;
          default = "0.0.0.0";
          description = "Bind address for TCP.";
        };
        port = mkOption {
          type = types.port;
          default = 27795;
          description = "Port to listen on.";
        };
        mtls = mkOption {
          type = types.submodule mtlsServer;
          default = {};
          description = "mTLS configuration.";
        };
        resolution = mkOption {
          type = types.enum ["none" "certificate" "tartarus"];
          default =
            if config.tartarus.clipboard-bridge.server.mtls.enable
            then "certificate"
            else "tartarus";
          description = ''
            How to resolve a connecting client's friendly name: `none`,
            `certificate` (verified peer cert CN), or `tartarus` (local VM
            bookkeeping).
          '';
        };
        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
      };

      client = {
        enable = mkEnableOption "the clipboard-bridge client (guest side)";
        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the generated client config. Defaults to `~/.config/clipboard-bridge/client.toml`.";
        };
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
          description = "TCP host to connect to.";
        };
        port = mkOption {
          type = types.port;
          default = 27795;
          description = "Port to connect to.";
        };
        vsockCid = mkOption {
          type = types.int;
          default = 2;
          description = "VSOCK CID to connect to.";
        };
        socket = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Unix socket path (overrides transport).";
        };
        mtls = mkOption {
          type = types.submodule mtlsClient;
          default = {};
          description = "mTLS configuration.";
        };
        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
        proxy = {
          enable = mkEnableOption ''
            a persistent local connection-reuse proxy: a background service
            holds one already-authenticated connection to the server and ad-hoc
            CLI invocations connect to it over a local unix socket
          '';
          socketPath = mkOption {
            type = types.str;
            default = "%t/clipboard-bridge-proxy";
            description = "Local unix socket the proxy listens on.";
          };
        };
      };

      adminClient = {
        enable = mkEnableOption "an ad-hoc admin client config at the CLI's default client path";
        configPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to the generated admin config. Defaults to `~/.config/clipboard-bridge/client.toml`.";
        };
        host = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "TCP host of the local server to administer.";
        };
        port = mkOption {
          type = types.port;
          default = 27795;
          description = "Port of the local server to administer.";
        };
        secretFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to a file containing the admin secret.";
        };
        mtls = mkOption {
          type = types.submodule mtlsClient;
          default = {};
          description = "mTLS configuration.";
        };
        proxy = {
          enable = mkEnableOption ''
            a persistent local connection-reuse proxy for the admin client
          '';
          socketPath = mkOption {
            type = types.str;
            default = "%t/clipboard-bridge-proxy";
            description = "Local unix socket the proxy listens on.";
          };
        };
        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr.";
        };
      };
    };
  };

  # Recursively drop nulls so pkgs.formats.toml can serialize the tree.
  cleanNulls = v:
    if builtins.isAttrs v
    then lib0.mapAttrs (_: cleanNulls) (lib0.filterAttrs (_: x: x != null) v)
    else if builtins.isList v
    then map cleanNulls v
    else v;

  # `lib` is not in scope in the outer let, so give `cleanNulls` a tiny local
  # alias to nixpkgs lib via a thunk (only used for mapAttrs/filterAttrs).
  lib0 = inputs.nixpkgs.lib;
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
    inherit
      (lib)
      filterAttrs
      mkIf
      mkMerge
      optionalAttrs
      ;
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
    settings = filterAttrs (_: v: v != null) {
      transport = server.transport;
      host = server.host;
      port = server.port;
      secret_file = server.secretFile;
      resolution = server.resolution;
      debug =
        if server.debug
        then true
        else null;
      mtls = optionalAttrs server.mtls.enable {
        enable = true;
        ca_file = server.mtls.caFile;
        cert_file = server.mtls.certFile;
        key_file = server.mtls.keyFile;
        required_oid = server.mtls.requiredOid;
        peer_required_oid = server.mtls.peerOid;
      };
    };
    configFile = tomlFormat.generate "clipboard-bridge-server.toml" (cleanNulls settings);
  in {
    imports = [optionsModule];

    config = mkIf (cfg.enable || server.enable) (lib.mkMerge [
      (mkService {
        name = "clipboard-bridge-server";
        description = "Clipboard bridge server";
        command = "${package}/bin/clipboard-bridge --config ${configPath} serve --no-notify";
        scope = "system";
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
      filterAttrs
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
      else "${home}/.config/clipboard-bridge/client.toml";

    mkMtls = m: {
      enable = true;
      ca_file = m.caFile;
      cert_file = m.certFile;
      key_file = m.keyFile;
      required_oid = m.requiredOid;
      peer_required_oid = m.peerOid;
    };

    serverConfigFile = tomlFormat.generate "clipboard-bridge-server.toml" (cleanNulls (filterAttrs (_: v: v != null) {
      transport = server.transport;
      host = server.host;
      port = server.port;
      secret_file = server.secretFile;
      resolution = server.resolution;
      debug =
        if server.debug
        then true
        else null;
      mtls = optionalAttrs server.mtls.enable (mkMtls server.mtls);
    }));

    clientConfigFile = tomlFormat.generate "clipboard-bridge.toml" (cleanNulls (filterAttrs (_: v: v != null) ({
        transport = client.transport;
        port = client.port;
        socket = client.socket;
        proxy_socket =
          if client.proxy.enable
          then client.proxy.socketPath
          else null;
        debug =
          if client.debug
          then true
          else null;
      }
      // optionalAttrs (client.transport == "tcp") {host = client.host;}
      // optionalAttrs (client.transport == "vsock") {cid = client.vsockCid;}
      // optionalAttrs client.mtls.enable {mtls = mkMtls client.mtls;})));

    adminConfigFile = tomlFormat.generate "clipboard-bridge-admin.toml" (cleanNulls (filterAttrs (_: v: v != null) {
      transport = "tcp";
      host = admin.host;
      port = admin.port;
      secret_file = admin.secretFile;
      proxy_socket =
        if admin.proxy.enable
        then admin.proxy.socketPath
        else null;
      debug =
        if admin.debug
        then true
        else null;
      mtls = optionalAttrs admin.mtls.enable (mkMtls admin.mtls);
    }));
  in {
    imports = [optionsModule];

    config = mkMerge [
      (mkIf (cfg.enable || server.enable || client.enable || admin.enable) {
        home.packages = [package];
      })

      (mkIf (cfg.enable || server.enable) (mkMerge [
        (mkService {
          name = "clipboard-bridge-server";
          description = "Clipboard bridge server";
          command = "${package}/bin/clipboard-bridge --config ${serverConfigPath} serve --no-notify";
        })
        {home.file.${serverConfigPath}.source = serverConfigFile;}
      ]))

      (mkIf client.enable (mkMerge [
        {
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
        })
        (mkIf client.proxy.enable (mkService {
          name = "clipboard-bridge";
          description = "Clipboard bridge connection-reuse proxy";
          command = "${package}/bin/clipboard-bridge --config ${clientConfigPath} proxy";
        }))
      ]))

      (mkIf admin.enable (mkMerge [
        {home.file.${adminConfigPath}.source = adminConfigFile;}
        (mkIf admin.proxy.enable (mkService {
          name = "clipboard-bridge";
          description = "Clipboard bridge connection-reuse proxy";
          command = "${package}/bin/clipboard-bridge --config ${adminConfigPath} proxy";
        }))
      ]))
    ];
  };
}

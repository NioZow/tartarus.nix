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
        type = types.enum ["vsock" "tcp"];
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

      configPath = mkOption {
        type = types.str;
        default = "/etc/sudo-auth-proxy/config.toml";
        description = "Path to the client configuration file passed to the binary.";
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

      proxy = {
        enable = mkEnableOption ''
          a persistent local connection-reuse daemon: a system service holds an
          already-authenticated connection to the server and each PAM attempt
          connects to it over a local unix socket instead of paying for a fresh
          connect + TLS handshake
        '';
        socketPath = mkOption {
          type = types.str;
          default = "/run/sudo-auth-proxy/proxy.sock";
          description = "Unix socket the proxy daemon listens on.";
        };
      };

      server = {
        enable = mkEnableOption "the sudo-auth-proxy server (host side)";

        transport = mkOption {
          type = types.enum ["vsock" "tcp"];
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

        debug = mkOption {
          type = types.bool;
          default = false;
          description = "Log connection/handshake/request timing to stderr for latency debugging.";
        };
      };
    };
  };

  # The guest-side PAM client: installs the client config and wires
  # `pam_exec.so` into the `sudo`/`login`/`su` stacks, plus the optional
  # local connection-reuse proxy daemon. It is self-contained (only its own
  # `tartarus.sudo-auth-proxy.*` options, `pkgs`, `lib` and the nix-service
  # library) and needs neither the tartarus host module nor a guest VM.
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
      mkMerge
      optionalAttrs
      recursiveUpdate
      ;
    mkService = mkServiceFor {
      inherit lib username;
      isDarwin = false;
      homeManager = false;
    };
    cfg = config.tartarus.sudo-auth-proxy;
    package = mkPackage {inherit pkgs;};
    tomlFormat = pkgs.formats.toml {};

    connectionSettings =
      {
        transport = cfg.transport;
        port = cfg.port;
      }
      // optionalAttrs (cfg.transport == "vsock") {cid = cfg.cid;}
      // optionalAttrs (cfg.transport == "tcp") {host = cfg.host;}
      // optionalAttrs cfg.mtls.enable {
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
          debug =
            if cfg.debug
            then true
            else null;
          proxy_socket =
            if cfg.proxy.enable
            then cfg.proxy.socketPath
            else null;
        }
        // connectionSettings)
      cfg.settings;
    cleanSettings = filterAttrs (_: v: v != null) settings;
    configFile = tomlFormat.generate "sudo-auth-proxy-client.toml" cleanSettings;

    proxySettings = filterAttrs (_: v: v != null) ({
        mode = "proxy";
        debug =
          if cfg.debug
          then true
          else null;
        proxy_socket = cfg.proxy.socketPath;
      }
      // connectionSettings);
    proxyConfigFile = tomlFormat.generate "sudo-auth-proxy-proxy.toml" proxySettings;

    clientScript = pkgs.writeShellScript "sudo-auth-proxy-pam-client" ''
      exec ${package}/bin/sudo-auth-proxy --config ${cfg.configPath}
    '';
  in {
    imports = [optionsModule];

    config = mkIf cfg.enable (mkMerge [
      {
        # World-readable, root-writable: pam_exec.so runs this PAM helper as
        # the invoking user, which must be able to read the config and the
        # mTLS cert/key paths it references.
        systemd.tmpfiles.rules = [
          "d /etc/sudo-auth-proxy 0755 root root -"
        ];

        environment.etc."sudo-auth-proxy/config.toml".source = configFile;

        security.pam.services = genAttrs ["sudo" "login" "su"] (_: {
          rules.auth.sudo-auth-proxy = {
            order = -1000;
            control = "[success=done default=ignore]";
            modulePath = "pam_exec.so";
            args = ["${clientScript}"];
          };
        });
      }

      (mkIf cfg.proxy.enable (mkMerge [
        {environment.etc."sudo-auth-proxy/proxy.toml".source = proxyConfigFile;}

        (mkService {
          name = "sudo-auth-proxy";
          description = "sudo-auth-proxy connection-reuse proxy";
          command = "${package}/bin/sudo-auth-proxy --config /etc/sudo-auth-proxy/proxy.toml";
          scope = "system";
          after = ["network-online.target"];
          wants = ["network-online.target"];
          restart = "always";
          restartSec = 2;
          extraSystemdServiceConfig = {
            DynamicUser = true;
            RuntimeDirectory = "sudo-auth-proxy";
            RuntimeDirectoryMode = "0755";
          };
        })
      ]))
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

    settings =
      recursiveUpdate
      ({
          mode = "server";
          transport = server.transport;
          port = server.port;
          dialog_program = server.dialogProgram;
          resolution = server.resolution;
          debug =
            if server.debug
            then true
            else null;
        }
        // optionalAttrs (server.transport == "vsock") {cid = server.cid;}
        // optionalAttrs (server.transport == "tcp") {host = server.host;}
        // optionalAttrs server.mtls.enable {
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

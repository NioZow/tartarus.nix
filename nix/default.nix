{
  inputs,
  self,
}: let
  lib = inputs.nixpkgs.lib;
  systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
  forAllSystems = lib.genAttrs systems;

  sudoAuthProxy = import ./packages/sudo-auth-proxy {inherit inputs;};
  sshAgentProxyPkg = import ./packages/ssh-agent-proxy {inherit inputs;};
  clipboardBridge = import ./packages/clipboard-bridge {inherit inputs;};

  # Eval-level test suite (shared across systems; evaluation is platform
  # independent and the checks only wrap its results).
  suite = import ../tests/suite.nix {inherit inputs self;};
in {
  # The build contract. Tartarus's own flake inputs/self are injected so a
  # caller only needs to supply its side of the world; caller-provided
  # `inputs`/`self` override.
  lib.mkGuests = args:
    import ./lib/mkGuests.nix ({
        tartarusInputs = inputs;
        tartarusSelf = self;
      }
      // args);

  nixosModules = {
    tartarus = import ./host/default.nix {inherit inputs self;};
    "sudo-auth-proxy" = sudoAuthProxy.nixosModule;
    # Explicitly-named alias for the guest-side PAM client module, so a
    # standalone consumer can request just the PAM wiring by name. Same
    # module as `"sudo-auth-proxy"` (see nix/packages/sudo-auth-proxy/default.nix).
    "sudo-auth-proxy-pam" = sudoAuthProxy.pamNixosModule;
    "ssh-agent-proxy" = sshAgentProxyPkg.nixosModule;
    "clipboard-bridge" = clipboardBridge.nixosModule;
  };

  homeManagerModules = {
    "sudo-auth-proxy" = sudoAuthProxy.homeManagerModule;
    "ssh-agent-proxy" = sshAgentProxyPkg.homeManagerModule;
    "clipboard-bridge" = clipboardBridge.homeManagerModule;
  };

  packages = forAllSystems (system: import ./packages {inherit inputs self system;});

  # Runnable apps. `nix run .#tartarus-certs` (and `.#tartarus`) work via
  # `packages` already; this mirrors them explicitly for callers that prefer
  # the `apps` output.
  apps = forAllSystems (system: let
    pkgs = import inputs.nixpkgs {inherit system;};
  in {
    "tartarus-certs" = {
      type = "app";
      program = "${(import ./packages {inherit inputs self system;})."tartarus-certs"}/bin/tartarus-certs";
    };
  });

  devShells = forAllSystems (system: let
    pkgs = import inputs.nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };
  in {
    default = pkgs.mkShell {
      packages = [pkgs.uv pkgs.python3];

      shellHook = ''
        if [ ! -f .venv/bin/activate ]; then
          uv venv
          uv pip install -e .
          uv pip install -e ".[dev]"
        fi

        source .venv/bin/activate
      '';
    };
  });

  # `nix flake check` surface for the eval-level suite. Each check is a trivial
  # derivation whose *evaluation* forces the corresponding test: a failure
  # throws before anything is built, so `--no-build` still catches it.
  #
  # The `tartarus-sudo-auth-proxy-toml-shape` check is the one build-forcing
  # member (doc §7.3): it renders a standalone home-manager server config with
  # two listeners and greps the generated `sudo-auth-proxy-server.toml` for the
  # multi-listener schema, pinning exactly what the module emits.
  checks = forAllSystems (system: let
    pkgs = import inputs.nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };
    safe = name: lib.replaceStrings ["/"] ["-"] name;
    mkCheck = name: t:
      if t.ok
      then pkgs.runCommand "tartarus-check-${safe name}" {} "echo ok > $out"
      else throw "tartarus test '${name}' failed: ${t.message}";

    # A standalone home-manager config whose sudo-auth-proxy server binds two
    # listeners (a `unix` one that disables auth explicitly, a `tcp` one that
    # resolves to mTLS via `auto`). The generated TOML must therefore carry a
    # `[listener_defaults]` block and two `[[listeners]]` headers.
    sudoTomlHm = inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules."sudo-auth-proxy"
        {
          _module.args.system = system;
          home.username = "user";
          home.homeDirectory = "/home/user";
          home.stateVersion = "26.05";
          tartarus.sudo-auth-proxy.server = {
            enable = true;
            listeners = [
              {
                type = "unix";
                socket = "/tmp/sudo-auth-proxy.sock";
                resolution = "none";
                security = {
                  transportEncryption = "none";
                  clientAuth = "none";
                  serverAuth = "none";
                };
              }
              {
                type = "tcp";
                host = "127.0.0.1";
                port = 65001;
              }
            ];
          };
        }
      ];
    };
    sudoToml =
      sudoTomlHm.config.home.file
      ."/home/user/.config/sudo-auth-proxy/config.toml"
      .source;
    tomlShape = pkgs.runCommand "tartarus-sudo-auth-proxy-toml-shape" {} ''
      set -eu
      grep -qF '[listener_defaults]' ${sudoToml}
      test "$(grep -c '^\[\[listeners\]\]' ${sudoToml})" -ge 2
      echo ok > $out
    '';
  in
    (lib.mapAttrs' (name: t: lib.nameValuePair (safe name) (mkCheck name t)) suite.tests)
    // {
      "tartarus-sudo-auth-proxy-toml-shape" = tomlShape;
    });
}

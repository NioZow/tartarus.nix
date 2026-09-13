{
  inputs,
  self,
}: let
  lib = inputs.nixpkgs.lib;
  systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
  forAllSystems = lib.genAttrs systems;

  sudoAuthProxy = import ./packages/sudo-auth-proxy.nix {inherit inputs;};
  sshAgentProxy = import ./packages/ssh-agent-proxy.nix {inherit inputs;};
  clipboardBridge = import ./packages/clipboard-bridge.nix {inherit inputs;};

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
    # module as `"sudo-auth-proxy"` (see nix/packages/sudo-auth-proxy.nix).
    "sudo-auth-proxy-pam" = sudoAuthProxy.pamNixosModule;
    "ssh-agent-proxy" = sshAgentProxy.nixosModule;
    "clipboard-bridge" = clipboardBridge.nixosModule;
  };

  homeManagerModules = {
    "sudo-auth-proxy" = sudoAuthProxy.homeManagerModule;
    "ssh-agent-proxy" = sshAgentProxy.homeManagerModule;
    "clipboard-bridge" = clipboardBridge.homeManagerModule;
  };

  packages = forAllSystems (system: import ./packages {inherit inputs self system;});

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
  in
    lib.mapAttrs' (name: t: lib.nameValuePair (safe name) (mkCheck name t)) suite.tests);
}

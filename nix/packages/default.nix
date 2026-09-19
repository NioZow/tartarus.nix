{
  inputs,
  self,
  system,
}: let
  pkgs = import inputs.nixpkgs {
    config.allowUnfree = true;
    inherit system;
  };
  sudoAuthProxy = import ./sudo-auth-proxy.nix {inherit inputs;};
  sshAgentProxyPkg = import ./ssh-agent-proxy.nix {inherit inputs;};
  clipboardBridge = import ./clipboard-bridge.nix {inherit inputs;};
in {
  tartarus = import ./tartarus.nix {inherit pkgs;};
  "sudo-auth-proxy" = sudoAuthProxy.package {inherit pkgs;};
  "ssh-agent-proxy" = sshAgentProxyPkg.package {inherit pkgs;};
  "clipboard-bridge" = clipboardBridge.package {inherit pkgs;};
}

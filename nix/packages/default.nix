{
  inputs,
  self,
  system,
}: let
  pkgs = import inputs.nixpkgs {
    config.allowUnfree = true;
    inherit system;
  };
  sudoAuthProxy = import ./sudo-auth-proxy {inherit inputs;};
  sshAgentProxyPkg = import ./ssh-agent-proxy {inherit inputs;};
  clipboardBridge = import ./clipboard-bridge {inherit inputs;};
in {
  tartarus = import ./tartarus {inherit pkgs;};
  "sudo-auth-proxy" = sudoAuthProxy.package {inherit pkgs;};
  "ssh-agent-proxy" = sshAgentProxyPkg.package {inherit pkgs;};
  "clipboard-bridge" = clipboardBridge.package {inherit pkgs;};
}

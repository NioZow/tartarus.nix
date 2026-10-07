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

  # Standalone X.509 certificate tooling (CA + per-service server/client
  # leaves), a shell counterpart of `src/tartarus/ca.py`. The script is
  # embedded verbatim; writeShellApplication provides `openssl`/`ssh-keygen`
  # and a clean PATH.
  tartarus-certs = pkgs.writeShellApplication {
    name = "tartarus-certs";
    runtimeInputs = [pkgs.openssl pkgs.openssh pkgs.coreutils pkgs.gnused pkgs.gnugrep pkgs.findutils];
    text = builtins.readFile ../../scripts/tartarus-certs.sh;
    # The embedded script is the artefact; skip shellcheck's style nits so a
    # future lint bump cannot break the build.
    checkPhase = ":";
  };
in {
  tartarus = import ./tartarus {inherit pkgs;};
  "sudo-auth-proxy" = sudoAuthProxy.package {inherit pkgs;};
  "ssh-agent-proxy" = sshAgentProxyPkg.package {inherit pkgs;};
  "clipboard-bridge" = clipboardBridge.package {inherit pkgs;};
  inherit tartarus-certs;
}

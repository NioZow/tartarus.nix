# Host CA: the on-disk layout of the shared per-host SSH + X509 CA under
# `~/.local/share/tartarus`, plus the `known_hosts_trs` service that teaches the
# host SSH client to trust the SSH CA for every guest (`*.trs` and the enabled
# guest subnets).
#
# The keypairs themselves are NOT generated here: they are created on demand by
# the `tartarus` CLI (see PLAN.md section 4, Phase 4). This module only exposes
# their paths as options -- consumed by `./services.nix`, `./ssh.nix` and the
# user's own configuration -- and keeps `known_hosts_trs` current.
#
# `config.toml` generation lives in `./config.nix`; it reads the CA paths
# defined below alongside `tartarus.guests` / `tartarus.proxy`.
{inputs}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    mkIf
    mkOption
    types
    ;

  # Read from the raw module args: this nixpkgs resolves defaulted module
  # arguments through `_module.args`, so a default here would be ignored when
  # the argument is absent and then shadow `config`.
  username = args.username or "user";
  homeDir =
    args.homeDir
    or (
      if lib.hasSuffix "-darwin" (args.system or builtins.currentSystem)
      then "/Users/${username}"
      else "/home/${username}"
    );

  cfg = config.tartarus.ca;
  instances = config.tartarus.instances;
  hasGuests = instances.vm.enabledNames != [] || instances.container.enabledNames != [];

  # Path defaults are computed from the home directory directly (not from
  # `config.tartarus.ca`) so an option default never has to force the module's
  # own config: doing so trips nixpkgs' `_module.args` recursion when a module
  # also reads submodule options.
  base = "${homeDir}/.local/share/tartarus";
  sshCaDir = "${base}/ssh/ca";
  sshKeyPath = "${sshCaDir}/tartarus";
  sshPubPath = "${sshKeyPath}.pub";
  sshMachinesDir = "${base}/ssh/machines";
  x509CaDir = "${base}/x509/ca";
  x509KeyPath = "${x509CaDir}/tartarus.key";
  x509CrtPath = "${x509CaDir}/tartarus.crt";
  x509HostDir = "${base}/x509/host";
  x509HostCertPath = "${x509HostDir}/server.crt";
  x509HostKeyPath = "${x509HostDir}/server.key";
  x509MachinesDir = "${base}/x509/machines";

  mkService = inputs.nix-service.lib.mkService {
    inherit lib username;
    isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
    homeManager = false;
  };

  # Writes (or refreshes) the `@cert-authority` line trusting the tartarus SSH
  # CA for both guest kinds under the shared `trs` SSH TLD.
  knownHostsScript = {
    caPubPath,
    subnets,
    knownHostsFile,
  }: let
    pattern = lib.concatStringsSep "," (subnets ++ ["*.trs"]);
  in ''
    set -euo pipefail
    if [ -s ${caPubPath} ]; then
      mkdir -p ${homeDir}/.ssh
      printf '@cert-authority %s ' '${pattern}' > '${knownHostsFile}'
      cat ${caPubPath} >> '${knownHostsFile}'
      chown ${username}:users '${homeDir}' '${homeDir}/.ssh' 2>/dev/null || true
      chmod 0700 '${homeDir}/.ssh'
      chown ${username}:users '${knownHostsFile}' 2>/dev/null || true
      chmod 0644 '${knownHostsFile}'
    fi
  '';

  script = pkgs.writeShellScript "tartarus-ca-known-hosts" (knownHostsScript {
    caPubPath = cfg.ssh.pubPath;
    subnets = instances.enabledSubnets;
    knownHostsFile = "${homeDir}/.ssh/known_hosts_trs";
  });
in {
  options.tartarus.ca = {
    enable = lib.mkEnableOption "the shared per-host tartarus SSH + X509 CA" // {default = true;};

    ssh = {
      caDir = mkOption {
        type = types.str;
        default = sshCaDir;
        description = "Directory containing the SSH CA keys on the host.";
      };
      keyPath = mkOption {
        type = types.str;
        default = sshKeyPath;
        description = "Path to the SSH CA private key on the host.";
      };
      pubPath = mkOption {
        type = types.str;
        default = sshPubPath;
        description = "Path to the SSH CA public key on the host.";
      };
      machinesDir = mkOption {
        type = types.str;
        default = sshMachinesDir;
        description = ''
          Root directory for every signed guest host key/cert, both MicroVMs
          and containers. Namespaced one level down by guest kind:
          `<machinesDir>/microvm/<name>` and `<machinesDir>/containers/<name>`.
        '';
      };
    };

    x509 = {
      caDir = mkOption {
        type = types.str;
        default = x509CaDir;
        description = "Directory containing the X509 root CA.";
      };
      keyPath = mkOption {
        type = types.str;
        default = x509KeyPath;
        description = "Path to the X509 root CA private key.";
      };
      crtPath = mkOption {
        type = types.str;
        default = x509CrtPath;
        description = "Path to the X509 root CA certificate.";
      };
      hostDir = mkOption {
        type = types.str;
        default = x509HostDir;
        description = "Directory containing the host's own server certificate.";
      };
      hostCertPath = mkOption {
        type = types.str;
        default = x509HostCertPath;
        description = "Path to the host server certificate.";
      };
      hostKeyPath = mkOption {
        type = types.str;
        default = x509HostKeyPath;
        description = "Path to the host server private key.";
      };
      machinesDir = mkOption {
        type = types.str;
        default = x509MachinesDir;
        description = ''
          Root directory for per-guest X509 client certs. Namespaced by guest
          kind: `<machinesDir>/microvm/<name>` and
          `<machinesDir>/containers/<name>`.
        '';
      };
    };
  };

  config = mkIf (cfg.enable && hasGuests) (mkService {
    name = "tartarus-ca-known-hosts";
    description = "Update tartarus (MicroVM/container) CA known_hosts for ${username}";
    command = "${script}/bin/tartarus-ca-known-hosts";
  });
}

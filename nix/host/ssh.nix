# Host-side SSH wiring that tartarus itself owns.
#
# The user-facing `Host *.trs` client entries live in the separate
# home-manager module (`homeManagerModules."tartarus-ssh"`, which writes
# `~/.ssh/config.d/tartarus`), because they are per-user config. What tartarus
# owns here is:
#
#   * the on-disk `known_hosts_trs` location, exposed as an option so the CA
#     service (`./ca.nix`) and any per-user config agree on one path;
#   * a system-wide `/etc/ssh/ssh_known_hosts` `@cert-authority` entry for the
#     tartarus SSH CA, so any local user (and root) can verify `*.trs` guests
#     even without their own known_hosts entry.
#
# The system entry needs the CA public key at evaluation time; when the key has
# not been created yet (the `tartarus` CLI generates it on demand) the entry is
# simply omitted -- the runtime `known_hosts_trs` service still covers the user.
{inputs ? {}}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  isLinux = !(lib.hasSuffix "-darwin" (args.system or builtins.currentSystem));
  username = args.username or "user";
  homeDir =
    args.homeDir
    or (
      if lib.hasSuffix "-darwin" (args.system or builtins.currentSystem)
      then "/Users/${username}"
      else "/home/${username}"
    );

  cfg = config.tartarus.ssh;
  ca = config.tartarus.ca;

  caPubPath = ca.ssh.pubPath;
  caPubExists = builtins.pathExists caPubPath;
  caPubKey =
    if caPubExists
    then lib.removeSuffix "\n" (builtins.readFile caPubPath)
    else "";
in {
  options.tartarus.ssh = {
    enable = mkEnableOption "system-wide SSH trust for the tartarus CA" // {default = true;};

    knownHostsFile = mkOption {
      type = types.str;
      default = "${homeDir}/.ssh/known_hosts_trs";
      description = "The per-user known_hosts file carrying the tartarus CA `@cert-authority` line (written by the `tartarus-ca-known-hosts` service).";
    };

    retries = mkOption {
      type = types.ints.unsigned;
      default = 5;
      description = ''
        How many times `tartarus ssh` retries after a failed connection
        (ssh exit status 255), e.g. while a freshly started guest is still
        bringing up sshd. Written to `[ssh].retries` in config.toml and
        overridable with `tartarus ssh --retry N`.
      '';
    };

    retryDelay = mkOption {
      type = types.numbers.nonnegative;
      default = 2.0;
      description = ''
        Fixed number of seconds between `tartarus ssh` connection retries.
        Written to `[ssh].retry_delay` in config.toml and overridable with
        `tartarus ssh --retry-delay SECONDS`.
      '';
    };
  };

  config = mkIf (cfg.enable && ca.enable && isLinux && caPubExists) {
    programs.ssh.knownHosts.tartarus-ca = {
      certAuthority = true;
      hostNames = ["*.trs"] ++ config.tartarus.instances.enabledSubnets;
      publicKey = caPubKey;
    };
  };
}

# Autostart: one nix-service user service per guest with `autostart = true`,
# invoking the tartarus CLI (`systemd --user` on Linux, a launchd agent on
# Darwin, both created by nix-service). The unit starts at login and is stopped
# when the session ends, so it is not a boot-time daemon.
#
# The service fragments are assigned to their concrete namespace rather than
# merged at the top level: a top-level `config = mkIf (...) (mkMerge (map ...))`
# forces the guest-derived list while nixpkgs is still resolving module
# arguments, which trips the `_module.args` recursion. Reading the same list
# from `config.tartarus.instances.autostart` once the namespace is evaluated is
# safe.
{
  inputs ? {},
  tartarusPkg ? null,
}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    map
    mkMerge
    optionalString
    ;

  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
  username = args.username or "user";

  enabled = config.tartarus.instances.autostart;

  # The CLI comes from `default.nix` (the flake's own package output). The
  # fallback only matters if this file is imported on its own.
  tartarus =
    if tartarusPkg != null
    then tartarusPkg
    else import ../packages/tartarus {inherit pkgs;};

  mkService = inputs.nix-service.lib.mkService {
    inherit lib username isDarwin;
    homeManager = false;
  };

  serviceFor = g: {
    name = "tartarus-autostart-${g.name}";
    description = "Autostart tartarus ${g.kind} ${g.name}";
    command = "${tartarus}/bin/tartarus ${optionalString (g.kind == "container") "--container "}start ${g.name}";
    after = ["network.target"];
    # `tartarus start` is a one-shot command (starts the VM background process
    # then exits).  Without this, launchd's default `KeepAlive = true` restarts
    # the agent continuously in a loop.
    extraLaunchdConfig = {
      KeepAlive = false;
    };
  };
in {
  config =
    if isDarwin
    then {
      # `launchd.user.agents` (not `launchd.agents`): nix-service renders
      # Darwin user scope as `launchd.agents`, which nix-darwin installs in
      # `/Library/LaunchAgents` and loads as root. macOS then warns
      # "Expecting a LaunchDaemons path..." and fails the unload with EIO, and
      # the agent ends up in the root domain. `launchd.user.agents` installs in
      # `~/Library/LaunchAgents` and the activation loads it in the primary
      # user's session (`launchctl asuser`), which is where these belong.
      launchd.user.agents = mkMerge (map (g: (mkService (serviceFor g)).launchd.agents) enabled);
    }
    else {
      systemd.user.services = mkMerge (map (g: (mkService (serviceFor g)).systemd.user.services) enabled);
    };
}

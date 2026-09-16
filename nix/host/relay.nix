# Darwin host-side port relays for guest services. vfkit's vmnet-shared mode
# flags the vmenet bridge ports PRIVATE, so guests cannot reach each other and
# the host cannot route to a guest's service through the gateway. A userspace
# `socat` relay bound to the gateway forwards the bytes instead. Linux needs no
# relay: the host routes straight to the guest's bridge IP.
#
# Two sources feed the relay set:
#   * `tartarus.guests.<name>.relays` -- user-declared forwards to any VM;
#   * the automatic guest-hosted proxy relay (`tartarus.proxy.location`), so a
#     proxy VM needs no extra declaration (see PLAN.md section 3.5).
#
# A relay to a privileged port (< 1024, e.g. DNS on 53) is emitted as a root
# launch daemon; everything else is a user launch agent.
#
# TCP uses `TCP-LISTEN,...,fork`. UDP must use `UDP-RECVFROM,...,fork` rather
# than `UDP-LISTEN,...,fork`: in LISTEN mode socat closes the listening socket
# in the parent after forking a child, then re-binds a fresh one and dies with
# EADDRINUSE because the child still holds the old socket (Linux tolerates the
# rebind via SO_REUSEADDR; Darwin does not, so launchd crash-loops). In
# RECVFROM mode the parent keeps its socket across forks and relays every
# datagram. The listening socket is also bound to the specific gateway address,
# which wins over macOS's mDNSResponder wildcard `*:53`, so DNS on `:53` works.
{inputs}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    concatLists
    filter
    map
    mapAttrsToList
    mkMerge
    optional
    ;

  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
  username = args.username or "user";
  ids = import ../lib/ids.nix {inherit lib;};

  instances = config.tartarus.instances;
  proxy = config.tartarus.proxy;

  guestFor = name: instances.guests.${name} or null;

  # `instances.guests` is the plain, already-forced view (see instances.nix);
  # reading it here rather than `config.tartarus.guests` avoids the nixpkgs
  # `_module.args` recursion this module would otherwise trigger while defining
  # `launchd.*`.
  declared = concatLists (
    mapAttrsToList (
      name: g:
        map (relay: {inherit name relay;})
        (g.relays or [])
    )
    instances.guests
  );

  proxyRelay =
    optional
    (proxy.enable && proxy.location != "host" && guestFor proxy.location != null)
    {
      name = proxy.location;
      relay = {
        port = proxy.port;
        targetPort = null;
        protocol = "tcp";
        host = null;
      };
    };

  allRelays = declared ++ proxyRelay;

  # Privileged ports are root services; the rest are user agents.
  isPrivileged = r: r.relay.port < 1024;
  userRelays = filter (r: !isPrivileged r) allRelays;
  systemRelays = filter isPrivileged allRelays;

  mkService = inputs.nix-service.lib.mkService {
    inherit lib username isDarwin;
    homeManager = false;
  };

  mkRelayService = {
    name,
    relay,
  }: let
    g = guestFor name;
    targetPort =
      if relay.targetPort != null
      then relay.targetPort
      else relay.port;
    host =
      if relay.host != null
      then relay.host
      else ids.darwinGateway;
    # See the header: UDP must RECVFROM (not LISTEN) so the parent keeps its
    # socket across forks instead of dying with EADDRINUSE on Darwin.
    listen =
      if relay.protocol == "udp"
      then "UDP4-RECVFROM:${toString relay.port},bind=${host},reuseaddr,fork"
      else "TCP4-LISTEN:${toString relay.port},bind=${host},reuseaddr,fork";
    target =
      if relay.protocol == "udp"
      then "UDP4:${g.ip}:${toString targetPort}"
      else "TCP4:${g.ip}:${toString targetPort}";
    serviceName = "tartarus-relay-${name}-${relay.protocol}-${toString relay.port}";
    command = "${pkgs.socat}/bin/socat ${listen} ${target}";
  in
    mkService {
      name = serviceName;
      description = "tartarus ${relay.protocol} relay ${host}:${toString relay.port} -> ${name}:${toString targetPort}";
      inherit command;
      # Binding a privileged port needs root.
      scope =
        if relay.port < 1024
        then "system"
        else "user";
      after = ["network.target"];
      restart = "on-failure";
    };
in {
  # Assign the fragments to their concrete launchd namespace (rather than a
  # top-level `mkIf ... (mkMerge (map ...))`) so the guest-derived relay list is
  # only forced once the option is read: forcing it while nixpkgs is still
  # resolving module arguments trips the `_module.args` recursion (see the same
  # note in autostart.nix).
  config =
    if isDarwin
    then {
      launchd.agents = mkMerge (map (r: (mkRelayService r).launchd.agents) userRelays);
      launchd.daemons = mkMerge (map (r: (mkRelayService r).launchd.daemons) systemRelays);
    }
    else {};
}

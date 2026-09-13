# Host-half service enablement. For every enabled guest that requests one of
# the tartarus-owned integrations, enable the matching *server* as a
# home-manager user service on the host (launchd agent on Darwin, systemd user
# unit on Linux), aggregating the guest CID/IP mappings.
#
# The guest half lives in `nix/guest/default.nix`; this module only configures
# the host. Host services are user-scoped because they need the invoking user's
# ssh-agent, keychain and GUI (dialogs/notifications), so this module targets
# `home-manager.users.<username>` and therefore requires home-manager to be
# imported whenever a guest requests a service.
{inputs}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    any
    attrValues
    filter
    filterAttrs
    map
    mapAttrsToList
    mkDefault
    mkIf
    mkMerge
    ;
  # Read from the raw module args (specialArgs), not via a defaulted formal:
  # this nixpkgs resolves defaulted module args through `_module.args`, so a
  # default would be ignored and an unprovided arg would shadow `config`.
  username = args.username or "user";
  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);

  # Phase 4 X509 layout -- read from the CA options (`nix/host/ca.nix`) rather
  # than re-deriving the paths here, so the on-disk layout stays in one place.
  ca = config.tartarus.ca.x509;
  x509Ca = ca.crtPath;
  x509HostCert = ca.hostCertPath;
  x509HostKey = ca.hostKeyPath;

  ids = import ../lib/ids.nix {inherit lib;};
  instances = config.tartarus.instances;

  guests = config.tartarus.guests or {};
  enabled = filterAttrs (_: g: g.enable) guests;
  svc = name: g: (g.services or {}).${name} or false;
  requesting = name: filterAttrs (_: g: svc name g) enabled;

  sudoReq = requesting "sudoAuthProxy";
  sshReq = requesting "sshAuthProxy";
  clipReq = requesting "clipboardBridge";

  needsSudo = sudoReq != {};
  needsSsh = sshReq != {};
  needsClip = clipReq != {};
  needsAny = needsSudo || needsSsh || needsClip;

  guestId = name: g:
    if g.kind == "vm"
    then instances.vm.idByName.${name}
    else instances.container.idByName.${name};

  guestIP = name: g: let
    id = guestId name g;
  in
    if g.kind == "vm"
    then
      (
        if isDarwin
        then ids.mkVmIPNat id
        else ids.mkVmIP id
      )
    else ids.mkCtnIP id;

  # VSOCK is Linux-VM-only; Darwin and containers are always TCP.
  transportOf = g:
    if !isDarwin && g.kind == "vm" && !(svc "disableVsock" g)
    then "vsock"
    else "tcp";

  listOf = req: mapAttrsToList (name: g: {inherit name g;}) req;

  mkTransport = req:
    if isDarwin
    then "tcp"
    else if any (e: transportOf e.g == "vsock") (listOf req)
    then "vsock"
    else "tcp";

  mkTcpHost = req: let
    e = listOf req;
    hasVm = any (x: x.g.kind == "vm") e;
    hasCtn = any (x: x.g.kind == "container") e;
  in
    if isDarwin
    then "0.0.0.0"
    else if hasCtn && !hasVm
    then instances.container.hostIP
    else instances.vm.hostIP;

  sudoHm = (import ../packages/sudo-auth-proxy.nix {inherit inputs;}).homeManagerModule;
  sshHm = (import ../packages/ssh-agent-proxy.nix {inherit inputs;}).homeManagerModule;
  clipHm = (import ../packages/clipboard-bridge.nix {inherit inputs;}).homeManagerModule;

  sshEntries = listOf sshReq;
  sshVmEntries =
    map (e: {
      cid = guestId e.name e.g;
      name = e.name;
    })
    (filter (e: transportOf e.g == "vsock") sshEntries);
  sshTcpEntries =
    map (e: {
      ip = guestIP e.name e.g;
      name = e.name;
    })
    sshEntries;
in {
  config = mkIf needsAny {
    # The tartarus home-manager service modules pick their unit schema from the
    # external `system` specialArg (read from the raw args to dodge this
    # nixpkgs' defaulted-arg handling). nixcfg already sets it; setting it here
    # too keeps the host half self-sufficient.
    home-manager.extraSpecialArgs.system = args.system or builtins.currentSystem;
    home-manager.users.${username} = mkMerge [
      {imports = [sudoHm sshHm clipHm];}

      (mkIf needsSudo {
        tartarus.sudo-auth-proxy.server = {
          enable = mkDefault true;
          transport = mkDefault (mkTransport sudoReq);
          host = mkDefault (mkTcpHost sudoReq);
          port = mkDefault 65001;
          cid = mkDefault 2;
          mtls = {
            enable = mkDefault true;
            caFile = mkDefault x509Ca;
            certFile = mkDefault x509HostCert;
            keyFile = mkDefault x509HostKey;
            requiredOid = mkDefault "1.3.6.1.4.1.99999.1.1";
            peerOid = mkDefault "1.3.6.1.4.1.99999.1.2";
          };
        };
      })

      (mkIf needsSsh {
        tartarus.ssh-agent-proxy.server = {
          enable = mkDefault true;
          settings = {
            vsock_port = mkDefault (
              if !isDarwin && any (e: transportOf e.g == "vsock") sshEntries
              then 65000
              else null
            );
            tcp_bind = mkDefault "${mkTcpHost sshReq}:65000";
            vm = mkDefault sshVmEntries;
            tcp_vm = mkDefault sshTcpEntries;
          };
          mtls = {
            enable = mkDefault true;
            caFile = mkDefault x509Ca;
            certFile = mkDefault x509HostCert;
            keyFile = mkDefault x509HostKey;
            requiredOid = mkDefault "1.3.6.1.4.1.99999.2.1";
            peerOid = mkDefault "1.3.6.1.4.1.99999.2.2";
          };
        };
      })

      (mkIf needsClip {
        tartarus.clipboard-bridge.server = {
          enable = mkDefault true;
          transport = mkDefault (mkTransport clipReq);
          host = mkDefault (mkTcpHost clipReq);
          port = mkDefault 27795;
          mtls = {
            enable = mkDefault true;
            caFile = mkDefault x509Ca;
            certFile = mkDefault x509HostCert;
            keyFile = mkDefault x509HostKey;
            requiredOid = mkDefault "1.3.6.1.4.1.99999.3.1";
            peerOid = mkDefault "1.3.6.1.4.1.99999.3.2";
          };
        };
      })
    ];
  };
}

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

  # Host-half services are only reachable for host-side guests. A nested
  # container reaches the host through its container-host VM (the VM DNATs the
  # service ports out to the host; see `guest/container-host.nix`), so the VM
  # stands in for its inner containers: it is added as a service peer carrying
  # the union of its own and its inner containers' requests, addressed by the
  # VM's NAT IP and named by the VM. Host ACLs therefore target the VM name
  # (the VM's masquerade collapses the inner identity).
  hostServices = ["sudoAuthProxy" "sshAgentProxy" "clipboardBridge"];
  innerContainersOf = hostName:
    filterAttrs (_: g: g.enable && g.kind == "container" && (g.host or null) == hostName) guests;
  standInVms =
    filterAttrs (
      name: g:
        g.enable
        && g.kind == "vm"
        && (g.vm.containerHost.enable or false)
        && any (inner: any (f: (inner.services or {}).${f} or false) hostServices) (attrValues (innerContainersOf name))
    )
    guests;
  mkStandIn = name: _: let
    g = guests.${name};
    inner = attrValues (innerContainersOf name);
  in {
    enable = true;
    kind = "vm";
    host = null;
    services =
      lib.genAttrs hostServices (
        f: (g.services.${f} or false) || any (innerGuest: (innerGuest.services or {}).${f} or false) inner
      )
      // {disableVsock = true;};
  };
  # Host-side guests plus the container-host VMs standing in for their nested
  # containers (overwriting the VM's own entry with the union of requests).
  enabled =
    filterAttrs (_: g: g.enable && (g.host or null) == null) guests
    // lib.mapAttrs mkStandIn standInVms;
  svc = name: g: (g.services or {}).${name} or false;
  requesting = name: filterAttrs (_: g: svc name g) enabled;

  sudoReq = requesting "sudoAuthProxy";
  sshReq = requesting "sshAgentProxy";
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

  # ---- sudo-auth-proxy host wiring (audit A1) ----------------------------
  # A guest asks for the SSH-forwarded `unix` transport through the per-guest
  # `services.sudoAuthProxyTransport` marker; every other value keeps the
  # platform's callback transport (`transportOf`). The server exposes exactly
  # ONE socket per host user, so all requesting guests must share one transport;
  # that single-transport invariant is what `sudoTransport` below enforces.
  #
  # There are two kinds of conflict (audit N1):
  #   * `unix` mixed with any callback transport is a genuine conflict: `unix`
  #     is host-dials-guest (one AF_UNIX socket, SSH-forwarded) while `vsock`/
  #     `tcp` are guest-dials-host, and the server binds a single socket with
  #     one direction -- so this stays a hard evaluation error.
  #   * `vsock` + `tcp` are two callback variants of the same direction, so we
  #     restore the previous deterministic behaviour (`vsock` wins) and emit a
  #     `lib.warn` instead of failing the whole host. A common Linux host with
  #     one vsock VM and one tcp container therefore still evaluates; the tcp
  #     guest is simply not reachable until the transports are unified.
  sapMarker = g: (g.services or {}).sudoAuthProxyTransport or "vsock";
  sapGuestTransport = g:
    if sapMarker g == "unix"
    then "unix"
    else transportOf g;
  sudoTransports = lib.unique (map (e: sapGuestTransport e.g) (listOf sudoReq));
  sudoTransport =
    if sudoTransports == []
    then "tcp" # unused (no sudo guests); keeps the binding total
    else if builtins.length sudoTransports == 1
    then builtins.head sudoTransports
    else if builtins.elem "unix" sudoTransports
    then
      throw (
        "tartarus: the enabled guests requesting sudo-auth-proxy mix the "
        + "SSH-forwarded `unix` transport with a callback transport "
        + "(${lib.concatStringsSep ", " sudoTransports}); the server exposes a "
        + "single socket and the two call directions are incompatible. Set "
        + "services.sudoAuthProxyTransport consistently."
      )
    else
      lib.warn (
        "tartarus: the enabled guests requesting sudo-auth-proxy use mixed "
        + "callback transports (${lib.concatStringsSep ", " sudoTransports}); "
        + "defaulting to `vsock` (the previous behaviour). The `tcp` guests are "
        + "not reachable until services.sudoAuthProxyTransport is unified."
      ) "vsock";
  sudoIsUnix = sudoTransport == "unix";
  # The sudo-auth-proxy client OID (doc §7.6). Every tartarus client cert
  # carries it today (audit A4 documents that the OIDs separate roles, not
  # services), so `acl.mode = "ca"` authorizes the guests without an operator
  # fingerprint list.
  sudoClientOid = "1.3.6.1.4.1.99999.1.2";
  homeDir =
    args.homeDir
    or (
      if isDarwin
      then "/Users/${username}"
      else "/home/${username}"
    );

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
        tartarus.sudo-auth-proxy = {
          # The server emitter reads the *top-level* `security` group (not
          # `server.security`) for the resolved knobs, so they are set here.
          #
          # `unix` (audit A1): the SSH tunnel protects the channel and mTLS
          # authenticates both ends inside it -- the only mechanism left (doc
          # §7). The guest presents its tartarus CA-chained client certificate,
          # the host presents its server certificate, and the ACL authorizes
          # the guest's SPKI against the tartarus CA + client OID.
          #
          # Callback transports (`vsock`/`tcp`): the tartarus-internal channel
          # is private by construction, so it runs with no crypto and no
          # authentication -- `transportEncryption = "none"`,
          # `serverAuth = "none"`, `clientAuth = "none"` and the fail-closed
          # matching `acl.mode = "none"`. The Python warns about `none` and
          # refuses a `client_auth`/`acl.mode` mismatch. No CA material, no
          # mTLS.
          security = {
            transportEncryption = mkDefault (
              if sudoIsUnix
              then "mtls"
              else "none"
            );
            serverAuth = mkDefault (
              if sudoIsUnix
              then "transport"
              else "none"
            );
            clientAuth = mkDefault (
              if sudoIsUnix
              then "transport"
              else "none"
            );
          };
          server = {
            enable = mkDefault true;
            # One socket per host user: unix if any requesting guest asked for
            # it, else the shared callback transport (vsock/tcp).
            transport = mkDefault sudoTransport;
            host = mkDefault (mkTcpHost sudoReq);
            port = mkDefault 65001;
            cid = mkDefault 2;
            # A2: the first frame (the pre-dialog ack) is bounded by the
            # client's recvTimeout; the human decision is bounded by
            # decisionTimeout. Keep the server values in the same shape.
            recvTimeout = mkDefault 0.5;
            decisionTimeout = mkDefault 120;
            # Usable, default-secure ACL: `ca` authorizes the CA-chained guests
            # on the `unix` path; `none` deliberately authorizes the
            # unauthenticated callback path and is only accepted because
            # `client_auth = "none"` above. Operators can override with
            # `mode = "list"` + `trustedFingerprints` (leaf SPKI pins).
            acl.mode = mkDefault (
              if sudoIsUnix
              then "ca"
              else "none"
            );
            # `acl.mode = "ca"` reads its own CA/OID: there is no
            # `security.caFile` to fall back on any more (that option went with
            # the removed x509 requester method).
            acl.caFile = mkDefault (
              if sudoIsUnix
              then x509Ca
              else null
            );
            acl.requiredOid = mkDefault (
              if sudoIsUnix
              then sudoClientOid
              else null
            );
            # mTLS is on for the `unix` path only; the callback channel is
            # unauthenticated by design.
            mtls = {
              enable = mkDefault sudoIsUnix;
              caFile = mkDefault x509Ca;
              certFile = mkDefault x509HostCert;
              keyFile = mkDefault x509HostKey;
              requiredOid = mkDefault "1.3.6.1.4.1.99999.1.1";
              peerOid = mkDefault sudoClientOid;
            };
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

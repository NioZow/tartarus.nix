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
    optional
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

  # Host address(es) a callback `tcp` listener must bind. `entries` is the set
  # of requesting guests whose *effective* transport is `tcp` (the callers
  # filter out vsock and `unix`-marker guests); only those decide the bind
  # address. This is what stops a vsock VM from dragging the tcp listener onto
  # the VM bridge (`10.200.0.1`) while the containers that need it dial their
  # own bridge gateway (`10.201.0.1`) and get a connection refused. Darwin has
  # no vsock, so every guest is tcp and the server binds all interfaces. A host
  # with both a `disableVsock` VM and a container on tcp yields one address per
  # kind (same port, distinct binds).
  mkTcpHosts = entries: let
    hasVm = any (e: e.g.kind == "vm") entries;
    hasCtn = any (e: e.g.kind == "container") entries;
  in
    if isDarwin
    then ["0.0.0.0"]
    else optional hasVm instances.vm.hostIP ++ optional hasCtn instances.container.hostIP;

  # Single-address convenience for the clipboard server, whose module binds one
  # socket. `entries` must already be tcp-only (as for `mkTcpHosts`).
  mkTcpHost = entries: let
    hosts = mkTcpHosts entries;
  in
    if hosts == []
    then
      (
        if isDarwin
        then "0.0.0.0"
        else instances.vm.hostIP
      )
    else builtins.head hosts;

  # ---- sudo-auth-proxy host wiring (audit A1) ----------------------------
  # One listener per distinct transport the requesting guests ask for: a guest
  # asks for the SSH-forwarded `unix` transport through the per-guest
  # `services.sudoAuthProxyTransport` marker; every other value keeps the
  # platform's callback transport (`transportOf`). The server process binds
  # every listener at once, so a vsock VM, a tcp container and an SSH-forwarded
  # unix guest are all served simultaneously -- the old mixed-transport
  # `throw`/`lib.warn` are gone.
  sapMarker = g: (g.services or {}).sudoAuthProxyTransport or "vsock";
  sapGuestTransport = g:
    if sapMarker g == "unix"
    then "unix"
    else transportOf g;
  sudoKinds = lib.unique (map (e: sapGuestTransport e.g) (listOf sudoReq));

  # `unix` is host-dials-guest (one AF_UNIX socket, SSH-forwarded) and runs mTLS
  # inside the SSH tunnel -- the only authentication mechanism left (doc §7);
  # the guest presents its tartarus CA-chained client certificate, the host its
  # server certificate. Callback transports (`vsock`/`tcp`) are private by
  # construction and run with no crypto and no authentication (their
  # `security`/`acl` defaults live in `transportDefaults` below).
  unixSecurity = {
    transportEncryption = "mtls";
    clientAuth = "transport";
    serverAuth = "transport";
  };

  sudoVsockListener = {
    type = "vsock";
    cid = 2;
  };
  # One tcp listener per bridge address the tcp-using guests actually dial (see
  # `mkTcpHosts`): a vsock VM is excluded, so on a mixed host the container
  # listener lands on the container bridge, not the VM bridge.
  sudoTcpEntries = filter (e: sapGuestTransport e.g == "tcp") (listOf sudoReq);
  sudoTcpListeners =
    lib.optionals (builtins.elem "tcp" sudoKinds)
    (map (host: {
        type = "tcp";
        inherit host;
        port = 65001;
      })
      (mkTcpHosts sudoTcpEntries));
  sudoUnixListener = {
    type = "unix";
    socket = "%t/sudo-auth-proxy/server.sock";
    security = unixSecurity;
    mtls = {
      enable = true;
      caFile = x509Ca;
      certFile = x509HostCert;
      keyFile = x509HostKey;
      requiredOid = "1.3.6.1.4.1.99999.1.1";
      peerOid = sudoClientOid;
    };
    # `acl.mode = "ca"` authorizes the CA-chained guests without an operator
    # fingerprint list; the callback listeners keep `acl.mode = "none"` (set in
    # `transportDefaults`).
    acl = {
      mode = "ca";
      caFile = x509Ca;
      requiredOid = sudoClientOid;
    };
  };
  # Stable, deterministic listener order: vsock, tcp, unix.
  sudoListeners =
    lib.optional (builtins.elem "vsock" sudoKinds) sudoVsockListener
    ++ sudoTcpListeners
    ++ lib.optional (builtins.elem "unix" sudoKinds) sudoUnixListener;

  # ---- ssh-agent-proxy host wiring (mirrors the sudo block above) ----------
  # A guest asks for the SSH-forwarded `unix` transport through the per-guest
  # `services.sshAgentProxyTransport` marker; every other value keeps the
  # platform's callback transport (`transportOf`). `resolution` is per listener
  # (`certificate` for unix, `tartarus` otherwise).
  sshMarker = g: (g.services or {}).sshAgentProxyTransport or "vsock";
  sshGuestTransport = g:
    if sshMarker g == "unix"
    then "unix"
    else transportOf g;
  sshKinds = lib.unique (map (e: sshGuestTransport e.g) (listOf sshReq));

  sshVsockListener = {
    type = "vsock";
    cid = 2;
    resolution = "tartarus";
  };
  # One tcp listener per bridge address the tcp-using guests actually dial (see
  # `mkTcpHosts`); a vsock VM is excluded so the container listener binds the
  # container bridge.
  sshTcpReq = filter (e: sshGuestTransport e.g == "tcp") (listOf sshReq);
  sshTcpListeners =
    lib.optionals (builtins.elem "tcp" sshKinds)
    (map (host: {
        type = "tcp";
        inherit host;
        port = 65000;
        resolution = "tartarus";
      })
      (mkTcpHosts sshTcpReq));
  sshUnixListener = {
    type = "unix";
    socket = "%t/ssh-agent-proxy/server.sock";
    resolution = "certificate";
    security = unixSecurity;
    mtls = {
      enable = true;
      caFile = x509Ca;
      certFile = x509HostCert;
      keyFile = x509HostKey;
      requiredOid = "1.3.6.1.4.1.99999.2.1";
      peerOid = "1.3.6.1.4.1.99999.2.2";
    };
  };
  sshListeners =
    lib.optional (builtins.elem "vsock" sshKinds) sshVsockListener
    ++ sshTcpListeners
    ++ lib.optional (builtins.elem "unix" sshKinds) sshUnixListener;
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

  sudoHm = (import ../packages/sudo-auth-proxy {inherit inputs;}).homeManagerModule;
  sshHm = (import ../packages/ssh-agent-proxy {inherit inputs;}).homeManagerModule;
  clipHm = (import ../packages/clipboard-bridge {inherit inputs;}).homeManagerModule;

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
          # One `{ type, ...; }` per distinct requesting transport, all bound by
          # the single server process.
          transports = mkDefault sudoListeners;
          # Shared defaults for every listener. Callback transports
          # (`vsock`/`tcp`) run with no crypto and no authentication -- the
          # tartarus-internal channel is private by construction -- and the
          # fail-closed matching `acl.mode = "none"`; the `unix` listener
          # overrides both with mTLS + `acl.mode = "ca"`. The Python refuses a
          # `client_auth`/`acl.mode` mismatch and warns about `none`.
          transportDefaults = {
            port = mkDefault 65001;
            # A2: the first frame (the pre-dialog ack) is bounded by the
            # client's recvTimeout; the human decision is bounded by
            # decisionTimeout. Keep the server values in the same shape.
            recvTimeout = mkDefault 0.5;
            decisionTimeout = mkDefault 120;
            security.transportEncryption = mkDefault "none";
            security.clientAuth = mkDefault "none";
            security.serverAuth = mkDefault "none";
            acl.mode = mkDefault "none";
          };
        };
      })

      (mkIf needsSsh {
        tartarus.ssh-agent-proxy.server = {
          enable = mkDefault true;
          transports = mkDefault sshListeners;
          # Defaults from the module cover connect/handshake/decision timeouts;
          # only the shared bind port and the callback security are overridden
          # here. Callback transports (`vsock`/`tcp`) are private by construction
          # and run with no crypto and no authentication (mirrors the sudo
          # block); the `unix` listener overrides with mTLS.
          transportDefaults = {
            port = mkDefault 65000;
            security.transportEncryption = mkDefault "none";
            security.clientAuth = mkDefault "none";
            security.serverAuth = mkDefault "none";
          };
          # `vm`/`tcp_vm` feed `resolution = "tartarus"`. A server can now have
          # a unix listener *and* a vsock/tcp listener, so the CID/IP maps are
          # always emitted (the old omit-on-unix hack is gone).
          settings = {
            vm = mkDefault sshVmEntries;
            tcp_vm = mkDefault sshTcpEntries;
          };
        };
      })

      (mkIf needsClip {
        tartarus.clipboard-bridge.server = {
          enable = mkDefault true;
          transport = mkDefault (mkTransport clipReq);
          host = mkDefault (mkTcpHost (filter (e: transportOf e.g == "tcp") (listOf clipReq)));
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

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

  # Same-user Unix socket the clipboard server binds for the host CLI. The
  # guest-facing listener may be `vsock` (a Linux VM's callback transport), and
  # a host process cannot dial its own VSOCK CID, so the admin client needs a
  # local socket. `%t` resolves to the same runtime dir for the service and the
  # CLI. It is a normal listener marked `admin = true`, authorized by same-user
  # Unix permissions (socket 0600, parent 0700) plus the allow-all rule -- there
  # is no shared secret and no admin certificate.
  clipAdminSocket = "%t/clipboard-bridge-admin.sock";

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

  # One listener per distinct transport the clipboard guests ask for, plus the
  # local admin listener. The server binds all of them in one process, so a
  # Linux host serves its VSOCK VMs and its TCP containers at the same time
  # instead of collapsing to a single transport and leaving the other kind with
  # connection refused.
  clipKinds = lib.unique (map (e: transportOf e.g) (listOf clipReq));
  clipTcpEntries = filter (e: transportOf e.g == "tcp") (listOf clipReq);

  # VSOCK callbacks are private by construction: plaintext with no peer auth.
  clipVsockListener = {
    type = "vsock";
    name = "tartarus-vsock";
    cid = 2;
    port = 27795;
    resolution = "tartarus";
    security = callbackSecurity;
  };

  # The tartarus TCP container listener is mTLS with the guest certificate: the
  # container bridge is shared, so this callback is not trusted by construction
  # (unlike VSOCK). One entry per bind address the TCP guests actually dial.
  clipTcpListeners =
    lib.optionals (builtins.elem "tcp" clipKinds)
    (map (host: {
        type = "tcp";
        name = "tartarus-tcp-${host}";
        inherit host;
        port = 27795;
        resolution = "tartarus";
        security = unixSecurity;
        mtls = {
          enable = true;
          caFile = x509Ca;
          certFile = x509HostCert;
          keyFile = x509HostKey;
          requiredOid = clipServerOid;
          peerOid = clipClientOid;
        };
      })
      (mkTcpHosts clipTcpEntries));

  # The host CLI talks to this same-user Unix listener, which serves the admin
  # control plane and is authorized by the allow-all rule below.
  clipAdminListener = {
    type = "unix";
    name = "admin";
    socket = clipAdminSocket;
    admin = true;
    resolution = "none";
    security = callbackSecurity;
    socketDirMode = "0700";
    socketMode = "0600";
  };

  # Stable, deterministic listener order: vsock, tcp, admin.
  clipListeners =
    optional (builtins.elem "vsock" clipKinds) clipVsockListener
    ++ clipTcpListeners
    ++ [clipAdminListener];

  # The local admin socket is same-user IPC, so its identity is the filesystem
  # boundary; allow every admin action on it. Guest listeners serve only the
  # guest actions, so they need no rule.
  clipRules = [
    {
      match.listeners = ["admin"];
      policy = "allow";
    }
  ];

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
  # construction and run with no crypto and no authentication, so every callback
  # listener carries this `security` block explicitly. (`auto` would resolve a
  # `tcp` listener to mTLS, so the callback listeners must say `none`.)
  unixSecurity = {
    transportEncryption = "mtls";
    clientAuth = "transport";
    serverAuth = "transport";
  };
  callbackSecurity = {
    transportEncryption = "none";
    clientAuth = "none";
    serverAuth = "none";
  };

  sudoVsockListener = {
    type = "vsock";
    cid = 2;
    security = callbackSecurity;
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
        security = callbackSecurity;
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
    # The mTLS handshake verifies the CA-chained guest certificate (no separate
    # ACL any more: authorization is the ordered `[[rule]]` list, and no rule
    # matching means `ask`). The callback listeners run with
    # `client_auth = none` (their explicit `callbackSecurity`).
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
    security = callbackSecurity;
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
        security = callbackSecurity;
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
  # services), so the unix listener's mTLS EKU check admits the guests without
  # an operator fingerprint list.
  sudoClientOid = "1.3.6.1.4.1.99999.1.2";

  # Clipboard EKU OIDs (same subtree convention as sudo/ssh). The admin OID is
  # reserved for the optional certificate-admin listener; the default host admin
  # path is the same-user Unix socket, which needs no certificate.
  clipServerOid = "1.3.6.1.4.1.99999.3.1";
  clipClientOid = "1.3.6.1.4.1.99999.3.2";
  clipAdminOid = "1.3.6.1.4.1.99999.3.3";

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

  # `vm`/`tcp_vm` feed `resolution = "tartarus"`: a VSOCK peer is named by CID,
  # a TCP peer by source IP. The TCP map covers every requesting guest (the IP
  # simply never matches for a VSOCK guest).
  clipVmEntries =
    map (e: {
      cid = guestId e.name e.g;
      name = e.name;
    })
    (filter (e: transportOf e.g == "vsock") (listOf clipReq));
  clipTcpEntriesForResolution =
    map (e: {
      ip = guestIP e.name e.g;
      name = e.name;
    })
    (listOf clipReq);
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
          # One self-contained `{ type, ...; }` per distinct requesting
          # transport, all bound by the single server process. Callback
          # transports (`vsock`/`tcp`) run with no crypto and no authentication
          # -- the tartarus-internal channel is private by construction, so each
          # carries `callbackSecurity` -- while the `unix` listener overrides
          # both with mTLS. The document-level `[[rule]]` list decides
          # allow/ask/deny; with no rules every request is prompted.
          listeners = mkDefault sudoListeners;
        };
      })

      (mkIf needsSsh {
        tartarus.ssh-agent-proxy.server = {
          enable = mkDefault true;
          # Every listener is self-contained: the module's defaults cover
          # connect/handshake/decision timeouts, each entry names its own bind
          # target and security. Callback transports (`vsock`/`tcp`) are private
          # by construction and run with no crypto and no authentication
          # (mirrors the sudo block); the `unix` listener overrides with mTLS.
          listeners = mkDefault sshListeners;
          # `vm`/`tcp_vm` feed `resolution = "tartarus"`. A server can have a
          # unix listener *and* a vsock/tcp listener, so the CID/IP maps are
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
          # Every listener is self-contained: VSOCK callbacks are private by
          # construction (plaintext, no auth), TCP callbacks are mTLS with the
          # guest certificate, and the local admin socket is same-user Unix IPC.
          listeners = mkDefault clipListeners;
          # Authorize the local admin listener; guest listeners only serve the
          # guest actions and need no rule.
          rule = mkDefault clipRules;
          # `vm`/`tcp_vm` feed `resolution = "tartarus"`.
          settings = {
            vm = mkDefault clipVmEntries;
            tcp_vm = mkDefault clipTcpEntriesForResolution;
          };
        };

        # Point an enabled admin client at the admin Unix socket. It is
        # same-user IPC, so it runs with no crypto and no authentication (both
        # auth knobs must be explicit for plaintext).
        tartarus.clipboard-bridge.adminClient = {
          transport = mkDefault "unix";
          socket = mkDefault clipAdminSocket;
          security = mkDefault callbackSecurity;
        };
      })
    ];
  };
}

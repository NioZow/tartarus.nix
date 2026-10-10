# The tartarus firewall, in one file because the host-side rules and the
# guest-side opt-in share the same internet x proxy policy.
#
# Host mode (Linux only) generates the `tartarus_vm` / `tartarus_container`
# nftables tables. The proxy `accept` rule lives in the *same* input chain as
# the guest rules -- the old tree had a separate `squid` table at priority 0
# which the guest chain's `policy drop` at priority -10 always preempted. It
# also owns the host bridges, `/etc/hosts` entries and the NAT table (with the
# cross-kind proxy exception) so the internet x proxy matrix below is real:
#
#   internet  proxy.enable  egress
#   true      false         NAT to the internet
#   false     false         none (internal host services still allowed)
#   false     true          proxy only; host services still allowed
#   true      true          rejected by the Phase 1 assertion
#
# Guest mode emits an in-guest nftables output policy for guests that opt into
# `firewall.location = "guest"` (the only option on Darwin, where there is no
# host nftables). It restricts ordinary processes; root can flush it, which is
# accepted as a policy rather than a hard boundary. On macOS, Darwin guests
# under vmnet-shared NAT share 192.168.64.0/24 and can reach each other and the
# host; a guest-hosted proxy works there too.
{mode ? "host"}: let
  hostModule = {
    config,
    lib,
    pkgs,
    ...
  } @ args: let
    inherit
      (lib)
      any
      attrValues
      concatMapStringsSep
      concatStringsSep
      filter
      filterAttrs
      listToAttrs
      map
      mkIf
      mkMerge
      nameValuePair
      optional
      optionalString
      ;

    # Platform from the consumer's `system` specialArg, never from `pkgs`:
    # forcing `pkgs.stdenv` while an option in this module's namespace is being
    # read trips nixpkgs' `_module.args` recursion.
    isLinux = !(lib.hasSuffix "-darwin" (args.system or builtins.currentSystem));
    ids = import ../lib/ids.nix {inherit lib;};

    guests = config.tartarus.instances.guests;
    instances = config.tartarus.instances;
    proxy = config.tartarus.proxy;

    proxyEnabled = proxy.enable;
    proxyLocation = proxy.location;
    proxyPort = proxy.port;
    proxyIsGuest = proxyEnabled && proxyLocation != "host";
    proxyClients = proxy.clients;

    hasVm = instances.vm.enabledNames != [];
    # Only host-side containers have a host bridge/table. Nested containers are
    # handled entirely inside their container-host VM (plan §5.3).
    hasCtn = instances.container.hostSideNames != [];
    anyGuest = hasVm || hasCtn;

    # Host-side names per kind. The VM set is the full enabled set; the
    # container set excludes nested containers.
    hostSideNames = kind:
      if kind == "vm"
      then instances.vm.enabledNames
      else instances.container.hostSideNames;

    # Host-reachable address of an `instances.guests` record. A VM sits at its
    # trunk IP; a native container at its `trs1` IP; a nested container is
    # reached at its container-host VM's trunk IP, because the host does not
    # route the VM-local inner subnet. `firewall.nix` host mode is Linux-only,
    # but the formula stays platform-correct.
    reachableIp = record: let
      hostId =
        if (record.host or null) == null
        then null
        else instances.vm.idByName.${record.host} or null;
    in
      if record.kind == "vm"
      then
        (
          if isLinux
          then ids.mkVmIP record.id
          else ids.mkVmIPNat record.id
        )
      else if hostId != null
      then
        (
          if isLinux
          then ids.mkVmIP hostId
          else ids.mkVmIPNat hostId
        )
      else ids.mkCtnIP record.id;

    # The guest named by `proxy.location`, when it is a guest. The assertion
    # guarantees it is an enabled VM or container with internet.
    targetGuest = guests.${proxyLocation} or null;
    targetIp =
      if targetGuest == null
      then null
      else reachableIp targetGuest;

    # The guest named by `tartarus.dns.location`, if any: its host-reachable IP
    # is where every client sends UDP/TCP 53.
    dnsResolver = instances.dnsResolver;
    dnsResolverIp =
      if dnsResolver == null
      then null
      else reachableIp dnsResolver;

    # Per-guest `firewall.allow` is an *input* (host-service) allowance. It is
    # never emitted in `forward`, so it can never become an egress backdoor.
    # A bare address/subnet (no spaces) is expanded to a source allowance; a
    # full rule fragment is inserted verbatim.
    allowEntry = a:
      if lib.hasInfix " " a
      then a
      else "ip saddr ${a} counter accept";
    allowRules = kind:
      concatMapStringsSep "\n" (
        name: let
          g = guests.${name};
          fw = g.firewall;
        in
          optionalString (fw.enable && fw.location == "host") (
            concatMapStringsSep "\n" (rule: "    ${allowEntry rule}") fw.allow
          )
      ) (hostSideNames kind);

    mkKind = kind: let
      bridge =
        if kind == "vm"
        then ids.vmBridge
        else ids.ctnBridge;
      subnet =
        if kind == "vm"
        then ids.vmSubnet
        else ids.ctnSubnet;
      hostIP =
        if kind == "vm"
        then ids.vmHostIP
        else ids.ctnHostIP;
      idByName = instances.${kind}.idByName;
      enabledNames = hostSideNames kind;
      enabledInst =
        filterAttrs
        (_: g: g.enable && g.kind == kind && (kind == "vm" || (g.host or null) == null))
        guests;

      mkIP = name: let
        id = idByName.${name};
      in
        if kind == "vm"
        then ids.mkVmIP id
        else ids.mkCtnIP id;

      # Containers get a constant set of their exact addresses; VMs use the
      # whole subnet (matching the old ruleset). The set is only emitted for
      # containers, below.
      useSet = kind == "container";
      srcSetName = "tartarus_${kind}_hosts";
      src =
        if useSet
        then "@${srcSetName}"
        else subnet;
      setElements =
        concatMapStringsSep ",\n" (n: "      ${mkIP n}  comment \"${n}\"") enabledNames;

      # VSOCK is Linux-VM-only; containers (and any VM with `disableVsock`)
      # fall back to TCP and need the matching host-service ports opened.
      isTcp = g: kind == "container" || g.services.disableVsock;
      needsClip = any (g: g.services.clipboardBridge && isTcp g) (attrValues enabledInst);
      # The `unix` ssh-agent-proxy transport is an SSH RemoteForward over the
      # single host AF_UNIX socket: no TCP port is opened (plan Phase 3 item 20).
      needsSsh = any (
        g:
          g.services.sshAgentProxy
          && isTcp g
          && (((g.services or {}).sshAgentProxyTransport or "vsock") != "unix")
      ) (attrValues enabledInst);
      needsSudo = any (g: g.services.sudoAuthProxy && isTcp g) (attrValues enabledInst);

      tcpRules = concatStringsSep "\n" (
        optional needsClip "ip saddr ${src} tcp dport 27795 counter accept comment \"clipboard-bridge-tcp\""
        ++ optional needsSsh "ip saddr ${src} tcp dport 65000 counter accept comment \"ssh-auth-proxy-tcp\""
        ++ optional needsSudo "ip saddr ${src} tcp dport 65001 counter accept comment \"sudo-auth-proxy-tcp\""
      );

      musicIP =
        if enabledInst ? music
        then mkIP "music"
        else null;
      pipewireRule =
        optionalString (enabledInst ? music)
        "ip saddr ${musicIP} tcp dport 4713 counter accept comment \"music-pipewire\"";
      litellmRule = "ip saddr ${src} ip daddr ${hostIP} tcp dport 27740 counter accept comment \"litellm-proxy\"";
      dnsRules =
        optionalString (kind == "container")
        "ip saddr ${src} udp dport 53 counter accept comment \"containers-dns\"\nip saddr ${src} tcp dport 53 counter accept comment \"containers-dns\"";

      # Host-service allowances: only guests that opted into a host firewall.
      guestAllows = allowRules kind;

      # The proxy accept rule -- in the SAME input chain as the guest rules,
      # only for the host-hosted proxy (a guest-hosted proxy is a forward path).
      proxyInputRules = optionalString (proxyEnabled && !proxyIsGuest) (
        concatMapStringsSep "\n" (
          c:
            optionalString (c.kind == kind)
            "ip saddr ${c.ip} ip daddr ${hostIP} tcp dport ${toString proxyPort} counter accept comment \"${c.name}-proxy\""
        )
        proxyClients
      );

      # Cross-kind (and same-kind) routing to a guest-hosted proxy: this must
      # precede the same-bridge drop and the no-internet drops below.
      proxyForwardRules = optionalString proxyIsGuest (
        concatMapStringsSep "\n" (
          c:
            optionalString (c.kind == kind)
            "iifname \"${bridge}\" ip saddr ${c.ip} ip daddr ${targetIp} tcp dport ${toString proxyPort} counter accept comment \"${c.name}-to-proxy\""
        )
        proxyClients
      );

      noInternetRules =
        concatMapStringsSep "\n" (
          name: let
            g = enabledInst.${name};
          in
            optionalString (!g.internet)
            "iifname \"${bridge}\" ip saddr ${mkIP name} oifname != \"${bridge}\" counter drop comment \"${name}-no-internet\""
        )
        enabledNames;

      # Forward DNS to the resolver guest (`tartarus.dns.location`), per client
      # kind: a VM client arrives on `trs0`, a native container client on
      # `trs1`, so both directions of the cross-bridge pair are covered. The
      # target is the resolver's host-reachable IP (a nested resolver is
      # reached at its container-host VM). Must precede the same-bridge drop.
      dnsForwardRules =
        optionalString (dnsResolverIp != null)
        "iifname \"${bridge}\" ip daddr ${dnsResolverIp} udp dport 53 counter accept comment \"dns-resolver\"\niifname \"${bridge}\" ip daddr ${dnsResolverIp} tcp dport 53 counter accept comment \"dns-resolver\"";

      setSection = optionalString useSet ''
        set ${srcSetName} {
          type ipv4_addr
          flags constant
          elements = {
            ${setElements}
          }
        }

      '';

      content = ''
        ${setSection}chain ${kind}_input {
          type filter hook input priority -10
          policy drop

          iifname != "${bridge}" accept

          ct state established,related counter accept

          ip saddr ${src} ip protocol icmp limit rate 20/second counter accept

          ${tcpRules}
          ${dnsRules}
          ${litellmRule}
          ${pipewireRule}
          ${guestAllows}
          ${proxyInputRules}
        }

        chain ${kind}_forward {
          type filter hook forward priority -10
          policy accept

          ct state established,related counter accept
          ${dnsForwardRules}
          ${proxyForwardRules}
          iifname "${bridge}" oifname "${bridge}" counter drop comment "drop-${kind}-to-${kind}"

          ${noInternetRules}
        }
      '';
    in {
      inherit content;
    };

    vm = mkKind "vm";
    ctn = mkKind "container";

    # Internet NAT. We do this in nftables (not systemd-networkd's
    # IPMasquerade) so the cross-kind proxy traffic can be exempted and the
    # client's source IP reaches the proxy VM intact for its per-guest `src`
    # ACLs.
    natTable = ''
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        ${optionalString proxyIsGuest "ip daddr ${targetIp} counter return comment \"proxy-no-masq\""}
        ${optionalString hasVm "ip saddr ${ids.vmSubnet} oifname != \"${ids.vmBridge}\" oifname != \"${ids.ctnBridge}\" counter masquerade comment \"vm-masq\""}
        ${optionalString hasCtn "ip saddr ${ids.ctnSubnet} oifname != \"${ids.vmBridge}\" oifname != \"${ids.ctnBridge}\" counter masquerade comment \"ctn-masq\""}
      }
    '';

    mkBridge = kind: let
      bridge =
        if kind == "vm"
        then ids.vmBridge
        else ids.ctnBridge;
      hostIP =
        if kind == "vm"
        then ids.vmHostIP
        else ids.ctnHostIP;
      subnet =
        if kind == "vm"
        then ids.vmSubnet
        else ids.ctnSubnet;
      # The engine only uses /24 bridges, so the first three octets identify
      # the network, and a target belongs to at most one of them.
      subnetPrefix = let
        octets = lib.splitString "." (lib.head (lib.splitString "/" subnet));
      in
        lib.concatStringsSep "." (lib.take 3 octets) + ".";
      # The explicit host route is only meaningful on the bridge that owns the
      # target's subnet. A nested proxy target sits at its container-host VM's
      # address (the VM bridge on Linux, off both bridges on Darwin), so it
      # must never be routed out of the container bridge.
      routeOnBridge =
        proxyIsGuest
        && targetIp != null
        && lib.hasPrefix subnetPrefix targetIp;
    in {
      systemd.network = {
        netdevs."10-${bridge}" = {
          netdevConfig = {
            Name = bridge;
            Kind = "bridge";
          };
        };
        networks."10-${bridge}" = {
          matchConfig.Name = bridge;
          networkConfig = {
            Address = "${hostIP}/24";
            # `IPMasquerade` is deliberately not set: see `natTable` above.
            IPv4Forwarding = true;
            ConfigureWithoutCarrier = true;
          };
          linkConfig.RequiredForOnline = "no";
          # Explicit host route to a guest-hosted proxy. The /24 connected
          # route already covers it on the target's own bridge, but keeping
          # the /32 makes the cross-kind path self-documenting.
          routes = optional routeOnBridge {
            Destination = "${targetIp}/32";
            Scope = "link";
          };
        };
      };
    };
  in
    # Return an empty module on non-Linux hosts: nix-darwin has no nftables and
    # no bridge networking, and even a `mkIf false` definition of options it
    # does not declare is rejected by its module checker.
    if !isLinux
    then {}
    else {
      config = mkIf anyGuest (mkMerge [
        # Bridges and the host's view of every guest.
        (mkIf hasVm (mkBridge "vm"))
        (mkIf hasCtn (mkBridge "container"))

        {
          systemd.network = {
            enable = true;
            wait-online.enable = false;
          };

          networking.hosts = listToAttrs (
            map (
              n: nameValuePair (ids.mkVmIP instances.vm.idByName.${n}) [n "${n}.trs"]
            )
            instances.vm.enabledNames
            ++ map (
              n: nameValuePair (ids.mkCtnIP instances.container.idByName.${n}) [n "${n}.trs"]
            )
            instances.container.hostSideNames
          );

          boot.kernelModules = ["br_netfilter"];
          boot.kernel.sysctl = {
            "net.ipv4.ip_forward" = 1;
            "net.bridge.bridge-nf-call-iptables" = 1;
            "net.bridge.bridge-nf-call-ip6tables" = 1;
          };

          environment.etc."qemu/bridge.conf".text = concatMapStringsSep "\n" (b: "allow ${b}") (
            optional hasVm ids.vmBridge ++ optional hasCtn ids.ctnBridge
          );

          networking.nftables.enable = true;

          networking.nftables.tables = {
            tartarus_vm = mkIf hasVm {
              family = "inet";
              content = vm.content;
            };
            tartarus_container = mkIf hasCtn {
              family = "inet";
              content = ctn.content;
            };
            tartarus_nat = {
              family = "inet";
              content = natTable;
            };
          };
        }
      ]);
    };

  guestModule = {
    config,
    lib,
    pkgs,
    tartarusGuest,
    ...
  }: let
    inherit
      (lib)
      concatMapStringsSep
      concatStringsSep
      mkIf
      optionalString
      ;
    ids = import ../lib/ids.nix {inherit lib;};
    g = tartarusGuest;
    fw = g.firewall;
    p = g.platform;
    proxy = g.proxy;

    # Only a non-internet guest needs an in-guest policy: an internet guest is
    # explicitly permitted to egress, so the firewall would be a no-op.
    enable = (fw.enable or false) && (fw.location or "guest") == "guest" && !(g.internet or true);

    proxyTcpRule =
      optionalString (proxy.enable or false)
      "ip daddr ${proxy.host} tcp dport ${toString (proxy.port or 3128)} counter accept comment \"proxy\"";
    proxyUdpDnsRule =
      optionalString (proxy.enable or false)
      "ip daddr ${proxy.host} udp dport 53 counter accept comment \"proxy-dns\"";
    proxyTcpDnsRule =
      optionalString (proxy.enable or false)
      "ip daddr ${proxy.host} tcp dport 53 counter accept comment \"proxy-dns\"";
    # The host's user services (ssh-agent-proxy, sudo-auth-proxy,
    # clipboard-bridge) are reached at the gateway on their fixed ports. On
    # Darwin the gateway is outside the trs subnets accepted below, so a guest
    # that opts into a firewall and uses one of these services would otherwise
    # drop its own connections to the host. VSOCK bypasses IP filtering, so
    # these only matter for TCP (Darwin, containers, disableVsock).
    hostServiceRule = svc: port:
      optionalString (g.services.${svc} or false)
      "ip daddr ${p.gateway} tcp dport ${toString port} counter accept comment \"${svc}\"";
    hostServiceRules = concatStringsSep "\n" [
      (hostServiceRule "sudoAuthProxy" 65001)
      # No port for the `unix` ssh-agent-proxy transport (SSH RemoteForward).
      (optionalString (
          (g.services.sshAgentProxy or false)
          && (((g.services or {}).sshAgentProxyTransport or "vsock") != "unix")
        )
        "ip daddr ${p.gateway} tcp dport 65000 counter accept comment \"sshAgentProxy\"")
      (hostServiceRule "clipboardBridge" 27795)
    ];
    allowEntry = a:
      if lib.hasInfix " " a
      then a
      else "ip saddr ${a} counter accept";
    allowRules = concatMapStringsSep "\n" (rule: allowEntry rule) (fw.allow or []);
  in
    mkIf enable {
      networking.nftables.enable = true;
      networking.nftables.tables.tartarus = {
        family = "inet";
        content = ''
          chain output {
            type filter hook output priority 0; policy drop;

            oifname "lo" counter accept
            ct state established,related counter accept

            udp dport 67 counter accept
            udp dport 68 counter accept
            ip daddr ${p.gateway} udp dport 53 counter accept
            ip daddr ${p.gateway} tcp dport 53 counter accept

            # Proxy and DNS to the proxy host; the whole vm/ctn subnets are
            # already reachable below, but these are explicit in case that changes.
            ${proxyTcpRule}
            ${proxyUdpDnsRule}
            ${proxyTcpDnsRule}
            ${hostServiceRules}
            ${allowRules}

            ip daddr ${ids.vmSubnet} counter accept
            ip daddr ${ids.ctnSubnet} counter accept
          }
        '';
      };
    };
in
  if mode == "guest"
  then guestModule
  else hostModule

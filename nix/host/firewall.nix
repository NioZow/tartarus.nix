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
# accepted as a policy rather than a hard boundary.
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
    hasCtn = instances.container.enabledNames != [];
    anyGuest = hasVm || hasCtn;

    # The guest named by `proxy.location`, when it is a guest. Phase 1 asserts
    # it is an enabled linux VM with internet, so its id exists here.
    targetGuest = guests.${proxyLocation} or null;
    targetKind =
      if targetGuest != null
      then targetGuest.kind
      else null;
    targetId =
      if targetKind == "vm"
      then instances.vm.idByName.${proxyLocation} or null
      else if targetKind == "container"
      then instances.container.idByName.${proxyLocation} or null
      else null;
    targetIp =
      if targetId == null
      then null
      else if targetKind == "vm"
      then ids.mkVmIP targetId
      else ids.mkCtnIP targetId;

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
      ) (instances.${kind}.enabledNames);

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
      enabledNames = instances.${kind}.enabledNames;
      enabledInst = filterAttrs (_: g: g.enable && g.kind == kind) guests;

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
      needsSsh = any (g: g.services.sshAuthProxy && isTcp g) (attrValues enabledInst);
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

      networkDnsRule =
        optionalString (kind == "vm" && enabledInst ? network)
        "ip daddr ${mkIP "network"} udp dport 53 counter accept comment \"network-vm-dns\"\nip daddr ${mkIP "network"} tcp dport 53 counter accept comment \"network-vm-dns\"";

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
          ${networkDnsRule}
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
          # route already covers it, but keeping the /32 makes the cross-kind
          # path self-documenting.
          routes = optional (proxyIsGuest && targetKind == kind) {
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
            instances.container.enabledNames
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

    proxyRule =
      optionalString (proxy.enable or false)
      "ip daddr ${proxy.host} tcp dport ${toString (proxy.port or 3128)} counter accept comment \"proxy\"";
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

            ${proxyRule}
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

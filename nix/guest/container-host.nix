# The container-host VM side of `vm.containerHost`.
#
# Imported into a container host VM's modules only (see `build.nix`), this
# declares the nested systemd-nspawn containers as NixOS `containers.<name>`
# entries, the VM-local inner bridge (`trs2` by default), the NAT that lets
# those containers reach the internet through the VM, and the DNS the
# containers resolve through.
#
# It is a NixOS module *factory*: `{ innerContainers }: { config, ... }: { ... }`
# mirroring `nix/host/firewall.nix`'s `{ mode }: module` pattern. The inner
# records come from `build.mkVm`, already evaluated through the guest engine
# with `inHostVm = true` (see `nix/guest/platform.nix`), so each nested
# container addresses itself on the inner bridge exactly like its top-level
# `ctn-<name>` configuration.
#
# NOTE (P0 gate): the plan's P0 runtime spike (nested nspawn under microvm.nix:
# cgroup-v2 delegation, host-key permissions over virtiofs, persisted state
# across a VM restart) was intentionally skipped. Everything here evaluates,
# but the runtime behaviours are unverified until that spike is run.
{innerContainers ? []}: {
  config,
  lib,
  pkgs,
  tartarusGuest,
  ...
}: let
  inherit
    (lib)
    any
    concatMap
    concatMapStringsSep
    dirOf
    filter
    hasPrefix
    listToAttrs
    map
    nameValuePair
    optional
    optionals
    optionalAttrs
    optionalString
    unique
    ;
  g = tartarusGuest;
  ids = import ../lib/ids.nix {inherit lib;};
  sharePolicy = import ../lib/shares.nix {inherit lib;};

  ch = g.vm.containerHost;

  # The inner network identity. `mkGuest` normalizes `containerHost` for
  # hand-written sample configs, so these are always present; the defaults are
  # the same constants `ids.nix` exposes and `platform.nix` uses to address the
  # inner containers, so bridge/IP/subnet stay consistent by construction.
  bridge = ch.network.bridge;
  hostIP = ch.network.hostIP;
  subnet = ch.network.subnet;
  stateSize = ch.stateVolume.size;

  # Host-service TCP ports the nested containers need forwarded out of the VM.
  # A nested container dials the inner bridge's host IP (`platform.serviceHost`)
  # for these; the DNAT below rewrites that to the VM's own upstream gateway,
  # and the existing masquerade SNATs to the VM's eth0 address, so the macOS
  # host sees the container-host VM. Only the ports some inner container
  # actually requests are opened.
  servicePorts = unique (concatMap (
      inner:
        optional (inner.cfg.services.sudoAuthProxy or false) 65001
        ++ optional (inner.cfg.services.sshAgentProxy or false) 65000
        ++ optional (inner.cfg.services.clipboardBridge or false) 27795
    )
    innerContainers);

  # A nested proxy client (internet = false, proxy.enable = true) dials the
  # inner bridge's host IP for the proxy; DNAT that to the VM gateway too, so
  # the request reaches the host proxy (or the host relay to a guest-hosted
  # proxy). `g.proxy.port` is the resolved global proxy port.
  anyInnerProxy = any (inner: inner.cfg.proxy.enable or false) innerContainers;
  dnatPorts =
    unique (servicePorts
      ++ optional anyInnerProxy g.proxy.port);

  # Nested containers that must not egress directly: their traffic is dropped
  # in `forward` except for the VM gateway (proxy + host services + DNS).
  noInternetInners = filter (inner: !(inner.cfg.internet or true)) innerContainers;
  noInternetRules =
    concatMapStringsSep "\n" (
      inner:
        "ip saddr ${ids.mkInnerIP inner.id} ip daddr ${g.platform.gateway} counter accept comment \"inner-egress-exempt\"\n"
        + "ip saddr ${ids.mkInnerIP inner.id} oifname \"eth0\" counter drop comment \"${inner.name}-no-internet\""
    )
    noInternetInners;

  # Host relays into a nested container are two-hop: the host socat targets
  # this VM (see host/relay.nix), and this VM DNATs the relayed port on to the
  # inner container. One forward per inner relay.
  relayForwards =
    concatMap (
      inner:
        map (r: {
          ip = ids.mkInnerIP inner.id;
          port = r.port;
          targetPort =
            if (r.targetPort or null) != null
            then r.targetPort
            else r.port;
          proto = r.protocol or "tcp";
        })
        (inner.cfg.relays or [])
    )
    innerContainers;
  relayRules =
    concatMapStringsSep "\n" (
      f:
      # Host -> container (the host socat targets this VM's eth0 address).
        "iifname \"eth0\" ${f.proto} dport ${toString f.port} counter dnat ip to ${f.ip}:${toString f.targetPort} comment \"inner-relay-host\"\n"
        # Container -> container, via the VM-local "gateway" name (e.g. a
        # guest's `litellm-proxy` alias resolving to the inner host IP): treat
        # the offering container's relay port as a virtual service on it.
        + "iifname \"${bridge}\" ip daddr ${hostIP} ${f.proto} dport ${toString f.port} counter dnat ip to ${f.ip}:${toString f.targetPort} comment \"inner-relay-service\""
    )
    relayForwards;

  # Where the host's CA-signed inner-container key material is made visible
  # inside the VM by `nix/guest/shares.nix`: ONE share each for the whole
  # `containers/` tree (ssh and x509), holding every inner container's material
  # as `<name>/...`. Apple caps virtio-fs devices at 26, so per-container cert
  # shares are not affordable. `vm.action_start` provisions each inner
  # container's certs before building the VM, so the sources exist at build time.
  certsSsh = name: "/var/lib/tartarus-inner/certs/ssh/${name}";
  certsX509 = name: "/var/lib/tartarus-inner/certs/x509/${name}";
  innerShared = name: "/var/lib/tartarus-inner/shared/${name}";

  # nspawn creates a missing bind-mount parent as root, so the nested
  # container's unprivileged user cannot create e.g. `~/.config/nix` and
  # home-manager activation fails. Reset every home-tree bind parent (and the
  # home itself) to the guest user at boot; tmpfiles `d` fixes the ownership of
  # directories that already exist.
  homeParents = inner: let
    mounts = map (s: s.mountPoint) (inner.cfg.shares or []);
  in
    unique (["/home/user"] ++ map dirOf (filter (p: hasPrefix "/home/user/" p) mounts));
  homeTmpfilesModule = inner: {
    systemd.tmpfiles.rules = map (d: "d ${d} 0755 user user -") (homeParents inner);
  };

  # A read-only inner share on Darwin is materialised into the Nix store
  # (`nix/lib/shares.nix`); the VM already reaches the host store through
  # `ro-store`, so the container can bind the snapshot path directly instead of
  # exporting it as its own virtiofs device. Referencing the path here also
  # forces it to build, so it is present in the store at boot.
  innerSnapshot = s: sharePolicy.storeSnapshot s.tag s.source;
  snapshotDeps =
    concatMap
    (inner: map innerSnapshot (filter (s: sharePolicy.needsStoreSnapshot g.platform s) (inner.cfg.shares or [])))
    innerContainers;

  # The shared MicroVM client key (`~/.ssh/tartarus`) the VM's `user` account
  # already trusts (see base.nix's `pubKeyFile`). The same key authorises root
  # here so the host CLI can manage nested containers over SSH as root without
  # any passwordless-sudo grant.
  rootPubKeyFile = "${g.hostHome}/.ssh/tartarus.pub";

  # nspawn preserves the ownership of a bind-mounted source, and the share
  # arrives owned by the host user (uid 501 / the invoking user) -- sshd
  # refuses a host key it does not own. Copy the material under /run as
  # root:root before the containers start and bind-mount that copy instead.
  stageDir = name: "/run/tartarus-inner/${name}";

  stageScript = pkgs.writeShellScript "tartarus-inner-key-stage" ''
    set -eu
    ${concatMapStringsSep "\n" (inner: ''
        src_ssh=${certsSsh inner.name}
        src_x509=${certsX509 inner.name}
        dst=${stageDir inner.name}
        for _ in $(seq 1 120); do
          [ -e "$src_ssh/ssh_host_ed25519_key" ] && break
          sleep 1
        done
        install -d -m 0755 "$dst/ssh" "$dst/x509"
        cp -f "$src_ssh/ssh_host_ed25519_key" "$dst/ssh/ssh_host_ed25519_key"
        cp -f "$src_ssh/ssh_host_ed25519_key.pub" "$dst/ssh/ssh_host_ed25519_key.pub" || true
        cp -f "$src_ssh/ssh_host_ed25519_key-cert.pub" "$dst/ssh/ssh_host_ed25519_key-cert.pub" || true
        cp -f "$src_x509/." "$dst/x509/" 2>/dev/null || true
        chmod 0600 "$dst/ssh/ssh_host_ed25519_key"
        chmod 0644 "$dst/ssh/"*.pub 2>/dev/null || true
      '')
      innerContainers}
  '';
in {
  # nixos-containers.nix defaults this to `containers != {}`, but a container
  # host must always have container support even if a future refactor moves the
  # declarations elsewhere.
  boot.enableContainers = true;

  # Store-snapshotted inner shares are not exported as virtiofs devices; they
  # are bound from `/nix/store` and so must be built into the host store the VM
  # reads through `ro-store`.
  system.extraDependencies = snapshotDeps;

  # Nested containers share the VM's kernel; the VM must forward and NAT their
  # traffic. (P0: forwarding under nested nspawn is unverified.)
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

  # The VM-local bridge the containers' host-side veths are attached to. This
  # is a normal bridge owned by the VM, never one of the host's trs bridges.
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
        IPv4Forwarding = true;
        ConfigureWithoutCarrier = true;
      };
      linkConfig.RequiredForOnline = "no";
    };
  };

  # Let the VM's sshd resolve the inner containers' ProxyJump targets
  # (`ssh -J <host>.trs user@<inner>`), and the containers themselves resolve
  # each other by `<name>.trs`.
  networking.hosts = listToAttrs (
    map (inner: nameValuePair (ids.mkInnerIP inner.id) [inner.name "${inner.name}.trs"]) innerContainers
  );

  # NAT inner-container traffic out of the VM (the VM's own egress is already
  # provided by the host platform: trs0 on Linux, vmnet-shared on Darwin).
  networking.nftables.enable = true;
  networking.nftables.tables =
    {
      tartarus_inner = {
        family = "inet";
        content = ''
          ${optionalString (dnatPorts != [] || relayForwards != []) ''
            chain prerouting {
              type nat hook prerouting priority dstnat; policy accept;

              ${optionalString (dnatPorts != []) ''
              iifname "${bridge}" ip daddr ${hostIP} tcp dport { ${concatMapStringsSep ", " toString dnatPorts} } counter dnat ip to ${g.platform.gateway} comment "inner-host-services"
            ''}
              ${relayRules}
            }
          ''}
          chain postrouting {
            type nat hook postrouting priority srcnat; policy accept;

            ip saddr ${subnet} oifname != "${bridge}" counter masquerade comment "inner-masq"
          }
        '';
      };
    }
    // optionalAttrs (noInternetInners != []) {
      tartarus_inner_filter = {
        family = "inet";
        content = ''
          chain forward {
            type filter hook forward priority 0; policy accept;

            ct state established,related counter accept
            ${noInternetRules}
          }
        '';
      };
    };

  # A minimal resolver the inner containers can use: listen on the inner bridge
  # and forward to the VM's own upstream gateway. `resolveLocalQueries = false`
  # keeps the VM's own DNS unchanged (network.nix points it at the gateway).
  services.dnsmasq = {
    enable = true;
    resolveLocalQueries = false;
    settings = {
      port = 53;
      listen-address = [hostIP];
      # Bind when the address appears rather than requiring the bridge to be up
      # at dnsmasq start; the bridge is created by systemd-networkd.
      bind-dynamic = true;
      server = [g.platform.gateway];
      no-resolv = true;
    };
  };

  # One declarative container per inner guest. The bind model (hostBridge +
  # privateNetwork) is used deliberately: each container's veth host side joins
  # the shared inner bridge, and the container configures its own static eth0
  # address/gateway (see network.nix + platform.nix `inHostVm`). Setting a
  # per-container `localAddress`/`hostAddress` instead would make every
  # container claim the same host address.
  containers = listToAttrs (
    map (
      inner:
        nameValuePair inner.name {
          # Only the inner containers that asked for it autostart, driven by
          # each guest's own `tartarus.guests.<name>.autostart`. The
          # container-host VM still boots when any inner container (or the VM
          # itself) requests autostart -- see the escalation in
          # `nix/host/instances.nix` -- but the remaining nested containers
          # stay down until `tartarus --container start <name>`.
          autoStart = inner.cfg.autostart or false;
          # State persists on the /var/lib/nixos-containers volume below.
          ephemeral = false;
          privateNetwork = true;
          hostBridge = bridge;

          # `config` is a single NixOS module, not a list: nixos-containers.nix
          # appends the definition values to the eval-config module list, and
          # the module system rejects a list *element* ("module imports can't
          # be nested lists"). Wrapping the guest's modules in `imports` is the
          # supported form. The extra module resets home bind-parent ownership
          # so home-manager can activate (see homeTmpfilesModule).
          config = {imports = inner.modules ++ [(homeTmpfilesModule inner)];};
          specialArgs = inner.specialArgs;

          # The host's CA-signed host key and mTLS client cert reach the VM via
          # shares.nix; the stage service copies them root-owned under /run and
          # these read-only binds expose that copy. `/run/tartarus` covers the
          # host-key path a MicroVM uses, `/etc/tartarus/*` the container path
          # base.nix reads in place.
          bindMounts =
            {
              "/etc/tartarus/ssh" = {
                hostPath = "${stageDir inner.name}/ssh";
                isReadOnly = true;
              };
              "/etc/tartarus/x509" = {
                hostPath = "${stageDir inner.name}/x509";
                isReadOnly = true;
              };
              "/run/tartarus" = {
                hostPath = "${stageDir inner.name}/ssh";
                isReadOnly = true;
              };
            }
            # The inner container's user shares and `~/shared`. A share whose
            # source is store-snapshotted is bound straight from `/nix/store`
            # (visible via the VM's ro-store, no device needed); the rest come
            # from the VM path `nix/guest/shares.nix` mounts under the
            # container's inner directory. Either way, read-only stays read-only
            # at the container's own mount point.
            // listToAttrs (map (s:
              nameValuePair s.mountPoint (
                if sharePolicy.needsStoreSnapshot g.platform s
                then {
                  hostPath = innerSnapshot s;
                  isReadOnly = true;
                }
                else {
                  hostPath = "/var/lib/tartarus-inner/${inner.name}/shares/${s.tag}";
                  isReadOnly = s.readOnly or false;
                }
              ))
            (inner.cfg.shares or []))
            // optionalAttrs (inner.cfg.sharedFolder or false) {
              "/home/user/shared" = {
                hostPath = innerShared inner.name;
                isReadOnly = false;
              };
            };
        }
    )
    innerContainers
  );

  # Root SSH for the container-host VM. The host CLI drives a nested container's
  # own systemd unit over SSH (`tartarus --container start/stop/restart <name>`
  # runs `ssh root@<vm> systemctl ... container@<name>`), so root must log in
  # key-only. The same shared MicroVM client key the login user trusts also
  # authorises root, and `prohibit-password` allows public-key root login while
  # still refusing passwords (globally off anyway). Only container-host VMs get
  # this; every other guest keeps base.nix's `PermitRootLogin = "no"`.
  users.users.root.openssh.authorizedKeys.keys =
    optionals (builtins.pathExists rootPubKeyFile) [(builtins.readFile rootPubKeyFile)];
  services.openssh.settings.PermitRootLogin = lib.mkForce "prohibit-password";

  # Root-owned staging of each inner container's key material, ordered before
  # the container so the read-only binds above have a root-owned source when
  # nspawn mounts them.
  systemd.services.tartarus-inner-key-stage = lib.mkIf (innerContainers != []) {
    description = "Stage nested-container CA key material root-owned";
    wantedBy = map (inner: "container@${inner.name}.service") innerContainers;
    before = map (inner: "container@${inner.name}.service") innerContainers;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = stageScript;
    };
  };

  # Container root filesystems and logs persist in the VM's state dir and
  # survive VM restarts (mirrors `home.img`/`nix-store-overlay.img`). The image
  # size is `vm.containerHost.stateVolume.size`.
  microvm.volumes = [
    {
      image = "nixos-containers.img";
      mountPoint = "/var/lib/nixos-containers";
      size = stateSize;
    }
  ];
}

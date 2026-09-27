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
    listToAttrs
    map
    nameValuePair
    ;
  g = tartarusGuest;
  ids = import ../lib/ids.nix {inherit lib;};

  ch = g.vm.containerHost;

  # The inner network identity. `mkGuest` normalizes `containerHost` for
  # hand-written sample configs, so these are always present; the defaults are
  # the same constants `ids.nix` exposes and `platform.nix` uses to address the
  # inner containers, so bridge/IP/subnet stay consistent by construction.
  bridge = ch.network.bridge;
  hostIP = ch.network.hostIP;
  subnet = ch.network.subnet;
  stateSize = ch.stateVolume.size;

  # Where the host's CA-signed inner-container key material is made visible
  # inside the VM by `nix/guest/shares.nix` (one virtiofs/9p share per inner
  # container). `vm.action_start` provisions each inner container's certs
  # before building the VM, so the bind-mount sources exist at build time.
  innerKeyDir = name: "/var/lib/tartarus-inner/${name}";
in {
  # nixos-containers.nix defaults this to `containers != {}`, but a container
  # host must always have container support even if a future refactor moves the
  # declarations elsewhere.
  boot.enableContainers = true;

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
  networking.nftables.tables.tartarus_inner = {
    family = "inet";
    content = ''
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        ip saddr ${subnet} oifname != "${bridge}" counter masquerade comment "inner-masq"
      }
    '';
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
          autoStart = true;
          # State persists on the /var/lib/nixos-containers volume below.
          ephemeral = false;
          privateNetwork = true;
          hostBridge = bridge;

          # `config` is a single NixOS module, not a list: nixos-containers.nix
          # appends the definition values to the eval-config module list, and
          # the module system rejects a list *element* ("module imports can't
          # be nested lists"). Wrapping the guest's modules in `imports` is the
          # supported form.
          config = {imports = inner.modules;};
          specialArgs = inner.specialArgs;

          # The host's CA-signed host key and mTLS client cert reach the VM via
          # shares.nix and are bind-mounted read-only into the container, where
          # base.nix reads /etc/tartarus/ssh in place. (P0: readability of the
          # virtiofs-backed key files inside nested nspawn is unverified.)
          bindMounts = {
            "/etc/tartarus/ssh" = {
              hostPath = "${innerKeyDir inner.name}/ssh";
              isReadOnly = true;
            };
            "/etc/tartarus/x509" = {
              hostPath = "${innerKeyDir inner.name}/x509";
              isReadOnly = true;
            };
          };
        }
    )
    innerContainers
  );

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

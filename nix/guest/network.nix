# Guest networking: the static address, gateway/DNS and the VSOCK sshd socket.
# All platform choices come from `tartarusGuest.platform` (see ./platform.nix);
# the address formulas come from ../../lib/ids.nix.
{
  lib,
  tartarusGuest,
  ...
}: let
  inherit (lib) mkIf;
  g = tartarusGuest;
  p = g.platform;
in {
  networking.hostName = lib.mkDefault g.name;

  # Guests resolve against the host, which is also the only DNS server they can
  # reach (the internal host services use `*.trs`). systemd-resolved is not used.
  services.resolved.enable = false;
  networking.nameservers = [p.gateway];
  networking.search = ["trs"];

  # Every guest reaches the *physical host* through the stable `host` alias
  # (and `host.trs`, matching the internal suffix). This is the address where
  # host-side relays live: the bridge gateway for a VM or native container,
  # the vmnet gateway on Darwin, and -- from inside a nested container -- the
  # container-host VM's upstream gateway, since the container's own gateway
  # (`10.202.0.1`) only NATs outward. Use `host:<relay port>` to reach a guest
  # port that its `relays` declaration exposes.
  networking.hosts = {
    ${p.hostGateway} = ["host" "host.trs"];
  };

  # The host (or, on Darwin, vmnet) enforces egress; the in-guest NixOS
  # firewall stays off.
  networking.firewall.enable = false;

  systemd.network = mkIf g.isVm {
    enable = true;
    # eth0 is forced by the `net.ifnames=0` kernel param in build.nix.
    networks."10-eth0" = {
      matchConfig.Name = "eth0";
      networkConfig = {
        Address = "${p.guestIP}/24";
        Gateway = p.gateway;
        DNS = p.gateway;
      };
    };
  };

  # nixos-container's own container-init assigns the address imperatively
  # before the guest's init runs; this only declares the same address so the
  # guest's networking options agree with it.
  networking.useDHCP = mkIf (!g.isVm) false;
  networking.interfaces.eth0.ipv4.addresses = mkIf (!g.isVm) [
    {
      address = p.guestIP;
      prefixLength = 24;
    }
  ];

  # A container is attached to its host bridge (the VM-local `trs2` when nested,
  # the host `trs1` when native) with `privateNetwork = true`, and the host end
  # of the veth carries the bridge's host IP. nixos-container only installs a
  # default route in the `hostAddress`/`localAddress` (point-to-point) model, so
  # both container flavours need the route declared here to reach beyond their
  # /24 (the resolver/proxy, and the internet through the host's NAT).
  networking.defaultGateway = mkIf (!g.isVm) {
    address = p.gateway;
    interface = "eth0";
  };

  # VSOCK is Linux-VM-only. The guest sshd additionally listens on it so the
  # host can reach it without TCP when VSOCK is available.
  systemd.sockets.sshd-vsock = mkIf p.vsockAvailable {
    wantedBy = ["sockets.target"];
    listenStreams = ["" "vsock::22"];
  };
}

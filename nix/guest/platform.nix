# The single source of truth for Linux-vs-Darwin guest behaviour.
#
# This is a pure helper (not a NixOS module) used by the engine (`build.nix`)
# and handed to every guest module through `tartarusGuest.platform`. It encodes
# the platform split described in PLAN.md §3.6:
#
#   Linux host    QEMU/KVM, trs0/trs1 bridges, static IPs, VSOCK available.
#   Darwin host   vfkit, vmnet-shared NAT (192.168.64.0/24), no VSOCK, TCP.
#
# `disableVsock`, the service transport/host, the guest proxy target and
# `NO_PROXY` are all derived here so the formulas live in exactly one place.
{lib}: let
  ids = import ../lib/ids.nix {inherit lib;};
in {
  mk = {
    hostSystem,
    kind,
    id,
    # Per-guest override from `services.disableVsock`; meaningless where VSOCK
    # does not exist (Darwin always, containers always).
    disableVsock ? false,
    # Resolved by the caller (the host's `tartarus.proxy.*`); when null the
    # guest-side proxy target falls back to the host gateway for its kind.
    proxyHost ? null,
    proxyPort ? 3128,
  }: let
    isDarwin = lib.hasSuffix "-darwin" hostSystem;
    isLinux = !isDarwin;
    isVm = kind == "vm";

    vsockAvailable = isLinux && isVm;
    useVsock = vsockAvailable && !disableVsock;

    hostIP =
      if isVm
      then ids.vmHostIP
      else ids.ctnHostIP;
    subnet =
      if isVm
      then ids.vmSubnet
      else ids.ctnSubnet;

    # DHCP is broken under vfkit, so Darwin VMs get deterministic static
    # addresses in the upper half of the vmnet-shared subnet (id + 42).
    guestIP =
      if isVm
      then
        (
          if isDarwin
          then ids.mkVmIPNat id
          else ids.mkVmIP id
        )
      else ids.mkCtnIP id;

    gateway =
      if isDarwin
      then ids.darwinGateway
      else hostIP;

    # Guest -> host service address when falling back to TCP: VSOCK CID 2 when
    # VSOCK is in use, the vmnet gateway on Darwin (loopback is unreachable from
    # a vmnet-shared guest), otherwise the bridge's host IP.
    serviceHost =
      if useVsock
      then "2"
      else if isDarwin
      then "_gateway"
      else hostIP;

    # Where a guest sends proxy requests when the proxy runs on the host. On
    # Darwin that is the vmnet gateway, never loopback.
    hostProxyIP =
      if isDarwin
      then ids.darwinGateway
      else hostIP;

    # Addresses the proxy may bind. Phase 5 consumes this; the proxy never
    # binds loopback.
    proxyBind =
      if isDarwin
      then [ids.darwinGateway]
      else [ids.vmHostIP ids.ctnHostIP];

    # Internal host services and the proxy itself must bypass the proxy. The
    # subnets cover every kind even when only one is in use -- harmless, and it
    # keeps the file identical across guests.
    noProxy = [
      ids.vmSubnet
      ids.ctnSubnet
      ids.vmHostIP
      ids.ctnHostIP
      ids.darwinGateway
      "localhost"
      "127.0.0.1"
      ".trs"
    ];
  in {
    inherit
      isDarwin
      isLinux
      isVm
      vsockAvailable
      useVsock
      hostIP
      subnet
      guestIP
      gateway
      serviceHost
      hostProxyIP
      proxyBind
      noProxy
      proxyPort
      ;

    hypervisor =
      if isDarwin
      then "vfkit"
      else "qemu";
    bridge =
      if isVm
      then ids.vmBridge
      else ids.ctnBridge;
    # VSOCK CID equal to the guest id; null when VSOCK is unavailable, which
    # microvm.nix maps to "omit the device".
    vsockCid =
      if vsockAvailable
      then id
      else null;
    # vfkit rejects non-virtiofs shares outright; Linux keeps 9p (its writable
    # shares get the `mapped` security model in shares.nix).
    shareProto =
      if isDarwin
      then "virtiofs"
      else "9p";
    resolvedProxyHost =
      if proxyHost != null
      then proxyHost
      else hostProxyIP;
  };
}

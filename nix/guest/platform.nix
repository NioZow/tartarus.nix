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
    # True for a `kind = "container"` guest that runs *nested* inside a
    # container-host VM (its `host` points at a VM). The inner container lives
    # on the VM's own bridge/subnet, independently of the host platform, so it
    # addresses itself as Linux-inner no matter whether the eval host is Darwin
    # or Linux. Everything else keeps the plain-kind formulas.
    inHostVm ? false,
    # Per-guest override from `services.disableVsock`; meaningless where VSOCK
    # does not exist (Darwin always, containers always).
    disableVsock ? false,
    # Resolved by the caller (the host's `tartarus.proxy.*`); when null the
    # guest-side proxy target falls back to the host gateway for its kind.
    proxyHost ? null,
    proxyPort ? 3128,
  }: let
    # An inner container never uses the host's Linux/Darwin split: it is always
    # Linux-inner (no vsock, the VM-local bridge, nested addressing).
    isDarwin = !inHostVm && lib.hasSuffix "-darwin" hostSystem;
    isLinux = !isDarwin;
    isVm = kind == "vm";

    vsockAvailable = !inHostVm && isLinux && isVm;
    useVsock = vsockAvailable && !disableVsock;

    # Darwin guests live on vfkit's vmnet-shared NAT, not the Linux trs
    # bridges, so both the host address and the subnet differ from the
    # kind-based defaults. Only the IP formula used to be Darwin-aware; the
    # subnet was not, which made the "network" guest's Unbound ACL allow
    # 10.200.0.0/24 while the host actually queried from 192.168.64.1
    # (REFUSED).
    hostIP =
      if inHostVm
      then ids.innerHostIP
      else if isDarwin
      then ids.darwinGateway
      else if isVm
      then ids.vmHostIP
      else ids.ctnHostIP;
    subnet =
      if inHostVm
      then ids.innerSubnet
      else if isDarwin
      then ids.darwinSubnet
      else if isVm
      then ids.vmSubnet
      else ids.ctnSubnet;

    # DHCP is broken under vfkit, so Darwin VMs get deterministic static
    # addresses in the upper half of the vmnet-shared subnet (id + 42). An
    # inner container gets its id-derived address on the VM's inner bridge.
    guestIP =
      if inHostVm
      then ids.mkInnerIP id
      else if isVm
      then
        (
          if isDarwin
          then ids.mkVmIPNat id
          else ids.mkVmIP id
        )
      else ids.mkCtnIP id;

    gateway =
      if inHostVm
      then ids.innerHostIP
      else if isDarwin
      then ids.darwinGateway
      else hostIP;

    # The address that reaches the *physical host* from this guest -- where
    # host-side services (the proxy, host relays such as `litellm-proxy`) live.
    # For a VM (or a native Linux container) that is simply its own gateway. A
    # nested container's own gateway is the container-host VM's inner bridge,
    # which only NATs outward, so the host is reached at *that VM's* gateway
    # instead. The host VM is always a VM, so its gateway is the platform
    # default for `kind = "vm"` on the eval host.
    hostGateway =
      if !inHostVm
      then gateway
      else if lib.hasSuffix "-darwin" hostSystem
      then ids.darwinGateway
      else ids.vmHostIP;

    # Guest -> host service address when falling back to TCP: VSOCK CID 2 when
    # VSOCK is in use, the vmnet gateway on Darwin (loopback is unreachable from
    # a vmnet-shared guest), otherwise the bridge's host IP. For an inner
    # container that is the container host's inner-bridge IP.
    serviceHost =
      if useVsock
      then "2"
      else if inHostVm
      then ids.innerHostIP
      else if isDarwin
      then "_gateway"
      else hostIP;

    # Where a guest sends proxy requests when the proxy runs on the host. On
    # Darwin that is the vmnet gateway, never loopback. An inner container
    # reaches a VM-hosted proxy at the inner bridge's host IP.
    hostProxyIP =
      if inHostVm
      then ids.innerHostIP
      else if isDarwin
      then ids.darwinGateway
      else hostIP;

    # Addresses the proxy may bind. Phase 5 consumes this; the proxy never
    # binds loopback.
    proxyBind =
      if inHostVm
      then [ids.innerHostIP]
      else if isDarwin
      then [ids.darwinGateway]
      else [ids.vmHostIP ids.ctnHostIP];

    # Internal host services and the proxy itself must bypass the proxy. The
    # subnets cover every kind even when only one is in use -- harmless, and it
    # keeps the file identical across guests. Inner containers additionally
    # bypass the VM-local inner bridge/subnet.
    noProxy =
      [
        ids.vmSubnet
        ids.ctnSubnet
        ids.vmHostIP
        ids.ctnHostIP
        ids.darwinGateway
        "localhost"
        "127.0.0.1"
        ".trs"
      ]
      ++ lib.optionals inHostVm [ids.innerSubnet ids.innerHostIP];
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
      hostGateway
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
      if inHostVm
      then ids.innerBridge
      else if isVm
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

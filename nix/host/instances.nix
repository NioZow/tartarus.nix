# Derived, internal guest data consumed by the later host modules (ca, ssh,
# firewall, proxy, launcher, autostart). One subtree per kind keeps ids scoped
# per kind, matching the id-assignment invariant.
#
# This module is also the one place that forces the `tartarus.guests` submodule
# values. Modules that define "heavy" nixpkgs options (`systemd`, `networking.
# nftables`, ...) must read the plain data here rather than `config.tartarus.
# guests` directly: forcing the submodule from within those modules trips
# nixpkgs' `_module.args` recursion.
{
  config,
  lib,
  ...
} @ args: let
  inherit
    (lib)
    filterAttrs
    mkOption
    types
    ;
  ids = import ../lib/ids.nix {inherit lib;};

  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);

  enabledOfKind = kind:
    filterAttrs (_: guest: guest.enable && guest.kind == kind) config.tartarus.guests;

  mkKindOptions = kind: {
    enabledNames = mkOption {
      type = types.listOf types.str;
      internal = true;
      default = [];
      description = "Names of enabled `${kind}` guests, in stable (sorted) order.";
    };
    idByName = mkOption {
      type = types.attrsOf types.ints.positive;
      internal = true;
      default = {};
      description = "Effective ID of every enabled `${kind}` guest (forced or auto-assigned).";
    };
    bridge = mkOption {
      type = types.str;
      internal = true;
      default =
        if kind == "vm"
        then ids.vmBridge
        else ids.ctnBridge;
      description = "Host bridge interface for `${kind}` guests.";
    };
    subnet = mkOption {
      type = types.str;
      internal = true;
      default =
        if kind == "vm"
        then ids.vmSubnet
        else ids.ctnSubnet;
      description = "Subnet for `${kind}` guests.";
    };
    hostIP = mkOption {
      type = types.str;
      internal = true;
      default =
        if kind == "vm"
        then ids.vmHostIP
        else ids.ctnHostIP;
      description = "Host IP on the `${kind}` bridge.";
    };
  };

  vmEnabled = enabledOfKind "vm";
  ctnEnabled = enabledOfKind "container";
  # A container is host-side present only when it is *not* nested inside a
  # container-host VM (`host == null`). Nested containers live on the VM-local
  # `trs2` bridge and must get no host bridge, nftables table, `/etc/hosts`
  # entry, relay or service wiring -- the invariant every host module filters
  # on. `enabledNames`/`idByName` stay the full container set so id assignment
  # and config.toml rendering still include nested containers.
  ctnHostSide = filterAttrs (_: g: (g.host or null) == null) ctnEnabled;
  vmIds = ids.assignIds vmEnabled;
  ctnIds = ids.assignIds ctnEnabled;

  guestIP = name: g: let
    id =
      if g.kind == "vm"
      then vmIds.${name}
      else ctnIds.${name};
  in
    if g.kind == "vm"
    then
      (
        if isDarwin
        then ids.mkVmIPNat id
        else ids.mkVmIP id
      )
    else if (g.host or null) != null
    then
      # Nested container: the address on its container-host VM's inner bridge
      # (`trs2`), never the host container bridge (`trs1`).
      ids.mkInnerIP id
    else ids.mkCtnIP id;

  # Plain (non-submodule) view of every enabled guest. Downstream modules read
  # this and never touch `config.tartarus.guests` themselves.
  detail = name: g: {
    inherit name;
    kind = g.kind;
    enable = g.enable;
    id =
      if g.kind == "vm"
      then vmIds.${name}
      else ctnIds.${name};
    ip = guestIP name g;
    internet = g.internet;
    autostart = g.autostart;
    graphical = g.graphical;
    sharedFolder = g.sharedFolder;
    apps = g.apps;
    services = g.services;
    firewall = g.firewall;
    proxy = g.proxy;
    relays = g.relays;
    requires = g.requires;
    host = g.host or null;
    containerHost = g.vm.containerHost.enable or false;
  };

  details = lib.mapAttrs detail (vmEnabled // ctnEnabled);

  # Autostart records. Starting a container-host VM starts its nested
  # containers (P2 declares them with `autoStart = true` inside the VM), so a
  # nested container's `autostart = true` becomes an autostart request for its
  # *host VM*, never for the container itself. Dedupe by name (via the keyed
  # attrset) so a host VM that also sets `autostart = true` yields exactly one
  # unit, and sorting is preserved.
  autostartOf = g:
    if g.kind == "container" && (g.host or null) != null && details ? ${g.host}
    then details.${g.host}
    else g;
  autostartRecords =
    builtins.attrValues
    (builtins.listToAttrs (builtins.map (g: {
      name = g.name;
      value = g;
    }) (map autostartOf (builtins.filter (g: g.autostart) (builtins.attrValues details)))));
in {
  options.tartarus.instances = {
    vm = mkKindOptions "vm";
    container =
      mkKindOptions "container"
      // {
        hostSideNames = mkOption {
          type = types.listOf types.str;
          internal = true;
          default = [];
          description = "Names of enabled container guests with host-side presence (`host == null`), in stable (sorted) order. Nested containers run inside a container-host VM and are excluded.";
        };
      };
    enabledSubnets = mkOption {
      type = types.listOf types.str;
      internal = true;
      default = [];
      description = "Subnets of the guest kinds that have at least one host-side enabled guest.";
    };
    guests = mkOption {
      type = types.attrsOf types.unspecified;
      internal = true;
      default = {};
      description = "Plain per-guest data for every enabled guest, keyed by name.";
    };
    autostart = mkOption {
      type = types.listOf types.unspecified;
      internal = true;
      default = [];
      description = "Autostart records: guests with `autostart = true`, with each nested container replaced by its container-host VM (and deduped by name).";
    };
    proxyClients = mkOption {
      type = types.listOf types.unspecified;
      internal = true;
      default = [];
      description = "Enabled guests with `proxy.enable = true`, as plain records.";
    };
  };

  config.tartarus.instances = {
    vm = {
      enabledNames = builtins.attrNames vmEnabled;
      idByName = vmIds;
    };
    container = {
      enabledNames = builtins.attrNames ctnEnabled;
      idByName = ctnIds;
      hostSideNames = builtins.attrNames ctnHostSide;
    };
    # The container subnet is a *host* bridge subnet: only advertise it when a
    # host-side container actually sits on it. Nested containers use the VM's
    # inner `trs2` subnet, which the host never routes.
    enabledSubnets =
      lib.optional (vmEnabled != {}) ids.vmSubnet
      ++ lib.optional (ctnHostSide != {}) ids.ctnSubnet;

    guests = details;
    autostart = autostartRecords;
    proxyClients = builtins.filter (g: g.proxy.enable) (builtins.attrValues details);
  };
}

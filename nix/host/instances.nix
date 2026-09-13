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
    requires = g.requires;
  };

  details = lib.mapAttrs detail (vmEnabled // ctnEnabled);
in {
  options.tartarus.instances = {
    vm = mkKindOptions "vm";
    container = mkKindOptions "container";
    enabledSubnets = mkOption {
      type = types.listOf types.str;
      internal = true;
      default = [];
      description = "Subnets of the guest kinds that have at least one enabled guest.";
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
      description = "Enabled guests with `autostart = true`, as plain records.";
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
    };
    enabledSubnets =
      lib.optional (vmEnabled != {}) ids.vmSubnet
      ++ lib.optional (ctnEnabled != {}) ids.ctnSubnet;

    guests = details;
    autostart = builtins.filter (g: g.autostart) (builtins.attrValues details);
    proxyClients = builtins.filter (g: g.proxy.enable) (builtins.attrValues details);
  };
}

# Pure, stable id -> address/MAC/CID derivation. Every consumer of a guest's
# network identity imports these functions so the formulas live in exactly one
# place. `assignIds` mirrors the old host module's `mkIdAssignment`: forced ids
# are honored verbatim, everything else is auto-assigned from 101.
{lib}: let
  inherit
    (lib)
    fixedWidthString
    nameValuePair
    toHexString
    ;

  vmBridge = "trs0";
  vmSubnet = "10.200.0.0/24";
  vmHostIP = "10.200.0.1";

  ctnBridge = "trs1";
  ctnSubnet = "10.201.0.0/24";
  ctnHostIP = "10.201.0.1";

  # vfkit on macOS uses vmnet-shared (192.168.64.0/24) with a host gateway.
  darwinGateway = "192.168.64.1";
  darwinSubnet = "192.168.64.0/24";

  mkVmIP = id: "10.200.0.${toString id}";

  # DHCP is broken under vfkit, so Darwin guests get deterministic static IPs.
  # +42 keeps them above the leases macOS hands out in the lower range.
  mkVmIPNat = id: "192.168.64.${toString (id + 42)}";

  mkCtnIP = id: "10.201.0.${toString id}";

  mkMac = id: "02:00:00:00:00:${fixedWidthString 2 "0" (toHexString id)}";

  # The VSOCK context ID is just the guest id on Linux.
  mkCid = id: id;

  # Forced ids are honored as-is; remaining instances are auto-assigned from
  # 101, skipping forced ids and earlier auto ids. Auto names are sorted so the
  # assignment is stable across builds, and a forced id below 101 never shifts
  # another guest.
  assignIds = instances: let
    forced = lib.filterAttrs (_: cfg: cfg.id != null) instances;
    forcedIds = lib.mapAttrsToList (_: cfg: cfg.id) forced;

    auto = lib.filterAttrs (_: cfg: cfg.id == null) instances;
    sortedAuto = lib.sort (a: b: a < b) (builtins.attrNames auto);

    nextFree = start: used:
      if lib.elem start used
      then nextFree (start + 1) used
      else start;

    autoIds = lib.listToAttrs (
      lib.foldl' (acc: name: let
        used = forcedIds ++ lib.attrValues (lib.listToAttrs acc);
        id = nextFree 101 used;
      in
        acc ++ [(nameValuePair name id)]) []
      sortedAuto
    );
  in
    autoIds // lib.mapAttrs (_: cfg: cfg.id) forced;
in {
  inherit
    vmBridge
    vmSubnet
    vmHostIP
    ctnBridge
    ctnSubnet
    ctnHostIP
    darwinGateway
    darwinSubnet
    mkVmIP
    mkVmIPNat
    mkCtnIP
    mkMac
    mkCid
    assignIds
    ;
}

{
  inputs,
  self,
}: {
  config,
  lib,
  pkgs,
  ...
} @ args: let
  inherit
    (lib)
    all
    attrValues
    concatLists
    concatMapStringsSep
    count
    filter
    filterAttrs
    length
    mapAttrsToList
    mkOption
    types
    unique
    ;

  # Platform from the consumer's `system` specialArg, never `pkgs` (forcing
  # `pkgs.stdenv` while reading a tartarus option trips nixpkgs' `_module.args`
  # recursion; see nix/host/firewall.nix).
  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);
  isLinux = !isDarwin;
  guests = config.tartarus.instances.guests;

  # The tartarus CLI, taken from this flake's own package outputs (built with
  # tartarus's own nixpkgs) so the host module never has to evaluate the
  # consumer's `pkgs` mid-config.
  tartarusPkg = self.packages.${args.system or builtins.currentSystem}.tartarus;

  dupes = ids: unique (filter (id: count (x: x == id) ids > 1) ids);
  fmt = xs: concatMapStringsSep ", " toString xs;

  guestAssertions = concatLists (mapAttrsToList (name: guest: [
      {
        assertion = !(guest.internet && guest.proxy.enable);
        message = "tartarus: guest '${name}' sets both `internet = true` and `proxy.enable = true`; they are mutually exclusive (a proxy-only guest has no direct egress).";
      }
      {
        assertion = !(guest.proxy.enable && !config.tartarus.proxy.enable);
        message = "tartarus: guest '${name}' sets `proxy.enable = true` but the global `tartarus.proxy.enable` is false.";
      }
      {
        assertion = !(isDarwin && guest.firewall.location == "host");
        message = "tartarus: guest '${name}' sets `firewall.location = \"host\"` on Darwin; host firewalling is Linux-only, use \"guest\".";
      }
    ])
    guests);

  # A guest-hosted proxy must be a reachable egress point: an enabled VM with
  # internet. Darwin has no guest-to-guest routing under vmnet-shared.
  proxyLocationAssertion = let
    location = config.tartarus.proxy.location;
    namedGuest = guests.${location} or null;
    guestOk =
      namedGuest
      != null
      && namedGuest.enable
      && namedGuest.kind == "vm"
      && namedGuest.internet;
  in {
    assertion = location == "host" || (isLinux && guestOk);
    message =
      if isDarwin
      then "tartarus: `tartarus.proxy.location = \"${location}\"` is invalid on Darwin; the proxy must run on the host (`\"host\"`)."
      else "tartarus: `tartarus.proxy.location = \"${location}\"` must be \"host\" or name an enabled `kind = \"vm\"` guest with `internet = true`.";
  };

  mkIdAssertions = kind: let
    enabled = filterAttrs (_: guest: guest.enable && guest.kind == kind) guests;
    staticIds = mapAttrsToList (_: guest: guest.id) (filterAttrs (_: guest: guest.id != null) enabled);
    effectiveIds = attrValues config.tartarus.instances.${kind}.idByName;
  in [
    {
      assertion = all (id: id <= 100) staticIds;
      message = "tartarus: static `${kind}` ids must be in 3-100 (auto-assignment starts at 101); out of range: ${fmt (filter (id: id > 100) staticIds)}.";
    }
    {
      assertion = length staticIds == length (unique staticIds);
      message = "tartarus: duplicate static `${kind}` id(s): ${fmt (dupes staticIds)}. Static ids must be unique within a kind.";
    }
    {
      assertion = length effectiveIds == length (unique effectiveIds);
      message = "tartarus: effective `${kind}` ids collide: ${fmt (dupes effectiveIds)}. Check duplicate static ids.";
    }
  ];

  # The full tartarus assertion list. Exposed read-only under an internal
  # option so the eval-level test suite can inspect *these* predicates without
  # tripping over unrelated nixpkgs assertions (see tests/suite.nix).
  tartarusAssertions =
    guestAssertions
    ++ [proxyLocationAssertion]
    ++ mkIdAssertions "vm"
    ++ mkIdAssertions "container";
in {
  imports =
    [
      ./options.nix
      ./instances.nix
      ./config.nix
      (import ./ca.nix {inherit inputs;})
      (import ./firewall.nix {})
      (import ./proxy.nix {inherit inputs;})
      (import ./launcher.nix {inherit inputs tartarusPkg;})
      (import ./ssh.nix {inherit inputs;})
      (import ./autostart.nix {inherit inputs tartarusPkg;})
      (import ./services.nix {inherit inputs;})
    ]
    # `nix.linux-builder` is a nix-darwin-only option, so this module must not
    # even be imported on NixOS (a `mkIf false` definition would still require
    # the option to exist).
    ++ lib.optionals isDarwin [./linux-builder.nix];

  options.tartarus.internalAssertions = mkOption {
    type = types.listOf types.unspecified;
    internal = true;
    readOnly = true;
    default = tartarusAssertions;
    description = "Internal: the tartarus-owned assertions, for the test suite.";
  };

  config.assertions = tartarusAssertions;
}

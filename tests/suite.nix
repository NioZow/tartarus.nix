# Eval-level test suite for tartarus (PLAN.md Phase 8).
#
# Pure evaluation only: no VM boots, no KVM, no network, no builds. Every check
# is exercised through the same code paths a consumer hits:
#
#   * `nix/lib/ids.nix` / `nix/lib/names.nix` / `nix/guest/platform.nix` directly;
#   * the host `tartarus.*` module through `lib.nixosSystem`, reading
#     `config.assertions` and the rendered `networking.nftables.tables`;
#   * the Squid renderer (`nix/host/proxy.nix` `mode = "squidConfig"`) directly;
#   * `tartarus.lib.mkGuests` for output names/ids and the generated
#     `environment.d` proxy variables.
#
# This file is a pure function so it can serve both entry points:
#   * `tests/default.nix` (standalone `nix eval --impure`), and
#   * the flake's `checks.<system>` output (see `nix/default.nix`).
{
  inputs,
  self,
}: let
  lib = inputs.nixpkgs.lib;
  inherit
    (lib)
    all
    attrNames
    concatStringsSep
    filter
    hasInfix
    hasPrefix
    hasSuffix
    head
    splitString
    ;

  evalSystem = "x86_64-linux";
  pkgs = import inputs.nixpkgs {
    system = evalSystem;
    config.allowUnfree = true;
  };

  ids = import ../nix/lib/ids.nix {inherit lib;};
  names = import ../nix/lib/names.nix {inherit lib;};
  platform = import ../nix/guest/platform.nix {inherit lib;};
  renderSquid = import ../nix/host/proxy.nix {mode = "squidConfig";};

  # ==== test-record helpers ==============================================
  # A test is `{ ok, message }`. Tests are attributes of the `tests` set keyed
  # by name: an attrset (unlike a list) keeps each `T ...` a single expression,
  # so the calls do not have to be parenthesised.
  T = ok: message: {inherit ok message;};
  inStr = needle: hay: T (hasInfix needle hay) "missing substring: ${needle}";
  notInStr = needle: hay: T (!hasInfix needle hay) "unexpected substring: ${needle}";

  # ==== host-system evaluation ==========================================
  # The module's platform split is driven by the `system` specialArg, never by
  # `pkgs`; the common tests all use a Linux evaluator.
  base = {...}: {
    system.stateVersion = "26.05";
    networking.hostName = "tartarus-test";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
    boot.loader.grub.enable = false;
    # The host modules write `home-manager.*`; giving the test user an account
    # and a stateVersion keeps home-manager's config forceable without a host.
    users.users.user = {
      name = "user";
      isNormalUser = true;
      home = "/home/user";
    };
    home-manager.users.user.home.stateVersion = "26.05";
  };

  mkHost = {
    hostSystem ? evalSystem,
    hostPkgs ? pkgs,
    proxy ? {},
    guests ? {},
    modules ? [],
  }:
    lib.nixosSystem {
      system = hostSystem;
      pkgs = hostPkgs;
      specialArgs = {
        username = "user";
        homeDir =
          if hasSuffix "-darwin" hostSystem
          then "/Users/user"
          else "/home/user";
        system = hostSystem;
      };
      modules =
        [
          inputs.home-manager.nixosModules.home-manager
          self.nixosModules.tartarus
          base
          {
            tartarus.proxy = proxy;
            tartarus.guests = guests;
          }
        ]
        ++ modules;
    };

  # Evaluate only tartarus's own assertion predicates (exposed read-only as
  # `tartarus.internalAssertions`), never nixpkgs'. Some nixpkgs assertion
  # *messages* only make sense on failure and raise unforceable attribute
  # errors that `tryEval` cannot catch in this Nix, so mixing them in would make
  # the suite brittle. Type errors (e.g. an out-of-range id) surface while
  # forcing the submodule value and are caught by `tryEval`.
  assertionBools = host: map (a: a.assertion) host.config.tartarus.internalAssertions;
  assertionsPass = host: let
    r = builtins.tryEval (all (x: x) (assertionBools host));
  in
    r.success && r.value;

  # ==== sample guest sets ===============================================
  fullProxy = {
    enable = true;
    location = "host";
    port = 3128;
    log = false;
  };

  hostOk = mkHost {
    proxy = fullProxy;
    guests = {
      # internet=false + proxy=true  -> proxy-only (accept + drop egress).
      vault = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = false;
        proxy = {
          enable = true;
          allowHosts = ["example.com" ".example.com"];
        };
        firewall = {
          enable = true;
          location = "host";
          allow = ["10.200.0.99"];
        };
      };
      # internet=false + proxy=false -> no egress at all.
      locked = {
        enable = true;
        kind = "vm";
        id = 4;
        internet = false;
      };
      # internet=true  + proxy=false -> NAT.
      net = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
      };
      # internet=true  + proxy=false -> NAT (container).
      box = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
      };
      # internet=false + proxy=true  -> proxy-only (container).
      pbox = {
        enable = true;
        kind = "container";
        id = 7;
        internet = false;
        proxy = {
          enable = true;
          allowHosts = ["ctn.example"];
        };
      };
      # Disabled: must NOT reach the generated config.toml (the CLI guard treats
      # absence from config.toml as "not enabled on this host").
      ghost = {
        enable = false;
        kind = "vm";
        id = 42;
        internet = true;
      };
    };
  };

  hostGuestProxy = mkHost {
    proxy = {
      enable = true;
      location = "proxyvm";
      port = 3128;
    };
    guests = {
      proxyvm = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
      };
      vclient = {
        enable = true;
        kind = "vm";
        id = 8;
        internet = false;
        proxy = {
          enable = true;
          allowHosts = ["a.example"];
        };
      };
      cclient = {
        enable = true;
        kind = "container";
        id = 9;
        internet = false;
        proxy = {
          enable = true;
          allowHosts = ["b.example"];
        };
      };
    };
  };

  # A Darwin host needs no nix-darwin input for the eval-level checks: a
  # `lib.nixosSystem` evaluated with `system = "aarch64-darwin"` plus test-local
  # stubs for the two nix-darwin-only options tartarus writes (`launchd.*` from
  # nix-service, `nix.linux-builder` from ./linux-builder.nix) is enough. The
  # assertions read via `internalAssertions` never touch nixpkgs' own list.
  darwinStub = {lib, ...}: {
    options.nix.linux-builder.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.launchd.agents = lib.mkOption {
      type = lib.types.attrsOf lib.types.unspecified;
      default = {};
    };
    options.launchd.daemons = lib.mkOption {
      type = lib.types.attrsOf lib.types.unspecified;
      default = {};
    };
  };
  mkDarwinHost = guests:
    lib.nixosSystem {
      system = "aarch64-darwin";
      pkgs = import inputs.nixpkgs {
        system = "aarch64-darwin";
        config.allowUnfree = true;
      };
      specialArgs = {
        username = "user";
        homeDir = "/Users/user";
        system = "aarch64-darwin";
      };
      modules = [
        inputs.home-manager.nixosModules.home-manager
        self.nixosModules.tartarus
        darwinStub
        base
        {
          tartarus.ca.enable = false;
          tartarus.ssh.enable = false;
          tartarus.guests = guests;
        }
      ];
    };
  hostBadFirewallDarwin = mkDarwinHost {
    x = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = false;
      firewall = {
        enable = true;
        location = "host";
      };
    };
  };
  hostDarwinGuestFw = mkDarwinHost {
    x = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = false;
      firewall = {
        enable = true;
        location = "guest";
      };
    };
  };
  # Darwin with a valid guest-hosted proxy now passes (vmnet-shared guests
  # can reach each other).
  hostDarwinGuestProxyOk = lib.nixosSystem {
    system = "aarch64-darwin";
    pkgs = import inputs.nixpkgs {
      system = "aarch64-darwin";
      config.allowUnfree = true;
    };
    specialArgs = {
      username = "user";
      homeDir = "/Users/user";
      system = "aarch64-darwin";
    };
    modules = [
      inputs.home-manager.nixosModules.home-manager
      self.nixosModules.tartarus
      darwinStub
      base
      {
        tartarus.ca.enable = false;
        tartarus.ssh.enable = false;
        tartarus.proxy = {
          enable = true;
          location = "proxyvm";
          port = 3128;
        };
        tartarus.guests = {
          proxyvm = {
            enable = true;
            kind = "vm";
            id = 5;
            internet = true;
          };
          client = {
            enable = true;
            kind = "vm";
            id = 8;
            internet = false;
            proxy = {
              enable = true;
              allowHosts = ["a.example"];
            };
          };
        };
      }
    ];
  };

  # Darwin relays: a privileged port (53) becomes a root launch daemon, the
  # rest user launch agents.
  hostDarwinRelays = mkDarwinHost {
    x = {
      enable = true;
      kind = "vm";
      id = 20;
      internet = true;
      relays = [
        {
          port = 53;
          protocol = "udp";
        }
        {
          port = 53;
          protocol = "tcp";
        }
        {
          port = 3128;
        }
      ];
    };
  };

  hostBadInternetProxy = mkHost {
    proxy = fullProxy;
    guests.x = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = true;
      proxy.enable = true;
    };
  };
  hostBadProxyNoGlobal = mkHost {
    proxy.enable = false;
    guests.x = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = false;
      proxy.enable = true;
    };
  };
  hostBadLocationMissing = mkHost {
    proxy = {
      enable = true;
      location = "nope";
    };
    guests.x = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = true;
    };
  };
  hostBadLocationContainer = mkHost {
    proxy = {
      enable = true;
      location = "box";
    };
    guests.box = {
      enable = true;
      kind = "container";
      id = 6;
      internet = true;
    };
  };
  hostBadLocationNoInternet = mkHost {
    proxy = {
      enable = true;
      location = "locked";
    };
    guests.locked = {
      enable = true;
      kind = "vm";
      id = 4;
      internet = false;
    };
  };
  hostBadStatic101 = mkHost {
    guests.big = {
      enable = true;
      kind = "vm";
      id = 101;
      internet = true;
    };
  };
  hostBadDup = mkHost {
    guests = {
      a = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = true;
      };
      b = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = true;
      };
    };
  };
  hostBadType = mkHost {
    guests.low = {
      enable = true;
      kind = "vm";
      id = 2;
      internet = true;
    };
  };

  # requires tests
  hostRequiresMissing = mkHost {
    guests = {
      a = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = true;
        requires = ["ghost"];
      };
    };
  };
  hostRequiresCycle = mkHost {
    guests = {
      a = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = true;
        requires = ["b"];
      };
      b = {
        enable = true;
        kind = "vm";
        id = 4;
        internet = true;
        requires = ["c"];
      };
      c = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        requires = ["a"];
      };
    };
  };

  # ==== rendered nftables ===============================================
  nftOf = host: host.config.networking.nftables.tables;
  # Split a kind's table content at the forward chain: everything before it is
  # the input chain (so "same chain as the guest rules" is a real assertion),
  # everything after it is the forward chain.
  inputPart = kind: content: head (splitString "chain ${kind}_forward {" content);
  forwardPart = kind: content: lib.elemAt (splitString "chain ${kind}_forward {" content) 1;

  hostOkNft = nftOf hostOk;
  # The generated CLI config. `nix/host/config.nix` emits only enabled guests,
  # so a disabled guest's name must never appear -- that absence is exactly what
  # the CLI guard (`Config.require_guest`) treats as "not enabled".
  configToml = hostOk.config.home-manager.users.user.home.file.".config/tartarus/config.toml".text;
  vmContent = hostOkNft.tartarus_vm.content;
  vmForward = forwardPart "vm" vmContent;
  ctnContent = hostOkNft.tartarus_container.content;
  ctnForward = forwardPart "container" ctnContent;
  natContent = hostOkNft.tartarus_nat.content;

  hostGuestNft = nftOf hostGuestProxy;
  vmForwardGuest = forwardPart "vm" hostGuestNft.tartarus_vm.content;
  ctnForwardGuest = forwardPart "container" hostGuestNft.tartarus_container.content;
  natGuest = hostGuestNft.tartarus_nat.content;
  vmInputGuest = inputPart "vm" hostGuestNft.tartarus_vm.content;

  # ==== rendered Squid config ===========================================
  squidClients = [
    {
      name = "vault";
      kind = "vm";
      ip = "10.200.0.3";
      allowHosts = ["example.com" ".example.com"];
    }
    {
      name = "box-net";
      kind = "container";
      ip = "10.201.0.6";
      allowHosts = [];
    }
  ];
  squidDefault = renderSquid {
    inherit lib;
    listenAddresses = ["10.200.0.1" "10.201.0.1"];
    port = 3128;
    log = false;
    clients = squidClients;
  };
  squidLogged = renderSquid {
    inherit lib;
    listenAddresses = ["10.200.0.1"];
    port = 3128;
    log = true;
    clients = squidClients;
  };

  # ==== mkGuests samples ================================================
  mkGuests = {
    hostSystem ? evalSystem,
    globalProxy,
    guests,
  }:
    self.lib.mkGuests {
      inherit inputs;
      nixpkgs = inputs.nixpkgs;
      system = evalSystem;
      inherit hostSystem;
      pkgs = pkgs;
      hostPkgs = pkgs;
      homeDir = "/home/user";
      config = {
        tartarus.proxy = globalProxy;
        tartarus.guests = guests;
      };
    };

  envText = guests: name:
    guests.nixosConfigurations."vm-${name}".config.home-manager.users.user.home.file.".config/environment.d/10-tartarus.conf".text;

  envLinuxGuests = mkGuests {
    globalProxy = fullProxy;
    guests.vault = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = false;
      proxy = {
        enable = true;
        allowHosts = ["example.com"];
      };
    };
  };
  envLinux = envText envLinuxGuests "vault";

  envGuestProxyGuests = mkGuests {
    globalProxy = {
      enable = true;
      location = "proxyvm";
      port = 3128;
    };
    guests = {
      proxyvm = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
      };
      vault = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = false;
        proxy.enable = true;
      };
    };
  };
  envGuestProxy = envText envGuestProxyGuests "vault";

  envDarwinGuests = mkGuests {
    hostSystem = "aarch64-darwin";
    globalProxy = fullProxy;
    guests.vault = {
      enable = true;
      kind = "vm";
      id = 3;
      internet = false;
      proxy.enable = true;
    };
  };
  envDarwin = envText envDarwinGuests "vault";

  # A Darwin guest with a firewall and all three host services: the in-guest
  # nftables output chain must accept the service ports at the vmnet gateway.
  fwDarwinGuests = mkGuests {
    hostSystem = "aarch64-darwin";
    globalProxy = fullProxy;
    guests.svc = {
      enable = true;
      kind = "vm";
      id = 20;
      internet = false;
      proxy.enable = true;
      firewall = {
        enable = true;
        location = "guest";
      };
      services = {
        sudoAuthProxy = true;
        sshAuthProxy = true;
        clipboardBridge = true;
      };
    };
  };
  fwDarwinNft = fwDarwinGuests.nixosConfigurations."vm-svc".config.networking.nftables.tables.tartarus.content;

  namesGuests = mkGuests {
    globalProxy.enable = false;
    guests = {
      vault = {
        enable = true;
        kind = "vm";
        id = 3;
        internet = true;
      };
      work = {
        enable = true;
        kind = "vm";
        id = null;
        internet = true;
      };
      box = {
        enable = true;
        kind = "container";
        id = 4;
        internet = true;
      };
      abox = {
        enable = true;
        kind = "container";
        id = null;
        internet = true;
      };
    };
  };

  # ==== standalone service modules ======================================
  # The three service packages must be usable from *any* NixOS/home-manager
  # config with no tartarus host/guest module anywhere in the closure. Each
  # check imports exactly one service module into a bare system/home config
  # and forces a derivation path; success proves the module is self-contained.
  bareNixos = {...}: {
    system.stateVersion = "26.05";
    networking.hostName = "standalone";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
    boot.loader.grub.enable = false;
  };

  mkStandaloneNixos = mod: cfg:
    lib.nixosSystem {
      system = evalSystem;
      modules = [bareNixos mod cfg];
    };

  # Force the full system derivation; a throw anywhere in the enabled module
  # makes `tryEval` return success=false.
  nixosDrvOk = host: let
    r = builtins.tryEval (builtins.seq host.config.system.build.toplevel.drvPath true);
  in
    r.success && r.value;

  # `_module.args.system` pins the platform independently of the evaluator so
  # the HM module's `isDarwin` branch matches the Linux `pkgs` used here.
  homeBase = {
    _module.args.system = evalSystem;
    home.username = "user";
    home.homeDirectory = "/home/user";
    home.stateVersion = "26.05";
  };

  mkStandaloneHm = mod: cfg:
    inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [mod homeBase cfg];
    };

  hmDrvOk = hm: let
    r = builtins.tryEval (builtins.seq hm.config.home.activationPackage.drvPath true);
  in
    r.success && r.value;
in {
  tests = {
    # ---- ids.nix: stable assignment ------------------------------------
    "ids/static-honored" =
      T (ids.assignIds {vault = {id = 3;};} == {vault = 3;}) "static id 3 not honored";
    "ids/auto-start-101" =
      T (ids.assignIds {work = {id = null;};} == {work = 101;}) "auto id does not start at 101";
    "ids/auto-sorted" =
      T
      (ids.assignIds {
          c = {id = null;};
          a = {id = null;};
          b = {id = null;};
        }
        == {
          a = 101;
          b = 102;
          c = 103;
        })
      "auto ids are not assigned in stable sorted order";

    # A forced id (3) does not push the autos around, lowering another guest
    # does not shift them, and removing the forced guest leaves them alone.
    # This is the "no shifting" invariant: autos are a pure function of the
    # sorted auto names and the *set* of forced ids, not of their values.
    "ids/forced-does-not-shift-autos" =
      T
      (let
        withForced3 = ids.assignIds {
          vault = {id = 3;};
          a = {id = null;};
          b = {id = null;};
        };
        withForced5 = ids.assignIds {
          vault = {id = 5;};
          a = {id = null;};
          b = {id = null;};
        };
        withoutForced = ids.assignIds {
          a = {id = null;};
          b = {id = null;};
        };
      in
        withForced3
        == {
          vault = 3;
          a = 101;
          b = 102;
        }
        && withForced5
        == {
          vault = 5;
          a = 101;
          b = 102;
        }
        && withoutForced
        == {
          a = 101;
          b = 102;
        })
      "lowering/removing a forced guest shifted an auto id";

    "ids/auto-skips-forced" =
      T
      (ids.assignIds {
          a = {id = null;};
          b = {id = 5;};
          c = {id = null;};
        }
        == {
          a = 101;
          b = 5;
          c = 102;
        })
      "auto assignment did not skip the forced id";

    "ids/formulas" =
      T
      (ids.mkVmIP 3
        == "10.200.0.3"
        && ids.mkVmIPNat 3 == "192.168.64.45"
        && ids.mkCtnIP 7 == "10.201.0.7"
        && ids.mkMac 3 == "02:00:00:00:00:03"
        && ids.mkMac 255 == "02:00:00:00:00:FF"
        && ids.mkCid 3 == 3)
      "id -> IP/MAC/CID formulas changed";

    # ---- names.nix ------------------------------------------------------
    "names/namespace" =
      T
      (names.namespace "vm" "vault"
        == "vm-vault"
        && names.namespace "container" "box" == "ctn-box"
        && names.kindPrefix "container" == "ctn")
      "guest namespace prefixes changed";

    # ---- platform.nix: Linux vs Darwin ----------------------------------
    "platform/linux-vm" =
      T
      (let
        p = platform.mk {
          hostSystem = "x86_64-linux";
          kind = "vm";
          id = 3;
        };
      in
        p.isLinux
        && !p.isDarwin
        && p.useVsock
        && p.guestIP == "10.200.0.3"
        && p.gateway == "10.200.0.1"
        && p.serviceHost == "2"
        && p.hypervisor == "qemu")
      "Linux VM platform resolution changed";
    "platform/darwin-vm" =
      T
      (let
        p = platform.mk {
          hostSystem = "aarch64-darwin";
          kind = "vm";
          id = 3;
        };
      in
        p.isDarwin
        && !p.vsockAvailable
        && !p.useVsock
        && p.guestIP == "192.168.64.45"
        && p.gateway == "192.168.64.1"
        && p.serviceHost == "_gateway"
        && p.hypervisor == "vfkit"
        && p.shareProto == "virtiofs"
        && p.resolvedProxyHost == "192.168.64.1")
      "Darwin VM platform resolution changed";
    "platform/container-no-vsock" =
      T
      (let
        p = platform.mk {
          hostSystem = "x86_64-linux";
          kind = "container";
          id = 4;
        };
      in
        !p.vsockAvailable && !p.useVsock && p.guestIP == "10.201.0.4" && p.hypervisor == "qemu")
      "containers must never select VSOCK";

    # ---- host assertions ------------------------------------------------
    "assertions/good-host-passes" =
      T (assertionsPass hostOk) "a valid host configuration was rejected";
    "assertions/internet-x-proxy-exclusive" =
      T (!assertionsPass hostBadInternetProxy) "internet=true + proxy.enable=true was accepted";
    "assertions/proxy-requires-global" =
      T (!assertionsPass hostBadProxyNoGlobal) "per-guest proxy without global proxy was accepted";
    "assertions/proxy-location-missing" =
      T (!assertionsPass hostBadLocationMissing) "proxy.location naming an unknown guest was accepted";
    "assertions/proxy-location-container" =
      T (!assertionsPass hostBadLocationContainer) "proxy.location naming a container was accepted";
    "assertions/proxy-location-no-internet" =
      T (!assertionsPass hostBadLocationNoInternet) "proxy.location naming a non-internet VM was accepted";
    "assertions/proxy-location-guest-ok" =
      T (assertionsPass hostGuestProxy) "a valid guest-hosted proxy was rejected";
    "assertions/id-101-rejected" =
      T (!assertionsPass hostBadStatic101) "static id 101 (auto range) was accepted";
    "assertions/id-duplicate-rejected" =
      T (!assertionsPass hostBadDup) "duplicate static ids were accepted";
    "assertions/id-type-rejected" =
      T (!assertionsPass hostBadType) "id = 2 (reserved) type check did not fire";
    "assertions/darwin-host-firewall-rejected" =
      T (!assertionsPass hostBadFirewallDarwin) "firewall.location=host was accepted on Darwin";
    "assertions/darwin-guest-firewall-ok" =
      T (assertionsPass hostDarwinGuestFw) "firewall.location=guest was rejected on Darwin";
    "assertions/darwin-guest-proxy-ok" =
      T (assertionsPass hostDarwinGuestProxyOk) "valid Darwin guest-hosted proxy was rejected";
    "assertions/requires-missing-rejected" =
      T (!assertionsPass hostRequiresMissing) "requires naming a disabled/missing guest was accepted";
    "assertions/requires-cycle-rejected" =
      T (!assertionsPass hostRequiresCycle) "requires cycle was accepted";

    # ---- Darwin guest firewall: host-service allowances ----------------
    # A proxy-only guest that opts into an in-guest firewall must still reach
    # the host's user services (their ports are outside the trs subnets on
    # Darwin).
    "guest-fw/host-services" =
      T
      (all (p: hasInfix "ip daddr 192.168.64.1 tcp dport ${p} counter accept" fwDarwinNft) ["65001" "65000" "27795"])
      "a firewalled guest did not allow the host service ports at the gateway";

    # ---- Darwin host relays -------------------------------------------
    "relay/darwin-udp-privileged" =
      T
      (hasInfix "UDP4-LISTEN:53,bind=192.168.64.1,reuseaddr,fork UDP4:192.168.64.62:53" (concatStringsSep " " hostDarwinRelays.config.launchd.daemons."tartarus-relay-x-udp-53".serviceConfig.ProgramArguments))
      "Darwin privileged UDP relay args changed";
    "relay/darwin-tcp-privileged" =
      T (hostDarwinRelays.config.launchd.daemons ? "tartarus-relay-x-tcp-53") "privileged TCP relay is not a root launch daemon";
    "relay/darwin-user-agent" =
      T (hostDarwinRelays.config.launchd.agents ? "tartarus-relay-x-tcp-3128") "non-privileged relay is not a user launch agent";
    "relay/darwin-proxy-auto" =
      T (hostDarwinGuestProxyOk.config.launchd.agents ? "tartarus-relay-proxyvm-tcp-3128") "the guest-hosted proxy relay was not generated automatically";

    # ---- rendered Squid config -----------------------------------------
    "squid/src-acl" = inStr "acl g_vault src 10.200.0.3/32" squidDefault;
    "squid/dstdomain-acl" = inStr "acl g_vault_hosts dstdomain example.com .example.com" squidDefault;
    "squid/connect-allow" = inStr "http_access allow g_vault CONNECT g_vault_hosts SSL_ports" squidDefault;
    "squid/per-guest-deny" = inStr "http_access deny g_vault" squidDefault;
    "squid/deny-all-tail" = inStr "http_access deny all" squidDefault;
    "squid/https-only" = inStr "acl SSL_ports port 443" squidDefault;
    "squid/no-plain-http" = notInStr "SSL_ports port 80" squidDefault;
    "squid/cache-deny-all" = inStr "cache deny all" squidDefault;
    # The header comment mentions `never_direct`; look for a real directive line.
    "squid/no-never-direct" = notInStr "\nnever_direct" squidDefault;
    "squid/log-off-none" = inStr "access_log none" squidDefault;
    "squid/log-on-stderr" = inStr "access_log stdio:/dev/stderr" squidLogged;
    "squid/http-port-per-listen" = inStr "http_port 10.201.0.1:3128" squidDefault;
    "squid/empty-allowlist-invalid" = inStr "acl g_box_net_hosts dstdomain .invalid" squidDefault;
    "squid/no-loopback" = notInStr "http_port 127.0.0.1" squidDefault;

    # ---- nftables snapshots: internet x proxy matrix --------------------
    # The Phase-5B priority-bug fix: the proxy accept lives in the *same* guest
    # input chain as the guest rules, not a separate priority-0 table.
    "nft/proxy-accept-in-vm-input" =
      T
      (hasInfix "ip saddr 10.200.0.3 ip daddr 10.200.0.1 tcp dport 3128 counter accept comment \"vault-proxy\"" (inputPart "vm" vmContent)
        && !hasInfix "vault-proxy" vmForward)
      "host proxy accept is not inside the vm input chain";
    "nft/proxy-accept-in-ctn-input" =
      T
      (hasInfix "ip saddr 10.201.0.7 ip daddr 10.201.0.1 tcp dport 3128 counter accept comment \"pbox-proxy\"" (inputPart "container" ctnContent)
        && !hasInfix "pbox-proxy" ctnForward)
      "host proxy accept is not inside the container input chain";
    "nft/no-separate-squid-table" =
      T (!(hostOk.config.networking.nftables.tables ? squid)) "a separate squid table still exists (priority bug)";
    "nft/proxy-only-guest-drops-egress" =
      T
      (hasInfix "iifname \"trs0\" ip saddr 10.200.0.3 oifname != \"trs0\" counter drop comment \"vault-no-internet\"" vmForward)
      "a proxy-only guest has no egress drop rule";
    "nft/no-internet-guest-drops-egress" =
      T
      (hasInfix "ip saddr 10.200.0.4 oifname != \"trs0\" counter drop comment \"locked-no-internet\"" vmForward)
      "a no-internet guest has no egress drop rule";
    "nft/internet-guest-not-dropped" = notInStr "net-no-internet" vmForward;
    "nft/nat-vm-masq" = inStr "ip saddr 10.200.0.0/24 oifname != \"trs0\"" natContent;
    "nft/nat-ctn-masq" = inStr "ip saddr 10.201.0.0/24 oifname != \"trs0\" oifname != \"trs1\"" natContent;
    "nft/firewall-host-allow-emitted" =
      T (hasInfix "ip saddr 10.200.0.99 counter accept" (inputPart "vm" vmContent)) "firewall.allow (location=host) rule was not emitted";
    "nft/resolved-listen-host" =
      T (lib.sort (a: b: a < b) hostOk.config.tartarus.proxy.resolvedListenAddresses == ["10.200.0.1" "10.201.0.1"]) "host proxy did not bind both bridges";

    # ---- nftables snapshots: cross-kind guest-hosted proxy -------------
    "nft-cross/cross-kind-forward" =
      inStr "iifname \"trs1\" ip saddr 10.201.0.9 ip daddr 10.200.0.5 tcp dport 3128 counter accept comment \"cclient-to-proxy\"" ctnForwardGuest;
    "nft-cross/same-kind-forward" =
      inStr "iifname \"trs0\" ip saddr 10.200.0.8 ip daddr 10.200.0.5 tcp dport 3128 counter accept comment \"vclient-to-proxy\"" vmForwardGuest;
    "nft-cross/no-masq-exception" =
      inStr "ip daddr 10.200.0.5 counter return comment \"proxy-no-masq\"" natGuest;
    "nft-cross/no-host-proxy-input" =
      notInStr "vclient-proxy" vmInputGuest;
    "nft-cross/resolved-listen-guest-proxy" =
      T (lib.sort (a: b: a < b) hostGuestProxy.config.tartarus.proxy.resolvedListenAddresses == ["10.200.0.1" "10.201.0.1"]) "guest-hosted proxy listen addresses changed";

    # ---- generated environment.d proxy variables ------------------------
    "env/http-proxy" = inStr "HTTP_PROXY=http://10.200.0.1:3128" envLinux;
    "env/https-proxy" = inStr "HTTPS_PROXY=http://10.200.0.1:3128" envLinux;
    "env/all-proxy" = inStr "ALL_PROXY=http://10.200.0.1:3128" envLinux;
    "env/lowercase-http" = inStr "http_proxy=http://10.200.0.1:3128" envLinux;
    "env/lowercase-https" = inStr "https_proxy=http://10.200.0.1:3128" envLinux;
    "env/lowercase-all" = inStr "all_proxy=http://10.200.0.1:3128" envLinux;
    "env/no-proxy" =
      inStr "NO_PROXY=10.200.0.0/24,10.201.0.0/24,10.200.0.1,10.201.0.1,192.168.64.1,localhost,127.0.0.1,.trs" envLinux;
    "env/lowercase-no-proxy" =
      inStr "no_proxy=10.200.0.0/24,10.201.0.0/24,10.200.0.1,10.201.0.1,192.168.64.1,localhost,127.0.0.1,.trs" envLinux;
    "env/guest-hosted-target" = inStr "HTTP_PROXY=http://10.200.0.5:3128" envGuestProxy;
    "env/darwin-host-gateway" = inStr "HTTP_PROXY=http://192.168.64.1:3128" envDarwin;

    # ---- mkGuests output names / ids ------------------------------------
    "mkGuests/nixosConfigurations-names" =
      T (attrNames namesGuests.nixosConfigurations == ["ctn-abox" "ctn-box" "vm-vault" "vm-work"]) "mkGuests nixosConfigurations keys changed";
    "mkGuests/package-names" =
      T (attrNames namesGuests.packages.${evalSystem} == ["vm-vault" "vm-work"]) "mkGuests must expose runnable packages for VMs only";
    "mkGuests/vmIds" = T (namesGuests.vmIds
      == {
        vault = 3;
        work = 101;
      }) "mkGuests vmIds changed (static 3 + auto 101 expected)";

    # ---- generated config.toml: enabled-only ----------------------------
    "config/enabled-guest-present" =
      inStr ''name = "vault"'' configToml;
    "config/disabled-guest-omitted" =
      notInStr ''name = "ghost"'' configToml;

    # ---- standalone service modules -------------------------------------
    # Each service must evaluate from a bare config that imports *only* that
    # module (no tartarus host/guest modules), and the legacy
    # `sudo-auth-proxy` NixOS output must behave identically to the
    # explicitly-named `sudo-auth-proxy-pam` alias.
    "standalone/nixos-clipboard-bridge" =
      T
      (nixosDrvOk (mkStandaloneNixos self.nixosModules."clipboard-bridge" {tartarus.clipboard-bridge.enable = true;}))
      "clipboard-bridge NixOS module does not evaluate standalone";
    "standalone/nixos-ssh-agent-proxy" =
      T
      (nixosDrvOk (mkStandaloneNixos self.nixosModules."ssh-agent-proxy" {tartarus.ssh-agent-proxy.enable = true;}))
      "ssh-agent-proxy NixOS module does not evaluate standalone";
    "standalone/nixos-sudo-auth-proxy" =
      T
      (nixosDrvOk (mkStandaloneNixos self.nixosModules."sudo-auth-proxy" {tartarus.sudo-auth-proxy.enable = true;}))
      "sudo-auth-proxy NixOS module does not evaluate standalone";
    "standalone/nixos-sudo-auth-proxy-pam" =
      T
      (nixosDrvOk (mkStandaloneNixos self.nixosModules."sudo-auth-proxy-pam" {tartarus.sudo-auth-proxy.enable = true;}))
      "sudo-auth-proxy-pam NixOS module does not evaluate standalone";

    "standalone/hm-clipboard-bridge" =
      T
      (hmDrvOk (mkStandaloneHm self.homeManagerModules."clipboard-bridge" {tartarus.clipboard-bridge.enable = true;}))
      "clipboard-bridge home-manager module does not evaluate standalone";
    "standalone/hm-ssh-agent-proxy" =
      T
      (hmDrvOk (mkStandaloneHm self.homeManagerModules."ssh-agent-proxy" {tartarus.ssh-agent-proxy.enable = true;}))
      "ssh-agent-proxy home-manager module does not evaluate standalone";
    "standalone/hm-sudo-auth-proxy" =
      T
      (hmDrvOk (mkStandaloneHm self.homeManagerModules."sudo-auth-proxy" {tartarus.sudo-auth-proxy.enable = true;}))
      "sudo-auth-proxy home-manager module does not evaluate standalone";

    # Importing a service module must not pull in the host option surface.
    "standalone/no-host-module" =
      T
      (let
        host = mkStandaloneNixos self.nixosModules."clipboard-bridge" {tartarus.clipboard-bridge.enable = true;};
      in
        !(host.config.tartarus ? guests) && !(host.config.tartarus ? proxy))
      "a service-only config pulled in tartarus host options (guests/proxy)";
  };

  # Human-inspectable renderings (plain strings, safe for `nix eval --json`).
  rendered = {
    inherit squidDefault squidLogged vmContent ctnContent natContent vmForwardGuest ctnForwardGuest natGuest envLinux envGuestProxy envDarwin configToml;
    vmInput = inputPart "vm" vmContent;
    ctnInput = inputPart "container" ctnContent;
    resolvedListenHost = hostOk.config.tartarus.proxy.resolvedListenAddresses;
  };
}

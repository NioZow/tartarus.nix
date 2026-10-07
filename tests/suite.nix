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
  sharePolicy = import ../nix/lib/shares.nix {inherit lib;};
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

  # `assertionsPass` only reads the plain instances map, which never touches
  # `vm.mem` / `vm.vcpu`, so an invalid resource ceiling must be forced
  # explicitly for its type check to run. `deepSeq` forces the nested values.
  resourceFieldsOk = host: let
    r = builtins.tryEval (
      builtins.deepSeq
      (builtins.map (g: [g.vm.mem g.vm.vcpu]) (lib.attrValues host.config.tartarus.guests))
      true
    );
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

  # A Darwin relay into a nested container is two-hop: the host socat targets
  # the container-host VM's NAT address (vm id 5 -> 192.168.64.47), and the VM
  # DNATs the port on to the inner container.
  hostDarwinNestedRelay = mkDarwinHost {
    ch = {
      enable = true;
      kind = "vm";
      id = 5;
      internet = true;
      vm.containerHost.enable = true;
    };
    inner = {
      enable = true;
      kind = "container";
      id = 6;
      internet = true;
      host = "ch";
      relays = [{port = 8080;}];
    };
  };
  darwinNestedRelayArgs =
    concatStringsSep " "
    hostDarwinNestedRelay.config.launchd.agents."tartarus-relay-inner-tcp-8080".serviceConfig.ProgramArguments;

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

  # ==== container-host / resource-ceiling hosts =========================
  # Darwin argument containers need a Linux kernel, so one with no `host`
  # pointer must be rejected.
  hostDarwinContainerNoHost = mkDarwinHost {
    c = {
      enable = true;
      kind = "container";
      id = 4;
      internet = true;
    };
  };

  # Linux: a container-host VM plus an inner container pointing at it passes.
  hostContainerHostOk = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
      };
    };
  };

  # The named host does not exist.
  hostContainerUnknown = mkHost {
    guests.inner = {
      enable = true;
      kind = "container";
      id = 6;
      internet = true;
      host = "ghost";
    };
  };

  # The named guest exists but is a plain VM (containerHost disabled).
  hostContainerNotHost = mkHost {
    guests = {
      plain = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "plain";
      };
    };
  };

  # `vm.containerHost.enable` is VM-only.
  hostContainerHostOnContainer = mkHost {
    guests.bad = {
      enable = true;
      kind = "container";
      id = 6;
      internet = true;
      vm.containerHost.enable = true;
    };
  };

  # `host` is container-only; a VM using it fails even when the target is a
  # valid container host.
  hostHostOnVm = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      v = {
        enable = true;
        kind = "vm";
        id = 7;
        internet = true;
        host = "ch";
      };
    };
  };

  # ==== P3: host-side predicate coverage ================================
  # A container-host VM `ch` with a nested `inner` and a native `box`. Only
  # `box` is host-side; `inner` lives on the VM's inner bridge (`10.202.0.6`)
  # and must never appear on the host container bridge (`trs1`).
  hostNestedAndNative = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
      };
      box = {
        enable = true;
        kind = "container";
        id = 7;
        internet = true;
      };
    };
  };
  nestedAndNativeNft = nftOf hostNestedAndNative;
  nestedAndNativeCtn = nestedAndNativeNft.tartarus_container.content;

  # A nested container that opts into the host proxy. The step-7 assertion
  # rejects it, but the option-level `tartarus.proxy.clients` must exclude it
  # defensively -- hence this host is only ever inspected through the option,
  # never through `assertionsPass` (the nested-proxy rejection has its own
  # fixture below).
  hostProxyNested = mkHost {
    proxy = {
      enable = true;
      location = "host";
      port = 3128;
      log = false;
    };
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = false;
        host = "ch";
        proxy = {
          enable = true;
          allowHosts = ["nested.example"];
        };
      };
      box = {
        enable = true;
        kind = "container";
        id = 7;
        internet = false;
        proxy = {
          enable = true;
          allowHosts = ["box.example"];
        };
      };
    };
  };
  proxyNestedClientNames = map (c: c.name) hostProxyNested.config.tartarus.proxy.clients;

  # A nested container with `autostart = true`: the autostart entry must be for
  # the host VM `ch`, not for `inner` (which the VM starts itself).
  hostNestedAutostart = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        autostart = true;
      };
    };
  };
  nestedAutostartNames = map (g: g.name) hostNestedAutostart.config.tartarus.instances.autostart;

  # Both the host VM and its nested container ask for autostart: the two
  # requests must collapse to a single host VM unit.
  hostNestedAutostartDup = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        autostart = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        autostart = true;
      };
    };
  };
  nestedAutostartDupNames = map (g: g.name) hostNestedAutostartDup.config.tartarus.instances.autostart;

  # Step-7 rejections: a nested container may not declare host-side relays or
  # route through the host proxy yet. Host services ARE supported: the
  # container-host VM stands in for its nested containers (DNAT to the host).
  hostNestedRelays = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        relays = [{port = 8080;}];
      };
    };
  };
  hostNestedService = mkHost {
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        services.sudoAuthProxy = true;
      };
    };
  };

  # Nullable / "host" sentinel ceilings must type-check.
  hostMemNullHost = mkHost {
    guests = {
      a = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm = {
          mem = null;
          vcpu = "host";
        };
      };
      b = {
        enable = true;
        kind = "vm";
        id = 6;
        internet = true;
        vm = {
          mem = "host";
          vcpu = null;
        };
      };
    };
  };

  # A non-positive mem must fail the type check when the value is forced.
  hostMemBad = mkHost {
    guests.a = {
      enable = true;
      kind = "vm";
      id = 5;
      internet = true;
      vm.mem = -1;
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
  # A container-host VM (`ch`) plus its nested container (`inner`), rendered
  # through the same host module as configToml.
  containerHostToml = hostContainerHostOk.config.home-manager.users.user.home.file.".config/tartarus/config.toml".text;
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
    # Host-level ceilings for `vm.mem = "host"` / `vm.vcpu = "host"` (P5). Left
    # out of the sample config entirely when null so the "option unset" path is
    # exercised faithfully.
    hostMemoryMiB ? null,
    hostCores ? null,
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
        tartarus =
          {
            proxy = globalProxy;
            guests = guests;
          }
          // (lib.optionalAttrs (hostMemoryMiB != null) {inherit hostMemoryMiB;})
          // (lib.optionalAttrs (hostCores != null) {inherit hostCores;});
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
        sshAgentProxy = true;
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

  # A container-host VM (`ch`) with one nested container (`inner`). Proves the
  # build engine declares `containers.inner` inside the VM's config and that the
  # inner container evaluates with inner-bridge addressing.
  chGuests = mkGuests {
    globalProxy.enable = false;
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
      };
    };
  };
  chVm = chGuests.nixosConfigurations."vm-ch";
  chInner = chGuests.nixosConfigurations."ctn-inner";

  # The same VM with one inner container opting into `autostart`, so the
  # per-inner `autoStart` mirroring (only opted-in inners autostart) can be
  # asserted against `chGuests`, where `inner` does not opt in.
  chAutoGuests = mkGuests {
    globalProxy.enable = false;
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        autostart = true;
      };
    };
  };
  chAutoVm = chAutoGuests.nixosConfigurations."vm-ch";

  # A container-host VM whose nested container requests host services, declares
  # a host relay, and has user shares + sharedFolder -- the feature-parity
  # fixture for the inner DNAT, share and bind-mount wiring.
  chRichGuests = mkGuests {
    globalProxy.enable = false;
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        sharedFolder = true;
        services = {
          sudoAuthProxy = true;
          sshAgentProxy = true;
        };
        relays = [
          {port = 8080;}
          {
            port = 53;
            protocol = "udp";
          }
        ];
        shares = [
          {
            tag = "notes";
            source = "/host/notes";
            mountPoint = "/home/user/notes";
            readOnly = true;
          }
          {
            tag = "work";
            source = "/host/work";
            mountPoint = "/home/user/work";
          }
        ];
      };
    };
  };
  chRichVm = chRichGuests.nixosConfigurations."vm-ch";
  chRichNft = chRichVm.config.networking.nftables.tables.tartarus_inner.content;
  chRichBinds = chRichVm.config.containers.inner.bindMounts;

  # A proxy-only nested container: the VM must DNAT the proxy port to the host
  # gateway and drop the container's other direct egress.
  chProxyGuests = mkGuests {
    globalProxy = {
      enable = true;
      location = "host";
      port = 3128;
    };
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = false;
        host = "ch";
        proxy = {
          enable = true;
          allowHosts = ["nested.example"];
        };
      };
    };
  };
  chProxyVm = chProxyGuests.nixosConfigurations."vm-ch";
  chProxyNft = chProxyVm.config.networking.nftables.tables.tartarus_inner.content;
  chProxyFilter = chProxyVm.config.networking.nftables.tables.tartarus_inner_filter.content;

  # A Darwin container-host: a read-only inner share is store-snapshotted and so
  # must NOT cost a virtiofs device (Apple caps them at 26); the container binds
  # the snapshot path straight from /nix/store.
  chDarwinGuests = mkGuests {
    hostSystem = "aarch64-darwin";
    globalProxy.enable = false;
    guests = {
      ch = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm.containerHost.enable = true;
      };
      inner = {
        enable = true;
        kind = "container";
        id = 6;
        internet = true;
        host = "ch";
        shares = [
          {
            tag = "rosnap";
            source = ./.;
            mountPoint = "/home/user/rosnap";
            readOnly = true;
          }
        ];
      };
    };
  };
  chDarwinVm = chDarwinGuests.nixosConfigurations."vm-ch";
  chDarwinBinds = chDarwinVm.config.containers.inner.bindMounts;

  # ==== P5: resource-ceiling resolution =================================
  # A plain VM keeps the numeric defaults (768 MiB / 1 vCPU) passed straight to
  # microvm.nix -- the regression guard for the retyped `vm.mem`/`vm.vcpu`.
  memDefaultVm =
    (mkGuests {
      globalProxy.enable = false;
      guests.v = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
      };
    })
    .nixosConfigurations."vm-v";

  # Explicit `null` must omit the definition so microvm.nix's own defaults win.
  # Pinned source: `nixos-modules/microvm/options.nix` -> mem default 512, vcpu
  # default 1.
  memNullVm =
    (mkGuests {
      globalProxy.enable = false;
      guests.v = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm = {
          mem = null;
          vcpu = null;
        };
      };
    })
    .nixosConfigurations."vm-v";

  # `"host"` resolves through the explicit host options at evaluation time.
  memHostVm =
    (mkGuests {
      globalProxy.enable = false;
      hostMemoryMiB = 4096;
      hostCores = 8;
      guests.v = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm = {
          mem = "host";
          vcpu = "host";
        };
      };
    })
    .nixosConfigurations."vm-v";

  # `"host"` with the matching host option unset must fail evaluation, not
  # silently fall back to a hypervisor default.
  memHostUnsetVm =
    (mkGuests {
      globalProxy.enable = false;
      guests.v = {
        enable = true;
        kind = "vm";
        id = 5;
        internet = true;
        vm = {
          mem = "host";
          vcpu = "host";
        };
      };
    })
    .nixosConfigurations."vm-v";

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

  # ---- nix/lib/shares.nix fixtures -------------------------------------
  darwin = platform.mk {
    hostSystem = "aarch64-darwin";
    kind = "vm";
    id = 3;
  };
  linux = platform.mk {
    hostSystem = "x86_64-linux";
    kind = "vm";
    id = 3;
  };
  vmReadOnlyShare = {
    tag = "zsh";
    source = "/home/user/.config/zsh";
    mountPoint = "/home/user/.config/zsh";
    proto = "virtiofs";
    readOnly = true;
  };
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
        && p.hostGateway == "10.200.0.1"
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
        && p.hostGateway == "192.168.64.1"
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
        !p.vsockAvailable
        && !p.useVsock
        && p.guestIP == "10.201.0.4"
        && p.gateway == "10.201.0.1"
        && p.hostGateway == "10.201.0.1"
        && p.hypervisor == "qemu")
      "containers must never select VSOCK";

    # ---- nix/lib/shares.nix: macOS read-only snapshot policy ------------
    # Darwin needs a store snapshot for read-only shares (vfkit ignores
    # `readOnly`); Linux does not (the hypervisor enforces it); secrets and
    # the store itself are never copied.
    "shares/darwin-ro-snapshots" =
      T
      (sharePolicy.needsStoreSnapshot darwin vmReadOnlyShare)
      "a read-only Darwin share was not snapshotted";
    "shares/darwin-writable-not-snapshotted" =
      T
      (!sharePolicy.needsStoreSnapshot darwin (vmReadOnlyShare // {readOnly = false;}))
      "a writable Darwin share was snapshotted";
    "shares/linux-ro-not-snapshotted" =
      T
      (!sharePolicy.needsStoreSnapshot linux vmReadOnlyShare)
      "a Linux read-only share was snapshotted (hypervisor enforces it)";
    "shares/opt-out" =
      T
      (!sharePolicy.needsStoreSnapshot darwin (vmReadOnlyShare // {snapshot = false;}))
      "the `snapshot = false` opt-out was ignored";
    "shares/run-never-snapshotted" =
      T
      (!sharePolicy.needsStoreSnapshot darwin (vmReadOnlyShare // {source = "/run/agenix/tartarus-dev";}))
      "a /run source was copied into the store";
    "shares/store-never-snapshotted" =
      T
      (!sharePolicy.needsStoreSnapshot darwin (vmReadOnlyShare // {source = "/nix/store";}))
      "the Nix store was copied into itself";

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

    # ---- container-host pointer + resource ceilings ---------------------
    "assertions/darwin-container-needs-host-rejected" =
      T (!assertionsPass hostDarwinContainerNoHost) "a Darwin container without a host was accepted";
    "assertions/container-host-ok" =
      T (assertionsPass hostContainerHostOk) "a valid container host + inner container was rejected";
    "assertions/container-host-unknown-rejected" =
      T (!assertionsPass hostContainerUnknown) "a container naming an unknown host was accepted";
    "assertions/container-host-not-a-host-rejected" =
      T (!assertionsPass hostContainerNotHost) "a container naming a non-container-host VM was accepted";
    "assertions/containerhost-on-container-rejected" =
      T (!assertionsPass hostContainerHostOnContainer) "vm.containerHost.enable on a container was accepted";
    "assertions/host-on-vm-rejected" =
      T (!assertionsPass hostHostOnVm) "`host` on a kind = \"vm\" guest was accepted";
    "types/mem-null-and-host-ok" =
      T (assertionsPass hostMemNullHost && resourceFieldsOk hostMemNullHost) "null/\"host\" mem or vcpu was rejected";
    "types/mem-bad-rejected" =
      T (!resourceFieldsOk hostMemBad) "vm.mem = -1 did not fail the type check";

    # ---- P5: mem/vcpu resolution into microvm.nix -----------------------
    "types/mem-defaults-numeric" =
      T
      (memDefaultVm.config.microvm.mem == 768 && memDefaultVm.config.microvm.vcpu == 1)
      "numeric defaults (768/1) were not passed through to microvm.nix";
    # Pinned microvm.nix default: mem = 512, vcpu = 1.
    "types/mem-null-uses-hypervisor-default" =
      T
      (memNullVm.config.microvm.mem == 512 && memNullVm.config.microvm.vcpu == 1)
      "mem/vcpu = null did not fall through to microvm.nix's defaults (512/1)";
    "types/mem-host-resolves" =
      T
      (memHostVm.config.microvm.mem == 4096 && memHostVm.config.microvm.vcpu == 8)
      "\"host\" did not resolve to tartarus.hostMemoryMiB / tartarus.hostCores";
    "types/mem-host-unset-throws" =
      T
      (let
        r = builtins.tryEval (builtins.deepSeq memHostUnsetVm.config.microvm.mem true);
      in
        !r.success)
      "\"host\" with an unset host option did not fail evaluation";

    # ---- inner containers on a container-host VM (P2 build engine) ------
    # A nested container is Linux-inner regardless of the host platform: the
    # darwin hostSystem below must not change its address/bridge.
    "platform/inner-container-addressing" =
      T
      (let
        pl = platform.mk {
          hostSystem = "aarch64-darwin";
          kind = "container";
          id = 6;
          inHostVm = true;
        };
      in
        pl.guestIP
        == "10.202.0.6"
        && pl.gateway == "10.202.0.1"
        && pl.hostGateway == "192.168.64.1"
        && pl.hostIP == "10.202.0.1"
        && pl.subnet == "10.202.0.0/24"
        && !pl.isDarwin
        && !pl.vsockAvailable
        && !pl.useVsock
        && pl.bridge == "trs2")
      "inner-container platform resolution changed";
    "platform/inner-container-constants" =
      T
      (ids.innerBridge
        == "trs2"
        && ids.innerSubnet == "10.202.0.0/24"
        && ids.innerHostIP == "10.202.0.1"
        && ids.mkInnerIP 6 == "10.202.0.6")
      "ids.nix inner constants changed";
    # A nested container on a Linux host reaches the physical host at the host
    # VM's trunk gateway (its own gateway is the inner bridge).
    "platform/inner-container-linux-host-gateway" =
      T
      (let
        pl = platform.mk {
          hostSystem = "x86_64-linux";
          kind = "container";
          id = 6;
          inHostVm = true;
        };
      in
        pl.gateway == "10.202.0.1" && pl.hostGateway == "10.200.0.1")
      "inner-container host gateway on Linux changed";

    "container-host/configurations" =
      T
      (attrNames chGuests.nixosConfigurations
        == ["ctn-inner" "vm-ch"]
        && attrNames chGuests.packages.${evalSystem} == ["vm-ch"])
      "container-host mkGuests output names changed";

    # The VM's config must declare the nested container and wire the bridge
    # model: hostBridge + privateNetwork, persistent state. `autoStart` mirrors
    # the inner guest's own `autostart`, so a non-opted-in inner stays down.
    "container-host/nested-declared" =
      T
      (chVm.config.containers ? inner
        && chVm.config.containers.inner.hostBridge == "trs2"
        && chVm.config.containers.inner.privateNetwork
        && chVm.config.containers.inner.autoStart == false
        && chVm.config.containers.inner.ephemeral == false)
      "containers.inner bridge/network flags changed";

    # Only the nested containers that opt into `autostart` come up with the VM.
    "container-host/nested-autostart-mirrors-guest" =
      T
      (chAutoVm.config.containers.inner.autoStart && !chVm.config.containers.inner.autoStart)
      "a nested container's autoStart does not mirror its own `autostart`";

    # The host CLI drives a nested container's unit over key-only root SSH
    # (`ssh root@<vm> systemctl ... container@<name>`), so the container-host VM
    # permits public-key root login with the same key the `user` account trusts.
    # A non-container-host VM keeps the base default of no root login.
    "container-host/nested-control-root-ssh" =
      T
      (chVm.config.services.openssh.settings.PermitRootLogin
        == "prohibit-password"
        && chVm.config.users.users.root.openssh.authorizedKeys.keys
        == chVm.config.users.users.user.openssh.authorizedKeys.keys
        && envLinuxGuests.nixosConfigurations."vm-vault".config.services.openssh.settings.PermitRootLogin == "no")
      "the container-host VM's root SSH for nested-container control is misconfigured";

    "container-host/nested-bindmounts" =
      T
      (chVm.config.containers.inner.bindMounts ? "/etc/tartarus/ssh"
        && chVm.config.containers.inner.bindMounts ? "/etc/tartarus/x509"
        && chVm.config.containers.inner.bindMounts."/etc/tartarus/ssh".isReadOnly
        && chVm.config.containers.inner.bindMounts."/etc/tartarus/x509".isReadOnly
        # The SSH host key is staged root-owned; the X509 client material binds
        # the live cert share directly (guest-user owned), so the ssh-agent /
        # sudo-auth clients can read `client.key`.
        && chVm.config.containers.inner.bindMounts."/etc/tartarus/ssh".hostPath
        == "/run/tartarus-inner/inner/ssh"
        && chVm.config.containers.inner.bindMounts."/etc/tartarus/x509".hostPath
        == "/var/lib/tartarus-inner/certs/x509/inner")
      "containers.inner key bind mounts are missing or wrong";

    # Feature parity: a nested container's services, relays and shares are wired
    # into the container-host VM (the VM DNATs services/relays out to the host /
    # inner address and holds the shares, then bind-mounts them inward).
    "container-host/nested-service-dnat" =
      T
      (hasInfix "ip daddr 10.202.0.1 tcp dport { 65001, 65000 } counter dnat ip to 10.200.0.1" chRichNft)
      "the nested container's host-service ports are not DNATed to the VM gateway";
    "container-host/nested-relay-dnat" =
      T
      (hasInfix "iifname \"eth0\" tcp dport 8080 counter dnat ip to 10.202.0.6:8080" chRichNft
        && hasInfix "iifname \"trs2\" ip daddr 10.202.0.1 udp dport 53 counter dnat ip to 10.202.0.6:53" chRichNft)
      "the nested container's relays are not DNATed (host and inner-service paths)";
    "container-host/nested-shares-mounted" =
      T
      (let
        byTag = tag: lib.findFirst (s: s.tag == tag) null chRichVm.config.microvm.shares;
        notes = byTag "ti6-s-notes";
        work = byTag "ti6-s-work";
        shared = byTag "ti-shared";
        certsSsh = byTag "ti-certs-ssh";
        certsX509 = byTag "ti-certs-x509";
      in
        notes
        != null
        && notes.mountPoint == "/var/lib/tartarus-inner/inner/shares/notes"
        && (notes.readOnly or false)
        && work != null
        && work.mountPoint == "/var/lib/tartarus-inner/inner/shares/work"
        && shared != null
        && shared.mountPoint == "/var/lib/tartarus-inner/shared"
        && certsSsh != null
        && certsSsh.mountPoint == "/var/lib/tartarus-inner/certs/ssh"
        && certsX509 != null
        && certsX509.mountPoint == "/var/lib/tartarus-inner/certs/x509")
      "the nested container's shares were not declared on the container-host VM";
    "container-host/nested-share-bindmounts" =
      T
      (chRichBinds ? "/home/user/notes"
        && chRichBinds ? "/home/user/work"
        && chRichBinds ? "/home/user/shared"
        && chRichBinds."/home/user/notes".isReadOnly
        && !(chRichBinds."/home/user/work".isReadOnly)
        && chRichBinds."/home/user/notes".hostPath == "/var/lib/tartarus-inner/inner/shares/notes"
        && chRichBinds."/home/user/work".hostPath == "/var/lib/tartarus-inner/inner/shares/work"
        && chRichBinds."/home/user/shared".hostPath == "/var/lib/tartarus-inner/shared/inner")
      "the nested container's shares are not bind-mounted at their guest paths";
    # Device-budget guard: on Darwin a read-only inner share is store-snapshotted
    # and bound from /nix/store rather than exported as a virtiofs device.
    "container-host/nested-rosnapshot-no-device" =
      T
      (let
        byTag = tag: lib.findFirst (s: s.tag == tag) null chDarwinVm.config.microvm.shares;
      in
        byTag "ti6-s-rosnap"
        == null
        && chDarwinBinds."/home/user/rosnap".isReadOnly
        && builtins.match "/nix/store/.*" chDarwinBinds."/home/user/rosnap".hostPath != null)
      "a store-snapshotted inner share still costs a virtiofs device";
    "container-host/nested-proxy-dnat" =
      T
      (hasInfix "ip daddr 10.202.0.1 tcp dport { 3128 } counter dnat ip to 10.200.0.1" chProxyNft)
      "the nested proxy client's port is not DNATed to the VM gateway";
    "container-host/nested-no-internet-drop" =
      T
      (hasInfix "ip saddr 10.202.0.6 oifname \"eth0\" counter drop comment \"inner-no-internet\"" chProxyFilter
        && hasInfix "ip saddr 10.202.0.6 ip daddr 10.200.0.1 counter accept" chProxyFilter)
      "a proxy-only nested container is not fenced to the VM gateway";

    # Force the nested container's own evaluation: its config must resolve with
    # inner-bridge addressing. `tryEval` so a heavy/fragile nested eval reports
    # rather than crashing the whole suite.
    "container-host/nested-config-addressing" =
      T
      (let
        r = builtins.tryEval (
          chVm.config.containers.inner.config.networking.nameservers
          == ["10.202.0.1"]
          && lib.any (a: a.address == "10.202.0.6")
          chVm.config.containers.inner.config.networking.interfaces.eth0.ipv4.addresses
        );
      in
        r.success && r.value)
      "the nested container config did not evaluate with inner addressing";

    # The inner container is still a standalone `ctn-<name>` configuration, now
    # built with inner-bridge addressing.
    "container-host/inner-standalone-addressing" =
      T
      (lib.any (a: a.address == "10.202.0.6") chInner.config.networking.interfaces.eth0.ipv4.addresses
        && chInner.config.networking.nameservers == ["10.202.0.1"]
        && chInner.config.networking.defaultGateway.address == "10.202.0.1")
      "the inner container did not evaluate with inner-bridge addressing";

    # ---- P3: nested containers are host-side absent ---------------------
    # A host with only a container-host VM and its nested container emits no
    # host `tartarus_container` table and no `trs1` container bridge.
    "p3/nested-only-no-container-table" =
      T
      (!(hostContainerHostOk.config.networking.nftables.tables ? tartarus_container))
      "a nested-only host still emitted the host tartarus_container table";
    "p3/nested-only-no-container-bridge" =
      T
      (!(hostContainerHostOk.config.systemd.network.networks ? "10-trs1"))
      "a nested-only host still declared the trs1 container bridge";
    "p3/nested-only-hostSideNames-empty" =
      T
      (hostContainerHostOk.config.tartarus.instances.container.hostSideNames == [])
      "nested-only host reported a host-side container";

    # With a native container present, the table exists and its constant set
    # lists only the native container's host-bridge address.
    "p3/mixed-container-table-present" =
      T (nestedAndNativeNft ? tartarus_container) "the mixed host did not emit the container table";
    "p3/mixed-set-has-native" =
      inStr "10.201.0.7  comment \"box\"" nestedAndNativeCtn;
    "p3/mixed-set-excludes-nested" =
      T
      (!(hasInfix "10.201.0.6" nestedAndNativeCtn) && !(hasInfix "comment \"inner\"" nestedAndNativeCtn))
      "the nested container leaked into the host container host set";
    "p3/mixed-hostSideNames" =
      T
      (hostNestedAndNative.config.tartarus.instances.container.hostSideNames == ["box"])
      "hostSideNames did not exclude the nested container";
    "p3/nested-address-is-inner" =
      T
      (hostNestedAndNative.config.tartarus.instances.guests.inner.ip
        == "10.202.0.6"
        && hostNestedAndNative.config.tartarus.instances.guests.box.ip == "10.201.0.7")
      "a nested container's plain `ip` is not its inner-bridge address";

    # Id assignment is deliberately unchanged: nested containers still consume
    # ids from the container pool and stay in `enabledNames`/`idByName`.
    "p3/enabledNames-still-full" =
      T
      (hostNestedAndNative.config.tartarus.instances.container.enabledNames == ["box" "inner"])
      "enabledNames no longer includes every enabled container";
    "p3/idByName-still-has-nested" =
      T
      (hostNestedAndNative.config.tartarus.instances.container.idByName.inner == 6)
      "idByName dropped or remapped the nested container id";

    # The host proxy ACL/listen set collapses nested clients into their
    # container-host VM (whose DNAT/SNAT makes the proxy see the VM), never the
    # inner container's own name/address.
    "p3/proxy-clients-nested-stand-in" =
      T
      (lib.elem "box" proxyNestedClientNames
        && lib.elem "ch" proxyNestedClientNames
        && !(lib.elem "inner" proxyNestedClientNames))
      "the proxy client list did not collapse nested clients to their host VM";

    # Autostart of a nested container starts its host VM, with no unit that
    # tries to start the inner container directly.
    "p3/nested-autostart-targets-host" =
      T (nestedAutostartNames == ["ch"]) "nested autostart did not target its host VM";
    "p3/nested-autostart-no-inner-unit" =
      T
      (!(hostNestedAutostart.config.systemd.user.services ? "tartarus-autostart-inner")
        && hostNestedAutostart.config.systemd.user.services ? "tartarus-autostart-ch")
      "nested autostart generated an inner unit (or omitted the host unit)";
    "p3/autostart-duplicates-deduped" =
      T (nestedAutostartDupNames == ["ch"]) "host + nested autostart were not deduped to one unit";

    # Step-7 rejections: only host proxy routing remains unimplemented for
    # nested containers.
    "p3/nested-relays-stand-in" =
      T (assertionsPass hostNestedRelays) "a nested container with relays was rejected";
    "p3/nested-service-stand-in" =
      T (assertionsPass hostNestedService) "a nested container requesting a host service was rejected";
    "p3/nested-service-stand-in-enables-server" =
      T
      (hostNestedService.config.home-manager.users.user.tartarus.sudo-auth-proxy.server.enable == true)
      "the container-host VM did not stand in for its nested container's host-service request";
    "p3/nested-proxy-stand-in" =
      T (assertionsPass hostProxyNested) "a nested container with proxy.enable was rejected";
    "p3/nested-proxy-stand-in-allowlist" =
      T
      (let
        c = lib.findFirst (x: x.name == "ch") null hostProxyNested.config.tartarus.proxy.clients;
      in
        c != null && lib.elem "nested.example" c.allowHosts)
      "the container-host VM did not carry its nested proxy client's allowlist";

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
      (hasInfix "UDP4-RECVFROM:53,bind=192.168.64.1,reuseaddr,fork UDP4:192.168.64.62:53" (concatStringsSep " " hostDarwinRelays.config.launchd.daemons."tartarus-relay-x-udp-53".serviceConfig.ProgramArguments))
      "Darwin privileged UDP relay args changed";
    "relay/darwin-tcp-privileged" =
      T (hostDarwinRelays.config.launchd.daemons ? "tartarus-relay-x-tcp-53") "privileged TCP relay is not a root launch daemon";
    "relay/darwin-user-agent" =
      T (hostDarwinRelays.config.launchd.agents ? "tartarus-relay-x-tcp-3128") "non-privileged relay is not a user launch agent";
    "relay/darwin-proxy-auto" =
      T (hostDarwinGuestProxyOk.config.launchd.agents ? "tartarus-relay-proxyvm-tcp-3128") "the guest-hosted proxy relay was not generated automatically";
    "relay/darwin-nested-targets-host-vm" =
      T
      (hostDarwinNestedRelay.config.launchd.agents ? "tartarus-relay-inner-tcp-8080"
        && hasInfix "TCP4-LISTEN:8080,bind=192.168.64.1,reuseaddr,fork TCP4:192.168.64.47:8080" darwinNestedRelayArgs)
      "a nested container's relay did not target its container-host VM";

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

    # ---- generated config.toml: schema 2 + container hosts --------------
    # Schema marker, the VM's `container_host` flag, and the nested
    # container's `host` pointer must all reach config.toml.
    "config/schema-v2" = inStr "schema = 2" containerHostToml;
    "config/container-host-flag" = inStr "container_host = true" containerHostToml;
    "config/nested-host-pointer" = inStr ''host = "ch"'' containerHostToml;
    # Every VM carries the flag (true or false); native containers do not.
    "config/container-host-flag-false" = inStr "container_host = false" configToml;
    # No VM/container in hostOk declares a `host` pointer, so no guest block
    # emits `host = "..."` (relay `host` lines would be the only other source,
    # and hostOk has none).
    "config/native-guest-no-host-pointer" = notInStr "host = \"" configToml;

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
    # `unix` transport with certificate resolution must evaluate standalone.
    "standalone/nixos-ssh-agent-proxy-unix" =
      T
      (nixosDrvOk (mkStandaloneNixos self.nixosModules."ssh-agent-proxy" {
        tartarus.ssh-agent-proxy = {
          enable = true;
          server = {
            enable = true;
            transport = "unix";
            resolution = "certificate";
            mtls.enable = true;
          };
        };
      }))
      "ssh-agent-proxy unix transport does not evaluate standalone";
    # mtls.enable is an alias for transport_encryption = "mtls": an explicit
    # `none` alongside it must be refused by the module assertion.
    "standalone/nixos-ssh-agent-proxy-mtls-conflict" =
      T
      (! (nixosDrvOk (mkStandaloneNixos self.nixosModules."ssh-agent-proxy" {
          tartarus.ssh-agent-proxy = {
            enable = true;
            server = {
              enable = true;
              transport = "vsock";
              mtls.enable = true;
              security.transportEncryption = "none";
            };
          };
        })))
      "ssh-agent-proxy accepted mtls.enable with transport_encryption = none";
    # `unix` cannot map a CID/IP, so tartarus/mofos resolution must be refused.
    "standalone/nixos-ssh-agent-proxy-unix-bad-resolution" =
      T
      (! (nixosDrvOk (mkStandaloneNixos self.nixosModules."ssh-agent-proxy" {
          tartarus.ssh-agent-proxy = {
            enable = true;
            server = {
              enable = true;
              transport = "unix";
              resolution = "tartarus";
            };
          };
        })))
      "ssh-agent-proxy accepted tartarus resolution on the unix transport";
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
    inherit
      squidDefault
      squidLogged
      vmContent
      ctnContent
      natContent
      vmForwardGuest
      ctnForwardGuest
      natGuest
      envLinux
      envGuestProxy
      envDarwin
      configToml
      containerHostToml
      ;
    vmInput = inputPart "vm" vmContent;
    ctnInput = inputPart "container" ctnContent;
    resolvedListenHost = hostOk.config.tartarus.proxy.resolvedListenAddresses;
  };
}

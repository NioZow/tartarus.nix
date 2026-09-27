# The guest engine: turns one `tartarus.guests.<name>` definition into a full
# NixOS system (`lib.nixosSystem`) and, for VMs, a runnable microvm runner.
#
# This is the port of the old `packages/tartarus/flake.nix` `mkVm`/`mkContainer`.
# Everything is derived from the option surface (`nix/host/options.nix`), the
# shared helpers (`nix/lib/*`) and the platform split (`nix/guest/platform.nix`);
# nothing reaches back into nixcfg.
#
# ---------------------------------------------------------------------------
# Deliberate impure env interface (PLAN.md §3.8 / §6)
#
# This function reads the invoking process environment via `builtins.getEnv`
# (hence `--impure`). This is the instance/shares interface: it lets the *same*
# flake attribute (e.g. `vm-vault`) produce a differently-configured build per
# invocation without editing any file. It is not a config source.
#
#   MICROVM_INSTANCE_SUFFIX   suffix for numbered `vm spawn` instances
#   MICROVM_ID_OVERRIDE       forced id/CID for a numbered VM instance
#   MICROVM_EXTRA_SHARES      JSON list of ad-hoc `vm start --mount` shares
#   TARTARUS_HOST_UID         invoking host uid (virtiofs ownership)
#   HOME                      invoking host home (share sources, pubkey)
#
# Container instances use CONTAINER_INSTANCE_SUFFIX / CONTAINER_ID_OVERRIDE.
# ---------------------------------------------------------------------------
{
  lib,
  inputs,
  self ? null,
  system,
  hostSystem,
  homeDir ? "/home/user",
  nixVersion,
  config,
  guestPkgs,
  hostPkgs,
}: let
  platformLib = import ./platform.nix {inherit lib;};
  ids = import ../lib/ids.nix {inherit lib;};

  # ==== impure instance/shares interface (see header) ====
  homeEnv = builtins.getEnv "HOME";
  hostHome =
    if homeEnv != ""
    then homeEnv
    else homeDir;

  hostUidRaw = builtins.getEnv "TARTARUS_HOST_UID";
  hostUid =
    if hostUidRaw == ""
    then null
    else lib.toInt hostUidRaw;
  # NixOS forbids isNormalUser accounts with uid < 1000 (macOS's first-user uid
  # 501 hits this); isSystemUser is the escape hatch used in base.nix.
  lowHostUid = hostUid != null && hostUid < 1000;

  vmInstanceSuffix = builtins.getEnv "MICROVM_INSTANCE_SUFFIX";
  vmIdOverride = builtins.getEnv "MICROVM_ID_OVERRIDE";
  vmExtraSharesRaw = builtins.getEnv "MICROVM_EXTRA_SHARES";
  ctnInstanceSuffix = builtins.getEnv "CONTAINER_INSTANCE_SUFFIX";
  ctnIdOverride = builtins.getEnv "CONTAINER_ID_OVERRIDE";

  # proto is normalized to the platform in shares.nix; only the tag/source/
  # mountPoint matter here.
  vmExtraShares =
    if vmExtraSharesRaw == "" || vmExtraSharesRaw == "[]"
    then []
    else
      lib.imap0 (i: s: {
        tag = "extra${toString i}";
        source = s.source;
        mountPoint = s.mountPoint;
      }) (builtins.fromJSON vmExtraSharesRaw);

  # ==== host config (both required to be present; both defaulted for a
  # hand-written sample config) ====
  guests = config.tartarus.guests or {};
  globalProxy = config.tartarus.proxy or {};

  # Host-level ceilings backing `vm.mem = "host"` / `vm.vcpu = "host"` (plan
  # §8). Read from the consumer's evaluated host config; a hand-written sample
  # config may omit them, which is fine until a guest actually asks for "host".
  hostMemoryMiB = (config.tartarus or {}).hostMemoryMiB or null;
  hostCores = (config.tartarus or {}).hostCores or null;

  # Resolve the proxy endpoint a guest should use. `location = "host"` (the
  # default) means the guest-side host gateway. A guest name means that VM's
  # trunk IP on Linux. On Darwin it also means the host gateway: vfkit/vmnet
  # shared mode marks the bridge ports PRIVATE, so guests cannot reach each
  # other, and a guest-hosted proxy is reached through the host's socat relay
  # (see host/proxy.nix). Returns null whenever the gateway is the answer, so
  # platform.nix supplies it.
  proxyHostFor = let
    location = globalProxy.location or "host";
  in
    if location == "host" || !(globalProxy.enable or false)
    then null
    else let
      target = guests.${location} or null;
      targetKind =
        if target != null
        then target.kind
        else "vm";
      kindGuests = lib.filterAttrs (_: gg: gg.enable && gg.kind == targetKind) guests;
      targetId = (ids.assignIds kindGuests).${location} or null;
    in
      if targetId == null
      then null
      else if targetKind == "vm"
      then
        (
          if lib.hasSuffix "-darwin" hostSystem
          then null
          else ids.mkVmIP targetId
        )
      else ids.mkCtnIP targetId;

  # One `mkService` factory per module system. The guest itself is always Linux
  # (`isDarwin = false`); system scope is homeManager = false, home-manager scope
  # is homeManager = true.
  mintService = homeManager:
    inputs.nix-service.lib.mkService {
      inherit lib;
      isDarwin = guestPkgs.stdenv.isDarwin;
      username = "user";
      inherit homeManager;
    };
  mkServiceSystem = mintService false;
  mkServiceHome = mintService true;

  pkgsUnstable = import inputs.nixpkgs-unstable {
    inherit system;
    config.allowUnfree = true;
  };

  # The resolved guest description handed to every guest module through
  # `specialArgs.tartarusGuest`.
  mkGuest = {
    kind,
    name,
    baseName,
    id,
    cfg,
    # True for a nested container running inside a container-host VM.
    inHostVm ? false,
    # The container-host VM's inner containers, each `{ name, id, cfg }`
    # (supplied by mkGuests). Empty for every other guest, so hand-written
    # sample configs keep working.
    innerContainers ? [],
  }: let
    proxyHost = proxyHostFor;
    platform = platformLib.mk {
      inherit hostSystem kind id proxyHost inHostVm;
      disableVsock = (cfg.services or {}).disableVsock or false;
      proxyPort = globalProxy.port or 3128;
    };

    # Normalize to the option-surface shape so the guest modules can rely on it
    # even when `config` is a hand-written sample rather than a fully evaluated
    # `nixosConfigurations.<host>.config`.
    services =
      {
        clipboardBridge = false;
        sshAgentProxy = false;
        sudoAuthProxy = false;
        # The per-guest sudo-auth-proxy transport marker (audit A1). Normalized
        # here so a hand-written sample config that predates the option still
        # resolves; a fully evaluated `tartarus.guests.<name>.services` already
        # carries the option default.
        sudoAuthProxyTransport = "vsock";
        gpgAgentProxy = false;
        disableVsock = false;
      }
      // (cfg.services or {});

    vmDefaults = {
      vcpu = 1;
      mem = 768;
      persistentHome = {
        enable = false;
        size = 5120;
      };
      nixStoreOverlay = {
        size = 2048;
      };
      # Defaults mirror `nix/lib/types.nix`'s containerHost submodule so a
      # hand-written sample config (which skips the submodule) still resolves.
      containerHost = {
        enable = false;
        stateVolume = {
          size = 10240;
        };
        network = {
          bridge = ids.innerBridge;
          hostIP = ids.innerHostIP;
          subnet = ids.innerSubnet;
        };
      };
    };
    vmCfg = cfg.vm or {};
    chCfg = vmCfg.containerHost or {};
    vm =
      vmDefaults
      // vmCfg
      // {
        persistentHome = vmDefaults.persistentHome // (vmCfg.persistentHome or {});
        nixStoreOverlay = vmDefaults.nixStoreOverlay // (vmCfg.nixStoreOverlay or {});
        containerHost =
          vmDefaults.containerHost
          // chCfg
          // {
            stateVolume = vmDefaults.containerHost.stateVolume // (chCfg.stateVolume or {});
            network = vmDefaults.containerHost.network // (chCfg.network or {});
          };
      };

    proxyCfg = cfg.proxy or {};
  in {
    inherit
      kind
      name
      baseName
      id
      platform
      hostHome
      hostUid
      lowHostUid
      inHostVm
      ;

    isVm = platform.isVm;

    # A VM that hosts nested systemd-nspawn containers. Only such a VM pulls in
    # ./container-host.nix and the inner key-material shares.
    isContainerHost = kind == "vm" && (cfg.vm.containerHost.enable or false);
    # The inner containers as plain `{ name, id }` records so shares.nix can
    # declare their key-material shares without re-deriving the container ids.
    innerContainers = map (inner: {inherit (inner) name id;}) innerContainers;

    graphical = cfg.graphical or false;
    internet = cfg.internet or true;
    sharedFolder = cfg.sharedFolder or false;
    apps = cfg.apps or [];
    autostart = cfg.autostart or false;
    firewall = cfg.firewall or {};
    systemConfig = cfg.systemConfig or {};
    userConfig = cfg.userConfig or {};

    inherit services vm;

    shares = cfg.shares or [];
    extraShares =
      if kind == "vm"
      then vmExtraShares
      else [];
    inherit nixVersion;

    # The guest account is always "user" @ the guest home; `homeDir`/`HOME`
    # above are the *host's* home, used only for share sources and the pubkey.
    user = {
      name = "user";
      home = "/home/user";
    };

    proxy = {
      enable = proxyCfg.enable or false;
      allowHosts = proxyCfg.allowHosts or [];
      host = platform.resolvedProxyHost;
      port = globalProxy.port or 3128;
      log = globalProxy.log or false;
      # True for the single guest named by `tartarus.proxy.location`; that guest
      # runs the Squid server (see guest/proxy.nix). The host evaluation has
      # already resolved the client list and the allowlists, so pass them
      # through verbatim rather than recomputing them here.
      isProxyHost = (globalProxy.enable or false) && (globalProxy.location or "host") == baseName;
      clients = globalProxy.clients or [];
    };
  };

  # Rootless virtiofsd launcher for Linux/QEMU virtiofs shares. Ported verbatim
  # from the old flake: microvm.nix's own virtiofsd-run is only wired by its
  # declarative host module (which tartarus does not use), and hardcodes root,
  # conflicting with tartarus's unprivileged-launch design.
  virtiofsdModule = {
    config,
    lib,
    pkgs,
    ...
  }: let
    virtiofsShares = builtins.filter (s: s.proto == "virtiofs") config.microvm.shares;
    needsVirtiofsd = virtiofsShares != [] && config.microvm.hypervisor == "qemu";
  in {
    microvm.preStart = lib.mkIf needsVirtiofsd (lib.mkAfter ''
      ${lib.concatMapStrings (share: ''
          ${lib.getExe config.microvm.virtiofsd.package} \
            --socket-path=${lib.escapeShellArg share.socket} \
            --shared-dir=${lib.escapeShellArg share.source} \
            --cache=${share.cache} \
            --sandbox none \
            ${lib.optionalString share.readOnly "--readonly"} \
            ${lib.concatStringsSep " " share.extraArgs} \
            &
          virtiofsd_pids="''${virtiofsd_pids:-} $!"
        '')
        virtiofsShares}

      all_up=0
      for _ in $(${lib.getExe' pkgs.coreutils "seq"} 1 100); do
        all_up=1
        ${lib.concatMapStrings (share: ''
          [ -S ${lib.escapeShellArg share.socket} ] || all_up=0
        '')
        virtiofsShares}
        if [ "$all_up" = 1 ]; then
          break
        fi
        ${lib.getExe' pkgs.coreutils "sleep"} 0.05
      done
      if [ "$all_up" != 1 ]; then
        echo "tartarus: virtiofsd socket(s) never appeared, aborting" >&2
        kill $virtiofsd_pids 2>/dev/null || true
        exit 1
      fi
    '');
  };

  mkSpecialArgs = guest: {
    inherit inputs self system nixVersion;
    tartarusGuest = guest;
    mkServiceSystem = mkServiceSystem;
    # System-scope alias for the guest's own units (mirrors the old builder).
    mkService = mkServiceSystem;
    # home.nix forwards this into the home-manager specialArgs.
    mkServiceHome = mkServiceHome;
    pkgs-unstable = pkgsUnstable;
  };

  # Resolve one resource ceiling (plan §8). `null` means "let microvm.nix's own
  # default apply" and is returned as null so mkVmHardware omits the definition;
  # a positive integer is passed through unchanged; `"host"` is resolved to the
  # matching host option (`tartarus.hostMemoryMiB` / `tartarus.hostCores`).
  #
  # Route chosen: explicit host options, not a runner prelude. microvm.nix's
  # only runtime hook (`microvm.extraArgsScript`) merely *appends* arguments to
  # the hypervisor command, while its runners always emit `--memory`/`--cpus`
  # from `microvm.mem`/`microvm.vcpu`, so a runtime override would mean
  # duplicate hypervisor flags. An explicit, rebuild-time option is unambiguous
  # and keeps a fixed RAM size at boot (which hypervisors require).
  resolveCeiling = {
    guestName,
    field,
    optionName,
    hostValue,
    value,
  }:
    if value == null
    then null
    else if value == "host"
    then
      if hostValue != null
      then hostValue
      else
        throw ''
          tartarus: guest "${guestName}" sets vm.${field} = "host" but
          ${optionName} is not set on this host. Set it to the host's ${
            if field == "mem"
            then "physical RAM in MiB"
            else "CPU count"
          } so the ceiling can be resolved at evaluation time.
        ''
    else value;

  # VM-only microvm.nix hardware wiring: hypervisor, CPU/RAM, the trunk
  # interface and VSOCK CID, all derived from the resolved platform/guest.
  # Shares live in guest/shares.nix, the store overlay in guest/store-overlay.nix.
  mkVmHardware = guest: _: let
    resolvedVcpu = resolveCeiling {
      guestName = guest.baseName;
      field = "vcpu";
      optionName = "tartarus.hostCores";
      hostValue = hostCores;
      value = guest.vm.vcpu;
    };
    resolvedMem = resolveCeiling {
      guestName = guest.baseName;
      field = "mem";
      optionName = "tartarus.hostMemoryMiB";
      hostValue = hostMemoryMiB;
      value = guest.vm.mem;
    };
  in {
    microvm =
      {
        hypervisor = guest.platform.hypervisor;
        kernelParams = ["net.ifnames=0"];
        vsock.cid = guest.platform.vsockCid;
        # QEMU, socat, jq, ... in the generated runner must be host-native
        # (darwin) binaries, not the guest's Linux packages.
        vmHostPackages = hostPkgs;
        interfaces =
          if guest.platform.isDarwin
          then [
            {
              type = "user";
              id = "vfkit-net0";
              mac = ids.mkMac guest.id;
            }
          ]
          else [
            {
              type = "bridge";
              id = guest.platform.bridge;
              bridge = guest.platform.bridge;
              mac = ids.mkMac guest.id;
            }
          ];
      }
      # `mkIf` keeps the attribute names always present (so module merging never
      # forces a "host" resolution) while still falling through to microvm.nix's
      # own default when the value is null.
      // {
        vcpu = lib.mkIf (resolvedVcpu != null) resolvedVcpu;
        mem = lib.mkIf (resolvedMem != null) resolvedMem;
      };
  };

  # `innerContainers` is the VM's nested container list (`{ name, id, cfg }`),
  # supplied by mkGuests; empty for a plain VM.
  mkVm = name: cfg: innerContainers: let
    vmName =
      if vmInstanceSuffix == ""
      then name
      else "${name}-${vmInstanceSuffix}";
    vmId =
      if vmIdOverride == ""
      then cfg.id
      else lib.toInt vmIdOverride;
    guest = mkGuest {
      kind = "vm";
      name = vmName;
      baseName = name;
      id = vmId;
      inherit cfg innerContainers;
    };

    # Resolve each inner container through the same guest engine, flagged
    # `inHostVm` so it addresses itself on the VM-local inner bridge. The
    # records are handed to container-host.nix, which declares them as
    # `containers.<name>` inside the VM. `modules`/`specialArgs` are exactly
    # what the top-level `ctn-<name>` configuration gets, so the nested and
    # standalone evaluations stay in lockstep.
    innerRecords =
      map (
        inner: let
          innerGuest = mkGuest {
            kind = "container";
            name = inner.name;
            baseName = inner.name;
            id = inner.id;
            cfg = inner.cfg;
            inHostVm = true;
          };
        in {
          inherit (inner) name id;
          modules = [
            inputs.home-manager.nixosModules.home-manager
            ./default.nix
          ];
          specialArgs = mkSpecialArgs innerGuest;
        }
      )
      innerContainers;
  in
    lib.nixosSystem {
      inherit system;
      pkgs = guestPkgs;
      specialArgs = mkSpecialArgs guest;
      modules =
        [
          inputs.microvm.nixosModules.microvm
          (mkVmHardware guest)
          virtiofsdModule
          inputs.home-manager.nixosModules.home-manager
          ./default.nix
        ]
        ++ lib.optional guest.isContainerHost (import ./container-host.nix {innerContainers = innerRecords;});
    };

  mkContainer = name: cfg: let
    ctrName =
      if ctnInstanceSuffix == ""
      then name
      else "${name}-${ctnInstanceSuffix}";
    ctrId =
      if ctnIdOverride == ""
      then cfg.id
      else lib.toInt ctnIdOverride;
    guest = mkGuest {
      kind = "container";
      name = ctrName;
      baseName = name;
      id = ctrId;
      inherit cfg;
      # A container with a `host` pointer runs nested inside that
      # container-host VM; it uses the VM-local inner bridge addressing.
      inHostVm = (cfg.host or null) != null;
    };
  in
    lib.nixosSystem {
      inherit system;
      pkgs = guestPkgs;
      specialArgs = mkSpecialArgs guest;
      modules = [
        inputs.home-manager.nixosModules.home-manager
        ./default.nix
      ];
    };
in {
  inherit mkVm mkContainer;
}

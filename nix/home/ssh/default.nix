# Home-manager client-side SSH configuration for tartarus guests.
#
# This is intentionally a separate home-manager module rather than part of the
# tartarus host (NixOS/nix-darwin) module: it writes the *user's* `~/.ssh`
# config, and a standalone home-manager setup may not have a tartarus host at
# all. The generated host blocks live in their own fragment
# (`~/.ssh/config.d/tartarus` by default) and are pulled in through
# `programs.ssh.includes`, so they never mix with the rest of the user's SSH
# configuration.
#
# Enable it per host with:
#
#   tartarus.ssh.client.enable = true;
{
  config,
  lib,
  pkgs,
  osConfig ? {},
  ...
}: let
  inherit
    (lib)
    mkEnableOption
    mkOption
    types
    ;

  inherit (import ../../lib/ssh-config.nix {inherit lib;}) mkBlock mkFile;

  cfg = config.tartarus.ssh.client;

  isDarwin = pkgs.stdenv.isDarwin;
  isLinux = pkgs.stdenv.isLinux;

  # Standalone home-manager has no `osConfig` (or leaves it null).
  hostConfig =
    if osConfig == null
    then {}
    else osConfig;

  # Derived guest data published by tartarus's host module.
  tartarus = hostConfig.tartarus or {};
  instances = tartarus.instances or {};
  guests = instances.guests or {};

  vmEnabledNames = instances.vm.enabledNames or [];
  vmIdByName = instances.vm.idByName or {};
  ctrIdByName = instances.container.idByName or {};

  vmGuests = lib.filterAttrs (_: g: g.enable && g.kind == "vm") guests;
  ctrGuests = lib.filterAttrs (_: g: g.enable && g.kind == "container") guests;
  # A nested container (`host = "<vm>"`) has no host-reachable bridge address;
  # it is reached by ProxyJump through its container-host VM, so it must not
  # get the direct `10.201.0.<id>` block.
  nativeCtrGuests = lib.filterAttrs (_: g: (g.host or null) == null) ctrGuests;
  nestedCtrGuests = lib.filterAttrs (_: g: (g.host or null) != null) ctrGuests;

  hasEnabledVms = vmEnabledNames != [];

  mkIP = id: "10.200.0.${toString id}";

  # Every tartarus guest authenticates with the one shared key
  # (`~/.ssh/tartarus`), whether it is a MicroVM or a container. Pin ssh to
  # exactly that key and keep it away from the user's ssh-agent: with an agent
  # loaded, ssh otherwise offers every agent identity before the IdentityFile,
  # hitting MaxAuthTries ("Too many authentication failures") first.
  # `IdentityAgent none` stops ssh from contacting the agent at all for these
  # hosts; `IdentitiesOnly` restricts it to the listed IdentityFile.
  guestIdentity = key: {
    IdentityFile = key;
    IdentitiesOnly = "yes";
    IdentityAgent = "none";
  };

  vsockVm = g: isLinux && g.kind == "vm" && !(g.services.disableVsock or false);

  mkCtrIP = id: "10.201.0.${toString id}";

  mkContainerEntry = ctrName: ctrId: extraAttrs:
    {
      user = "user";
      hostname = mkCtrIP ctrId;
      port = 22;
      HostKeyAlias = "${ctrName}.trs";
      StrictHostKeyChecking =
        if cfg.strictHostKeyChecking
        then "yes"
        else null;
      ControlMaster = "auto";
      ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
      StreamLocalBindUnlink = "yes";
      ExitOnForwardFailure = "yes";
    }
    // guestIdentity "~/.ssh/tartarus"
    // mkGpgForward ctrName
    // extraAttrs;

  mkNestedContainerEntry = ctrName: g:
    {
      user = "user";
      ProxyJump = "${g.host}.trs";
      port = 22;
      HostKeyAlias = "${ctrName}.trs";
      userKnownHostsFile = "~/.ssh/known_hosts_trs";
      StrictHostKeyChecking =
        if cfg.strictHostKeyChecking
        then "yes"
        else null;
      ControlMaster = "auto";
      ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
      StreamLocalBindUnlink = "yes";
      ExitOnForwardFailure = "yes";
    }
    // guestIdentity "~/.ssh/tartarus"
    // mkGpgForward ctrName;

  manualJumpEntries =
    map (j: mkBlock j.name (mkContainerEntry j.name j.id {ProxyJump = j.via;}))
    cfg.containerJumps;

  # ---- tartarus GPG agent forwarding -------------------------------------
  wantsGpg = name: (guests.${name}.services or {}).gpgAgentProxy or false;

  hostGpgSocket =
    if isDarwin
    then "${config.home.homeDirectory}/.gnupg/S.gpg-agent.extra"
    else "/run/user/${toString cfg.tartarusUid}/gnupg/S.gpg-agent.extra";

  guestGpgSocket = "/run/user/${toString cfg.tartarusUid}/gnupg/S.gpg-agent";

  mkGpgForward = name:
    lib.optionalAttrs (wantsGpg name) {
      RemoteForward = [
        {
          bind.address = guestGpgSocket;
          host.address = hostGpgSocket;
        }
      ];
    };

  mkGpgTrsBlock = vmName:
    mkBlock "${vmName}.trs" ({
        user = "user";
        port = 22;
        userKnownHostsFile = "~/.ssh/known_hosts_trs";
        ProxyCommand = "${pkgs.tartarus}/bin/tartarus ${
          if isDarwin
          then "proxy-ip"
          else "proxy"
        } %h";
        ControlMaster = "auto";
        ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
        StreamLocalBindUnlink = "yes";
        ExitOnForwardFailure = "yes";
        StrictHostKeyChecking =
          if cfg.strictHostKeyChecking
          then "yes"
          else null;
      }
      // guestIdentity "~/.ssh/tartarus"
      // mkGpgForward vmName);

  gpgVmGuests = lib.filterAttrs (n: _: wantsGpg n) vmGuests;

  # Linux per-VM entries: every enabled VM gets a bare-name Host block so
  # `ssh <name>` (as `tartarus ssh <name>` execs) works, not just
  # `<name>.trs` through the wildcard below. VSOCK-enabled VMs reach the
  # guest through `tartarus proxy <name>`; the rest use their static
  # 10.200.0.<id> bridge IP. HostKeyAlias pins the CA-signed
  # "<name>.trs" principal so the `@cert-authority` line in
  # known_hosts_trs verifies the guest host cert (no "unknown host key").
  linuxVmBlocks =
    lib.mapAttrsToList (
      vmName: g:
        mkBlock vmName ({
            user = "user";
            HostKeyAlias = "${vmName}.trs";
            userKnownHostsFile = "~/.ssh/known_hosts_trs";
            port = 22;
            StrictHostKeyChecking =
              if cfg.strictHostKeyChecking
              then "yes"
              else null;
            ControlMaster = "auto";
            ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
            StreamLocalBindUnlink = "yes";
            ExitOnForwardFailure = "yes";
          }
          // (
            if cfg.vmVsock && vsockVm g
            then {
              ProxyCommand = "${pkgs.tartarus}/bin/tartarus proxy ${vmName}";
            }
            else {
              hostname = mkIP vmIdByName.${vmName};
            }
          )
          // guestIdentity "~/.ssh/tartarus"
          // mkGpgForward vmName)
    )
    vmGuests;

  # macOS per-VM entries: `ssh <name>` (as `tartarus ssh <name>` does)
  # must reach the guest without the caller guessing the vmnet IP.
  # Each enabled VM gets a Host block that proxies to its deterministic
  # static address at connect time; the HostKeyAlias pins the CA-signed
  # "<name>.trs" principal so verification matches the guest cert.
  darwinVmBlocks =
    lib.mapAttrsToList (
      vmName: _:
        mkBlock vmName ({
            user = "user";
            HostKeyAlias = "${vmName}.trs";
            userKnownHostsFile = "~/.ssh/known_hosts_trs";
            ProxyCommand = "${pkgs.tartarus}/bin/tartarus proxy-ip ${vmName}";
            StrictHostKeyChecking =
              if cfg.strictHostKeyChecking
              then "yes"
              else null;
            ControlMaster = "auto";
            ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
            StreamLocalBindUnlink = "yes";
            ExitOnForwardFailure = "yes";
          }
          // guestIdentity "~/.ssh/tartarus"
          // mkGpgForward vmName)
    )
    vmGuests;

  # "*.trs" is only ever wired up for VMs -- containers get a fully
  # self-contained block per name instead (see mkContainerEntry above),
  # since a container connection needs no ProxyCommand and a shared
  # wildcard would otherwise force VSOCK settings onto container
  # connections too (both guest kinds share the "trs" TLD now that
  # they share one CA -- see tartarus's host ca module).
  linuxTrsBlock = mkBlock "*.trs" (
    {
      user = "user";
      port = 22;
      userKnownHostsFile = "~/.ssh/known_hosts_trs";
      ProxyCommand = "${pkgs.tartarus}/bin/tartarus proxy %h";
      ControlMaster = "auto";
      ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
      StreamLocalBindUnlink = "yes";
      ExitOnForwardFailure = "yes";
    }
    // guestIdentity "~/.ssh/tartarus"
  );

  darwinTrsBlock = mkBlock "*.trs" (
    {
      user = "user";
      port = 22;
      userKnownHostsFile = "~/.ssh/known_hosts_trs";
      ProxyCommand = "${pkgs.tartarus}/bin/tartarus proxy-ip %h";
      ControlMaster = "auto";
      ControlPath = "~/.ssh/controlmaster/%r@%h:%p";
      StreamLocalBindUnlink = "yes";
      ExitOnForwardFailure = "yes";
    }
    // guestIdentity "~/.ssh/tartarus"
  );

  nativeCtrBlocks =
    lib.mapAttrsToList (
      ctrName: _:
        mkBlock ctrName (mkContainerEntry ctrName ctrIdByName.${ctrName} {})
    )
    nativeCtrGuests;

  nestedCtrBlocks =
    lib.mapAttrsToList (
      ctrName: g: mkBlock ctrName (mkNestedContainerEntry ctrName g)
    )
    nestedCtrGuests;

  configFile = mkFile "# Managed by tartarus (tartarus.ssh.client); do not edit." (
    lib.optionals (isLinux && hasEnabledVms) linuxVmBlocks
    # GPG-forwarding VMs get an explicit "<name>.trs" block ahead of the
    # wildcard so the RemoteForward is scoped to them (the wildcard would
    # otherwise forward the agent for every VM).
    ++ lib.optionals hasEnabledVms (lib.mapAttrsToList (vmName: _: mkGpgTrsBlock vmName) gpgVmGuests)
    ++ lib.optionals (isLinux && hasEnabledVms) [linuxTrsBlock]
    ++ lib.optionals (isDarwin && hasEnabledVms) darwinVmBlocks
    ++ lib.optionals (isDarwin && hasEnabledVms) [darwinTrsBlock]
    ++ nativeCtrBlocks
    ++ nestedCtrBlocks
    ++ manualJumpEntries
  );

  defaultTartarusUid =
    if isDarwin
    then 501
    else let
      hostUser = (hostConfig.users.users or {}).${config.home.username} or null;
    in
      if hostUser != null && (hostUser.uid or null) != null
      then hostUser.uid
      else 1000;
in {
  options.tartarus.ssh.client = {
    enable = mkEnableOption "the tartarus SSH client configuration";

    configFile = mkOption {
      type = types.str;
      default = ".ssh/config.d/tartarus";
      description = ''
        Path of the generated SSH config fragment, relative to the home
        directory. It is included from the user's SSH config through
        `programs.ssh.includes`; the file is managed by home-manager.
      '';
    };

    include = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Add `configFile` to `programs.ssh.includes`. Disable this only when the
        including config is managed elsewhere.
      '';
    };

    strictHostKeyChecking = mkOption {
      type = types.bool;
      default = true;
      description = "Reject connections to tartarus guests not present in known_hosts (StrictHostKeyChecking yes).";
    };

    vmVsock = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Reach MicroVMs over AF_VSOCK through a socat ProxyCommand instead of
        their bridge IP. Only applies to VMs that opt into VSOCK (i.e. not
        `services.disableVsock`); the others keep their `10.200.0.x` entry.
      '';
    };

    containerJumps = mkOption {
      type = types.listOf (types.submodule {
        options = {
          name = mkOption {
            type = types.str;
            description = "SSH host alias for the container.";
          };
          id = mkOption {
            type = types.int;
            description = "Container ID (gives IP 10.201.0.<id> on the trs1 bridge inside the VM).";
          };
          via = mkOption {
            type = types.str;
            description = "SSH host alias to ProxyJump through (the VM running the container).";
          };
        };
      });
      default = [];
      description = ''
        Explicit container ProxyJump entries. Use this on Darwin or standalone
        home-manager where `osConfig.tartarus` is not available. Each entry
        generates an SSH Host block that reaches the container through the
        specified VM alias.

        On NixOS hosts, prefer declaring the container directly as
        `tartarus.guests.<name>.kind = "container"`.
      '';
    };

    tartarusUid = mkOption {
      type = types.int;
      default = defaultTartarusUid;
      defaultText = lib.literalExpression "the invoking host user's uid (501 on Darwin, 1000 if unknown)";
      description = ''
        UID shared by the host user and its tartarus guest users (tartarus runs
        guests as the invoking host uid). Used to locate the guest-side gpg-agent
        runtime socket (`/run/user/<uid>/gnupg/S.gpg-agent`) when a guest enables
        `services.gpgAgentProxy`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    programs.ssh = lib.mkMerge [
      {
        enable = lib.mkDefault true;
        enableDefaultConfig = lib.mkDefault false;
      }

      (lib.mkIf cfg.include {
        includes = lib.mkOrder 1100 ["~/${cfg.configFile}"];
      })
    ];

    home.file."${cfg.configFile}".text = configFile;
  };
}

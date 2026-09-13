# The unified `tartarus.*` host option surface: `tartarus.proxy` holds only
# global transport config (never filtering), and `tartarus.guests.<name>` holds
# the per-guest metadata + host-enforced networking.
{lib, ...}: let
  inherit
    (lib)
    mkEnableOption
    mkOption
    types
    ;
  shared = import ../lib/types.nix {inherit lib;};
in {
  options.tartarus.proxy = {
    enable = mkEnableOption "the tartarus HTTP proxy";

    location = mkOption {
      type = types.str;
      default = "host";
      description = ''
        Where the proxy runs: `"host"` (default) or the name of an enabled
        `kind = "vm"` guest with `internet = true`. Darwin hosts only support
        `"host"`. This is global transport config only -- filtering is per
        guest.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 3128;
      description = "TCP port the proxy listens on.";
    };

    listenAddresses = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = ''
        Addresses the proxy binds. When null, they are derived from the enabled
        guest kinds (the trs bridges, or the vmnet gateway on Darwin); the
        proxy never binds loopback.
      '';
    };

    log = mkOption {
      type = types.bool;
      default = false;
      description = "Log proxy metadata (client IP, CONNECT host) to journald.";
    };
  };

  options.tartarus.guests = mkOption {
    type = types.attrsOf (types.submodule {
      options = {
        enable = mkEnableOption "this tartarus guest";

        kind = mkOption {
          type = types.enum ["vm" "container"];
          default = "vm";
          description = "Guest kind: a QEMU/vfkit MicroVM or a systemd-nspawn container.";
        };

        id = mkOption {
          type = shared.idType;
          default = null;
          description = ''
            Force a specific guest ID, which determines its IP, MAC, and (for
            VMs) VSOCK CID. Valid static IDs are 3-100; when null the ID is
            auto-assigned starting at 101.
          '';
        };

        graphical = mkEnableOption "graphical remote-display support for this guest";

        internet = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Allow this guest direct internet egress via NAT. Mutually exclusive
            with `proxy.enable = true`.
          '';
        };

        sharedFolder = mkOption {
          type = types.bool;
          default = false;
          description = "Mount a per-guest host directory at ~/shared inside the guest.";
        };

        shares = mkOption {
          type = types.listOf shared.shareType;
          default = [];
          description = ''
            Extra host<->guest directory shares, passed through to the guest
            engine (microvm.shares). Each entry needs at least `tag`, `source`
            and `mountPoint`; `proto` is normalized to the host platform by the
            engine, and writable Linux 9p shares automatically get the `mapped`
            security model plus an ownership fixup.

            `readOnly = true` makes the share read-only for the guest. On Linux
            the hypervisor enforces this; on macOS/vfkit, which ignores it, the
            engine instead copies `source` into the Nix store and shares that,
            since store paths are root-owned and non-writable (see
            `docs/shares.md`). Because that copy is world-readable, set
            `snapshot = false` on a read-only share that contains secrets;
            sources under `/nix/store` and `/run` are never copied.
          '';
        };

        apps = mkOption {
          type = types.listOf shared.appType;
          default = [];
          description = ".desktop applications created on the host that run inside this guest via the graphical tunnel.";
        };

        autostart = mkOption {
          type = types.bool;
          default = false;
          description = "Start this guest automatically on login via a tartarus user service.";
        };

        requires = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "Names of other enabled guests that must be started before this one. tartarus start/spawn/autostart start them first; the graph must be acyclic.";
        };

        relays = mkOption {
          type = types.listOf shared.relay;
          default = [];
          description = ''
            Host-side port forwards into this guest, exposed on the vmnet
            gateway. Darwin-only: vfkit's vmnet-shared mode gives guests no
            path to each other and the host cannot route to a guest service
            through the gateway, so a userspace relay (socat) is needed. On
            Linux direct routing already reaches the guest, so these are
            ignored. Ports below 1024 are run as a root service.
          '';
        };

        services = mkOption {
          type = shared.serviceFlags;
          default = {};
          description = "Tartarus-owned guest/host service integrations.";
        };

        vm = mkOption {
          type = shared.vmExtras;
          default = {};
          description = "VM-only extras (vcpu, mem, persistent home, nix store overlay); ignored for containers.";
        };

        firewall = mkOption {
          type = shared.firewall;
          default = {};
          description = "Tartarus-managed firewall for this guest.";
        };

        proxy = mkOption {
          type = shared.proxyPerGuest;
          default = {};
          description = "Per-guest proxy filtering, merged with the global `tartarus.proxy` transport config.";
        };

        systemConfig = mkOption {
          type = types.unspecified;
          default = {};
          description = "User-defined NixOS configuration for this guest (packages, secrets, overlays, ...).";
        };

        userConfig = mkOption {
          type = types.unspecified;
          default = {};
          description = "User-defined home-manager configuration for this guest.";
        };
      };
    });
    default = {};
    description = "Declarative tartarus guest definitions.";
  };
}

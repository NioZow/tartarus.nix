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

  # A `--private-users` value: nspawn's modes plus a numeric UID/GID base.
  # Shared by the host-wide default and the per-guest override.
  privateUsersType = types.either types.ints.u32 (types.enum ["no" "identity" "pick"]);
in {
  options.tartarus.proxy = {
    enable = mkEnableOption "the tartarus HTTP proxy";

    location = mkOption {
      type = types.str;
      default = "host";
      description = ''
        Where the proxy runs: `"host"` (default) or the name of an enabled
        `kind = "vm"` or `kind = "container"` guest with `internet = true`.
        Darwin hosts only support `"host"`. This is global transport config
        only -- filtering is per guest.
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

  options.tartarus.dns = {
    location = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Name of the enabled guest that is the resolver for all guests on this
        host. When set, the firewall accepts DNS traffic (UDP/TCP 53) from every
        guest kind to that resolver. `null` (default) disables the carve-out.
      '';
    };
  };

  # Passwordless sudo for the `container@<name>` units the tartarus CLI drives.
  # Starting/stopping a container is a root operation (`sudo systemctl start
  # container@<name>`, see src/tartarus/ctn.py), so without this every
  # `tartarus start`/`stop` prompts. Enabling it adds a scoped `NOPASSWD` rule
  # for `systemctl <verb> container@*` only; nothing else is unlocked.
  options.tartarus.containers.sudoNoPassword = {
    enable = mkEnableOption "passwordless sudo for `systemctl <verb> container@*` (starting/stopping tartarus containers)";

    verbs = mkOption {
      type = types.listOf (types.enum ["start" "stop" "restart"]);
      default = ["start"];
      description = "`systemctl` verbs granted without a password.";
    };

    users = mkOption {
      type = types.listOf (types.either types.str types.int);
      default = [];
      description = "Users granted the passwordless container rule.";
    };

    groups = mkOption {
      type = types.listOf (types.either types.str types.int);
      default = ["wheel"];
      description = "Groups granted the passwordless container rule.";
    };
  };

  # Host-wide default user namespace for every `kind = "container"` guest. The
  # per-guest `tartarus.guests.<name>.privateUsers` overrides it (including back
  # to `"no"`); VMs ignore it entirely.
  options.tartarus.containers.privateUsers = mkOption {
    type = privateUsersType;
    default = "no";
    description = ''
      Give every `kind = "container"` guest on this host its own user namespace
      (`systemd-nspawn --private-users`), unless the guest overrides it. The
      container still starts as host root -- networking, bridges and nftables
      are unchanged -- but its internal UIDs/GIDs no longer map 1:1 to the
      host's.

      `"no"` (default) disables it. `"identity"` maps UIDs 1:1 and only
      provides process-capability isolation. `"pick"` lets nspawn choose a
      disjoint UID range per container automatically (the recommended mode);
      a number pins the range's base (usually 65536 or above). `"pick"`/a
      number is the real UID isolation but requires the kernel and the
      bind-mount source filesystems to support ID-mapped mounts: tartarus
      attaches the `idmap` mount option to its CA/shares bind mounts so their
      host ownership stays visible inside the guest. On source filesystems
      without ID-mapped-mount support those binds fall back to
      `nobody`/`nogroup` and the guest will not start cleanly. A guest opts out
      (or picks a different range) with `tartarus.guests.<name>.privateUsers`.
    '';
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

        vmOnly = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Pin this guest to `kind = "vm"`. Declared next to the guest content
            (e.g. because it needs its own kernel, such as Docker), it fails
            evaluation if the guest is ever switched to a `kind = "container"`.
          '';
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

        host = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            Run this `kind = "container"` guest nested inside the named
            container-host VM (`kind = "vm"` with `vm.containerHost.enable =
            true`). Required on Darwin.
          '';
        };

        privateUsers = mkOption {
          type = types.nullOr privateUsersType;
          default = null;
          description = ''
            Per-container override for the user namespace
            (`systemd-nspawn --private-users`). When `null` (default) the guest
            inherits the host-wide `tartarus.containers.privateUsers`; set it
            here to give one container a different range (or `"no"` to opt a
            single container out of a host-wide default).

            The container still starts as root on the host -- networking,
            bridges and nftables are unchanged -- but its internal UIDs/GIDs no
            longer map 1:1 to the host's. `"identity"` maps UIDs 1:1 and only
            provides process-capability isolation; `"pick"`/a number is the real
            UID isolation but requires ID-mapped-mount support on the CA/share
            source filesystems (tartarus attaches `idmap` to its binds
            automatically).

            Containers only (VMs cannot use it).
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
            Host-side port forwards into this guest. On Darwin a userspace
            `socat` relay binds the vmnet gateway (guests have no path to each
            other and the host cannot route to a guest service through the
            gateway). On Linux the host firewall DNATs the port: a guest dials
            its bridge gateway (`10.200.0.1` on trs0, `10.201.0.1` on trs1) --
            its service hostname (e.g. `litellm-proxy`) resolves there -- and a
            host-local client dials `127.0.0.1`; the destination is rewritten to
            the guest's bridge IP. Set `host` on a relay to bind specific
            addresses instead. Privileged ports (< 1024) run as a root service
            on Darwin.
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
          description = "VM-only extras (vcpu, mem, ballooning, persistent home, nix store overlay); ignored for containers.";
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

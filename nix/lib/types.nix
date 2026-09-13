{lib}: let
  inherit
    (lib)
    mkEnableOption
    mkOption
    types
    ;
in {
  # Static IDs share the 3-100 range; auto-assignment (see ./ids.nix) starts
  # at 101 so forced and auto IDs can never collide.
  idType = types.nullOr (types.addCheck types.ints.positive (x: x > 2));

  # A host<->guest directory share. Deliberately permissive: the engine passes
  # these straight through to `microvm.shares` (see nix/guest/shares.nix), which
  # validates them against microvm.nix's own submodule, so tartarus only needs
  # to accept the fields the user writes (tag/source/mountPoint/readOnly/...)
  # without shadowing microvm's defaults for the rest.
  shareType = types.attrsOf types.unspecified;

  # A single .desktop application that runs inside the guest via the
  # graphical (wprs) tunnel.
  appType = types.submodule {
    options = {
      name = mkOption {
        type = types.str;
        description = "Internal name for the .desktop file (used in the file name).";
      };
      desktopName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Name shown in the desktop environment (defaults to `name`).";
      };
      exec = mkOption {
        type = types.str;
        description = "Command to execute inside the guest (forwarded over the graphical tunnel).";
      };
      icon = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Icon name for the .desktop entry.";
      };
      terminal = mkOption {
        type = types.bool;
        default = false;
        description = "Whether the application should run in a terminal.";
      };
    };
  };

  serviceFlags = types.submodule {
    options = {
      clipboardBridge = mkEnableOption "the clipboard-bridge client in the guest and server on the host (mTLS)";
      sshAuthProxy = mkEnableOption "the ssh-agent host in the guest and ssh-agent-proxy on the host (mTLS)";
      sudoAuthProxy = mkEnableOption "the PAM sudo-auth-proxy client in the guest and server on the host (mTLS)";
      disableVsock = mkEnableOption "forcing TCP instead of VSOCK for the guest/host services (no-op where VSOCK is unavailable)";
    };
  };

  vmExtras = types.submodule {
    options = {
      vcpu = mkOption {
        type = types.ints.positive;
        default = 1;
        description = "Number of virtual CPUs for the guest (VM only).";
      };
      mem = mkOption {
        type = types.ints.positive;
        default = 768;
        description = "Guest memory in MiB (VM only).";
      };
      persistentHome = {
        enable = mkEnableOption "a persistent /home backed by a writable disk image (VM only)";
        size = mkOption {
          type = types.ints.positive;
          default = 5120;
          description = "Persistent home size in MiB (VM only).";
        };
      };
      nixStoreOverlay = {
        size = mkOption {
          type = types.ints.positive;
          default = 2048;
          description = "Size in MiB of the writable /nix/store overlay (VM only).";
        };
      };
    };
  };

  proxyPerGuest = types.submodule {
    options = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Route this guest's egress through the tartarus HTTP proxy. Requires
          the global `tartarus.proxy.enable` and is mutually exclusive with
          `internet = true`.
        '';
      };
      allowHosts = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Allowlist of destination hosts reachable through the proxy over
          HTTPS/443 only. Entries are Squid `dstdomain` patterns; a leading dot
          matches subdomains.
        '';
      };
    };
  };

  firewall = types.submodule {
    options = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable a tartarus-managed firewall for this guest.";
      };
      location = mkOption {
        type = types.enum ["host" "guest"];
        default = "guest";
        description = ''
          Where the guest's firewall is enforced. `"host"` needs root/nftables
          and is Linux-only; `"guest"` runs nftables inside the guest.
        '';
      };
      allow = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Extra host-service allowances for this guest (e.g. clipboard / ssh /
          sudo fallback ports). Not an internet-egress backdoor.
        '';
      };
    };
  };
}

{lib}: let
  inherit
    (lib)
    mkEnableOption
    mkOption
    types
    ;

  # One lifecycle hook entry. Shared by the host-wide `tartarus.hooks` and the
  # per-guest `tartarus.guests.<name>.hooks` surfaces; the renderer
  # (`nix/host/hooks.nix`) flattens both into `~/.config/tartarus/hooks.toml`
  # and the CLI (`src/tartarus/hooks.py`) runs the matching entries.
  #
  # `command` runs as the invoking host user through `/bin/sh -c` (never sudo).
  # It may contain the tokens `{name}`, `{template}`, `{kind}`, `{id}`,
  # `{event}` and `{phase}`. Substitution is a plain `str.replace`, not
  # `str.format`, so shell braces (`$VAR`, `awk '{print $1}'`) stay intact.
  hookType = types.submodule {
    options = {
      command = mkOption {
        type = types.str;
        description = ''
          Shell command to run, executed as `/bin/sh -c <command>` by the
          invoking host user with the hook's environment variables set.

          The tokens `{name}` (instance name), `{template}` (the base guest the
          instance was spawned from), `{kind}` (`vm`/`container`), `{id}`,
          `{event}` and `{phase}` are replaced before the shell sees the
          command. Substitution is a literal string replace, so ordinary shell
          syntax that uses braces is safe.
        '';
      };
      guests = mkOption {
        type = types.listOf types.str;
        default = ["*"];
        description = ''
          `fnmatch` glob patterns selecting the guests this hook applies to.
          Each pattern is matched against BOTH the instance name and its base
          template, so `["notes"]` matches `notes` and `notes-2`, and
          `["dev-*"]` matches every numbered `dev` instance.

          A leading `!` excludes a match (`["*" "!vpn"]` = every guest except
          `vpn`). The default `["*"]` is the all-inclusive spelling; `[]`
          selects nothing and therefore disables the hook.

          Per-guest hooks (`tartarus.guests.<name>.hooks`) ignore this field:
          the renderer forces `["<name>"]` there.
        '';
      };
      kinds = mkOption {
        type = types.listOf (types.enum ["vm" "container"]);
        default = ["vm" "container"];
        description = ''
          Guest kinds this hook applies to. Defaults to both; narrow it to
          `["vm"]` or `["container"]` to skip the other. Per-guest hooks ignore
          this field (the renderer forces the guest's own kind).
        '';
      };
      timeout = mkOption {
        type = types.ints.positive;
        default = 30;
        description = ''
          Per-attempt timeout in seconds (rendered as a TOML float). A command
          that runs longer is killed and counts as a failed attempt.
        '';
      };
      retries = mkOption {
        type = types.ints.unsigned;
        default = 0;
        description = ''
          Number of extra attempts after the first failure. Useful right after
          a start, when a just-booted guest's service may not be reachable yet.
        '';
      };
      retryDelay = mkOption {
        type = types.numbers.nonnegative;
        default = 2.0;
        description = ''
          Seconds to wait between attempts (accepts `2` or `2.0`; rendered as
          a TOML float).
        '';
      };
      onFailure = mkOption {
        type = types.enum ["warn" "abort"];
        default = "warn";
        description = ''
          What to do once every attempt failed: `"warn"` (default) prints a
          warning and lets the tartarus command continue, `"abort"` fails the
          command with an error. A failing `before` hook aborts the operation
          itself before it runs.
        '';
      };
      description = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Human-readable label used in hook log lines. `null` falls back to the command.";
      };
    };
  };

  # One event's hook phases. `before` runs before the operation, `after` once
  # it completed successfully (for `start`, after relays are up).
  #
  # A plain attrset of option declarations, deliberately NOT a
  # `types.submodule { options = ...; }` binding: `types.submodule` merges
  # `options` into the enclosing submodule when nested, which would flatten
  # every event's hooks into a single list instead of keeping them per event.
  # Keeping the phase shape an attrset of lists also indexes cleanly:
  # `hooks.start.after` reads a list directly.
  hookPhaseOptions = {
    before = mkOption {
      type = types.listOf hookType;
      default = [];
      description = "Hooks run before the event's operation. A failing `onFailure = \"abort\"` hook prevents the operation.";
    };
    after = mkOption {
      type = types.listOf hookType;
      default = [];
      description = "Hooks run after the event's operation completed.";
    };
  };

  # The full event/phase set used by both hook scopes:
  #
  #   tartarus.hooks.<event>.<phase>        # host-wide
  #   tartarus.guests.<name>.hooks.<event>.<phase>  # per guest
  #
  # Event semantics:
  #   * `create` -- a new instance is provisioned (VM `spawn`, container
  #     create / first start of an ad-hoc instance);
  #   * `start` / `stop` -- every real transition, including the start implied
  #     by `create`. No-op transitions (already running / already stopped) run
  #     no hooks;
  #   * `remove` -- `stop --purge` (the VM state dir or the container
  #     registration is destroyed);
  #   * `build` -- an explicit `tartarus build`.
  #
  # `restart` is composed from stop + start and has no event of its own; both
  # hook sets fire, `stop` first.
  #
  # Ordering of create+start: `before create` -> `before start` -> operation
  # -> `after start` -> `after create`. Purge orders as `before stop` -> stop
  # -> `after stop` -> `before remove` -> remove -> `after remove`; purging an
  # already-stopped instance fires only the remove hooks.
  #
  # Gotcha: containers that auto-start *inside* a container-host VM are not
  # started through the host CLI, so their `start.after` hooks do not fire; an
  # explicit `tartarus -c start <name>` does fire them.
  hooksType = types.submodule {
    options = {
      create = mkOption {
        type = types.submodule {options = hookPhaseOptions;};
        default = {};
        description = "Hooks for provisioning a new instance (VM spawn / container create).";
      };
      start = mkOption {
        type = types.submodule {options = hookPhaseOptions;};
        default = {};
        description = "Hooks for every real start transition (including the start implied by `create`).";
      };
      stop = mkOption {
        type = types.submodule {options = hookPhaseOptions;};
        default = {};
        description = "Hooks for every real stop transition.";
      };
      remove = mkOption {
        type = types.submodule {options = hookPhaseOptions;};
        default = {};
        description = "Hooks for `stop --purge`, i.e. destroying the instance's state.";
      };
      build = mkOption {
        type = types.submodule {options = hookPhaseOptions;};
        default = {};
        description = "Hooks for an explicit `tartarus build`.";
      };
    };
  };
in {
  # Shared hook types. `hooksType` is the full event/phase set used by both
  # `tartarus.hooks` and `tartarus.guests.<name>.hooks`; `hookType` is a single
  # entry, exported for callers that build one outside the option tree.
  inherit hookType hooksType;

  # Static IDs share the 3-100 range; auto-assignment (see ./ids.nix) starts
  # at 101 so forced and auto IDs can never collide.
  idType = types.nullOr (types.addCheck types.ints.positive (x: x > 2));

  # A host<->guest directory share. Deliberately permissive: the engine passes
  # these straight through to `microvm.shares` (see nix/guest/shares.nix), which
  # validates them against microvm.nix's own submodule, so tartarus only needs
  # to accept the fields the user writes (tag/source/mountPoint/readOnly/...)
  # without shadowing microvm's defaults for the rest.
  #
  # `overlay = true` is tartarus-only (stripped before `microvm.shares`): the
  # source is exported read-only as `/run/tartarus/lower/<tag>` and the guest
  # gets a writable overlay at `mountPoint` whose upper/work live under the
  # guest home. Linux hosts only. See `nix/lib/shares.nix` and
  # `nix/guest/overlay-shares.nix`.
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
      sshAgentProxy = mkEnableOption "the ssh-agent host in the guest and ssh-agent-proxy on the host (mTLS)";
      sudoAuthProxy = mkEnableOption "the PAM sudo-auth-proxy client in the guest and server on the host (mTLS)";
      gpgAgentProxy = mkEnableOption "GPG agent forwarding over SSH: the guest's gpg-agent socket is RemoteForward-ed to the host's gpg-agent, and the guest sshd accepts the stream-local bind";
      disableVsock = mkEnableOption "forcing TCP instead of VSOCK for the guest/host services (no-op where VSOCK is unavailable)";
      # Transport for the sudo-auth-proxy service specifically. This is the
      # per-guest marker the host SSH wrapper and the host server transport
      # selection read (audit A1); `services.sudoAuthProxyTransport` was
      # referenced by `modules/programs/user/ssh.nix` but never defined, so the
      # `unix` transport could not be requested through the module graph.
      # `vsock`/`tcp` keep the platform's existing callback behaviour; `unix`
      # selects the host→guest SSH-forwarded Unix socket and is served with
      # transport_encryption = "none" + client_auth = "x509" (the guest's
      # tartarus X.509 client cert), not mTLS.
      sudoAuthProxyTransport = mkOption {
        type = types.enum ["vsock" "tcp" "unix"];
        default = "vsock";
        description = ''
          Transport the sudo-auth-proxy integration uses for this guest. `unix`
          requests the SSH-forwarded host→guest Unix socket (no network port);
          `vsock`/`tcp` keep the platform's normal callback transport. At most
          one transport per host user is supported: the host server exposes a
          single socket, so mixing `unix` with a callback transport across the
          guests of one host is an evaluation error.
        '';
      };
      # Transport for the ssh-agent-proxy integration specifically. Mirrors
      # `sudoAuthProxyTransport`: the per-guest marker the host server transport
      # selection reads. `unix` selects the host→guest SSH-forwarded Unix socket
      # (one server socket, no port); `vsock`/`tcp` keep the platform's callback
      # transport. Mixing `unix` with a callback transport across the guests of
      # one host is an evaluation error (the server exposes one socket).
      sshAgentProxyTransport = mkOption {
        type = types.enum ["vsock" "tcp" "unix"];
        default = "vsock";
        description = ''
          Transport the ssh-agent-proxy integration uses for this guest. `unix`
          requests the SSH-forwarded host→guest Unix socket (no network port);
          `vsock`/`tcp` keep the platform's normal callback transport. At most
          one transport per host user is supported: the host server exposes a
          single socket, so mixing `unix` with a callback transport across the
          guests of one host is an evaluation error.
        '';
      };
    };
  };

  vmExtras = types.submodule {
    options = {
      vcpu = mkOption {
        type = types.nullOr (types.either (types.enum ["host"]) types.ints.positive);
        default = 1;
        description = "Number of virtual CPUs for the guest (VM only): a positive integer, `null` for the hypervisor default, or `\"host\"` for a host-sized cap.";
      };
      mem = mkOption {
        type = types.nullOr (types.either (types.enum ["host"]) types.ints.positive);
        default = 768;
        description = "Guest memory in MiB (VM only): a positive integer, `null` for the hypervisor default, or `\"host\"` for a host-sized cap.";
      };
      balloon = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Enable the virtio-balloon and free page reporting (VM only,
            Linux/QEMU). Defaults to `true`: free page reporting is automatic and
            safe (the guest hands its already-free pages back to the host), so
            idle VMs cost the host less than `vm.mem`. The balloon device itself
            is host-driven and only changes size when you ask it to (see the
            README's "Memory management"). Silently ignored on Darwin (vfkit has
            no balloon device) and on containers.
          '';
        };
        deflateOnOOM = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Auto-deflate the balloon when the guest runs out of memory, letting
            it reclaim memory the host took back (VM only, Linux/QEMU). Only
            meaningful after the balloon has been inflated manually.
          '';
        };
      };
      containerHost = {
        enable = mkEnableOption "hosting nested systemd-nspawn containers inside this VM";

        stateVolume.size = mkOption {
          type = types.ints.positive;
          default = 10240;
          description = "MiB backing /var/lib/nixos-containers.";
        };

        network = {
          bridge = mkOption {
            type = types.str;
            default = "trs2";
            description = "Inner bridge interface for nested containers.";
          };
          hostIP = mkOption {
            type = types.str;
            default = "10.202.0.1";
            description = "Host IP on the inner bridge.";
          };
          subnet = mkOption {
            type = types.str;
            default = "10.202.0.0/24";
            description = "Subnet for nested containers.";
          };
        };

        dns = {
          enable = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Run dnsmasq on the inner bridge as the nested containers'
              resolver, forwarding upstream. Disable on a VM that does not
              serve DNS to its containers.
            '';
          };
          upstream = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              Upstream server the inner containers' dnsmasq forwards to. `null`
              forwards to the VM's own upstream gateway (today's behaviour);
              set an address to send inner queries to a resolver guest instead.
            '';
          };
        };
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

  # A host-side port forward into a guest. On Darwin vfkit's vmnet-shared mode
  # makes guests unable to reach each other and the host cannot route to a
  # guest's service at the gateway, so a userspace relay exposes the guest port
  # on the gateway (`192.168.64.1`). On Linux the host firewall DNATs the port:
  # a guest dials its bridge gateway (`10.200.0.1` on trs0, `10.201.0.1` on
  # trs1) and a host-local client dials `127.0.0.1`, both rewritten to the
  # guest's bridge IP.
  relay = types.submodule {
    options = {
      port = mkOption {
        type = types.port;
        description = "Host-side (gateway) port the relay listens on.";
      };
      targetPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Guest-side port to forward to. Defaults to `port`.";
      };
      protocol = mkOption {
        type = types.enum ["tcp" "udp"];
        default = "tcp";
        description = "Transport protocol of the relay.";
      };
      host = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Host address to bind. Defaults to the vmnet gateway on Darwin, or the loopback plus the bridge gateways on Linux.";
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

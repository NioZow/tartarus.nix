# Guest module entry. Composes the tartarus guest base with the optional
# integrations and finally the user's `systemConfig`, so user content always
# wins.
#
# `nix/guest/platform.nix` is deliberately NOT imported: it is a pure helper
# consumed by the engine, exposed to these modules as `tartarusGuest.platform`.
# `shares.nix`/`store-overlay.nix` touch `microvm.*` and are therefore only
# imported for VMs; containers bind-mount their directories instead.
#
# The tartarus-owned integrations are imported directly from `nix/packages/*`
# (no nixcfg routing):
#   - sudo-auth-proxy client/PAM  -> NixOS module, always imported
#   - ssh-agent-proxy / clipboard-bridge guest halves -> home-manager modules,
#     imported into the guest user only when requested.
{
  lib,
  inputs,
  pkgs,
  tartarusGuest,
  ...
}: let
  inherit
    (lib)
    mkIf
    mkMerge
    optional
    optionalAttrs
    ;
  g = tartarusGuest;
  p = g.platform;
  services = g.services;
  x509 = "/etc/tartarus/x509";
  user = g.user.name;

  # Per-guest sudo-auth-proxy transport marker (audit A1). `unix` selects the
  # host→guest SSH-forwarded Unix socket instead of the callback transports.
  # Since mTLS is the only authentication mechanism left (doc §7), the `unix`
  # path runs mTLS *inside* the SSH tunnel: same tartarus CA and the same
  # client certificate the other guest services already present.
  sapUnix = (services.sudoAuthProxyTransport or "vsock") == "unix";

  # Per-guest ssh-agent-proxy transport marker. `unix` selects the
  # host→guest SSH-forwarded Unix socket; the bridge then runs mTLS *inside*
  # the SSH tunnel with the tartarus client certificate, so per-guest
  # `machine` rules keep working (plan §1.1).
  sshUnix = (services.sshAgentProxyTransport or "vsock") == "unix";

  sudoAuthProxy = import ../packages/sudo-auth-proxy {inherit inputs;};
  sshAgentProxyPkg = import ../packages/ssh-agent-proxy {inherit inputs;};
  clipboardBridge = import ../packages/clipboard-bridge {inherit inputs;};

  # Common mTLS client block; the OIDs differ per service.
  clientMtls = requiredOid: peerOid: {
    enable = true;
    caFile = "${x509}/ca.crt";
    certFile = "${x509}/client.crt";
    keyFile = "${x509}/client.key";
    inherit requiredOid peerOid;
  };

  # VSOCK when the platform provides it, TCP otherwise (Darwin, containers, or
  # `services.disableVsock`).
  connection = {
    transport =
      if p.useVsock
      then "vsock"
      else "tcp";
    host =
      if p.useVsock
      then "2"
      else p.serviceHost;
    cid = 2;
  };
in {
  imports =
    [
      ./base.nix
      ./network.nix
      ./home.nix
      ./overlay-shares.nix
      (import ../host/firewall.nix {mode = "guest";})
    ]
    ++ optional g.isVm ./shares.nix
    ++ optional g.isVm ./store-overlay.nix
    ++ optional (g.proxy.enable || (g.proxy.isProxyHost or false)) ./proxy.nix
    ++ [sudoAuthProxy.nixosModule]
    ++ [g.systemConfig];

  config = mkMerge [
    # PAM sudo-auth-proxy client (system scope) inside the guest.
    (mkIf services.sudoAuthProxy {
      tartarus.sudo-auth-proxy = {
        enable = true;
        # `unix` is the host→guest SSH RemoteForward path; vsock/tcp keep the
        # platform's callback transport (doc §3; audit A1).
        transport = if sapUnix then "unix" else connection.transport;
        host = connection.host;
        cid = connection.cid;
        port = 65001;
        # The PAM helper runs as the invoking (guest login) user, so give the
        # config directory to that user's group instead of the world (doc §9.2;
        # mode stays 0750). The guest account is always "user" (build.nix), whose
        # group is also "user".
        configDirGroup = user;
        # Timeouts: the first frame is the immediate `auth_pending` ack, bounded
        # by recvTimeout (short, so a stale socket still fast-fails); the human
        # decision is bounded by decisionTimeout (audit A2).
        recvTimeout = 0.5;
        decisionTimeout = 120;
        # `unix`: the SSH tunnel protects the channel, and mTLS authenticates
        # both ends inside it (the only mechanism left, doc §7) with the
        # tartarus client certificate. The server presents its tartarus server
        # certificate and authorizes the guest's SPKI against the CA.
        #
        # Callback transports (vsock/tcp): the tartarus-internal channel is
        # private by construction, so use it unencrypted and unauthenticated --
        # stated explicitly on all three knobs (the module asserts it). The
        # Python warns about `none`; the server's ordered `[[rule]]` list
        # decides allow/ask/deny. The client may additionally pin the host
        # server identity with its own `acl` (`trustedFingerprints`/
        # `trustedNames`) to refuse a fake server.
        security = {
          transportEncryption = if sapUnix then "mtls" else "none";
          serverAuth = if sapUnix then "transport" else "none";
          clientAuth = if sapUnix then "transport" else "none";
        };
        # mTLS material for the `unix` path only; under `none` the block is not
        # emitted at all (`transport_encryption != "mtls"`), so the guest
        # carries the tartarus client certificate only where it is used.
        mtls =
          clientMtls "1.3.6.1.4.1.99999.1.2" "1.3.6.1.4.1.99999.1.1"
          // {enable = sapUnix;};
      };
    })

    (mkIf (services.sshAgentProxy || services.clipboardBridge) {
      home-manager.users.${user} = mkMerge [
        {
          imports = [
            sshAgentProxyPkg.homeManagerModule
            clipboardBridge.homeManagerModule
          ];
        }

        (mkIf services.sshAgentProxy {
          tartarus.ssh-agent-proxy = {
            # Guest-local agent (the keys added inside the guest).
            agent.enable = true;
            # ONE process, no separate `bridge`: a local allow-all proxy server
            # that merges the guest's agent with the host's. The host agent is
            # just another `[[upstream]]` -- on callback transports the server
            # dials the host's vsock/tcp endpoint with no crypto (the tartarus
            # channel is private by construction); on the SSH-forwarded `unix`
            # transport it dials the per-session socket (`$SSH_AUTH_PROXY_SOCK`)
            # with mTLS inside the tunnel. The merged identities are served on a
            # local unix socket that `setSshAuthSock` points SSH_AUTH_SOCK at.
            server = {
              enable = true;
              # A distinct `configPath` keeps it from colliding with the
              # default `~/.config/ssh-agent-proxy/config.toml`.
              configPath = "${g.user.home}/.config/ssh-agent-proxy/server.toml";
              setSshAuthSock = true;
              settings = {
                upstream = [
                  # Local agent first: it is the default `key.socket` and the
                  # `ssh-add`/`ssh-add -d` target.
                  {transport = "unix"; socket = "%t/ssh-agent";}
                  ({
                    name = "host";
                    transport = if sshUnix then "unix" else connection.transport;
                    port = 65000;
                    security = {
                      transport_encryption = if sshUnix then "mtls" else "none";
                      server_auth = if sshUnix then "transport" else "none";
                      client_auth = if sshUnix then "transport" else "none";
                    };
                  }
                  // optionalAttrs (!sshUnix) {
                    host = connection.host;
                    cid = connection.cid;
                  }
                  // optionalAttrs sshUnix {
                    # The `unix` transport omits `socket`: the proxy reads the
                    # per-session `$SSH_AUTH_PROXY_SOCK` at connect time.
                    mtls = clientMtls "1.3.6.1.4.1.99999.2.2" "1.3.6.1.4.1.99999.2.1";
                  })
                ];
                rule = [
                  {
                    key = "*";
                    auth = "allow";
                    data_signing = "allow";
                    # Mirror the old merge mode's blind forwarding: `ssh-add`
                    # through the merged socket adds to the first upstream agent
                    # (`%t/ssh-agent`), `ssh-add -d` removes from it.
                    add = "allow";
                    remove = "allow";
                    notify = false;
                  }
                ];
              };
              listeners = [
                {
                  type = "unix";
                  socket = "%t/ssh-agent-merged";
                  resolution = "none";
                  security = {
                    transportEncryption = "none";
                    clientAuth = "none";
                    serverAuth = "none";
                  };
                }
              ];
            };
          };
        })

        (mkIf services.clipboardBridge {
          tartarus.clipboard-bridge.client = {
            enable = true;
            transport = connection.transport;
            host = connection.host;
            vsockCid = connection.cid;
            port = 27795;
            mtls = clientMtls "1.3.6.1.4.1.99999.3.2" "1.3.6.1.4.1.99999.3.1";
            waylandDisplay = "wprs-0";
            autostart = g.graphical;
            proxy.enable = true;
          };
        })
      ];
    })

    # GPG agent forwarding is done entirely by the SSH client/server (a
    # RemoteForward of the host's agent socket), so the guest only needs to
    # make sure sshd can bind the forwarded socket under the runtime dir
    # GnuPG uses for its agent (`$XDG_RUNTIME_DIR/gnupg`). The sshd side lives
    # in base.nix; here we pre-create that directory (sshd binds the socket but
    # not its parent) via a lingering user service.
    (mkIf services.gpgAgentProxy {
      home-manager.users.${user} = {
        systemd.user.services.tartarus-gpg-agent-socketdir = {
          Unit = {
            Description = "Create the gpg-agent runtime socket directory (tartarus GPG forwarding)";
          };
          Service = {
            Type = "oneshot";
            RemainAfterExit = true;
            RuntimeDirectory = "gnupg";
            RuntimeDirectoryMode = "0700";
            RuntimeDirectoryPreserve = "yes";
            ExecStart = "${pkgs.coreutils}/bin/true";
          };
          Install.WantedBy = ["default.target"];
        };
      };
    })
  ];
}

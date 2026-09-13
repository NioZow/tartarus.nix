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
    ;
  g = tartarusGuest;
  p = g.platform;
  services = g.services;
  x509 = "/etc/tartarus/x509";
  user = g.user.name;

  sudoAuthProxy = import ../packages/sudo-auth-proxy.nix {inherit inputs;};
  sshAgentProxy = import ../packages/ssh-agent-proxy.nix {inherit inputs;};
  clipboardBridge = import ../packages/clipboard-bridge.nix {inherit inputs;};

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
        transport = connection.transport;
        host = connection.host;
        cid = connection.cid;
        port = 65001;
        mtls = clientMtls "1.3.6.1.4.1.99999.1.2" "1.3.6.1.4.1.99999.1.1";
        proxy.enable = true;
      };
    })

    (mkIf (services.sshAuthProxy || services.clipboardBridge) {
      home-manager.users.${user} = mkMerge [
        {
          imports = [
            sshAgentProxy.homeManagerModule
            clipboardBridge.homeManagerModule
          ];
        }

        (mkIf services.sshAuthProxy {
          tartarus.ssh-agent-proxy = {
            # Guest -> host proxy bridge.
            bridge = {
              enable = true;
              transport = connection.transport;
              host = connection.host;
              vsockCid = connection.cid;
              vsockPort = 65000;
              port = 65000;
              listenSocket = "%t/ssh-agent-host";
              setSshAuthSock = true;
              mtls = clientMtls "1.3.6.1.4.1.99999.2.2" "1.3.6.1.4.1.99999.2.1";
            };
            # Guest-local agent, merged with the host-forwarded one.
            agent.enable = true;
            merge = {
              enable = true;
              setSshAuthSock = true;
              sockets = ["%t/ssh-agent" "%t/ssh-agent-host"];
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
  ];
}

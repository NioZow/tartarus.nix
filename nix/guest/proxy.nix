# Guest-side proxy wiring. Two roles share this file:
#
#   * a proxy *client* (`proxy.enable`): writes the environment.d file the
#     proxy firewall expects ordinary tools to honour. The host firewall is the
#     enforcement; these variables are usability only.
#   * the single guest-hosted proxy *server* (`proxy.isProxyHost`, set by the
#     engine for the guest named in `tartarus.proxy.location`): runs the same
#     Squid configuration the host module would have run, but bound to this
#     guest's trunk IP. The engine passes the resolved client allowlists in
#     `proxy.clients`.
{
  lib,
  pkgs,
  tartarusGuest,
  mkService,
  ...
}: let
  inherit
    (lib)
    concatStringsSep
    mkIf
    mkMerge
    ;

  g = tartarusGuest;
  p = g.platform;
  proxy = g.proxy;
  proxyUrl = "http://${proxy.host}:${toString proxy.port}";
  noProxy = concatStringsSep "," p.noProxy;

  squidConfig = (import ../host/proxy.nix {mode = "squidConfig";}) {
    inherit lib;
    listenAddresses = [p.guestIP];
    port = proxy.port;
    log = proxy.log;
    clients = proxy.clients;
  };
in {
  config = mkMerge [
    (mkIf proxy.enable {
      home-manager.users.${g.user.name}.home.file.".config/environment.d/10-tartarus.conf".text = ''
        HTTP_PROXY=${proxyUrl}
        HTTPS_PROXY=${proxyUrl}
        http_proxy=${proxyUrl}
        https_proxy=${proxyUrl}
        ALL_PROXY=${proxyUrl}
        all_proxy=${proxyUrl}
        NO_PROXY=${noProxy}
        no_proxy=${noProxy}
      '';
    })

    (mkIf (proxy.isProxyHost or false) (mkMerge [
      {
        environment.etc."tartarus/proxy/squid.conf".text = squidConfig;
      }
      (mkService {
        name = "tartarus-proxy";
        description = "tartarus HTTP forward proxy (Squid)";
        command = "${pkgs.squid}/bin/squid -N -f /etc/tartarus/proxy/squid.conf";
        scope = "system";
        after = ["network.target"];
        restart = "on-failure";
      })
    ]))
  ];
}

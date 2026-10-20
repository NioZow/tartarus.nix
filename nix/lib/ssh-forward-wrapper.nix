{lib}: let
  inherit
    (lib)
    concatStringsSep
    ;

  # The Match stage that scopes a wrapper to the configured hosts. With an
  # empty list the wrapper is a pure pass-through: it execs the real ssh
  # immediately, *before* the token/forward code, so nothing is wired and an
  # accidentally empty `hosts` cannot add a RemoteForward/SetEnv to every
  # destination. With a non-empty list, non-matching destinations pass through
  # and matching ones fall through to the forwarding code.
  mkHostCase = hosts:
    if hosts == []
    then ''exec "$realSsh" "$@"''
    else ''
      case "$dest" in
        ${concatStringsSep "|" hosts})
          ;;
        *)
          exec "$realSsh" "$@"
          ;;
      esac
    '';

  # Generic RemoteForward + SetEnv wrapper shared by the sudo-auth-proxy and
  # ssh-agent-proxy integrations, so the token/`-R`/`SetEnv` shell cannot
  # drift. `<name>` is the always-installed, explicit entry point; when the
  # service's `shadowSsh` is set an identical wrapper named `ssh` is installed
  # too, so `ssh <guest>` is transparent (because `~/.nix-profile/bin`
  # precedes `/run/current-system/sw/bin` on this user's PATH). Shadowing is
  # opt-in because a wrapper bug would affect every SSH connection;
  # non-matching destinations pass through unchanged either way.
  mkForwardWrapper = pkgs: name: opts:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.openssh
        pkgs.coreutils
        pkgs.gnused
        pkgs.gnugrep
      ];
      text = ''
        realSsh=${pkgs.openssh}/bin/ssh

        # Resolve the target config-only (`ssh -G` never connects): `host` is the
        # destination as typed (== ssh's own %h) and `user` the resolved login
        # user (== ssh's own %r). Any resolution failure falls through to the
        # real ssh unchanged.
        config=$("$realSsh" -G "$@" 2>/dev/null) || exec "$realSsh" "$@"
        dest=$(printf '%s\n' "$config" | sed -n 's/^host //p' | head -n1)
        ruser=$(printf '%s\n' "$config" | sed -n 's/^user //p' | head -n1)
        [ -n "$dest" ] || exec "$realSsh" "$@"

        ${mkHostCase opts.hosts}
        # Unpredictable per-session token, injected into BOTH the forwarded
        # guest path and the SetEnv selector. OpenSSH cannot generate
        # randomness, which is the whole reason this wrapper exists.
        token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')

        # Expand %t for the host server socket ourselves: OpenSSH expands it in
        # some keywords but silently drops a %t in the RemoteForward
        # remote-socket field, so pass a literal instead.
        host_sock='${opts.hostSocket}'
        case "$host_sock" in
          %t/*)
            case "$(uname -s)" in
              Darwin) runtime_dir=$(/usr/bin/getconf DARWIN_USER_TEMP_DIR) ;;
              *) runtime_dir="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" ;;
            esac
            host_sock="$runtime_dir/''${host_sock#%t/}"
            ;;
        esac

        # Literal guest path: substitute %r/%h ourselves, then append the token
        # before the .sock suffix (only the basename is random; the parent
        # directory stays a literal from Nix).
        guest_sock='${opts.remoteSocket}'
        guest_sock=$(printf '%s' "$guest_sock" | sed -e "s|%r|$ruser|g" -e "s|%h|$dest|g")
        case "$guest_sock" in
          *.sock) guest_sock="''${guest_sock%.sock}-$token.sock" ;;
          *) guest_sock="$guest_sock-$token" ;;
        esac

        exec "$realSsh" -o StreamLocalBindUnlink=yes -o ExitOnForwardFailure=yes -o "RemoteForward=$guest_sock $host_sock" -o "SetEnv=${opts.envVar}=$guest_sock" "$@"
      '';
    };
in {
  inherit mkHostCase mkForwardWrapper;
}

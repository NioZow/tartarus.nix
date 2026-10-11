# Passwordless sudo for tartarus-managed container units
# (`tartarus.containers.sudoNoPassword`).
#
# `tartarus start <container>` runs `sudo systemctl start container@<name>`
# (see src/tartarus/ctn.py), so every container action prompts unless a
# passwordless rule exists. When enabled, this adds a single scoped
# `security.sudo.extraRules` entry granting the configured users/groups
# `NOPASSWD` for `systemctl <verb> container@*` -- and nothing else.
#
# The rule is emitted after nixpkgs' `wheel` rule (which is `ALL` with a
# password): sudoers uses the *last* matching entry for a command, so the
# `container@*` commands take the passwordless rule while every other command
# keeps the normal password prompt.
#
# Linux only: containers are native systemd `container@` units, which Darwin
# has no equivalent of (its containers are nested inside a Linux VM).
{
  config,
  lib,
  ...
} @ args: let
  cfg = config.tartarus.containers.sudoNoPassword;

  isDarwin = lib.hasSuffix "-darwin" (args.system or builtins.currentSystem);

  # sudo resolves a bare `systemctl` from the invoking user's PATH; on NixOS the
  # default PATH entry `/run/current-system/sw/bin` yields this path, which is
  # what sudo matches the rule against.
  systemctl = "/run/current-system/sw/bin/systemctl";
in {
  config = lib.mkIf (cfg.enable && !isDarwin) {
    security.sudo.extraRules = [
      {
        inherit (cfg) users groups;
        commands =
          map (verb: {
            command = "${systemctl} ${verb} container@*";
            options = ["NOPASSWD"];
          })
          cfg.verbs;
      }
    ];
  };
}

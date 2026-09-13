# Standalone entry point for tartarus's eval-level tests.
#
# Run:
#   nix eval --impure --file tests/default.nix --json
#
# It evaluates `tests/suite.nix` against this repository (via `builtins.getFlake`,
# hence `--impure`) and fails if any check does not hold. The same suite is wired
# into the flake's `checks.<system>` output; see `nix/default.nix`.
#
# `rendered` carries the human-inspectable snapshots (Squid config, nftables
# rulesets, environment.d files) so a failure can be diffed without re-running.
let
  flake = builtins.getFlake (toString ./..);
  lib = flake.inputs.nixpkgs.lib;
  suite = import ./suite.nix {
    inputs = flake.inputs;
    self = flake;
  };

  failed = lib.filterAttrs (_: t: !t.ok) suite.tests;
  failures = lib.mapAttrsToList (name: t: "  - ${name}: ${t.message}") failed;
in
  assert lib.assertMsg (failed == {}) ''
    tartarus eval test failures:
    ${lib.concatStringsSep "\n" failures}
  ''; {
    passed = lib.attrNames (lib.filterAttrs (_: t: t.ok) suite.tests);
    rendered = suite.rendered;
  }

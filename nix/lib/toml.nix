# Minimal TOML value renderers shared by the host-side generators
# (`nix/host/config.nix` and `nix/host/hooks.nix`).
#
# Hand-rolled rather than `pkgs.formats.toml`: the schemas are tiny, stable, and
# must match what the Python side parses (`src/tartarus/config.py`,
# `src/tartarus/hooks.py`) exactly -- including per-guest inline tables the
# generic generator does not emit. Keeping the primitives here means both
# generated files escape strings and render numbers the same way.
{lib}: let
  inherit
    (lib)
    concatMapStringsSep
    concatStringsSep
    mapAttrsToList
    replaceStrings
    ;

  # Escape a value for a TOML basic (double-quoted) string.
  esc = s:
    replaceStrings
    ["\\" "\"" "\n" "\r" "\t"]
    ["\\\\" "\\\"" "\\n" "\\r" "\\t"]
    s;

  # A TOML basic string. `{name}`-style tokens in a command pass through
  # untouched: `{` and `}` need no escaping inside a basic string.
  tStr = s: "\"${esc s}\"";
  tBool = b:
    if b
    then "true"
    else "false";
  tInt = i: toString i;
  # TOML floats must carry a decimal point; Nix renders 2.0 as "2.000000",
  # so collapse trailing zeros to keep the generated files readable.
  tFloat = f: let
    rendered = toString f;
    whole = builtins.match "([0-9]+)\\.0+" rendered;
  in
    if whole != null
    then "${builtins.head whole}.0"
    else rendered;
  tArr = xs: "[${concatMapStringsSep ", " tStr xs}]";
  tInline = attrs: "{ ${concatStringsSep ", " (mapAttrsToList (k: v: "${k} = ${v}") attrs)} }";
in {
  inherit esc tArr tBool tFloat tInline tInt tStr;
}

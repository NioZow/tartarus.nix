{lib}: let
  inherit
    (lib)
    concatMapStringsSep
    concatStringsSep
    filter
    isAttrs
    isBool
    isList
    ;

  renderScalar = value:
    if isBool value
    then
      (
        if value
        then "yes"
        else "no"
      )
    else toString value;

  addressPort = entry: let
    address = entry.address or "localhost";
    port = entry.port or null;
  in
    address
    + lib.optionalString (port != null) " ${toString port}";

  renderForward = f: "${addressPort (f.bind or {})} ${addressPort (f.host or {})}";

  renderDirective = name: value:
    if value == null
    then ""
    else if isList value
    then concatMapStringsSep "\n" (renderDirective name) value
    else if isAttrs value
    then "${name} ${renderForward value}"
    else "${name} ${renderScalar value}";

  mkBlock = host: attrs: let
    lines = filter (line: line != "") (
      map (name: renderDirective name attrs.${name}) (builtins.attrNames attrs)
    );
    body = lib.replaceStrings ["\n"] ["\n  "] (concatStringsSep "\n" lines);
  in
    concatStringsSep "\n" (["Host ${host}"] ++ lib.optional (body != "") ("  " + body));
in {
  inherit mkBlock;
  mkFile = header: blocks: concatStringsSep "\n\n" ([header] ++ filter (b: b != "") blocks) + "\n";
}

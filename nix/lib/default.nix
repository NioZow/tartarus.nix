{lib}: {
  ids = import ./ids.nix {inherit lib;};
  names = import ./names.nix {inherit lib;};
  types = import ./types.nix {inherit lib;};
}

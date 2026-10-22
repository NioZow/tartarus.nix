{
  pkgs,
  lib ? pkgs.lib,
}: let
  runtimeInputs =
    [
      pkgs.nix
      pkgs.socat
      pkgs.openssh
      pkgs.openssl
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [pkgs.util-linux]; # `sg` for the kvm-group re-exec
in
  pkgs.python3Packages.buildPythonApplication {
    pname = "tartarus";
    version = "0.1.0";
    pyproject = true;

    src = lib.fileset.toSource {
      root = ../../..;
      fileset = lib.fileset.unions [
        ../../../pyproject.toml
        ../../../uv.lock
        ../../../README.md
        (lib.fileset.fileFilter (file: file.hasExt "py") ../../../src)
      ];
    };

    build-system = [pkgs.python3Packages.hatchling];
    dependencies = [];

    # Fail the build if a module is missing from the packaged source (e.g. a new
    # file left untracked, which Nix flakes do not see). `tartarus.cli` imports
    # every action module, so a missing one is caught here, not at runtime.
    pythonImportsCheck = ["tartarus.cli"];

    nativeBuildInputs = [pkgs.makeWrapper];

    # No runtime Python dependencies (stdlib only); the external tools the CLI
    # shells out to are pinned on PATH instead.
    postFixup = ''
      wrapProgram $out/bin/tartarus \
        --prefix PATH : ${lib.makeBinPath runtimeInputs}
    '';

    doCheck = false;

    meta = {
      description = "Ad-hoc MicroVMs and containers driven from the user's own flake";
      mainProgram = "tartarus";
      platforms = lib.platforms.all;
    };
  }

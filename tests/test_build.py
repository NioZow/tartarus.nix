"""Tests for the `build` subcommand (guest validation + parser acceptance)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import cli  # noqa: E402
from tartarus.config import Config, Guest  # noqa: E402
from tartarus.errors import TartarusError  # noqa: E402


def make_config(*guests: Guest) -> Config:
    return Config(
        user="user",
        home_dir=Path("/home/user"),
        flake_path=Path("/home/user/.config/nixcfg"),
        system="aarch64-linux",
        state_root=Path("/home/user/.local/state/tartarus"),
        ssh_dir=Path("/home/user/.ssh"),
        ssh_ca_dir=Path("/home/user/.local/share/tartarus/ssh"),
        x509_ca_dir=Path("/home/user/.local/share/tartarus/x509"),
        enabled_guests=list(guests),
    )


VAULT = Guest(name="vault", kind="vm", id=3)
BOX = Guest(name="box", kind="container", id=4)


@pytest.mark.parametrize("argv,kind", [
    (["build", "vault"], "vm"),
    (["--container", "build", "box"], "container"),
])
def test_build_parser_accepts_command(monkeypatch, argv: list[str], kind: str):
    config = make_config(VAULT, BOX)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)

    reached: list[str] = []
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: reached.append(a.command))
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: reached.append(a.command))
    monkeypatch.setattr(cli.flake, "require_flake", lambda _config: None)

    cli.main(argv)
    assert reached == ["build"]


def test_build_rejects_disabled_guest(monkeypatch, capsys):
    config = make_config(VAULT)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)

    def _no_dispatch(*_a, **_k):  # pragma: no cover
        raise AssertionError("dispatch reached for a disabled guest")

    monkeypatch.setattr(cli.vm, "dispatch", _no_dispatch)
    monkeypatch.setattr(cli.ctn, "dispatch", _no_dispatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(["build", "ghost"])
    assert exc.value.code == 1
    assert "not enabled on this host" in capsys.readouterr().err

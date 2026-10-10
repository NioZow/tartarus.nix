"""Tests for ``tartarus ip <container>``.

A native container (``host = null``) lives on the host's ``trs1`` bridge and has
a static ``LOCAL_ADDRESS`` in its ``nixos-container`` registration, so ``ip``
prints it. A nested container (``host = "<vm>"``) lives on its container-host
VM's inner bridge and has no host-reachable address, so ``ip`` refuses it.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_ctn_ip.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import ctn  # noqa: E402
from tartarus.config import Config, Guest  # noqa: E402
from tartarus.errors import TartarusError  # noqa: E402


def make_config(*guests: Guest) -> Config:
    return Config(
        user="user",
        home_dir=Path("/home/user"),
        flake_path=Path("/home/user/.config/nixcfg"),
        system="x86_64-linux",
        state_root=Path("/home/user/.local/state/tartarus"),
        ssh_dir=Path("/home/user/.ssh"),
        ssh_ca_dir=Path("/home/user/.local/share/tartarus/ssh"),
        x509_ca_dir=Path("/home/user/.local/share/tartarus/x509"),
        enabled_guests=list(guests),
    )


CH = Guest(name="ch", kind="vm", id=5, container_host=True)
INNER = Guest(name="inner", kind="container", id=6, host="ch")
BOX = Guest(name="box", kind="container", id=7)


def _patch_common(monkeypatch) -> None:
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)


def test_native_container_prints_its_local_address(monkeypatch, capsys):
    config = make_config(BOX)
    _patch_common(monkeypatch)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "box")
    monkeypatch.setattr(ctn, "list_conf_names", lambda: {"box"})
    monkeypatch.setattr(ctn, "is_running", lambda _n: True)
    monkeypatch.setattr(ctn, "read_local_address", lambda _n: "10.201.0.7")

    ctn.action_ip(config, "box")

    assert capsys.readouterr().out.strip() == "10.201.0.7"


def test_nested_container_is_refused(monkeypatch, capsys):
    config = make_config(CH, INNER)
    _patch_common(monkeypatch)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")

    with pytest.raises(TartarusError) as exc:
        ctn.action_ip(config, "inner")

    message = str(exc.value)
    assert "nested container" in message
    assert "ch" in message
    assert "tartarus --container ssh inner" in message
    # The refusal must reach the user as an error, not a bogus address.
    assert capsys.readouterr().out == ""


def test_NOT_provisioned_container_is_refused(monkeypatch, capsys):
    config = make_config(BOX)
    _patch_common(monkeypatch)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "box")
    monkeypatch.setattr(ctn, "list_conf_names", lambda: set())

    with pytest.raises(SystemExit) as exc:
        ctn.action_ip(config, "box")
    assert exc.value.code == 1
    assert "not provisioned" in capsys.readouterr().err


def test_stopped_container_is_refused(monkeypatch, capsys):
    config = make_config(BOX)
    _patch_common(monkeypatch)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "box")
    monkeypatch.setattr(ctn, "list_conf_names", lambda: {"box"})
    monkeypatch.setattr(ctn, "is_running", lambda _n: False)

    with pytest.raises(SystemExit) as exc:
        ctn.action_ip(config, "box")
    assert exc.value.code == 1
    assert "is not running" in capsys.readouterr().err


def test_missing_recorded_address_is_refused(monkeypatch, capsys):
    config = make_config(BOX)
    _patch_common(monkeypatch)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "box")
    monkeypatch.setattr(ctn, "list_conf_names", lambda: {"box"})
    monkeypatch.setattr(ctn, "is_running", lambda _n: True)
    monkeypatch.setattr(ctn, "read_local_address", lambda _n: None)

    with pytest.raises(SystemExit) as exc:
        ctn.action_ip(config, "box")
    assert exc.value.code == 1
    assert "no recorded address" in capsys.readouterr().err

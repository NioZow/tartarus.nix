"""Tests for ``ssh -s/--start`` (start the guest first if it isn't running)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import cli, ctn, vm  # noqa: E402
from tartarus.config import Config, Guest  # noqa: E402


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


# --- parser ---------------------------------------------------------------


@pytest.mark.parametrize("flag", [[], ["-s"], ["--start"]])
def test_ssh_parser_accepts_start(monkeypatch, flag: list[str]):
    config = make_config(VAULT)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)

    seen: list = []
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: seen.append(a))
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: seen.append(a))
    monkeypatch.setattr(cli.flake, "require_flake", lambda _config: None)

    cli.main(["ssh", "vault", *flag])
    assert seen[0].start is bool(flag)


# --- VM action_ssh --------------------------------------------------------


def _vm_stubs(monkeypatch, running: bool):
    calls: list = []
    monkeypatch.setattr(vm.flake, "base_name", lambda _c, _k, name: name)
    monkeypatch.setattr(vm.flake, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.ssh, "is_running", lambda _c, _n: running)
    monkeypatch.setattr(vm.ssh, "exec_ssh", lambda _c, n: calls.append(("ssh", n)))
    monkeypatch.setattr(vm.ca, "ensure_vm_certs", lambda *_a, **_k: None)
    monkeypatch.setattr(vm, "action_start", lambda _c, n, mounts: calls.append(("start", n)))
    return calls


def test_vm_ssh_start_when_stopped(monkeypatch):
    config = make_config(VAULT)
    calls = _vm_stubs(monkeypatch, running=False)

    vm.action_ssh(config, "vault", start=True)
    assert calls == [("start", "vault"), ("ssh", "vault")]


def test_vm_ssh_start_skips_when_running(monkeypatch):
    config = make_config(VAULT)
    calls = _vm_stubs(monkeypatch, running=True)

    vm.action_ssh(config, "vault", start=True)
    assert calls == [("ssh", "vault")]


def test_vm_ssh_without_start_does_not_start(monkeypatch):
    config = make_config(VAULT)
    calls = _vm_stubs(monkeypatch, running=False)

    vm.action_ssh(config, "vault")
    assert calls == [("ssh", "vault")]


# --- container action_ssh -------------------------------------------------


def _ctn_stubs(monkeypatch, running: bool):
    calls: list = []
    state = {"running": running}
    monkeypatch.setattr(ctn, "base_name", lambda _c, name: name)
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn, "is_running", lambda _n: state["running"])
    monkeypatch.setattr(ctn.ca, "ensure_ctn_certs", lambda *_a, **_k: None)

    def _start(_c, n):
        calls.append(("start", n))
        state["running"] = True

    def _exec(*_a):
        calls.append(("ssh", None))
        raise _Exec  # real execvp never returns

    monkeypatch.setattr(ctn, "action_start", _start)
    monkeypatch.setattr(ctn.os, "execvp", _exec)
    return calls


class _Exec(Exception):
    pass


def test_ctn_ssh_start_when_stopped(monkeypatch):
    config = make_config(BOX)
    calls = _ctn_stubs(monkeypatch, running=False)

    with pytest.raises(_Exec):
        ctn.action_ssh(config, "box", start=True)
    assert calls == [("start", "box"), ("ssh", None)]


def test_ctn_ssh_without_start_still_refuses_stopped(monkeypatch, capsys):
    config = make_config(BOX)
    calls = _ctn_stubs(monkeypatch, running=False)

    with pytest.raises(SystemExit) as exc:
        ctn.action_ssh(config, "box")
    assert exc.value.code == 1
    assert calls == []

"""Regression tests for ``vm.action_stop``'s bounded graceful shutdown.

``microvm-shutdown`` loops until QEMU exits; a guest that ignores the ACPI
powerdown never exits, so on Linux the graceful step used to block forever and
the SIGKILL fallback was unreachable.
"""

from __future__ import annotations

import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import vm  # noqa: E402
from tartarus.config import Config  # noqa: E402


def make_config(state_root: Path) -> Config:
    return Config(
        user="user",
        home_dir=Path("/home/user"),
        flake_path=Path("/home/user/.config/nixcfg"),
        system="aarch64-linux",
        state_root=state_root,
        ssh_dir=Path("/home/user/.ssh"),
        ssh_ca_dir=Path("/home/user/.local/share/tartarus/ssh"),
        x509_ca_dir=Path("/home/user/.local/share/tartarus/x509"),
    )


def _prepare_state(state_root: Path, name: str, pid: int) -> Path:
    state = state_root / name
    (state / "result" / "bin").mkdir(parents=True)
    (state / "result" / "bin" / "microvm-shutdown").write_text("#!/bin/sh\n")
    (state / "microvm.pid").write_text(f"{pid}\n")
    return state


def _stub_action_stop(monkeypatch, *, timeout: bool):
    monkeypatch.setattr(vm.flake, "base_name", lambda _c, _k, name: name)
    monkeypatch.setattr(vm.flake, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(vm, "_reap_stale_vfkits", lambda *_a, **_k: 0)
    monkeypatch.setattr(vm, "_stop_relays", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.ssh, "is_running", lambda *_a, **_k: True)

    shutdown_calls: list[dict] = []

    def _run_quiet(cmd, **kwargs):
        shutdown_calls.append({"cmd": cmd, **kwargs})
        if timeout:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(vm, "run_quiet", _run_quiet)
    return shutdown_calls


def test_stop_bounds_graceful_shutdown(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    _prepare_state(tmp_path, "vault", 999999)
    shutdown_calls = _stub_action_stop(monkeypatch, timeout=True)

    killed: list[int] = []
    monkeypatch.setattr(vm.os, "kill", lambda _pid, sig: killed.append(sig) if sig else None)
    monkeypatch.setattr(vm.os, "killpg", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.time, "sleep", lambda *_a, **_k: None)

    vm.action_stop(config, "vault", purge=False)

    assert shutdown_calls, "graceful shutdown was never attempted"
    assert shutdown_calls[0]["timeout"] == vm.GRACEFUL_SHUTDOWN_SECONDS
    assert signal.SIGKILL in killed


def test_stop_breaks_when_guest_already_exited(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    _prepare_state(tmp_path, "vault", 999999)
    _stub_action_stop(monkeypatch, timeout=False)

    killed: list[int] = []

    def _kill(_pid, sig):
        if sig == 0:
            raise ProcessLookupError
        killed.append(sig)

    monkeypatch.setattr(vm.os, "kill", _kill)
    monkeypatch.setattr(vm.os, "killpg", lambda *_a, **_k: None)

    vm.action_stop(config, "vault", purge=False)

    assert signal.SIGKILL not in killed


def test_stop_not_running_is_a_noop(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    (tmp_path / "vault").mkdir()
    monkeypatch.setattr(vm.flake, "base_name", lambda _c, _k, name: name)
    monkeypatch.setattr(vm.flake, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(vm, "_reap_stale_vfkits", lambda *_a, **_k: 0)
    monkeypatch.setattr(vm, "_stop_relays", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.ssh, "is_running", lambda *_a, **_k: False)

    def _boom(*_a, **_k):
        raise AssertionError("must not attempt shutdown for a stopped guest")

    monkeypatch.setattr(vm, "run_quiet", _boom)
    monkeypatch.setattr(vm.os, "kill", _boom)

    vm.action_stop(config, "vault", purge=False)

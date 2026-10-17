"""Tests for host-reachable guest IP resolution.

Darwin guests are statically addressed (DHCP is broken under vfkit), so
``resolve_running_ip`` returns the deterministic address directly without
touching the ARP table. On Linux it prefers whatever the host ARP table
reports (probing the known address to prime it) and falls back to the
deterministic address instead of failing.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_ssh.py -v
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Make the package importable when run with a bare interpreter (no venv).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import ssh  # noqa: E402
from tartarus.config import Config, load_config  # noqa: E402
from tartarus.errors import TartarusError  # noqa: E402

# macOS `arp -an` spellings: an unrelated entry, then the wanted guest.
ARP_OTHER = "? (192.168.64.1) at 0:1:2:3:4:5 on bridge100 ifscope [bridge]\n"
ARP_LITELLM = "? (192.168.64.54) at 2:0:0:0:0:c on bridge100 ifscope [bridge]\n"


def make_config(tmp_path: Path) -> Config:
    return Config(
        user="user",
        home_dir=tmp_path,
        flake_path=tmp_path / "nixcfg",
        system="aarch64-darwin",
        state_root=tmp_path / "state",
        ssh_dir=tmp_path / ".ssh",
        ssh_ca_dir=tmp_path / "ssh-ca",
        x509_ca_dir=tmp_path / "x509-ca",
        enabled_guests=[],
    )


def _running_state(config: Config, name: str = "litellm", guest_id: int = 12) -> None:
    state = config.state_dir(name)
    state.mkdir(parents=True, exist_ok=True)
    (state / "cid").write_text(str(guest_id))


# --- arp_ip_for_mac -------------------------------------------------------


def test_macos_arp_format_matches_zero_stripped_mac():
    assert ssh.arp_ip_for_mac(ARP_LITELLM, "02:00:00:00:00:0c") == "192.168.64.54"


def test_linux_arp_format_matches():
    line = "litellm (10.200.0.12) at 02:00:00:00:00:0c [ether] on trs0\n"
    assert ssh.arp_ip_for_mac(line, "02:00:00:00:00:0c") == "10.200.0.12"


def test_arp_miss_returns_none():
    assert ssh.arp_ip_for_mac(ARP_OTHER, "02:00:00:00:00:0c") is None


# --- resolve_running_ip ---------------------------------------------------


def test_linux_waits_until_the_arp_entry_appears(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    _running_state(config)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh.system, "is_darwin", lambda: False)
    monkeypatch.setattr(ssh, "_ping_once", lambda _ip: None)
    monkeypatch.setattr(ssh.time, "sleep", lambda _seconds: None)

    outputs = iter([ARP_OTHER, ARP_OTHER, ARP_LITELLM])
    monkeypatch.setattr(ssh, "_arp_table", lambda: next(outputs))

    assert ssh.resolve_running_ip(config, "litellm") == "192.168.64.54"

    # The progress note must not touch stdout: this path backs ssh's
    # ProxyCommand, where stdout is the SSH transport.
    captured = capsys.readouterr()
    assert "probing 'litellm'" in captured.err
    assert captured.out == ""


def test_linux_falls_back_to_the_deterministic_static_ip(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    _running_state(config, name="network", guest_id=9)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh.system, "is_darwin", lambda: False)
    monkeypatch.setattr(ssh, "_ping_once", lambda _ip: None)
    monkeypatch.setattr(ssh, "_arp_table", lambda: ARP_OTHER)
    monkeypatch.setattr(ssh.time, "sleep", lambda _seconds: None)
    ticks = iter([0.0, 1000.0])
    monkeypatch.setattr(ssh.time, "monotonic", lambda: next(ticks))

    assert ssh.resolve_running_ip(config, "network") == "10.200.0.9"


def test_darwin_returns_the_static_ip_without_probing(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    _running_state(config, name="network", guest_id=9)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh.system, "is_darwin", lambda: True)

    def boom(*_a, **_k):  # pragma: no cover - must never run
        raise AssertionError("the ARP probe must not run on Darwin")

    monkeypatch.setattr(ssh, "_arp_table", boom)
    monkeypatch.setattr(ssh, "_ping_once", boom)

    assert ssh.resolve_running_ip(config, "network") == "192.168.64.51"

    captured = capsys.readouterr()
    assert "probing" not in captured.err
    assert captured.out == ""


def test_does_not_wait_when_the_guest_is_stopped(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: False)

    with pytest.raises(SystemExit) as exc:
        ssh.resolve_running_ip(config, "litellm")
    assert exc.value.code == 1
    assert "is not running" in capsys.readouterr().err


# --- run_ssh retries ------------------------------------------------------

def _completed(argv: list[str], code: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, code)


def test_run_ssh_retries_connection_failures_then_succeeds(monkeypatch, capsys):
    codes = iter([255, 255, 0])
    monkeypatch.setattr(ssh.subprocess, "run", lambda argv: _completed(argv, next(codes)))
    sleeps: list[float] = []
    monkeypatch.setattr(ssh.time, "sleep", sleeps.append)

    with pytest.raises(SystemExit) as exc:
        ssh.run_ssh(["ssh", "vault"], retries=5, retry_delay=2.0)
    assert exc.value.code == 0
    assert sleeps == [2.0, 2.0]

    err = capsys.readouterr().err
    assert "retrying in 2s (1/5)" in err
    assert "retrying in 2s (2/5)" in err


def test_run_ssh_exhausts_retries_and_returns_the_last_status(monkeypatch):
    attempts: list[list[str]] = []

    def _run(argv):
        attempts.append(argv)
        return _completed(argv, 255)

    monkeypatch.setattr(ssh.subprocess, "run", _run)
    monkeypatch.setattr(ssh.time, "sleep", lambda _s: None)

    with pytest.raises(SystemExit) as exc:
        ssh.run_ssh(["ssh", "vault"], retries=3, retry_delay=0.5)
    assert exc.value.code == 255
    assert len(attempts) == 4  # first attempt + 3 retries


@pytest.mark.parametrize("code", [0, 1, 42])
def test_run_ssh_does_not_retry_non_connection_failures(monkeypatch, code: int):
    attempts: list[list[str]] = []

    def _run(argv):
        attempts.append(argv)
        return _completed(argv, code)

    monkeypatch.setattr(ssh.subprocess, "run", _run)
    monkeypatch.setattr(
        ssh.time, "sleep", lambda _s: pytest.fail("must not sleep on a non-255 exit")
    )

    with pytest.raises(SystemExit) as exc:
        ssh.run_ssh(["ssh", "vault"], retries=5, retry_delay=2.0)
    assert exc.value.code == code
    assert len(attempts) == 1


# --- config reload: [ssh] retry settings ----------------------------------

def _retry_config(tmp_path: Path, extra: str = "[ssh]\nretries = 7\nretry_delay = 0.25\n") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(extra)
    return path


def test_config_parses_ssh_retry_settings(monkeypatch, tmp_path):
    path = _retry_config(tmp_path)
    monkeypatch.setenv("TARTARUS_CONFIG", str(path))
    monkeypatch.delenv("TARTARUS_SSH_RETRIES", raising=False)
    monkeypatch.delenv("TARTARUS_SSH_RETRY_DELAY", raising=False)

    config = load_config()
    assert config.ssh_retries == 7
    assert config.ssh_retry_delay == 0.25


def test_config_ssh_retry_defaults(monkeypatch, tmp_path):
    path = _retry_config(tmp_path, "")
    monkeypatch.setenv("TARTARUS_CONFIG", str(path))
    monkeypatch.delenv("TARTARUS_SSH_RETRIES", raising=False)
    monkeypatch.delenv("TARTARUS_SSH_RETRY_DELAY", raising=False)

    config = load_config()
    assert config.ssh_retries == 5
    assert config.ssh_retry_delay == 2.0


def test_config_ssh_retry_env_wins_over_toml(monkeypatch, tmp_path):
    path = _retry_config(tmp_path)
    monkeypatch.setenv("TARTARUS_CONFIG", str(path))
    monkeypatch.setenv("TARTARUS_SSH_RETRIES", "9")
    monkeypatch.setenv("TARTARUS_SSH_RETRY_DELAY", "1.5")

    config = load_config()
    assert config.ssh_retries == 9
    assert config.ssh_retry_delay == 1.5


@pytest.mark.parametrize(
    "extra",
    [
        "[ssh]\nretries = -1\n",
        "[ssh]\nretry_delay = -0.5\n",
        "[ssh]\nretry_delay = \"soon\"\n",
        "ssh = 3\n",
    ],
)
def test_config_rejects_invalid_ssh_retry_settings(monkeypatch, tmp_path, extra: str):
    path = _retry_config(tmp_path, extra)
    monkeypatch.setenv("TARTARUS_CONFIG", str(path))

    with pytest.raises(TartarusError):
        load_config()

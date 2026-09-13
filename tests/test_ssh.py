"""Tests for ARP-based guest IP resolution (Darwin MicroVMs).

``vmnet``'s DHCP server does not record leases where the host can read them
(only bootpd's own, unrelated to QEMU's deterministic MAC), so the host ARP
table is the only way to map a running guest's MAC to its IP. A guest that has
just booted may not be in the table yet, so ``resolve_running_ip`` polls.

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
from tartarus.config import Config  # noqa: E402

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


def _arp_run(stdout: str):
    def fake_run(cmd, **_kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    return fake_run


# --- arp_ip_for_mac -------------------------------------------------------


def test_macos_arp_format_matches_zero_stripped_mac():
    assert ssh.arp_ip_for_mac(ARP_LITELLM, "02:00:00:00:00:0c") == "192.168.64.54"


def test_linux_arp_format_matches():
    line = "litellm (10.200.0.12) at 02:00:00:00:00:0c [ether] on trs0\n"
    assert ssh.arp_ip_for_mac(line, "02:00:00:00:00:0c") == "10.200.0.12"


def test_arp_miss_returns_none():
    assert ssh.arp_ip_for_mac(ARP_OTHER, "02:00:00:00:00:0c") is None


# --- resolve_running_ip ---------------------------------------------------


def test_waits_until_the_arp_entry_appears(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    _running_state(config)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)

    outputs = iter([ARP_OTHER, ARP_OTHER, ARP_LITELLM])
    monkeypatch.setattr(
        ssh.subprocess,
        "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, next(outputs), ""),
    )
    monkeypatch.setattr(ssh.time, "sleep", lambda _seconds: None)

    assert ssh.resolve_running_ip(config, "litellm") == "192.168.64.54"

    # The progress note must not touch stdout: this path backs ssh's
    # ProxyCommand, where stdout is the SSH transport.
    captured = capsys.readouterr()
    assert "waiting for 'litellm'" in captured.err
    assert captured.out == ""


def test_dies_once_the_wait_expires(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    _running_state(config)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh.subprocess, "run", _arp_run(ARP_OTHER))
    monkeypatch.setattr(ssh.time, "sleep", lambda _seconds: None)

    ticks = iter([0.0, 0.0, 1000.0])
    monkeypatch.setattr(ssh.time, "monotonic", lambda: next(ticks))

    with pytest.raises(SystemExit) as exc:
        ssh.resolve_running_ip(config, "litellm")
    assert exc.value.code == 1
    assert "no ARP entry for 'litellm'" in capsys.readouterr().err


def test_does_not_wait_when_the_guest_is_stopped(monkeypatch, capsys, tmp_path):
    config = make_config(tmp_path)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: False)

    with pytest.raises(SystemExit) as exc:
        ssh.resolve_running_ip(config, "litellm")
    assert exc.value.code == 1
    assert "is not running" in capsys.readouterr().err

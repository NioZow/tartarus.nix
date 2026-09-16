"""Tests for relay parsing in config.toml and lifecycle helpers in vm.py.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_relays.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus.config import Config, Guest, GuestRelay  # noqa: E402


def _load_toml(toml: bytes) -> Config:
    import tempfile
    from tartarus.config import load_config

    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as fh:
        fh.write(toml)
        fh.flush()
        parsed = load_config({"config": fh.name})
        Path(fh.name).unlink(missing_ok=True)
        return parsed


def test_relays_default_to_empty():
    toml = b"""
user = "user"
home = "/home/user"
system = "x86_64-linux"
flake = "/home/user/.config/nixcfg"
state_root = "/home/user/.local/state/tartarus"
ssh_dir = "/home/user/.ssh"
ssh_ca_dir = "/home/user/.local/share/tartarus/ssh"
x509_ca_dir = "/home/user/.local/share/tartarus/x509"
log = false

[proxy]
enable = false
location = "host"
port = 3128
listen_addresses = []
log = false

[[guests]]
name = "a"
kind = "vm"
id = 3
internet = true
graphical = false
autostart = false
shared_folder = false
requires = []
proxy = { enable = false, allow_hosts = [] }
"""
    parsed = _load_toml(toml)
    a = parsed.guest("a", "vm")
    assert a is not None
    assert a.relays == []


def test_relays_parsed_correctly():
    toml = b"""
user = "user"
home = "/home/user"
system = "x86_64-linux"
flake = "/home/user/.config/nixcfg"
state_root = "/home/user/.local/state/tartarus"
ssh_dir = "/home/user/.ssh"
ssh_ca_dir = "/home/user/.local/share/tartarus/ssh"
x509_ca_dir = "/home/user/.local/share/tartarus/x509"
log = false

[proxy]
enable = false
location = "host"
port = 3128
listen_addresses = []
log = false

[[guests]]
name = "a"
kind = "vm"
id = 3
internet = true
graphical = false
autostart = false
shared_folder = false
requires = []

[[guests.relays]]
port = 5000
protocol = "tcp"

[[guests.relays]]
port = 53
target_port = 53
protocol = "udp"
host = "192.168.64.1"

proxy = { enable = false, allow_hosts = [] }
"""
    parsed = _load_toml(toml)
    a = parsed.guest("a", "vm")
    assert a is not None
    assert len(a.relays) == 2
    r0 = a.relays[0]
    assert r0.port == 5000
    assert r0.target_port is None
    assert r0.protocol == "tcp"
    assert r0.host is None
    r1 = a.relays[1]
    assert r1.port == 53
    assert r1.target_port == 53
    assert r1.protocol == "udp"
    assert r1.host == "192.168.64.1"

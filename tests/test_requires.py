"""Tests for ``Guest.requires`` parsing and defaults.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_requires.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

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


def test_guest_requires_default_is_empty():
    guest = Guest(name="vault", kind="vm", id=3)
    assert guest.requires == []


def test_config_parses_requires_from_toml():
    toml = b"""
[user]
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
requires = ["b", "c"]
proxy = { enable = false, allow_hosts = [] }

[[guests]]
name = "b"
kind = "container"
id = 4
internet = true
graphical = false
autostart = false
shared_folder = false
requires = []
proxy = { enable = false, allow_hosts = [] }
"""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as fh:
        fh.write(toml)
        fh.flush()
        config = Config(
            user="user",
            home_dir=Path("/home/user"),
            flake_path=Path("/home/user/.config/nixcfg"),
            system="x86_64-linux",
            state_root=Path("/home/user/.local/state/tartarus"),
            ssh_dir=Path("/home/user/.ssh"),
            ssh_ca_dir=Path("/home/user/.local/share/tartarus/ssh"),
            x509_ca_dir=Path("/home/user/.local/share/tartarus/x509"),
            enabled_guests=[],
            config_path=None,
        )
        config.config_path = Path(fh.name)
        # Use the file path passed to overrides so load_config reads it.
    from tartarus.config import load_config

    parsed = load_config({"config": fh.name})
    a = parsed.guest("a", "vm")
    b = parsed.guest("b", "container")
    assert a is not None
    assert a.requires == ["b", "c"]
    assert b is not None
    assert b.requires == []
    Path(fh.name).unlink(missing_ok=True)

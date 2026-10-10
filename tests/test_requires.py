"""Tests for ``Guest.requires`` parsing and defaults.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_requires.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import ctn, ssh, vm  # noqa: E402
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


# --- vm._ensure_dependencies: container deps dispatch to the container path -


def _nested_dns_config() -> tuple[Config, Guest, Guest, Guest]:
    """A VM ``dev`` requiring the nested container ``dns`` inside VM ``network``.

    ``dns`` is a ``kind = "container"`` guest with a non-null ``host`` (the
    athena topology from the plan), and ``network`` is the container-host VM, so
    :meth:`Config.require_guest` resolves both.
    """
    network = Guest(name="network", kind="vm", id=9, container_host=True)
    dns = Guest(name="dns", kind="container", id=3, host="network")
    dev = Guest(name="dev", kind="vm", id=7, requires=["dns"])
    return make_config(network, dns, dev), network, dns, dev


def test_vm_requires_container_dep_dispatches_to_ctn(monkeypatch):
    """A VM requiring a nested container brings it up via ``ctn.action_start``.

    ``vm._ensure_dependencies`` must route a ``kind == "container"`` dependency
    (the nested ``dns``) through ``ctn.action_start`` -- whose own start
    escalates to the host VM -- and must NOT call ``vm.action_start`` for it.
    """
    config, _network, _dns, _dev = _nested_dns_config()

    monkeypatch.setattr(ssh, "is_running", lambda _config, _name: False)
    ctn_calls: list[str] = []
    monkeypatch.setattr(ctn, "action_start", lambda _config, name: ctn_calls.append(name))
    vm_calls: list[str] = []
    monkeypatch.setattr(vm, "action_start", lambda _config, name, mounts=None: vm_calls.append(name))

    vm._ensure_dependencies(config, "dev")

    assert ctn_calls == ["dns"]
    assert vm_calls == []


def test_vm_requires_container_dep_noop_when_root_pid_running(monkeypatch):
    """An already-running container dep needs no host-aware VM-side mechanism.

    ``ssh.is_running`` for a container name is a VM-pid check that (per the
    plan) returns ``False`` for a genuine container, but when it reports the
    dependency up, ``_ensure_dependencies`` must short-circuit and start
    nothing -- no ``ctn.action_start`` and no ``vm.action_start``.
    """
    config, _network, _dns, _dev = _nested_dns_config()

    monkeypatch.setattr(ssh, "is_running", lambda _config, _name: True)
    monkeypatch.setattr(
        ctn, "action_start", lambda *_args, **_kwargs: pytest.fail("container start ran for a running dep")
    )
    monkeypatch.setattr(
        vm, "action_start", lambda *_args, **_kwargs: pytest.fail("VM start ran for a running dep")
    )

    vm._ensure_dependencies(config, "dev")


# --- ctn.action_start: a nested dep escalates to its container-host VM ------


class _FakeResult:
    """Minimal stand-in for a ``subprocess.CompletedProcess``."""

    returncode = 0
    stderr = ""


def test_nested_ctn_start_escalates_to_host_vm(monkeypatch):
    """Starting a nested ``dns`` starts its (down) host VM ``network`` first.

    Mirrors ``test_container_host._patch_nested_start``: the host-VM start is
    recorded, inner unit control goes through ``nested_systemctl``, and
    ``nixos-container`` is never invoked.
    """
    network = Guest(name="network", kind="vm", id=9, container_host=True)
    dns = Guest(name="dns", kind="container", id=3, host="network")
    config = make_config(network, dns)

    monkeypatch.setattr(ctn, "base_name", lambda _config, _name: "dns")
    monkeypatch.setattr(ctn, "require_template", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _config, _name: False)
    monkeypatch.setattr(ctn.ca, "ensure_ctn_certs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ctn, "run_sudo", lambda *_args, **_kwargs: pytest.fail("nixos-container was invoked"))
    monkeypatch.setattr(
        ctn, "run_sudo_quiet", lambda *_args, **_kwargs: pytest.fail("nixos-container was invoked")
    )
    vm_calls: list[tuple] = []
    monkeypatch.setattr(
        vm,
        "action_start",
        lambda _config, name, mounts, upgrade=False: vm_calls.append((name, mounts, upgrade)),
    )
    monkeypatch.setattr(ctn, "nested_state", lambda *_args, **_kwargs: "stopped")
    ctl: list[tuple] = []
    monkeypatch.setattr(
        ctn,
        "nested_systemctl",
        lambda _config, host, verb, name: ctl.append((host, verb, name)) or _FakeResult(),
    )

    ctn.action_start(config, "dns")

    assert vm_calls == [("network", [], False)]
    assert ctl == [("network", "start", "dns")]

"""Tests for container-host VMs and nested containers (plan P4).

Covers the config.toml schema-2 fields (``container_host`` / ``host``), the
``Config.inner_guests`` lookup, and the CLI routing that makes a nested
container start/build/ssh through its host VM instead of ``nixos-container``.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_container_host.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import cli, ctn, vm  # noqa: E402
from tartarus import ssh as ssh_mod  # noqa: E402
from tartarus.config import Config, Guest, load_config  # noqa: E402
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


def make_config_in(tmp_path: Path, *guests: Guest) -> Config:
    """A Config whose state and home dirs live under ``tmp_path``."""
    config = make_config(*guests)
    config.home_dir = tmp_path / "home"
    config.state_root = tmp_path / "state"
    return config


CH = Guest(name="ch", kind="vm", id=5, container_host=True)
INNER = Guest(name="inner", kind="container", id=6, host="ch")
BOX = Guest(name="box", kind="container", id=7)


class _Exec(Exception):
    """Raised by the fake ``os.execvp`` so the real one never runs."""


# --- config.toml parsing --------------------------------------------------


SCHEMA2_TOML = b"""
user = "user"
home = "/home/user"
system = "x86_64-linux"
flake = "/home/user/.config/nixcfg"
state_root = "/home/user/.local/state/tartarus"
ssh_dir = "/home/user/.ssh"
ssh_ca_dir = "/home/user/.local/share/tartarus/ssh"
x509_ca_dir = "/home/user/.local/share/tartarus/x509"
log = false
schema = 2

[proxy]
enable = false
location = "host"
port = 3128
listen_addresses = []
log = false

[[guests]]
name = "ch"
kind = "vm"
id = 5
internet = true
graphical = false
autostart = false
shared_folder = false
container_host = true
requires = []
proxy = { enable = false, allow_hosts = [] }

[[guests]]
name = "inner"
kind = "container"
id = 6
internet = true
graphical = false
autostart = false
shared_folder = false
host = "ch"
requires = []
proxy = { enable = false, allow_hosts = [] }

[[guests]]
name = "box"
kind = "container"
id = 7
internet = true
graphical = false
autostart = false
shared_folder = false
requires = []
proxy = { enable = false, allow_hosts = [] }
"""


def _load(tmp_path: Path, toml: bytes) -> Config:
    path = tmp_path / "config.toml"
    path.write_bytes(toml)
    return load_config({"config": str(path)})


def test_schema2_fields_parse(tmp_path):
    parsed = _load(tmp_path, SCHEMA2_TOML)

    assert parsed.schema == 2
    ch = parsed.guest("ch", "vm")
    assert ch is not None and ch.container_host is True and ch.host is None
    inner = parsed.guest("inner", "container")
    assert inner is not None and inner.host == "ch" and inner.container_host is False
    box = parsed.guest("box", "container")
    assert box is not None and box.host is None


def test_old_schema_defaults(tmp_path):
    # A schema-1 file (no `schema`, no `container_host`, no `host`) must keep
    # parsing, with the new fields defaulting.
    old = b"""
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
name = "vault"
kind = "vm"
id = 3
internet = true
graphical = false
autostart = false
shared_folder = false
requires = []
proxy = { enable = false, allow_hosts = [] }
"""
    parsed = _load(tmp_path, old)
    assert parsed.schema == 1
    vault = parsed.guest("vault", "vm")
    assert vault is not None and vault.container_host is False and vault.host is None


def test_non_string_host_rejected(tmp_path):
    bad = SCHEMA2_TOML.replace(b'host = "ch"', b"host = 5")
    with pytest.raises(TartarusError) as exc:
        _load(tmp_path, bad)
    assert "`host` must be a non-empty string" in str(exc.value)


# --- Config.inner_guests --------------------------------------------------


def test_inner_guests_lists_only_nested_containers():
    config = make_config(CH, INNER, BOX)
    assert config.inner_guests("ch") == [INNER]
    assert config.inner_guests("box") == []
    assert config.inner_guests("ghost") == []


def test_inner_guests_preserves_stable_order():
    b = Guest(name="b-inner", kind="container", id=8, host="ch")
    a = Guest(name="a-inner", kind="container", id=9, host="ch")
    config = make_config(CH, b, a)
    # Order follows `enabled_guests` (config.toml emits sorted-by-name).
    assert config.inner_guests("ch") == [b, a]


# --- vm.action_start: publish inner key material --------------------------


class _FakeProc:
    pid = 4242


def _patch_vm_build_path(monkeypatch, config, name: str = "ch"):
    """Mock everything ``vm.action_start`` touches once past its running check."""
    monkeypatch.setattr(vm.flake, "base_name", lambda _c, _k, n: n)
    monkeypatch.setattr(vm.flake, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.flake, "guest_id", lambda _c, _k, _n: 5)
    monkeypatch.setattr(vm, "_reap_stale_vfkits", lambda *_a, **_k: 0)
    monkeypatch.setattr(vm.ssh, "is_running", lambda _c, _n: False)
    monkeypatch.setattr(vm, "_ensure_dependencies", lambda *_a, **_k: None)
    monkeypatch.setattr(vm, "_start_relays", lambda *_a, **_k: None)
    monkeypatch.setattr(vm.platform, "system", lambda: "Linux")
    state = config.state_dir(name)
    state.mkdir(parents=True, exist_ok=True)
    (state / "result").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(vm, "_build_runner", lambda _c, _n, _m, upgrade=False: (state / "result", None))
    monkeypatch.setattr(vm.subprocess, "Popen", lambda *_a, **_k: _FakeProc())
    return state


def test_container_host_start_ensures_inner_certs(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    _patch_vm_build_path(monkeypatch, config)
    monkeypatch.setattr(vm.ca, "ensure_vm_certs", lambda *_a, **_k: None)
    ensured: list[str] = []
    monkeypatch.setattr(vm.ca, "ensure_ctn_certs", lambda _c, name: ensured.append(name))

    vm.action_start(config, "ch", mounts=[])

    assert ensured == ["inner"]


def test_container_host_start_skips_certs_when_already_running(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(vm.flake, "base_name", lambda _c, _k, name: name)
    monkeypatch.setattr(vm.flake, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(vm, "_reap_stale_vfkits", lambda *_a, **_k: 0)
    monkeypatch.setattr(vm.ssh, "is_running", lambda _c, _n: True)
    monkeypatch.setattr(vm.ca, "ensure_vm_certs", lambda *_a, **_k: pytest.fail("cert work ran for a running VM"))
    monkeypatch.setattr(vm.ca, "ensure_ctn_certs", lambda *_a, **_k: pytest.fail("cert work ran for a running VM"))
    state = config.state_dir("ch")
    state.mkdir(parents=True, exist_ok=True)
    (state / "microvm.pid").write_text("123\n")

    vm.action_start(config, "ch", mounts=[])

    assert "already running" in capsys.readouterr().err


def test_plain_vm_start_ignores_inner_certs(monkeypatch, tmp_path):
    plain = Guest(name="plain", kind="vm", id=5)
    config = make_config_in(tmp_path, plain)
    _patch_vm_build_path(monkeypatch, config, "plain")
    ensured_vm: list[str] = []
    monkeypatch.setattr(vm.ca, "ensure_vm_certs", lambda _c, name: ensured_vm.append(name))
    monkeypatch.setattr(vm.ca, "ensure_ctn_certs", lambda *_a, **_k: pytest.fail("inner certs for a plain VM"))

    vm.action_start(config, "plain", mounts=[])

    assert ensured_vm == ["plain"]


def _done(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _patch_nested_start(monkeypatch, state: str = "stopped") -> tuple[list[tuple], list[tuple]]:
    """Mock the VM start, the unit-state probe and the SSH systemctl."""
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ca, "ensure_ctn_certs", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn, "run_sudo", lambda *_a, **_k: pytest.fail("nixos-container was invoked"))
    monkeypatch.setattr(ctn, "run_sudo_quiet", lambda *_a, **_k: pytest.fail("nixos-container was invoked"))
    started: list[tuple] = []
    monkeypatch.setattr(
        vm, "action_start", lambda _c, name, mounts, upgrade=False: started.append((name, mounts, upgrade))
    )
    monkeypatch.setattr(ctn, "nested_state", lambda *_a, **_k: state)
    ctl: list[tuple] = []
    monkeypatch.setattr(
        ctn, "nested_systemctl", lambda _c, host, verb, name: ctl.append((host, verb, name)) or _done()
    )
    return started, ctl


# --- ctn.action_start: delegate to the host VM, then start the unit --------


def test_nested_start_delegates_to_host_vm(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    started, ctl = _patch_nested_start(monkeypatch)

    ctn.action_start(config, "inner")

    assert started == [("ch", [], False)]
    assert ctl == [("ch", "start", "inner")]


def test_nested_start_forwards_upgrade_to_host_vm(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    started, ctl = _patch_nested_start(monkeypatch)

    ctn.action_start(config, "inner", upgrade=True)

    assert started == [("ch", [], True)]
    assert ctl == [("ch", "start", "inner")]


def test_nested_start_noop_when_already_running(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    started, ctl = _patch_nested_start(monkeypatch, state="running")

    ctn.action_start(config, "inner")

    assert started == [("ch", [], False)]
    assert ctl == []


def test_nested_start_ensures_own_certs_when_host_vm_already_running(monkeypatch, tmp_path):
    # The host VM start already certifies every inner container; when it is up
    # it is skipped, so a container added after boot would otherwise never get
    # its client cert. The nested start must ensure its own material.
    config = make_config_in(tmp_path, CH, INNER)
    started, ctl = _patch_nested_start(monkeypatch)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: True)
    ensured: list[str] = []
    monkeypatch.setattr(ctn.ca, "ensure_ctn_certs", lambda _c, name: ensured.append(name))

    ctn.action_start(config, "inner")

    assert started == []
    assert ensured == ["inner"]
    assert ctl == [("ch", "start", "inner")]


# --- ctn.action_stop / action_restart: drive the unit over SSH ------------


def test_nested_stop_over_ssh(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: True)
    ctl: list[tuple] = []
    monkeypatch.setattr(
        ctn, "nested_systemctl", lambda _c, host, verb, name: ctl.append((host, verb, name)) or _done()
    )

    ctn.action_stop(config, "inner", False)

    assert ctl == [("ch", "stop", "inner")]


def test_nested_stop_when_vm_down(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: False)
    monkeypatch.setattr(ctn, "nested_systemctl", lambda *_a, **_k: pytest.fail("ssh systemctl was invoked"))

    ctn.action_stop(config, "inner", False)

    assert "is down" in capsys.readouterr().err


def test_nested_stop_purge_rejected(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)

    with pytest.raises(SystemExit) as exc:
        ctn.action_stop(config, "inner", True)
    assert exc.value.code == 1


def test_nested_restart_over_ssh(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: True)
    monkeypatch.setattr(ctn, "run_sudo", lambda *_a, **_k: pytest.fail("host systemctl was invoked"))
    ctl: list[tuple] = []
    monkeypatch.setattr(
        ctn, "nested_systemctl", lambda _c, host, verb, name: ctl.append((host, verb, name)) or _done()
    )

    ctn.action_restart(config, "inner")

    assert ctl == [("ch", "restart", "inner")]


def test_nested_status_queries_unit_state(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn, "nested_state", lambda _c, _h, _n: "running")

    ctn.action_status(config, "inner")

    out = capsys.readouterr().out
    assert "nested in container-host VM 'ch'" in out
    assert "running" in out


# --- nested unit control goes over root SSH (no sudoers grant) ------------


def test_nested_systemctl_runs_as_root_over_ssh(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    calls: list[list[str]] = []

    def _run(argv, **_kwargs):
        calls.append(argv)
        return _done()

    monkeypatch.setattr(ctn.subprocess, "run", _run)

    ctn.nested_systemctl(config, "ch", "stop", "inner")

    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "ssh"
    assert "root@ch" in argv
    assert "sudo" not in argv
    assert argv[-3:] == [ctn.VM_SYSTEMCTL, "stop", "container@inner"]


def test_nested_state_probe_stays_unprivileged(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    calls: list[list[str]] = []

    def _run(argv, **_kwargs):
        calls.append(argv)
        return _done(stdout="active\n")

    monkeypatch.setattr(ctn.subprocess, "run", _run)

    assert ctn.nested_state(config, "ch", "inner") == "running"

    argv = calls[0]
    assert "ch" in argv
    assert "root@ch" not in argv
    assert argv[-3:] == [ctn.VM_SYSTEMCTL, "is-active", "container@inner"]


def test_nested_states_batches_in_one_ssh_roundtrip(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    calls: list[list[str]] = []

    def _run(argv, **_kwargs):
        calls.append(argv)
        return _done(stdout="dotfiles active\ninner inactive\n")

    monkeypatch.setattr(ctn.subprocess, "run", _run)

    states = ctn.nested_states(config, "ch", ["dotfiles", "inner"])

    assert states == {"dotfiles": "running", "inner": "stopped"}
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "ssh"
    assert "ch" in argv
    # ssh joins the remote-command arguments with spaces, so the whole script
    # must be ONE argv element. Passing ["sh", "-c", script] lets ssh send
    # `sh -c printf ...`, whose first token is dropped -- misreporting the first
    # name as stopped (the bug this guards).
    assert "-c" not in argv
    assert all(f"container@{n}" in argv[-1] for n in ("dotfiles", "inner"))


# --- ctn.action_build: delegate to the host VM ----------------------------


def test_nested_build_delegates_to_host_vm(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    built: list[tuple] = []
    monkeypatch.setattr(
        vm, "action_build", lambda _c, name, mounts, upgrade=False: built.append((name, mounts, upgrade))
    )

    ctn.action_build(config, "inner", upgrade=True)

    assert built == [("ch", [], True)]


# --- ctn.action_ssh: ProxyJump through the host VM ------------------------


def _nested_ssh_config(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn, "is_running", lambda _n: False)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: True)
    monkeypatch.setattr(ctn.ca, "ensure_ctn_certs", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ssh, "known_hosts_trs", lambda c: c.ssh_dir / "known_hosts_trs")
    return config


def test_nested_ssh_builds_proxyjump_argv(monkeypatch, tmp_path):
    config = _nested_ssh_config(monkeypatch, tmp_path)
    calls: list[tuple] = []

    def _execvp(prog, argv):
        calls.append((prog, argv))
        raise _Exec

    monkeypatch.setattr(ctn.os, "execvp", _execvp)

    with pytest.raises(_Exec):
        ctn.action_ssh(config, "inner")

    assert len(calls) == 1
    prog, argv = calls[0]
    assert prog == "ssh"
    assert "ProxyJump=ch.trs" in argv
    assert "HostKeyAlias=inner.trs" in argv
    assert "HostName=inner" in argv
    assert argv[-1] == "inner"


def test_nested_ssh_start_starts_host_vm(monkeypatch, tmp_path):
    config = _nested_ssh_config(monkeypatch, tmp_path)
    started: list[str] = []
    monkeypatch.setattr(vm, "action_start", lambda _c, name, mounts, upgrade=False: started.append(name))
    monkeypatch.setattr(ctn.os, "execvp", lambda *_a: (_ for _ in ()).throw(_Exec))

    with pytest.raises(_Exec):
        ctn.action_ssh(config, "inner", start=True)

    assert started == ["ch"]


def test_nested_ssh_without_start_refuses_stopped_host(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)
    monkeypatch.setattr(ctn.ssh, "is_running", lambda _c, _n: False)

    with pytest.raises(TartarusError) as exc:
        ctn.action_ssh(config, "inner")
    assert "container-host VM 'ch' is not running" in str(exc.value)


# --- ctn commands with no host-side equivalent refuse a nested container --


@pytest.mark.parametrize(
    "call",
    [
        lambda config: ctn.action_logs(config, "inner"),
        lambda config: ctn.action_spawn(config, "inner", None),
    ],
)
def test_nested_lifecycle_commands_refused(monkeypatch, tmp_path, call):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "base_name", lambda _c, _n: "inner")
    monkeypatch.setattr(ctn, "require_template", lambda *_a, **_k: None)

    with pytest.raises(TartarusError) as exc:
        call(config)
    message = str(exc.value)
    assert "nested container" in message
    assert "ch" in message


# --- ssh.py: cid/ip have no host-reachable address ------------------------


@pytest.mark.parametrize("action", [ssh_mod.action_cid, ssh_mod.action_ip])
def test_ssh_cid_ip_refuse_nested(tmp_path, action):
    config = make_config_in(tmp_path, CH, INNER)
    with pytest.raises(TartarusError) as exc:
        action(config, "inner.trs")
    message = str(exc.value)
    assert "nested container" in message
    assert "tartarus --container ssh inner" in message


def test_ssh_refuse_allows_plain_vm(tmp_path):
    config = make_config_in(tmp_path, CH, INNER)
    # A plain VM name is left to the normal VM path (no raise, no nix eval).
    ssh_mod.refuse_nested_container(config, "vault.trs")


# --- list/status show the host association --------------------------------


def test_ctn_list_shows_host(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "list_templates", lambda _c: ["inner"])
    monkeypatch.setattr(ctn, "list_conf_names", lambda: set())
    monkeypatch.setattr(ctn, "nested_states", lambda _c, _h, names: {n: "running" for n in names})

    ctn.action_list(config, json_output=False)

    out = capsys.readouterr().out
    assert "HOST" in out
    assert "inner" in out
    assert "ch" in out


def test_ctn_list_json_includes_host(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH, INNER)
    monkeypatch.setattr(ctn, "list_templates", lambda _c: ["inner"])
    monkeypatch.setattr(ctn, "list_conf_names", lambda: set())
    monkeypatch.setattr(ctn, "nested_states", lambda _c, _h, names: {n: "stopped" for n in names})

    ctn.action_list(config, json_output=True)

    data = json.loads(capsys.readouterr().out)
    assert data[0]["host"] == "ch"


def test_vm_list_marks_container_host(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH)
    monkeypatch.setattr(vm.flake, "list_templates", lambda _c, _k: ["ch"])

    vm.action_list(config, json_output=True)

    data = json.loads(capsys.readouterr().out)
    assert data[0]["container_host"] is True


def test_vm_list_container_host_marker_in_table(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, CH)
    monkeypatch.setattr(vm.flake, "list_templates", lambda _c, _k: ["ch"])

    vm.action_list(config, json_output=False)

    out = capsys.readouterr().out
    assert "container host" in out


# --- collect derives the enabled set from config, not a nix eval ----------


def _no_eval(*_a, **_k):  # pragma: no cover - must never run
    raise AssertionError("collect_instances must not run a nix eval")


def test_vm_collect_does_not_eval_the_flake(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, CH)
    monkeypatch.setattr(vm.flake, "list_templates", _no_eval)
    monkeypatch.setattr(vm.ssh, "is_running", lambda *_a, **_k: False)

    entries = vm.collect_instances(config)

    assert [e["name"] for e in entries] == ["ch"]


def test_ctn_collect_does_not_eval_the_flake(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, INNER, BOX)
    monkeypatch.setattr(ctn.flake, "list_templates", _no_eval)
    monkeypatch.setattr(ctn, "list_conf_names", lambda: set())
    monkeypatch.setattr(ctn, "nested_states", lambda _c, _h, names: {n: "stopped" for n in names})

    entries = ctn.collect_instances(config)

    assert [e["name"] for e in entries] == ["box", "inner"]


def test_ctn_collect_skips_ssh_when_host_vm_is_down(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, INNER)
    monkeypatch.setattr(ctn, "list_conf_names", lambda: set())
    monkeypatch.setattr(ctn.ssh, "is_running", lambda *_a, **_k: False)

    def fail(*_a, **_k):  # pragma: no cover - must never run
        raise AssertionError("must not SSH to a stopped host VM")

    monkeypatch.setattr(ctn, "nested_states", fail)

    entries = ctn.collect_instances(config)

    assert entries == [
        {"name": "inner", "type": "template", "status": "stopped", "address": None, "host": "ch"}
    ]


# --- CLI guard: nested containers validate as kind = "container" ----------


def test_guard_accepts_nested_container(monkeypatch):
    config = make_config(CH, INNER)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _c: None)
    reached: list[str] = []
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: reached.append(a.command))
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: reached.append(a.command))

    cli.main(["--container", "ssh", "inner"])

    assert reached == ["ssh"]


def test_vm_command_on_nested_container_infers_container(monkeypatch):
    # Without `--container`, the CLI infers the kind from config.toml, so a
    # nested container's name routes to the container path.
    config = make_config(CH, INNER, BOX)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _c: None)
    reached: list[str] = []
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: reached.append(("ctn", a.command)))
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: reached.append(("vm", a.command)))

    cli.main(["ssh", "inner"])
    cli.main(["start", "box"])
    cli.main(["ssh", "ch"])

    assert reached == [("ctn", "ssh"), ("ctn", "start"), ("vm", "ssh")]

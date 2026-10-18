"""Tests for the runtime-mount host CLI skeleton (``tartarus.mounts``)."""

from __future__ import annotations

import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import mounts, ssh  # noqa: E402
from tartarus.config import Config, Guest  # noqa: E402
from tartarus.errors import TartarusError  # noqa: E402


def make_config(state_root: Path, *guests: Guest) -> Config:
    return Config(
        user="user",
        home_dir=Path("/home/user"),
        flake_path=Path("/home/user/.config/nixcfg"),
        system="aarch64-linux",
        state_root=state_root,
        ssh_dir=Path("/home/user/.ssh"),
        ssh_ca_dir=Path("/home/user/.local/share/tartarus/ssh"),
        x509_ca_dir=Path("/home/user/.local/share/tartarus/x509"),
        enabled_guests=list(guests),
    )


VAULT = Guest(name="vault", kind="vm", id=3)
BOX = Guest(name="box", kind="container", id=4)


# --- parse_spec -----------------------------------------------------------


def test_parse_spec_absolute(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    host, target = mounts.parse_spec(f"{source}:/home/user/src")
    assert host == source.resolve()
    assert target == "/home/user/src"


def test_parse_spec_relative_uses_supplied_cwd(tmp_path):
    (tmp_path / "src").mkdir()
    host, target = mounts.parse_spec("src:/home/user/src", cwd=tmp_path)
    assert host == (tmp_path / "src").resolve()
    assert target == "/home/user/src"


def test_parse_spec_expands_tilde(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "src").mkdir()
    host, target = mounts.parse_spec("~/src:/home/user/src")
    assert host == (tmp_path / "src").resolve()
    assert target == "/home/user/src"


def test_parse_spec_rejects_missing_host_path(tmp_path):
    with pytest.raises(TartarusError, match="does not exist"):
        mounts.parse_spec(f"{tmp_path / 'nope'}:/mnt")


def test_parse_spec_rejects_file(tmp_path):
    file_path = tmp_path / "file"
    file_path.write_text("x")
    with pytest.raises(TartarusError, match="not a directory"):
        mounts.parse_spec(f"{file_path}:/mnt")


@pytest.mark.parametrize("value", [":/mnt", "/tmp:", "just-a-path"])
def test_parse_spec_rejects_empty_or_missing_sides(tmp_path, value):
    with pytest.raises(TartarusError, match="invalid mount spec"):
        mounts.parse_spec(value)


def test_parse_spec_rejects_relative_guest_path(tmp_path):
    (tmp_path / "src").mkdir()
    with pytest.raises(TartarusError, match="must be absolute"):
        mounts.parse_spec(f"{tmp_path / 'src'}:mnt")


def test_parse_spec_expands_guest_tilde(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    host, target = mounts.parse_spec(f"{source}:~/src")
    assert host == source.resolve()
    assert target == "/home/user/src"


# --- validate_target ------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/home/user/src", "/home/user/src"),
        ("/a/../b", "/b"),
        ("/a/b/../c", "/a/c"),
    ],
)
def test_validate_target_accepts(value, expected):
    assert mounts.validate_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "/",
        "/proc",
        "/proc/x",
        "/sys",
        "/sys/kernel",
        "/dev",
        "/dev/shm",
        "/run/tartarus-mount",
        "/run/tartarus-mount/staging/x",
        "relative/path",
    ],
)
def test_validate_target_rejects(value):
    with pytest.raises(TartarusError):
        mounts.validate_target(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("~", "/home/user"),
        ("~/src", "/home/user/src"),
        ("~/src/../other", "/home/user/other"),
    ],
)
def test_validate_target_expands_guest_home(value, expected):
    assert mounts.validate_target(value) == expected


def test_validate_target_rejects_named_user_home():
    with pytest.raises(TartarusError, match="only '~' and '~/' expand"):
        mounts.validate_target("~root/src")


# --- resolve_mode ---------------------------------------------------------


def test_resolve_mode_rw_by_default():
    assert mounts.resolve_mode(read_only=False, overlay=False) == "rw"


def test_resolve_mode_read_only():
    assert mounts.resolve_mode(read_only=True, overlay=False) == "ro"


def test_resolve_mode_overlay():
    assert mounts.resolve_mode(read_only=False, overlay=True) == "overlay"


def test_resolve_mode_rejects_both():
    with pytest.raises(TartarusError, match="mutually exclusive"):
        mounts.resolve_mode(read_only=True, overlay=True)


# --- state file -----------------------------------------------------------


def test_write_read_state_round_trip(tmp_path):
    config = make_config(tmp_path)
    entries = [{"id": "a1", "kind": "vm", "target": "/mnt", "mode": "rw"}]
    mounts.write_state(config, "vault", entries)

    assert mounts.read_state(config, "vault") == entries
    path = tmp_path / "vault" / mounts.STATE_NAME
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(path.parent.glob("*.tmp")) == []


def test_write_state_atomically_replaces(tmp_path):
    config = make_config(tmp_path)
    mounts.write_state(config, "vault", [{"target": "/old"}])
    mounts.write_state(config, "vault", [{"target": "/new"}])

    assert mounts.read_state(config, "vault") == [{"target": "/new"}]
    assert list((tmp_path / "vault").glob("*.tmp")) == []


def test_read_state_missing_is_empty(tmp_path):
    config = make_config(tmp_path)
    assert mounts.read_state(config, "ghost") == []


@pytest.mark.parametrize("payload", ["not json", '{"target": "/mnt"}', "[1, 2]"])
def test_read_state_malformed_is_empty(tmp_path, payload):
    config = make_config(tmp_path)
    path = tmp_path / "vault" / mounts.STATE_NAME
    path.parent.mkdir(parents=True)
    path.write_text(payload)
    assert mounts.read_state(config, "vault") == []


def test_append_find_remove_record(tmp_path):
    config = make_config(tmp_path)
    record = {"id": "a1", "kind": "vm", "target": "/mnt", "mode": "rw"}
    mounts.append_record(config, "vault", record)

    assert mounts.find_record(config, "vault", "/mnt") == record
    assert mounts.find_record(config, "vault", "/other") is None

    mounts.remove_record(config, "vault", "/mnt")
    assert mounts.find_record(config, "vault", "/mnt") is None


def test_remove_missing_record_is_idempotent(tmp_path):
    config = make_config(tmp_path)
    mounts.remove_record(config, "vault", "/mnt")
    assert mounts.read_state(config, "vault") == []


# --- collect_mounts status -----------------------------------------------


def test_collect_mounts_vm_stale_when_not_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    mounts.write_state(config, "vault", [{"id": "a1", "kind": "vm", "target": "/mnt"}])
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: False)

    records = mounts.collect_mounts(config, "vault")

    assert len(records) == 1
    assert records[0]["guest"] == "vault"
    assert records[0]["status"] == "stale"


def test_collect_mounts_vm_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    mounts.write_state(config, "vault", [{"id": "a1", "kind": "vm", "target": "/mnt"}])
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: True)

    records = mounts.collect_mounts(config, "vault")

    assert records[0]["status"] == "running"


def test_collect_mounts_container_stale_when_not_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    mounts.write_state(config, "box", [{"id": "b1", "kind": "container", "target": "/mnt"}])
    monkeypatch.setattr(mounts.ctn, "is_running", lambda *_a, **_k: False)

    records = mounts.collect_mounts(config, "box")

    assert records[0]["status"] == "stale"


def test_collect_mounts_container_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    mounts.write_state(config, "box", [{"id": "b1", "kind": "container", "target": "/mnt"}])
    monkeypatch.setattr(mounts.ctn, "is_running", lambda *_a, **_k: True)

    records = mounts.collect_mounts(config, "box")

    assert records[0]["status"] == "running"


def test_collect_mounts_all_guests_scans_state_dirs(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    mounts.write_state(config, "vault", [{"id": "a1", "kind": "vm", "target": "/one"}])
    mounts.write_state(config, "vault-2", [{"id": "a2", "kind": "vm", "target": "/two"}])
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: True)

    records = mounts.collect_mounts(config)

    assert sorted(record["guest"] for record in records) == ["vault", "vault-2"]


# --- actions --------------------------------------------------------------


def test_action_unmount_absent_target_raises(tmp_path):
    config = make_config(tmp_path, VAULT)
    with pytest.raises(TartarusError, match="no runtime mount"):
        mounts.action_unmount(config, "vault", "/mnt")


def test_action_mount_container_records_record(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    record = {
        "id": "deadbeef",
        "kind": "container",
        "source": str(source),
        "target": "/mnt",
        "mode": "rw",
        "stage": "/run/tartarus-mount/staging/deadbeef",
    }
    monkeypatch.setattr(
        mounts, "_mount_container", lambda *_a, **_k: dict(record)
    )

    mounts.action_mount(config, "box", f"{source}:/mnt", kind="container")

    assert mounts.read_state(config, "box") == [record]


# --- ssh.run_remote -------------------------------------------------------


def _completed(argv: list[str], code: int, *, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, code, stdout="", stderr=stderr)


def _forbid_flake_eval(monkeypatch) -> None:
    def _fail(*_a, **_k):
        raise AssertionError("flake evaluated")

    monkeypatch.setattr(ssh.flake, "base_name", _fail)
    monkeypatch.setattr(ssh.flake, "require_template", _fail)
    monkeypatch.setattr(ssh.system, "is_darwin", lambda: False)


def test_run_remote_builds_the_expected_command(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    _forbid_flake_eval(monkeypatch)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh, "resolve_cid", lambda *_a, **_k: "3")

    calls: list[dict] = []

    def _run(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return _completed(argv, 0)

    monkeypatch.setattr(ssh.subprocess, "run", _run)

    remote_argv = ["sh", "-c", "echo hi"]
    result = ssh.run_remote(config, "vault", remote_argv)

    assert result.returncode == 0
    assert len(calls) == 1
    assert calls[0]["kwargs"] == {"capture_output": True, "text": True}

    argv = calls[0]["argv"]
    joined = " ".join(argv)
    assert "ProxyCommand=socat - VSOCK-CONNECT:3:22" in joined
    assert "BatchMode=yes" in joined
    assert "ConnectTimeout=8" in joined
    assert "HostKeyAlias=vault.trs" in joined
    assert "IdentityFile=/home/user/.ssh/tartarus" in joined
    assert argv[-4:-2] == ["-l", "user"]
    assert argv[-2] == "vault"
    assert argv[-1] == shlex.join(remote_argv)


def test_run_remote_does_not_evaluate_flake(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    _forbid_flake_eval(monkeypatch)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh, "resolve_cid", lambda *_a, **_k: "3")
    monkeypatch.setattr(
        ssh.subprocess, "run", lambda argv, **_kwargs: _completed(argv, 0)
    )

    result = ssh.run_remote(config, "vault", ["true"])

    assert result.returncode == 0


def test_run_remote_retries_connection_failures(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    _forbid_flake_eval(monkeypatch)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh, "resolve_cid", lambda *_a, **_k: "3")

    codes = iter([255, 255, 0])
    attempts: list[list[str]] = []

    def _run(argv, **_kwargs):
        attempts.append(argv)
        return _completed(argv, next(codes))

    monkeypatch.setattr(ssh.subprocess, "run", _run)
    sleeps: list[float] = []
    monkeypatch.setattr(ssh.time, "sleep", sleeps.append)

    result = ssh.run_remote(config, "vault", ["true"], retries=5, retry_delay=2.0)

    assert result.returncode == 0
    assert len(attempts) == 3
    assert sleeps == [2.0, 2.0]


def test_run_remote_does_not_retry_command_failures(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    _forbid_flake_eval(monkeypatch)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(ssh, "resolve_cid", lambda *_a, **_k: "3")

    attempts: list[list[str]] = []

    def _run(argv, **_kwargs):
        attempts.append(argv)
        return _completed(argv, 7)

    monkeypatch.setattr(ssh.subprocess, "run", _run)
    monkeypatch.setattr(
        ssh.time, "sleep", lambda _s: pytest.fail("must not sleep on a non-255 exit")
    )

    result = ssh.run_remote(config, "vault", ["false"], retries=5, retry_delay=2.0)

    assert result.returncode == 7
    assert len(attempts) == 1


def test_run_remote_refuses_on_darwin(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    monkeypatch.setattr(ssh.system, "is_darwin", lambda: True)

    with pytest.raises(TartarusError, match="macOS/vfkit"):
        ssh.run_remote(config, "vault", ["true"])


def test_run_remote_refuses_when_not_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    _forbid_flake_eval(monkeypatch)
    monkeypatch.setattr(ssh, "is_running", lambda *_a, **_k: False)

    with pytest.raises(TartarusError, match="not running"):
        ssh.run_remote(config, "vault", ["true"])


# --- VM runtime path ------------------------------------------------------


def _install_fake_remote(monkeypatch, *, helper_code: int = 0) -> list[list[str]]:
    calls: list[list[str]] = []

    def _run(_config, _name, argv, **_kwargs):
        calls.append(list(argv))
        code = helper_code if argv[0] == mounts.MOUNT_HELPER else 0
        return _completed(argv, code, stderr="helper boom" if code else "")

    monkeypatch.setattr(mounts.ssh, "run_remote", _run)
    return calls


def _install_fake_sudo(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def _run(cmd, **_kwargs):
        calls.append(list(cmd))
        return _completed(cmd, 0)

    monkeypatch.setattr(mounts.process, "run_sudo_capture", _run)
    return calls


def test_mount_vm_refuses_on_darwin(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    monkeypatch.setattr(mounts.system, "is_darwin", lambda: True)

    with pytest.raises(TartarusError, match="macOS/vfkit"):
        mounts._mount_vm(config, "vault", tmp_path / "src", "/mnt", "rw")


@pytest.mark.parametrize(
    ("kwargs", "mode"),
    [({}, "rw"), ({"read_only": True}, "ro"), ({"overlay": True}, "overlay")],
)
def test_action_mount_vm_happy_path(monkeypatch, tmp_path, kwargs, mode):
    config = make_config(tmp_path, VAULT)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(mounts.secrets, "token_hex", lambda _n: "deadbeef")
    remote = _install_fake_remote(monkeypatch)
    sudo = _install_fake_sudo(monkeypatch)

    mounts.action_mount(config, "vault", f"{source}:/home/user/src", **kwargs)

    stage = tmp_path / "vault" / mounts.STAGING_NAME / "deadbeef"
    record = mounts.read_state(config, "vault")[0]
    assert record == {
        "id": "deadbeef",
        "kind": "vm",
        "source": str(source.resolve()),
        "target": "/home/user/src",
        "mode": mode,
        "stage": str(stage),
    }
    assert remote[0][0] == "sh"
    assert remote[1] == [
        mounts.MOUNT_HELPER,
        "mount",
        "deadbeef",
        "/home/user/src",
        mode,
    ]

    expected_sudo = [["mount", "--bind", str(source.resolve()), str(stage)]]
    if mode in ("ro", "overlay"):
        expected_sudo.append(["mount", "-o", "remount,ro,bind", str(stage)])
    assert sudo == expected_sudo
    assert stage.is_dir()


def test_action_mount_vm_helper_failure_releases_stage(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    source = tmp_path / "src"
    source.mkdir()
    stage = tmp_path / "vault" / mounts.STAGING_NAME / "deadbeef"
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: True)
    monkeypatch.setattr(mounts.secrets, "token_hex", lambda _n: "deadbeef")
    _install_fake_remote(monkeypatch, helper_code=1)
    sudo = _install_fake_sudo(monkeypatch)
    monkeypatch.setattr(mounts.os.path, "ismount", lambda path: Path(path) == stage)

    with pytest.raises(TartarusError, match="failed to mount"):
        mounts.action_mount(config, "vault", f"{source}:/home/user/src")

    assert ["umount", str(stage)] in sudo
    assert not stage.exists()
    assert mounts.read_state(config, "vault") == []


def test_unmount_vm_running_calls_helper_and_releases_stage(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    stage = tmp_path / "vault" / mounts.STAGING_NAME / "deadbeef"
    stage.mkdir(parents=True)
    record = {
        "id": "deadbeef",
        "kind": "vm",
        "target": "/home/user/src",
        "stage": str(stage),
    }
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: True)
    remote = _install_fake_remote(monkeypatch)
    sudo = _install_fake_sudo(monkeypatch)
    monkeypatch.setattr(mounts.os.path, "ismount", lambda _path: True)

    mounts._unmount_vm(config, "vault", record)

    assert remote == [
        [mounts.MOUNT_HELPER, "umount", "/home/user/src"],
    ]
    assert ["umount", str(stage)] in sudo
    assert not stage.exists()


def test_unmount_vm_guest_down_skips_helper_but_releases_stage(monkeypatch, tmp_path):
    config = make_config(tmp_path, VAULT)
    stage = tmp_path / "vault" / mounts.STAGING_NAME / "deadbeef"
    stage.mkdir(parents=True)
    record = {
        "id": "deadbeef",
        "kind": "vm",
        "target": "/home/user/src",
        "stage": str(stage),
    }
    monkeypatch.setattr(mounts.ssh, "is_running", lambda *_a, **_k: False)
    monkeypatch.setattr(
        mounts.ssh,
        "run_remote",
        lambda *_a, **_k: pytest.fail("must not run the guest helper when down"),
    )
    sudo = _install_fake_sudo(monkeypatch)
    monkeypatch.setattr(mounts.os.path, "ismount", lambda _path: False)

    mounts._unmount_vm(config, "vault", record)

    assert sudo == []
    assert not stage.exists()


# --- container runtime path ----------------------------------------------


def _completed_full(
    argv: list[str], code: int, *, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)


def _container_ready(
    monkeypatch,
    *,
    leader: int = 123,
    running: bool = True,
    nested: str | None = None,
    idmap: bool = False,
    stub_nested_host: bool = True,
) -> None:
    if stub_nested_host:
        monkeypatch.setattr(mounts, "_nested_host", lambda *_a, **_k: nested)
    monkeypatch.setattr(mounts.ctn, "is_running", lambda *_a, **_k: running)
    monkeypatch.setattr(mounts, "container_leader", lambda _name: leader)
    monkeypatch.setattr(mounts, "needs_idmap", lambda _leader: idmap)
    monkeypatch.setattr(mounts.secrets, "token_hex", lambda _n: "deadbeef")
    monkeypatch.setattr(mounts.os, "open", lambda *_a, **_k: 3)
    monkeypatch.setattr(mounts.os, "close", lambda _fd: None)


def _install_fake_namespace(monkeypatch, responder=None):
    calls: list[tuple[int, list[str], tuple[int, ...]]] = []

    def _run(leader, argv, *, preserve_fds=()):
        argv = list(argv)
        fds = tuple(preserve_fds)
        calls.append((leader, argv, fds))
        code = responder(leader, argv, fds) if responder is not None else 0
        return _completed_full(argv, code, stderr="namespace boom" if code else "")

    monkeypatch.setattr(mounts, "_namespace_run", _run)
    return calls


def _argv_calls(calls) -> list[list[str]]:
    return [argv for _leader, argv, _fds in calls]


# --- read_id_map / needs_idmap -------------------------------------------


def test_read_id_map_identity(tmp_path):
    path = tmp_path / "uid_map"
    path.write_text("         0          0 4294967295\n")
    assert mounts.read_id_map(path) == (0, 0)


def test_read_id_map_shifted(tmp_path):
    path = tmp_path / "gid_map"
    path.write_text("         0     100000      65536\n")
    assert mounts.read_id_map(path) == (0, 100000)


@pytest.mark.parametrize("payload", ["", "garbage\n", "0\n", "0 nope 5\n"])
def test_read_id_map_malformed_is_none(tmp_path, payload):
    path = tmp_path / "uid_map"
    path.write_text(payload)
    assert mounts.read_id_map(path) is None


def test_read_id_map_missing_is_none(tmp_path):
    assert mounts.read_id_map(tmp_path / "nope") is None


def test_needs_idmap_identity(monkeypatch):
    monkeypatch.setattr(mounts, "read_id_map", lambda _path: (0, 0))
    assert mounts.needs_idmap(1) is False


def test_needs_idmap_shifted(monkeypatch):
    monkeypatch.setattr(mounts, "read_id_map", lambda _path: (0, 100000))
    assert mounts.needs_idmap(1) is True


def test_needs_idmap_unreadable_warns(monkeypatch):
    warnings: list[str] = []
    monkeypatch.setattr(mounts, "read_id_map", lambda _path: None)
    monkeypatch.setattr(mounts, "warn", warnings.append)

    assert mounts.needs_idmap(1) is False
    assert warnings
    assert "nobody/nogroup" in warnings[0]


# --- container_leader -----------------------------------------------------


def test_container_leader_uses_machinectl(monkeypatch):
    calls: list[list[str]] = []

    def _run(argv, **_kwargs):
        calls.append(argv)
        return _completed_full(argv, 0, stdout=" 123 \n")

    monkeypatch.setattr(mounts.subprocess, "run", _run)

    assert mounts.container_leader("box") == 123
    assert calls == [["machinectl", "show", "box", "-p", "Leader", "--value"]]


def test_container_leader_falls_back_to_systemctl_and_children(monkeypatch):
    calls: list[list[str]] = []

    def _run(argv, **_kwargs):
        calls.append(argv)
        if argv[0] == "machinectl":
            return _completed_full(argv, 1, stderr="no machinectl")
        return _completed_full(argv, 0, stdout="456\n")

    monkeypatch.setattr(mounts.subprocess, "run", _run)
    monkeypatch.setattr(mounts, "_first_child_pid", lambda pid: 789 if pid == 456 else 0)

    assert mounts.container_leader("box") == 789
    assert [call[0] for call in calls] == ["machinectl", "systemctl"]
    assert calls[1] == [
        "systemctl",
        "show",
        "-p",
        "MainPID",
        "--value",
        "container@box",
    ]


def test_container_leader_falls_back_to_monitor_when_no_child(monkeypatch):
    def _run(argv, **_kwargs):
        if argv[0] == "machinectl":
            return _completed_full(argv, 1)
        return _completed_full(argv, 0, stdout="456\n")

    monkeypatch.setattr(mounts.subprocess, "run", _run)
    monkeypatch.setattr(mounts, "_first_child_pid", lambda _pid: 0)

    assert mounts.container_leader("box") == 456


def test_container_leader_raises_when_both_fail(monkeypatch):
    def _run(argv, **_kwargs):
        return _completed_full(argv, 1, stderr="nope")

    monkeypatch.setattr(mounts.subprocess, "run", _run)

    with pytest.raises(TartarusError, match="cannot resolve the leader"):
        mounts.container_leader("box")


def test_namespace_run_builds_nsenter_with_preserved_fds(monkeypatch):
    calls: list[tuple[list[str], dict]] = []

    def _run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _completed_full(cmd, 0)

    monkeypatch.setattr(mounts.process, "run_sudo_capture", _run)

    mounts._namespace_run(42, ["umount", "/mnt"], preserve_fds=(5,))

    cmd, kwargs = calls[0]
    assert cmd[0] == "--preserve-fds=3"
    assert cmd[1:5] == ["nsenter", "-t", "42", "-m"]
    assert cmd[-3:] == ["--", "umount", "/mnt"]
    assert kwargs == {"pass_fds": (5,)}


# --- container refusals ---------------------------------------------------


def test_mount_container_refuses_nested(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    _container_ready(monkeypatch, nested="ch")

    with pytest.raises(TartarusError, match="nested container"):
        mounts._mount_container(config, "box", tmp_path / "src", "/mnt", "rw")


def test_mount_container_refuses_when_not_running(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    _container_ready(monkeypatch, running=False)

    with pytest.raises(TartarusError, match="not running"):
        mounts._mount_container(config, "box", tmp_path / "src", "/mnt", "rw")


def test_mount_container_does_not_evaluate_flake(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, stub_nested_host=False)

    def _fail(*_a, **_k):
        raise AssertionError("flake evaluated")

    monkeypatch.setattr(mounts.ctn, "nested_host", _fail)
    _install_fake_namespace(
        monkeypatch,
        responder=lambda _l, argv, _fds: 1
        if argv[:3] == ["test", "-d", "/home/user/src"]
        else 0,
    )

    record = mounts._mount_container(
        config, "box", source, "/home/user/src", "rw"
    )

    assert record["kind"] == "container"
    assert record["target"] == "/home/user/src"


# --- _mount_container modes ----------------------------------------------


def test_mount_container_rw_identity_bind(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, idmap=False)
    calls = _install_fake_namespace(
        monkeypatch,
        responder=lambda _l, argv, _fds: 1 if argv[:3] == ["test", "-d", "/home/user/src"] else 0,
    )

    record = mounts._mount_container(
        config, "box", source, "/home/user/src", "rw"
    )

    stage = "/run/tartarus-mount/staging/deadbeef"
    assert record == {
        "id": "deadbeef",
        "kind": "container",
        "source": str(source),
        "target": "/home/user/src",
        "mode": "rw",
        "stage": stage,
    }

    arguments = _argv_calls(calls)
    assert [
        "mkdir",
        "-p",
        "/run/tartarus-mount/staging",
        "/run/tartarus-mount/overlays",
    ] in arguments
    bind = next(
        argv for argv in arguments if argv[:2] == ["mount", "--bind"] and stage in argv
    )
    assert bind == ["mount", "--bind", "/proc/self/fd/3", stage]
    assert ["mkdir", "-p", "/home/user/src"] in arguments
    assert ["chown", "user:users", "/home/user/src"] in arguments
    assert ["mount", "--bind", stage, "/home/user/src"] in arguments
    assert not any("--map-users" in arg for argv in arguments for arg in argv)

    bind_call = next(call for call in calls if call[1] == bind)
    assert bind_call[2] == (3,)


def test_mount_container_shifted_map_uses_idmap_flags(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, idmap=True)
    calls = _install_fake_namespace(monkeypatch)

    mounts._mount_container(config, "box", source, "/home/user/src", "rw")

    stage = "/run/tartarus-mount/staging/deadbeef"
    bind = [
        "mount",
        "--bind",
        "--map-users=0:0:65536",
        "--map-groups=0:0:65536",
        f"/proc/self/fd/3",
        stage,
    ]
    assert bind in _argv_calls(calls)


def test_mount_container_no_idmap_omits_flags_and_warns(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, idmap=True)
    warnings: list[str] = []
    monkeypatch.setattr(mounts, "warn", warnings.append)
    calls = _install_fake_namespace(monkeypatch)

    mounts._mount_container(
        config, "box", source, "/home/user/src", "rw", no_idmap=True
    )

    arguments = _argv_calls(calls)
    assert not any("--map-users" in arg for argv in arguments for arg in argv)
    assert any("--no-idmap" in message for message in warnings)
    assert any("nobody/nogroup" in message for message in warnings)


def test_mount_container_idmap_failure_falls_back_to_plain_bind(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, idmap=True)
    warnings: list[str] = []
    monkeypatch.setattr(mounts, "warn", warnings.append)

    def _responder(_leader, argv, _fds):
        if argv[:2] == ["mount", "--bind"] and any(
            arg.startswith("--map-") for arg in argv
        ):
            return 1
        return 0

    calls = _install_fake_namespace(monkeypatch, responder=_responder)

    record = mounts._mount_container(
        config, "box", source, "/home/user/src", "rw"
    )

    stage = "/run/tartarus-mount/staging/deadbeef"
    binds = [
        argv
        for argv in _argv_calls(calls)
        if argv[:2] == ["mount", "--bind"] and "/proc/self/fd/3" in argv
    ]
    assert len(binds) == 2
    assert any("--map-users=0:0:65536" in argv for argv in binds)
    assert binds[-1] == ["mount", "--bind", "/proc/self/fd/3", stage]
    assert any("idmapped bind failed" in message for message in warnings)
    assert record["kind"] == "container"


def test_mount_container_plain_bind_failure_releases_and_raises(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch, idmap=True)
    monkeypatch.setattr(mounts, "warn", lambda _message: None)

    def _responder(_leader, argv, _fds):
        if argv[:2] == ["mount", "--bind"]:
            return 1
        return 0

    calls = _install_fake_namespace(monkeypatch, responder=_responder)

    with pytest.raises(TartarusError, match="failed to bind"):
        mounts._mount_container(config, "box", source, "/home/user/src", "rw")

    stage = "/run/tartarus-mount/staging/deadbeef"
    arguments = _argv_calls(calls)
    assert ["umount", stage] in arguments
    assert ["rm", "-rf", stage] in arguments


def test_mount_container_ro_remounts_target_read_only(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch)
    calls = _install_fake_namespace(monkeypatch)

    mounts._mount_container(config, "box", source, "/home/user/src", "ro")

    stage = "/run/tartarus-mount/staging/deadbeef"
    arguments = _argv_calls(calls)
    assert ["mount", "--bind", stage, "/home/user/src"] in arguments
    assert ["mount", "-o", "remount,ro,bind", stage] in arguments
    assert ["mount", "-o", "remount,ro,bind", "/home/user/src"] in arguments


def test_mount_container_overlay_creates_upper_work_and_mounts(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    source = tmp_path / "src"
    source.mkdir()
    _container_ready(monkeypatch)
    calls = _install_fake_namespace(monkeypatch)

    mounts._mount_container(
        config, "box", source, "/home/user/src", "overlay"
    )

    stage = "/run/tartarus-mount/staging/deadbeef"
    overlay = "/run/tartarus-mount/overlays/deadbeef"
    arguments = _argv_calls(calls)
    assert [
        "mkdir",
        "-p",
        f"{overlay}/upper",
        f"{overlay}/work",
    ] in arguments
    assert ["chown", "-R", "user:users", overlay] in arguments

    overlay_mount = next(
        argv for argv in arguments if argv[:4] == ["mount", "-t", "overlay", "overlay"]
    )
    joined = " ".join(overlay_mount)
    assert f"lowerdir={stage}" in joined
    assert f"upperdir={overlay}/upper" in joined
    assert f"workdir={overlay}/work" in joined
    assert "userxattr" in joined
    assert overlay_mount[-1] == "/home/user/src"


# --- _unmount_container ---------------------------------------------------


def test_unmount_container_running_umounts_overlay_and_releases_stage(
    monkeypatch, tmp_path
):
    config = make_config(tmp_path, BOX)
    _container_ready(monkeypatch, running=True)
    calls = _install_fake_namespace(monkeypatch)
    record = {
        "id": "deadbeef",
        "kind": "container",
        "target": "/home/user/src",
        "mode": "overlay",
        "stage": "/run/tartarus-mount/staging/deadbeef",
    }

    mounts._unmount_container(config, "box", record)

    arguments = _argv_calls(calls)
    assert ["umount", "/home/user/src"] in arguments
    assert ["rm", "-rf", "/run/tartarus-mount/overlays/deadbeef"] in arguments
    assert ["umount", "/run/tartarus-mount/staging/deadbeef"] in arguments
    assert ["rm", "-rf", "/run/tartarus-mount/staging/deadbeef"] in arguments


def test_unmount_container_stopped_is_a_noop(monkeypatch, tmp_path):
    config = make_config(tmp_path, BOX)
    _container_ready(monkeypatch, running=False)
    monkeypatch.setattr(
        mounts,
        "_namespace_run",
        lambda *_a, **_k: pytest.fail("must not enter a stopped container"),
    )

    mounts._unmount_container(
        config,
        "box",
        {
            "id": "deadbeef",
            "kind": "container",
            "target": "/home/user/src",
            "mode": "rw",
            "stage": "/run/tartarus-mount/staging/deadbeef",
        },
    )


# --- cleanup_vm_mounts ----------------------------------------------------


def test_cleanup_vm_mounts_releases_recorded_stages(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    root = mounts.staging_root(config, "vault")
    mounted = root / "a1"
    plain = root / "b2"
    mounted.mkdir(parents=True)
    plain.mkdir()
    mounts.write_state(
        config,
        "vault",
        [
            {"id": "a1", "stage": str(mounted)},
            {"id": "b2", "stage": str(plain)},
        ],
    )
    monkeypatch.setattr(mounts.os.path, "ismount", lambda path: Path(path) == mounted)
    sudo = _install_fake_sudo(monkeypatch)

    mounts.cleanup_vm_mounts(config, "vault")

    assert ["umount", str(mounted)] in sudo
    sudo_flat = [" ".join(call) for call in sudo]
    assert all(str(plain) not in call for call in sudo_flat)
    assert not mounted.exists()
    assert not plain.exists()
    assert not mounts.state_path(config, "vault").exists()


def test_cleanup_vm_mounts_removes_untracked_leftover(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    root = mounts.staging_root(config, "vault")
    leftover = root / "leftover"
    leftover.mkdir(parents=True)
    monkeypatch.setattr(mounts.os.path, "ismount", lambda _path: True)
    sudo = _install_fake_sudo(monkeypatch)

    mounts.cleanup_vm_mounts(config, "vault")

    assert ["umount", str(leftover)] in sudo
    assert not leftover.exists()
    assert not mounts.state_path(config, "vault").exists()


def test_cleanup_vm_mounts_nothing_is_a_noop(monkeypatch, tmp_path):
    config = make_config(tmp_path)
    monkeypatch.setattr(mounts.os.path, "ismount", lambda _path: False)
    monkeypatch.setattr(
        mounts.process,
        "run_sudo_capture",
        lambda *_a, **_k: pytest.fail("sudo ran with nothing to clean"),
    )

    mounts.cleanup_vm_mounts(config, "vault")

    assert not mounts.state_path(config, "vault").exists()


# --- cleanup_container_mounts --------------------------------------------


def test_cleanup_container_mounts_removes_state_and_staging(tmp_path):
    config = make_config(tmp_path, BOX)
    mounts.write_state(config, "box", [{"id": "b1", "target": "/mnt"}])
    root = mounts.staging_root(config, "box")
    root.mkdir(parents=True)

    mounts.cleanup_container_mounts(config, "box")

    assert not mounts.state_path(config, "box").exists()
    assert not root.exists()

    # Idempotent second pass.
    mounts.cleanup_container_mounts(config, "box")

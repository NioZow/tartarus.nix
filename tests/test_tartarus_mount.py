"""Unit tests for the tartarus-mount guest helper.

The helper file has a hyphen in its name, so load it explicitly with
importlib instead of a normal import. Everything here is pure Python: no root,
no real mounts, no systemd.
"""

import grp
import importlib.util
import json
import os
import pwd
import types
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "nix/packages/tartarus-mount/tartarus-mount.py"

_spec = importlib.util.spec_from_file_location("tartarus_mount", MODULE_PATH)
tm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tm)

USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name


def ok_result():
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def failed_result(stderr="boom"):
    return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr)


def test_validate_target_accepts_and_normalizes():
    assert tm.validate_target("/home/user/src") == "/home/user/src"
    assert tm.validate_target("/a/../b") == "/b"
    assert tm.validate_target("/home/user/./src/") == "/home/user/src"


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/proc",
        "/proc/x",
        "/sys",
        "/dev",
        "/run/tartarus-mount",
        "/run/tartarus-mount/staging/x",
        "home/user/src",
    ],
)
def test_validate_target_rejects(target):
    with pytest.raises(ValueError):
        tm.validate_target(target)


def test_validate_id_accepts():
    assert tm.validate_id("a1b2c3d4") == "a1b2c3d4"
    assert tm.validate_id("with_underscore-1") == "with_underscore-1"


@pytest.mark.parametrize("value", ["", "../x", "a/b", "a b"])
def test_validate_id_rejects(value):
    with pytest.raises(ValueError):
        tm.validate_id(value)


def test_state_roundtrip_and_atomic_replacement(tmp_path):
    state = tmp_path / "state.json"
    first = [{"id": "a", "target": "/home/user/a", "mode": "rw", "stage": "/run/tartarus-mount/staging/a"}]
    second = [{"id": "b", "target": "/home/user/b", "mode": "ro", "stage": "/run/tartarus-mount/staging/b"}]

    tm.write_state(state, first)
    assert tm.read_state(state) == first

    tm.write_state(state, second)
    assert tm.read_state(state) == second
    assert state.stat().st_mode & 0o777 == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_read_state_missing_or_malformed(tmp_path):
    state = tmp_path / "state.json"
    assert tm.read_state(state) == []

    state.write_text("{not json", encoding="utf-8")
    assert tm.read_state(state) == []

    state.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    assert tm.read_state(state) == []


def test_list_op_drops_stale_targets(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    live = tmp_path / "live"
    stale = tmp_path / "stale"
    live.mkdir()
    stale.mkdir()
    entries = [
        {"id": "live", "target": str(live), "mode": "rw", "stage": "/staging/live"},
        {"id": "stale", "target": str(stale), "mode": "rw", "stage": "/staging/stale"},
    ]
    tm.write_state(state, entries)

    monkeypatch.setattr(tm.os.path, "ismount", lambda path: path == str(live))

    assert tm.list_op(state) == [entries[0]]
    assert tm.read_state(state) == [entries[0]]


def test_umount_op_removes_record_and_overlay(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    overlays = tmp_path / "overlays"
    overlay = overlays / "ov1"
    (overlay / "upper").mkdir(parents=True)
    (overlay / "work").mkdir()
    target = "/home/user/ov"
    tm.write_state(
        state,
        [{"id": "ov1", "target": target, "mode": "overlay", "stage": "/staging/ov1"}],
    )

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    removed = tm.umount_op(target, overlay_dir=overlays, state_file=state)

    assert removed["id"] == "ov1"
    assert calls == [[tm.UMOUNT_BIN, target]]
    assert not overlay.exists()
    assert tm.read_state(state) == []


def test_umount_op_retries_lazily(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    target = "/home/user/src"
    tm.write_state(
        state,
        [{"id": "abc", "target": target, "mode": "rw", "stage": "/staging/abc"}],
    )

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return failed_result() if len(calls) == 1 else ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    tm.umount_op(target, overlay_dir=tmp_path / "overlays", state_file=state)

    assert calls[0] == [tm.UMOUNT_BIN, target]
    assert calls[1] == [tm.UMOUNT_BIN, "-l", target]
    assert tm.read_state(state) == []


def test_umount_op_unknown_target_errors(tmp_path):
    state = tmp_path / "state.json"
    tm.write_state(state, [])

    with pytest.raises(RuntimeError):
        tm.umount_op("/home/user/src", overlay_dir=tmp_path / "overlays", state_file=state)


def _staging(tmp_path, identifier):
    staging = tmp_path / "staging"
    (staging / identifier).mkdir(parents=True)
    return staging


def test_mount_op_rw_binds(tmp_path, monkeypatch):
    staging = _staging(tmp_path, "abc")
    state = tmp_path / "state.json"
    target = tmp_path / "target"
    target.mkdir()

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    entry = tm.mount_op(
        "abc",
        str(target),
        "rw",
        staging_dir=staging,
        overlay_dir=tmp_path / "overlays",
        state_file=state,
        user=USER,
        group=GROUP,
    )

    assert calls == [[tm.MOUNT_BIN, "--bind", str(staging / "abc"), str(target)]]
    assert entry == {
        "id": "abc",
        "target": str(target),
        "mode": "rw",
        "stage": str(staging / "abc"),
    }
    assert tm.read_state(state) == [entry]


def test_mount_op_ro_remounts_read_only(tmp_path, monkeypatch):
    staging = _staging(tmp_path, "abc")
    state = tmp_path / "state.json"
    target = tmp_path / "target"
    target.mkdir()

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    tm.mount_op(
        "abc",
        str(target),
        "ro",
        staging_dir=staging,
        overlay_dir=tmp_path / "overlays",
        state_file=state,
        user=USER,
        group=GROUP,
    )

    assert calls[0] == [tm.MOUNT_BIN, "--bind", str(staging / "abc"), str(target)]
    assert calls[1] == [tm.MOUNT_BIN, "-o", "remount,ro,bind", str(target)]


def test_mount_op_overlay_creates_layers_and_mounts(tmp_path, monkeypatch):
    staging = _staging(tmp_path, "abc")
    overlays = tmp_path / "overlays"
    state = tmp_path / "state.json"
    target = tmp_path / "target"
    target.mkdir()

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    entry = tm.mount_op(
        "abc",
        str(target),
        "overlay",
        staging_dir=staging,
        overlay_dir=overlays,
        state_file=state,
        user=USER,
        group=GROUP,
    )

    upper = overlays / "abc" / "upper"
    work = overlays / "abc" / "work"
    assert upper.is_dir()
    assert work.is_dir()
    assert len(calls) == 1
    command = calls[0]
    assert command[:5] == [tm.MOUNT_BIN, "-t", "overlay", "overlay", "-o"]
    options = command[5]
    assert f"lowerdir={staging / 'abc'}" in options
    assert f"upperdir={upper}" in options
    assert f"workdir={work}" in options
    assert "userxattr" in options
    assert command[6] == str(target)
    assert entry["mode"] == "overlay"


def test_mount_op_is_idempotent(tmp_path, monkeypatch):
    staging = _staging(tmp_path, "abc")
    state = tmp_path / "state.json"
    target = tmp_path / "target"
    target.mkdir()

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return ok_result()

    monkeypatch.setattr(tm.subprocess, "run", fake_run)

    kwargs = {
        "staging_dir": staging,
        "overlay_dir": tmp_path / "overlays",
        "state_file": state,
        "user": USER,
        "group": GROUP,
    }
    first = tm.mount_op("abc", str(target), "rw", **kwargs)
    second = tm.mount_op("abc", str(target), "rw", **kwargs)

    assert first == second
    assert len(calls) == 1
    assert tm.read_state(state) == [first]


def test_mount_op_missing_staging_errors(tmp_path):
    with pytest.raises(RuntimeError):
        tm.mount_op(
            "abc",
            str(tmp_path / "target"),
            "rw",
            staging_dir=tmp_path / "staging",
            overlay_dir=tmp_path / "overlays",
            state_file=tmp_path / "state.json",
            user=USER,
            group=GROUP,
        )


def test_mount_op_refuses_foreign_mountpoint(tmp_path, monkeypatch):
    staging = _staging(tmp_path, "abc")
    target = tmp_path / "target"
    target.mkdir()

    monkeypatch.setattr(tm.os.path, "ismount", lambda path: True)

    with pytest.raises(RuntimeError):
        tm.mount_op(
            "abc",
            str(target),
            "rw",
            staging_dir=staging,
            overlay_dir=tmp_path / "overlays",
            state_file=tmp_path / "state.json",
            user=USER,
            group=GROUP,
        )

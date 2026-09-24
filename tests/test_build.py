"""Tests for the `build` subcommand (guest validation + parser acceptance)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import cli, vm  # noqa: E402
from tartarus.config import Config, Guest  # noqa: E402
from tartarus.nix import flake  # noqa: E402


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


def make_config_in(tmp_path: Path, *guests: Guest) -> Config:
    """A Config whose state and home dirs live under ``tmp_path``."""
    config = make_config(*guests)
    config.home_dir = tmp_path / "home"
    config.state_root = tmp_path / "state"
    return config


def _seed_valid_result(config: Config, name: str) -> Path:
    """A live state/result out-link with a runnable microvm-run inside."""
    result = config.state_dir(name) / "result"
    (result / "bin").mkdir(parents=True, exist_ok=True)
    (result / "bin" / "microvm-run").write_text("#!/bin/sh\n")
    return result


def _record_build(monkeypatch) -> list:
    """Replace nix_eval.build with a recorder; returns the call list."""
    calls: list = []
    monkeypatch.setattr(vm.nix_eval, "build", lambda *args, **kwargs: calls.append((args, kwargs)))
    return calls


@pytest.mark.parametrize("argv,kind", [
    (["build", "vault"], "vm"),
    (["--container", "build", "box"], "container"),
])
def test_build_parser_accepts_command(monkeypatch, argv: list[str], kind: str):
    config = make_config(VAULT, BOX)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)

    reached: list[str] = []
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: reached.append(a.command))
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: reached.append(a.command))
    monkeypatch.setattr(cli.flake, "require_flake", lambda _config: None)

    cli.main(argv)
    assert reached == ["build"]


def test_build_rejects_disabled_guest(monkeypatch, capsys):
    config = make_config(VAULT)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)

    def _no_dispatch(*_a, **_k):  # pragma: no cover
        raise AssertionError("dispatch reached for a disabled guest")

    monkeypatch.setattr(cli.vm, "dispatch", _no_dispatch)
    monkeypatch.setattr(cli.ctn, "dispatch", _no_dispatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(["build", "ghost"])
    assert exc.value.code == 1
    assert "not enabled on this host" in capsys.readouterr().err


# --- _build_runner reuse / rebuild decision -------------------------------


def test_build_runner_reuses_valid_result(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    result = _seed_valid_result(config, "vault")
    calls = _record_build(monkeypatch)

    returned, cid = vm._build_runner(config, "vault", [])

    assert calls == []
    assert returned == result
    assert cid is None


def test_build_runner_upgrade_forces_build(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", [], upgrade=True)

    assert len(calls) == 1


def test_build_runner_mounts_force_build(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", ["/host:/guest"])

    assert len(calls) == 1


def test_build_runner_absent_result_builds(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", [])

    assert len(calls) == 1


def test_build_runner_dangling_result_builds(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    state = config.state_dir("vault")
    state.mkdir(parents=True, exist_ok=True)
    os.symlink(tmp_path / "gone", state / "result")
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", [])

    assert len(calls) == 1


def _write_build_info(config: Config, name: str, mounts: list[str]) -> None:
    (config.state_dir(name) / "build-info.json").write_text(
        json.dumps({"fingerprint": "fp", "result": "x", "built_at": 1, "mounts": mounts})
    )


def test_build_runner_stale_recorded_mount_forces_build(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    _write_build_info(config, "vault", ["/a:/a"])
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", [])

    assert len(calls) == 1


def test_build_runner_empty_recorded_mounts_reuses(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    _write_build_info(config, "vault", [])
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", [])

    assert calls == []


def test_build_runner_matching_mounts_reuses(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    _write_build_info(config, "vault", ["/a:/a"])
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", ["/a:/a"])

    assert calls == []


def test_build_runner_records_mounts(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "fp")

    vm._build_runner(config, "vault", ["/a:/a"])

    assert len(calls) == 1
    info = json.loads((config.state_dir("vault") / "build-info.json").read_text())
    assert info["mounts"] == ["/a:/a"]


# --- cid persistence for numbered instances -------------------------------


def test_build_runner_numbered_instance_persists_allocated_cid(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault-2")
    calls = _record_build(monkeypatch)
    monkeypatch.setattr(flake, "base_name", lambda _c, _k, _n: "vault")
    monkeypatch.setattr(vm.ssh, "alloc_cid", lambda _c: 4242)

    _result, cid = vm._build_runner(config, "vault-2", [])

    assert calls == []
    assert cid == 4242
    assert (config.state_dir("vault-2") / "cid").read_text().strip() == "4242"


def test_build_runner_numbered_instance_reuses_persisted_cid(monkeypatch, tmp_path):
    config = make_config_in(tmp_path, VAULT)
    state = config.state_dir("vault-2")
    _seed_valid_result(config, "vault-2")
    (state / "cid").write_text("7\n")
    monkeypatch.setattr(flake, "base_name", lambda _c, _k, _n: "vault")

    def _boom(_c):  # pragma: no cover - must never run
        raise AssertionError("alloc_cid called despite a persisted cid")

    monkeypatch.setattr(vm.ssh, "alloc_cid", _boom)
    monkeypatch.setattr(vm.nix_eval, "build", lambda *_a, **_k: None)

    _result, cid = vm._build_runner(config, "vault-2", [])

    assert cid == 7


# --- update notice --------------------------------------------------------


def test_build_runner_notices_changed_fingerprint(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    state = config.state_dir("vault")
    (state / "build-info.json").write_text(
        json.dumps({"fingerprint": "old", "result": "x", "built_at": 1})
    )
    _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "new")

    vm._build_runner(config, "vault", [])

    assert "has an update available" in capsys.readouterr().out


def test_build_runner_silent_on_same_fingerprint(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    state = config.state_dir("vault")
    (state / "build-info.json").write_text(
        json.dumps({"fingerprint": "same", "result": "x", "built_at": 1})
    )
    _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "same")

    vm._build_runner(config, "vault", [])

    assert capsys.readouterr().out == ""


def test_build_runner_silent_on_malformed_build_info(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    (config.state_dir("vault") / "build-info.json").write_text("{not json")
    _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: "new")

    vm._build_runner(config, "vault", [])

    assert capsys.readouterr().out == ""


def test_build_runner_silent_when_fingerprint_unavailable(monkeypatch, tmp_path, capsys):
    config = make_config_in(tmp_path, VAULT)
    _seed_valid_result(config, "vault")
    state = config.state_dir("vault")
    (state / "build-info.json").write_text(
        json.dumps({"fingerprint": "old", "result": "x", "built_at": 1})
    )
    _record_build(monkeypatch)
    monkeypatch.setattr(flake, "build_fingerprint", lambda _path: None)

    vm._build_runner(config, "vault", [])

    assert capsys.readouterr().out == ""


# --- parser: --upgrade ----------------------------------------------------


@pytest.mark.parametrize("command", ["start", "build", "spawn", "restart"])
def test_upgrade_flag_reaches_dispatch(monkeypatch, command: str):
    config = make_config(VAULT)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _config: None)

    seen: list[bool] = []
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: seen.append(a.upgrade))
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: seen.append(a.upgrade))

    cli.main([command, "vault", "--upgrade"])

    assert seen == [True]


@pytest.mark.parametrize("command", ["start", "build", "spawn", "restart"])
def test_upgrade_defaults_to_false(monkeypatch, command: str):
    config = make_config(VAULT)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _config: None)

    seen: list[bool] = []
    monkeypatch.setattr(cli.vm, "dispatch", lambda _c, a: seen.append(a.upgrade))
    monkeypatch.setattr(cli.ctn, "dispatch", lambda _c, a: seen.append(a.upgrade))

    cli.main([command, "vault"])

    assert seen == [False]

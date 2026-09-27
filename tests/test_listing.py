"""Tests for the unified ``list`` (MicroVMs + containers, flat or tree).

The listing composes the two per-kind collectors; these tests stub those
collectors so the flattening/tree/JSON logic is exercised without nix or SSH.

Run from the repository root::

    .venv/bin/python -m pytest tests/test_listing.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import cli, listing  # noqa: E402
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


CH = Guest(name="ch", kind="vm", id=5, container_host=True)
INNER = Guest(name="inner", kind="container", id=6, host="ch")
BOX = Guest(name="box", kind="container", id=7)

VM_ENTRIES = [
    {"name": "ch", "type": "template", "status": "running", "pid": "42", "cid": "30", "container_host": True},
    {"name": "plain", "type": "template", "status": "stopped", "pid": None, "cid": None, "container_host": False},
]
CTN_ENTRIES = [
    {"name": "inner", "type": "template", "status": "running", "address": None, "host": "ch"},
    {"name": "box", "type": "template", "status": "stopped", "address": "10.201.0.7", "host": None},
]


@pytest.fixture
def stub_collect(monkeypatch):
    def _apply(vms=None, ctns=None):
        vm_entries = VM_ENTRIES if vms is None else vms
        ctn_entries = CTN_ENTRIES if ctns is None else ctns
        monkeypatch.setattr(listing.vm, "collect_instances", lambda _c: [dict(e) for e in vm_entries])
        monkeypatch.setattr(listing.ctn, "collect_instances", lambda _c: [dict(e) for e in ctn_entries])

    return _apply


# --- collect ---------------------------------------------------------------


def test_collect_tags_kind_and_orders_vms_first(stub_collect):
    stub_collect()
    entries = listing.collect(make_config(CH, INNER, BOX))
    assert [e["name"] for e in entries] == ["ch", "plain", "inner", "box"]
    assert [e["kind"] for e in entries] == ["vm", "vm", "container", "container"]


def test_collect_filters_by_kind(stub_collect):
    stub_collect()
    config = make_config(CH, INNER, BOX)
    assert [e["name"] for e in listing.collect(config, "vm")] == ["ch", "plain"]
    assert [e["name"] for e in listing.collect(config, "container")] == ["inner", "box"]


# --- build_tree ------------------------------------------------------------


def test_build_tree_nests_nested_containers():
    # Build the tagged entries directly (collect is stubbed elsewhere).
    tagged = [{"kind": "vm", **e} for e in VM_ENTRIES] + [{"kind": "container", **e} for e in CTN_ENTRIES]

    roots = listing.build_tree(tagged)

    assert [r["name"] for r in roots] == ["ch", "plain", "box"]
    ch = roots[0]
    assert [c["name"] for c in ch["children"]] == ["inner"]
    assert "children" not in roots[1]


def test_build_tree_keeps_orphan_nested_container_as_root():
    tagged = [{"kind": "container", "name": "inner", "type": "template", "status": "running", "host": "ch"}]
    roots = listing.build_tree(tagged)
    assert [r["name"] for r in roots] == ["inner"]


# --- action_list rendering -------------------------------------------------


def test_action_list_table_shows_both_kinds(stub_collect, capsys):
    stub_collect()
    listing.action_list(make_config(CH, INNER, BOX), json_output=False)
    out = capsys.readouterr().out
    assert "KIND" in out and "HOST" in out
    assert "ch" in out and "container host" in out
    assert "inner" in out and "box" in out


def test_action_list_tree_indents_children(stub_collect, capsys):
    stub_collect()
    listing.action_list(make_config(CH, INNER, BOX), json_output=False, tree=True)
    lines = capsys.readouterr().out.splitlines()
    ch = next(line for line in lines if line.startswith("ch "))
    inner = next(line for line in lines if "inner" in line)
    assert inner.startswith("  inner")
    assert ch.startswith("ch ")


def test_action_list_json_includes_kind(stub_collect, capsys):
    stub_collect()
    listing.action_list(make_config(CH, INNER, BOX), json_output=True)
    data = json.loads(capsys.readouterr().out)
    assert [e["kind"] for e in data] == ["vm", "vm", "container", "container"]


def test_action_list_json_tree_nests_children(stub_collect, capsys):
    stub_collect()
    listing.action_list(make_config(CH, INNER, BOX), json_output=True, tree=True)
    data = json.loads(capsys.readouterr().out)
    by_name = {e["name"]: e for e in data}
    assert [c["name"] for c in by_name["ch"]["children"]] == ["inner"]
    assert "children" not in by_name["box"]


def test_action_list_empty_message(stub_collect, capsys):
    stub_collect(vms=[], ctns=[])
    listing.action_list(make_config(), json_output=False)
    assert "No guests" in capsys.readouterr().out


# --- CLI wiring ------------------------------------------------------------


@pytest.mark.parametrize("argv", [["--container", "list", "--vm"], ["list", "-c", "--vm"]])
def test_list_kind_rejects_vm_and_container(monkeypatch, argv):
    config = make_config(CH)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _c: None)
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 1


@pytest.mark.parametrize(
    ("argv", "expected_kind"),
    [
        (["list", "--json"], None),
        (["list", "--json", "--vm"], "vm"),
        (["-c", "list", "--json"], "container"),
        (["list", "--json", "-c"], "container"),
    ],
)
def test_list_cli_passes_kind(monkeypatch, capsys, argv, expected_kind):
    config = make_config(CH, INNER, BOX)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: config)
    monkeypatch.setattr(cli.flake, "require_flake", lambda _c: None)
    seen: list = []
    monkeypatch.setattr(cli.listing, "collect", lambda _c, kind=None: seen.append(kind) or [])

    cli.main(argv)

    assert seen == [expected_kind]
    assert json.loads(capsys.readouterr().out) == []

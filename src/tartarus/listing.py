"""Unified ``list`` across MicroVMs and containers.

``tartarus list`` shows every enabled guest -- MicroVMs and containers, native
or nested -- in one flat table, or as a tree (``--tree``) that nests containers
under their container-host VM. The per-kind ``vm.action_list`` /
``ctn.action_list`` remain the implementation of a nameless ``status``.
"""

from __future__ import annotations

import json

from . import ctn, vm
from .config import Config
from .output import print_table


def collect(config: Config, kind: str | None = None) -> list[dict]:
    """Every enabled guest, each tagged with ``kind``.

    ``kind`` restricts the result to ``"vm"`` or ``"container"``; ``None``
    returns both, MicroVMs first (the historical table order).
    """
    entries: list[dict] = []
    if kind in (None, "vm"):
        entries += [{"kind": "vm", **e} for e in vm.collect_instances(config)]
    if kind in (None, "container"):
        entries += [{"kind": "container", **e} for e in ctn.collect_instances(config)]
    return entries


def build_tree(entries: list[dict]) -> list[dict]:
    """Nest nested containers under their container-host VM.

    Returns the root entries (MicroVMs and native containers); a VM root carries
    a ``children`` list. A container whose host VM is absent from ``entries``
    (e.g. a containers-only listing) is left a root so nothing is dropped.
    """
    roots: list[dict] = []
    children: dict[str, list[dict]] = {}
    for entry in entries:
        host = entry.get("host")
        if entry["kind"] == "container" and host:
            children.setdefault(host, []).append(entry)
        else:
            roots.append(entry)
    for root in roots:
        if root["kind"] == "vm":
            kids = children.pop(root["name"], [])
            if kids:
                root["children"] = kids
    for orphans in children.values():
        roots += orphans
    return roots


def _type_label(entry: dict) -> str:
    if entry["kind"] == "vm" and entry.get("container_host"):
        return f"{entry['type']} (container host)"
    return entry["type"]


def _detail(entry: dict) -> str:
    if entry["kind"] == "vm":
        parts = []
        if entry.get("pid"):
            parts.append(f"pid {entry['pid']}")
        if entry.get("cid"):
            parts.append(f"cid {entry['cid']}")
        return ", ".join(parts) or "-"
    return entry.get("address") or "-"


def _row(entry: dict, depth: int = 0) -> list[str]:
    return [
        "  " * depth + entry["name"],
        ctn.status_word(entry["status"]),
        entry["kind"],
        _type_label(entry),
        _detail(entry),
        entry.get("host") or "-",
    ]


_HEADERS = ["NAME", "STATUS", "KIND", "TYPE", "DETAIL", "HOST"]


def _rows(entries: list[dict], tree: bool) -> list[list[str]]:
    if not tree:
        return [_row(e) for e in entries]
    rows: list[list[str]] = []
    for root in build_tree(entries):
        rows.append(_row(root))
        for child in root.get("children", []):
            rows.append(_row(child, depth=1))
    return rows


def action_list(
    config: Config, *, json_output: bool, tree: bool = False, kind: str | None = None
) -> None:
    """Print every enabled guest, flat or as a tree, as a table or JSON."""
    entries = collect(config, kind)

    if json_output:
        print(json.dumps(build_tree(entries) if tree else entries, indent=2))
        return

    if not entries:
        print("No guests defined.")
        return

    print_table(_HEADERS, _rows(entries, tree))

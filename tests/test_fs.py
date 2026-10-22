"""Tests for the mount-aware recursive-deletion helper (``tartarus.fs``)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tartarus import fs  # noqa: E402


def test_safe_rmtree_removes_a_normal_tree(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "file").write_text("x", encoding="utf-8")
    (root / "sub" / "nested").write_text("y", encoding="utf-8")

    assert fs.safe_rmtree(root) is True
    assert not root.exists()


def test_safe_rmtree_removes_a_plain_file(tmp_path):
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")

    assert fs.safe_rmtree(target) is True
    assert not target.exists()


def test_safe_rmtree_missing_path_is_a_noop(tmp_path):
    assert fs.safe_rmtree(tmp_path / "nope") is True


def test_safe_rmtree_never_follows_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    precious = outside / "keep.txt"
    precious.write_text("do not delete", encoding="utf-8")

    root = tmp_path / "tree"
    root.mkdir()
    (root / "link").symlink_to(outside)

    assert fs.safe_rmtree(root) is True
    assert not root.exists()
    assert precious.exists()


def test_safe_rmtree_refuses_a_mount_point_root(monkeypatch, tmp_path):
    root = tmp_path / "mounted"
    root.mkdir()
    precious = root / "keep.txt"
    precious.write_text("data", encoding="utf-8")

    monkeypatch.setattr(fs.os.path, "ismount", lambda path: Path(path) == root)
    warnings: list[str] = []

    assert fs.safe_rmtree(root, warn=warnings.append) is False
    assert precious.exists()
    assert warnings and "refusing to delete mount point" in warnings[0]


def test_safe_rmtree_skips_a_nested_mount_point(monkeypatch, tmp_path):
    root = tmp_path / "state"
    mounted = root / "mounts" / "id"
    mounted.mkdir(parents=True)
    precious = mounted / "keep.txt"
    precious.write_text("data", encoding="utf-8")
    sibling = root / "microvm.pid"
    sibling.write_text("123", encoding="utf-8")

    monkeypatch.setattr(fs.os.path, "ismount", lambda path: Path(path) == mounted)
    warnings: list[str] = []

    assert fs.safe_rmtree(root, warn=warnings.append) is False
    assert precious.exists()
    assert not sibling.exists()
    assert warnings and str(mounted) in warnings[0]

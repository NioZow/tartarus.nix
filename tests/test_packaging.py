"""Packaging guards: every source module must import and be visible to Nix.

Nix flakes only see git-tracked files. A new ``src/tartarus/*.py`` that is left
untracked is silently omitted from the built package, which previously produced
an installed CLI that crashed with ``ModuleNotFoundError`` while the in-tree test
suite passed. These tests fail before that can happen.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))


def _source_modules() -> list[Path]:
    return sorted(
        path
        for path in (SRC / "tartarus").rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_every_source_module_imports():
    for path in _source_modules():
        relative = path.relative_to(SRC).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        try:
            __import__(module)
        except Exception as exc:  # noqa: BLE001 - report the module that broke
            pytest.fail(f"{module} failed to import: {exc!r}")


def test_every_source_file_is_git_tracked():
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")

    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "--", "src/tartarus"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    untracked = [line for line in result.stdout.splitlines() if line.endswith(".py")]
    assert not untracked, (
        "these source files are untracked and would be omitted from the Nix "
        "build (git add them): " + ", ".join(untracked)
    )

"""Thin wrappers around ``nix eval`` / ``nix build``.

Every call is ``--impure`` because the ``mkGuests`` builders deliberately read
the impure instance/shares env interface (PLAN.md §6), and every eval returns
parsed JSON so callers never shell-parse Nix output.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..output import die
from ..system import NIX_FLAGS, extra_nix_args


def eval_json(
    flake_ref: str,
    attr: str,
    *,
    apply: str | None = None,
    env: dict[str, str] | None = None,
) -> Any:
    """Evaluate ``<flake_ref>#<attr>`` to JSON, optionally through ``--apply``."""
    cmd = ["nix", *NIX_FLAGS, "eval", "--impure", "--json", f"{flake_ref}#{attr}"]
    if apply is not None:
        cmd += ["--apply", apply]
    cmd += extra_nix_args()
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        die(f"nix eval {attr} failed:\n{result.stderr.strip() or result.stdout.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        die(f"nix eval {attr} returned non-JSON output: {exc}")


def attr_names(flake_ref: str, attr: str, *, env: dict[str, str] | None = None) -> list[str]:
    """The attribute names under ``attr``, sorted like the original script."""
    return sorted(eval_json(flake_ref, attr, apply="builtins.attrNames", env=env))


def build(
    flake_ref: str,
    attr: str,
    out_link: Path,
    *,
    env: dict[str, str] | None = None,
) -> None:
    """Build ``<flake_ref>#<attr>``, writing the out-link to ``out_link``."""
    cmd = [
        "nix",
        *NIX_FLAGS,
        "build",
        f"{flake_ref}#{attr}",
        "--impure",
        "--out-link",
        str(out_link),
        *extra_nix_args(),
    ]
    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)

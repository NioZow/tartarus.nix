"""Subprocess helpers, including the sudo wrappers used by container actions.

Everything here preserves the original script's conventions:
``stdin`` is redirected from ``/dev/null`` for quiet runs (a MicroVM shutdown
helper blocks forever on an inherited interactive TTY), and failures either
propagate the child's exit code or die with a single clean line.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from .output import die


def _sudo_bin() -> str:
    return "/usr/bin/sudo" if platform.system() == "Darwin" else "sudo"


def run_sudo(cmd: list[str]) -> None:
    result = subprocess.run([_sudo_bin(), *cmd])
    if result.returncode != 0:
        sys.exit(result.returncode)


def run_sudo_quiet(cmd: list[str], *, debug: bool = False) -> None:
    """Like :func:`run_sudo`, but swallows the command's stdout/stderr unless
    ``debug`` is set or it actually fails -- for the mutating calls behind
    ``ctn stop``, where the caller only wants the final status line."""
    if debug:
        result = subprocess.run([_sudo_bin(), *cmd])
        if result.returncode != 0:
            sys.exit(result.returncode)
        return
    result = subprocess.run([_sudo_bin(), *cmd], capture_output=True, text=True)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)


def run_quiet(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    debug: bool = False,
    check: bool = False,
) -> None:
    """Run ``cmd`` with stdin always at ``/dev/null``.

    ``microvm-shutdown`` ends in a bare ``cat`` that holds its pipe into socat
    open until the QMP socket itself closes -- it expects stdin to already be
    at EOF, as systemd gives ``ExecStop``. Left inherited, an interactive
    terminal never reaches EOF and this hangs forever regardless of whether
    the guest shut down cleanly.
    """
    if debug:
        subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, check=check)
        return

    if check:
        result = subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            die(f"command failed ({result.returncode}): {' '.join(cmd)}\n{err}")
    else:
        subprocess.run(
            cmd,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

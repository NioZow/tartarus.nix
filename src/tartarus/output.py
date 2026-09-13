"""Terminal output helpers: colored status marks, tables, and ``die``.

All user-visible formatting lives here so the action modules stay focused on
behaviour. Coloring is suppressed when the stream is not a TTY or ``NO_COLOR``
is set, matching the original single-file script.
"""

from __future__ import annotations

import os
import re
import sys
from typing import NoReturn

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _colorable(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None


def c(code: str, text: str, stream=sys.stdout) -> str:
    return f"\033[{code}m{text}\033[0m" if _colorable(stream) else text


def mark(symbol: str, code: str, stream=sys.stdout) -> str:
    return c(code, f"[{symbol}]", stream)


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def info(message: str) -> None:
    print(f"{mark('*', '36')} {message}")


def ok(message: str) -> None:
    print(f"{mark('+', '32')} {message}")


def warn(message: str) -> None:
    print(f"{mark('!', '33', sys.stderr)} {message}", file=sys.stderr)


def die(message: str) -> NoReturn:
    print(f"{mark('!', '31', sys.stderr)} error: {message}", file=sys.stderr)
    sys.exit(1)


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))

    def fmt(cells: list[str]) -> str:
        return "  ".join(cell + " " * (widths[i] - visible_len(cell)) for i, cell in enumerate(cells))

    print(fmt(headers))
    for row in rows:
        print(fmt(row))

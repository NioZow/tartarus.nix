"""Filesystem helpers that are safe in the presence of mounts and symlinks.

Recursive deletion is dangerous here: a staging directory can be a live bind
mount of a user directory, so walking it removes the *source* contents. Every
recursive delete in tartarus must go through :func:`safe_rmtree`, which never
descends into a mount point and never follows a symlink.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

Warn = Callable[[str], None]


def safe_rmtree(path: Path, *, warn: Warn | None = None) -> bool:
    """Remove ``path`` recursively without crossing mounts or symlinks.

    Returns ``True`` only when the whole tree was removed. A mount point
    (including ``path`` itself) is left untouched and reported through
    ``warn``; symlinks are unlinked, never followed. Failure to remove a file
    or directory is also reported and makes the result ``False``.
    """
    path = Path(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError as exc:
        _warn(warn, f"cannot inspect {path}: {exc}")
        return False

    if not _is_dir(info):
        try:
            os.unlink(path)
        except FileNotFoundError:
            return True
        except OSError as exc:
            _warn(warn, f"cannot remove {path}: {exc}")
            return False
        return True

    if os.path.ismount(path):
        _warn(warn, f"refusing to delete mount point {path}")
        return False

    removed = True
    try:
        entries = list(os.scandir(path))
    except FileNotFoundError:
        return True
    except OSError as exc:
        _warn(warn, f"cannot read {path}: {exc}")
        return False

    for entry in entries:
        try:
            if entry.is_symlink():
                os.unlink(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                if not safe_rmtree(Path(entry.path), warn=warn):
                    removed = False
            else:
                os.unlink(entry.path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _warn(warn, f"cannot remove {entry.path}: {exc}")
            removed = False

    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _warn(warn, f"cannot remove {path}: {exc}")
        removed = False
    return removed


def _is_dir(info: os.stat_result) -> bool:
    return stat.S_ISDIR(info.st_mode)


def _warn(warn: Warn | None, message: str) -> None:
    if warn is not None:
        warn(message)

"""User-defined lifecycle hooks around ``tartarus`` operations.

The host renders ``hooks.toml`` at rebuild time (``nix/host/hooks.nix``): a
list of shell commands to run *before* or *after* each lifecycle event, each
narrowed to some guests by glob patterns. This module is the runtime half:
it parses that file, decides which hooks apply to a given operation, and runs
them as the invoking user.

The module deliberately imports nothing from the action modules (:mod:`vm`,
:mod:`ctn`) and nothing from :mod:`config` at runtime: hooks are a leaf
feature, and a real import cycle would appear as soon as the lifecycle code
calls back into it.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import TartarusError
from .output import info, warn

if TYPE_CHECKING:
    from .config import Config

# The lifecycle events and phases. Kept in step with `nix/lib/types.nix` and
# the explicit matrix in `nix/host/hooks.nix`; anything else in the TOML file
# is a rendering bug, so it is rejected rather than silently ignored.
EVENTS = ("create", "start", "stop", "remove", "build")
PHASES = ("before", "after")
KINDS = ("vm", "container")
ON_FAILURE = ("warn", "abort")

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRY_DELAY = 2.0

# Tokens substituted into `command`; the same values are exported as
# `TARTARUS_*` environment variables so a command can use either style.
_ENV_NAMES = {
    "name": "TARTARUS_GUEST",
    "template": "TARTARUS_TEMPLATE",
    "kind": "TARTARUS_KIND",
    "id": "TARTARUS_GUEST_ID",
    "event": "TARTARUS_EVENT",
    "phase": "TARTARUS_PHASE",
}


@dataclass(frozen=True)
class Hook:
    """One ``[[hooks]]`` entry of ``hooks.toml``."""

    event: str
    phase: str
    command: str
    guests: list[str] = field(default_factory=lambda: ["*"])
    kinds: list[str] = field(default_factory=lambda: list(KINDS))
    timeout: float = DEFAULT_TIMEOUT
    retries: int = 0
    retry_delay: float = DEFAULT_RETRY_DELAY
    on_failure: str = "warn"
    description: str | None = None

    def matches(self, name: str, template: str, kind: str) -> bool:
        """Whether this hook applies to instance ``name`` of template ``template``.

        Patterns are matched against *both* the instance name and its base
        template, so ``guests = ["notes"]`` covers ``notes`` and ``notes-2``.
        A leading ``!`` negates: negations are evaluated first and exclude the
        guest outright; the positive patterns then OR together, and no
        positive pattern means no match. Hence ``["*"]`` is the all-inclusive
        spelling, ``["*", "!vpn"]`` excludes ``vpn`` and its instances, and
        ``[]`` (or a lone ``["!vpn"]``) matches nothing.
        """
        if kind not in self.kinds:
            return False

        excluded = []
        positive = []
        for pattern in self.guests:
            if pattern.startswith("!"):
                excluded.append(pattern[1:])
            else:
                positive.append(pattern)

        def hits(pattern: str) -> bool:
            return fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(template, pattern)

        if any(hits(pattern) for pattern in excluded):
            return False
        return any(hits(pattern) for pattern in positive)


def substitute(command: str, values: dict[str, str]) -> str:
    """Expand the ``{token}`` names of ``values`` inside ``command``.

    Plain :meth:`str.replace` on purpose: :meth:`str.format` would treat every
    other brace in the command as a placeholder and choke on ordinary shell
    constructs (``${HOME}``, ``${1:-x}``, awk/``find -exec`` bodies).
    """
    for key, value in values.items():
        command = command.replace("{" + key + "}", value)
    return command


def load_hooks(path: Path) -> list[Hook]:
    """Parse ``hooks.toml`` into hooks, in file order.

    A missing file is *not* an error: a host with no hooks is the normal case,
    and the CLI must keep working on a machine that never rendered the file.
    Malformed content is an error: silently dropping hooks would hide a broken
    rebuild.
    """
    if not path.is_file():
        return []

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise TartarusError(f"malformed TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise TartarusError(f"cannot read {path}: {exc}") from exc

    # `hooks.toml` carries its own schema marker, independent of config.toml's.
    # A newer file is a warning, never fatal: the entries we know still parse.
    schema = data.get("schema", 1)
    if isinstance(schema, int) and not isinstance(schema, bool) and schema > 1:
        warn(
            f"hooks.toml uses schema {schema}, newer than this tartarus "
            "understands (1); unknown fields are ignored. Update tartarus or "
            "rebuild your host."
        )

    raw = data.get("hooks", [])
    if not isinstance(raw, list):
        raise TartarusError(f"{path}: `hooks` must be an array of tables ([[hooks]])")

    return [_parse_hook(index, item, path) for index, item in enumerate(raw)]


def _parse_hook(index: int, item: Any, path: Path) -> Hook:
    """Validate one ``[[hooks]]`` table with ``hooks[<i>]``-prefixed errors."""
    if not isinstance(item, dict):
        raise TartarusError(f"{path}: hooks[{index}]: expected a table ([[hooks]])")

    event = item.get("event")
    if event not in EVENTS:
        raise TartarusError(
            f"{path}: hooks[{index}]: 'event' must be one of {', '.join(repr(e) for e in EVENTS)}, got {event!r}"
        )

    phase = item.get("phase")
    if phase not in PHASES:
        raise TartarusError(
            f"{path}: hooks[{index}]: 'phase' must be {', '.join(repr(p) for p in PHASES)}, got {phase!r}"
        )

    command = item.get("command")
    if not isinstance(command, str) or not command.strip():
        raise TartarusError(f"{path}: hooks[{index}]: 'command' must be a non-empty string")

    guests = _hook_list(item, "guests", index, path, default=["*"])
    kinds = _hook_list(item, "kinds", index, path, default=list(KINDS))
    for kind in kinds:
        if kind not in KINDS:
            raise TartarusError(
                f"{path}: hooks[{index}]: 'kinds' entries must be one of "
                f"{', '.join(repr(k) for k in KINDS)}, got {kind!r}"
            )

    on_failure = item.get("on_failure", "warn")
    if on_failure not in ON_FAILURE:
        raise TartarusError(
            f"{path}: hooks[{index}]: 'on_failure' must be {', '.join(repr(o) for o in ON_FAILURE)}, got {on_failure!r}"
        )

    timeout = _hook_number(item, "timeout", index, path, DEFAULT_TIMEOUT)
    if timeout <= 0:
        raise TartarusError(f"{path}: hooks[{index}]: 'timeout' must be positive, got {timeout}")

    retries = item.get("retries", 0)
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
        raise TartarusError(f"{path}: hooks[{index}]: 'retries' must be a non-negative integer, got {retries!r}")

    retry_delay = _hook_number(item, "retry_delay", index, path, DEFAULT_RETRY_DELAY)
    if retry_delay < 0:
        raise TartarusError(f"{path}: hooks[{index}]: 'retry_delay' must be non-negative, got {retry_delay}")

    description = item.get("description")
    if description is not None and not isinstance(description, str):
        raise TartarusError(f"{path}: hooks[{index}]: 'description' must be a string")

    return Hook(
        event=event,
        phase=phase,
        command=command,
        guests=guests,
        kinds=kinds,
        timeout=timeout,
        retries=retries,
        retry_delay=retry_delay,
        on_failure=on_failure,
        description=description,
    )


def _hook_list(item: dict[str, Any], key: str, index: int, path: Path, *, default: list[str]) -> list[str]:
    value = item.get(key, default)
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise TartarusError(f"{path}: hooks[{index}]: '{key}' must be a list of strings, got {value!r}")
    return list(value)


def _hook_number(item: dict[str, Any], key: str, index: int, path: Path, default: float) -> float:
    value = item.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TartarusError(f"{path}: hooks[{index}]: '{key}' must be a number, got {value!r}")
    return float(value)


def run_hooks(
    config: Config,
    event: str,
    phase: str,
    name: str,
    *,
    template: str,
    kind: str,
    guest_id: int | None = None,
) -> None:
    """Run every hook matching ``event``/``phase``/``name``/``kind``, in order.

    Hooks run as the invoking user with ``/bin/sh -c`` (never through sudo) and
    inherit stdout/stderr so their output is visible in the terminal. The
    working directory is the user's home, which is where a hand-written
    command reasonably expects to start.
    """
    hooks = config.hooks_for(event, phase, name, template=template, kind=kind)
    if not hooks:
        return

    cwd = config.home_dir if os.path.isdir(config.home_dir) else None
    values = {
        "name": name,
        "template": template,
        "kind": kind,
        "id": "" if guest_id is None else str(guest_id),
        "event": event,
        "phase": phase,
    }
    env_extra = {variable: values[key] for key, variable in _ENV_NAMES.items()}

    for hook in hooks:
        command = substitute(hook.command, values)
        env = {**os.environ, **env_extra}
        if config.log:
            info(f"hook {event}.{phase}: {hook.description or command}")

        failure = _run_one(hook, command, env, cwd)
        if failure is None:
            continue

        reason, returncode = failure
        if hook.on_failure == "abort":
            raise TartarusError(
                f"hook {event}.{phase} failed for '{name}'"
                + (f" (exit {returncode})" if reason == "exit" else f" ({reason})")
                + f": {command}"
            )
        detail = f"exit {returncode}" if reason == "exit" else reason
        warn(f"hook {event}.{phase} failed for '{name}' ({detail}): {command}")


def _run_one(hook: Hook, command: str, env: dict[str, str], cwd: str | Path | None) -> tuple[str, int | None] | None:
    """Run one hook, retrying on failure; return ``(reason, exit)`` or ``None``.

    ``reason`` is ``"exit"`` for a non-zero exit status or ``"timeout"`` when
    the attempt outlived ``timeout``. The last attempt's outcome is reported.
    """
    attempts = hook.retries + 1
    failure: tuple[str, int | None] | None = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(hook.retry_delay)
        try:
            # `check=True` would turn a non-zero exit into `CalledProcessError`,
            # but a failed hook is an expected outcome for the retry/abort logic.
            result = subprocess.run(["/bin/sh", "-c", command], cwd=cwd, env=env, timeout=hook.timeout, check=False)
        except subprocess.TimeoutExpired:
            failure = ("timeout", None)
            continue
        if result.returncode == 0:
            return None
        failure = ("exit", result.returncode)
    return failure

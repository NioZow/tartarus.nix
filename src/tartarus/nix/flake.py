"""Locate the **user's** flake and the guest attributes inside it.

Tartarus is installed into the Nix store and therefore cannot self-locate a
checkout. Following PLAN.md §6, the user's flake root comes from
``config.toml`` (with env/CLI overrides), and every guest is addressed as an
attribute of that flake:

* VMs          -> ``packages.<system>.vm-<name>`` (the microvm runner)
* containers   -> ``nixosConfigurations.ctn-<name>``

This module never points at the tartarus repo itself.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from ..config import Config
from ..output import die
from ..system import CTN_PREFIX, VM_PREFIX
from . import eval as nix_eval

INSTANCE_RE = re.compile(r"^(.+)-(\d+)$")


def require_flake(config: Config) -> None:
    """Die with a helpful message if the configured user flake is missing."""
    if not (config.flake_path / "flake.nix").is_file():
        die(
            f"no flake.nix under the configured flake path ({config.flake_path}).\n"
            "Set it in ~/.config/tartarus/config.toml (flake = \"...\"), "
            "with TARTARUS_FLAKE_PATH, or with --flake."
        )


def flake_ref(config: Config) -> str:
    """The ``git+file://`` URI for the user's flake, submodules included."""
    return f"git+file://{config.flake_path}?submodules=1"


def packages_attr(config: Config, name: str) -> str:
    """The VM runner attribute for guest ``name`` (unprefixed)."""
    return f"packages.{config.system}.{VM_PREFIX}{name}"


def ctn_config_attr(name: str) -> str:
    """The ``nixosConfigurations`` attribute for container ``name``."""
    return f"nixosConfigurations.{CTN_PREFIX}{name}"


def _attr_root(config: Config, kind: str) -> str:
    return f"packages.{config.system}" if kind == "vm" else "nixosConfigurations"


def _prefix(kind: str) -> str:
    return VM_PREFIX if kind == "vm" else CTN_PREFIX


def list_templates(config: Config, kind: str) -> list[str]:
    """Every guest name of ``kind`` exposed by the user's flake."""
    prefix = _prefix(kind)
    root = _attr_root(config, kind)
    names = nix_eval.attr_names(flake_ref(config), root)
    return sorted(name[len(prefix) :] for name in names if name.startswith(prefix))


def require_template(config: Config, kind: str, name: str) -> None:
    templates = list_templates(config, kind)
    if name not in templates:
        noun = "MicroVM" if kind == "vm" else "container"
        die(
            f"no {noun} named '{name}' in {config.flake_path}/flake.nix\n"
            f"Available: {' '.join(templates) or '<none>'}"
        )


def base_name(config: Config, kind: str, name: str) -> str:
    """``"vault-2"`` -> ``"vault"`` when ``vault`` is a real template.

    Otherwise the name is returned as-is, covering both the canonical
    ``vault`` and any typo'd/custom name (``require_template`` catches the
    former).
    """
    match = INSTANCE_RE.match(name)
    if match and match.group(1) in list_templates(config, kind):
        return match.group(1)
    return name


def build_fingerprint(flake_path: Path) -> str | None:
    """Identify the working-tree revision a build was made from.

    Combines the git ``HEAD`` commit, whether tracked files are dirty, and a
    hash of ``flake.lock`` into one stable token. The dirty flag only affects
    the update *notice* the CLI prints when reusing a build -- it never
    triggers an automatic rebuild. Returns ``None`` when the revision cannot
    be determined (not a git checkout, git missing, etc.).
    """
    try:
        head = subprocess.run(
            ["git", "-C", str(flake_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    if head.returncode != 0:
        return None

    try:
        status = subprocess.run(
            ["git", "-C", str(flake_path), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    dirty = "1" if status.stdout.strip() else "0"

    lock = flake_path / "flake.lock"
    try:
        lock_hash = hashlib.sha256(lock.read_bytes()).hexdigest()
    except FileNotFoundError:
        lock_hash = "nolock"

    return f"{head.stdout.strip()}:{dirty}:{lock_hash}"


def guest_id(config: Config, kind: str, name: str) -> int:
    """Resolve a guest's numeric id from ``config.toml`` (the single source).

    No ``nix eval`` is performed for ids: the effective (forced or
    auto-assigned) id is written to the TOML at rebuild time, and CID/IP/MAC
    are derived from it locally (PLAN.md §6). ``vmIds`` remains a flake output
    for compatibility only.
    """
    guest = config.guest(name, kind)
    if guest is not None and guest.id is not None:
        return guest.id

    where = config.config_path or "config.toml"
    die(
        f"no id recorded for {kind} guest '{name}' in {where}.\n"
        "Rebuild your host so the tartarus host module regenerates config.toml "
        "(ids are assigned at rebuild time)."
    )

"""Runtime configuration for the tartarus CLI.

The CLI never locates its own repository. Instead it reads the **user's**
flake path and the host-runtime knobs from a TOML file (PLAN.md §6). This
module defines the schema, the :class:`Config` dataclass, and the loader with
its precedence rules.

TOML schema -- ``$XDG_CONFIG_HOME/tartarus/config.toml`` (default
``~/.config/tartarus/config.toml``), generated at rebuild time by
``nix/host/config.nix``::

    # The user's own flake root. Never the tartarus repo itself.
    flake = "/home/user/.config/nixcfg"

    user = "user"
    home = "/home/user"
    system = "aarch64-linux"
    state_root = "/home/user/.local/state/tartarus"

    # Client keys / host files, and the two CA roots (each containing the
    # ``ca/`` and ``machines/`` subtrees the CLI manages).
    ssh_dir = "/home/user/.ssh"
    ssh_ca_dir = "/home/user/.local/share/tartarus/ssh"
    x509_ca_dir = "/home/user/.local/share/tartarus/x509"

    log = false

    # Proxy transport config only; filtering is per guest.
    [proxy]
    enable = true
    location = "host"
    port = 3128
    listen_addresses = ["10.200.0.1"]   # resolved by Nix; never loopback
    log = false

    # Enabled guests, each carrying the effective ``id`` (forced or
    # auto-assigned). The CLI derives CID/IP/MAC from ``id`` locally.
    [[guests]]
    name = "vault"
    kind = "vm"
    id = 3
    internet = false
    graphical = false
    autostart = false
    shared_folder = false
    proxy = { enable = true, allow_hosts = ["example.com"] }

    [[guests]]
    name = "box"
    kind = "container"
    id = 4
    internet = true
    graphical = false
    autostart = false
    shared_folder = false
    proxy = { enable = false, allow_hosts = [] }

Precedence, highest first: **CLI flag > environment variable > config.toml >
built-in default**. Environment variable names are ``TARTARUS_``-prefixed
(see the ``_layer`` calls below); ``TARTARUS_CONFIG`` selects the TOML file
itself. A missing default file is not an error: the loader warns and falls
back to the built-in defaults so ``tartarus --help`` still works.
"""

from __future__ import annotations

import getpass
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .errors import TartarusError
from .output import warn
from .system import detect_system

# ``vault-2`` -> base template ``vault``; mirrors ``nix.flake.INSTANCE_RE``.
_INSTANCE_RE = re.compile(r"^(.+)-(\d+)$")


@dataclass(frozen=True)
class GuestProxy:
    """Per-guest proxy filtering (merged with the global transport config)."""

    enable: bool = False
    allow_hosts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Guest:
    """One enabled guest, as recorded in ``config.toml``."""

    name: str
    kind: str = "vm"
    id: int | None = None
    internet: bool = True
    graphical: bool = False
    autostart: bool = False
    shared_folder: bool = False
    proxy: GuestProxy = field(default_factory=GuestProxy)


@dataclass
class ProxyConfig:
    """Global proxy transport config (never filtering)."""

    enable: bool = False
    location: str = "host"
    port: int = 3128
    listen_addresses: list[str] = field(default_factory=list)
    log: bool = False


@dataclass
class Config:
    """Fully resolved runtime configuration."""

    user: str
    home_dir: Path
    flake_path: Path
    system: str
    state_root: Path
    ssh_dir: Path
    ssh_ca_dir: Path
    x509_ca_dir: Path
    enabled_guests: list[Guest] = field(default_factory=list)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    log: bool = False
    config_path: Path | None = None

    def guest(self, name: str, kind: str | None = None) -> Guest | None:
        """The enabled guest called ``name``, optionally restricted to ``kind``."""
        for guest in self.enabled_guests:
            if guest.name == name and (kind is None or guest.kind == kind):
                return guest
        return None

    def require_guest(self, name: str, kind: str | None = None) -> Guest:
        """Return the enabled guest ``name`` or fail with an actionable error.

        ``config.toml`` is generated from the host's ``tartarus.guests`` and
        only ever lists guests whose ``enable`` is true, so presence in
        :attr:`enabled_guests` *is* the "enabled on this host" predicate; a
        disabled guest is simply absent. Numbered instances (``vault-2``) and
        the ``.trs`` ssh suffix resolve to their base template, which must
        itself be enabled.

        Raises :class:`~tartarus.errors.TartarusError` so the CLI renders a
        single clean message (and exits non-zero) instead of operating on a
        guest that has no host-side firewall rules, CA certs or proxy entries.
        """
        candidate = name[: -len(".trs")] if name.endswith(".trs") else name
        guest = self.guest(candidate, kind)
        match = _INSTANCE_RE.match(candidate)
        base = match.group(1) if match else candidate
        if guest is None and match is not None:
            guest = self.guest(base, kind)
        if guest is not None:
            return guest

        if kind is not None:
            other = self.guest(candidate) or self.guest(base)
            if other is not None:
                raise TartarusError(
                    f"guest \"{candidate}\" is enabled as kind \"{other.kind}\", "
                    f"not \"{kind}\""
                )

        raise TartarusError(
            f"guest \"{candidate}\" is not enabled on this host; set "
            f"`tartarus.guests.{base}.enable = true`"
            + (f" (kind = \"{kind}\")" if kind is not None else "")
            + " in your configuration and rebuild "
            "(tartarus rebuild / darwin-rebuild / nixos-rebuild)."
        )

    def state_dir(self, name: str) -> Path:
        """Per-instance runtime state (pid, cid, console log, overlay)."""
        return self.state_root / name

    def shared_dir(self, name: str) -> Path:
        """Per-instance host directory mounted at ``~/shared`` in the guest."""
        return self.home_dir / "shared" / name


def _as_bool(value: Any, field_name: str = "") -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, int):
        return value != 0
    raise TartarusError(f"{field_name or 'value'}: expected a boolean, got {value!r}")


def _as_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TartarusError(f"{field_name}: expected an integer, got {value!r}")
    try:
        return int(value)
    except ValueError:
        raise TartarusError(f"{field_name}: expected an integer, got {value!r}") from None


def _as_list(value: Any, field_name: str = "") -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    raise TartarusError(f"{field_name or 'value'}: expected a list of strings, got {value!r}")


def _layer(cli_value: Any, env_name: str, toml_value: Any, default: Any) -> Any:
    """Apply the CLI > env > TOML > default precedence for one field."""
    if cli_value is not None:
        return cli_value
    env = os.environ.get(env_name)
    if env:
        return env
    if toml_value is not None:
        return toml_value
    return default


def _default_user() -> str:
    return os.environ.get("USER") or getpass.getuser()


def _default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "tartarus" / "config.toml"


def _default_state_root(home_dir: Path) -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else home_dir / ".local" / "state"
    return base / "tartarus"


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise TartarusError(f"malformed TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise TartarusError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise TartarusError(f"{path}: expected a top-level TOML table")
    return data


def _parse_guests(raw: Any) -> list[Guest]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise TartarusError("`guests` must be an array of tables ([[guests]]), not a single table")

    guests: list[Guest] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise TartarusError(f"guests[{index}]: expected a table ([[guests]])")

        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise TartarusError(f"guests[{index}]: `name` is required and must be a non-empty string")

        kind = item.get("kind", "vm")
        if kind not in ("vm", "container"):
            raise TartarusError(f"guest '{name}': `kind` must be \"vm\" or \"container\", got {kind!r}")

        guest_id = item.get("id")
        if guest_id is not None:
            if isinstance(guest_id, bool) or not isinstance(guest_id, int) or guest_id <= 0:
                raise TartarusError(f"guest '{name}': `id` must be a positive integer, got {guest_id!r}")

        proxy_raw = item.get("proxy", {})
        if proxy_raw is None:
            proxy_raw = {}
        if not isinstance(proxy_raw, dict):
            raise TartarusError(f"guest '{name}': `proxy` must be a table")

        guests.append(
            Guest(
                name=name,
                kind=kind,
                id=guest_id,
                internet=_as_bool(item.get("internet", True), f"guest '{name}'.internet"),
                graphical=_as_bool(item.get("graphical", False), f"guest '{name}'.graphical"),
                autostart=_as_bool(item.get("autostart", False), f"guest '{name}'.autostart"),
                shared_folder=_as_bool(item.get("shared_folder", False), f"guest '{name}'.shared_folder"),
                proxy=GuestProxy(
                    enable=_as_bool(proxy_raw.get("enable", False), f"guest '{name}'.proxy.enable"),
                    allow_hosts=_as_list(proxy_raw.get("allow_hosts"), f"guest '{name}'.proxy.allow_hosts"),
                ),
            )
        )
    return guests


def load_config(overrides: Mapping[str, Any] | None = None) -> Config:
    """Load and resolve the effective configuration.

    ``overrides`` carries CLI flags (only non-``None`` values win). The TOML
    path itself may be overridden with the ``config`` key / ``TARTARUS_CONFIG``.

    Raises :class:`~tartarus.errors.TartarusError` for an explicitly selected
    but missing file, or for malformed TOML/content. A missing *default* file
    is not fatal -- the user is warned to rebuild and defaults are used.
    """
    cli = dict(overrides or {})

    explicit = cli.get("config") or os.environ.get("TARTARUS_CONFIG")
    config_path = Path(explicit).expanduser() if explicit else _default_config_path()

    if config_path.is_file():
        data = _read_toml(config_path)
    elif explicit:
        raise TartarusError(f"config file not found: {config_path}")
    else:
        warn(
            f"no config.toml at {config_path}; using built-in defaults.\n"
            "Rebuild your host to generate it (the tartarus host module writes it at rebuild time)."
        )
        data = {}

    user = str(_layer(cli.get("user"), "TARTARUS_USER", data.get("user"), _default_user()))
    home_dir = Path(_layer(cli.get("home"), "HOME", data.get("home"), Path.home())).expanduser()
    flake_path = Path(
        _layer(cli.get("flake"), "TARTARUS_FLAKE_PATH", data.get("flake"), home_dir / ".config" / "nixcfg")
    ).expanduser()
    system = str(_layer(cli.get("system"), "TARTARUS_SYSTEM", data.get("system"), detect_system()))
    state_root = Path(
        _layer(cli.get("state_root"), "TARTARUS_STATE_ROOT", data.get("state_root"), _default_state_root(home_dir))
    ).expanduser()
    ssh_dir = Path(
        _layer(cli.get("ssh_dir"), "TARTARUS_SSH_DIR", data.get("ssh_dir"), home_dir / ".ssh")
    ).expanduser()
    ssh_ca_dir = Path(
        _layer(
            cli.get("ssh_ca_dir"),
            "TARTARUS_SSH_CA_DIR",
            data.get("ssh_ca_dir"),
            home_dir / ".local" / "share" / "tartarus" / "ssh",
        )
    ).expanduser()
    x509_ca_dir = Path(
        _layer(
            cli.get("x509_ca_dir"),
            "TARTARUS_X509_CA_DIR",
            data.get("x509_ca_dir"),
            home_dir / ".local" / "share" / "tartarus" / "x509",
        )
    ).expanduser()

    log = _as_bool(_layer(cli.get("log"), "TARTARUS_LOG", data.get("log"), False), "log")

    proxy_raw = data.get("proxy") or {}
    if not isinstance(proxy_raw, dict):
        raise TartarusError("`proxy` must be a table ([proxy])")

    proxy = ProxyConfig(
        enable=_as_bool(
            _layer(cli.get("proxy_enable"), "TARTARUS_PROXY_ENABLE", proxy_raw.get("enable"), False),
            "proxy.enable",
        ),
        location=str(_layer(cli.get("proxy_location"), "TARTARUS_PROXY_LOCATION", proxy_raw.get("location"), "host")),
        port=_as_int(_layer(cli.get("proxy_port"), "TARTARUS_PROXY_PORT", proxy_raw.get("port"), 3128), "proxy.port"),
        listen_addresses=_as_list(
            _layer(
                cli.get("proxy_listen_addresses"),
                "TARTARUS_PROXY_LISTEN_ADDRESSES",
                proxy_raw.get("listen_addresses"),
                [],
            ),
            "proxy.listen_addresses",
        ),
        log=_as_bool(
            _layer(cli.get("proxy_log"), "TARTARUS_PROXY_LOG", proxy_raw.get("log"), False),
            "proxy.log",
        ),
    )

    return Config(
        user=user,
        home_dir=home_dir,
        flake_path=flake_path,
        system=system,
        state_root=state_root,
        ssh_dir=ssh_dir,
        ssh_ca_dir=ssh_ca_dir,
        x509_ca_dir=x509_ca_dir,
        enabled_guests=_parse_guests(data.get("guests")),
        proxy=proxy,
        log=log,
        config_path=config_path if config_path.is_file() else None,
    )

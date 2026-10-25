#!/usr/bin/env python3
"""
Clipboard Bridge - A secure clipboard bridge for containers, VMs, and Neovim.

ARCHITECTURE
------------
The clipboard bridge consists of a server (host) and clients (guests, admin
CLI):

  Host:  clipboard-bridge.py serve [--config FILE]
  Guest: clipboard-bridge.py push    # Send clipboard to host
         clipboard-bridge.py pull    # Receive clipboard from host
  Admin: clipboard-bridge.py clients # Control-plane operations

The server maintains per-client clipboard buffers and syncs with the host
system clipboard (wl-copy/wl-paste). Each client (VM) is isolated and can
only read/write its own clipboard slot.

One server process binds every entry in its ``[[listeners]]`` array before it
serves any of them: a host can expose VSOCK to its VMs, mTLS TCP to its
containers and a same-user Unix admin socket from a single process, all
sharing one clipboard store. Listeners are self-contained: each carries its
own transport, bind target, ``[listeners.security]``, optional
``[listeners.mtls]``, identity resolution and resource bounds.

SECURITY MODEL
--------------
  - Guest listeners only serve ``set``/``get`` on the caller's own slot plus
    ``register``/``subscribe``.
  - Admin listeners (``admin = true``) serve ``clients``, targeted
    ``set``/``get`` and ``get --json``; every admin request is authorized by
    the ordered ``[[rule]]`` engine (first match wins, default deny).
  - There is no shared secret and no password: a peer is authenticated by the
    mTLS channel (CA chain + EKU OID) or by the same-user Unix socket
    boundary. The default admin listener is a ``0600`` Unix socket inside a
    ``0700`` directory.
  - Clients that have not been seen for 5 minutes are automatically removed.

PROTOCOL
--------
JSON messages over a stream socket (TCP, Unix, or VSOCK):

  Client -> Server: {"action": "set", "data": "<base64-content>"}
  Client -> Server: {"action": "get"}
  Server -> Client: {"status": "ok", "data": "<base64-content>"}

  Admin -> Server:  {"action": "clients"}
  Admin -> Server:  {"action": "get", "json": true}
  Admin -> Server:  {"action": "set", "data": "<base64-content>", "target": "vsock:5"}

  Subscriber -> Server: {"action": "subscribe"}
  Server -> Subscriber: {"status": "ok", "message": "Subscribed"}  (followed by live pushes via same stream)

CONFIGURATION
-------------
  --config / -c PATH    Override the auto-selected config path.
  Separate config files per role, auto-selected by the command:
    serve                          -> ~/.config/clipboard-bridge/server.toml
    clients, push/pull --target,
    pull --json                    -> ~/.config/clipboard-bridge/admin.toml
    every other client command     -> ~/.config/clipboard-bridge/client.toml

  When the preferred file is absent the other role's file is used, so the
  same command works on a host (admin.toml) and in a guest (client.toml).

  A server document uses a non-empty ``[[listeners]]`` array:

    mode = "server"
    [[vm]]                  # cid -> name map for resolution = "tartarus"
    cid = 7
    name = "dev"
    [[tcp_vm]]              # ip -> name map for resolution = "tartarus"
    ip = "10.201.0.10"
    name = "notes"

    [[listeners]]
    type = "vsock" | "tcp" | "unix"
    name = "..."            # optional, unique, matched by match.listeners
    cid = 2                 # vsock
    host = "10.201.0.1"     # tcp
    port = 27795
    socket = "%t/clipboard.sock"  # unix
    admin = false
    resolution = "none" | "certificate" | "tartarus" | "mofos"
    connect_timeout = 5
    handshake_timeout = 10
    max_connections = 100
    server_read_timeout = 60
    socket_dir_mode = "0700"
    socket_mode = "0600"

    [listeners.security]
    transport_encryption = "auto" | "none" | "mtls"
    client_auth = "transport" | "none"
    server_auth = "transport" | "none"

    [listeners.mtls]        # required when the listener resolves to mTLS
    enable = true
    ca_file = "./ca.crt"
    cert_file = "./server.crt"
    key_file = "./server.key"
    required_oid = "1.3.6.1.4.1.99999.3.1"
    peer_required_oid = "1.3.6.1.4.1.99999.3.2"

    [[rule]]
    match.listeners = ["admin"]
    match.machine = ["dev"]
    match.action = ["clients", "get", "set"]
    match.target = ["*"]
    policy = "allow"

  A client document uses exactly one transport:

    mode = "client"
    transport = "tcp" | "vsock" | "unix"
    host = "10.201.0.1"
    port = 27795
    cid = 2
    socket = "/path/to.sock"
    connect_timeout = 5
    handshake_timeout = 10
    recv_timeout = 60
    register = true
    proxy_socket = "%t/clipboard-bridge-proxy"
    debug = true

    [security]
    transport_encryption = "auto" | "none" | "mtls"
    client_auth = "transport" | "none"
    server_auth = "transport" | "none"

    [mtls]
    enable = true
    ca_file = "./ca.crt"
    cert_file = "./client.crt"
    key_file = "./client.key"
    required_oid = "1.3.6.1.4.1.99999.3.2"
    peer_required_oid = "1.3.6.1.4.1.99999.3.1"

    [acl]
    trusted_fingerprints = ["SHA256:..."]
    trusted_names = ["server-*"]

Paths in ``[mtls]`` and ``[listeners.mtls]`` starting with ``./`` are resolved
relative to the config file's directory. Socket paths starting with ``~/`` or
``%t/`` are expanded to the user's home or per-session runtime directory.

No environment variables are read by this tool; everything is configured via
TOML config files.

Examples:
  # Start a server that binds every configured listener
  clipboard-bridge.py serve

  # Push from a guest (reads stdin when piped)
  echo "hello" | clipboard-bridge.py push

  # Pull from a guest (prints to stdout when piped)
  clipboard-bridge.py pull

  # Host admin over the local Unix listener (no password, no certificate)
  clipboard-bridge.py clients
  clipboard-bridge.py push "hello" --target vsock:5
"""

import argparse
import base64
import binascii
import contextlib
import fnmatch
import hashlib
import json
import os
import re
import select
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

if TYPE_CHECKING:
    import cryptography.x509 as x509

DEFAULT_PORT = 27795
DEFAULT_CID = 2
DEFAULT_BIND = "0.0.0.0"
DEFAULT_CONNECT_HOST = "127.0.0.1"
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/clipboard-bridge")
DEFAULT_SERVER_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "server.toml")
DEFAULT_CLIENT_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "client.toml")
DEFAULT_ADMIN_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "admin.toml")
DEFAULT_PROXY_SOCKET = "%t/clipboard-bridge-proxy"
TARTARUS_STATE_ROOT = Path(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state"))
) / "tartarus"

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_RECV_TIMEOUT = 60.0
DEFAULT_SERVER_READ_TIMEOUT = 60.0
DEFAULT_MAX_CONNECTIONS = 100
DEFAULT_SOCKET_DIR_MODE = 0o700
DEFAULT_SOCKET_MODE = 0o600

# OID allocation (sudo-auth-proxy subtree convention)
SERVER_OID = "1.3.6.1.4.1.99999.3.1"
CLIENT_OID = "1.3.6.1.4.1.99999.3.2"
ADMIN_OID = "1.3.6.1.4.1.99999.3.3"

TRANSPORT_ENCRYPTIONS = ("none", "mtls")
CLIENT_AUTH_METHODS = ("transport", "none")
SERVER_AUTH_METHODS = ("transport", "none")
LISTENER_TYPES = ("vsock", "tcp", "unix")
RESOLUTION_MODES = ("none", "certificate", "tartarus", "mofos")
RULE_POLICIES = ("allow", "deny")

CONFIG_SECURITY_KEYS = frozenset(
    {"transport_encryption", "client_auth", "server_auth"}
)
CONFIG_MTLS_KEYS = frozenset(
    {
        "enable",
        "ca_file",
        "cert_file",
        "key_file",
        "required_oid",
        "peer_required_oid",
    }
)
CONFIG_ACL_KEYS = frozenset({"trusted_fingerprints", "trusted_names"})
CONFIG_RULE_KEYS = frozenset({"match", "policy"})
CONFIG_RULE_MATCH_KEYS = frozenset({"machine", "listeners", "action", "target"})

CONFIG_LISTENER_KEYS = frozenset(
    {
        "type",
        "name",
        "admin",
        "port",
        "cid",
        "host",
        "socket",
        "socket_dir_mode",
        "socket_mode",
        "connect_timeout",
        "handshake_timeout",
        "max_connections",
        "server_read_timeout",
        "resolution",
        "security",
        "mtls",
    }
)

SERVER_TOP_LEVEL_KEYS = frozenset(
    {
        "mode",
        "debug",
        "vm",
        "tcp_vm",
        "labels",
        "listeners",
        "rule",
    }
)

CLIENT_TOP_LEVEL_KEYS = frozenset(
    {
        "mode",
        "transport",
        "host",
        "port",
        "cid",
        "socket",
        "proxy_socket",
        "register",
        "debug",
        "connect_timeout",
        "handshake_timeout",
        "recv_timeout",
        "security",
        "mtls",
        "acl",
    }
)

TABLE_KEYS = {
    "security": CONFIG_SECURITY_KEYS,
    "mtls": CONFIG_MTLS_KEYS,
    "acl": CONFIG_ACL_KEYS,
}


class ConfigError(ValueError):
    """Raised for every invalid configuration or schema value."""


# Global state
no_notify = False
debug_enabled = False
client_clipboards = {}
client_lock = threading.Lock()

# Active subscriber connections for push (server -> client)
# {client_id: [list of wfile objects]}
client_subscribers = {}
subscriber_lock = threading.Lock()

# Clients that have not been seen for 5 minutes are automatically removed.
CLIENT_EXPIRY_SECONDS = 300


def expire_clients():
    """Remove clients that have not been seen for 5 minutes."""
    cutoff = time.time() - CLIENT_EXPIRY_SECONDS
    with subscriber_lock:
        active = set(client_subscribers.keys())
    with client_lock:
        stale = [
            cid
            for cid, info in client_clipboards.items()
            if cid not in active and info.get("updated", 0) < cutoff
        ]
        for cid in stale:
            client_clipboards.pop(cid, None)
            _debug(f"expired client {cid}")
    with subscriber_lock:
        for cid in stale:
            client_subscribers.pop(cid, None)


# --- Debug / Timing ---


def set_debug(config: dict) -> None:
    """Enable debug output from the document-level flag."""
    global debug_enabled
    value = config.get("debug")
    if value is None:
        value = config.get("_debug")
    debug_enabled = bool(value)


def _debug(msg: str) -> None:
    if debug_enabled:
        print(f"clipboard-bridge: [debug] {msg}", file=sys.stderr)


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms"


# --- Config Loading ---


def expand_socket_path(path: str) -> str:
    """Expand placeholder prefixes in a unix socket path.

    Supported placeholders:
      ~   -> user home directory
      %t/ -> DARWIN_USER_TEMP_DIR (macOS) or $XDG_RUNTIME_DIR (Linux)

    Branches on the platform first (matching
    packages/ssh-agent-proxy/ssh-agent-proxy.py's `_expand_socket_path`)
    rather than just checking whether XDG_RUNTIME_DIR happens to be set --
    some macOS shells here export a stale/bogus XDG_RUNTIME_DIR (e.g.
    "/run/user/501", which doesn't exist on macOS) for Linux-tool
    compatibility, which would otherwise silently win over the real
    per-session temp dir.
    """
    if path.startswith("~"):
        return os.path.expanduser(path)
    if path.startswith("%t/"):
        if sys.platform == "darwin":
            try:
                # Absolute path -- a caller's PATH can't be trusted here (e.g.
                # Raycast's dev-mode extension host runs commands with a PATH
                # that doesn't include /usr/bin, so a bare "getconf" raised
                # FileNotFoundError and crashed the whole CLI invocation).
                result = subprocess.run(
                    ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"],
                    capture_output=True,
                    text=True,
                )
                runtime_dir = result.stdout.strip() if result.returncode == 0 else "/tmp"
            except OSError:
                runtime_dir = "/tmp"
        else:
            runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return os.path.join(runtime_dir, path[3:])
    return path


def _resolve_config_path(value, config_dir: Path):
    """Resolve an mTLS path against the config file's directory."""
    if not isinstance(value, str):
        return value
    if value.startswith("~/"):
        return os.path.expanduser(value)
    path = Path(value)
    if not path.is_absolute():
        return str(config_dir / path)
    return str(path)


def _validate_table(container: dict, name: str, allowed: frozenset) -> None:
    """Check one nested table against its exact key set."""
    table = container.get(name)
    if table is None:
        return
    if not isinstance(table, dict):
        raise ConfigError(f"'[{name}]' must be a table")
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(
            f"unknown key(s) inside [{name}]: "
            + ", ".join(repr(key) for key in unknown)
        )


def _parse_mode_value(value, *, field: str, where: str) -> int:
    """Parse ``"0700"`` or ``0o700`` into a mode, rejecting invalid values."""
    if isinstance(value, bool):
        raise ConfigError(f"{where}.{field} must be an octal mode")
    if isinstance(value, int):
        mode = value
    else:
        try:
            mode = int(str(value), 8)
        except (TypeError, ValueError) as error:
            raise ConfigError(f"{where}.{field} must be an octal mode") from error
    if mode < 0 or mode > 0o777:
        raise ConfigError(
            f"{where}.{field} must be an octal mode between 0000 and 0777"
        )
    return mode


def _positive_number(value, *, field: str, where: str, integer: bool = False):
    """Require an explicitly positive numeric bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}.{field} must be a positive number")
    if integer and not isinstance(value, int):
        raise ConfigError(f"{where}.{field} must be a positive integer")
    if value <= 0:
        raise ConfigError(f"{where}.{field} must be positive")
    return value


def _positive_int(value, default: int) -> int:
    """Coerce a runtime bound to a positive int, falling back to ``default``."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _positive_float(value, default: float) -> float:
    """Coerce a runtime bound to a positive float, falling back to ``default``."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def load_mtls(container: dict, *, where: str = "[mtls]", required: bool = False):
    """Validate one ``[mtls]`` table and return it (or ``None`` when absent).

    A listener whose resolved transport encryption is mTLS must carry a
    complete block: ``enable = true``, the three certificate paths and both
    EKU OIDs. An incomplete block is a startup error, never a silent plaintext
    fallback.
    """
    raw = container.get("mtls")
    if raw is None:
        if required:
            raise ConfigError(
                f"{where} is required when transport encryption is mTLS"
            )
        return None
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a table")
    unknown = sorted(set(raw) - CONFIG_MTLS_KEYS)
    if unknown:
        raise ConfigError(
            f"{where} has unknown key(s): "
            + ", ".join(repr(key) for key in unknown)
        )
    if required:
        if raw.get("enable") is not True:
            raise ConfigError(f"{where}.enable must be true for an mTLS listener")
        for key in ("ca_file", "cert_file", "key_file"):
            value = raw.get(key)
            if not isinstance(value, str) or not value:
                raise ConfigError(
                    f"{where}.{key} is required for an mTLS listener"
                )
    return raw


def resolve_listener_security(entry: dict) -> dict:
    """Resolve one listener's three security knobs (never downgrades).

    ``security.transport_encryption = "auto"`` resolves to ``mtls`` on TCP and
    ``none`` on VSOCK/Unix. An enabled ``[mtls]`` block forces mTLS on any
    transport. Plaintext is accepted only when both authentication knobs say
    ``none`` explicitly, and mTLS forces both to ``transport``.
    """
    if not isinstance(entry, dict):
        raise ConfigError("a listener entry must be a table")

    security = entry.get("security")
    if security is None:
        security = {}
    if not isinstance(security, dict):
        raise ConfigError("'[security]' must be a table")
    unknown = sorted(set(security) - CONFIG_SECURITY_KEYS)
    if unknown:
        raise ConfigError(
            "unknown key(s) inside [security]: "
            + ", ".join(repr(key) for key in unknown)
        )

    transport = entry.get("type") or entry.get("transport") or "tcp"
    if transport not in LISTENER_TYPES:
        raise ConfigError(
            f"unknown transport {transport!r} "
            f"(expected one of {', '.join(LISTENER_TYPES)})"
        )

    mtls = entry.get("mtls")
    if mtls is not None and not isinstance(mtls, dict):
        raise ConfigError("'[mtls]' must be a table")
    mtls_enabled = isinstance(mtls, dict) and bool(mtls.get("enable", False))

    transport_encryption = security.get("transport_encryption")
    if transport_encryption is None or transport_encryption == "auto":
        transport_encryption = (
            "mtls" if (mtls_enabled or transport == "tcp") else "none"
        )
    if transport_encryption not in TRANSPORT_ENCRYPTIONS:
        raise ConfigError(
            f"unknown transport_encryption {transport_encryption!r} "
            f"(expected one of {', '.join(TRANSPORT_ENCRYPTIONS)})"
        )
    if mtls_enabled and transport_encryption != "mtls":
        raise ConfigError(
            "mtls.enable = true conflicts with transport_encryption = "
            f"{transport_encryption!r}; refusing to downgrade"
        )

    client_auth = security.get("client_auth")
    server_auth = security.get("server_auth")
    for name, value in (
        ("client_auth", client_auth),
        ("server_auth", server_auth),
    ):
        if value is not None and not isinstance(value, str):
            raise ConfigError(f"{name} must be a single string")
        if value is not None and value not in ("transport", "none"):
            raise ConfigError(
                f"unknown {name} {value!r} (expected one of 'transport', 'none')"
            )

    if transport_encryption == "mtls":
        if client_auth not in (None, "transport"):
            raise ConfigError(
                "under transport_encryption = 'mtls', client_auth must be "
                f"'transport', not {client_auth!r} (mTLS forces it)"
            )
        if server_auth not in (None, "transport"):
            raise ConfigError(
                "under transport_encryption = 'mtls', server_auth must be "
                f"'transport', not {server_auth!r} (mTLS forces it)"
            )
        client_auth = "transport"
        server_auth = "transport"
    else:
        if client_auth == "transport":
            raise ConfigError(
                "client_auth = 'transport' requires transport_encryption = 'mtls'"
            )
        if server_auth == "transport":
            raise ConfigError(
                "server_auth = 'transport' requires transport_encryption = 'mtls'"
            )
        if client_auth is None or server_auth is None:
            missing = [
                name
                for name, value in (
                    ("client_auth", client_auth),
                    ("server_auth", server_auth),
                )
                if value is None
            ]
            raise ConfigError(
                "transport_encryption = 'none' requires an explicit "
                + " and ".join(f"{name} = 'none'" for name in missing)
            )

    return {
        "transport_encryption": transport_encryption,
        "client_auth": client_auth,
        "server_auth": server_auth,
    }


def validate_security_config(config: dict) -> dict:
    """Validate one flat security block (the client's single transport)."""
    return resolve_listener_security(config)


def _as_pattern_tuple(value, *, field: str, where: str) -> tuple:
    """Normalize a rule selector to a tuple of glob patterns."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)) and all(
        isinstance(item, str) for item in value
    ):
        return tuple(value)
    raise ConfigError(
        f"{where}.{field} must be a string or a list of strings, got {value!r}"
    )


@dataclass(frozen=True)
class Rule:
    """One ordered ``[[rule]]`` authorization rule.

    Every selector is a tuple of ``fnmatch`` patterns; an empty selector
    matches anything. ``machine`` never matches an unauthenticated identity
    (``None``) unless the selector is empty. Rules are evaluated in file order
    and the first match wins.
    """

    machine: tuple = ()
    listeners: tuple = ()
    action: tuple = ()
    target: tuple = ()
    policy: str = "deny"

    def matches(
        self,
        *,
        listener: str,
        machine: Optional[str],
        action: str,
        target: Optional[str],
    ) -> bool:
        """True when every selector matches this request context."""
        return (
            _machine_matches(self.machine, machine)
            and _any_pattern_matches(self.listeners, listener or "")
            and _any_pattern_matches(self.action, action or "")
            and _any_pattern_matches(self.target, target or "")
        )


def _machine_matches(patterns: tuple, machine: Optional[str]) -> bool:
    """Empty selector matches anything; a non-empty one requires an identity."""
    if not patterns:
        return True
    if machine is None:
        return False
    return any(fnmatch.fnmatchcase(machine, pattern) for pattern in patterns)


def _any_pattern_matches(patterns: tuple, value: str) -> bool:
    """True when an empty selector, or any pattern, matches ``value``."""
    if not patterns:
        return True
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def parse_rules(entries) -> tuple:
    """Validate the top-level ``[[rule]]`` list into ordered ``Rule`` objects."""
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise ConfigError("'rule' must be an array of tables")
    rules = []
    for index, entry in enumerate(entries):
        where = f"rule[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = sorted(set(entry) - CONFIG_RULE_KEYS)
        if unknown:
            raise ConfigError(
                f"{where} has unknown key(s): "
                + ", ".join(repr(key) for key in unknown)
            )
        policy = entry.get("policy", "deny")
        if policy not in RULE_POLICIES:
            raise ConfigError(
                f"{where}.policy must be one of "
                f"{', '.join(RULE_POLICIES)}, got {policy!r}"
            )
        match = entry.get("match", {})
        if not isinstance(match, dict):
            raise ConfigError(f"{where}.match must be a table")
        unknown = sorted(set(match) - CONFIG_RULE_MATCH_KEYS)
        if unknown:
            raise ConfigError(
                f"{where}.match has unknown key(s): "
                + ", ".join(repr(key) for key in unknown)
            )
        rules.append(
            Rule(
                machine=_as_pattern_tuple(
                    match.get("machine"),
                    field="machine",
                    where=f"{where}.match",
                ),
                listeners=_as_pattern_tuple(
                    match.get("listeners"),
                    field="listeners",
                    where=f"{where}.match",
                ),
                action=_as_pattern_tuple(
                    match.get("action"),
                    field="action",
                    where=f"{where}.match",
                ),
                target=_as_pattern_tuple(
                    match.get("target"),
                    field="target",
                    where=f"{where}.match",
                ),
                policy=policy,
            )
        )
    return tuple(rules)


def evaluate_rules(
    rules,
    *,
    listener: str,
    machine: Optional[str],
    action: str,
    target: Optional[str],
) -> str:
    """Return the first matching rule's policy, or ``"deny"`` by default."""
    for rule in rules or ():
        if rule.matches(
            listener=listener, machine=machine, action=action, target=target
        ):
            return rule.policy
    return "deny"


def _normalize_fingerprint(fingerprint: object, kind: str) -> str:
    """Return a validated ``SHA256:<base64>`` fingerprint, padding stripped."""
    if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
        raise ConfigError(
            f"{kind} entries must be 'SHA256:...' fingerprints, "
            f"got {fingerprint!r}"
        )
    body = fingerprint[len("SHA256:") :].rstrip("=")
    if not body:
        raise ConfigError(f"{kind} entry {fingerprint!r} has no digest")
    padded = body + "=" * (-len(body) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ConfigError(
            f"{kind} entry {fingerprint!r} is not valid base64"
        ) from error
    if len(raw) != 32:
        raise ConfigError(f"{kind} entry {fingerprint!r} is not a SHA-256 digest")
    return "SHA256:" + body


def _fingerprint_set(entries: object, kind: str) -> frozenset:
    """Validate a ``[acl]`` fingerprint list into a frozen set."""
    if entries is None:
        return frozenset()
    if not isinstance(entries, list):
        raise ConfigError(f"[acl] {kind} must be a list of fingerprints")
    return frozenset(_normalize_fingerprint(entry, kind) for entry in entries)


def load_client_acl(config: dict) -> tuple:
    """Validate the client ``[acl]`` server pin.

    Returns ``(trusted_fingerprints, trusted_names)``. An absent ``[acl]``
    means no extra pin; a present one must pin at least one identity.
    """
    raw = config.get("acl")
    if raw is None:
        return frozenset(), ()
    if not isinstance(raw, dict):
        raise ConfigError("'[acl]' must be a table")
    unknown = sorted(set(raw) - CONFIG_ACL_KEYS)
    if unknown:
        raise ConfigError(
            "[acl] has unknown key(s): "
            + ", ".join(repr(key) for key in unknown)
        )
    trusted_fingerprints = _fingerprint_set(
        raw.get("trusted_fingerprints"), "trusted_fingerprints"
    )
    names = raw.get("trusted_names")
    if names is None:
        trusted_names: tuple = ()
    elif isinstance(names, str):
        trusted_names = (names,) if names else ()
    elif isinstance(names, list) and all(
        isinstance(name, str) for name in names
    ):
        trusted_names = tuple(names)
    else:
        raise ConfigError(
            "[acl] trusted_names must be a string or a list of strings"
        )
    if not trusted_fingerprints and not trusted_names:
        raise ConfigError(
            "[acl] must set trusted_fingerprints and/or trusted_names "
            "(an empty pin would trust any CA-signed server)"
        )
    return trusted_fingerprints, trusted_names


def validate_listener_table(entry: dict, *, where: str) -> None:
    """Validate one self-contained ``[[listeners]]`` entry."""
    if not isinstance(entry, dict):
        raise ConfigError(f"'{where}' must be a table")
    unknown = sorted(set(entry) - CONFIG_LISTENER_KEYS)
    if unknown:
        raise ConfigError(
            f"unknown key(s) in {where}: "
            + ", ".join(repr(key) for key in unknown)
        )
    if "type" not in entry:
        raise ConfigError(f"{where} is missing the required 'type' key")
    transport = entry.get("type")
    if transport not in LISTENER_TYPES:
        raise ConfigError(
            f"unknown {where}.type {transport!r} "
            f"(expected one of {', '.join(LISTENER_TYPES)})"
        )
    if transport == "unix" and not entry.get("socket"):
        raise ConfigError(
            f"{where} is a unix listener and requires a 'socket' path"
        )

    for name, allowed in TABLE_KEYS.items():
        table = entry.get(name)
        if table is None:
            continue
        if not isinstance(table, dict):
            raise ConfigError(f"[{where}.{name}] must be a table")
        nested_unknown = sorted(set(table) - allowed)
        if nested_unknown:
            raise ConfigError(
                f"unknown key(s) inside [{where}.{name}]: "
                + ", ".join(repr(key) for key in nested_unknown)
            )

    if "admin" in entry and not isinstance(entry["admin"], bool):
        raise ConfigError(f"{where}.admin must be a boolean")

    resolution = entry.get("resolution")
    if resolution is not None:
        if resolution not in RESOLUTION_MODES:
            raise ConfigError(
                f"unknown {where}.resolution {resolution!r} "
                f"(expected one of {', '.join(RESOLUTION_MODES)})"
            )
        if transport == "unix" and resolution in ("tartarus", "mofos"):
            raise ConfigError(
                f"{where}.resolution = {resolution!r} is not valid on a unix "
                "listener (there is no CID or IP to map)"
            )

    for field in (
        "connect_timeout",
        "handshake_timeout",
        "max_connections",
        "server_read_timeout",
    ):
        if field in entry:
            _positive_number(
                entry[field],
                field=field,
                where=where,
                integer=(field == "max_connections"),
            )
    for field in ("socket_dir_mode", "socket_mode"):
        if field in entry:
            _parse_mode_value(entry[field], field=field, where=where)

    resolved = resolve_listener_security(entry)
    if (
        resolution == "certificate"
        and resolved["transport_encryption"] != "mtls"
    ):
        raise ConfigError(
            f"{where}.resolution = 'certificate' requires "
            "transport_encryption = 'mtls'"
        )
    if resolved["transport_encryption"] == "mtls":
        mtls = load_mtls(entry, where=f"{where}.mtls", required=True)
        # A server listener authenticates both ends: its own EKU and the
        # peer's EKU must both be stated explicitly.
        for key in ("required_oid", "peer_required_oid"):
            value = mtls.get(key)
            if not isinstance(value, str) or not value:
                raise ConfigError(
                    f"{where}.mtls.{key} is required for an mTLS listener"
                )
        peer_oid = mtls.get("peer_required_oid")
        if entry.get("admin") is True:
            if peer_oid != ADMIN_OID:
                raise ConfigError(
                    f"{where} is an admin listener, so its mTLS "
                    f"peer_required_oid must be the admin OID {ADMIN_OID}"
                )
        elif peer_oid == ADMIN_OID:
            raise ConfigError(
                f"{where} is not an admin listener and may not accept the "
                f"admin EKU OID {ADMIN_OID}"
            )
    else:
        if entry.get("mtls") is not None:
            load_mtls(entry, where=f"{where}.mtls", required=False)


def _validate_vm_table(config: dict, name: str, key: str) -> None:
    """Validate the optional ``[[vm]]`` / ``[[tcp_vm]]`` resolution maps."""
    entries = config.get(name)
    if entries is None:
        return
    if not isinstance(entries, list):
        raise ConfigError(f"'{name}' must be an array of tables")
    for index, entry in enumerate(entries):
        where = f"{name}[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = sorted(set(entry) - {key, "name"})
        if unknown:
            raise ConfigError(
                f"{where} has unknown key(s): "
                + ", ".join(repr(item) for item in unknown)
            )
        if key not in entry:
            raise ConfigError(f"{where} is missing the required {key!r} key")
        if not isinstance(entry.get("name"), str) or not entry.get("name"):
            raise ConfigError(f"{where}.name must be a non-empty string")


def validate_document_schema(
    config: dict, *, role: Optional[str] = None, source: Optional[str] = None
) -> str:
    """Validate a whole clipboard-bridge document for ``role``.

    The top level and every nested table are checked against an exact key set;
    a server must carry a non-empty ``[[listeners]]`` array whose entries are
    self-contained and uniquely named. Returns the resolved role.
    """
    if not isinstance(config, dict):
        raise ConfigError("the configuration document must be a table")
    if role is None:
        mode = config.get("mode")
        if mode in ("server", "client"):
            role = mode
        elif "listeners" in config:
            role = "server"
        else:
            role = "client"
    if role not in ("server", "client"):
        raise ConfigError(
            f"unknown role {role!r} (expected 'server' or 'client')"
        )
    if "mode" in config and config["mode"] != role:
        raise ConfigError(
            f"mode = {config['mode']!r} does not match the {role} role"
        )

    allowed = (
        SERVER_TOP_LEVEL_KEYS if role == "server" else CLIENT_TOP_LEVEL_KEYS
    )
    unknown = sorted(set(config) - allowed)
    if unknown:
        raise ConfigError(
            "unknown key(s) at the top level: "
            + ", ".join(repr(key) for key in unknown)
        )

    if role == "server":
        entries = config.get("listeners")
        if not isinstance(entries, list) or not entries:
            raise ConfigError(
                "a server config must define a non-empty [[listeners]] array"
            )
        seen_names: set[str] = set()
        for index, entry in enumerate(entries):
            where = f"listeners[{index}]"
            validate_listener_table(entry, where=where)
            name = entry.get("name")
            if name is not None:
                if not isinstance(name, str) or not name:
                    raise ConfigError(
                        f"{where}.name must be a non-empty string"
                    )
                if name in seen_names:
                    raise ConfigError(f"duplicate listener name: {name!r}")
                seen_names.add(name)
        _validate_vm_table(config, "vm", "cid")
        _validate_vm_table(config, "tcp_vm", "ip")
        parse_rules(config.get("rule"))
    else:
        for name, allowed_keys in TABLE_KEYS.items():
            _validate_table(config, name, allowed_keys)
        if any(key in config for key in ("security", "mtls", "transport")):
            normalized = resolve_listener_security(config)
            if normalized["transport_encryption"] == "mtls":
                load_mtls(config, where="[mtls]", required=True)
        if config.get("transport") == "unix" and not config.get("socket"):
            raise ConfigError(
                "a unix client requires a non-empty 'socket' path"
            )
        for field in ("connect_timeout", "handshake_timeout", "recv_timeout"):
            if field in config:
                _positive_number(
                    config[field], field=field, where="client"
                )
        load_client_acl(config)

    return role


def load_config(path: Optional[str] = None, role: str = "client") -> dict:
    """Load and validate the TOML config for ``role``.

    The role selects the default file when no ``--config`` is given. mTLS
    paths are resolved against the config file's own directory, and socket
    paths get their ``~``/``%t/`` placeholders expanded. A missing file returns
    ``{}`` (client defaults); a server config without listeners is rejected.
    """
    if role not in ("server", "client"):
        raise ConfigError(
            f"unknown role {role!r} (expected 'server' or 'client')"
        )
    if path is None:
        path = (
            DEFAULT_SERVER_CONFIG_PATH
            if role == "server"
            else DEFAULT_CLIENT_CONFIG_PATH
        )
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = p.resolve()
    if not p.exists():
        return {}

    with open(p, "rb") as f:
        config = tomllib.load(f)

    config_dir = p.parent

    def resolve_tables(container: dict) -> None:
        mtls = container.get("mtls")
        if isinstance(mtls, dict):
            for key in ("ca_file", "cert_file", "key_file"):
                if mtls.get(key):
                    mtls[key] = _resolve_config_path(mtls[key], config_dir)

    resolve_tables(config)

    for key in ("socket", "proxy_socket"):
        if isinstance(config.get(key), str) and config[key]:
            config[key] = expand_socket_path(config[key])

    entries = config.get("listeners")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                resolve_tables(entry)
                if isinstance(entry.get("socket"), str) and entry["socket"]:
                    entry["socket"] = expand_socket_path(entry["socket"])

    validate_document_schema(config, role=role, source=str(p))
    return config


def listener_views(config: dict) -> list[dict]:
    """Expand a server document into one self-contained view per listener.

    Every ``[[listeners]]`` entry keeps its own transport, bind target,
    security, mTLS material and resolution. Document-scoped values the handler
    needs (rules, debug and the ``vm``/``tcp_vm``/``labels`` maps) are attached
    under private ``_`` keys; security, mTLS and resolution are never
    inherited. A flat server document is rejected outright.
    """
    if not isinstance(config, dict):
        raise ConfigError("the configuration document must be a table")
    entries = config.get("listeners")
    if not isinstance(entries, list) or not entries:
        raise ConfigError(
            "a server config must define a non-empty [[listeners]] array"
        )

    views = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"listeners[{index}] must be a table")
        view = dict(entry)
        transport = view.get("type", view.get("transport"))
        if transport is not None:
            view["transport"] = transport
        view.pop("type", None)
        view["_listener_index"] = index
        view["_listener_name"] = view.get("name")
        view["_admin"] = bool(view.get("admin", False))
        if "debug" in config:
            view["_debug"] = config["debug"]
        if "rule" in config:
            view["_rule"] = config["rule"]
        if "labels" in config:
            view["_labels"] = config["labels"]
        if "vm" in config:
            view["_vm"] = config["vm"]
        if "tcp_vm" in config:
            view["_tcp_vm"] = config["tcp_vm"]
        views.append(view)
    return views


# --- EKU OID Verification ---

# cryptography.x509 costs ~500-700ms to import (Rust extension + a long
# submodule chain) -- deferred to first actual use so invocations that never
# touch a certificate (--help, plaintext calls, admin over a Unix socket)
# don't pay for it.
_x509 = None
_NameOID = None


def _load_x509():
    global _x509, _NameOID
    if _x509 is None:
        try:
            import cryptography.x509 as x509_mod
            from cryptography.x509.oid import NameOID as name_oid_mod
        except ImportError:
            return None, None
        _x509, _NameOID = x509_mod, name_oid_mod
    return _x509, _NameOID


def _require_x509():
    """Return ``cryptography.x509`` or raise when it is unavailable."""
    x509_module, _ = _load_x509()
    if x509_module is None:
        raise RuntimeError(
            "cryptography library is required for certificate handling"
        )
    return x509_module


def _cert_has_oid(cert: "x509.Certificate", oid: str) -> bool:
    x509, _ = _load_x509()
    if x509 is None:
        return False
    try:
        ekus = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        return any(eku.dotted_string == oid for eku in ekus)
    except x509.ExtensionNotFound:
        return False


def verify_cert_file(path: str, oid: str, label: str) -> None:
    """Verify that a PEM certificate carries the required EKU OID."""
    x509 = _require_x509()
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if not _cert_has_oid(cert, oid):
        raise ValueError(
            f"{label} certificate {path} missing required EKU OID {oid}"
        )


def verify_cert_der(der: bytes, oid: str, label: str) -> None:
    """Verify that a DER certificate carries the required EKU OID."""
    x509 = _require_x509()
    cert = x509.load_der_x509_certificate(der)
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate missing required EKU OID {oid}")


def _load_der_cert(der: bytes):
    x509 = _require_x509()
    return x509.load_der_x509_certificate(der)


def spki_fingerprint(public_key) -> str:
    """``SHA256:<base64>`` SPKI fingerprint (padding stripped)."""
    from cryptography.hazmat.primitives import serialization

    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _cert_names_from_der(der: bytes) -> tuple:
    """Return the CN and DNS SANs of a DER certificate, for ACL pinning."""
    x509, NameOID = _load_x509()
    if x509 is None or NameOID is None:
        raise RuntimeError(
            "cryptography library is required for certificate handling"
        )
    cert = x509.load_der_x509_certificate(der)
    names = []
    for attribute in cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    ):
        if isinstance(attribute.value, str) and attribute.value:
            names.append(attribute.value)
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        names.extend(san.get_values_for_type(x509.DNSName))
    return tuple(names)


def _verify_peer_oid(sock, config: dict, label: str) -> None:
    """Enforce the configured peer EKU OID on a TLS-wrapped socket."""
    try:
        resolved = resolve_listener_security(config)
    except ConfigError:
        return
    if resolved["transport_encryption"] != "mtls":
        return
    mtls = config.get("mtls")
    if not isinstance(mtls, dict):
        return
    peer_oid = mtls.get("peer_required_oid")
    if not peer_oid:
        return
    der = sock.getpeercert(binary_form=True)
    if der:
        verify_cert_der(der, peer_oid, label)


def verify_server_acl(sock, config: dict) -> None:
    """Enforce the client ``[acl]`` pin on a TLS-wrapped server connection."""
    trusted_fingerprints, trusted_names = load_client_acl(config)
    if not trusted_fingerprints and not trusted_names:
        return
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise ConnectionError(
            "transport_encryption = 'mtls' did not yield a peer certificate "
            "to pin"
        )
    fingerprint = spki_fingerprint(_load_der_cert(der).public_key())
    if fingerprint in trusted_fingerprints:
        return
    names = _cert_names_from_der(der)
    if trusted_names and any(
        fnmatch.fnmatchcase(name, pattern)
        for name in names
        for pattern in trusted_names
    ):
        return
    raise ConnectionError(
        f"server certificate {fingerprint} is not in the client [acl] "
        "(neither its fingerprint nor its CN/SAN is pinned)"
    )


# --- SSL Context ---


def create_ssl_context(config: dict, *, server: bool) -> Optional[ssl.SSLContext]:
    """Build the mTLS context, or ``None`` when the channel is plaintext.

    The decision is driven by the validated ``transport_encryption``, never by
    ``mtls.enable`` alone. When mTLS is required but ``[mtls]`` is missing or
    incomplete the process exits non-zero instead of continuing unencrypted.
    """
    try:
        normalized = resolve_listener_security(config)
    except ConfigError as error:
        print(f"clipboard-bridge: {error}", file=sys.stderr)
        sys.exit(1)
    if normalized["transport_encryption"] != "mtls":
        return None

    try:
        mtls = load_mtls(config, where="[mtls]", required=True)
    except ConfigError as error:
        print(f"clipboard-bridge: {error}", file=sys.stderr)
        sys.exit(1)

    ca_file = mtls["ca_file"]
    cert_file = mtls["cert_file"]
    key_file = mtls["key_file"]
    required_oid = mtls.get("required_oid")
    if required_oid:
        try:
            verify_cert_file(cert_file, required_oid, "Local")
        except (ValueError, RuntimeError) as e:
            print(f"clipboard-bridge: {e}", file=sys.stderr)
            sys.exit(1)

    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose)
    if not server:
        # Peer identity is enforced by the EKU OID check and the optional
        # [acl] pin, not by hostname/IP matching: the guest's host address is
        # a DHCP lease (or a VSOCK CID, not a hostname at all) and the server
        # certificate's CN is a template name, not an address.
        context.check_hostname = False
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


# --- Client Identification & Resolution ---


def get_client_id(server_type, client_address):
    if server_type == "vsock":
        return f"vsock:{client_address[0]}"
    if server_type == "tcp":
        return f"tcp:{client_address[0]}"
    if server_type == "unix":
        return "unix:local"
    return "unknown"


def resolve_target_to_id(target, config=None):
    """Resolve an admin ``target`` to a canonical client id.

    Direct client ids (``vsock:``, ``tcp:``, ``unix:``) are exact matches, so an
    admin can always address a slot before its guest registers. Any other value
    is a friendly name: it is resolved against the registered clients first,
    then against the listener document's ``[[vm]]`` (``name -> vsock:<cid>``)
    and ``[[tcp_vm]]`` (``name -> tcp:<ip>``) maps, and only then used verbatim
    as a raw slot key. Checking names before the raw fallback stops a
    pre-registration ``set target=notes`` from creating a phantom ``notes`` slot
    that would shadow the real guest once it registers.
    """
    if target is None:
        return None
    if isinstance(target, str) and target.startswith(
        ("vsock:", "tcp:", "unix:")
    ):
        return target
    for cid, info in client_clipboards.items():
        if info.get("name") == target:
            return cid
    document = config or {}
    for vm in document.get("_vm") or document.get("vm") or []:
        if isinstance(vm, dict) and vm.get("name") == target:
            return f"vsock:{vm.get('cid')}"
    for vm in document.get("_tcp_vm") or document.get("tcp_vm") or []:
        if isinstance(vm, dict) and vm.get("name") == target:
            return f"tcp:{vm.get('ip')}"
    return target


def get_cert_cn(der: bytes) -> Optional[str]:
    """Extract the Subject CN from a DER-encoded peer certificate."""
    x509, NameOID = _load_x509()
    if x509 is None:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def tartarus_name_for_id(vm_id: int) -> Optional[str]:
    """Resolve a tartarus VM id to its name via tartarus's state directory."""
    if not TARTARUS_STATE_ROOT.is_dir():
        return None
    try:
        for entry in TARTARUS_STATE_ROOT.iterdir():
            cid_file = entry / "cid"
            if not cid_file.is_file():
                continue
            try:
                if int(cid_file.read_text().strip()) == vm_id:
                    return entry.name
            except ValueError:
                continue
    except Exception:
        pass
    return None


_mofos_cache = {}
MOFOS_CACHE_TTL = 30


def _mofos_name_for(field: str, value):
    """Resolve a VSOCK CID or IPv4 address to a VM name via ``mofos ls``."""
    cache_key = (field, value)
    now = time.time()
    cached = _mofos_cache.get(cache_key)
    if cached is not None:
        name, timestamp = cached
        if now - timestamp < MOFOS_CACHE_TTL:
            return name
    try:
        result = subprocess.run(
            ["mofos", "ls", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            _debug(f"mofos ls failed: {result.stderr.strip()}")
            return None
        vms = json.loads(result.stdout)
        name = None
        for vm in vms:
            if vm.get(field) == value:
                name = vm.get("name")
                break
        _mofos_cache[cache_key] = (name, now)
        stale = [
            key
            for key, (_, timestamp) in _mofos_cache.items()
            if now - timestamp >= MOFOS_CACHE_TTL
        ]
        for key in stale:
            del _mofos_cache[key]
        return name
    except Exception as e:
        _debug(f"mofos resolution failed: {e}")
        return None


def resolve_mofos_name(cid) -> Optional[str]:
    """Resolve a VSOCK CID to a VM name via ``mofos ls --json``."""
    try:
        return _mofos_name_for("cid", int(cid))
    except (ValueError, TypeError):
        return None


def resolve_mofos_ip(ip: str) -> Optional[str]:
    """Resolve an IPv4 address to a VM name via ``mofos ls --json``."""
    return _mofos_name_for("ipv4_address", ip)


def tartarus_id_for_ip(ip: str) -> Optional[int]:
    """Resolve a peer IP to a tartarus VM id.

    Linux: guests sit on a static bridge subnet (10.200.0.<id>), so the id is
    just the last octet -- no lookup needed. macOS: guests get a DHCP-assigned
    IP over vmnet-shared that isn't known ahead of time, so correlate via the
    ARP table -> the VM's deterministic MAC (02:00:00:00:00:<id-hex>), the
    same convention tartarus.py's vm_resolve_running_ip uses, in reverse.
    """
    match = re.match(r"^10\.200\.0\.(\d+)$", ip)
    if match:
        return int(match.group(1))
    try:
        result = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return None
    mac = None
    for line in result.stdout.splitlines():
        if f"({ip})" in line:
            m = re.search(r"at ([0-9a-fA-F:]+)", line)
            if m:
                mac = m.group(1)
            break
    if not mac:
        return None
    try:
        return int(mac.split(":")[-1], 16)
    except ValueError:
        return None


def _resolve_tartarus_name(client_id: str, config: dict) -> Optional[str]:
    """Resolve a client id via the listener's ``[[vm]]``/``[[tcp_vm]]`` maps."""
    if client_id.startswith("vsock:"):
        try:
            cid = int(client_id.split(":", 1)[1])
        except ValueError:
            return None
        for vm in config.get("_vm", []) or []:
            if isinstance(vm, dict) and vm.get("cid") == cid:
                return vm.get("name")
        return tartarus_name_for_id(cid)
    if client_id.startswith("tcp:"):
        ip = client_id.split(":", 1)[1]
        for vm in config.get("_tcp_vm", []) or []:
            if isinstance(vm, dict) and vm.get("ip") == ip:
                return vm.get("name")
        vm_id = tartarus_id_for_ip(ip)
        if vm_id is None:
            return None
        return tartarus_name_for_id(vm_id)
    return None


def resolve_client_name(client_id):
    """Resolve a client id to a name via tartarus bookkeeping."""
    if not client_id.startswith("vsock:"):
        return client_id
    try:
        cid = int(client_id.split(":", 1)[1])
    except ValueError:
        return client_id
    name = tartarus_name_for_id(cid)
    return name if name else client_id


def get_resolution_mode(config: dict) -> str:
    """Return the listener's configured resolution mode (default ``none``)."""
    mode = config.get("resolution")
    if mode is None:
        return "none"
    if mode == "qemu":
        raise ConfigError(
            "resolution = 'qemu' was removed; use 'tartarus' or 'mofos'"
        )
    if mode not in RESOLUTION_MODES:
        raise ConfigError(f"unknown resolution mode {mode!r}")
    return mode


def resolve_friendly_name(
    client_id: str, config: dict, peer_der: Optional[bytes]
) -> Optional[str]:
    """Resolve the identity of the connecting peer for this listener."""
    mode = get_resolution_mode(config)
    if mode == "none":
        return None
    if mode == "certificate":
        return get_cert_cn(peer_der) if peer_der else None
    if mode == "tartarus":
        return _resolve_tartarus_name(client_id, config)
    if mode == "mofos":
        if client_id.startswith("vsock:"):
            try:
                cid = int(client_id.split(":", 1)[1])
            except ValueError:
                return None
            return resolve_mofos_name(cid)
        if client_id.startswith("tcp:"):
            return resolve_mofos_ip(client_id.split(":", 1)[1])
        return None
    return None


def notify(client_name, action):
    if no_notify:
        return
    display_name = client_name if client_name is not None else "unknown"
    try:
        subprocess.run(
            [
                "notify-send",
                "Clipboard Bridge",
                f"{action} from {display_name}",
            ],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        pass


def notify_and_broadcast(
    target_id,
    data,
    action_text,
    name=None,
    config=None,
    exclude_wfile=None,
):
    """Update clipboard store and notify/broadcast to subscribers.

    ``name`` overrides the resolved friendly name -- pass it only when the
    connecting peer IS target_id (a client pushing to its own slot), never for
    an admin push to a ``--target``.
    """
    with client_lock:
        if config is not None and get_resolution_mode(config) == "none":
            name = None
        elif name is None:
            existing = client_clipboards.get(target_id, {}).get("name")
            if existing is not None:
                name = existing
            else:
                name = resolve_client_name(target_id)
        client_clipboards[target_id] = {
            "data": data,
            "updated": time.time(),
            "name": name,
        }
    notify(name, action_text)

    with subscriber_lock:
        subs = list(client_subscribers.get(target_id, []))
    for wfile in subs:
        if wfile is exclude_wfile:
            continue
        try:
            msg = json.dumps({"status": "ok", "data": data}) + "\n"
            wfile.write(msg.encode("utf-8"))
            wfile.flush()
        except Exception:
            pass


# --- JSON Protocol Handler ---


def _unauthorized(
    message: str = "request not authorized by listener/rule",
) -> dict:
    """Build the single authorization error every denial uses."""
    return {"status": "error", "message": message}


class ClipboardHandler(socketserver.StreamRequestHandler):
    def setup(self):
        """Complete the TLS handshake in this per-connection thread.

        The accept loop hands over a raw socket; the handshake runs here, under
        ``handshake_timeout``, after a ``max_connections`` slot has been taken.
        """
        server = self.server
        sock = self.request
        handshake_timeout = getattr(server, "cb_handshake_timeout", None)
        read_timeout = getattr(server, "cb_read_timeout", None)
        ssl_context = getattr(server, "ssl_context", None)
        if ssl_context is not None and handshake_timeout is not None:
            with contextlib.suppress(OSError):
                sock.settimeout(handshake_timeout)
        if ssl_context is not None:
            try:
                sock = ssl_context.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError) as error:
                print(
                    f"clipboard-bridge: SSL handshake failed from "
                    f"{self.client_address}: {error}",
                    file=sys.stderr,
                )
                with contextlib.suppress(OSError):
                    sock.close()
                raise
            self.request = sock
        if read_timeout is not None:
            with contextlib.suppress(OSError):
                sock.settimeout(read_timeout)
        super().setup()

    def handle(self):
        # Loops over multiple requests on the same connection so a persistent
        # caller (PersistentConnection / the proxy, and a VM client's reused
        # push connection) keeps its already-completed TLS handshake warm.
        server = self.server
        config = getattr(server, "cb_config", {})
        set_debug(config)
        server_type = config.get("transport", "tcp")
        client_id = get_client_id(server_type, self.client_address)
        admin_listener = bool(getattr(server, "cb_admin", False))
        listener_name = getattr(server, "cb_listener_name", None) or ""
        rules = getattr(server, "cb_rules", ())

        try:
            security = resolve_listener_security(config)
        except ConfigError as error:
            self._send_error(f"configuration error: {error}")
            return

        peer_der = None
        if security["transport_encryption"] == "mtls" and hasattr(
            self.request, "getpeercert"
        ):
            peer_der = self.request.getpeercert(binary_form=True)
            peer_oid = (config.get("mtls") or {}).get("peer_required_oid")
            if peer_oid and peer_der:
                try:
                    verify_cert_der(peer_der, peer_oid, "Peer")
                except (ValueError, RuntimeError) as e:
                    print(f"clipboard-bridge: {e}", file=sys.stderr)
                    self._send_error("SSL verification failed")
                    return

        # Identity used by `match.machine` and by friendly-name display.
        machine = resolve_friendly_name(client_id, config, peer_der)

        while True:
            t_start = time.monotonic()
            try:
                line = self.rfile.readline()
                if not line:
                    return

                request = json.loads(line.decode("utf-8"))
                action = request.get("action")
                data = request.get("data", "")
                target = request.get("target")
                wants_json = bool(request.get("json"))

                if admin_listener:
                    response = self._handle_admin(
                        action=action,
                        data=data,
                        target=target,
                        wants_json=wants_json,
                        config=config,
                        machine=machine,
                        rules=rules,
                        listener_name=listener_name,
                    )
                else:
                    response = self._handle_guest(
                        action=action,
                        data=data,
                        target=target,
                        wants_json=wants_json,
                        config=config,
                        machine=machine,
                        client_id=client_id,
                    )
                if response is None:
                    return

                _debug(
                    f"handle: action={action} client={client_id} "
                    f"total={_ms(time.monotonic() - t_start)}"
                )
                self.wfile.write(
                    (json.dumps(response) + "\n").encode("utf-8")
                )
                self.wfile.flush()
            except json.JSONDecodeError as e:
                try:
                    self.wfile.write(
                        (
                            json.dumps(
                                {
                                    "status": "error",
                                    "message": f"Invalid JSON: {e}",
                                }
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    self.wfile.flush()
                except Exception:
                    return
            except (socket.timeout, TimeoutError):
                return
            except Exception as e:
                try:
                    self.wfile.write(
                        (
                            json.dumps(
                                {"status": "error", "message": str(e)}
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    self.wfile.flush()
                except Exception:
                    return

    def _handle_admin(
        self,
        *,
        action,
        data,
        target,
        wants_json,
        config,
        machine,
        rules,
        listener_name,
    ):
        """Serve an admin listener; every accepted shape passes the rules.

        ``get`` with ``json`` and a ``target`` returns only the resolved target
        (a one-entry map, or ``{}`` when it has no slot), so a target-scoped
        rule can never leak another client's data.
        """
        is_admin_action = (
            action == "clients"
            or (action == "get" and (target or wants_json))
            or (action == "set" and target)
        )
        if not is_admin_action:
            return _unauthorized(
                "request not authorized by listener/rule: this is not an "
                "admin action on the admin listener"
            )
        if (
            evaluate_rules(
                rules,
                listener=listener_name,
                machine=machine,
                action=action,
                target=target,
            )
            != "allow"
        ):
            return _unauthorized()

        if action == "clients":
            with client_lock:
                result = [
                    {
                        "id": cid,
                        "name": info["name"],
                        "updated": info["updated"],
                    }
                    for cid, info in client_clipboards.items()
                ]
            return {"status": "ok", "data": result}

        if action == "get":
            if wants_json:
                with client_lock:
                    if target:
                        resolved = resolve_target_to_id(target, config)
                        info = client_clipboards.get(resolved)
                        result = (
                            {
                                resolved: {
                                    "data": info["data"],
                                    "updated": info["updated"],
                                    "name": info["name"],
                                }
                            }
                            if info is not None
                            else {}
                        )
                    else:
                        result = {
                            cid: {
                                "data": info["data"],
                                "updated": info["updated"],
                                "name": info["name"],
                            }
                            for cid, info in client_clipboards.items()
                        }
                return {"status": "ok", "data": result}
            with client_lock:
                resolved = resolve_target_to_id(target, config)
                info = client_clipboards.get(resolved, {})
            return {"status": "ok", "data": info.get("data", "")}

        if action == "set":
            resolved = resolve_target_to_id(target, config)
            notify_and_broadcast(
                resolved, data, "Host push", config=config
            )
            return {"status": "ok"}

        return _unauthorized()

    def _handle_guest(
        self,
        *,
        action,
        data,
        target,
        wants_json,
        config,
        machine,
        client_id,
    ):
        """Serve a guest listener: own slot, register and subscribe only."""
        if action == "set":
            if target:
                return _unauthorized(
                    "request not authorized by listener/rule: a guest "
                    "listener only writes the caller's own slot"
                )
            notify_and_broadcast(
                client_id,
                data,
                "Push",
                name=machine,
                config=config,
                exclude_wfile=self.wfile,
            )
            return {"status": "ok"}

        if action == "get":
            if target or wants_json:
                return _unauthorized(
                    "request not authorized by listener/rule: a guest "
                    "listener only reads the caller's own slot"
                )
            with client_lock:
                info = client_clipboards.get(client_id, {})
            return {"status": "ok", "data": info.get("data", "")}

        if action == "register":
            with client_lock:
                if client_id not in client_clipboards:
                    client_clipboards[client_id] = {
                        "data": "",
                        "updated": time.time(),
                        "name": machine,
                    }
                else:
                    client_clipboards[client_id]["updated"] = time.time()
                    if machine is not None:
                        client_clipboards[client_id]["name"] = machine
            return {"status": "ok"}

        if action == "subscribe":
            response = {"status": "ok", "message": "Subscribed"}
            self.wfile.write(
                (json.dumps(response) + "\n").encode("utf-8")
            )
            self.wfile.flush()

            with subscriber_lock:
                client_subscribers.setdefault(client_id, []).append(
                    self.wfile
                )

            try:
                while True:
                    ready, _, _ = select.select([self.rfile], [], [], 30.0)
                    if ready:
                        line = self.rfile.readline()
                        if not line:
                            break
            except Exception:
                pass
            finally:
                with subscriber_lock:
                    subs = client_subscribers.get(client_id, [])
                    if self.wfile in subs:
                        subs.remove(self.wfile)
                    if not subs:
                        client_subscribers.pop(client_id, None)
            return None

        return _unauthorized(
            "request not authorized by listener/rule: unknown guest "
            f"action {action!r}"
        )

    def _send_error(self, message):
        response = {"status": "error", "message": message}
        try:
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()
        except Exception:
            pass


# --- Server Transports ---


def _chmod(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as error:
        print(
            f"clipboard-bridge: could not chmod {path} to {mode:o}: {error}",
            file=sys.stderr,
        )


def _assert_owner_only(
    path: str, mode: int, kind: str, *, expect_dir: bool = False
) -> None:
    """Fail closed when ``path`` is not owned by us or is not at ``mode``."""
    try:
        info = os.lstat(path)
    except OSError as error:
        raise RuntimeError(f"cannot stat {kind} {path}: {error}") from error
    if info.st_uid != os.getuid():
        raise RuntimeError(
            f"{kind} {path} is not owned by uid {os.getuid()}"
        )
    actual = stat.S_IMODE(info.st_mode)
    if actual != mode:
        raise RuntimeError(
            f"{kind} {path} has mode {actual:04o}, expected {mode:04o}"
        )
    if expect_dir and not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{kind} {path} is not a directory")


def _prepare_unix_socket(path: str, dir_mode: int) -> None:
    """Create/verify the parent dir and remove a stale socket before bind."""
    target = Path(path)
    parent = target.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise RuntimeError(
            f"refusing to bind {path}: parent {parent} is a symlink"
        )
    _chmod(str(parent), dir_mode)
    _assert_owner_only(
        str(parent), dir_mode, "socket directory", expect_dir=True
    )
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"refusing to bind {path}: path is a symlink")
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(
            f"refusing to bind {path}: path exists and is not a socket"
        )
    if info.st_uid != os.getuid():
        raise RuntimeError(
            f"refusing to bind {path}: socket is not owned by uid "
            f"{os.getuid()}"
        )
    os.unlink(path)


def _unlink_bound_socket(server) -> None:
    """Unlink only the socket inode this server actually bound."""
    path = getattr(server, "cb_socket_path", None)
    bound_ino = getattr(server, "cb_bound_ino", None)
    if not path:
        return
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        bound_ino is not None
        and info.st_ino == bound_ino
        and stat.S_ISSOCK(info.st_mode)
    ):
        with contextlib.suppress(OSError):
            os.unlink(path)


class _ClipboardServer:
    """Per-listener bounds and error reporting shared by all transports."""

    ssl_context = None
    cb_config = {}
    cb_admin = False
    cb_listener_name = None
    cb_rules = ()
    cb_read_timeout = DEFAULT_SERVER_READ_TIMEOUT
    cb_handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT
    cb_max_connections = DEFAULT_MAX_CONNECTIONS
    _cb_semaphore = None

    def get_request(self):
        """Accept a connection and apply the per-connection read bound."""
        sock, addr = super().get_request()
        if self.cb_read_timeout is not None:
            with contextlib.suppress(OSError):
                sock.settimeout(self.cb_read_timeout)
        return sock, addr

    def process_request(self, request, client_address):
        """Spawn a handler thread only while under ``max_connections``."""
        semaphore = self._cb_semaphore
        if semaphore is not None and not semaphore.acquire(blocking=False):
            print(
                f"clipboard-bridge server: refusing connection from "
                f"{client_address}: connection limit "
                f"({self.cb_max_connections}) reached",
                file=sys.stderr,
            )
            with contextlib.suppress(OSError):
                request.close()
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        """Close a request and return its concurrency slot."""
        try:
            super().shutdown_request(request)
        finally:
            if self._cb_semaphore is not None:
                self._cb_semaphore.release()

    def handle_error(self, request, client_address):
        """Report expected transport errors without a traceback."""
        error = sys.exc_info()[1]
        if isinstance(
            error,
            (ssl.SSLError, ConnectionError, TimeoutError, socket.timeout),
        ):
            print(
                f"clipboard-bridge server: connection from "
                f"{client_address} failed: {error}",
                file=sys.stderr,
            )
            return
        super().handle_error(request, client_address)


class ThreadedTCPServer(
    _ClipboardServer, socketserver.ThreadingMixIn, socketserver.TCPServer
):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class ThreadedUnixServer(
    _ClipboardServer, socketserver.ThreadingMixIn, socketserver.UnixStreamServer
):
    daemon_threads = True
    block_on_close = False
    cb_socket_path = None
    cb_bound_ino = None


if hasattr(socket, "AF_VSOCK"):

    class ThreadedVsockServer(
        _ClipboardServer,
        socketserver.ThreadingMixIn,
        socketserver.TCPServer,
    ):
        address_family = socket.AF_VSOCK
        allow_reuse_address = True
        daemon_threads = True
        block_on_close = False

else:
    ThreadedVsockServer = None  # type: ignore


def _configure_server(
    server,
    view: dict,
    ssl_context,
    *,
    max_connections: int,
    read_timeout: float,
    handshake_timeout: float,
) -> None:
    """Attach the listener config, role, rules and bounds to a server."""
    server.ssl_context = ssl_context
    server.cb_config = view
    server.cb_admin = bool(view.get("_admin", False))
    server.cb_listener_name = view.get("_listener_name")
    server.cb_rules = view.get("_rules", ())
    server.cb_read_timeout = read_timeout
    server.cb_handshake_timeout = handshake_timeout
    server.cb_max_connections = max_connections
    server._cb_semaphore = threading.BoundedSemaphore(max_connections)
    server.request_queue_size = max_connections


def _bind_listener(view: dict):
    """Bind one listener and return ``(server, description)``."""
    transport = view.get("transport", "tcp")
    ssl_context = create_ssl_context(view, server=True)
    max_connections = _positive_int(
        view.get("max_connections"), DEFAULT_MAX_CONNECTIONS
    )
    read_timeout = _positive_float(
        view.get("server_read_timeout"), DEFAULT_SERVER_READ_TIMEOUT
    )
    handshake_timeout = _positive_float(
        view.get("handshake_timeout"), DEFAULT_HANDSHAKE_TIMEOUT
    )

    if transport == "unix":
        path = view.get("socket")
        if not path:
            raise ConfigError("a unix listener requires a 'socket' path")
        dir_mode = _parse_mode_value(
            view.get("socket_dir_mode", DEFAULT_SOCKET_DIR_MODE),
            field="socket_dir_mode",
            where="listener",
        )
        socket_mode = _parse_mode_value(
            view.get("socket_mode", DEFAULT_SOCKET_MODE),
            field="socket_mode",
            where="listener",
        )
        _prepare_unix_socket(path, dir_mode)
        old_umask = os.umask(0o177)
        try:
            server = ThreadedUnixServer(path, ClipboardHandler)
        finally:
            os.umask(old_umask)
        _chmod(path, socket_mode)
        _assert_owner_only(path, socket_mode, "socket")
        server.cb_socket_path = path
        server.cb_bound_ino = os.lstat(path).st_ino
        description = f"unix:{path}"
    elif transport == "vsock":
        if ThreadedVsockServer is None:
            raise ConfigError("VSOCK is not supported on this platform")
        cid = view.get("cid", DEFAULT_CID)
        port = view.get("port", DEFAULT_PORT)
        server = ThreadedVsockServer((cid, port), ClipboardHandler)
        description = f"vsock:{cid}:{port}"
    else:
        host = view.get("host", DEFAULT_BIND)
        port = view.get("port", DEFAULT_PORT)
        server = ThreadedTCPServer((host, port), ClipboardHandler)
        description = f"tcp:{host}:{port}"

    _configure_server(
        server,
        view,
        ssl_context,
        max_connections=max_connections,
        read_timeout=read_timeout,
        handshake_timeout=handshake_timeout,
    )
    return server, description


def _close_server(server) -> None:
    """Stop (if serving) and release one bound listener."""
    if getattr(server, "_cb_serving", False):
        with contextlib.suppress(Exception):
            server.shutdown()
    with contextlib.suppress(Exception):
        server.server_close()
    with contextlib.suppress(Exception):
        _unlink_bound_socket(server)


# --- Client Functions ---


def resolve_default_gateway() -> str:
    """Read the default IPv4 gateway from /proc/net/route.

    Guests behind macOS's QEMU vmnet-shared get a DHCP-assigned subnet that
    isn't known at config-generation time. The host is always reachable at
    that subnet's gateway, so resolving it at connect time is the only way a
    static guest config can keep working across reboots/subnet changes. Used
    when the client config sets host = "_gateway".
    """
    with open("/proc/net/route") as f:
        next(f)  # header line
        for line in f:
            fields = line.split()
            if len(fields) < 3:
                continue
            _iface, dest, gateway = fields[0], fields[1], fields[2]
            if dest == "00000000":
                return socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
    raise RuntimeError("no default gateway found in /proc/net/route")


def get_connection_info(config: dict):
    """Resolve connection target from TOML config only.

    A ``unix`` client must name a socket: silently dialing TCP would connect a
    typo'd admin config to an unrelated transport and bypass the intended
    same-user Unix boundary.
    """
    transport = config.get("transport")
    if transport == "unix":
        sock = config.get("socket")
        if not sock:
            raise ConfigError(
                "a unix client requires a non-empty 'socket' path"
            )
        return ("unix", sock)
    elif transport == "vsock":
        cid = config.get("cid", DEFAULT_CID)
        port = config.get("port", DEFAULT_PORT)
        return ("vsock", (cid, port))
    elif transport == "tcp":
        host = config.get("host", DEFAULT_CONNECT_HOST)
        if host == "_gateway":
            host = resolve_default_gateway()
        port = config.get("port", DEFAULT_PORT)
        return ("tcp", (host, port))

    return ("tcp", (DEFAULT_CONNECT_HOST, DEFAULT_PORT))


def _connect(conn_type, address, timeout=None):
    """Create and connect a raw socket under a bounded connect timeout."""
    if conn_type == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    elif conn_type == "vsock":
        if not hasattr(socket, "AF_VSOCK"):
            raise OSError("VSOCK not supported on this platform")
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout is None:
        timeout = DEFAULT_CONNECT_TIMEOUT
    sock.settimeout(timeout)
    try:
        sock.connect(address)
    except BaseException:
        with contextlib.suppress(OSError):
            sock.close()
        raise
    return sock


def _wrap_ssl(sock, config: dict, conn_type: str, host: str):
    """Wrap a connected socket in TLS and enforce peer OID and ``[acl]``.

    TLS is applied whenever the resolved ``transport_encryption`` is ``mtls``,
    including over Unix. The handshake is bounded by ``handshake_timeout``.
    """
    try:
        security = resolve_listener_security(config)
    except ConfigError as error:
        raise ConnectionError(str(error)) from error
    if security["transport_encryption"] != "mtls":
        return sock

    ssl_context = create_ssl_context(config, server=False)
    if ssl_context is None:
        return sock
    handshake_timeout = _positive_float(
        config.get("handshake_timeout"), DEFAULT_HANDSHAKE_TIMEOUT
    )
    with contextlib.suppress(OSError):
        sock.settimeout(handshake_timeout)
    server_hostname = host if conn_type == "tcp" else None
    try:
        sock = ssl_context.wrap_socket(
            sock, server_hostname=server_hostname
        )
        _verify_peer_oid(sock, config, "Server")
        verify_server_acl(sock, config)
    except BaseException:
        with contextlib.suppress(OSError):
            sock.close()
        raise
    return sock


def _recv_timeout(config: dict) -> float:
    return _positive_float(config.get("recv_timeout"), DEFAULT_RECV_TIMEOUT)


def send_request(conn_type, address, request, config: dict):
    t0 = time.monotonic()
    sock = _connect(
        conn_type,
        address,
        _positive_float(
            config.get("connect_timeout"), DEFAULT_CONNECT_TIMEOUT
        ),
    )
    t1 = time.monotonic()
    host = address[0] if isinstance(address, tuple) else address
    try:
        sock = _wrap_ssl(sock, config, conn_type, host)
        t2 = time.monotonic()
        sock.settimeout(_recv_timeout(config))
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

        response_data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"\n" in response_data:
                    break
        except ConnectionResetError:
            pass  # Server closed connection; we may still have valid data

        if not response_data:
            raise ConnectionError("Server closed connection without response")

        t3 = time.monotonic()
        _debug(
            f"send_request: connect={_ms(t1 - t0)} tls={_ms(t2 - t1)} "
            f"roundtrip={_ms(t3 - t2)} total={_ms(t3 - t0)}"
        )
        return json.loads(response_data.decode("utf-8"))
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def _proxy_connection_config(config: dict) -> dict:
    """Config for the local plaintext leg to the connection-reuse proxy."""
    return {
        "transport": "unix",
        "security": {
            "transport_encryption": "none",
            "client_auth": "none",
            "server_auth": "none",
        },
        "recv_timeout": config.get("recv_timeout", DEFAULT_RECV_TIMEOUT),
        "debug": config.get("debug", False),
    }


def send_admin_request(request: dict, config: dict, conn_type, address) -> dict:
    """Send an admin/CLI request, preferring a running local proxy."""
    proxy_socket = config.get("proxy_socket")
    if proxy_socket:
        try:
            response = send_request(
                "unix", proxy_socket, request, _proxy_connection_config(config)
            )
            if response.get("status") != "proxy_unavailable":
                return response
            _debug(
                f"proxy reports its remote connection is down "
                f"({response.get('message')}); falling back to direct "
                "connection"
            )
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            _debug(
                f"proxy socket {proxy_socket} unavailable ({e}); "
                "falling back to direct connection"
            )
    return send_request(conn_type, address, request, config)


class PersistentConnection:
    """A single persistent connection, reused across many requests.

    Reconnects once transparently on failure. Only one request is ever in
    flight at a time -- this JSON-line protocol carries no request ID to
    demultiplex concurrent ones -- enforced by ``lock``.
    """

    def __init__(self, conn_type: str, address, config: dict):
        self.conn_type = conn_type
        self.address = address
        self.config = config
        self.lock = threading.Lock()
        self.sock = None
        self._connect_count = 0

    def _connect(self):
        self._connect_count += 1
        t0 = time.monotonic()
        sock = _connect(
            self.conn_type,
            self.address,
            _positive_float(
                self.config.get("connect_timeout"), DEFAULT_CONNECT_TIMEOUT
            ),
        )
        t1 = time.monotonic()
        host = (
            self.address[0]
            if isinstance(self.address, tuple)
            else self.address
        )
        sock = _wrap_ssl(sock, self.config, self.conn_type, host)
        sock.settimeout(_recv_timeout(self.config))
        t2 = time.monotonic()
        _debug(
            f"PersistentConnection: connect={_ms(t1 - t0)} "
            f"tls={_ms(t2 - t1)}"
        )
        if self._connect_count > 1:
            print(
                f"clipboard-bridge: PersistentConnection reconnected to "
                f"{self.address} (connect #{self._connect_count}) -- reuse "
                "is not actually happening",
                file=sys.stderr,
            )
        return sock

    def ensure_connected(self) -> None:
        """Connect now, so the handshake is already warm before the first
        real request arrives."""
        with self.lock:
            if self.sock is None:
                try:
                    self.sock = self._connect()
                except Exception as e:
                    print(
                        f"clipboard-bridge: initial connection failed ({e}); "
                        "will retry on first request",
                        file=sys.stderr,
                    )

    def request(self, request: dict) -> dict:
        with self.lock:
            last_error = None
            for _attempt in range(2):
                if self.sock is None:
                    try:
                        self.sock = self._connect()
                    except Exception as e:
                        last_error = e
                        break
                try:
                    t0 = time.monotonic()
                    self.sock.sendall(
                        (json.dumps(request) + "\n").encode("utf-8")
                    )
                    data = b""
                    while b"\n" not in data:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            raise ConnectionError(
                                "remote closed the connection"
                            )
                        data += chunk
                    _debug(
                        f"PersistentConnection: roundtrip="
                        f"{_ms(time.monotonic() - t0)}"
                    )
                    return json.loads(data.decode("utf-8"))
                except Exception as e:
                    last_error = e
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                    self.sock = None
            raise ConnectionError(f"request failed: {last_error}")

    def close(self) -> None:
        with self.lock:
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None


# --- Clipboard System Integration ---


def get_wayland_env():
    """Return a dict with WAYLAND_DISPLAY if present in the environment."""
    env = {}
    display = os.environ.get("WAYLAND_DISPLAY")
    if display:
        env["WAYLAND_DISPLAY"] = display
    return env


def get_system_clipboard(env=None):
    plat = sys.platform
    if plat == "darwin":
        try:
            result = subprocess.run(
                ["pbpaste"],
                capture_output=True,
                check=True,
                env={**os.environ, **(env or {})},
            )
            return result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return b""
    else:
        if env is None:
            env = get_wayland_env()
        try:
            result = subprocess.run(
                ["wl-paste", "--no-newline"],
                capture_output=True,
                check=True,
                env={**os.environ, **env},
            )
            return result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return b""


def set_system_clipboard(data, env=None):
    plat = sys.platform
    if plat == "darwin":
        try:
            subprocess.run(
                ["pbcopy"],
                input=data,
                check=True,
                env={**os.environ, **(env or {})},
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    else:
        if env is None:
            env = get_wayland_env()
        try:
            subprocess.run(
                ["wl-copy"],
                input=data,
                check=True,
                env={**os.environ, **env},
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


# --- Command Implementations ---


def cmd_serve(args):
    global no_notify
    no_notify = args.no_notify
    config = load_config(args.config, "server")
    set_debug(config)
    # A server config must produce at least one listener; load_config already
    # rejects a document without [[listeners]], and listener_views re-checks.
    views = listener_views(config)
    rules = parse_rules(config.get("rule"))
    for view in views:
        view["_rules"] = rules

    servers = []
    descriptions = []
    try:
        for view in views:
            server, description = _bind_listener(view)
            servers.append(server)
            descriptions.append((description, bool(view.get("_admin"))))
    except BaseException as error:
        # Bind every listener before serving any of them, so a failure never
        # leaves a half-configured server running.
        for server in servers:
            _close_server(server)
        if isinstance(error, (ConfigError, OSError, RuntimeError)):
            print(f"clipboard-bridge server: {error}", file=sys.stderr)
            sys.exit(1)
        raise

    for description, is_admin in descriptions:
        print(
            f"Clipboard server listening on {description} "
            f"(admin={is_admin})"
        )

    try:

        def expiry_loop():
            while True:
                time.sleep(60)
                expire_clients()

        threading.Thread(target=expiry_loop, daemon=True).start()

        threads = []
        for server in servers:
            thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            threads.append((thread, server))

        try:
            for thread, _server in threads:
                thread.start()
            for _thread, server in threads:
                server._cb_serving = True
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            for server in servers:
                _close_server(server)
    except BaseException:
        for server in servers:
            _close_server(server)
        raise


def cmd_pull(args):
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)
    data = None
    stdout_piped = not sys.stdout.isatty() or getattr(args, "stdout", False)

    try:
        request = {"action": "get"}
        if args.json:
            request["json"] = True
        if args.target:
            request["target"] = args.target

        response = send_admin_request(request, config, conn_type, address)
        if response.get("status") == "ok":
            data = response.get("data", "")
        else:
            print(
                f"Error: {response.get('message', 'Unknown error')}",
                file=sys.stderr,
            )
            sys.exit(1)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        if stdout_piped:
            print(
                f"Error: Failed to connect to clipboard bridge server: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

    if data is None:
        data = get_system_clipboard()
        if data is None:
            if stdout_piped:
                print(
                    "Error: No clipboard data available and wl-clipboard is "
                    "not installed.",
                    file=sys.stderr,
                )
                sys.exit(1)
            data = b""

    if args.json:
        if isinstance(data, dict):
            if args.decode:
                decoded_data = {}
                for cid, info in data.items():
                    decoded_data[cid] = dict(info)
                    try:
                        decoded_data[cid]["data"] = base64.b64decode(
                            info["data"]
                        ).decode("utf-8", errors="replace")
                    except Exception:
                        decoded_data[cid]["data"] = info["data"]
                print(json.dumps(decoded_data, indent=2))
            else:
                print(json.dumps(data, indent=2))
        else:
            print(data)
    else:
        try:
            decoded = base64.b64decode(data)
        except Exception:
            decoded = data.encode("utf-8") if isinstance(data, str) else data
        if args.stdout or stdout_piped:
            sys.stdout.buffer.write(decoded)
        else:
            set_system_clipboard(decoded)


def cmd_push(args):
    config = load_config(args.config, "client")
    set_debug(config)
    stdin_piped = not sys.stdin.isatty()

    if args.content:
        content = args.content.encode("utf-8")
    elif stdin_piped:
        content = sys.stdin.buffer.read()
    else:
        content = get_system_clipboard()
        if content is None:
            print(
                "Error: No content provided and wl-clipboard is not "
                "available.",
                file=sys.stderr,
            )
            sys.exit(1)

    encoded = base64.b64encode(content).decode("ascii")
    conn_type, address = get_connection_info(config)

    try:
        request = {"action": "set", "data": encoded}
        if args.target:
            request["target"] = args.target

        response = send_admin_request(request, config, conn_type, address)
        if response.get("status") != "ok":
            print(
                f"Error: {response.get('message', 'Unknown error')}",
                file=sys.stderr,
            )
            sys.exit(1)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        if stdin_piped:
            print(
                f"Error: Failed to connect to clipboard bridge server: {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        set_system_clipboard(content)


def cmd_clients(args):
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)

    try:
        response = send_admin_request(
            {"action": "clients"}, config, conn_type, address
        )
        if response.get("status") == "ok":
            print(json.dumps(response.get("data", [])))
        else:
            print(
                f"Error: {response.get('message', 'Unknown error')}",
                file=sys.stderr,
            )
            sys.exit(1)
    except ConnectionRefusedError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ConnectionError:
        print(
            "Error: Server closed connection. Is the server running and "
            "reachable?",
            file=sys.stderr,
        )
        sys.exit(1)
    except (FileNotFoundError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_register(args):
    """Register with the clipboard bridge server (for VM systemd startup)."""
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)
    try:
        response = send_admin_request(
            {"action": "register"}, config, conn_type, address
        )
        if response.get("status") == "ok":
            print("Registered with clipboard bridge server")
        else:
            print(
                f"Error: {response.get('message', 'Unknown error')}",
                file=sys.stderr,
            )
            sys.exit(1)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(
            f"Error: Failed to connect to clipboard bridge server: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


# --- Argument Parser ---


def _uses_admin_config(args) -> bool:
    """Return whether ``args`` addresses the admin listener."""
    if args.command == "clients":
        return True
    return args.command in ("push", "pull") and bool(
        getattr(args, "target", None) or getattr(args, "json", False)
    )


def resolve_default_config(args) -> str:
    """Select the config file for ``args`` when ``--config`` was not given.

    Admin commands prefer ``admin.toml``; every other client command prefers
    ``client.toml``; ``serve`` always uses ``server.toml``. The other client
    file is the fallback, so the host's admin commands and a guest's client
    commands work without spelling out ``--config`` in either place.
    """
    if args.command == "serve":
        return DEFAULT_SERVER_CONFIG_PATH
    preferred, fallback = (
        (DEFAULT_ADMIN_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH)
        if _uses_admin_config(args)
        else (DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_ADMIN_CONFIG_PATH)
    )
    for candidate in (preferred, fallback):
        if Path(candidate).expanduser().exists():
            return candidate
    return preferred


def create_parser():
    parser = argparse.ArgumentParser(
        description="Clipboard bridge for containers, VMs, and Neovim",
        epilog=f"""
Configuration:
  --config / -c PATH    Path to TOML config file (overrides the auto-default:
                        serve uses ~/.config/clipboard-bridge/server.toml;
                        admin commands (clients, --target, --json) use
                        ~/.config/clipboard-bridge/admin.toml; other client
                        commands use ~/.config/clipboard-bridge/client.toml.
                        The other client file is used when the preferred one
                        is absent, so host and guest commands work without -c.
                        A server config binds every non-empty [[listeners]]
                        entry; each listener carries its own transport,
                        [listeners.security], optional [listeners.mtls] and
                        resolution mode. A client config names one transport
                        with [security], optional [mtls] and optional [acl].

Security Notes:
  - There is no shared secret and no password. Guest listeners authenticate
    through their transport (mTLS for TCP, the private VSOCK boundary for
    VMs); the local admin listener is a same-user Unix socket.
  - Admin actions (clients, --target, --json) are accepted only on a
    listener marked admin = true, and are authorized by the ordered [[rule]]
    list (first match wins, default deny).
  - Optional mTLS with CA and EKU OID enforcement applies per listener.

Examples:
  # Start a server that binds every configured listener
  clipboard-bridge.py serve

  # VM/container push (no secret)
  echo "hello" | clipboard-bridge.py push

  # Local admin over the Unix listener (no password, no certificate)
  clipboard-bridge.py clients
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to TOML config file (defaults: serve uses "
        f"{DEFAULT_SERVER_CONFIG_PATH}, admin commands use "
        f"{DEFAULT_ADMIN_CONFIG_PATH}, other client commands use "
        f"{DEFAULT_CLIENT_CONFIG_PATH}; the other client file is the "
        "fallback).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser(
        "serve", help="Start clipboard server"
    )
    serve_parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Disable desktop notifications",
    )

    pull_parser = subparsers.add_parser(
        "pull",
        help="Pull from internal clipboard (copies to system clipboard by "
        "default)",
    )
    pull_parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of system clipboard",
    )
    pull_parser.add_argument(
        "-d",
        "--decode",
        action="store_true",
        help="Decode base64 data (auto-enabled for stdout)",
    )
    pull_parser.add_argument(
        "--json",
        action="store_true",
        help="Return all client clipboards as JSON (admin listener only)",
    )
    pull_parser.add_argument(
        "--target",
        help="Target client ID (admin listener only, required with --json "
        "instead)",
    )

    push_parser = subparsers.add_parser(
        "push",
        help="Push content to internal clipboard (reads from stdin if piped)",
    )
    push_parser.add_argument(
        "content",
        nargs="?",
        help="Content to push (default: stdin or system clipboard)",
    )
    push_parser.add_argument(
        "--target",
        help="Target client ID (admin listener only)",
    )

    subparsers.add_parser(
        "clients", help="List connected clients (admin listener only)"
    )

    subparsers.add_parser(
        "register",
        help="Register with the clipboard bridge server (VM startup)",
    )

    client_parser = subparsers.add_parser(
        "client",
        help="Run a clipboard client daemon (subscribe + publish loop for VMs)",
    )
    client_parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval for local clipboard changes in seconds "
        "(default: 1.0)",
    )

    subparsers.add_parser(
        "proxy",
        help=(
            "Run a local connection-reuse proxy: holds one persistent, "
            "already-authenticated connection to the configured server and "
            "relays push/pull/clients/register requests over a local unix "
            "socket, so those CLI invocations don't each pay for a fresh "
            "connect + TLS handshake"
        ),
    )

    return parser


def cmd_client(args):
    """Run as a persistent client daemon in a VM.

    1. Connects to server and subscribes for push notifications.
    2. In a background thread, monitors local clipboard and pushes changes.
    3. When server pushes data, applies it to local wayland clipboard.
    """
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)
    wayland_env = get_wayland_env()
    host = address[0] if isinstance(address, tuple) else address
    push_conn = PersistentConnection(conn_type, address, config)

    # --- Register with the server so we appear in the clients list ---
    try:
        reg_resp = send_request(
            conn_type, address, {"action": "register"}, config
        )
        if reg_resp.get("status") == "ok":
            print("Registered with clipboard bridge server", file=sys.stderr)
        else:
            print(
                f"Registration warning: "
                f"{reg_resp.get('message', 'unknown error')}",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)

    # Shared mutable state so subscriber updates are visible to the monitor
    # loop.
    shared_state = {"last_data": None}

    # --- One-time initial sync on startup ---
    try:
        init_response = send_request(
            conn_type, address, {"action": "get"}, config
        )
        if init_response.get("status") == "ok" and "data" in init_response:
            data_b64 = init_response["data"]
            try:
                decoded = base64.b64decode(data_b64)
            except Exception:
                decoded = (
                    data_b64.encode("utf-8")
                    if isinstance(data_b64, str)
                    else data_b64
                )
            set_system_clipboard(decoded, env=wayland_env)
            shared_state["last_data"] = decoded
            print("Initial sync from server", file=sys.stderr)
    except Exception as e:
        print(f"Initial sync failed: {e}", file=sys.stderr)

    def run_subscriber():
        """Maintain a subscribe connection to receive server pushes."""
        while True:
            sock = None
            try:
                sock = _connect(conn_type, address)
                sock = _wrap_ssl(sock, config, conn_type, host)
                # A subscriber is idle between pushes: block rather than
                # reconnect every recv_timeout.
                sock.settimeout(None)

                sock.sendall(
                    (json.dumps({"action": "subscribe"}) + "\n").encode(
                        "utf-8"
                    )
                )

                # Skip the subscribe confirmation line before treating
                # subsequent lines as data pushes.
                confirm = b""
                while b"\n" not in confirm:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    confirm += chunk
                if not confirm:
                    print(
                        "Subscriber: server closed before confirmation",
                        file=sys.stderr,
                    )
                    time.sleep(5)
                    continue

                while True:
                    response_data = b""
                    while b"\n" not in response_data:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk

                    if not response_data:
                        break

                    for line in response_data.split(b"\n"):
                        if not line:
                            continue
                        try:
                            response = json.loads(line.decode("utf-8"))
                            if (
                                response.get("status") == "ok"
                                and "data" in response
                            ):
                                data_b64 = response["data"]
                                try:
                                    decoded = base64.b64decode(data_b64)
                                except Exception:
                                    decoded = (
                                        data_b64.encode("utf-8")
                                        if isinstance(data_b64, str)
                                        else data_b64
                                    )
                                set_system_clipboard(
                                    decoded, env=wayland_env
                                )
                                shared_state["last_data"] = decoded
                                print(
                                    "Clipboard updated from server",
                                    file=sys.stderr,
                                )
                        except json.JSONDecodeError:
                            pass
            except (
                ConnectionRefusedError,
                FileNotFoundError,
                OSError,
                ConnectionResetError,
            ) as e:
                print(
                    f"Subscriber connection lost: {e}. Reconnecting in 5s...",
                    file=sys.stderr,
                )
                time.sleep(5)
                continue
            except Exception as e:
                print(
                    f"Subscriber error: {e}. Reconnecting in 5s...",
                    file=sys.stderr,
                )
                time.sleep(5)
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

            # If we exited the inner while normally (server closed cleanly),
            # also wait before reconnecting to avoid a tight loop.
            print(
                "Subscriber closed cleanly. Reconnecting in 5s...",
                file=sys.stderr,
            )
            time.sleep(5)

    subscriber_thread = threading.Thread(
        target=run_subscriber, daemon=True
    )
    subscriber_thread.start()

    # Local clipboard monitor loop
    while True:
        try:
            current = get_system_clipboard(env=wayland_env)
            # Skip empty reads: a missing or empty local clipboard must not
            # overwrite the server's stored data (especially on first
            # iteration, before the clipboard has ever been set).
            if current and current != shared_state["last_data"]:
                encoded = base64.b64encode(current).decode("ascii")
                try:
                    push_conn.request({"action": "set", "data": encoded})
                    print("Pushed local clipboard to server", file=sys.stderr)
                except Exception as e:
                    print(f"Push failed: {e}", file=sys.stderr)
                shared_state["last_data"] = current
        except Exception as e:
            print(f"Clipboard monitor error: {e}", file=sys.stderr)

        time.sleep(args.interval)


def cmd_proxy(args):
    """Run a local connection-reuse proxy (see PersistentConnection).

    Holds one persistent, already-authenticated connection to the configured
    server, and relays requests from local unix-socket clients over it so they
    don't each pay for a fresh connect + TLS handshake.
    """
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)

    listen_path = expand_socket_path(
        config.get("proxy_socket") or DEFAULT_PROXY_SOCKET
    )
    listen = Path(listen_path)
    listen.parent.mkdir(parents=True, exist_ok=True)
    if listen.exists():
        listen.unlink()

    remote = PersistentConnection(conn_type, address, config)
    remote.ensure_connected()

    # A headless guest has no `client` daemon (that one needs a Wayland
    # clipboard), so its proxy is the only connection the server ever sees.
    # Register it, and keep re-registering well inside the server's 5-minute
    # expiry window, so `clients` (and the host's target picker) can address
    # the guest even before it has pushed anything.
    if config.get("register"):

        def register_loop():
            while True:
                try:
                    remote.request({"action": "register"})
                except Exception as e:
                    _debug(f"proxy register failed: {e}")
                time.sleep(60)

        threading.Thread(target=register_loop, daemon=True).start()

    class ProxyHandler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except Exception as e:
                    response = {
                        "status": "error",
                        "message": f"Invalid request: {e}",
                    }
                else:
                    try:
                        response = remote.request(request)
                    except Exception as e:
                        # The persistent connection's own reconnect-once
                        # retry already failed -- the remote is genuinely
                        # down (e.g. mid-restart), not a bad request. Tell
                        # the caller to retry directly instead of surfacing
                        # a raw error.
                        response = {
                            "status": "proxy_unavailable",
                            "message": str(e),
                        }
                self.wfile.write(
                    (json.dumps(response) + "\n").encode("utf-8")
                )
                self.wfile.flush()

    # Restrict the socket's permissions from the moment it's created, so
    # there's no window where it's reachable by anything other than us.
    old_umask = os.umask(0o177)
    try:
        server = ThreadedUnixServer(str(listen), ProxyHandler)
    finally:
        os.umask(old_umask)

    print(
        f"clipboard-bridge proxy listening on unix:{listen} -> "
        f"{conn_type}:{address}"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.shutdown()
        remote.close()
        if listen.exists():
            listen.unlink()


def main():
    parser = create_parser()
    args = parser.parse_args()
    if args.config is None:
        args.config = resolve_default_config(args)

    try:
        if args.command == "serve":
            cmd_serve(args)
        elif args.command == "pull":
            cmd_pull(args)
        elif args.command == "push":
            cmd_push(args)
        elif args.command == "clients":
            cmd_clients(args)
        elif args.command == "register":
            cmd_register(args)
        elif args.command == "client":
            cmd_client(args)
        elif args.command == "proxy":
            cmd_proxy(args)
    except ConfigError as error:
        print(f"clipboard-bridge: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Executable contract for the clipboard-bridge configuration and policy layer.

This suite pins the target design in
``docs/technical/design/clipboard-bridge-parity.md``:

* a server process owns one or more self-contained ``[[listeners]]`` entries
  (VSOCK, TCP or Unix), each with its own bind target, security, ``[mtls]``
  material, resolution mode and bounds;
* a listener's ``security.transport_encryption = "auto"`` resolves per
  transport (TCP -> mTLS, VSOCK/Unix -> none), and plaintext never disables
  authentication implicitly;
* admin access is a listener role (``admin = true``), authorized by the
  ordered ``[[rule]]`` engine -- there is no shared secret and no password;
* the client can pin the server it trusts through ``[acl]``.

The module is a standalone script rather than an importable package module, so
it is loaded by path with ``importlib``; importing it has no side effects.
These tests were written before the Phase 1 implementation (TDD) and are
expected to fail until that implementation lands.

Run from the package root::

    python -m pytest tests/test_clipboard_bridge.py -v
"""

from __future__ import annotations

import base64
import dataclasses
import importlib.util
import json
import textwrap
import types
from pathlib import Path

import pytest

SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "clipboard-bridge"
    / "clipboard-bridge.py"
)

# OIDs used by the design's certificate layouts. ADMIN_OID is the dedicated
# admin EKU OID; SERVER_OID / GUEST_OID are ordinary service identities.
ADMIN_OID = "1.3.6.1.4.1.99999.3.3"
SERVER_OID = "1.3.6.1.4.1.99999.3.1"
GUEST_OID = "1.3.6.1.4.1.99999.3.2"
OTHER_ADMIN_OID = "1.3.6.1.4.1.99999.3.4"


@pytest.fixture(scope="session")
def cb() -> types.ModuleType:
    """Load the standalone ``clipboard-bridge.py`` script as a module."""
    spec = importlib.util.spec_from_file_location(
        "clipboard_bridge_under_test", SOURCE_PATH
    )
    assert spec is not None and spec.loader is not None, f"cannot load {SOURCE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- config fixtures -------------------------------------------------------


def _write_config(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _server_toml(
    *,
    mode: str = "server",
    extra_top_level: str = "",
    socket: str = "%t/clipboard-admin.sock",
) -> str:
    """A minimal valid server document with room for one offending top key.

    Every documented top-level server key is exercised here (``debug``,
    ``vm``, ``tcp_vm``, ``listeners``, ``rule``) so the negative tests below
    fail on the injected key, not on an unrelated schema gap.
    """
    lines = [f'mode = "{mode}"', "debug = true"]
    if extra_top_level:
        lines.append(extra_top_level)
    lines += [
        "",
        "[[vm]]",
        "cid = 7",
        'name = "dev"',
        "",
        "[[tcp_vm]]",
        'ip = "10.201.0.10"',
        'name = "notes"',
        "",
        "[[listeners]]",
        'type = "unix"',
        'name = "admin"',
        f'socket = "{socket}"',
        "admin = true",
        'resolution = "none"',
        "",
        "[listeners.security]",
        'transport_encryption = "none"',
        'client_auth = "none"',
        'server_auth = "none"',
        "",
        "[[rule]]",
        'match.listeners = ["admin"]',
        'policy = "allow"',
    ]
    return "\n".join(lines) + "\n"


def _client_toml(*, mode: str = "client", extra_top_level: str = "") -> str:
    """A minimal valid client document with room for one offending top key."""
    lines = [
        f'mode = "{mode}"',
        'transport = "unix"',
        'socket = "/tmp/clipboard.sock"',
        "cid = 2",
        "connect_timeout = 5",
        "handshake_timeout = 10",
        "recv_timeout = 30",
        "register = true",
        'proxy_socket = "/tmp/clipboard-proxy.sock"',
        "debug = true",
    ]
    if extra_top_level:
        lines.append(extra_top_level)
    lines += [
        "",
        "[security]",
        'transport_encryption = "none"',
        'client_auth = "none"',
        'server_auth = "none"',
    ]
    return "\n".join(lines) + "\n"


# --- listener fixtures -----------------------------------------------------


def _none_security() -> dict:
    return {
        "transport_encryption": "none",
        "client_auth": "none",
        "server_auth": "none",
    }


def _mtls_security() -> dict:
    return {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }


def _mtls_block(peer_required_oid: str = GUEST_OID) -> dict:
    return {
        "enable": True,
        "ca_file": "/run/clipboard/ca.crt",
        "cert_file": "/run/clipboard/server.crt",
        "key_file": "/run/clipboard/server.key",
        "required_oid": SERVER_OID,
        "peer_required_oid": peer_required_oid,
    }


def _unix_listener(**overrides) -> dict:
    entry = {
        "type": "unix",
        "name": "admin",
        "socket": "%t/clipboard-admin.sock",
        "resolution": "none",
        "security": _none_security(),
    }
    entry.update(overrides)
    return entry


def _vsock_listener(**overrides) -> dict:
    entry = {
        "type": "vsock",
        "name": "tartarus-vsock",
        "cid": 2,
        "port": 27795,
        "resolution": "none",
        "security": _none_security(),
    }
    entry.update(overrides)
    return entry


def _tcp_mtls_listener(**overrides) -> dict:
    entry = {
        "type": "tcp",
        "name": "tartarus-tcp",
        "host": "10.201.0.1",
        "port": 27795,
        "resolution": "certificate",
        "security": _mtls_security(),
        "mtls": _mtls_block(),
    }
    entry.update(overrides)
    return entry


def _admin_mtls_listener(peer_required_oid: str) -> dict:
    return _tcp_mtls_listener(
        name="admin-tls",
        host="127.0.0.1",
        port=27796,
        admin=True,
        mtls=_mtls_block(peer_required_oid),
    )


def _sha256_fingerprint(byte: bytes = b"\x42") -> str:
    """A padded ``SHA256:<base64>`` fingerprint for exactly 32 bytes."""
    return "SHA256:" + base64.b64encode(byte * 32).decode("ascii")


# --- module surface --------------------------------------------------------


def test_config_error_is_a_value_error(cb: types.ModuleType) -> None:
    assert issubclass(cb.ConfigError, ValueError)


def test_admin_oid_constant(cb: types.ModuleType) -> None:
    assert cb.ADMIN_OID == ADMIN_OID


@pytest.mark.parametrize(
    "symbol", ["generate_secret", "get_client_secret", "check_admin"]
)
def test_removed_secret_and_admin_helpers_are_gone(
    cb: types.ModuleType, symbol: str
) -> None:
    assert not hasattr(cb, symbol), (
        f"{symbol} must not exist: clipboard-bridge has no shared secret and "
        "authorizes admin access through listeners and rules"
    )


# --- load_config: server schema -------------------------------------------


def test_server_accepts_the_documented_listener_config(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    path = _write_config(tmp_path, "server.toml", _server_toml())

    config = cb.load_config(str(path), "server")

    assert config["mode"] == "server"
    assert isinstance(config["listeners"], list)
    assert len(config["listeners"]) == 1
    assert config["listeners"][0]["type"] == "unix"


@pytest.mark.parametrize(
    "body",
    [
        'mode = "server"\n',
        'mode = "server"\nlisteners = []\n',
        (
            'mode = "server"\n'
            'transport = "tcp"\n'
            'host = "10.201.0.1"\n'
            "port = 27795\n"
        ),
    ],
)
def test_server_requires_a_non_empty_listeners_array(
    cb: types.ModuleType, tmp_path: Path, body: str
) -> None:
    path = _write_config(tmp_path, "server.toml", body)

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "server")


@pytest.mark.parametrize(
    "snippet",
    [
        'transport = "tcp"',
        'host = "10.201.0.1"',
        "port = 27795",
        'secret = "shared"',
        'secret_file = "/run/secrets/clipboard-bridge"',
        'admin_socket = "/tmp/clipboard-admin.sock"',
        "mtls = { enable = true }",
        'resolution = "certificate"',
        "bogus_setting = 1",
    ],
)
def test_server_rejects_removed_legacy_and_unknown_top_level_keys(
    cb: types.ModuleType, tmp_path: Path, snippet: str
) -> None:
    path = _write_config(
        tmp_path, "server.toml", _server_toml(extra_top_level=snippet)
    )

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "server")


def test_server_rejects_client_mode(cb: types.ModuleType, tmp_path: Path) -> None:
    path = _write_config(tmp_path, "server.toml", _server_toml(mode="client"))

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "server")


# --- load_config: client schema -------------------------------------------


def test_client_accepts_the_documented_keys(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    path = _write_config(tmp_path, "client.toml", _client_toml())

    config = cb.load_config(str(path), "client")

    assert config["mode"] == "client"
    assert config["transport"] == "unix"


@pytest.mark.parametrize(
    "snippet",
    [
        'secret = "shared"',
        'secret_file = "/run/secrets/clipboard-bridge"',
        'admin_socket = "/tmp/clipboard-admin.sock"',
        "bogus_setting = 1",
    ],
)
def test_client_rejects_removed_and_unknown_keys(
    cb: types.ModuleType, tmp_path: Path, snippet: str
) -> None:
    path = _write_config(
        tmp_path, "client.toml", _client_toml(extra_top_level=snippet)
    )

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "client")


def test_client_rejects_server_mode(cb: types.ModuleType, tmp_path: Path) -> None:
    path = _write_config(tmp_path, "client.toml", _client_toml(mode="server"))

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "client")


# --- load_config: mTLS path resolution ------------------------------------


def test_listener_mtls_paths_resolve_against_the_config_directory(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    certs = tmp_path / "certs"
    certs.mkdir()
    body = textwrap.dedent(
        """
        mode = "server"

        [[listeners]]
        type = "tcp"
        name = "notes"
        host = "10.201.0.1"
        port = 27795
        resolution = "certificate"

        [listeners.security]
        transport_encryption = "mtls"
        client_auth = "transport"
        server_auth = "transport"

        [listeners.mtls]
        enable = true
        ca_file = "certs/ca.crt"
        cert_file = "certs/server.crt"
        key_file = "certs/server.key"
        required_oid = "1.3.6.1.4.1.99999.3.1"
        peer_required_oid = "1.3.6.1.4.1.99999.3.2"
        """
    )
    path = _write_config(tmp_path, "server.toml", body)

    config = cb.load_config(str(path), "server")

    mtls = config["listeners"][0]["mtls"]
    assert Path(mtls["ca_file"]).resolve() == (certs / "ca.crt").resolve()
    assert Path(mtls["cert_file"]).resolve() == (certs / "server.crt").resolve()
    assert Path(mtls["key_file"]).resolve() == (certs / "server.key").resolve()


def test_document_mtls_paths_resolve_against_the_config_directory(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    certs = tmp_path / "certs"
    certs.mkdir()
    body = textwrap.dedent(
        """
        mode = "client"
        transport = "tcp"
        host = "10.201.0.1"
        port = 27795

        [security]
        transport_encryption = "mtls"
        client_auth = "transport"
        server_auth = "transport"

        [mtls]
        enable = true
        ca_file = "certs/ca.crt"
        cert_file = "certs/client.crt"
        key_file = "certs/client.key"
        """
    )
    path = _write_config(tmp_path, "client.toml", body)

    config = cb.load_config(str(path), "client")

    assert Path(config["mtls"]["ca_file"]).resolve() == (certs / "ca.crt").resolve()
    assert (
        Path(config["mtls"]["cert_file"]).resolve()
        == (certs / "client.crt").resolve()
    )
    assert (
        Path(config["mtls"]["key_file"]).resolve() == (certs / "client.key").resolve()
    )


# --- listener_views --------------------------------------------------------


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"mode": "server"},
        {"listeners": []},
        {"listeners": "tcp"},
        {
            "mode": "server",
            "transport": "tcp",
            "host": "10.201.0.1",
            "port": 27795,
        },
    ],
)
def test_listener_views_requires_a_non_empty_listeners_array(
    cb: types.ModuleType, config: dict
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.listener_views(config)


def test_listener_views_expands_self_contained_listeners(
    cb: types.ModuleType,
) -> None:
    config = {
        "mode": "server",
        # Document-level values must not leak into any listener entry.
        "resolution": "certificate",
        "security": _none_security(),
        "mtls": {"enable": True},
        "debug": True,
        "listeners": [
            {
                "type": "vsock",
                "name": "tartarus-vsock",
                "cid": 2,
                "port": 27795,
                "resolution": "tartarus",
            },
            {
                "type": "tcp",
                "name": "tartarus-tcp",
                "host": "10.201.0.1",
                "port": 27795,
            },
            {
                "type": "unix",
                "name": "admin",
                "socket": "%t/clipboard-admin.sock",
                "admin": True,
                "resolution": "none",
            },
        ],
    }

    views = cb.listener_views(config)

    assert len(views) == 3
    assert [view["transport"] for view in views] == ["vsock", "tcp", "unix"]
    assert [view["_listener_index"] for view in views] == [0, 1, 2]
    assert [view["_listener_name"] for view in views] == [
        "tartarus-vsock",
        "tartarus-tcp",
        "admin",
    ]
    assert views[0]["_admin"] is False
    assert views[1]["_admin"] is False
    assert views[2]["_admin"] is True

    # Self-contained: no document-level security/mtls/resolution inheritance.
    for view in views:
        assert "security" not in view
        assert "mtls" not in view
    assert views[0]["resolution"] == "tartarus"
    assert "resolution" not in views[1]
    assert views[2]["resolution"] == "none"

    # Bind targets stay with their own entry.
    assert views[0]["cid"] == 2
    assert views[1]["host"] == "10.201.0.1"
    assert views[2]["socket"] == "%t/clipboard-admin.sock"


def test_listener_views_reports_unnamed_listener_as_none(
    cb: types.ModuleType,
) -> None:
    views = cb.listener_views({"listeners": [{"type": "vsock", "cid": 2, "port": 1}]})

    assert views[0]["_listener_name"] is None
    assert views[0]["_listener_index"] == 0
    assert views[0]["_admin"] is False


# --- per-listener security resolution -------------------------------------


def test_security_auto_tcp_resolves_to_mtls(cb: types.ModuleType) -> None:
    assert cb.resolve_listener_security({"type": "tcp"}) == _mtls_security()


def test_security_explicit_auto_tcp_resolves_to_mtls(cb: types.ModuleType) -> None:
    entry = {"type": "tcp", "security": {"transport_encryption": "auto"}}
    assert cb.resolve_listener_security(entry) == _mtls_security()


def test_security_auto_vsock_and_unix_resolve_to_none(
    cb: types.ModuleType,
) -> None:
    for transport in ("vsock", "unix"):
        entry = {
            "type": transport,
            "security": {
                "transport_encryption": "auto",
                "client_auth": "none",
                "server_auth": "none",
            },
        }
        assert cb.resolve_listener_security(entry) == _none_security()


def test_security_reads_type_then_transport_then_defaults_to_tcp(
    cb: types.ModuleType,
) -> None:
    assert cb.resolve_listener_security(
        {"transport": "vsock", "security": _none_security()}
    ) == _none_security()
    # No type/transport means tcp, which auto-resolves to mTLS.
    assert cb.resolve_listener_security({}) == _mtls_security()


@pytest.mark.parametrize(
    "security",
    [
        {"transport_encryption": "none"},
        {"transport_encryption": "none", "client_auth": "none"},
        {"transport_encryption": "none", "server_auth": "none"},
        {"client_auth": "none"},
        {"transport_encryption": "none", "client_auth": None, "server_auth": "none"},
    ],
)
def test_security_plaintext_requires_explicit_none_on_both_auth_knobs(
    cb: types.ModuleType, security: dict
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.resolve_listener_security({"type": "vsock", "security": security})


@pytest.mark.parametrize("knob", ["client_auth", "server_auth"])
def test_security_plaintext_rejects_transport_auth(
    cb: types.ModuleType, knob: str
) -> None:
    security = _none_security()
    security[knob] = "transport"

    with pytest.raises(cb.ConfigError):
        cb.resolve_listener_security({"type": "vsock", "security": security})


def test_security_mtls_forces_transport_auth(cb: types.ModuleType) -> None:
    entry = {"type": "tcp", "security": {"transport_encryption": "mtls"}}
    assert cb.resolve_listener_security(entry) == _mtls_security()


@pytest.mark.parametrize("knob", ["client_auth", "server_auth"])
def test_security_mtls_rejects_explicit_non_transport_auth(
    cb: types.ModuleType, knob: str
) -> None:
    security = {"transport_encryption": "mtls", knob: "none"}

    with pytest.raises(cb.ConfigError):
        cb.resolve_listener_security({"type": "tcp", "security": security})


@pytest.mark.parametrize("transport", ["tcp", "vsock", "unix"])
def test_security_mtls_enable_forces_mtls_on_any_transport(
    cb: types.ModuleType, transport: str
) -> None:
    entry = {"type": transport, "mtls": {"enable": True}}
    assert cb.resolve_listener_security(entry) == _mtls_security()


def test_security_mtls_enable_conflicts_with_explicit_none(
    cb: types.ModuleType,
) -> None:
    entry = {
        "type": "tcp",
        "security": _none_security(),
        "mtls": {"enable": True},
    }

    with pytest.raises(cb.ConfigError):
        cb.resolve_listener_security(entry)


@pytest.mark.parametrize(
    "security",
    [
        {"transport_encryption": "bogus"},
        {"transport_encryption": "mtls", "client_auth": "bogus"},
        {"transport_encryption": "none", "client_auth": "bogus", "server_auth": "none"},
        {"transport_encryption": "none", "client_auth": "none", "server_auth": "bogus"},
    ],
)
def test_security_rejects_unknown_values(
    cb: types.ModuleType, security: dict
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.resolve_listener_security({"type": "tcp", "security": security})


# --- validate_listener_table ----------------------------------------------


def test_valid_unix_none_listener_passes(cb: types.ModuleType) -> None:
    cb.validate_listener_table(_unix_listener(), where="listeners[0]")


def test_valid_tcp_mtls_listener_passes(cb: types.ModuleType) -> None:
    cb.validate_listener_table(_tcp_mtls_listener(), where="listeners[0]")


@pytest.mark.parametrize("key", ["bogus", "secret", "admin_socket"])
def test_listener_table_rejects_unknown_keys(
    cb: types.ModuleType, key: str
) -> None:
    entry = _unix_listener()
    entry[key] = "value"

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize("entry", ["tcp", None, ["tcp"]])
def test_listener_table_rejects_non_table_entries(
    cb: types.ModuleType, entry: object
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_listener_table_requires_type(cb: types.ModuleType) -> None:
    entry = _unix_listener()
    entry.pop("type")

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize("transport", ["http", "udp"])
def test_listener_table_rejects_unknown_type(
    cb: types.ModuleType, transport: str
) -> None:
    entry = _unix_listener(type=transport)

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_unix_listener_requires_socket(cb: types.ModuleType) -> None:
    entry = _unix_listener()
    entry.pop("socket")

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize("resolution", ["tartarus", "mofos"])
def test_unix_listener_rejects_identity_resolution(
    cb: types.ModuleType, resolution: str
) -> None:
    entry = _unix_listener(resolution=resolution)

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize("resolution", ["qemu", "bogus"])
def test_listener_rejects_unknown_resolution(
    cb: types.ModuleType, resolution: str
) -> None:
    entry = _vsock_listener(resolution=resolution)

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_mtls_listener_requires_an_mtls_block(cb: types.ModuleType) -> None:
    entry = _tcp_mtls_listener()
    entry.pop("mtls")

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_tcp_auto_mtls_requires_an_mtls_block(cb: types.ModuleType) -> None:
    entry = {
        "type": "tcp",
        "name": "notes",
        "host": "10.201.0.1",
        "port": 27795,
        "resolution": "certificate",
    }

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize(
    "field",
    [
        "enable",
        "ca_file",
        "cert_file",
        "key_file",
        "required_oid",
        "peer_required_oid",
    ],
)
def test_mtls_listener_requires_a_complete_mtls_block(
    cb: types.ModuleType, field: str
) -> None:
    entry = _tcp_mtls_listener()
    del entry["mtls"][field]

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_mtls_listener_requires_enable_true(cb: types.ModuleType) -> None:
    entry = _tcp_mtls_listener()
    entry["mtls"]["enable"] = False

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_timeout", 0),
        ("handshake_timeout", -1),
        ("max_connections", 0),
        ("server_read_timeout", -1),
    ],
)
def test_listener_rejects_non_positive_bounds(
    cb: types.ModuleType, field: str, value: int
) -> None:
    entry = _unix_listener(**{field: value})

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_listener_accepts_positive_bounds(cb: types.ModuleType) -> None:
    entry = _unix_listener(
        connect_timeout=5,
        handshake_timeout=10,
        max_connections=100,
        server_read_timeout=30,
    )
    cb.validate_listener_table(entry, where="listeners[0]")


def test_listener_accepts_octal_socket_modes(cb: types.ModuleType) -> None:
    entry = _unix_listener(socket_dir_mode="0700", socket_mode="0600")
    cb.validate_listener_table(entry, where="listeners[0]")


@pytest.mark.parametrize("field", ["socket_dir_mode", "socket_mode"])
@pytest.mark.parametrize("value", ["0800", "banana"])
def test_listener_rejects_invalid_socket_modes(
    cb: types.ModuleType, field: str, value: str
) -> None:
    entry = _unix_listener(**{field: value})

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


# --- admin listener authorization -----------------------------------------


def test_admin_mtls_listener_accepts_the_admin_peer_oid(
    cb: types.ModuleType,
) -> None:
    cb.validate_listener_table(
        _admin_mtls_listener(cb.ADMIN_OID), where="listeners[0]"
    )


@pytest.mark.parametrize("peer_oid", [GUEST_OID, OTHER_ADMIN_OID])
def test_admin_mtls_listener_rejects_other_peer_oids(
    cb: types.ModuleType, peer_oid: str
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(
            _admin_mtls_listener(peer_oid), where="listeners[0]"
        )


def test_admin_mtls_listener_requires_peer_required_oid(
    cb: types.ModuleType,
) -> None:
    entry = _admin_mtls_listener(cb.ADMIN_OID)
    del entry["mtls"]["peer_required_oid"]

    with pytest.raises(cb.ConfigError):
        cb.validate_listener_table(entry, where="listeners[0]")


def test_admin_unix_plaintext_listener_needs_no_certificate(
    cb: types.ModuleType,
) -> None:
    entry = _unix_listener(admin=True)
    cb.validate_listener_table(entry, where="listeners[0]")


# --- rule engine -----------------------------------------------------------


def test_parse_rules_normalizes_selectors_to_tuples(
    cb: types.ModuleType,
) -> None:
    rules = cb.parse_rules(
        [
            {
                "match": {
                    "machine": "dev",
                    "listeners": ["admin", "guest"],
                    "action": "get",
                    "target": "clip/*",
                },
                "policy": "allow",
            }
        ]
    )

    assert isinstance(rules, tuple)
    assert len(rules) == 1
    rule = rules[0]
    assert dataclasses.is_dataclass(rule)
    assert rule.machine == ("dev",)
    assert rule.listeners == ("admin", "guest")
    assert rule.action == ("get",)
    assert rule.target == ("clip/*",)
    assert rule.policy == "allow"


def test_parse_rules_uses_empty_selectors_when_absent(
    cb: types.ModuleType,
) -> None:
    (rule,) = cb.parse_rules([{"policy": "deny"}])

    assert (rule.machine, rule.listeners, rule.action, rule.target) == ((), (), (), ())
    assert rule.policy == "deny"


@pytest.mark.parametrize("policy", ["ask", "maybe", "ALLOW"])
def test_parse_rules_rejects_unknown_policies(
    cb: types.ModuleType, policy: str
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.parse_rules([{"policy": policy}])


def test_evaluate_rules_first_match_wins(cb: types.ModuleType) -> None:
    deny_dev_then_allow_all = cb.parse_rules(
        [
            {"match": {"machine": ["dev"]}, "policy": "deny"},
            {"match": {"machine": ["*"]}, "policy": "allow"},
        ]
    )

    assert (
        cb.evaluate_rules(
            deny_dev_then_allow_all,
            listener="admin",
            machine="dev",
            action="get",
            target="clip-1",
        )
        == "deny"
    )
    assert (
        cb.evaluate_rules(
            deny_dev_then_allow_all,
            listener="admin",
            machine="prod",
            action="get",
            target="clip-1",
        )
        == "allow"
    )

    allow_dev_then_deny_all = cb.parse_rules(
        [
            {"match": {"machine": ["dev"]}, "policy": "allow"},
            {"match": {"machine": ["*"]}, "policy": "deny"},
        ]
    )
    assert (
        cb.evaluate_rules(
            allow_dev_then_deny_all,
            listener="admin",
            machine="dev",
            action="get",
            target="clip-1",
        )
        == "allow"
    )


def test_evaluate_rules_defaults_to_deny(cb: types.ModuleType) -> None:
    assert (
        cb.evaluate_rules(
            (), listener="admin", machine="dev", action="get", target="clip-1"
        )
        == "deny"
    )

    only_prod = cb.parse_rules([{"match": {"machine": ["prod"]}, "policy": "allow"}])
    assert (
        cb.evaluate_rules(
            only_prod, listener="admin", machine="dev", action="get", target="clip-1"
        )
        == "deny"
    )


def test_machine_none_matches_only_an_empty_selector(
    cb: types.ModuleType,
) -> None:
    machine_dev = cb.parse_rules([{"match": {"machine": ["dev"]}, "policy": "allow"}])
    assert (
        cb.evaluate_rules(
            machine_dev, listener="admin", machine=None, action="get", target=None
        )
        == "deny"
    )
    assert (
        cb.evaluate_rules(
            machine_dev, listener="admin", machine="dev", action="get", target=None
        )
        == "allow"
    )

    empty_selector = cb.parse_rules(
        [{"match": {"machine": []}, "policy": "allow"}]
    )
    assert (
        cb.evaluate_rules(
            empty_selector, listener="admin", machine=None, action="get", target=None
        )
        == "allow"
    )

    no_selector = cb.parse_rules([{"policy": "allow"}])
    assert (
        cb.evaluate_rules(
            no_selector, listener="admin", machine=None, action="get", target=None
        )
        == "allow"
    )


def test_evaluate_rules_matches_listener_action_target_and_globs(
    cb: types.ModuleType,
) -> None:
    rules = cb.parse_rules(
        [
            {
                "match": {
                    "listeners": ["admin*"],
                    "action": ["get", "set"],
                    "target": ["clip-*"],
                },
                "policy": "allow",
            }
        ]
    )

    def evaluate(**overrides: object) -> str:
        kwargs = {
            "listener": "admin-unix",
            "machine": None,
            "action": "get",
            "target": "clip-1",
        }
        kwargs.update(overrides)
        return cb.evaluate_rules(rules, **kwargs)

    assert evaluate() == "allow"
    assert evaluate(listener="guest") == "deny"
    assert evaluate(action="clients") == "deny"
    assert evaluate(target="other") == "deny"


def test_evaluate_rules_treats_absent_target_as_empty_string(
    cb: types.ModuleType,
) -> None:
    wildcard = cb.parse_rules([{"match": {"target": ["*"]}, "policy": "allow"}])
    assert (
        cb.evaluate_rules(
            wildcard, listener="admin", machine=None, action="get", target=None
        )
        == "allow"
    )

    exact = cb.parse_rules([{"match": {"target": ["clip-1"]}, "policy": "allow"}])
    assert (
        cb.evaluate_rules(
            exact, listener="admin", machine=None, action="get", target=None
        )
        == "deny"
    )


# --- client ACL ------------------------------------------------------------


def test_client_acl_absent_means_no_pin(cb: types.ModuleType) -> None:
    assert cb.load_client_acl({}) == (frozenset(), ())


def test_client_acl_fingerprints_are_normalized(cb: types.ModuleType) -> None:
    padded = _sha256_fingerprint()
    assert padded.endswith("=")
    unpadded = padded.rstrip("=")

    fingerprints, names = cb.load_client_acl(
        {"acl": {"trusted_fingerprints": [padded]}}
    )

    assert fingerprints == frozenset({unpadded})
    assert names == ()

    # The unpadded spelling is accepted and normalizes to the same value.
    assert cb.load_client_acl(
        {"acl": {"trusted_fingerprints": [unpadded]}}
    ) == (frozenset({unpadded}), ())


def test_client_acl_names_accept_a_string_or_a_list(cb: types.ModuleType) -> None:
    assert cb.load_client_acl({"acl": {"trusted_names": "server-*"}}) == (
        frozenset(),
        ("server-*",),
    )
    assert cb.load_client_acl({"acl": {"trusted_names": ["a", "b"]}}) == (
        frozenset(),
        ("a", "b"),
    )


def test_client_acl_accepts_fingerprints_and_names_together(
    cb: types.ModuleType,
) -> None:
    fingerprint = _sha256_fingerprint()

    assert cb.load_client_acl(
        {
            "acl": {
                "trusted_fingerprints": [fingerprint],
                "trusted_names": ["server-*"],
            }
        }
    ) == (frozenset({fingerprint.rstrip("=")}), ("server-*",))


@pytest.mark.parametrize(
    "acl",
    [
        {},
        {"trusted_fingerprints": []},
        {"trusted_names": []},
        {"trusted_fingerprints": [], "trusted_names": []},
    ],
)
def test_client_acl_must_pin_something(
    cb: types.ModuleType, acl: dict
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.load_client_acl({"acl": acl})


@pytest.mark.parametrize(
    "fingerprint",
    [
        "not-a-fingerprint",
        "SHA256:",
        "SHA256:!!!not-base64!!!",
        "SHA256:" + base64.b64encode(b"x" * 16).decode("ascii"),
        "SHA256:" + base64.b64encode(b"x" * 33).decode("ascii"),
        "sha256:" + _sha256_fingerprint()[len("SHA256:") :],
    ],
)
def test_client_acl_rejects_bad_fingerprints(
    cb: types.ModuleType, fingerprint: str
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.load_client_acl({"acl": {"trusted_fingerprints": [fingerprint]}})


def test_client_acl_fingerprints_must_be_a_list(cb: types.ModuleType) -> None:
    with pytest.raises(cb.ConfigError):
        cb.load_client_acl({"acl": {"trusted_fingerprints": _sha256_fingerprint()}})


@pytest.mark.parametrize("names", [123, ["ok", 5], {"a": "b"}])
def test_client_acl_rejects_invalid_trusted_names(
    cb: types.ModuleType, names: object
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.load_client_acl({"acl": {"trusted_names": names}})


# --- target resolution (friendly names vs raw ids) ------------------------


def _reset_clipboards(cb: types.ModuleType) -> None:
    """Clear the module-level client store between resolution tests."""
    cb.client_clipboards.clear()


def test_resolve_target_to_id_treats_prefixed_ids_as_exact(
    cb: types.ModuleType,
) -> None:
    """A ``vsock:``/``tcp:``/``unix:`` target is never re-interpreted as a name."""
    _reset_clipboards(cb)
    try:
        cb.client_clipboards["tcp:10.201.0.10"] = {
            "data": "",
            "updated": 0,
            "name": "notes",
        }

        assert cb.resolve_target_to_id("tcp:10.201.0.10") == "tcp:10.201.0.10"
        assert cb.resolve_target_to_id("tcp:10.201.0.99") == "tcp:10.201.0.99"
        assert cb.resolve_target_to_id("vsock:7") == "vsock:7"
        assert cb.resolve_target_to_id("unix:local") == "unix:local"
    finally:
        _reset_clipboards(cb)


def test_resolve_target_to_id_prefers_registered_names_over_raw(
    cb: types.ModuleType,
) -> None:
    """A registered friendly name wins over a same-named phantom slot."""
    _reset_clipboards(cb)
    try:
        cb.client_clipboards["tcp:10.201.0.10"] = {
            "data": "REAL",
            "updated": 0,
            "name": "notes",
        }
        cb.client_clipboards["notes"] = {
            "data": "PHANTOM",
            "updated": 0,
            "name": None,
        }

        assert cb.resolve_target_to_id("notes") == "tcp:10.201.0.10"
    finally:
        _reset_clipboards(cb)


def test_resolve_target_to_id_uses_listener_document_maps(
    cb: types.ModuleType,
) -> None:
    """An unregistered name resolves through ``_vm``/``_tcp_vm`` before raw."""
    _reset_clipboards(cb)
    try:
        config = {
            "_vm": [{"cid": 7, "name": "dev"}],
            "_tcp_vm": [{"ip": "10.201.0.10", "name": "notes"}],
        }

        assert cb.resolve_target_to_id("dev", config) == "vsock:7"
        assert cb.resolve_target_to_id("notes", config) == "tcp:10.201.0.10"
        assert cb.resolve_target_to_id("ghost", config) == "ghost"
    finally:
        _reset_clipboards(cb)


# --- client transport and bounds ------------------------------------------


def _client_document(**fields: object) -> str:
    """A minimal unix client document with per-test key overrides."""
    values: dict[str, object] = {
        "mode": "client",
        "transport": "unix",
        "socket": "/tmp/clipboard-client.sock",
        "connect_timeout": 5,
        "handshake_timeout": 10,
        "recv_timeout": 30,
    }
    values.update(fields)
    lines = [
        f"{key} = {json.dumps(value)}"
        for key, value in values.items()
        if value is not None
    ]
    lines += [
        "",
        "[security]",
        'transport_encryption = "none"',
        'client_auth = "none"',
        'server_auth = "none"',
    ]
    return "\n".join(lines) + "\n"


def test_client_unix_requires_a_socket(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    path = _write_config(
        tmp_path, "client.toml", _client_document(socket=None)
    )

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "client")


def test_client_unix_requires_a_non_empty_socket(
    cb: types.ModuleType, tmp_path: Path
) -> None:
    path = _write_config(tmp_path, "client.toml", _client_document(socket=""))

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "client")


def test_get_connection_info_refuses_unix_without_a_socket(
    cb: types.ModuleType,
) -> None:
    with pytest.raises(cb.ConfigError):
        cb.get_connection_info({"transport": "unix"})
    with pytest.raises(cb.ConfigError):
        cb.get_connection_info({"transport": "unix", "socket": ""})

    assert cb.get_connection_info(
        {"transport": "unix", "socket": "/tmp/clip.sock"}
    ) == ("unix", "/tmp/clip.sock")


@pytest.mark.parametrize(
    "field", ["connect_timeout", "handshake_timeout", "recv_timeout"]
)
@pytest.mark.parametrize("value", [0, -1, "five", True])
def test_client_rejects_invalid_timeouts(
    cb: types.ModuleType, tmp_path: Path, field: str, value: object
) -> None:
    path = _write_config(
        tmp_path, "client.toml", _client_document(**{field: value})
    )

    with pytest.raises(cb.ConfigError):
        cb.load_config(str(path), "client")


@pytest.mark.parametrize(
    "field", ["connect_timeout", "handshake_timeout", "recv_timeout"]
)
def test_client_accepts_positive_timeouts(
    cb: types.ModuleType, tmp_path: Path, field: str
) -> None:
    path = _write_config(
        tmp_path, "client.toml", _client_document(**{field: 2.5})
    )

    cb.load_config(str(path), "client")


def test_machine_wildcard_does_not_match_an_unauthenticated_identity(
    cb: types.ModuleType,
) -> None:
    """``machine = ["*"]`` still needs an identity; only an empty selector matches None."""
    wildcard = cb.parse_rules(
        [{"match": {"machine": ["*"]}, "policy": "allow"}]
    )

    assert (
        cb.evaluate_rules(
            wildcard, listener="admin", machine=None, action="get", target=None
        )
        == "deny"
    )
    assert (
        cb.evaluate_rules(
            wildcard, listener="admin", machine="admin", action="get", target=None
        )
        == "allow"
    )


# --- default config selection ----------------------------------------------


def _default_args(command: str, **kwargs: object) -> types.SimpleNamespace:
    return types.SimpleNamespace(command=command, **kwargs)


@pytest.fixture
def default_config_paths(
    cb: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    paths = {
        "server": tmp_path / "server.toml",
        "client": tmp_path / "client.toml",
        "admin": tmp_path / "admin.toml",
    }
    monkeypatch.setattr(cb, "DEFAULT_SERVER_CONFIG_PATH", str(paths["server"]))
    monkeypatch.setattr(cb, "DEFAULT_CLIENT_CONFIG_PATH", str(paths["client"]))
    monkeypatch.setattr(cb, "DEFAULT_ADMIN_CONFIG_PATH", str(paths["admin"]))
    return paths


def test_default_config_serve_uses_server(
    cb: types.ModuleType, default_config_paths: dict[str, Path]
) -> None:
    assert cb.resolve_default_config(_default_args("serve")) == str(
        default_config_paths["server"]
    )


@pytest.mark.parametrize(
    "command,kwargs",
    [
        ("clients", {}),
        ("push", {"target": "dev"}),
        ("pull", {"target": "dev"}),
        ("pull", {"json": True}),
    ],
)
def test_default_config_admin_commands_use_admin(
    cb: types.ModuleType,
    default_config_paths: dict[str, Path],
    command: str,
    kwargs: dict[str, object],
) -> None:
    default_config_paths["admin"].write_text("", encoding="utf-8")
    default_config_paths["client"].write_text("", encoding="utf-8")

    assert cb.resolve_default_config(_default_args(command, **kwargs)) == str(
        default_config_paths["admin"]
    )


def test_default_config_admin_falls_back_to_client(
    cb: types.ModuleType, default_config_paths: dict[str, Path]
) -> None:
    default_config_paths["client"].write_text("", encoding="utf-8")

    assert cb.resolve_default_config(_default_args("clients")) == str(
        default_config_paths["client"]
    )


@pytest.mark.parametrize(
    "command,kwargs",
    [
        ("push", {}),
        ("pull", {}),
        ("register", {}),
        ("client", {}),
        ("proxy", {}),
    ],
)
def test_default_config_client_commands_use_client(
    cb: types.ModuleType,
    default_config_paths: dict[str, Path],
    command: str,
    kwargs: dict[str, object],
) -> None:
    default_config_paths["admin"].write_text("", encoding="utf-8")
    default_config_paths["client"].write_text("", encoding="utf-8")

    assert cb.resolve_default_config(_default_args(command, **kwargs)) == str(
        default_config_paths["client"]
    )


def test_default_config_client_falls_back_to_admin(
    cb: types.ModuleType, default_config_paths: dict[str, Path]
) -> None:
    default_config_paths["admin"].write_text("", encoding="utf-8")

    assert cb.resolve_default_config(_default_args("push")) == str(
        default_config_paths["admin"]
    )


def test_main_resolves_default_config(
    cb: types.ModuleType,
    default_config_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    default_config_paths["admin"].write_text("", encoding="utf-8")
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        cb, "cmd_clients", lambda args: seen.update({"args": args})
    )
    monkeypatch.setattr(
        cb.sys, "argv", ["clipboard-bridge", "clients"]
    )

    cb.main()

    assert seen["args"].config == str(default_config_paths["admin"])


def test_main_keeps_an_explicit_config(
    cb: types.ModuleType,
    default_config_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        cb, "cmd_clients", lambda args: seen.update({"args": args})
    )
    monkeypatch.setattr(
        cb.sys,
        "argv",
        ["clipboard-bridge", "-c", "/custom/admin.toml", "clients"],
    )

    cb.main()

    assert seen["args"].config == "/custom/admin.toml"

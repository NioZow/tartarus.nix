"""Tests for ``ssh-agent-proxy`` (plan Phases 1-2, 6).

The service is a standalone script (not an importable package module), so it is
loaded by path with ``importlib``; importing it has no side effects.

Behaviours covered:

1. transport parsing -- the explicit ``transport`` key, the legacy
   ``vsock_port``/``tcp_bind`` derivation (with a warning) and the default;
2. the ``[security]`` model -- ``auto`` resolving from the transport, the
   no-downgrade rule (``mtls.enable`` vs an explicit ``transport_encryption``),
   and the ``client_auth``/``server_auth`` consistency checks;
3. the ``unix`` transport rejecting ``tartarus``/``mofos`` resolution at load;
4. the wildcard-only matching rule for an unset identity (``resolution =
   "none"``): a specific ``machine`` pattern can never match an
   unauthenticated peer;
5. ``mofos`` resolution (``mofos ls --json`` by CID / ``ipv4_address``);
6. the display-label vs matching-identity split of ``resolve_peer``;
7. ``_resolve_agent_sockets`` -- per-connection directory scanning (opt-in via
   ``scan_dirs``), non-socket children ignored, absent entries skipped, realpath
   de-duplication, and the per-session socket short-circuit;
8. a real ``unix`` server/client round-trip over AF_UNIX (no mTLS);
9. the multi-listener server schema -- ``Config.load`` builds one
   ``ListenerConfig`` per self-contained ``[[listeners]]`` entry (per-listener
   resolution/security), keeps a flat config as a single implicit listener,
   rejects an ambiguous mix, allows duplicate types, binds several ``unix``
   listeners at once, and builds one TLS context per listener.

Run from the package root::

    python -m pytest tests/test_ssh_agent_proxy.py -v
"""

from __future__ import annotations

import importlib.util
import socket
import struct
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "ssh-agent-proxy"
    / "ssh-agent-proxy.py"
)

# The shipped server examples. The multi-listener one (`-listeners.toml`) is
# loaded by `test_shipped_multi_listener_example_parses`; the flat one is the
# legacy single-listener form.
EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"

REQUEST_IDENTITIES = 11
IDENTITIES_ANSWER = 12
FAILURE = 5


@pytest.fixture(scope="session")
def sap() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "ssh_agent_proxy_under_test", SOURCE_PATH
    )
    assert spec is not None and spec.loader is not None, f"cannot load {SOURCE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _clear_mofos_cache(monkeypatch: pytest.MonkeyPatch, sap: types.ModuleType) -> None:
    """Do not let one test's mocked ``mofos`` listing leak into the next."""
    monkeypatch.setattr(sap, "_mofos_cache", None)


# --- config helpers --------------------------------------------------------


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def _load_proxy(sap: types.ModuleType, tmp_path: Path, body: str) -> Any:
    config = sap.Config()
    config.load(str(_write_config(tmp_path, body)), mode="proxy")
    return config


# --- 1. transport parsing --------------------------------------------------


def test_default_transport_is_tcp(sap: types.ModuleType, tmp_path: Path) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n',
    )
    assert cfg.transport == "tcp"


def test_legacy_vsock_port_derives_vsock(
    sap: types.ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\nagent_sockets = ["/tmp/a"]\nvsock_port = 65000\n',
    )
    assert cfg.transport == "vsock"
    assert cfg.vsock_port == 65000
    assert "vsock_port is deprecated" in caplog.text


def test_legacy_tcp_bind_derives_tcp(
    sap: types.ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
        'tcp_bind = "127.0.0.1:65000"\n',
    )
    assert cfg.transport == "tcp"
    assert "tcp_bind is deprecated" in caplog.text


# --- 2. security model -----------------------------------------------------


def test_security_auto_on_tcp_is_mtls(sap: types.ModuleType) -> None:
    te, client, server = sap.validate_security_config(
        {"transport": "tcp", "security": {"transport_encryption": "auto"}}, "tcp"
    )
    assert (te, client, server) == ("mtls", "transport", "transport")


def test_security_auto_on_vsock_is_none(sap: types.ModuleType) -> None:
    te, client, server = sap.validate_security_config(
        {"transport": "vsock", "security": {"transport_encryption": "auto"}}, "vsock"
    )
    assert (te, client, server) == ("none", "none", "none")


def test_security_mtls_enable_cannot_downgrade(sap: types.ModuleType) -> None:
    with pytest.raises(ValueError, match="refusing to downgrade"):
        sap.validate_security_config(
            {
                "transport": "vsock",
                "mtls": {"enable": True},
                "security": {"transport_encryption": "none"},
            },
            "vsock",
        )


def test_security_transport_auth_requires_mtls(sap: types.ModuleType) -> None:
    with pytest.raises(ValueError, match="requires transport_encryption"):
        sap.validate_security_config(
            {
                "transport": "vsock",
                "security": {
                    "transport_encryption": "none",
                    "client_auth": "transport",
                    "server_auth": "none",
                },
            },
            "vsock",
        )


def test_security_absent_is_lenient_for_legacy(sap: types.ModuleType) -> None:
    # A legacy tcp config with no `[security]` keeps running plaintext rather
    # than failing to load (plan §6).
    te, client, server = sap.validate_security_config({"transport": "tcp"}, "tcp")
    assert (te, client, server) == ("none", "none", "none")


# --- 3. unix resolution rejection ------------------------------------------


@pytest.mark.parametrize("resolution", ["tartarus", "mofos"])
def test_unix_rejects_cid_ip_resolution(
    sap: types.ModuleType, tmp_path: Path, resolution: str
) -> None:
    with pytest.raises(ValueError, match="not valid on the unix transport"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\ntransport = "unix"\nagent_sockets = ["/tmp/a"]\n'
            + f'resolution = "{resolution}"\n',
        )


# --- 4. wildcard-only matching ---------------------------------------------


def test_none_identity_matches_only_wildcards(sap: types.ModuleType) -> None:
    assert sap.Rule(key="*").matches_machine(None) is True
    assert sap.Rule(key="*", machine=[]).matches_machine(None) is True
    assert sap.Rule(key="*", machine=["*"]).matches_machine(None) is True
    assert sap.Rule(key="*", machine=["dev"]).matches_machine(None) is False
    # every pattern must be a wildcard
    assert sap.Rule(key="*", machine=["dev", "*"]).matches_machine(None) is False


def test_identity_matches_specific_and_wildcard(sap: types.ModuleType) -> None:
    assert sap.Rule(key="*", machine=["dev"]).matches_machine("dev") is True
    assert sap.Rule(key="*", machine=["dev"]).matches_machine("other") is False
    assert sap.Rule(key="*", machine=["d*"]).matches_machine("dev") is True


def test_listener_selector_matching(sap: types.ModuleType) -> None:
    # An empty selector matches every listener, named or unnamed.
    assert sap.Rule(key="*").matches_listener(None) is True
    assert sap.Rule(key="*").matches_listener("merge") is True
    assert sap.Rule(key="*", listeners=[]).matches_listener(None) is True
    # A named listener is matched by a specific or wildcard pattern.
    assert sap.Rule(key="*", listeners=["merge"]).matches_listener("merge") is True
    assert sap.Rule(key="*", listeners=["merge"]).matches_listener("other") is False
    assert sap.Rule(key="*", listeners=["m*"]).matches_listener("merge") is True
    # An unnamed listener only matches a wildcard selector (mirrors matches_machine).
    assert sap.Rule(key="*", listeners=["merge"]).matches_listener(None) is False
    assert sap.Rule(key="*", listeners=["*"]).matches_listener(None) is True
    assert sap.Rule(key="*", listeners=["*", "merge"]).matches_listener(None) is False


# --- 5. mofos resolution ---------------------------------------------------


def test_resolve_mofos_name_by_cid_and_ip(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sap,
        "_mofos_vms",
        lambda: [
            {"cid": 4, "name": "template-nixos", "ipv4_address": "192.168.90.147"},
            {"cid": 7, "name": "dev", "ipv4_address": "10.200.0.7"},
        ],
    )
    assert sap.resolve_mofos_name(4) == "template-nixos"
    assert sap.resolve_mofos_name("10.200.0.7") == "dev"
    assert sap.resolve_mofos_name(999) is None


# --- 6. display label vs identity ------------------------------------------


def test_resolve_peer_none_splits_label_and_identity(sap: types.ModuleType) -> None:
    display, identity = sap.resolve_peer(
        "none", None, object(), None, "unknown-cid-7", 7
    )
    assert display == "unknown-cid-7"
    assert identity is None


def test_resolve_peer_certificate_uses_cn(sap: types.ModuleType) -> None:
    class _Req:
        def getpeercert(self) -> dict:
            return {"subject": ((("commonName", "dev"),),)}

    display, identity = sap.resolve_peer(
        "certificate", object(), _Req(), None, "local", None
    )
    assert (display, identity) == ("dev", "dev")


def test_resolve_peer_mofos_uses_name(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "resolve_mofos_name", lambda peer: "dev")
    display, identity = sap.resolve_peer(
        "mofos", None, object(), None, "unknown-ip-1.2.3.4", "1.2.3.4"
    )
    assert (display, identity) == ("dev", "dev")


# --- 7. merge upstream resolution ------------------------------------------


def _bind_socket(path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    sock.listen(1)
    return sock


def test_resolve_agent_sockets_directory_scan(sap: types.ModuleType, tmp_path: Path) -> None:
    sockets_dir = tmp_path / "forwarded"
    sockets_dir.mkdir()
    s1 = _bind_socket(sockets_dir / "s1.sock")
    (sockets_dir / "not-a-socket").write_text("x")
    missing = tmp_path / "missing"
    # a literal entry pointing at the same socket as a directory child, to test
    # realpath de-duplication.
    entries = [str(sockets_dir), str(s1.getsockname()), str(missing)]
    try:
        resolved = sap._resolve_agent_sockets(entries, scan_dirs=True)
    finally:
        s1.close()
    # non-socket ignored, absent skipped, the aliased socket appears once.
    assert resolved == [str(sockets_dir / "s1.sock")]


def test_resolve_agent_sockets_scan_off_skips_dirs(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    sockets_dir = tmp_path / "forwarded"
    sockets_dir.mkdir()
    child = _bind_socket(sockets_dir / "child.sock")
    literal = _bind_socket(tmp_path / "literal.sock")
    literal_path = str(literal.getsockname())
    try:
        # With the scan off, a directory entry contributes nothing, but a
        # literal socket path is still used as-is.
        resolved = sap._resolve_agent_sockets([str(sockets_dir), literal_path])
    finally:
        child.close()
        literal.close()
    assert resolved == [literal_path]


def test_resolve_agent_sockets_session_socket_short_circuits(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    sockets_dir = tmp_path / "forwarded"
    sockets_dir.mkdir()
    child = _bind_socket(sockets_dir / "child.sock")
    session = _bind_socket(sockets_dir / "session.sock")
    session_path = str(session.getsockname())
    try:
        resolved = sap._resolve_agent_sockets(
            [str(sockets_dir)], scan_dirs=True, session_socket=session_path
        )
    finally:
        child.close()
        session.close()
    # The exact session socket is preferred and the directory is not scanned.
    assert resolved == [session_path]


def test_resolve_agent_sockets_expands_runtime_dir(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    literal = _bind_socket(tmp_path / "ssh-agent")
    forwarded = tmp_path / "forwarded"
    forwarded.mkdir()
    child = _bind_socket(forwarded / "s1.sock")
    try:
        # A `%t/...` literal is expanded for the filesystem check but returned
        # verbatim as the identifier (so it still matches `key.socket`).
        assert sap._resolve_agent_sockets(["%t/ssh-agent"]) == ["%t/ssh-agent"]
        # A `%t/...` directory entry is expanded before being scanned.
        assert sap._resolve_agent_sockets(["%t/forwarded"], scan_dirs=True) == [
            str(forwarded / "s1.sock")
        ]
        # A `%t` literal and its absolute spelling de-duplicate to one entry.
        assert sap._resolve_agent_sockets(
            ["%t/ssh-agent", str(tmp_path / "ssh-agent")]
        ) == ["%t/ssh-agent"]
    finally:
        literal.close()
        child.close()


# --- 8. unix round-trip ----------------------------------------------------


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _recv_frame(sock: socket.socket) -> bytes:
    rawlen = sock.recv(4)
    length = struct.unpack(">I", rawlen)[0]
    data = b""
    while len(data) < length:
        data += sock.recv(length - len(data))
    return data


def _fake_agent(path: Path, stop: threading.Event) -> threading.Thread:
    """A minimal upstream agent: empty identity list, FAILURE for everything."""

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            try:
                msg = _recv_frame(conn)
                if msg and msg[0] == REQUEST_IDENTITIES:
                    conn.sendall(_frame(struct.pack(">BI", IDENTITIES_ANSWER, 0)))
                else:
                    conn.sendall(_frame(bytes([FAILURE])))
            except OSError:
                pass
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"socket {path} did not appear within {timeout}s")


def test_unix_server_client_roundtrip(sap: types.ModuleType, tmp_path: Path) -> None:
    upstream = tmp_path / "upstream.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    _fake_agent(upstream, stop)
    _wait_for_socket(upstream)

    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"
transport = "unix"
socket = "{server_sock}"
resolution = "none"
agent_sockets = ["{upstream}"]
[security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)

    try:
        # Client dials the server over AF_UNIX (the `run_client` transport path).
        remote = sap.RemoteConnection(str(server_sock), 0, "unix", None, cfg)
        resp = remote.request(bytes([REQUEST_IDENTITIES]))
        assert resp is not None
        assert resp[0] == IDENTITIES_ANSWER
        assert struct.unpack(">I", resp[1:5])[0] == 0
    finally:
        stop.set()


def _fake_agent_one_identity(
    path: Path, stop: threading.Event, blob: bytes, comment: bytes
) -> threading.Thread:
    """An upstream agent that always offers the single given identity."""

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            try:
                msg = _recv_frame(conn)
                if msg and msg[0] == REQUEST_IDENTITIES:
                    payload = struct.pack(">BI", IDENTITIES_ANSWER, 1)
                    payload += _frame(blob) + _frame(comment)
                    conn.sendall(_frame(payload))
                else:
                    conn.sendall(_frame(bytes([FAILURE])))
            except OSError:
                pass
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_upstream_agent_socket_expands_runtime_dir(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `%t/...` agent_sockets entry is expanded at connect time, so a key
    offered by the upstream is actually enumerated (the pre-fix behaviour left
    `%t` literal, failed to connect, and returned zero identities)."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    upstream = tmp_path / "upstream.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    key_blob = struct.pack(">I", 11) + b"ssh-ed25519" + b"AAAA"
    _fake_agent_one_identity(upstream, stop, key_blob, b"test-key")
    _wait_for_socket(upstream)

    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"
transport = "unix"
socket = "{server_sock}"
resolution = "none"
agent_sockets = ["%t/upstream.sock"]
[security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)

    try:
        remote = sap.RemoteConnection(str(server_sock), 0, "unix", None, cfg)
        resp = remote.request(bytes([REQUEST_IDENTITIES]))
        assert resp is not None
        assert resp[0] == IDENTITIES_ANSWER
        assert struct.unpack(">I", resp[1:5])[0] == 1
    finally:
        stop.set()


def test_authorize_unix_peer_same_uid(sap: types.ModuleType) -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # The test process owns both ends, so the peer uid is our own.
        assert sap.authorize_unix_peer(b) == sap.getuid()
    finally:
        a.close()
        b.close()


# --- 9. multi-listener server schema ---------------------------------------


def _wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met within timeout")


def test_load_builds_listeners_from_listeners(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "vsock"
cid = 3
resolution = "tartarus"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "tcp"
host = "10.0.0.1"
port = 65000
resolution = "mofos"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    assert len(cfg.listeners) == 2
    vsock, tcp = cfg.listeners
    assert isinstance(vsock, sap.ListenerConfig)
    assert vsock.transport == "vsock"
    assert vsock.cid == 3
    assert vsock.resolution == "tartarus"
    assert (
        vsock.transport_encryption,
        vsock.client_auth,
        vsock.server_auth,
    ) == ("none", "none", "none")
    assert tcp.transport == "tcp"
    assert tcp.host == "10.0.0.1"
    assert tcp.port == 65000
    assert tcp.resolution == "mofos"


def test_load_parses_listener_names_and_match_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "unix"
socket = "/tmp/merge.sock"
name = "merge"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "unix"
socket = "/tmp/other.sock"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[rule]]
key = "*"
match.listeners = "merge"
auth = "allow"

[[rule]]
key = "*"
match.listeners = ["a", "b"]
auth = "ask"
''',
    )
    # a named listener and an unnamed one
    assert [listener.name for listener in cfg.listeners] == ["merge", None]
    # `match.listeners` accepts a bare string or a list of patterns
    merge_rule, multi_rule = cfg.rules
    assert merge_rule.listeners == ["merge"]
    assert multi_rule.listeners == ["a", "b"]


def test_duplicate_listener_name_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="duplicate listener name"):
        _load_proxy(
            sap,
            tmp_path,
            '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "unix"
socket = "/tmp/a.sock"
name = "dup"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "unix"
socket = "/tmp/b.sock"
name = "dup"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
        )


def test_empty_listener_name_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="listener name"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\ntransport = "vsock"\ncid = 2\nname = ""\n'
            'agent_sockets = ["/tmp/agent"]\n',
        )


def test_load_legacy_flat_single_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\ntransport = "vsock"\ncid = 4\nport = 65000\n'
        'resolution = "tartarus"\nagent_sockets = ["/tmp/agent"]\n',
    )
    assert len(cfg.listeners) == 1
    listener = cfg.listeners[0]
    assert listener.transport == cfg.transport == "vsock"
    assert listener.cid == cfg.cid == 4
    assert listener.port == cfg.vsock_port == 65000
    assert listener.resolution == cfg.resolution == "tartarus"
    assert listener.host == cfg.host


def test_load_listeners_with_flat_transport_is_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\ntransport = "tcp"\n'
            'agent_sockets = ["/tmp/agent"]\n'
            '[[listeners]]\ntype = "vsock"\n',
        )


def test_old_transports_key_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    """The renamed `transports`/`transport_defaults` keys fail loudly."""
    with pytest.raises(ValueError, match="renamed to"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/agent"]\n'
            '[[transports]]\ntype = "vsock"\ncid = 2\n',
        )


def test_listener_defaults_key_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """The removed `[listener_defaults]` block fails loudly."""
    with pytest.raises(ValueError, match="listener_defaults"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/agent"]\n'
            "[listener_defaults]\nresolution = \"none\"\n"
            '[[listeners]]\ntype = "vsock"\ncid = 2\n',
        )


def test_duplicate_transport_types_allowed(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "unix"
socket = "/tmp/a.sock"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "unix"
socket = "/tmp/b.sock"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    assert len(cfg.listeners) == 2
    assert [listener.transport for listener in cfg.listeners] == ["unix", "unix"]
    assert cfg.listeners[0].socket != cfg.listeners[1].socket


def test_listener_resolution_is_per_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "unix"
socket = "/tmp/x.sock"

[listeners.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[listeners.mtls]
enable = true
ca_file = "/tmp/ca.crt"
cert_file = "/tmp/server.crt"
key_file = "/tmp/server.key"

[[listeners]]
type = "vsock"
resolution = "tartarus"
''',
    )
    # `unix` + mTLS defaults to certificate identity; `vsock` keeps its explicit
    # CID-based identity. Resolution is resolved per listener, not once.
    assert cfg.listeners[0].resolution == "certificate"
    assert cfg.listeners[1].resolution == "tartarus"

    with pytest.raises(ValueError, match="not valid on the unix transport"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/agent"]\n'
            '[[listeners]]\ntype = "unix"\nsocket = "/tmp/x.sock"\n'
            'resolution = "tartarus"\n',
        )


def test_shipped_multi_listener_example_parses(sap: types.ModuleType) -> None:
    """The shipped multi-listener example loads and builds three listeners.

    `examples/ssh-agent-proxy-server.toml` is the file the multi-transport
    setup tells an operator to install, so it must load and expand to one
    `ListenerConfig` per `[[listeners]]` entry, each with its own `name`,
    `resolution`/`security`. Loading the shipped file (rather than an inline
    copy) keeps the example and the parser in sync.
    """
    path = EXAMPLES_DIR / "ssh-agent-proxy-server.toml"

    config = sap.Config()
    config.load(str(path), mode="proxy")

    assert len(config.listeners) == 3
    vsock, unix, merge = config.listeners
    assert [listener.transport for listener in config.listeners] == [
        "vsock",
        "unix",
        "unix",
    ]
    # only the two intended listeners are named; the callback is unnamed.
    assert [listener.name for listener in config.listeners] == [
        None,
        "remote-guest",
        "merge",
    ]
    # per-listener identity: CID-based on the callback, certificate on the SSH
    # forwarded socket, unset on the local merge socket.
    assert vsock.resolution == "tartarus"
    assert unix.resolution == "certificate"
    assert merge.resolution == "none"
    # per-listener security: the callback and the local merge socket are
    # unauthenticated, the unix forwarded socket is mTLS (so the certificate CN
    # names the peer).
    assert (vsock.transport_encryption, vsock.client_auth, vsock.server_auth) == (
        "none",
        "none",
        "none",
    )
    assert (unix.transport_encryption, unix.client_auth, unix.server_auth) == (
        "mtls",
        "transport",
        "transport",
    )
    assert (merge.transport_encryption, merge.client_auth, merge.server_auth) == (
        "none",
        "none",
        "none",
    )
    # a relative path inside a listener resolves next to the config file
    assert unix.mtls_ca_file == str(path.parent / "ca.crt")
    # the merge listener is scoped by a `match.listeners` rule that allows all.
    merge_rule = next(r for r in config.rules if r.listeners == ["merge"])
    assert merge_rule.auth == "allow"
    assert merge_rule.data_signing == "allow"
    assert merge_rule.notify is False


def test_run_proxy_binds_two_unix_listeners(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = tmp_path / "upstream.sock"
    sock_a = tmp_path / "a.sock"
    sock_b = tmp_path / "b.sock"
    stop = threading.Event()
    _fake_agent(upstream, stop)
    _wait_for_socket(upstream)

    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"
agent_sockets = ["{upstream}"]

[[listeners]]
type = "unix"
socket = "{sock_a}"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "unix"
socket = "{sock_b}"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    assert len(cfg.listeners) == 2

    bound_servers: list[Any] = []
    real_bind = sap._bind_listener

    def recording_bind(listener, ssl_ctx):
        server = real_bind(listener, ssl_ctx)
        bound_servers.append(server)
        return server

    monkeypatch.setattr(sap, "_bind_listener", recording_bind)

    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(sock_a)
    _wait_for_socket(sock_b)
    _wait_until(lambda: len(bound_servers) == 2)

    remotes = []
    try:
        # A real AF_UNIX round-trip on each listener in the same process.
        for server_sock in (sock_a, sock_b):
            remote = sap.RemoteConnection(str(server_sock), 0, "unix", None, cfg)
            remotes.append(remote)
            resp = remote.request(bytes([REQUEST_IDENTITIES]))
            assert resp is not None
            assert resp[0] == IDENTITIES_ANSWER
            assert struct.unpack(">I", resp[1:5])[0] == 0

        # Each listener carries its own per-listener config.
        assert {server.listener_config.transport for server in bound_servers} == {
            "unix"
        }

        # Closing the clients lets the handler threads exit; shutting the
        # listeners down makes run_proxy's finally unlink both sockets.
        for remote in remotes:
            if remote.sock is not None:
                remote.sock.close()
        for server in bound_servers:
            server.shutdown()
        thread.join(timeout=5)
    finally:
        stop.set()

    assert not thread.is_alive()
    assert not sock_a.exists()
    assert not sock_b.exists()


def _write_tls_material(directory: Path) -> dict:
    """Write a self-signed CA/leaf cert + key carrying an EKU OID to disk."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    oid = "1.3.6.1.4.1.99999.2.1"
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ssh-agent-proxy-test")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid)]), critical=False
        )
        .sign(key, None)
    )
    (directory / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "server.crt").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    (directory / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {"oid": oid}


def test_create_ssl_context_is_per_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    _write_tls_material(tmp_path)
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/agent"]

[[listeners]]
type = "vsock"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[listeners]]
type = "tcp"
resolution = "none"

[listeners.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[listeners.mtls]
enable = true
ca_file = "./ca.crt"
cert_file = "./server.crt"
key_file = "./server.key"
required_oid = "1.3.6.1.4.1.99999.2.1"
''',
    )
    plain, secure = cfg.listeners
    # Relative mTLS paths resolve against the config dir.
    assert secure.mtls_ca_file == str(tmp_path / "ca.crt")
    assert sap.create_ssl_context(plain, server=True) is None
    assert sap.create_ssl_context(secure, server=True) is not None


# --- 10. agent_sockets -----------------------------------------------------


def test_agent_sockets_defaults_to_env(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/env-agent")
    cfg = _load_proxy(sap, tmp_path, 'mode = "proxy"\n')
    assert cfg.agent_sockets == ["/tmp/env-agent"]


def test_agent_sockets_requires_a_socket(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    with pytest.raises(ValueError, match="SSH_AUTH_SOCK empty"):
        _load_proxy(sap, tmp_path, 'mode = "proxy"\n')


def test_agent_sockets_first_is_key_default(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\n'
        'agent_sockets = ["/tmp/first", "/tmp/second"]\n'
        '[[key]]\nid = "k1"\npubkey = "ssh-ed25519 aGVsbG8="\n',
    )
    assert cfg.agent_sockets == ["/tmp/first", "/tmp/second"]
    k1 = next(k for k in cfg.keys.values() if k.id == "k1")
    assert k1.socket == "/tmp/first"


# --- 11. merge = an allow-all local proxy server ---------------------------


SIGN_REQUEST = 13
SIGN_RESPONSE = 14


def _fake_key_agent(
    path: Path, stop: threading.Event, blob: bytes, comment: bytes = b"test"
) -> threading.Thread:
    """An upstream agent exposing one identity and answering sign requests."""

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            conn.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        msg = _recv_frame(conn)
                    except socket.timeout:
                        continue
                    except (OSError, struct.error):
                        break
                    if not msg:
                        break
                    if msg[0] == REQUEST_IDENTITIES:
                        payload = struct.pack(">BI", IDENTITIES_ANSWER, 1)
                        payload += struct.pack(">I", len(blob)) + blob
                        payload += struct.pack(">I", len(comment)) + comment
                        conn.sendall(_frame(payload))
                    elif msg[0] == SIGN_REQUEST:
                        conn.sendall(_frame(bytes([SIGN_RESPONSE]) + b"sig"))
                    else:
                        conn.sendall(_frame(bytes([FAILURE])))
            except OSError:
                pass
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_proxy_unix_listener_merges_two_agents_allow_all(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """Merging is a normal allow-all unix proxy: two upstreams, one socket."""
    a = tmp_path / "a.sock"
    b = tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    blob_a = struct.pack(">I", 11) + b"ssh-ed25519"
    blob_b = struct.pack(">I", 11) + b"ssh-ed25519"
    _fake_key_agent(a, stop, blob_a + b"A", b"key-a")
    _fake_key_agent(b, stop, blob_b + b"B", b"key-b")
    _wait_for_socket(a)
    _wait_for_socket(b)

    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"
agent_sockets = ["{a}", "{b}"]

[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
notify = false

[[listeners]]
type = "unix"
socket = "{server_sock}"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5.0)
    try:
        client.connect(str(server_sock))
        client.sendall(_frame(bytes([REQUEST_IDENTITIES])))
        resp = _recv_frame(client)
        assert resp[0] == IDENTITIES_ANSWER
        count = struct.unpack(">I", resp[1:5])[0]
        # the union of both upstreams, no prompts (allow-all wildcard rule)
        assert count == 2

        # a sign request for one upstream's key is forwarded without a dialog
        sign = bytes([SIGN_REQUEST])
        sign += struct.pack(">I", len(blob_a) + 1) + blob_a + b"A"
        sign += struct.pack(">I", 4) + b"data"
        client.sendall(_frame(sign))
        sign_resp = _recv_frame(client)
        assert sign_resp[0] == SIGN_RESPONSE
    finally:
        client.close()
        stop.set()


def test_merge_mode_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="merge"):
        _load_proxy(sap, tmp_path, 'mode = "merge"\n')
    # also without the CLI mode override
    path = _write_config(tmp_path, 'mode = "merge"\n')
    with pytest.raises(ValueError, match="merge"):
        sap.Config().load(str(path))


def test_merge_sockets_key_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="merge"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nmerge_sockets = ["/tmp/a"]\nagent_sockets = ["/tmp/a"]\n',
        )


def test_scan_flags_rejected_on_non_unix(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="only valid on the unix transport"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
            '[[listeners]]\ntype = "vsock"\nscan_agent_socket_dirs = true\n',
        )
    with pytest.raises(ValueError, match="only valid on the unix transport"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
            '[[listeners]]\ntype = "tcp"\nresolve_session_socket = true\n',
        )
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
        '[[listeners]]\ntype = "unix"\nsocket = "/tmp/x.sock"\n'
        'resolution = "none"\n'
        'scan_agent_socket_dirs = true\nresolve_session_socket = true\n',
    )
    assert cfg.listeners[0].scan_agent_socket_dirs is True
    assert cfg.listeners[0].resolve_session_socket is True


# --- add/remove (key mutation) policy --------------------------------------

ADD_IDENTITY = 17
REMOVE_IDENTITY = 18
REMOVE_ALL_IDENTITIES = 19
ADD_ID_CONSTRAINED = 25
SUCCESS = 6


def _add_msg(
    keytype: bytes = b"ssh-ed25519",
    pub: bytes = b"\x01" * 32,
    comment: bytes = b"gram",
    mtype: int = ADD_IDENTITY,
    suffix: bytes = b"",
) -> bytes:
    """An SSH_AGENTC_ADD_IDENTITY (_CONSTRAINED) frame body (private half
    ignored by the proxy)."""
    return (
        bytes([mtype])
        + _frame(keytype)
        + _frame(pub)
        + _frame(b"\x02" * 64)
        + _frame(comment)
        + suffix
    )


def _public_blob(keytype: bytes, pub: bytes) -> bytes:
    return _frame(keytype) + _frame(pub)


def _fake_mutating_agent(
    path: Path, stop: threading.Event, seen: list[bytes]
) -> threading.Thread:
    """An upstream agent that records every message and accepts add/remove."""

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            conn.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        msg = _recv_frame(conn)
                    except socket.timeout:
                        continue
                    except (OSError, struct.error):
                        break
                    if not msg:
                        break
                    seen.append(msg)
                    if msg[0] == REQUEST_IDENTITIES:
                        conn.sendall(_frame(struct.pack(">BI", IDENTITIES_ANSWER, 0)))
                    elif msg[0] in (
                        ADD_IDENTITY,
                        ADD_ID_CONSTRAINED,
                        REMOVE_IDENTITY,
                        REMOVE_ALL_IDENTITIES,
                    ):
                        conn.sendall(_frame(bytes([SUCCESS])))
                    else:
                        conn.sendall(_frame(bytes([FAILURE])))
            except OSError:
                pass
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def _mutation_config(
    sap: types.ModuleType,
    tmp_path: Path,
    a: Path,
    b: Path,
    server_sock: Path,
    rule_extra: str,
) -> Any:
    return _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"
transport = "unix"
socket = "{server_sock}"
resolution = "none"
agent_sockets = ["{a}", "{b}"]
[security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
{rule_extra}
notify = false
''',
    )


def _start_server(
    sap: types.ModuleType, cfg: Any, server_sock: Path
) -> threading.Thread:
    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)
    return thread


def _mutate(
    server_sock: Path, msg: bytes
) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5.0)
    try:
        client.connect(str(server_sock))
        client.sendall(_frame(msg))
        return _recv_frame(client)
    finally:
        client.close()


def test_rule_add_remove_parse_and_default(sap: types.ModuleType, tmp_path: Path) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
        '[[rule]]\nkey = "*"\nadd = "ask"\nremove = "allow"\n',
    )
    rule = cfg.rules[0]
    assert rule.add == "ask"
    assert rule.remove == "allow"
    assert rule.auth == "ask"  # untouched default
    assert rule.data_signing == "deny"


def test_rule_add_invalid_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="add must be deny"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/a"]\n'
            '[[rule]]\nkey = "*"\nadd = "yes"\n',
        )


def test_public_blob_from_private_ed25519(sap: types.ModuleType) -> None:
    pub = b"\x01" * 32
    key_type, blob, comment = sap._public_blob_from_private(_add_msg(pub=pub, comment=b"gram"))
    assert key_type == "ssh-ed25519"
    assert blob == _public_blob(b"ssh-ed25519", pub)
    assert comment == "gram"
    assert sap._fingerprint(blob).startswith("SHA256:")


def test_public_blob_from_private_unknown_type(sap: types.ModuleType) -> None:
    msg = bytes([ADD_IDENTITY]) + _frame(b"ssh-frobnicate") + _frame(b"junk")
    key_type, blob, comment = sap._public_blob_from_private(msg)
    assert key_type == "ssh-frobnicate"
    assert blob is None
    assert comment == ""


def test_add_denied_by_default(sap: types.ModuleType, tmp_path: Path) -> None:
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    seen_b: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, seen_b)
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, "")
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, _add_msg()) == bytes([FAILURE])
        assert all(
            m[0] not in (ADD_IDENTITY, ADD_ID_CONSTRAINED) for m in seen_a + seen_b
        )
    finally:
        stop.set()


def test_add_allowed_forwarded_to_first_agent(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    seen_b: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, seen_b)
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, 'add = "allow"')
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, _add_msg())[0] == SUCCESS
        # the default agent is agent_sockets[0]; the second is untouched
        assert any(m[0] == ADD_IDENTITY for m in seen_a)
        assert all(m[0] != ADD_IDENTITY for m in seen_b)
    finally:
        stop.set()


def test_add_constrained_allowed(sap: types.ModuleType, tmp_path: Path) -> None:
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, [])
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, 'add = "allow"')
    _start_server(sap, cfg, server_sock)
    try:
        constrained = _add_msg(
            mtype=ADD_ID_CONSTRAINED, suffix=bytes([1]) + struct.pack(">I", 60)
        )
        assert _mutate(server_sock, constrained)[0] == SUCCESS
        assert any(m[0] == ADD_ID_CONSTRAINED for m in seen_a)
    finally:
        stop.set()


def test_add_ask_declined_returns_failure(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda *a, **k: False)
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, [])
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, 'add = "ask"')
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, _add_msg()) == bytes([FAILURE])
        assert all(m[0] != ADD_IDENTITY for m in seen_a)
    finally:
        stop.set()


def test_add_ask_accepted_forwards(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda *a, **k: True)
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, [])
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, 'add = "ask"')
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, _add_msg())[0] == SUCCESS
        assert any(m[0] == ADD_IDENTITY for m in seen_a)
    finally:
        stop.set()


def test_remove_denied_by_default(sap: types.ModuleType, tmp_path: Path) -> None:
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, [])
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, "")
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, bytes([REMOVE_ALL_IDENTITIES])) == bytes([FAILURE])
        assert all(m[0] != REMOVE_ALL_IDENTITIES for m in seen_a)
    finally:
        stop.set()


def test_remove_all_and_identity_allowed(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    a, b = tmp_path / "a.sock", tmp_path / "b.sock"
    server_sock = tmp_path / "server.sock"
    stop = threading.Event()
    seen_a: list[bytes] = []
    _fake_mutating_agent(a, stop, seen_a)
    _fake_mutating_agent(b, stop, [])
    _wait_for_socket(a)
    _wait_for_socket(b)
    cfg = _mutation_config(sap, tmp_path, a, b, server_sock, 'remove = "allow"')
    _start_server(sap, cfg, server_sock)
    try:
        assert _mutate(server_sock, bytes([REMOVE_ALL_IDENTITIES]))[0] == SUCCESS
        assert any(m[0] == REMOVE_ALL_IDENTITIES for m in seen_a)
        blob = _public_blob(b"ssh-ed25519", b"\x01" * 32)
        assert _mutate(server_sock, bytes([REMOVE_IDENTITY]) + _frame(blob))[0] == SUCCESS
        assert any(m[0] == REMOVE_IDENTITY for m in seen_a)
    finally:
        stop.set()


# --- 12. upstreams (unified listeners + outbound sources) ------------------


def test_upstream_tables_parse_transports(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"

[[upstream]]
transport = "unix"
socket = "/tmp/local.sock"

[[upstream]]
transport = "vsock"
cid = 3
port = 65000

[[upstream]]
transport = "tcp"
host = "10.0.0.1"
port = 7000

[[listeners]]
type = "unix"
socket = "/tmp/srv.sock"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    assert [u.transport for u in cfg.upstreams] == ["unix", "vsock", "tcp"]
    assert cfg.agent_sockets == ["/tmp/local.sock"]
    assert cfg.remote_ids == ["vsock:3:65000", "tcp:10.0.0.1:7000"]
    assert cfg.upstream_order == [
        "/tmp/local.sock",
        "vsock:3:65000",
        "tcp:10.0.0.1:7000",
    ]
    assert cfg.upstreams[0].is_local is True
    assert cfg.upstreams[1].is_local is False
    # A remote upstream with no [security] resolves plaintext (lenient).
    assert cfg.upstreams[1].transport_encryption == "none"
    assert cfg.upstreams[1].uses_tls is False


def test_upstream_array_precedes_legacy_agent_sockets(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = ["/tmp/legacy.sock"]

[[upstream]]
transport = "vsock"
cid = 2
port = 65000
''',
    )
    # `[[upstream]]` entries come first so a local agent listed there is the
    # default `key.socket` / add/remove target.
    assert cfg.upstream_order == ["vsock:2:65000", "/tmp/legacy.sock"]
    assert cfg.agent_sockets == ["/tmp/legacy.sock"]
    assert cfg.remote_ids == ["vsock:2:65000"]


def test_agent_sockets_accepts_table_entries(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
agent_sockets = [
  "/tmp/local.sock",
  { transport = "vsock", cid = 4, port = 65000 },
]
''',
    )
    assert cfg.upstream_order == ["/tmp/local.sock", "vsock:4:65000"]
    assert cfg.agent_sockets == ["/tmp/local.sock"]
    assert cfg.remote_ids == ["vsock:4:65000"]


def test_upstream_named_id_overrides_default(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"

[[upstream]]
name = "host"
transport = "vsock"
cid = 2
port = 65000
''',
    )
    assert cfg.upstream_order == ["host"]
    assert cfg.remote_ids == ["host"]


def test_upstream_duplicate_id_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="duplicate upstream id"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\nagent_sockets = ["/tmp/a.sock", "/tmp/a.sock"]\n',
        )


def test_unix_upstream_requires_socket(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unix upstream requires 'socket'"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\n[[upstream]]\ntransport = "unix"\n',
        )


def test_client_mode_deprecated_translates(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    listen_socket = tmp_path / "host.sock"
    path = _write_config(
        tmp_path,
        f'''transport = "vsock"
cid = 2
port = 65000
listen_socket = "{listen_socket}"

[security]
transport_encryption = "none"
''',
    )
    cfg = sap.Config()
    cfg.load(str(path), mode="client")
    # One local unix listener exposing the merged/forwarded identities ...
    assert len(cfg.listeners) == 1
    assert cfg.listeners[0].transport == "unix"
    assert cfg.listeners[0].socket == str(listen_socket)
    # ... fed by exactly one remote upstream.
    assert [u.transport for u in cfg.upstreams] == ["vsock"]
    assert cfg.upstreams[0].id == "vsock:2:65000"
    # A deprecated bridge is a transparent forwarder: allow-all, no prompt.
    assert cfg.rules[0].auth == "allow"
    assert cfg.rules[0].data_signing == "allow"
    assert cfg.rules[0].add == "allow"
    assert cfg.rules[0].remove == "allow"
    assert cfg.rules[0].notify is False


def _fake_tcp_key_agent(
    host: str, port: int, stop: threading.Event, blob: bytes, comment: bytes
) -> threading.Thread:
    """A TCP upstream agent exposing one identity and answering sign requests."""

    def serve() -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            conn.settimeout(0.5)
            try:
                while not stop.is_set():
                    try:
                        msg = _recv_frame(conn)
                    except socket.timeout:
                        continue
                    except (OSError, struct.error):
                        break
                    if not msg:
                        break
                    if msg[0] == REQUEST_IDENTITIES:
                        payload = struct.pack(">BI", IDENTITIES_ANSWER, 1)
                        payload += struct.pack(">I", len(blob)) + blob
                        payload += struct.pack(">I", len(comment)) + comment
                        conn.sendall(_frame(payload))
                    elif msg[0] == SIGN_REQUEST:
                        conn.sendall(_frame(bytes([SIGN_RESPONSE]) + b"sig"))
                    else:
                        conn.sendall(_frame(bytes([FAILURE])))
            except OSError:
                pass
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_remote_tcp_upstream_merged_over_unix_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """A single process merges a *remote* (TCP) upstream into a local unix
    listener -- the capability the old client/bridge split could not express."""
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + b"RR"
    stop = threading.Event()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    _fake_tcp_key_agent("127.0.0.1", port, stop, blob, b"remote-key")
    server_sock = tmp_path / "srv.sock"

    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"

[[upstream]]
transport = "tcp"
host = "127.0.0.1"
port = {port}

[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
notify = false

[[listeners]]
type = "unix"
socket = "{server_sock}"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5.0)
    try:
        client.connect(str(server_sock))
        client.sendall(_frame(bytes([REQUEST_IDENTITIES])))
        resp = _recv_frame(client)
        assert resp[0] == IDENTITIES_ANSWER
        assert struct.unpack(">I", resp[1:5])[0] == 1

        sign = bytes([SIGN_REQUEST])
        sign += struct.pack(">I", len(blob)) + blob
        sign += struct.pack(">I", 4) + b"data"
        client.sendall(_frame(sign))
        assert _recv_frame(client)[0] == SIGN_RESPONSE
    finally:
        client.close()
        stop.set()


def test_unix_upstream_socket_falls_back_to_session_env(
    sap: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `unix` upstream with no explicit `socket` dials the per-session
    `$SSH_AUTH_PROXY_SOCK` (the SSH-forwarded socket), fresh per inbound
    connection -- the one-process replacement for the client/bridge split on the
    `unix` ssh-agent-proxy transport."""
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + b"EE"
    forward = tmp_path / "forwarded.sock"
    stop = threading.Event()
    _fake_agent_one_identity(forward, stop, blob, b"forwarded-key")
    _wait_for_socket(forward)
    monkeypatch.setenv("SSH_AUTH_PROXY_SOCK", str(forward))

    server_sock = tmp_path / "srv.sock"
    cfg = _load_proxy(
        sap,
        tmp_path,
        f'''mode = "proxy"

[[upstream]]
transport = "unix"
name = "host"

[[rule]]
key = "*"
auth = "allow"
data_signing = "allow"
notify = false

[[listeners]]
type = "unix"
socket = "{server_sock}"
resolution = "none"

[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
''',
    )
    assert [u.id for u in cfg.upstreams] == ["host"]
    assert cfg.upstreams[0].socket is None

    thread = threading.Thread(target=sap.run_proxy, args=(cfg,), daemon=True)
    thread.start()
    _wait_for_socket(server_sock)
    try:
        # Dialed per connection: two sequential clients both see the identity.
        for _ in range(2):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5.0)
            try:
                client.connect(str(server_sock))
                client.sendall(_frame(bytes([REQUEST_IDENTITIES])))
                resp = _recv_frame(client)
                assert resp[0] == IDENTITIES_ANSWER
                assert struct.unpack(">I", resp[1:5])[0] == 1
            finally:
                client.close()
    finally:
        stop.set()

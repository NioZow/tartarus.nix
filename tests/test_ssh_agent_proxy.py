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
   "none"``): a specific ``vm_names`` pattern can never match an
   unauthenticated peer;
5. ``mofos`` resolution (``mofos ls --json`` by CID / ``ipv4_address``);
6. the display-label vs matching-identity split of ``resolve_peer``;
7. ``_merge_upstream_paths`` -- per-connection directory scanning, non-socket
   children ignored, absent entries skipped, realpath de-duplication;
8. a real ``unix`` server/client round-trip over AF_UNIX (no mTLS).

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
from typing import Any, Iterator

import pytest

SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "ssh-agent-proxy"
    / "ssh-agent-proxy.py"
)

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
        'mode = "proxy"\ndefault_agent_socket_path = "/tmp/a"\n',
    )
    assert cfg.transport == "tcp"


def test_legacy_vsock_port_derives_vsock(
    sap: types.ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\ndefault_agent_socket_path = "/tmp/a"\nvsock_port = 65000\n',
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
        'mode = "proxy"\ndefault_agent_socket_path = "/tmp/a"\n'
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
            'mode = "proxy"\ntransport = "unix"\ndefault_agent_socket_path = "/tmp/a"\n'
            + f'resolution = "{resolution}"\n',
        )


# --- 4. wildcard-only matching ---------------------------------------------


def test_none_identity_matches_only_wildcards(sap: types.ModuleType) -> None:
    assert sap.Rule(key="*").matches_vm(None) is True
    assert sap.Rule(key="*", vm_names=[]).matches_vm(None) is True
    assert sap.Rule(key="*", vm_names=["*"]).matches_vm(None) is True
    assert sap.Rule(key="*", vm_names=["dev"]).matches_vm(None) is False
    # every pattern must be a wildcard
    assert sap.Rule(key="*", vm_names=["dev", "*"]).matches_vm(None) is False


def test_identity_matches_specific_and_wildcard(sap: types.ModuleType) -> None:
    assert sap.Rule(key="*", vm_names=["dev"]).matches_vm("dev") is True
    assert sap.Rule(key="*", vm_names=["dev"]).matches_vm("other") is False
    assert sap.Rule(key="*", vm_names=["d*"]).matches_vm("dev") is True


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


def test_merge_upstream_paths_directory_scan(sap: types.ModuleType, tmp_path: Path) -> None:
    sockets_dir = tmp_path / "forwarded"
    sockets_dir.mkdir()
    s1 = _bind_socket(sockets_dir / "s1.sock")
    (sockets_dir / "not-a-socket").write_text("x")
    missing = tmp_path / "missing"
    # a literal entry pointing at the same socket as a directory child, to test
    # realpath de-duplication.
    entries = [str(sockets_dir), str(s1.getsockname()), str(missing)]
    try:
        resolved = sap._merge_upstream_paths(entries)
    finally:
        s1.close()
    # non-socket ignored, absent skipped, the aliased socket appears once.
    assert resolved == [str(sockets_dir / "s1.sock")]


def test_merge_upstream_paths_session_socket_short_circuits(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    sockets_dir = tmp_path / "forwarded"
    sockets_dir.mkdir()
    child = _bind_socket(sockets_dir / "child.sock")
    session = _bind_socket(sockets_dir / "session.sock")
    session_path = str(session.getsockname())
    try:
        resolved = sap._merge_upstream_paths(
            [str(sockets_dir)], session_socket=session_path
        )
    finally:
        child.close()
        session.close()
    # The exact session socket is preferred and the directory is not scanned.
    assert resolved == [session_path]


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
default_agent_socket_path = "{upstream}"
forward_sockets = ["{upstream}"]
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


def test_authorize_unix_peer_same_uid(sap: types.ModuleType) -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # The test process owns both ends, so the peer uid is our own.
        assert sap.authorize_unix_peer(b) == sap.getuid()
    finally:
        a.close()
        b.close()

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
8. a real ``unix`` server/client round-trip over AF_UNIX (no mTLS);
9. the multi-listener server schema -- ``Config.load`` expands a
   ``[transport_defaults]`` + ``[[transports]]`` document into one
   ``ListenerConfig`` per entry (per-listener resolution/security), keeps a flat
   config as a single implicit listener, rejects an ambiguous mix, allows
   duplicate types, binds several ``unix`` listeners at once, and builds one
   TLS context per listener.

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


# --- 9. multi-listener server schema ---------------------------------------


def _wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met within timeout")


def test_load_builds_listeners_from_transports(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
default_agent_socket_path = "/tmp/agent"

[transport_defaults]
resolution = "tartarus"

[transport_defaults.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[transports]]
type = "vsock"
cid = 3

[[transports]]
type = "tcp"
host = "10.0.0.1"
port = 65000
resolution = "mofos"
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


def test_load_legacy_flat_single_listener(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        'mode = "proxy"\ntransport = "vsock"\ncid = 4\nport = 65000\n'
        'resolution = "tartarus"\ndefault_agent_socket_path = "/tmp/agent"\n',
    )
    assert len(cfg.listeners) == 1
    listener = cfg.listeners[0]
    assert listener.transport == cfg.transport == "vsock"
    assert listener.cid == cfg.cid == 4
    assert listener.port == cfg.vsock_port == 65000
    assert listener.resolution == cfg.resolution == "tartarus"
    assert listener.host == cfg.host


def test_load_transports_with_flat_transport_is_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        _load_proxy(
            sap,
            tmp_path,
            'mode = "proxy"\ntransport = "tcp"\n'
            'default_agent_socket_path = "/tmp/agent"\n'
            '[[transports]]\ntype = "vsock"\n',
        )


def test_duplicate_transport_types_allowed(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    cfg = _load_proxy(
        sap,
        tmp_path,
        '''mode = "proxy"
default_agent_socket_path = "/tmp/agent"

[transport_defaults]
resolution = "none"

[transport_defaults.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[transports]]
type = "unix"
socket = "/tmp/a.sock"

[[transports]]
type = "unix"
socket = "/tmp/b.sock"
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
default_agent_socket_path = "/tmp/agent"

[[transports]]
type = "unix"
socket = "/tmp/x.sock"

[transports.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[transports.mtls]
enable = true
ca_file = "/tmp/ca.crt"
cert_file = "/tmp/server.crt"
key_file = "/tmp/server.key"

[[transports]]
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
            'mode = "proxy"\ndefault_agent_socket_path = "/tmp/agent"\n'
            '[[transports]]\ntype = "unix"\nsocket = "/tmp/x.sock"\n'
            'resolution = "tartarus"\n',
        )


def test_shipped_multi_listener_example_parses(sap: types.ModuleType) -> None:
    """The shipped multi-listener example loads and builds two listeners.

    `examples/ssh-agent-proxy-listeners.toml` is the file the multi-transport
    setup tells an operator to install, so it must load and expand to one
    `ListenerConfig` per `[[transports]]` entry, each with its own
    `resolution`/`security`. Loading the shipped file (rather than an inline
    copy) keeps the example and the parser in sync.
    """
    path = EXAMPLES_DIR / "ssh-agent-proxy-listeners.toml"

    config = sap.Config()
    config.load(str(path), mode="proxy")

    assert len(config.listeners) == 2
    vsock, unix = config.listeners
    assert [listener.transport for listener in config.listeners] == ["vsock", "unix"]
    # per-listener identity: CID-based on the callback, certificate on the SSH
    # forwarded socket.
    assert vsock.resolution == "tartarus"
    assert unix.resolution == "certificate"
    # per-listener security: the callback is unauthenticated, the unix socket is
    # mTLS (so the certificate CN names the peer).
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
    # a relative path inside a listener resolves next to the config file
    assert unix.mtls_ca_file == str(path.parent / "ca.crt")


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
default_agent_socket_path = "{upstream}"

[transport_defaults]
resolution = "none"

[transport_defaults.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[transports]]
type = "unix"
socket = "{sock_a}"

[[transports]]
type = "unix"
socket = "{sock_b}"
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
default_agent_socket_path = "/tmp/agent"

[transport_defaults]
resolution = "none"

[transport_defaults.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"

[[transports]]
type = "vsock"

[[transports]]
type = "tcp"

[transports.security]
transport_encryption = "mtls"
client_auth = "transport"
server_auth = "transport"

[transports.mtls]
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

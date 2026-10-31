"""No-CA self-signed certificate pinning (the `pubkey` Nix mode).

The `pubkey` Nix option emits a `[mtls]` block whose `ca_file` is the
concatenation of the peer's *self-signed* certificates -- there is no CA. This
only works because the leaf carries the standard ``serverAuth``/``clientAuth``
EKUs in addition to its service OID: OpenSSL rejects a self-signed leaf used as
a trust anchor with ``unsuitable certificate purpose`` otherwise.

These tests prove that premise against the real ``create_ssl_context`` in
``sudo-auth-proxy.py`` (the same context builder used by all three services):
both ends pin the other end's certificate directly and complete a TLS
handshake. A negative test shows the standard EKU is mandatory.
"""

from __future__ import annotations

import importlib.util
import shutil
import socket
import ssl
import subprocess
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "tartarus-certs.sh"
SUDO_PROXY = ROOT / "nix" / "packages" / "sudo-auth-proxy" / "sudo-auth-proxy.py"

SUDO_SERVER_OID = "1.3.6.1.4.1.99999.1.1"
SUDO_CLIENT_OID = "1.3.6.1.4.1.99999.1.2"


@pytest.fixture(scope="module")
def sap() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("sap_pubkey_certs", SUDO_PROXY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _run_certs(*arguments: str) -> None:
    subprocess.run(
        ["bash", str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )


def _selfsigned(
    cert: Path,
    key: Path,
    *,
    role: str,
    cn: str,
    service: str = "sudo-auth-proxy",
) -> None:
    _run_certs(
        "selfsigned",
        "--role",
        role,
        "--cn",
        cn,
        "--service",
        service,
        "--cert",
        str(cert),
        "--key",
        str(key),
        "--days",
        "2",
    )


def _config(
    *,
    server: bool,
    local_cert: Path,
    local_key: Path,
    peer_cert: Path,
) -> dict:
    """A minimal `[mtls]` config, as the Nix module would emit it."""
    return {
        "mode": "server" if server else "client",
        "transport": "tcp",
        "security": {
            "transport_encryption": "mtls",
            "client_auth": "transport",
            "server_auth": "transport",
        },
        "mtls": {
            "enable": True,
            # `ca_file` is the peer certificate, not a CA.
            "ca_file": str(peer_cert),
            "cert_file": str(local_cert),
            "key_file": str(local_key),
            "required_oid": SUDO_SERVER_OID if server else SUDO_CLIENT_OID,
            "peer_required_oid": SUDO_CLIENT_OID if server else SUDO_SERVER_OID,
        },
    }


def _handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext) -> dict:
    """Run one loopback TLS handshake and return the peer subjects/errors."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    result: dict = {}

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            wrapped = server_ctx.wrap_socket(conn, server_side=True)
            result["server_peer"] = wrapped.getpeercert()
            wrapped.close()
        except BaseException as error:  # noqa: BLE001 - surfaced to the test
            result["server_error"] = error

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        raw = socket.create_connection(listener.getsockname(), timeout=5)
        wrapped = client_ctx.wrap_socket(raw, server_hostname="athena")
        result["client_peer"] = wrapped.getpeercert()
        wrapped.close()
    except BaseException as error:  # noqa: BLE001 - surfaced to the test
        result["client_error"] = error
    finally:
        thread.join(timeout=5)
        listener.close()
    return result


def _common_name(peer_cert: dict) -> str:
    subject = dict(pair for rdn in peer_cert.get("subject", []) for pair in rdn)
    return subject.get("commonName", "")


def test_self_signed_certs_work_as_mutual_trust_anchors(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """Two CA:FALSE leaves pin each other directly; no CA exists."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    server_crt = tmp_path / "athena.crt"
    server_key = tmp_path / "athena.key"
    client_crt = tmp_path / "zeus.crt"
    client_key = tmp_path / "zeus.key"
    _selfsigned(server_crt, server_key, role="server", cn="athena")
    _selfsigned(client_crt, client_key, role="client", cn="zeus")

    server_ctx = sap.create_ssl_context(
        _config(
            server=True,
            local_cert=server_crt,
            local_key=server_key,
            peer_cert=client_crt,
        ),
        server=True,
    )
    client_ctx = sap.create_ssl_context(
        _config(
            server=False,
            local_cert=client_crt,
            local_key=client_key,
            peer_cert=server_crt,
        ),
        server=False,
    )
    assert server_ctx is not None and client_ctx is not None

    result = _handshake(server_ctx, client_ctx)
    assert "client_error" not in result, result.get("client_error")
    assert "server_error" not in result, result.get("server_error")
    # Each side saw the other side's self-signed identity, not a CA.
    assert _common_name(result["client_peer"]) == "athena"
    assert _common_name(result["server_peer"]) == "zeus"


def test_self_signed_missing_standard_eku_is_rejected(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """A trust anchor without serverAuth/clientAuth fails the handshake."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    server_crt = tmp_path / "athena.crt"
    server_key = tmp_path / "athena.key"
    bad_client_crt = tmp_path / "zeus.crt"
    bad_client_key = tmp_path / "zeus.key"
    _selfsigned(server_crt, server_key, role="server", cn="athena")

    # A self-signed client cert carrying ONLY the service OID (no clientAuth).
    subprocess.run(
        ["openssl", "genrsa", "-out", str(bad_client_key), "2048"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(bad_client_key),
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=zeus",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            f"extendedKeyUsage={SUDO_CLIENT_OID}",
            "-out",
            str(bad_client_crt),
        ],
        check=True,
        capture_output=True,
    )

    server_ctx = sap.create_ssl_context(
        _config(
            server=True,
            local_cert=server_crt,
            local_key=server_key,
            peer_cert=bad_client_crt,
        ),
        server=True,
    )
    client_ctx = sap.create_ssl_context(
        _config(
            server=False,
            local_cert=bad_client_crt,
            local_key=bad_client_key,
            peer_cert=server_crt,
        ),
        server=False,
    )
    assert server_ctx is not None and client_ctx is not None

    result = _handshake(server_ctx, client_ctx)
    # At least one side must refuse: the self-signed leaf is not a valid
    # client-Auth trust anchor without the standard EKU.
    assert "server_error" in result or "client_error" in result, result

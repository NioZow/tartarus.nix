"""Tests for the optional clipboard-bridge admin certificate (design Phase 5).

``tartarus ca admin`` mints a *distinct* client certificate for the clipboard
control plane. Unlike a guest client certificate, which carries all three
service client OIDs, the admin certificate carries only ``clientAuth`` plus
``OID_CLIPBOARD_ADMIN`` (``1.3.6.1.4.1.99999.3.3``). That is what lets an
admin mTLS listener require the admin EKU and reject a guest certificate.

These tests run the real ``ca.py`` code against ``openssl`` in a temp
directory, mirroring the CA permission tests in ``test_sudo_auth_proxy.py``.
"""

from __future__ import annotations

import filecmp
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parents[1] / "src"

# ca.py uses package-relative imports, so import the real ``tartarus`` package
# from ``src/`` rather than loading the file by path.
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _ca_test_config(tmp_path: Path):
    """Build the same ``Config`` shape the existing ca.py tests use."""
    from tartarus.config import Config

    return Config(
        user="user",
        home_dir=tmp_path,
        flake_path=tmp_path / "nixcfg",
        system="x86_64-linux",
        state_root=tmp_path / "state",
        ssh_dir=tmp_path / ".ssh",
        ssh_ca_dir=tmp_path / "ssh-ca",
        x509_ca_dir=tmp_path / "x509-ca",
    )


def _extended_key_usage(cert: Path) -> str:
    """Return the human-readable extendedKeyUsage line(s) of a certificate."""
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "extendedKeyUsage"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_admin_cert_has_only_admin_eku(tmp_path: Path) -> None:
    """The admin cert is 0600/0644, has ca.crt, and carries only the admin OID."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    from tartarus import ca

    config = _ca_test_config(tmp_path)
    ca._ensure_x509_ca(config)
    ca.ensure_clipboard_admin_cert(config)

    admin_dir = ca.x509_machine_dir(config, "host", "admin")
    client_key = admin_dir / "client.key"
    client_crt = admin_dir / "client.crt"
    ca_copy = admin_dir / "ca.crt"

    assert client_key.exists()
    assert stat.S_IMODE(os.lstat(client_key).st_mode) == 0o600
    assert client_crt.exists()
    assert stat.S_IMODE(os.lstat(client_crt).st_mode) == 0o644
    assert ca_copy.exists()
    assert filecmp.cmp(ca._x509_ca_crt(config), ca_copy, shallow=False)

    eku = _extended_key_usage(client_crt)
    assert ca.OID_CLIPBOARD_ADMIN in eku
    assert ca.OID_CLIPBOARD_CLIENT not in eku
    assert ca.OID_CLIPBOARD_SERVER not in eku


def test_guest_cert_does_not_carry_admin_oid(tmp_path: Path) -> None:
    """Guest client certificates keep their service OIDs and never get the admin one."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    from tartarus import ca

    config = _ca_test_config(tmp_path)
    ca._ensure_x509_ca(config)
    ca._ensure_x509_client_cert(config, "microvm", "guest")

    guest_crt = ca.x509_machine_dir(config, "microvm", "guest") / "client.crt"
    eku = _extended_key_usage(guest_crt)

    assert ca.OID_CLIPBOARD_CLIENT in eku
    assert ca.OID_CLIPBOARD_ADMIN not in eku


def test_admin_cert_is_idempotent_and_repairs_key_mode(tmp_path: Path) -> None:
    """Re-running reuses the key/cert and restores a loosened key to 0600."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    from tartarus import ca

    config = _ca_test_config(tmp_path)
    ca.ensure_clipboard_admin_cert(config)

    admin_dir = ca.x509_machine_dir(config, "host", "admin")
    client_key = admin_dir / "client.key"
    client_crt = admin_dir / "client.crt"

    key_bytes = client_key.read_bytes()
    key_inode = client_key.stat().st_ino
    crt_bytes = client_crt.read_bytes()
    crt_inode = client_crt.stat().st_ino

    client_key.chmod(0o644)  # simulate a loosened key
    ca.ensure_clipboard_admin_cert(config)

    assert stat.S_IMODE(os.lstat(client_key).st_mode) == 0o600
    # The existing material was reused, not regenerated.
    assert client_key.read_bytes() == key_bytes
    assert client_key.stat().st_ino == key_inode
    assert client_crt.read_bytes() == crt_bytes
    assert client_crt.stat().st_ino == crt_inode


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "tartarus-certs.sh"


def _run_certs(*arguments: str) -> subprocess.CompletedProcess:
    """Run ``tartarus-certs.sh`` and return the completed process."""
    return subprocess.run(
        ["bash", str(SCRIPT_PATH), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )


def test_tartarus_certs_install_and_verify_admin_without_kind(
    tmp_path: Path,
) -> None:
    """`install/verify --admin` (and `--name admin`) find machines/host/admin."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    out = tmp_path / "x509"
    dest = tmp_path / "installed"
    _run_certs("init-ca", "--out", str(out), "--bits", "2048")
    _run_certs("issue-admin", "--out", str(out), "--bits", "2048")

    _run_certs("install", "--out", str(out), "--admin", "--dest", str(dest))
    assert (dest / "client.crt").is_file()
    assert (dest / "client.key").is_file()
    assert stat.S_IMODE(os.lstat(dest / "client.key").st_mode) == 0o600

    by_flag = _run_certs("verify", "--out", str(out), "--admin")
    assert "1.3.6.1.4.1.99999.3.3" in by_flag.stdout

    by_name = _run_certs("verify", "--out", str(out), "--name", "admin")
    assert "1.3.6.1.4.1.99999.3.3" in by_name.stdout

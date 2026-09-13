"""SSH + X509 CA, implemented natively (no helper scripts, no nixcfg).

This is the Python port of the three legacy CA scripts (PLAN.md §4 Phase 4):
``microvm-ssh-setup.sh``, ``tartarus-x509-setup.sh`` and
``microvm-ssh-setup-user.sh``. Everything runs **on demand from the CLI**
(before the build/start that needs a key), never at rebuild time.

Public surface (kept stable from Phase 3):

* :func:`ensure_user_ssh`          -- the shared client key + ``known_hosts_trs``.
* :func:`ensure_ssh_host_key`      -- per-guest SSH host keypair + CA certificate.
* :func:`ensure_x509_client_cert`  -- per-guest X509 client keypair + cert.
* :func:`ensure_vm_certs`          -- the composite used by ``vm start``.
* :func:`ensure_ctn_certs`         -- the container composite used by ``ctn start``.

Only stdlib and the ``ssh-keygen`` / ``openssl`` binaries are used. Paths are
resolved through :class:`~tartarus.config.Config`, never ``$HOME`` directly.
Idempotency mirrors the scripts exactly: keys and certificates are reused
unless a file is missing (or a public key is newer than its certificate).
"""

from __future__ import annotations

import filecmp
import grp
import os
import shutil
import socket
import subprocess
from pathlib import Path

from . import ssh
from .config import Config
from .errors import TartarusError
from .output import info

# --- SSH CA ---------------------------------------------------------------

SSH_CA_NAME = "tartarus"
SSH_CA_COMMENT = "tartarus"
SSH_HOST_KEY_NAME = "ssh_host_ed25519_key"
SSH_HOST_DOMAIN = "trs"
# OpenSSH relative validity, exactly as the legacy script passed it.
SSH_CERT_VALIDITY = "+52w"

# --- X509 CA --------------------------------------------------------------

X509_CA_KEY_NAME = "tartarus.key"
X509_CA_CRT_NAME = "tartarus.crt"
X509_HOST_KEY_NAME = "server.key"
X509_HOST_CRT_NAME = "server.crt"
X509_CA_SUBJECT = "/C=US/O=Tartarus/CN=tartarus-ca"
X509_CA_DAYS = "3650"
X509_CERT_DAYS = "365"
X509_RSA_BITS = "4096"
X509_LEAF_RSA_BITS = "2048"

# Extended Key Usage OIDs (private enterprise number 99999), per service.
OID_CLIPBOARD_SERVER = "1.3.6.1.4.1.99999.3.1"
OID_CLIPBOARD_CLIENT = "1.3.6.1.4.1.99999.3.2"
OID_SSHAGENT_SERVER = "1.3.6.1.4.1.99999.2.1"
OID_SSHAGENT_CLIENT = "1.3.6.1.4.1.99999.2.2"
OID_SUDO_SERVER = "1.3.6.1.4.1.99999.1.1"
OID_SUDO_CLIENT = "1.3.6.1.4.1.99999.1.2"


def _run(cmd: list[str]) -> None:
    """Run a helper binary, raising :class:`TartarusError` with its output."""
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "(no output)"
        raise TartarusError(f"command failed ({result.returncode}): {' '.join(cmd)}\n{detail}")


def _chgrp_kvm(path: Path) -> None:
    """Best-effort ``chgrp kvm`` for the unprivileged qemu reader (Linux)."""
    try:
        gid = grp.getgrnam("kvm").gr_gid
    except KeyError:
        return
    try:
        os.chown(path, -1, gid)
    except OSError:
        # Not a member / not permitted: the script ignored this too.
        pass


# --- path helpers ---------------------------------------------------------


def ssh_machine_dir(config: Config, kind: str, name: str) -> Path:
    """Where a guest's SSH host key material lives (``microvm``/``containers``)."""
    return config.ssh_ca_dir / "machines" / kind / name


def x509_machine_dir(config: Config, kind: str, name: str) -> Path:
    """Where a guest's X509 client material lives (``microvm``/``containers``)."""
    return config.x509_ca_dir / "machines" / kind / name


def ssh_ca_pub(config: Config) -> Path:
    """The tartarus SSH CA public key used to build ``known_hosts_trs``."""
    return config.ssh_ca_dir / "ca" / f"{SSH_CA_NAME}.pub"


def _ssh_ca_key(config: Config) -> Path:
    return config.ssh_ca_dir / "ca" / SSH_CA_NAME


def _x509_ca_key(config: Config) -> Path:
    return config.x509_ca_dir / "ca" / X509_CA_KEY_NAME


def _x509_ca_crt(config: Config) -> Path:
    return config.x509_ca_dir / "ca" / X509_CA_CRT_NAME


def _x509_host_key(config: Config) -> Path:
    return config.x509_ca_dir / "host" / X509_HOST_KEY_NAME


def _x509_host_crt(config: Config) -> Path:
    return config.x509_ca_dir / "host" / X509_HOST_CRT_NAME


# --- SSH CA ---------------------------------------------------------------


def _ensure_ssh_ca(config: Config) -> Path:
    """Create the shared Ed25519 SSH CA keypair if missing; return the key."""
    ca_key = _ssh_ca_key(config)
    ca_pub = ssh_ca_pub(config)
    ca_key.parent.mkdir(parents=True, exist_ok=True)

    if ca_key.exists():
        return ca_key

    info(f"Generating shared guest SSH CA key: {ca_key}")
    _run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(ca_key),
            "-N",
            "",
            "-C",
            SSH_CA_COMMENT,
        ]
    )
    ca_key.chmod(0o600)
    ca_pub.chmod(0o644)
    return ca_key


def _sign_ssh_host_key(config: Config, kind: str, name: str) -> None:
    """Ensure a signed Ed25519 host key/cert for one guest, mirroring sign_guest."""
    ca_key = _ssh_ca_key(config)
    guest_dir = ssh_machine_dir(config, kind, name)
    guest_dir.mkdir(parents=True, exist_ok=True)

    host_key = guest_dir / SSH_HOST_KEY_NAME
    host_pub = guest_dir / f"{SSH_HOST_KEY_NAME}.pub"
    host_cert = guest_dir / f"{SSH_HOST_KEY_NAME}-cert.pub"

    if not host_key.exists():
        info(f"Generating host key for {name}...")
        _run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(host_key),
                "-N",
                "",
                "-C",
                f"host key for {name}",
            ]
        )
        host_pub.chmod(0o644)

    # Group-readable (not world) by kvm: qemu reads this straight off disk via
    # an unprivileged share. Containers bind-mount the same directory.
    _chgrp_kvm(host_key)
    host_key.chmod(0o640)

    # Sign only if the certificate is missing or the public key is newer.
    if not host_cert.exists() or host_pub.stat().st_mtime > host_cert.stat().st_mtime:
        info(f"Signing host certificate for {name} ({name}.{SSH_HOST_DOMAIN})...")
        _run(
            [
                "ssh-keygen",
                "-s",
                str(ca_key),
                "-I",
                name,
                "-h",
                "-n",
                f"{name},{name}.{SSH_HOST_DOMAIN}",
                "-V",
                SSH_CERT_VALIDITY,
                str(host_pub),
            ]
        )
        host_cert.chmod(0o644)
    else:
        info(f"Certificate up-to-date for {name}.")


# --- X509 CA --------------------------------------------------------------


def _write_extfile(path: Path, eku: str) -> None:
    path.write_text(f"[v3_ext]\nextendedKeyUsage = {eku}\n")


def _ensure_x509_ca(config: Config) -> None:
    ca_key = _x509_ca_key(config)
    ca_crt = _x509_ca_crt(config)
    ca_key.parent.mkdir(parents=True, exist_ok=True)

    if not ca_key.exists():
        info("Generating X509 root CA...")
        _run(["openssl", "genrsa", "-out", str(ca_key), X509_RSA_BITS])
        ca_key.chmod(0o600)

    if not ca_crt.exists():
        info("Generating X509 root CA certificate...")
        # -addext keyUsage is required: OpenSSL 3.x's strict chain validation
        # (on by default for Python's ssl.create_default_context) rejects a CA
        # cert with no keyUsage extension at all.
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(ca_key),
                "-sha256",
                "-days",
                X509_CA_DAYS,
                "-subj",
                X509_CA_SUBJECT,
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                str(ca_crt),
            ]
        )
        ca_crt.chmod(0o644)


def _ensure_x509_host_cert(config: Config) -> None:
    """Ensure the host's own server certificate exists (all server OIDs)."""
    host_dir = config.x509_ca_dir / "host"
    host_dir.mkdir(parents=True, exist_ok=True)
    host_key = _x509_host_key(config)
    host_crt = _x509_host_crt(config)

    if host_key.exists():
        return

    info("Generating host server certificate...")
    _run(["openssl", "genrsa", "-out", str(host_key), X509_LEAF_RSA_BITS])
    host_key.chmod(0o600)

    csr = host_dir / "server.csr"
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(host_key),
            "-subj",
            f"/C=US/O=Tartarus/CN={socket.gethostname()}",
            "-out",
            str(csr),
        ]
    )

    extfile = host_dir / "extfile.cnf"
    _write_extfile(
        extfile,
        f"serverAuth,{OID_CLIPBOARD_SERVER},{OID_SSHAGENT_SERVER},{OID_SUDO_SERVER}",
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(_x509_ca_crt(config)),
            "-CAkey",
            str(_x509_ca_key(config)),
            "-CAcreateserial",
            "-sha256",
            "-days",
            X509_CERT_DAYS,
            "-extfile",
            str(extfile),
            "-extensions",
            "v3_ext",
            "-out",
            str(host_crt),
        ]
    )
    host_crt.chmod(0o644)
    csr.unlink(missing_ok=True)
    extfile.unlink(missing_ok=True)


def _ensure_x509_client_cert(config: Config, kind: str, name: str) -> None:
    """Ensure one guest's client keypair/cert and its local ``ca.crt`` copy."""
    ca_crt = _x509_ca_crt(config)
    guest_dir = x509_machine_dir(config, kind, name)
    guest_dir.mkdir(parents=True, exist_ok=True)

    client_key = guest_dir / "client.key"
    client_crt = guest_dir / "client.crt"

    if not client_key.exists():
        info(f"Generating client key for {name} ({kind})...")
        _run(["openssl", "genrsa", "-out", str(client_key), X509_LEAF_RSA_BITS])
        # World-readable: exposed read-only to the guest, whose unprivileged
        # user must read it (mTLS trusts the CA, not root<->user).
        client_key.chmod(0o644)

        csr = guest_dir / "client.csr"
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(client_key),
                "-subj",
                f"/C=US/O=Tartarus/CN={name}",
                "-out",
                str(csr),
            ]
        )

        extfile = guest_dir / "extfile.cnf"
        _write_extfile(
            extfile,
            f"clientAuth,{OID_CLIPBOARD_CLIENT},{OID_SSHAGENT_CLIENT},{OID_SUDO_CLIENT}",
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(_x509_ca_key(config)),
                "-CAcreateserial",
                "-sha256",
                "-days",
                X509_CERT_DAYS,
                "-extfile",
                str(extfile),
                "-extensions",
                "v3_ext",
                "-out",
                str(client_crt),
            ]
        )
        client_crt.chmod(0o644)
        csr.unlink(missing_ok=True)
        extfile.unlink(missing_ok=True)
        info(f"Client cert generated for {name}: {client_crt}")
    else:
        info(f"Client cert already exists for {name}.")

    # Copy (not symlink) the CA cert into the machine directory: the directory
    # is the guest's filesystem root over 9p, so a symlink outside it cannot
    # resolve. The CA cert is public, so a copy needs no upkeep.
    ca_copy = guest_dir / "ca.crt"
    if ca_copy.is_symlink():
        ca_copy.unlink()
    if not (ca_copy.exists() and filecmp.cmp(ca_crt, ca_copy, shallow=False)):
        shutil.copyfile(ca_crt, ca_copy)
        ca_copy.chmod(0o644)


# --- public entry points --------------------------------------------------


def ensure_user_ssh(config: Config) -> None:
    """Create the shared ``~/.ssh/tartarus`` key and ``known_hosts_trs``."""
    ssh.ensure_user_ssh_key(config)
    ssh.ensure_known_hosts_trs(config, ssh_ca_pub(config))


def ensure_ssh_host_key(config: Config, kind: str, name: str) -> None:
    """Ensure a CA-signed SSH host keypair exists for the guest."""
    _ensure_ssh_ca(config)
    _sign_ssh_host_key(config, kind, name)


def ensure_x509_client_cert(config: Config, kind: str, name: str) -> None:
    """Ensure the X509 CA, host server cert and a signed client cert exist."""
    _ensure_x509_ca(config)
    _ensure_x509_host_cert(config)
    _ensure_x509_client_cert(config, kind, name)


def ensure_vm_certs(config: Config, name: str) -> None:
    """SSH + X509 material for a MicroVM's canonical instance (base name)."""
    ensure_ssh_host_key(config, "microvm", name)
    ensure_user_ssh(config)
    ensure_x509_client_cert(config, "microvm", name)


def ensure_ctn_certs(config: Config, name: str) -> None:
    """SSH + X509 material for a container's canonical instance (base name)."""
    ensure_ssh_host_key(config, "containers", name)
    ensure_user_ssh(config)
    ensure_x509_client_cert(config, "containers", name)

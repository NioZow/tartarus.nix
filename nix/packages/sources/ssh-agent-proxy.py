#!/usr/bin/env -S python3 -u

from argparse import ArgumentParser
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from enum import IntEnum
from fnmatch import fnmatchcase
from hashlib import sha256
from json import dumps as json_dumps
from logging import getLogger, basicConfig, DEBUG, INFO
from os import environ, umask
from pathlib import Path
from re import compile as re_compile
import socket
from socket import socket as Socket, AF_UNIX, SOCK_STREAM
import ssl
import threading

# AF_VSOCK is a Linux-only address family -- the macOS socket module has no
# such constant, so an unconditional `from socket import ... AF_VSOCK` crashes
# at import time on darwin. Only the VSOCK proxy path needs it; --merge mode
# never constructs a VSOCK server. Import it defensively so the module loads
# cleanly on macOS (ThreadedVsockServer is only ever instantiated on Linux).
try:
    from socket import AF_VSOCK
except ImportError:  # pragma: no cover - macOS
    AF_VSOCK = None
from socketserver import (
    BaseRequestHandler,
    TCPServer,
    ThreadingMixIn,
    UnixStreamServer,
)
from struct import pack, unpack
from subprocess import run
from sys import exit, platform as sys_platform
from tempfile import gettempdir
from threading import Lock
from time import monotonic
from tomllib import load
from typing import Any, Optional
from xml.etree import ElementTree

# Cryptography is always required for signature verification in
# session-bind and SSH agent protocol operations.
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

# PyCA cryptography is also used for EKU OID enforcement in mTLS.
import cryptography.x509 as x509

# Optional: notification support via the freedesktop org.freedesktop.Notifications
# D-Bus service. Only present on Linux; missing/absent (e.g. macOS) degrades to
# logging-only notifications.
try:
    from dbus import Byte, Interface, SessionBus
except ImportError:
    Byte = None
    Interface = None
    SessionBus = None

try:
    # Optional: only needed when `libvirt_uri` is set in the config, to
    # dynamically resolve a connecting VM's name from its (possibly
    # reassigned-on-restart) VSOCK CID. Plain libvirt introspection only --
    # no mofos-specific XML, no external CLI -- so it works for any
    # libvirt/QEMU domain with a <vsock> device, not just mofos VMs.
    # Linux-only: absent on macOS by design.
    from libvirt import open as libvirt_open, virConnect, libvirtError
except ImportError:
    libvirt_open = None
    virConnect = None
    libvirtError = Exception

# --- Constants ---
DEFAULT_VSOCK_PORT = 65000
HOST_CID = 2
# Default TCP listener. VSOCK is no longer the default: unless `vsock_port`
# is set in the config the proxy listens on TCP (host:port).
DEFAULT_TCP_BIND = "127.0.0.1:65000"


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms"


def _split_bind(bind: str) -> tuple[str, int]:
    """Split a "host:port" bind string into (host, port)."""
    try:
        host, port = bind.rsplit(":", 1)
        return host, int(port)
    except ValueError as e:
        raise ValueError(f"invalid tcp_bind {bind!r}, expected 'host:port'") from e


DEFAULT_CONFIG_PATH = "~/.config/ssh-agent-proxy/config.toml"
# Upper bound on a single agent message coming from an untrusted guest, so a
# malicious length prefix cannot make the host attempt a huge allocation/read.
MAX_AGENT_MSG_LEN = 256 * 1024
# Bound slowloris / hung upstream: recv() gives up after this many seconds.
SOCKET_TIMEOUT = 300
# In --merge mode, a single hung upstream (e.g. Apple's ssh-agent waiting on a
# keychain-unlock prompt, or a stale gpg-agent socket) must not block the whole
# merged agent for SOCKET_TIMEOUT seconds. Use a short per-upstream timeout so
# an unresponsive socket is skipped quickly instead of making `ssh-add -l`
# appear to hang.
MERGE_UPSTREAM_TIMEOUT = 5
# SSH public key algorithms accepted in config (user keys + destination host keys).
_ACCEPTED_KEY_TYPES = {
    "ssh-rsa",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}

log = getLogger("ssh-agent-proxy")

# A host/key selector that contains any of these must be evaluated with fnmatch
# instead of exact equality.
_WILDCARD_RE = re_compile(r"[*?\[\]]")


def _fingerprint(blob: bytes) -> str:
    """SHA256 fingerprint of a raw public key blob, matching `ssh-keygen -lf`
    output: "SHA256:" prefix + base64 of the digest with '=' padding stripped."""
    digest = b64encode(sha256(blob).digest()).decode("utf8").rstrip("=")
    return f"SHA256:{digest}"


# --- Data Modeling ---
@dataclass(frozen=True)
class KeyConfig:
    """An SSH key the proxy can expose. Identity only; usage is governed by rules."""

    id: str
    key_type: str
    public_blob: bytes
    fingerprint: str
    socket: str


@dataclass(frozen=True)
class Rule:
    """A policy binding: which VMs may use which key, and how.

    A rule matches a (key, VM) pair when the key selector matches (an id or "*")
    and the VM selector matches (vm_names; an empty selector matches any VM).
    Rules are evaluated in file order and the first match wins -- it fully
    defines the policy, there is no merging between rules.
    """

    key: str  # a key id, or "*" for any key
    vm_names: list[str] = field(default_factory=list)
    auth: str = "ask"  # "deny" | "ask" | "allow"
    data_signing: str = "deny"  # "deny" | "ask" | "allow"
    notify: bool = True
    allowed_host_keys: set[bytes] = field(default_factory=set)

    def matches_key(self, key_id: str) -> bool:
        if not _WILDCARD_RE.search(self.key):
            return self.key == "*" or self.key == key_id
        return fnmatchcase(key_id, self.key)

    def matches_vm(self, vm_name: str) -> bool:
        if not self.vm_names:
            return True  # empty selector -> any VM
        return any(fnmatchcase(vm_name, pattern) for pattern in self.vm_names)


# Fallback policy for a key that isn't governed by any explicit `rule` (see
# `forward_sockets`): any key, any VM, prompt before use, never sign arbitrary
# data. Keeps the proxy usable out of the box with zero `key`/`rule` config --
# explicit rules only need to be added to *override* this for specific keys
# (e.g. allow one without prompting, or restrict/deny it).
DEFAULT_RULE = Rule(key="*")


class KnownHosts:
    """Resolve a hostname or host pattern to its host public key blob(s) from
    known_hosts files.

    Supports plaintext, hashed (|1|salt|hash) entries, and @cert-authority
    lines (used to trust all hosts signed by an SSH CA). Marker lines that do
    not grant a trust relationship (@revoked) are skipped -- those are not
    usable destination host keys here.
    """

    def __init__(self) -> None:
        self._plain: dict[str, set[bytes]] = {}
        self._hashed: list[tuple[bytes, bytes, bytes]] = []  # (salt, hash, blob)
        # @cert-authority lines: (pattern, CA public key blob)
        self._authority: list[tuple[str, bytes]] = []

    def load(self, paths: list[str]) -> None:
        for p in paths:
            path = Path(p).expanduser()
            try:
                text = path.read_text("utf-8", "replace")
            except OSError as e:
                log.warning(f"known_hosts: cannot read {path}: {e}")
                continue
            for line in text.splitlines():
                self._add_line(line)
            log.debug(f"known_hosts: loaded {path}")

    def _add_line(self, line: str) -> None:
        line = line.strip()
        if not line or line.startswith("#"):
            return
        parts = line.split()
        if parts[0].startswith("@"):
            if parts[0] == "@cert-authority" and len(parts) >= 4:
                keytype, blob_b64 = parts[2], parts[3]
                if keytype in _ACCEPTED_KEY_TYPES:
                    try:
                        blob = b64decode(blob_b64)
                    except Exception:
                        return
                    self._authority.append((parts[1], blob))
            return  # any other marker (@revoked, ...) grants no trust
        if len(parts) < 3:
            return  # malformed
        host_field, keytype, blob_b64 = parts[0], parts[1], parts[2]
        if keytype not in _ACCEPTED_KEY_TYPES:
            return
        try:
            blob = b64decode(blob_b64)
        except Exception:
            return
        if host_field.startswith("|1|"):
            try:
                _, _, salt_b64, hash_b64 = host_field.split("|")
                self._hashed.append((b64decode(salt_b64), b64decode(hash_b64), blob))
            except Exception:
                return
        else:
            for pattern in host_field.split(","):
                self._plain.setdefault(pattern, set()).add(blob)

    def lookup(self, hostname: str) -> set[bytes]:
        blobs = set(self._plain.get(hostname, set()))
        for salt, digest, blob in self._hashed:
            h = crypto_hmac.HMAC(salt, hashes.SHA1())
            h.update(hostname.encode("utf-8"))
            try:
                h.verify(digest)
                blobs.add(blob)
            except InvalidSignature:
                pass
        return blobs

    def resolve(self, pattern: str) -> set[bytes]:
        """Resolve an exact hostname or a wildcard pattern to a set of trusted
        destination key blobs.

        Blobs are drawn only from the (trusted) known_hosts files: exact
        hostnames use the explicit/plain + hashed lookup, while patterns also
        pull in the CA public keys from matching @cert-authority lines and the
        explicit plain entries whose stored host pattern matches the query. An
        empty result means nothing is trusted -- the caller fails closed.
        """
        blobs: set[bytes] = set()
        is_pattern = _WILDCARD_RE.search(pattern) is not None

        for auth_pattern, ca_blob in self._authority:
            matched = fnmatchcase(pattern, auth_pattern) or (
                is_pattern and fnmatchcase(auth_pattern, pattern)
            )
            if matched:
                blobs.add(ca_blob)

        for stored, stored_blobs in self._plain.items():
            if _WILDCARD_RE.search(stored) or is_pattern:
                if fnmatchcase(stored, pattern) or fnmatchcase(pattern, stored):
                    blobs |= stored_blobs

        if not is_pattern:
            blobs |= self.lookup(pattern)

        return blobs


class Config:
    def __init__(self) -> None:
        self.mode: Optional[str] = None
        self.merge_sockets: list[str] = []
        self.listen_socket: Optional[str] = None
        self.transport: str = "tcp"
        self.host: str = "127.0.0.1"
        self.port: int = DEFAULT_VSOCK_PORT
        self.cid: int = HOST_CID

        self.dialog_program: Optional[str] = None

        self.mtls_enable: bool = False
        self.mtls_ca_file: Optional[str] = None
        self.mtls_cert_file: Optional[str] = None
        self.mtls_key_file: Optional[str] = None
        self.mtls_required_oid: Optional[str] = None
        self.mtls_peer_required_oid: Optional[str] = None

        self.vsock_port: int = DEFAULT_VSOCK_PORT
        # "host:port" to listen on over TCP, or None to use VSOCK instead.
        self.tcp_bind: Optional[str] = None
        # How to resolve a connecting VM's name: "none" | "certificate" |
        # "tartarus". None (unset in config) means "not loaded yet"; load()
        # resolves it to "certificate" if mtls_enable else "tartarus" unless
        # the config sets it explicitly. Proxy-mode only.
        self.resolution: Optional[str] = None
        self.default_agent_socket_path: Optional[str] = environ.get("SSH_AUTH_SOCK")
        # Upstream agent sockets whose identities are forwarded to every VM by
        # default (DEFAULT_RULE: ask, no data signing) -- no `key`/`rule`
        # entries required. None (unset in config) means "not loaded yet";
        # `load()` resolves it to [default_agent_socket_path] unless the
        # config explicitly sets forward_sockets (including explicitly to []
        # to disable auto-forwarding entirely).
        self.forward_sockets: list[str] = []
        self.keys: dict[bytes, KeyConfig] = {}
        self.rules: list[Rule] = []
        # VSOCK CID -> VM name, statically declared in config (e.g. generated
        # by modules/virtualisation/microvm/, whose CIDs are fixed at build
        # time). Checked first since it's a plain dict lookup.
        self.vm_by_cid: dict[int, str] = {}
        # Peer IP -> VM name, for the TCP listener. Only meaningful when the
        # proxy is reached over TCP (guests' source IPs on the bridge).
        self.vm_by_ip: dict[str, str] = {}
        # Optional fallback for VMs whose CID isn't statically known/stable
        # (e.g. mofos VMs, whose CID can change across restarts): a libvirt
        # connection URI to query live on a cache miss. None disables it.
        self.libvirt_uri: Optional[str] = None
        # known_hosts files: resolve a hostname in allowed_host_keys to its key(s).
        self.known_hosts = KnownHosts()

    def _parse_host_keys(self, entries: list[str]) -> set[bytes]:
        host_keys: set[bytes] = set()
        for entry in entries:
            entry = entry.strip()
            first = entry.split()[0] if entry else ""
            if first in _ACCEPTED_KEY_TYPES:
                # a literal "keytype base64 [comment]" public key
                _, blob, fp = self._parse_pubkey(entry)
                host_keys.add(blob)
                log.debug(f"Registered allowed destination host key {fp}")
            elif entry:
                # a hostname or wildcard pattern -> resolve its key(s) via the
                # trusted known_hosts files (includes SSH CA authorities).
                found = self.known_hosts.resolve(entry)
                if not found:
                    log.warning(
                        f"allowed_host_keys: no known_hosts entry for host/pattern {entry!r}"
                    )
                host_keys |= found
                log.debug(f"Resolved host/pattern {entry!r} -> {len(found)} host key(s)")
        return host_keys

    def load(self, config_file: str, mode: Optional[str] = None) -> None:
        p = Path(config_file).expanduser()
        if not p.is_absolute():
            p = p.resolve()
        config_dir = p.parent
        log.debug(f"Loading configuration from {p}")

        with p.open("rb") as fp:
            data = load(fp)

        def resolve(value):
            if not isinstance(value, str):
                return value
            if value.startswith("%t/"):
                # %t/... is a runtime placeholder (XDG_RUNTIME_DIR on Linux,
                # DARWIN_USER_TEMP_DIR on macOS), expanded later by
                # _expand_socket_path. Do NOT resolve it relative to the config
                # dir -- that would embed a literal %t directory in the path.
                return value
            if value.startswith("~/"):
                return environ.get("HOME", str(Path.home())) + value[1:]
            pth = Path(value)
            if not pth.is_absolute():
                return str(config_dir / pth)
            return str(pth)

        self.mode = data.get("mode", self.mode)
        if mode is not None:
            self.mode = mode
        self.merge_sockets = data.get("merge_sockets", self.merge_sockets)
        self.listen_socket = resolve(data.get("listen_socket", self.listen_socket))
        self.transport = data.get("transport", self.transport)
        self.host = data.get("host", self.host)
        self.port = data.get("port", self.port)
        self.cid = data.get("cid", self.cid)
        self.dialog_program = data.get("dialog_program", self.dialog_program)

        mtls = data.get("mtls", {})
        if isinstance(mtls, dict):
            self.mtls_enable = mtls.get("enable", False)
            self.mtls_ca_file = resolve(mtls.get("ca_file"))
            self.mtls_cert_file = resolve(mtls.get("cert_file"))
            self.mtls_key_file = resolve(mtls.get("key_file"))
            self.mtls_required_oid = mtls.get("required_oid")
            self.mtls_peer_required_oid = mtls.get("peer_required_oid")

        # Client mode is a pure forwarder: it needs only the transport,
        # destination address/port and mTLS material to reach the host's proxy.
        # Everything below (vsock/tcp listener, SSH_AUTH_SOCK, VM/key/rule
        # policy) is proxy-only and must not be parsed for a client, so a
        # minimal client config cannot fail to load (e.g. on SSH_AUTH_SOCK).
        if self.mode == "client":
            log.info(
                f"Loaded client config from {p}: "
                f"transport={self.transport}, connect to {self.host}:{self.port}, "
                f"cid={self.cid}, listen_socket={self.listen_socket}, "
                f"mtls={self.mtls_enable}"
            )
            return

        self.vsock_port = data.get("vsock_port", DEFAULT_VSOCK_PORT)
        tcp_bind = data.get("tcp_bind")
        if tcp_bind is not None:
            _split_bind(str(tcp_bind))
        self.tcp_bind = tcp_bind
        self.default_agent_socket_path = resolve(
            data.get("default_agent_socket_path", self.default_agent_socket_path)
        )
        self.libvirt_uri = data.get("libvirt_uri")
        if self.libvirt_uri and libvirt_open is None:
            raise ValueError(
                "libvirt_uri is set but the `libvirt` python module isn't "
                "installed -- add it to the ssh-agent-proxy package's pythonEnv"
            )

        self.resolution = data.get("resolution", self.resolution)
        if self.resolution not in (None, "none", "certificate", "tartarus"):
            raise ValueError(f"invalid resolution: {self.resolution!r}")
        if self.resolution is None:
            self.resolution = "certificate" if self.mtls_enable else "tartarus"

        log.debug(
            f"Config: mode={self.mode}, vsock_port={self.vsock_port}, "
            f"default_socket={self.default_agent_socket_path}, libvirt_uri={self.libvirt_uri}, "
            f"resolution={self.resolution}"
        )

        if not self.default_agent_socket_path:
            raise ValueError(
                "Failed to load path to the actual SSH agent socket (SSH_AUTH_SOCK empty)"
            )

        forward_sockets = data.get("forward_sockets")
        if forward_sockets is None:
            # Not set at all -> auto-forward the default agent socket, so the
            # proxy is useful with zero key/rule config. Set forward_sockets
            # explicitly (even to []) to opt out of this.
            self.forward_sockets = (
                [self.default_agent_socket_path] if self.default_agent_socket_path else []
            )
        else:
            self.forward_sockets = [resolve(s) for s in forward_sockets]

        for entry in data.get("vm", []):
            cid = entry.get("cid")
            name = entry.get("name")
            if not isinstance(cid, int) or cid <= HOST_CID:
                raise ValueError(f"vm entry has invalid cid: {cid!r}")
            if not name:
                raise ValueError(f"vm entry for cid {cid} is missing a name")
            if cid in self.vm_by_cid:
                raise ValueError(f"Duplicate vm cid {cid}: already bound to {self.vm_by_cid[cid]!r}")
            self.vm_by_cid[cid] = name
            log.debug(f"Registered VM {name!r} at CID {cid}")

        for entry in data.get("tcp_vm", []):
            ip = entry.get("ip")
            name = entry.get("name")
            if not isinstance(ip, str) or not ip:
                raise ValueError(f"tcp_vm entry is missing an ip: {entry!r}")
            if not name:
                raise ValueError(f"tcp_vm entry for {ip!r} is missing a name")
            self.vm_by_ip[ip] = name
            log.debug(f"Registered VM {name!r} at peer IP {ip}")

        # Load known_hosts first so allowed_host_keys can reference hostnames.
        self.known_hosts.load([resolve(path) for path in data.get("known_hosts_files", [])])

        for entry in data.get("key", []):
            socket_path = resolve(entry.get("socket", self.default_agent_socket_path))
            k_type, blob, fingerprint = self._parse_pubkey(entry.get("pubkey", ""))

            if blob in self.keys:
                existing_id = self.keys[blob].id
                raise ValueError(
                    f"Duplicate public key: '{entry.get('id')}' is identical to '{existing_id}'."
                )

            self.keys[blob] = KeyConfig(
                id=entry.get("id", "unnamed-key"),
                key_type=k_type,
                public_blob=blob,
                fingerprint=fingerprint,
                socket=socket_path,
            )
            log.debug(f"Registered key {entry.get('id')} ({fingerprint})")

        key_ids = {k.id for k in self.keys.values()}
        for entry in data.get("rule", []):
            key_sel = entry.get("key", "*")
            if key_sel != "*" and key_sel not in key_ids:
                raise ValueError(f"rule references unknown key {key_sel!r}")
            match = entry.get("match", {})
            self.rules.append(
                Rule(
                    key=key_sel,
                    vm_names=match.get("vm_names", []),
                    auth=self._policy(entry, "auth", "ask"),
                    data_signing=self._policy(entry, "data_signing", "deny"),
                    notify=entry.get("notify", True),
                    allowed_host_keys=self._parse_host_keys(
                        entry.get("allowed_host_keys", [])
                    ),
                )
            )

        log.info(
            f"Loaded {len(self.keys)} key(s) and {len(self.rules)} rule(s) from {p}"
        )

    @staticmethod
    def _policy(entry: dict[str, Any], field: str, default: str) -> str:
        val = entry.get(field, default)
        if val not in ("deny", "ask", "allow"):
            raise ValueError(
                f"rule for key {entry.get('key')!r}: "
                f"{field} must be deny|ask|allow, got {val!r}"
            )
        return val

    def _parse_pubkey(self, line: str) -> tuple[str, bytes, str]:
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"Invalid public key line: {line}")

        key_type = parts[0]
        if key_type not in _ACCEPTED_KEY_TYPES:
            raise ValueError(f"Unsupported key type: {key_type}")

        try:
            public_blob = b64decode(parts[1])
        except Exception as e:
            raise ValueError(f"Failed to decode base64 for key: {line}") from e

        return key_type, public_blob, _fingerprint(public_blob)


# --- Protocol Helpers ---


class SSHBuffer:
    """Helper class to parse SSH protocol wire format."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read_int(self) -> int:
        val = unpack(">I", self.data[self.offset : self.offset + 4])[0]
        self.offset += 4
        return val

    def read_string(self) -> bytes:
        length = self.read_int()
        val = self.data[self.offset : self.offset + length]
        self.offset += length
        return val

    def read_byte(self) -> int:
        val = self.data[self.offset]
        self.offset += 1
        return val

    def read_mpint(self) -> int:
        data = self.read_string()
        return int.from_bytes(data, "big") if data else 0

    def has_data(self) -> bool:
        return self.offset < len(self.data)


class AgentMsg(IntEnum):
    FAILURE = 5
    SUCCESS = 6
    REQUEST_IDENTITIES = 11
    IDENTITIES_ANSWER = 12
    SIGN_REQUEST = 13
    SIGN_RESPONSE = 14
    EXTENSION = 27


# --- OS & System Utilities ---


def _expand_socket_path(path: str) -> str:
    """Expand platform-specific placeholders in socket paths.

    Supported placeholders:
      - __APPLE_SSH_AUTH_SOCK__  -> launchctl SSH_AUTH_SOCK (macOS only)
      - %t                       -> $XDG_RUNTIME_DIR (Linux) or
                                    DARWIN_USER_TEMP_DIR (macOS)
      - ~                        -> user home directory
    """
    if path == "__APPLE_SSH_AUTH_SOCK__":
        import subprocess

        # Ask launchd for the per-session SSH_AUTH_SOCK pointing at the
        # com.apple.launchd.* Unix socket.
        res = subprocess.run(
            ["/bin/launchctl", "getenv", "SSH_AUTH_SOCK"],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
        # Fallback: use the well-known path on modern macOS versions.
        return "/var/run/com.apple.launchd/Listeners"
    if path.startswith("%t/"):
        if sys_platform == "darwin":
            import subprocess

            result = subprocess.run(
                ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"],
                capture_output=True,
                text=True,
            )
            runtime_dir = result.stdout.strip() if result.returncode == 0 else gettempdir()
        else:
            runtime_dir = environ.get("XDG_RUNTIME_DIR", "/run/user/" + str(environ.get("UID", 0)))
        path = f"{runtime_dir}/{path[3:]}"
    return str(Path(path).expanduser())


def resolve_default_gateway() -> str:
    """Read the default IPv4 gateway from /proc/net/route.

    Guests behind macOS's QEMU vmnet-shared get a DHCP-assigned subnet that
    isn't known at config-generation time -- it shifts depending on what
    else on the host is using vmnet (e.g. 192.168.2.0/24 instead of the
    usual 192.168.64.0/24 if that range is already taken). The host is
    always reachable at that subnet's gateway, so resolving it at connect
    time is the only way a static guest config can keep working across
    reboots/subnet changes. Used when the client config sets host = "_gateway".
    """
    with open("/proc/net/route") as f:
        next(f)  # header line
        for line in f:
            fields = line.split()
            if len(fields) < 3:
                continue
            _iface, dest, gateway = fields[0], fields[1], fields[2]
            if dest == "00000000":
                return socket.inet_ntoa(pack("<L", int(gateway, 16)))
    raise RuntimeError("no default gateway found in /proc/net/route")


class LibvirtResolver:
    """Dynamic CID -> VM name lookup via a live libvirt connection.

    Fallback for VMs not in the statically-declared `vm` table -- notably
    mofos VMs, whose CID isn't guaranteed stable across restarts. Always
    queries live (no caching), so a reassigned CID is picked up immediately.
    Reads the domain's own <devices><vsock><cid address="N"/> XML, so it
    works for any libvirt/QEMU domain with a vsock device, not just mofos.
    """

    _conn: Optional["virConnect"] = None
    _lock = Lock()

    @classmethod
    def _get_connection(cls, uri: str) -> "virConnect":
        with cls._lock:
            if cls._conn is None:
                cls._conn = libvirt_open(uri)
            else:
                try:
                    cls._conn.getLibVersion()
                except libvirtError:
                    log.debug("Libvirt connection lost, reconnecting...")
                    cls._conn = libvirt_open(uri)
            return cls._conn

    @classmethod
    def resolve_cid(cls, uri: str, cid: int) -> Optional[str]:
        try:
            conn = cls._get_connection(uri)
            for dom in conn.listAllDomains():
                try:
                    xml = ElementTree.fromstring(dom.XMLDesc())
                except ElementTree.ParseError:
                    continue
                cid_el = xml.find("./devices/vsock/cid")
                if cid_el is not None and cid_el.get("address") == str(cid):
                    return dom.name()
        except libvirtError as e:
            log.error(f"Libvirt error resolving CID {cid}: {e}")
            with cls._lock:
                cls._conn = None
        except Exception:
            log.exception(f"Unexpected error resolving CID {cid} via libvirt")
        return None


def notify(title: str, message: str, critical: bool = False) -> None:
    if SessionBus is None:
        log.warning(f"{title}: {message}")
        return
    try:
        urgency = Byte(2) if critical else Byte(1)
        timeout = 0 if critical else -1
        bus = SessionBus()
        obj = bus.get_object(
            "org.freedesktop.Notifications", "/org/freedesktop/Notifications"
        )
        interface = Interface(obj, "org.freedesktop.Notifications")
        interface.Notify(
            "ssh-agent-proxy",
            0,
            "dialog-information" if not critical else "dialog-warning",
            title,
            message,
            [],
            {"urgency": urgency},
            timeout,
        )
    except Exception as e:
        log.warning(f"Notification failed: {e}")


def prompt_for_confirmation(title: str, message: str, dialog_program: str) -> bool:
    """Ask the user to authorize an operation. Returns True if approved.

    `dialog_program` picks the confirmation mechanism explicitly (one of
    "swiftdialog", "osascript", "zenity") -- set via config, not
    auto-detected. Detecting swiftDialog at request time meant spawning a
    throwaway "dialog" subprocess before the real one on every single
    request, which noticeably delayed the prompt appearing.
    """
    if dialog_program == "swiftdialog":
        res = run(
            [
                "dialog",
                "--title", "Privilege Elevation",
                "--message", message.replace("\n", "  "),
                # Bare "lock.shield.fill" isn't a valid --icon value (it's
                # neither a file path nor a builtin keyword), so swiftDialog
                # silently fell back to its own logo -- a speech-bubble icon
                # that reads as a chat message, not an auth prompt. SF
                # Symbols require the "SF=" prefix.
                "--icon", "SF=lock.shield.fill,colour=accent,weight=medium",
                "--iconsize", "70",
                "--iconalttext", "Authentication required",
                "--button1text", "Authorize",
                "--button2text", "Deny",
                "--width", "480",
                "--height", "260",
                "--ontop",
                "--blurscreen",
                "--messagefont", "size=15",
                "--titlefont", "size=20,weight=heavy",
                "--centericon",
                "--position", "center",
            ],
            capture_output=True,
        )
        return res.returncode == 0

    if dialog_program == "osascript":
        script = (
            f'display dialog {json_dumps(message)} with title '
            f'{json_dumps(title)} with icon caution '
            'buttons {"No", "Yes"} default button "Yes" cancel button "No"'
        )
        res = run(
            ["osascript", "-e", script],
            capture_output=True,
        )
        return res.returncode == 0

    if dialog_program == "zenity":
        res = run(
            [
                "zenity",
                "--title",
                title,
                "--question",
                "--no-markup",
                "--text",
                message,
                "--ok-label",
                "Authorize",
                "--cancel-label",
                "Deny",
            ],
            capture_output=True,
        )
        return res.returncode == 0

    raise ValueError(f"unknown dialog_program: {dialog_program!r}")


# --- mTLS / EKU Helpers ---


def _cert_has_oid(cert: "x509.Certificate", oid: str) -> bool:
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return any(eku.dotted_string == oid for eku in ekus)
    except x509.ExtensionNotFound:
        return False


def verify_cert_file(path: str, oid: str, label: str) -> None:
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate {path} missing required EKU OID {oid}")


def verify_cert_der(der: bytes, oid: str, label: str) -> None:
    cert = x509.load_der_x509_certificate(der)
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate missing required EKU OID {oid}")


def _cert_common_name(cert: dict) -> Optional[str]:
    """Extract the subject commonName from ssl.SSLSocket.getpeercert()'s
    dict form (as opposed to the DER form used for OID verification)."""
    subject = dict(rdn[0] for rdn in cert.get("subject", ()))
    return subject.get("commonName")


def resolve_peer_name(
    resolution: str,
    ssl_ctx: Optional[ssl.SSLContext],
    request: Any,
    static_name: Optional[str],
    unknown_label: str,
) -> str:
    """Resolve a connecting peer's VM name per the configured `resolution` mode.

    `static_name` is whatever the caller already looked up from the static
    vm_by_cid/vm_by_ip table (+ LibvirtResolver fallback for VSOCK) -- the
    "tartarus" strategy's answer, precomputed since it differs by address
    family. `unknown_label` (e.g. "unknown-cid-7") is used when nothing
    resolves, or unconditionally when resolution is "none".
    """
    if resolution == "none":
        return unknown_label
    if resolution == "certificate" and ssl_ctx and hasattr(request, "getpeercert"):
        cert = request.getpeercert()
        if cert:
            cn = _cert_common_name(cert)
            if cn:
                return cn
    if static_name is not None:
        return static_name
    log.warning(f"Connection from unresolvable peer; no rule can match it ({unknown_label})")
    return unknown_label


def create_ssl_context(config: Config, *, server: bool) -> Optional[ssl.SSLContext]:
    if not config.mtls_enable:
        return None
    ca_file = config.mtls_ca_file
    cert_file = config.mtls_cert_file
    key_file = config.mtls_key_file

    if not all([ca_file, cert_file, key_file]):
        log.error("mTLS enabled but missing ca_file, cert_file, or key_file")
        exit(1)

    required_oid = config.mtls_required_oid
    if required_oid:
        try:
            verify_cert_file(cert_file, required_oid, "Local")
        except (ValueError, RuntimeError) as e:
            log.error(f"ssh-agent-proxy: {e}")
            exit(1)

    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose)
    if not server:
        # Peer identity here is enforced by the EKU OID check above/below
        # (verify_cert_file/verify_cert_der against the shared CA), not by
        # hostname/IP matching -- the guest's host address is a DHCP lease
        # under macOS vmnet-shared (or a VSOCK CID, not a hostname at all)
        # and the server cert's CN is a template name, not an address, so
        # standard hostname verification can never succeed here and isn't
        # the actual trust mechanism in use.
        context.check_hostname = False
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


# --- Request Handler ---


class AgentIO:
    """Shared SSH agent protocol framing, used by both the policy-enforcing
    vsock Handler, the allow-all merge Handler, and the client Handler."""

    def _recv_exactly(self, sock: socket, n: int) -> Optional[bytes]:
        """Read exactly n bytes, looping over short reads. None on EOF."""
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _recv_msg(self, sock: socket) -> Optional[bytes]:
        try:
            rawlen = self._recv_exactly(sock, 4)
            if not rawlen:
                return None
            length = unpack(">I", rawlen)[0]
            if length == 0:
                return b""
            if length > MAX_AGENT_MSG_LEN:
                log.warning(
                    f"Rejecting oversized agent message ({length} bytes) from {getattr(self, 'vm_name', '?')}"
                )
                return None
            return self._recv_exactly(sock, length)
        except Exception as e:
            log.debug(f"Socket receive error: {e}")
            return None

    def _send_msg(self, sock: socket, payload: bytes) -> None:
        sock.sendall(pack(">I", len(payload)) + payload)

    def _pipe(self, a: socket, b: socket) -> None:
        """Bidirectionally forward raw data between two stream sockets."""

        def forward(src: socket, dst: socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except (OSError, ConnectionResetError, BrokenPipeError):
                pass
            finally:
                try:
                    src.shutdown(socket.SHUT_RD)
                except OSError:
                    pass
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=forward, args=(b, a))
        t.start()
        forward(a, b)
        t.join()


class Handler(AgentIO, BaseRequestHandler):
    def setup(self) -> None:
        t0 = monotonic()
        self.config: Config = self.server.app_config
        self._abort = False

        ssl_ctx = getattr(self.server, "ssl_context", None)
        if ssl_ctx:
            peer_oid = getattr(self.server, "_mtls_config", {}).get("peer_required_oid")
            if peer_oid and hasattr(self.request, "getpeercert"):
                der = self.request.getpeercert(binary_form=True)
                if der:
                    try:
                        verify_cert_der(der, peer_oid, "Peer")
                    except (ValueError, RuntimeError) as e:
                        log.warning(f"ssh-agent-proxy: {e}")
                        self._abort = True
                        return

        address_family = getattr(self.server, "address_family", AF_UNIX)
        resolution = self.config.resolution
        if address_family == AF_VSOCK:
            cid, _ = self.client_address
            static_name = self.config.vm_by_cid.get(cid)
            if static_name is None and self.config.libvirt_uri:
                static_name = LibvirtResolver.resolve_cid(self.config.libvirt_uri, cid)
            self.vm_name = resolve_peer_name(
                resolution, ssl_ctx, self.request, static_name, f"unknown-cid-{cid}"
            )
        else:
            # TCP listener: a guest's source IP is not a reliable identity --
            # under macOS vmnet-shared it's a DHCP lease that can differ from
            # what was known at config-generation time (see the tcp_vm
            # option's docstring), so an IP-based mapping can silently never
            # match there.
            peer_ip = self.client_address[0]
            static_name = self.config.vm_by_ip.get(peer_ip)
            self.vm_name = resolve_peer_name(
                resolution, ssl_ctx, self.request, static_name, f"unknown-ip-{peer_ip}"
            )
        log.debug(
            f"setup: resolved vm_name={self.vm_name!r} (resolution={resolution}) "
            f"in {_ms(monotonic() - t0)}"
        )
        self.allowed_keys_for_client: dict[bytes, KeyConfig] = {}
        self.allowed_sockets: list[str] = []
        # session identifier -> verified target host key (from session-bind)
        self.bound_destinations: dict[bytes, bytes] = {}
        # usable key blob -> the rule that governs its use for this VM
        self.key_rule: dict[bytes, Rule] = {}

        for blob, k_cfg in self.config.keys.items():
            rule = self._match_rule(k_cfg.id)
            if rule is None:
                continue
            self.allowed_keys_for_client[blob] = k_cfg
            self.key_rule[blob] = rule
            if k_cfg.socket not in self.allowed_sockets:
                self.allowed_sockets.append(k_cfg.socket)

        # forward_sockets are always probed, regardless of whether any
        # explicit rule matched above -- identities coming back from them are
        # admitted opportunistically in _handle_identities/_maybe_autoregister,
        # governed by an explicit rule if one matches or DEFAULT_RULE otherwise.
        for sock_path in self.config.forward_sockets:
            if sock_path not in self.allowed_sockets:
                self.allowed_sockets.append(sock_path)

        log.debug(
            f"Client {self.vm_name} initialized with "
            f"{len(self.allowed_keys_for_client)} pre-ruled key(s) via "
            f"{len(self.allowed_sockets)} agent socket(s)"
        )

    def _match_rule(self, key_id: str) -> Optional[Rule]:
        # First rule (in file order) matching this key and VM defines the policy.
        for rule in self.config.rules:
            if rule.matches_key(key_id) and rule.matches_vm(self.vm_name):
                return rule
        return None

    def _maybe_autoregister(
        self, key_blob: bytes, comment: bytes, socket_path: str
    ) -> Optional[KeyConfig]:
        """Admit a key discovered from an upstream agent that wasn't already
        pre-ruled in setup() (see forward_sockets). Only keys arriving from a
        forward_sockets upstream are eligible. A configured `key` entry for
        this blob keeps its declared id (so rules can target it reliably even
        without a match at connection setup, e.g. a rule scoped to a different
        VM); an unrecognized blob is named after its agent comment (falling
        back to its fingerprint). Either way, the first explicit rule matching
        that id and this VM governs it, or DEFAULT_RULE if none matches.
        """
        if socket_path not in self.config.forward_sockets:
            return None

        named = self.config.keys.get(key_blob)
        if named is not None:
            k_cfg = named
        else:
            fingerprint = _fingerprint(key_blob)
            key_id = comment.decode("utf-8", "replace") or fingerprint
            key_type = SSHBuffer(key_blob).read_string().decode("utf-8", "replace")
            k_cfg = KeyConfig(
                id=key_id,
                key_type=key_type,
                public_blob=key_blob,
                fingerprint=fingerprint,
                socket=socket_path,
            )

        rule = self._match_rule(k_cfg.id) or DEFAULT_RULE
        self.allowed_keys_for_client[key_blob] = k_cfg
        self.key_rule[key_blob] = rule
        log.debug(
            f"Auto-registered forwarded key {k_cfg.id!r} ({k_cfg.fingerprint}) "
            f"via {socket_path} for {self.vm_name} (rule auth={rule.auth})"
        )
        return k_cfg

    def handle(self) -> None:
        if self._abort:
            return

        client = self.request
        client.settimeout(SOCKET_TIMEOUT)
        log.info(f"Connection from {self.vm_name}")

        real_agents = {}
        for path in self.allowed_sockets:
            try:
                sock = Socket(AF_UNIX, SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect(path)
                real_agents[path] = sock
                log.debug(f"Connected to upstream agent at {path}")
            except Exception as e:
                log.error(f"Could not connect to real agent at {path}: {e}")

        try:
            while True:
                msg = self._recv_msg(client)
                if not msg:
                    break

                mtype = msg[0]
                mname = (
                    AgentMsg(mtype).name
                    if mtype in list(AgentMsg)
                    else f"UNKNOWN({mtype})"
                )
                log.debug(f"Received {mname} from {self.vm_name}")

                match mtype:
                    case AgentMsg.REQUEST_IDENTITIES:
                        self._handle_identities(client, msg, real_agents)
                    case AgentMsg.SIGN_REQUEST:
                        self._handle_sign_request(client, msg, real_agents)
                    case AgentMsg.EXTENSION:
                        self._handle_extension(client, msg)
                    case _:
                        self._handle_unknown(client, mtype)
        except Exception:
            log.exception("Error in client handler loop")
        finally:
            for s in real_agents.values():
                s.close()
            client.close()
            log.debug(f"Connection with {self.vm_name} closed")

    def _handle_identities(
        self, client: socket, raw_msg: bytes, real_agents: dict[str, socket]
    ) -> None:
        aggregated_identities = []
        for path, sock in real_agents.items():
            self._send_msg(sock, raw_msg)
            resp = self._recv_msg(sock)
            if not resp or resp[0] != AgentMsg.IDENTITIES_ANSWER:
                continue

            buf = SSHBuffer(resp)
            buf.read_byte()
            count = buf.read_int()
            log.debug(f"Upstream {path} returned {count} identities")

            for _ in range(count):
                key_blob = buf.read_string()
                comment = buf.read_string()
                admitted = key_blob in self.allowed_keys_for_client or self._maybe_autoregister(
                    key_blob, comment, path
                )
                if admitted:
                    if (key_blob, comment) not in aggregated_identities:
                        aggregated_identities.append((key_blob, comment))
                else:
                    log.debug(
                        f"Filtered out unauthorized identity from upstream: {comment.decode(errors='replace')}"
                    )

        payload = pack(">BI", AgentMsg.IDENTITIES_ANSWER, len(aggregated_identities))
        for blob, comment in aggregated_identities:
            payload += pack(">I", len(blob)) + blob
            payload += pack(">I", len(comment)) + comment

        log.info(f"Returning {len(aggregated_identities)} identities to {self.vm_name}")
        self._send_msg(client, payload)

    def _handle_sign_request(
        self, client: socket, raw_msg: bytes, real_agents: dict[str, socket]
    ) -> None:
        buf = SSHBuffer(raw_msg)
        buf.read_byte()
        key_blob = buf.read_string()
        data_to_sign = buf.read_string()
        purpose = self._determine_purpose(data_to_sign)
        title = f"SSH Agent proxy: {self.vm_name}"

        if key_blob not in self.allowed_keys_for_client:
            log_msg = f"Forbidden key request: VM={self.vm_name}, Purpose={purpose}"
            log.warning(log_msg)
            notify(title, log_msg, critical=True)
            self._send_msg(client, bytes([AgentMsg.FAILURE]))
            return

        k_cfg = self.allowed_keys_for_client[key_blob]
        rule = self.key_rule[key_blob]
        is_auth = purpose == "SSH Server Authentication"
        # Per-usage policy ("deny" | "ask" | "allow") from the matched rule.
        # data_signing defaults to "deny" so a guest cannot get arbitrary data
        # signed unless a rule enables it.
        policy = rule.auth if is_auth else rule.data_signing

        if policy == "deny":
            log_msg = f"Refused {purpose}: VM={self.vm_name}, key={k_cfg.id}"
            log.warning(log_msg)
            notify(title, log_msg, critical=True)
            self._send_msg(client, bytes([AgentMsg.FAILURE]))
            return

        # Destination validation: only for SSH auth, only when the rule restricts
        # it. Fail closed -- no verified session-bind => refuse.
        if is_auth and rule.allowed_host_keys:
            if not self._destination_allowed(data_to_sign, rule.allowed_host_keys):
                log_msg = (
                    f"Forbidden destination: VM={self.vm_name} attempted auth to a "
                    "non-allowlisted / unverified host"
                )
                log.warning(log_msg)
                notify(title, log_msg, critical=True)
                self._send_msg(client, bytes([AgentMsg.FAILURE]))
                return

        prompt = f"Allow {self.vm_name} to use key '{k_cfg.id}'?\nPurpose: {purpose}\nFingerprint: {k_cfg.fingerprint}"

        # "allow" -> silent; "ask" -> prompt the user (destination already validated).
        dialog_program = self.config.dialog_program or (
            "swiftdialog" if sys_platform == "darwin" else "zenity"
        )
        is_authorized = policy == "allow" or prompt_for_confirmation(
            title, prompt, dialog_program
        )

        if is_authorized:
            target_sock = real_agents.get(k_cfg.socket)
            if target_sock:
                log.info(
                    f"Access granted: VM={self.vm_name}, Key={k_cfg.id}, Fingerprint={k_cfg.fingerprint}, Purpose={purpose}"
                )
                self._send_msg(target_sock, raw_msg)
                resp = self._recv_msg(target_sock)
                if resp is None:
                    log.warning(
                        f"Upstream agent closed before responding for key {k_cfg.id}"
                    )
                    self._send_msg(client, bytes([AgentMsg.FAILURE]))
                    return
                self._send_msg(client, resp)
                if rule.notify:
                    notify(title, f"{self.vm_name} used key '{k_cfg.id}' for {purpose}")
                return
        else:
            log.warning(
                f"Access refused: VM={self.vm_name}, Key={k_cfg.id}, Fingerprint={k_cfg.fingerprint}, Purpose={purpose}"
            )

        self._send_msg(client, bytes([AgentMsg.FAILURE]))

    def _determine_purpose(self, data_to_sign: bytes) -> str:
        try:
            if data_to_sign.startswith(b"SSHSIG"):
                sig_buf = SSHBuffer(data_to_sign[6:])
                namespace = sig_buf.read_string().decode("utf-8", "replace")
                if namespace == "git":
                    return "Git Signing"
                # namespace is guest-controlled -> strip to printable + cap length so
                # it can't inject newlines/markup into the confirmation dialog.
                safe = "".join(c for c in namespace if c.isprintable())[:48]
                return f"Data Sign ({safe})"
            inner_buf = SSHBuffer(data_to_sign)
            inner_buf.read_string()
            if inner_buf.has_data() and inner_buf.read_byte() == 50:
                return "SSH Server Authentication"
        except Exception:
            pass
        return "Unknown Purpose (UNSAFE)"

    def _handle_extension(self, client: socket, raw_msg: bytes) -> None:
        buf = SSHBuffer(raw_msg)
        buf.read_byte()  # message type
        try:
            ext_name = buf.read_string().decode("utf-8", "replace")
        except Exception:
            self._send_msg(client, bytes([AgentMsg.FAILURE]))
            return
        if ext_name == "session-bind@openssh.com":
            self._handle_session_bind(client, buf)
        else:
            # unsupported extension -> FAILURE (clients degrade gracefully)
            self._send_msg(client, bytes([AgentMsg.FAILURE]))

    def _handle_session_bind(self, client: socket, buf: SSHBuffer) -> None:
        # session-bind@openssh.com payload (after the extension name):
        #   string hostkey, string session_id, string signature, bool is_forwarding
        try:
            hostkey = buf.read_string()
            session_id = buf.read_string()
            signature = buf.read_string()
            is_forwarding = buf.read_byte()
        except Exception:
            self._send_msg(client, bytes([AgentMsg.FAILURE]))
            return

        # The signature proves the client really completed a KEX with a server
        # holding this host key -- it cannot be forged without the host private
        # key (or a signature from a trusted CA). Refuse to record an
        # unverifiable bind.
        trust = self._verify_bind_sig(hostkey, session_id, signature)
        if trust is None:
            log.warning(
                f"session-bind: invalid signature from {self.vm_name}; refusing"
            )
            self._send_msg(client, bytes([AgentMsg.FAILURE]))
            return

        self.bound_destinations[session_id] = trust
        log.debug(
            f"session-bind: {self.vm_name} bound a session to a host key "
            f"(forwarding={bool(is_forwarding)})"
        )
        self._send_msg(client, bytes([AgentMsg.SUCCESS]))

    def _verify_bind_sig(
        self, hostkey: bytes, session_id: bytes, signature: bytes
    ) -> Optional[bytes]:
        """Verify a session-bind signature and return the destination's
        "trust blob" -- the identifier matched against allowed_host_keys.

        For a plain host key the trust blob is the host key itself. For a host
        key that is a certificate (ssh-*-cert-v01@openssh.com) the signature is
        verified against the embedded per-host public key while the trust blob
        is the embedded CA public key, so an SSH-CA-trusted wildcard can
        authorize it.
        """
        try:
            key_blob, trust_blob = self._split_hostkey(hostkey)
            if key_blob is None:
                log.warning("session-bind: unsupported host key type")
                return None
            if not self._verify_key_signature(key_blob, signature, session_id):
                return None
            return trust_blob
        except Exception:
            log.debug("session-bind: signature verification failed", exc_info=True)
            return None

    @staticmethod
    def _split_hostkey(
        hostkey: bytes,
    ) -> tuple[Optional[bytes], Optional[bytes]]:
        """Split a host key into the blob used to verify its signature and the
        blob used as the destination trust identifier.

        Returns (key_blob, trust_blob). For plain keys both are the host key
        itself; for a certificate the signature key is the embedded per-host
        public key and the trust blob is the embedded CA public key. Returns
        (None, None) for an unsupported key type.
        """
        try:
            kb = SSHBuffer(hostkey)
            keytype = kb.read_string().decode("utf-8", "replace")

            if keytype.endswith("-cert-v01@openssh.com"):
                # PROTOCOL.certkeys: after the cert type string:
                #   string nonce
                #   string key            <- string alg, string data (per-host pubkey)
                #   uint64 serial, uint32 type, string key_id
                #   string valid_principals, uint64 valid_after, uint64 valid_before
                #   string critical_options, string extensions, string reserved
                #   string signature_key  <- string alg, string data (CA pubkey)
                kb.read_string()  # nonce
                inner_key = kb.read_string()
                if inner_key is None:
                    return None, None
                kb.read_mpint()  # serial
                kb.read_int()  # type
                kb.read_string()  # key id
                kb.read_string()  # valid principals
                kb.read_mpint()  # valid after
                kb.read_mpint()  # valid before
                kb.read_string()  # critical options
                kb.read_string()  # extensions
                kb.read_string()  # reserved
                sig_key = kb.read_string()  # CA public key blob
                return inner_key, sig_key

            # plain host key: signature and trust identity are the whole blob
            return hostkey, hostkey
        except (InvalidSignature, Exception):
            return None, None

    def _verify_key_signature(
        self, pubkey_blob: bytes, signature_blob: bytes, session_id: bytes
    ) -> bool:
        """Verify a signature over session_id using a public key blob that is
        already in 'string alg, string data' form (per-host key of a cert, or
        a plain host key).
        """
        try:
            kb = SSHBuffer(pubkey_blob)
            keytype = kb.read_string().decode("utf-8", "replace")
            sb = SSHBuffer(signature_blob)
            sigtype = sb.read_string().decode("utf-8", "replace")

            if keytype == "ssh-ed25519":
                pub = kb.read_string()  # 32-byte public key
                Ed25519PublicKey.from_public_bytes(pub).verify(
                    sb.read_string(), session_id
                )
                return True

            if keytype == "ssh-rsa":
                e = kb.read_mpint()
                n = kb.read_mpint()
                hash_alg = {
                    "ssh-rsa": hashes.SHA1(),
                    "rsa-sha2-256": hashes.SHA256(),
                    "rsa-sha2-512": hashes.SHA512(),
                }[sigtype]
                rsa.RSAPublicNumbers(e, n).public_key().verify(
                    sb.read_string(), session_id, padding.PKCS1v15(), hash_alg
                )
                return True

            if keytype.startswith("ecdsa-sha2-"):
                curve_name = kb.read_string().decode("utf-8", "replace")
                point = kb.read_string()
                curve, hash_alg = {
                    "nistp256": (ec.SECP256R1(), hashes.SHA256()),
                    "nistp384": (ec.SECP384R1(), hashes.SHA384()),
                    "nistp521": (ec.SECP521R1(), hashes.SHA512()),
                }[curve_name]
                # the ecdsa signature blob wraps mpint r || mpint s
                inner = SSHBuffer(sb.read_string())
                der = encode_dss_signature(inner.read_mpint(), inner.read_mpint())
                ec.EllipticCurvePublicKey.from_encoded_point(curve, point).verify(
                    der, session_id, ec.ECDSA(hash_alg)
                )
                return True

            log.warning(f"session-bind: unsupported host key type {keytype!r}")
            return False
        except (InvalidSignature, Exception):
            log.debug("session-bind: signature verification failed", exc_info=True)
            return False

    def _destination_allowed(
        self, data_to_sign: bytes, allowed_hosts: set[bytes]
    ) -> bool:
        # For SSH auth, the first field of the signed data is the session id.
        try:
            session_id = SSHBuffer(data_to_sign).read_string()
        except Exception:
            return False
        dest = self.bound_destinations.get(session_id)
        if dest is None:
            log.warning(
                f"No verified session-bind for this sign request from {self.vm_name}"
            )
            return False
        return dest in allowed_hosts

    def _handle_unknown(self, client: socket, mtype: int) -> None:
        msg = f"Filtered operation {mtype} from {self.vm_name}"
        log.warning(msg)
        notify("SSH Proxy Warning", msg, critical=True)
        self._send_msg(client, bytes([AgentMsg.FAILURE]))


class MergeHandler(AgentIO, BaseRequestHandler):
    """Allow-all handler for --merge mode: no VM resolution, no rules, no
    confirmation prompts -- just aggregates identities from every upstream
    agent socket and blindly forwards everything else to whichever upstream
    answers first with something other than FAILURE.
    """

    def setup(self) -> None:
        self.upstream_sockets: list[str] = self.server.app_sockets  # type: ignore

    def handle(self) -> None:
        client = self.request
        client.settimeout(SOCKET_TIMEOUT)
        log.info("merge: new client connection")

        real_agents: dict[str, socket] = {}
        for path in self.upstream_sockets:
            try:
                sock = Socket(AF_UNIX, SOCK_STREAM)
                # Short per-upstream timeout so a hung upstream is dropped
                # quickly rather than blocking the client for SOCKET_TIMEOUT.
                sock.settimeout(MERGE_UPSTREAM_TIMEOUT)
                sock.connect(path)
                real_agents[path] = sock
                log.debug(f"merge: connected to upstream agent at {path}")
            except Exception as e:
                log.error(f"merge: could not connect to upstream agent at {path}: {e}")

        try:
            while True:
                msg = self._recv_msg(client)
                if not msg:
                    break

                if msg[0] == AgentMsg.REQUEST_IDENTITIES:
                    self._handle_identities(client, msg, real_agents)
                else:
                    self._handle_forward(client, msg, real_agents)
        except Exception:
            log.exception("merge: error in client handler loop")
        finally:
            for s in real_agents.values():
                s.close()
            client.close()
            log.debug("merge: client connection closed")

    def _handle_identities(
        self, client: socket, raw_msg: bytes, real_agents: dict[str, socket]
    ) -> None:
        aggregated_identities: list[tuple[bytes, bytes]] = []
        seen: set[bytes] = set()
        for path, sock in real_agents.items():
            self._send_msg(sock, raw_msg)
            resp = self._recv_msg(sock)
            if not resp or resp[0] != AgentMsg.IDENTITIES_ANSWER:
                continue

            buf = SSHBuffer(resp)
            buf.read_byte()
            count = buf.read_int()
            log.debug(f"merge: upstream {path} returned {count} identities")

            for _ in range(count):
                key_blob = buf.read_string()
                comment = buf.read_string()
                if key_blob not in seen:
                    seen.add(key_blob)
                    aggregated_identities.append((key_blob, comment))

        payload = pack(">BI", AgentMsg.IDENTITIES_ANSWER, len(aggregated_identities))
        for blob, comment in aggregated_identities:
            payload += pack(">I", len(blob)) + blob
            payload += pack(">I", len(comment)) + comment

        log.debug(f"merge: returning {len(aggregated_identities)} merged identities")
        self._send_msg(client, payload)

    def _handle_forward(
        self, client: socket, raw_msg: bytes, real_agents: dict[str, socket]
    ) -> None:
        # Allow-all: no policy to enforce, so just try each upstream agent in
        # turn and relay the first response that isn't a FAILURE. This
        # correctly handles sign requests (only the agent holding the private
        # key will answer with SIGN_RESPONSE) and any other request type.
        for sock in real_agents.values():
            self._send_msg(sock, raw_msg)
            resp = self._recv_msg(sock)
            if resp is not None and (len(resp) == 0 or resp[0] != AgentMsg.FAILURE):
                self._send_msg(client, resp)
                return
        self._send_msg(client, bytes([AgentMsg.FAILURE]))


class ThreadedVsockServer(ThreadingMixIn, TCPServer):
    address_family = AF_VSOCK
    allow_reuse_address = True

    def get_request(self):
        sock, addr = TCPServer.get_request(self)
        if getattr(self, "ssl_context", None):
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except ssl.SSLError as e:
                log.warning(f"SSL handshake failed from {addr}: {e}")
                sock.close()
                raise
        return sock, addr


class ThreadedTcpServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

    def get_request(self):
        sock, addr = TCPServer.get_request(self)
        if getattr(self, "ssl_context", None):
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except ssl.SSLError as e:
                log.warning(f"SSL handshake failed from {addr}: {e}")
                sock.close()
                raise
        return sock, addr


class ThreadedUnixServer(ThreadingMixIn, UnixStreamServer):
    allow_reuse_address = True


class RemoteConnection(AgentIO):
    """A single persistent connection to the host's ssh-agent-proxy, shared
    across every local (guest-side) client connection.

    A TLS/mTLS handshake is expensive (asymmetric crypto + cert validation);
    doing a fresh one per agent request would make every `ssh`/`git`
    invocation pay that cost on top of its own work. Connected eagerly at
    startup (see `run_client`) so the first real request doesn't pay it
    either, and transparently reconnected if the remote side drops it.
    Only one agent request is ever in flight on it at a time -- the SSH
    agent wire protocol carries no request ID to demultiplex concurrent
    ones -- enforced by `lock`.
    """

    def __init__(
        self, host: "str | int", port: int, transport: str,
        ssl_ctx: Optional[ssl.SSLContext], config: Config
    ) -> None:
        self.host = host
        self.port = port
        self.transport = transport
        self.ssl_ctx = ssl_ctx
        self.config = config
        self.lock = Lock()
        self.sock: Optional[socket.socket] = None

    @property
    def peer(self) -> str:
        return f"{self.transport}:{self.host}:{self.port}"

    def _connect(self) -> socket.socket:
        t0 = monotonic()
        family = AF_VSOCK if self.transport == "vsock" else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((self.host, self.port))
        t1 = monotonic()
        if self.ssl_ctx:
            server_hostname = self.host if self.transport == "tcp" else None
            sock = self.ssl_ctx.wrap_socket(sock, server_hostname=server_hostname)

            peer_oid = self.config.mtls_peer_required_oid
            if peer_oid and hasattr(sock, "getpeercert"):
                der = sock.getpeercert(binary_form=True)
                if der:
                    verify_cert_der(der, peer_oid, "Server")
        t2 = monotonic()

        log.debug(f"client: connect={_ms(t1 - t0)} tls={_ms(t2 - t1)}")
        log.info(f"client: connected to {self.peer} (tls={self.ssl_ctx is not None})")
        return sock

    def ensure_connected(self) -> None:
        """Connect now, so the connection (and its handshake) is already
        warm before the first real agent request arrives."""
        with self.lock:
            if self.sock is None:
                try:
                    self.sock = self._connect()
                except Exception as e:
                    log.warning(
                        f"client: initial connection to {self.peer} failed "
                        f"({e}); will retry on first request"
                    )

    def request(self, msg: bytes) -> Optional[bytes]:
        """Send one framed agent message and return the framed response, or
        None on failure. Reconnects once transparently before giving up."""
        with self.lock:
            for _attempt in range(2):
                if self.sock is None:
                    try:
                        self.sock = self._connect()
                    except Exception as e:
                        log.error(f"client: connection to {self.peer} failed: {e}")
                        return None
                try:
                    t0 = monotonic()
                    self._send_msg(self.sock, msg)
                    resp = self._recv_msg(self.sock)
                    if resp is None:
                        raise ConnectionError("remote closed the connection")
                    log.debug(f"client: roundtrip={_ms(monotonic() - t0)}")
                    return resp
                except Exception as e:
                    log.warning(f"client: request to {self.peer} failed ({e}); reconnecting")
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                    self.sock = None
            return None


class ClientHandler(AgentIO, BaseRequestHandler):
    """Local Unix socket handler that relays agent protocol messages to the
    remote proxy over the server's single shared, persistent connection
    (see RemoteConnection) rather than opening a fresh TCP/TLS connection
    per local client."""

    def setup(self) -> None:
        self.remote: RemoteConnection = self.server.remote

    def handle(self) -> None:
        local = self.request
        local.settimeout(SOCKET_TIMEOUT)
        try:
            while True:
                msg = self._recv_msg(local)
                if not msg:
                    break
                resp = self.remote.request(msg)
                if resp is None:
                    self._send_msg(local, bytes([AgentMsg.FAILURE]))
                    break
                self._send_msg(local, resp)
        except Exception:
            log.exception("client: error in local handler loop")
        finally:
            try:
                local.close()
            except Exception:
                pass


def run_merge(sockets: list[str], listen_path: str) -> None:
    """Merge mode: no VSOCK, no VM/policy logic -- just fan multiple upstream
    agent sockets into a single unix socket that allows everything.
    """
    # Resolve platform-specific placeholders first.
    sockets = [_expand_socket_path(s) for s in sockets]
    listen_path = _expand_socket_path(listen_path)

    listen = Path(listen_path)
    listen.parent.mkdir(parents=True, exist_ok=True)
    if listen.exists():
        listen.unlink()

    # Restrict the socket's permissions from the moment it's created, so
    # there's no window where it's reachable by anything other than us.
    old_umask = umask(0o177)
    try:
        server = ThreadedUnixServer(str(listen), MergeHandler)
    finally:
        umask(old_umask)

    try:
        with server:
            server.app_sockets = sockets  # type: ignore
            log.info(
                f"SSH Agent merge proxy listening on {listen} "
                f"(allow-all, merging {len(sockets)} upstream socket(s): {', '.join(sockets)})"
            )
            server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        exit(0)
    finally:
        listen.unlink(missing_ok=True)


def run_proxy(config: Config) -> None:
    ssl_ctx = create_ssl_context(config, server=True)
    try:
        if config.tcp_bind:
            host, port = _split_bind(config.tcp_bind)
            with ThreadedTcpServer((host, port), Handler) as server:
                server.app_config = config  # type: ignore
                server.ssl_context = ssl_ctx
                server._mtls_config = {"peer_required_oid": config.mtls_peer_required_oid}
                log.info(
                    f"SSH Agent Proxy listening on tcp:{host}:{port} "
                    f"(tls={ssl_ctx is not None})"
                )
                server.serve_forever()
        else:
            with ThreadedVsockServer(
                (HOST_CID, config.vsock_port), Handler
            ) as server:  # type: ignore[arg-type]
                server.app_config = config  # type: ignore
                server.ssl_context = ssl_ctx
                server._mtls_config = {"peer_required_oid": config.mtls_peer_required_oid}
                log.info(
                    f"SSH Agent Proxy listening on vsock:{HOST_CID}:{config.vsock_port} "
                    f"(tls={ssl_ctx is not None})"
                )
                server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        exit(0)


def run_client(config: Config) -> None:
    ssl_ctx = create_ssl_context(config, server=False)
    listen_path = config.listen_socket or "%t/ssh-agent-host"
    listen_path = _expand_socket_path(listen_path)

    listen = Path(listen_path)
    listen.parent.mkdir(parents=True, exist_ok=True)
    if listen.exists():
        listen.unlink()

    old_umask = umask(0o177)
    try:
        server = ThreadedUnixServer(str(listen), ClientHandler)
    finally:
        umask(old_umask)

    if config.transport == "vsock":
        remote_host = config.cid
    else:
        remote_host = config.host
        if remote_host == "_gateway":
            try:
                remote_host = resolve_default_gateway()
                log.info(f"Resolved _gateway -> {remote_host}")
            except Exception as e:
                log.error(f"Failed to resolve default gateway: {e}")
                exit(1)

    remote = RemoteConnection(remote_host, config.port, config.transport, ssl_ctx, config)
    # Connect (and TLS-handshake) now rather than on the first agent
    # request -- see RemoteConnection's docstring.
    remote.ensure_connected()
    server.remote = remote

    try:
        with server:
            log.info(
                f"SSH Agent client listening on {listen} "
                f"(forwarding to {remote.peer}, tls={ssl_ctx is not None})"
            )
            server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        exit(0)
    finally:
        listen.unlink(missing_ok=True)


def main() -> None:
    parser = ArgumentParser(description="SSH Agent Proxy")
    parser.add_argument(
        "-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to config file"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--mode",
        choices=["merge", "proxy", "client"],
        default=None,
        help="Operation mode (default: proxy, or from config)",
    )
    parser.add_argument(
        "--merge",
        nargs="+",
        metavar="SOCKET",
        help="(Deprecated) Merge mode: upstream sockets",
    )
    parser.add_argument(
        "--listen",
        metavar="PATH",
        help="(Deprecated) Unix socket path for merge mode",
    )
    args = parser.parse_args()

    log_level = DEBUG if args.debug else INFO
    basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")

    # Backward compatibility: --merge/--listen still work but are deprecated.
    if args.merge:
        log.warning(
            "--merge is deprecated; set mode='merge' and merge_sockets=[...] in config"
        )
        if not args.listen:
            parser.error("--merge requires --listen PATH")
        run_merge(args.merge, args.listen)
        return

    if args.listen:
        log.warning("--listen is deprecated; use listen_socket in config")

    config = Config()
    try:
        config.load(args.config, mode=args.mode)
    except Exception as e:
        log.error(f"Configuration error: {e}")
        exit(1)

    mode = args.mode or config.mode or "proxy"

    if mode == "merge":
        sockets = config.merge_sockets
        listen_path = args.listen or config.listen_socket
        if not sockets or not listen_path:
            log.error("merge mode requires merge_sockets and listen_socket in config")
            exit(1)
        run_merge(sockets, listen_path)
    elif mode == "client":
        run_client(config)
    else:
        run_proxy(config)


if __name__ == "__main__":
    main()

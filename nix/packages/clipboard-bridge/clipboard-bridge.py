#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Clipboard Bridge - A secure clipboard bridge for containers, VMs, and Neovim.

ARCHITECTURE
------------
The clipboard bridge consists of a server (host) and client (guest/VM):

  Host:  clipboard-bridge.py serve [--config FILE]
  Guest: clipboard-bridge.py push    # Send clipboard to host
         clipboard-bridge.py pull    # Receive clipboard from host

The server maintains per-client clipboard buffers and syncs with the host
system clipboard (wl-copy/wl-paste). Each client (VM) is isolated and can
only read/write its own clipboard slot.

SECURITY MODEL
--------------
  - VMs (remote clients) can ONLY access their own clipboard slot.
  - Admin actions (list clients, read/write other slots, pull all data)
    require a shared secret configured in the config file.
  - Server behavior:
    * If secret or secret_file is configured: use that secret
    * If NOT configured: generate a random secret and print it to stdout
  - The secret is read from the config file (secret = "..." or
    secret_file = "/path/to/secret"). Admin commands load the same config.
  - Optional mTLS with EKU OID enforcement for connection authentication.
  - Clients that have not been seen for 5 minutes are automatically removed.

PROTOCOL
--------
JSON messages over a stream socket (TCP, Unix, or VSOCK):

  Client -> Server: {"action": "set", "data": "<base64-content>"}
  Client -> Server: {"action": "get"}
  Server -> Client: {"status": "ok", "data": "<base64-content>"}

  Admin -> Server:  {"action": "clients", "secret": "<password>"}
  Admin -> Server:  {"action": "get", "json": true, "secret": "<password>"}
  Admin -> Server:  {"action": "set", "data": "<base64-content>", "target": "vsock:5", "secret": "<password>"}

  Subscriber -> Server: {"action": "subscribe"}
  Server -> Subscriber: {"status": "ok", "message": "Subscribed"}  (followed by live pushes via same stream)

CONFIGURATION
-------------
  --config / -c PATH    Override the role default config path.
  Separate config files per role, auto-selected by the command:
    server commands -> ~/.config/clipboard-bridge/server.toml
    client commands -> ~/.config/clipboard-bridge/client.toml
  Override either with --config / -c PATH.

  Each file is flat TOML:
    transport = "tcp" | "vsock" | "unix"
    host = "0.0.0.0"              (server bind / client connect address)
    port = 27795
    cid = 2                       (VSOCK CID, client only)
    socket = "/path/to.sock"      (Unix socket path)
    secret = "mysecret"           (shared admin secret, inlined)
    secret_file = "/path/secret"  (path to a file containing the shared secret)
    resolution = "tartarus"       (server only: none | certificate | tartarus | mofos | qemu)
    proxy_socket = "%t/clipboard-bridge-proxy"  (client only: local connection-reuse proxy socket)
    debug = true

  [mtls]
  enable = false
  ca_file = "./ca.crt"
  cert_file = "./server.crt"
  key_file = "./server.key"
  required_oid = "1.3.6.1.4.1.99999.3.1"
  peer_required_oid = "1.3.6.1.4.1.99999.3.2"

Paths starting with ./ are resolved relative to the config file's directory.
Paths starting with ~/ are expanded to the user's home directory.

No environment variables are read by this tool; everything is configured via
TOML config files.

Examples:
  # Start server on host (VSOCK for VMs)
  clipboard-bridge.py serve

  # Push from guest (reads stdin when piped, no secret needed)
  echo "hello" | clipboard-bridge.py push

  # Pull from guest (prints to stdout when piped, no secret needed)
  clipboard-bridge.py pull

  # Host: list all VM clients (requires secret in config)
  clipboard-bridge.py clients

  # Host: push to specific VM (requires secret in config)
  clipboard-bridge.py push "hello" --target vsock:5

  # Host: pull latest VM clipboard (requires secret in config)
  clipboard-bridge.py pull
"""

import argparse
import base64
import json
import os
import re
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

if TYPE_CHECKING:
    import cryptography.x509 as x509

DEFAULT_PORT = 27795
DEFAULT_BIND = "0.0.0.0"
DEFAULT_CONNECT_HOST = "127.0.0.1"
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/clipboard-bridge")
DEFAULT_SERVER_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "server.toml")
DEFAULT_CLIENT_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "client.toml")
DEFAULT_PROXY_SOCKET = "%t/clipboard-bridge-proxy"
TARTARUS_STATE_ROOT = Path(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state"))) / "tartarus"

# OID allocation (sudo-auth-proxy subtree convention)
SERVER_OID = "1.3.6.1.4.1.99999.3.1"
CLIENT_OID = "1.3.6.1.4.1.99999.3.2"


def generate_secret():
    """Generate a 16-byte (32 hex chars) cryptographically secure random secret."""
    return os.urandom(16).hex()


# Global state
server_secret = None
no_notify = False
debug_enabled = False
client_clipboards = {}
client_lock = threading.Lock()
latest_client_id = None

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
    global debug_enabled
    debug_enabled = bool(config.get("debug"))


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


def load_config(path: Optional[str] = None, role: str = "client") -> dict:
    """Load the TOML config for the given role.

    The role selects the default file when no --config is given: server
    commands read `server.toml`, client commands read `client.toml`. Relative
    and home-relative paths are resolved against the config file's directory.
    """
    if path is None:
        path = DEFAULT_SERVER_CONFIG_PATH if role == "server" else DEFAULT_CLIENT_CONFIG_PATH
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = p.resolve()
    if not p.exists():
        return {}

    with open(p, "rb") as f:
        config = tomllib.load(f)

    config_dir = p.parent

    def resolve(value):
        if not isinstance(value, str):
            return value
        if value.startswith("~/"):
            return os.path.expanduser(value)
        pth = Path(value)
        if not pth.is_absolute():
            return str(config_dir / pth)
        return str(pth)

    for key in ("ca_file", "cert_file", "key_file", "secret_file"):
        if key in config and config[key]:
            config[key] = resolve(config[key])

    mtls = config.get("mtls")
    if isinstance(mtls, dict):
        for key in ("ca_file", "cert_file", "key_file"):
            if key in mtls and mtls[key]:
                mtls[key] = resolve(mtls[key])

    if config.get("proxy_socket"):
        config["proxy_socket"] = expand_socket_path(config["proxy_socket"])

    return config


# --- EKU OID Verification ---

# cryptography.x509 costs ~500-700ms to import (Rust extension + a long
# submodule chain) -- deferred to first actual use so invocations that never
# touch a certificate (--help, early argument/secret errors, admin calls
# proxied over a local unix socket) don't pay for it.
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


def _cert_has_oid(cert: "x509.Certificate", oid: str) -> bool:
    x509, _ = _load_x509()
    if x509 is None:
        return False
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return any(eku.dotted_string == oid for eku in ekus)
    except x509.ExtensionNotFound:
        return False


def verify_cert_file(path: str, oid: str, label: str) -> None:
    x509, _ = _load_x509()
    if x509 is None:
        raise RuntimeError("cryptography library is required for OID verification")
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate {path} missing required EKU OID {oid}")


def verify_cert_der(der: bytes, oid: str, label: str) -> None:
    x509, _ = _load_x509()
    if x509 is None:
        raise RuntimeError("cryptography library is required for OID verification")
    cert = x509.load_der_x509_certificate(der)
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate missing required EKU OID {oid}")


# --- SSL Context ---


def create_ssl_context(config: dict, *, server: bool) -> Optional[ssl.SSLContext]:
    mtls = config.get("mtls")
    if not isinstance(mtls, dict):
        return None
    if not mtls.get("enable", False):
        return None
    ca_file = mtls.get("ca_file")
    cert_file = mtls.get("cert_file")
    key_file = mtls.get("key_file")
    if not all([ca_file, cert_file, key_file]):
        print("mTLS enabled but missing ca_file, cert_file, or key_file", file=sys.stderr)
        sys.exit(1)
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


# --- Client Identification & Resolution ---


def get_client_id(server_type, client_address):
    if server_type == "vsock":
        return f"vsock:{client_address[0]}"
    elif server_type == "tcp":
        return f"tcp:{client_address[0]}"
    elif server_type == "unix":
        return "unix:local"
    return "unknown"


def resolve_qemu_name(cid):
    """Resolve a VSOCK CID to a QEMU guest name by scanning /proc."""
    regex = r"-name.guest=([^,]+).*guest-cid\":(\d+),"
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                with open(f"/proc/{pid}/cmdline") as fp:
                    cmdline = fp.read()
                    if cmdline.startswith("/usr/bin/qemu-system-"):
                        match = re.search(regex, cmdline)
                        if match and cid == int(match.group(2)):
                            return match.group(1)
    except Exception:
        pass
    return None


def resolve_client_name(client_id):
    if not client_id.startswith("vsock:"):
        return client_id
    try:
        cid = int(client_id.split(":", 1)[1])
    except ValueError:
        return client_id
    name = resolve_qemu_name(cid)
    return name if name else client_id


def resolve_target_to_id(target):
    """Resolve a target (name or id) to a client_id."""
    # Direct match
    if target in client_clipboards:
        return target
    # Name match
    for cid, info in client_clipboards.items():
        if info.get("name") == target:
            return cid
    return target


def get_cert_cn(der: bytes) -> Optional[str]:
    """Extract the Subject CN from a DER-encoded peer certificate, if present."""
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
    """Resolve a tartarus VM id (VSOCK CID, or the id baked into its
    deterministic MAC/IP) to its name via tartarus's own state directory
    (~/.local/state/tartarus/<name>/cid)."""
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


def resolve_mofos_name(cid):
    """Resolve a VSOCK CID to a VM name via `mofos ls --json`."""
    try:
        cid = int(cid)
    except (ValueError, TypeError):
        return None
    now = time.time()
    cached = _mofos_cache.get(cid)
    if cached is not None:
        name, ts = cached
        if now - ts < MOFOS_CACHE_TTL:
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
            if vm.get("cid") == cid:
                name = vm.get("name")
                break
        _mofos_cache[cid] = (name, now)
        stale = [k for k, (_, t) in _mofos_cache.items() if now - t >= MOFOS_CACHE_TTL]
        for k in stale:
            del _mofos_cache[k]
        return name
    except Exception as e:
        _debug(f"mofos resolution failed: {e}")
        return None


def tartarus_id_for_ip(ip: str) -> Optional[int]:
    """Resolve a peer IP to a tartarus VM id.

    Linux: guests sit on a static bridge subnet (10.200.0.<id>), so the id is
    just the last octet -- no lookup needed. macOS: guests get a
    DHCP-assigned IP over vmnet-shared that isn't known ahead of time, so
    correlate via the ARP table -> the VM's deterministic MAC
    (02:00:00:00:00:<id-hex>, see packages/tartarus/flake.nix and
    packages/tartarus/tartarus.py) -- the same convention tartarus.py's own
    vm_resolve_running_ip uses, in reverse.
    """
    match = re.match(r"^10\.200\.0\.(\d+)$", ip)
    if match:
        return int(match.group(1))
    try:
        result = subprocess.run(["arp", "-an"], capture_output=True, text=True, check=False)
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


def resolve_tartarus_name(client_id: str) -> Optional[str]:
    """Resolve a client id to a VM name via tartarus's own state directory."""
    if client_id.startswith("vsock:"):
        try:
            vm_id = int(client_id.split(":", 1)[1])
        except ValueError:
            return None
    elif client_id.startswith("tcp:"):
        vm_id = tartarus_id_for_ip(client_id.split(":", 1)[1])
        if vm_id is None:
            return None
    else:
        return None
    return tartarus_name_for_id(vm_id)


def get_resolution_mode(config: dict) -> str:
    mode = config.get("resolution")
    if mode in ("none", "certificate", "tartarus", "mofos", "qemu"):
        return mode
    # Not configured: preserve pre-existing behavior implicitly.
    return "certificate" if config.get("mtls", {}).get("enable") else "tartarus"


def resolve_friendly_name(client_id: str, config: dict, peer_der: Optional[bytes]) -> Optional[str]:
    """Resolve a friendly name for a client whose identity we can vouch for on
    this connection -- the connecting peer itself, never an admin's --target
    (see notify_and_broadcast's `name` override for why that distinction
    matters)."""
    mode = get_resolution_mode(config)
    if mode == "none":
        return None
    if mode == "certificate":
        return get_cert_cn(peer_der) if peer_der else None
    if mode == "tartarus":
        return resolve_tartarus_name(client_id)
    if mode == "mofos":
        if client_id.startswith("vsock:"):
            try:
                cid = int(client_id.split(":", 1)[1])
            except ValueError:
                return None
            return resolve_mofos_name(cid)
        return None
    if mode == "qemu":
        if client_id.startswith("vsock:"):
            try:
                cid = int(client_id.split(":", 1)[1])
            except ValueError:
                return None
            return resolve_qemu_name(cid)
        return None
    return None


def notify(client_name, action):
    if no_notify:
        return
    display_name = client_name if client_name is not None else "unknown"
    try:
        subprocess.run(
            ["notify-send", "Clipboard Bridge", f"{action} from {display_name}"],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        pass


def notify_and_broadcast(target_id, data, action_text, name=None, config=None, exclude_wfile=None):
    """Update clipboard store and notify/broadcast to subscribers.

    `name` overrides the resolved friendly name -- pass it only when the
    connecting peer IS target_id (a client pushing to its own slot), never
    for an admin push to a --target: the admin's own identity isn't the
    target's, so omitting it here keeps whatever name the target already
    registered under instead of clobbering it.
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
        global latest_client_id
        latest_client_id = target_id
    notify(name, action_text)

    # Push to any subscribers waiting for this client
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


# --- JSON Protocol Handlers ---


def check_admin(request):
    """Check if the request contains the correct admin secret."""
    provided = request.get("secret", "")
    return provided == server_secret


class ClipboardHandler(socketserver.StreamRequestHandler):
    def finish(self):
        # Don't close rfile/wfile for long-lived subscribe sockets
        if getattr(self.request, "_cb_keep_alive", False):
            return
        super().finish()

    def handle(self):
        # Loops over multiple requests on the same connection (not just one)
        # so a persistent caller (PersistentConnection / the proxy, and a VM
        # client's reused push connection) can keep its already-completed TLS
        # handshake warm across many requests instead of silently reconnecting
        # (and re-handshaking) on every single one. A one-shot caller closes
        # its socket right after reading its single response, which this loop
        # sees as clean EOF on the next readline() and returns, exactly as
        # before.
        global latest_client_id
        server_type = getattr(self.server, "server_type", "tcp")
        client_address = self.client_address
        client_id = get_client_id(server_type, client_address)
        config = getattr(self.server, "cb_config", {})
        set_debug(config)

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
                is_admin = check_admin(request)

                # mTLS peer OID verification (skip for unix sockets); also
                # captures the peer's certificate DER for friendly-name
                # resolution (resolution = "certificate") below.
                mtls = config.get("mtls", {})
                peer_der = None
                if mtls.get("enable", False) and server_type != "unix" and hasattr(self.request, "getpeercert"):
                    peer_der = self.request.getpeercert(binary_form=True)
                    if peer_der:
                        peer_oid = mtls.get("peer_required_oid")
                        if peer_oid:
                            try:
                                verify_cert_der(peer_der, peer_oid, "Peer")
                            except (ValueError, RuntimeError) as e:
                                print(f"clipboard-bridge: {e}", file=sys.stderr)
                                self._send_error("SSL verification failed")
                                return

                # Friendly name for THIS connecting peer only -- never used for
                # an admin's --target, whose identity differs from the peer's.
                peer_name = resolve_friendly_name(client_id, config, peer_der)

                if action == "set":
                    if is_admin:
                        # Admin: must specify target
                        if not target:
                            response = {
                                "status": "error",
                                "message": "Admin push requires --target",
                            }
                        else:
                            resolved = resolve_target_to_id(target)
                            notify_and_broadcast(resolved, data, "Host push", config=config)
                            response = {"status": "ok"}
                    else:
                        # Client: write to own slot
                        if target:
                            # Non-admin clients can't target other VMs; ignore
                            # the flag and silently use their own slot.
                            _debug(f"non-admin client {client_id} sent --target {target}; ignoring")
                        notify_and_broadcast(client_id, data, "Push", name=peer_name, config=config, exclude_wfile=self.wfile)
                        response = {"status": "ok"}

                elif action == "get":
                    if is_admin:
                        # Admin: must specify target or use --json
                        if request.get("json"):
                            with client_lock:
                                result = {}
                                for cid, info in client_clipboards.items():
                                    result[cid] = {
                                        "data": info["data"],
                                        "updated": info["updated"],
                                        "name": info["name"],
                                    }
                            response = {"status": "ok", "data": result}
                        elif target:
                            with client_lock:
                                resolved = resolve_target_to_id(target)
                                info = client_clipboards.get(resolved, {})
                            response = {"status": "ok", "data": info.get("data", "")}
                        else:
                            response = {
                                "status": "error",
                                "message": "Admin pull requires --target or --json",
                            }
                    else:
                        # Client: return own entry
                        with client_lock:
                            info = client_clipboards.get(client_id, {})
                        response = {"status": "ok", "data": info.get("data", "")}

                elif action == "register":
                    # Client advertises itself to the server (e.g., systemd startup)
                    with client_lock:
                        mode = get_resolution_mode(config)
                        if client_id not in client_clipboards:
                            name = peer_name
                            if name is None and mode != "none":
                                name = resolve_client_name(client_id)
                            client_clipboards[client_id] = {
                                "data": "",
                                "updated": time.time(),
                                "name": name,
                            }
                        else:
                            # Just update the timestamp to show it's still alive
                            client_clipboards[client_id]["updated"] = time.time()
                            if mode == "none":
                                client_clipboards[client_id]["name"] = None
                            elif peer_name is not None:
                                client_clipboards[client_id]["name"] = peer_name
                    response = {"status": "ok"}

                elif action == "subscribe":
                    # VM client opens a long-lived stream to receive host-initiated
                    # pushes. This owns the connection for its whole lifetime (it
                    # never loops back for another request/response) -- return
                    # once it ends instead of falling through to the shared
                    # response write below.
                    response = {"status": "ok", "message": "Subscribed"}
                    self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
                    self.wfile.flush()

                    # Tell the server class not to close this socket after handle() returns
                    try:
                        self.request._cb_keep_alive = True
                    except (AttributeError, TypeError):
                        pass

                    with subscriber_lock:
                        client_subscribers.setdefault(client_id, []).append(self.wfile)

                    # Keep connection alive; server will push data via notify_and_broadcast
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
                    return

                elif action == "clients":
                    if not is_admin:
                        response = {
                            "status": "error",
                            "message": "Permission denied: admin secret required",
                        }
                    else:
                        with client_lock:
                            result = []
                            for cid, info in client_clipboards.items():
                                result.append(
                                    {
                                        "id": cid,
                                        "name": info["name"],
                                        "updated": info["updated"],
                                    }
                                )
                        response = {"status": "ok", "data": result}

                else:
                    response = {
                        "status": "error",
                        "message": f"Unknown action: {action}",
                    }

                _debug(f"handle: action={action} client={client_id} total={_ms(time.monotonic() - t_start)}")
                self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
                self.wfile.flush()
            except json.JSONDecodeError as e:
                response = {"status": "error", "message": f"Invalid JSON: {e}"}
                try:
                    self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    return
            except Exception as e:
                response = {"status": "error", "message": str(e)}
                try:
                    self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    return

    def _send_error(self, message):
        response = {"status": "error", "message": message}
        try:
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()
        except Exception:
            pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    server_type = "tcp"
    ssl_context = None
    cb_config = {}

    def get_request(self):
        sock, addr = socketserver.TCPServer.get_request(self)
        if self.ssl_context:
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except ssl.SSLError as e:
                print(f"SSL handshake failed from {addr}: {e}", file=sys.stderr)
                sock.close()
                raise
        return sock, addr

    def shutdown_request(self, request):
        # Don't close sockets for long-lived subscribe requests
        if getattr(request, "_cb_keep_alive", False):
            return
        try:
            try:
                request.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            request.close()
        except OSError:
            pass


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    server_type = "unix"
    cb_config = {}

    def shutdown_request(self, request):
        if getattr(request, "_cb_keep_alive", False):
            return
        try:
            request.close()
        except OSError:
            pass


if hasattr(socket, "AF_VSOCK"):

    class ThreadedVsockServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        address_family = socket.AF_VSOCK
        allow_reuse_address = True
        daemon_threads = True
        server_type = "vsock"
        ssl_context = None
        cb_config = {}

        def get_request(self):
            sock, addr = socketserver.TCPServer.get_request(self)
            if self.ssl_context:
                try:
                    sock = self.ssl_context.wrap_socket(sock, server_side=True)
                except ssl.SSLError as e:
                    print(f"SSL handshake failed from {addr}: {e}", file=sys.stderr)
                    sock.close()
                    raise
            return sock, addr

        def shutdown_request(self, request):
            if getattr(request, "_cb_keep_alive", False):
                return
            try:
                try:
                    request.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                request.close()
            except OSError:
                pass

else:
    ThreadedVsockServer = None  # type: ignore


# --- Client Functions ---


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
                return socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
    raise RuntimeError("no default gateway found in /proc/net/route")


def get_client_secret(config: Optional[dict] = None):
    """Get the admin secret from an inline config key or a file."""
    if config:
        inline = config.get("secret", "")
        if inline:
            return inline
        secret_file = config.get("secret_file", "")
        if secret_file and os.path.exists(secret_file):
            with open(secret_file, "r") as f:
                return f.read().strip()
    return ""


def get_connection_info(config: dict):
    """Resolve connection target from TOML config only."""
    transport = config.get("transport")
    if transport == "unix":
        sock = config.get("socket")
        if sock:
            return ("unix", sock)
    elif transport == "vsock":
        cid = config.get("cid", 2)
        port = config.get("port", DEFAULT_PORT)
        return ("vsock", (cid, port))
    elif transport == "tcp":
        host = config.get("host", DEFAULT_CONNECT_HOST)
        if host == "_gateway":
            host = resolve_default_gateway()
        port = config.get("port", DEFAULT_PORT)
        return ("tcp", (host, port))

    return ("tcp", (DEFAULT_CONNECT_HOST, DEFAULT_PORT))


def _connect(conn_type, address):
    """Create and connect a raw socket."""
    if conn_type == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    elif conn_type == "vsock":
        if not hasattr(socket, "AF_VSOCK"):
            raise OSError("VSOCK not supported on this platform")
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)
    return sock


def _wrap_ssl(sock, config: dict, conn_type: str, host: str):
    """Wrap a connected socket with SSL and verify peer OID if configured.

    Unix sockets are never TLS-wrapped (mirrors the server, which already
    skips mTLS peer verification for unix sockets) -- a local unix socket
    (e.g. the connection-reuse proxy's local leg) is trusted IPC, not a
    network hop with a peer identity to authenticate.
    """
    if conn_type == "unix":
        return sock
    ssl_ctx = create_ssl_context(config, server=False)
    if ssl_ctx is None:
        return sock
    server_hostname = host if conn_type != "vsock" else None
    sock = ssl_ctx.wrap_socket(sock, server_hostname=server_hostname)
    peer_oid = config.get("mtls", {}).get("peer_required_oid")
    if peer_oid:
        der = sock.getpeercert(binary_form=True)
        if der:
            try:
                verify_cert_der(der, peer_oid, "Server")
            except (ValueError, RuntimeError) as e:
                print(f"clipboard-bridge: {e}", file=sys.stderr)
                raise ConnectionError("Peer certificate missing required EKU OID")
    return sock


def send_request(conn_type, address, request, config: dict):
    t0 = time.monotonic()
    sock = _connect(conn_type, address)
    t1 = time.monotonic()
    host = address[0] if isinstance(address, tuple) else address
    try:
        sock = _wrap_ssl(sock, config, conn_type, host)
        t2 = time.monotonic()
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
        sock.close()


def send_admin_request(request: dict, config: dict, conn_type, address) -> dict:
    """Send an admin/CLI request, preferring a running local proxy (see
    `cmd_proxy`/`PersistentConnection`) over a fresh direct connection --
    falls back transparently if the proxy socket isn't there or isn't
    listening."""
    proxy_socket = config.get("proxy_socket")
    if proxy_socket:
        try:
            response = send_request("unix", proxy_socket, request, config)
            if response.get("status") != "proxy_unavailable":
                return response
            _debug(
                f"proxy reports its remote connection is down ({response.get('message')}); "
                "falling back to direct connection"
            )
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            _debug(f"proxy socket {proxy_socket} unavailable ({e}); falling back to direct connection")
    return send_request(conn_type, address, request, config)


class PersistentConnection:
    """A single persistent connection, reused across many requests, so a
    connect + TLS/mTLS handshake is only paid once instead of on every
    push/pull. Reconnects once transparently on failure. Only one request is
    ever in flight at a time -- this JSON-line protocol carries no request ID
    to demultiplex concurrent ones -- enforced by `lock`.
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
        sock = _connect(self.conn_type, self.address)
        t1 = time.monotonic()
        host = self.address[0] if isinstance(self.address, tuple) else self.address
        sock = _wrap_ssl(sock, self.config, self.conn_type, host)
        t2 = time.monotonic()
        _debug(f"PersistentConnection: connect={_ms(t1 - t0)} tls={_ms(t2 - t1)}")
        if self._connect_count > 1:
            # The whole point of this class is to pay the handshake cost once.
            # A second (or later) connect means the remote closed on us
            # between requests -- surfaced unconditionally (not just under
            # debug) since it silently defeats connection reuse otherwise.
            print(
                f"clipboard-bridge: PersistentConnection reconnected to {self.address} "
                f"(connect #{self._connect_count}) -- reuse is not actually happening",
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
                        f"clipboard-bridge: initial connection failed ({e}); will retry on first request",
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
                    self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
                    data = b""
                    while b"\n" not in data:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            raise ConnectionError("remote closed the connection")
                        data += chunk
                    _debug(f"PersistentConnection: roundtrip={_ms(time.monotonic() - t0)}")
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
    global no_notify, server_secret
    no_notify = args.no_notify
    config = load_config(args.config, "server")
    set_debug(config)
    server_secret = get_client_secret(config)

    if server_secret:
        print("Admin secret configured from config file")
    else:
        server_secret = generate_secret()
        print(f"Admin secret (auto-generated): {server_secret}")
        print(
            "Add this secret to the server's TOML config file (secret = '...') to enable admin actions."
        )

    # Precedence: CLI flags (--no-notify only) > TOML config > defaults
    port = config.get("port", DEFAULT_PORT)
    socket_path = config.get("socket")
    transport = config.get("transport", "tcp")
    bind_host = config.get("host", DEFAULT_BIND)

    ssl_ctx = create_ssl_context(config, server=True)

    if socket_path:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        server = ThreadedUnixServer(socket_path, ClipboardHandler)
        server.cb_config = config
        print(f"Clipboard server listening on unix:{socket_path}")
    elif transport == "vsock":
        if ThreadedVsockServer is None:
            print("Error: VSOCK not supported on this platform", file=sys.stderr)
            sys.exit(1)
        cid = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)
        server = ThreadedVsockServer((cid, port), ClipboardHandler)
        server.ssl_context = ssl_ctx
        server.cb_config = config
        print(f"Clipboard server listening on vsock:{cid}:{port}")
    else:
        server = ThreadedTCPServer((bind_host, port), ClipboardHandler)
        server.ssl_context = ssl_ctx
        server.cb_config = config
        print(f"Clipboard server listening on tcp:{bind_host}:{port}")

    try:
        # Start a background thread to prune stale clients (5 min expiry)
        def expiry_loop():
            while True:
                time.sleep(60)
                expire_clients()

        expiry_thread = threading.Thread(target=expiry_loop, daemon=True)
        expiry_thread.start()

        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.shutdown()
        if socket_path and os.path.exists(socket_path):
            os.unlink(socket_path)


def cmd_pull(args):
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)
    data = None
    stdout_piped = not sys.stdout.isatty() or getattr(args, "stdout", False)
    secret = get_client_secret(config)

    # Admin must specify target or use --json
    if secret and not args.target and not args.json:
        print(
            "Error: Admin pull requires --target or --json.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        request = {"action": "get"}
        if args.json:
            request["json"] = True
        if args.target:
            request["target"] = args.target
        if secret:
            request["secret"] = secret

        response = send_admin_request(request, config, conn_type, address)
        if response.get("status") == "ok":
            data = response.get("data", "")
        else:
            msg = response.get("message", "Unknown error")
            if "Permission denied" in msg:
                msg = "Permission denied: config secret does not match the server's secret"
            print(f"Error: {msg}", file=sys.stderr)
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
                    "Error: No clipboard data available and wl-clipboard is not installed.",
                    file=sys.stderr,
                )
                sys.exit(1)
            data = b""

    if args.json:
        if isinstance(data, dict):
            if args.decode:
                # Decode base64 values inside the dict for each client
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
        # Decode base64 for stdout or clipboard
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
    secret = get_client_secret(config)

    if args.content:
        content = args.content.encode("utf-8")
    elif stdin_piped:
        content = sys.stdin.buffer.read()
    else:
        content = get_system_clipboard()
        if content is None:
            print(
                "Error: No content provided and wl-clipboard is not available.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Base64 encode for JSON transport (supports binary data)
    encoded = base64.b64encode(content).decode("ascii")

    conn_type, address = get_connection_info(config)

    try:
        request = {"action": "set", "data": encoded}
        if args.target:
            request["target"] = args.target
        if secret:
            request["secret"] = secret

        response = send_admin_request(request, config, conn_type, address)
        if response.get("status") != "ok":
            msg = response.get("message", "Unknown error")
            if "Permission denied" in msg:
                msg = "Permission denied: config secret does not match the server's secret"
            print(f"Error: {msg}", file=sys.stderr)
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
    secret = get_client_secret(config)
    if not secret:
        print(
            "Error: Admin secret is not configured. Add `secret = \"...\"` or `secret_file = \"/path/secret\"` to the client config.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        response = send_admin_request(
            {"action": "clients", "secret": secret}, config, conn_type, address
        )
        if response.get("status") == "ok":
            clients = response.get("data", [])
            print(json.dumps(clients))
        else:
            msg = response.get("message", "Unknown error")
            if "Permission denied" in msg:
                msg = "Permission denied: config secret does not match the server's secret"
            print(f"Error: {msg}", file=sys.stderr)
            sys.exit(1)
    except ConnectionRefusedError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ConnectionError:
        print(
            "Error: Server closed connection. Is the server running and configured with the same secret?",
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
        response = send_admin_request({"action": "register"}, config, conn_type, address)
        if response.get("status") == "ok":
            print("Registered with clipboard bridge server")
        else:
            msg = response.get("message", "Unknown error")
            print(f"Error: {msg}", file=sys.stderr)
            sys.exit(1)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(
            f"Error: Failed to connect to clipboard bridge server: {e}", file=sys.stderr
        )
        sys.exit(1)


# --- Argument Parser ---


def create_parser():
    parser = argparse.ArgumentParser(
        description="Clipboard bridge for containers, VMs, and Neovim",
        epilog=f"""
Configuration:
  --config / -c PATH    Path to TOML config file (overrides the role default:
                        server commands default to {DEFAULT_SERVER_CONFIG_PATH},
                        client commands to {DEFAULT_CLIENT_CONFIG_PATH}).
                        A `secret` or `secret_file` key in this file provides
                        the admin secret; transport, host, port, cid, socket,
                        and mTLS settings are also read from it.

Security Notes:
  - If no secret is configured in the server's TOML, a random 32-character
    secret is generated and printed to stdout. Add that value as `secret =
    "..."` (or `secret_file = "/path/to/secret"`) to the server's config.
  - VMs/clients do NOT need the secret for normal push/pull operations.
  - Admin actions (clients, --target, --json) always require the secret.
  - Optional mTLS with EKU OID enforcement can be configured in the TOML file.

Examples:
  # Start server (auto-generates secret if not configured)
  clipboard-bridge.py serve
  # -> Admin secret: aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6v

  # Copy the printed secret into server.toml as `secret = "..."`, then:
  clipboard-bridge.py clients

  # VM push (no secret needed)
  echo "hello" | clipboard-bridge.py push
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to TOML config file (defaults: server commands use "
        f"{DEFAULT_SERVER_CONFIG_PATH}, client commands use {DEFAULT_CLIENT_CONFIG_PATH}).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start clipboard server")
    serve_parser.add_argument(
        "--no-notify", action="store_true", help="Disable desktop notifications"
    )

    pull_parser = subparsers.add_parser(
        "pull",
        help="Pull from internal clipboard (copies to system clipboard by default)",
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
        help="Return all client clipboards as JSON (admin only, keeps base64)",
    )
    pull_parser.add_argument(
        "--target", help="Target client ID (admin only, required unless --json)"
    )

    push_parser = subparsers.add_parser(
        "push", help="Push content to internal clipboard (reads from stdin if piped)"
    )
    push_parser.add_argument(
        "content",
        nargs="?",
        help="Content to push (default: stdin or system clipboard)",
    )
    push_parser.add_argument(
        "--target",
        help="Target client ID (admin only, required for admin)",
    )

    clients_parser = subparsers.add_parser(
        "clients", help="List connected clients (requires secret)"
    )

    register_parser = subparsers.add_parser(
        "register", help="Register with the clipboard bridge server (VM startup)"
    )

    client_parser = subparsers.add_parser(
        "client",
        help="Run a clipboard client daemon (subscribe + publish loop for VMs)",
    )
    client_parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval for local clipboard changes in seconds (default: 1.0)",
    )

    proxy_parser = subparsers.add_parser(
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
        reg_resp = send_request(conn_type, address, {"action": "register"}, config)
        if reg_resp.get("status") == "ok":
            print("Registered with clipboard bridge server", file=sys.stderr)
        else:
            print(f"Registration warning: {reg_resp.get('message', 'unknown error')}", file=sys.stderr)
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)

    # Shared mutable state so subscriber updates are visible to the monitor loop
    shared_state = {"last_data": None}

    # --- One-time initial sync on startup ---
    try:
        init_response = send_request(conn_type, address, {"action": "get"}, config)
        if init_response.get("status") == "ok" and "data" in init_response:
            data_b64 = init_response["data"]
            try:
                decoded = base64.b64decode(data_b64)
            except Exception:
                decoded = (
                    data_b64.encode("utf-8") if isinstance(data_b64, str) else data_b64
                )
            set_system_clipboard(decoded, env=wayland_env)
            shared_state["last_data"] = decoded
            print("Initial sync from server", file=sys.stderr)
    except Exception as e:
        print(f"Initial sync failed: {e}", file=sys.stderr)

    def run_subscriber():
        """Maintain a subscribe connection to receive server pushes."""
        while True:
            try:
                sock = _connect(conn_type, address)
                sock = _wrap_ssl(sock, config, conn_type, host)

                # --- Open persistent subscribe socket ---
                sock.sendall(
                    (json.dumps({"action": "subscribe"}) + "\n").encode("utf-8")
                )

                # Skip the subscribe confirmation line before treating subsequent
                # lines as data pushes.
                confirm = b""
                while b"\n" not in confirm:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    confirm += chunk
                if not confirm:
                    print("Subscriber: server closed before confirmation", file=sys.stderr)
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
                            if response.get("status") == "ok" and "data" in response:
                                data_b64 = response["data"]
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
                                print("Clipboard updated from server", file=sys.stderr)
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
                print(f"Subscriber error: {e}. Reconnecting in 5s...", file=sys.stderr)
                time.sleep(5)
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            # If we exited the inner while normally (server closed cleanly),
            # also wait before reconnecting to avoid a tight loop.
            print("Subscriber closed cleanly. Reconnecting in 5s...", file=sys.stderr)
            time.sleep(5)

    subscriber_thread = threading.Thread(target=run_subscriber, daemon=True)
    subscriber_thread.start()

    # Local clipboard monitor loop
    while True:
        try:
            current = get_system_clipboard(env=wayland_env)
            # Skip empty reads: a missing or empty local clipboard must not
            # overwrite the server's stored data (especially on first iteration,
            # before the clipboard has ever been set).
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
    """Run a local connection-reuse proxy (see PersistentConnection): holds
    one persistent, already-authenticated connection to the configured
    server, and relays requests from local unix-socket clients over it so
    they don't each pay for a fresh connect + TLS handshake."""
    config = load_config(args.config, "client")
    set_debug(config)
    conn_type, address = get_connection_info(config)

    listen_path = expand_socket_path(config.get("proxy_socket") or DEFAULT_PROXY_SOCKET)
    listen = Path(listen_path)
    listen.parent.mkdir(parents=True, exist_ok=True)
    if listen.exists():
        listen.unlink()

    remote = PersistentConnection(conn_type, address, config)
    remote.ensure_connected()

    class ProxyHandler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except Exception as e:
                    response = {"status": "error", "message": f"Invalid request: {e}"}
                else:
                    try:
                        response = remote.request(request)
                    except Exception as e:
                        # The persistent connection's own reconnect-once retry
                        # already failed -- the remote is genuinely down (e.g.
                        # mid-restart), not a bad request. Tell the caller to
                        # retry directly instead of surfacing a raw error, so
                        # a transient server restart doesn't fail admin calls
                        # that a fresh direct connection would have served.
                        response = {"status": "proxy_unavailable", "message": str(e)}
                self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
                self.wfile.flush()

    # Restrict the socket's permissions from the moment it's created, so
    # there's no window where it's reachable by anything other than us.
    old_umask = os.umask(0o177)
    try:
        server = ThreadedUnixServer(str(listen), ProxyHandler)
    finally:
        os.umask(old_umask)

    print(f"clipboard-bridge proxy listening on unix:{listen} -> {conn_type}:{address}")
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


if __name__ == "__main__":
    main()

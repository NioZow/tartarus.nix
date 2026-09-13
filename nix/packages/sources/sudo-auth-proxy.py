#!/usr/bin/env python3

import argparse
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path
from socketserver import (
    StreamRequestHandler,
    TCPServer,
    ThreadingMixIn,
    UnixStreamServer,
)
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import cryptography.x509 as x509

DEFAULT_CONFIG_PATH = "/etc/sudo-auth-proxy/config.toml"
# A fixed, system-wide path (not per-user %t/...) -- sudo can be invoked by
# any local user, not just whichever user has a home-manager session, so the
# reuse-proxy daemon and its socket must be reachable regardless of who's
# authenticating.
DEFAULT_PROXY_SOCKET = "/run/sudo-auth-proxy/proxy.sock"
TARTARUS_STATE_ROOT = Path(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state"))) / "tartarus"

debug_enabled = False


def set_debug(config: dict) -> None:
    global debug_enabled
    debug_enabled = bool(os.environ.get("SUDO_AUTH_PROXY_DEBUG")) or bool(config.get("debug"))


def _debug(msg: str) -> None:
    if debug_enabled:
        print(f"sudo-auth-proxy: [debug] {msg}", file=sys.stderr)


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms"


def load_config(path: str) -> dict:
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = p.resolve()
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

    # Top-level cert paths (keep for forward compat)
    for key in ("ca_file", "cert_file", "key_file"):
        if key in config and config[key]:
            config[key] = resolve(config[key])

    # mtls subsection
    mtls = config.get("mtls")
    if isinstance(mtls, dict):
        for key in ("ca_file", "cert_file", "key_file"):
            if key in mtls and mtls[key]:
                mtls[key] = resolve(mtls[key])

    return config


def expand_socket_path(path: str) -> str:
    """Expand placeholder prefixes in a unix socket path.

    `~` expands to the user's home directory. `%t/` expands to a per-user
    runtime directory ($XDG_RUNTIME_DIR on Linux, the Darwin per-user temp
    dir on macOS via `getconf DARWIN_USER_TEMP_DIR`) -- checked platform-first
    since a stray XDG_RUNTIME_DIR env var (e.g. exported for Linux
    compatibility in a dotfiles setup) can point at a directory that simply
    doesn't exist on macOS. Anything else (e.g. DEFAULT_PROXY_SOCKET's fixed
    /run/... path) is returned unchanged.
    """
    if path.startswith("~"):
        return os.path.expanduser(path)
    if path.startswith("%t/"):
        if sys.platform == "darwin":
            try:
                # Absolute path -- a caller's PATH can't be trusted here (a
                # bare "getconf" can fail to resolve in some hosts' spawn
                # environments, e.g. Raycast's dev-mode extension host,
                # crashing the whole invocation with FileNotFoundError).
                result = subprocess.run(
                    ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True
                )
                runtime_dir = result.stdout.strip() if result.returncode == 0 else "/tmp"
            except OSError:
                runtime_dir = "/tmp"
        else:
            runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return os.path.join(runtime_dir, path[3:])
    return path


# cryptography.x509 costs ~500-700ms to import (Rust extension + a long
# submodule chain) -- deferred to first actual use so invocations that never
# touch a certificate (early argument errors, client calls proxied over the
# local unix socket) don't pay for it, since this module is invoked fresh by
# pam_exec on every single sudo call.
_x509 = None


def _load_x509():
    global _x509
    if _x509 is None:
        try:
            import cryptography.x509 as x509_mod
        except ImportError:
            return None
        _x509 = x509_mod
    return _x509


def _cert_has_oid(cert: "x509.Certificate", oid: str) -> bool:
    x509 = _load_x509()
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return any(eku.dotted_string == oid for eku in ekus)
    except x509.ExtensionNotFound:
        return False


def verify_cert_file(path: str, oid: str, label: str) -> None:
    x509 = _load_x509()
    if x509 is None:
        raise RuntimeError("cryptography library is required for OID verification")
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate {path} missing required EKU OID {oid}")


def verify_cert_der(der: bytes, oid: str, label: str) -> None:
    x509 = _load_x509()
    if x509 is None:
        raise RuntimeError("cryptography library is required for OID verification")
    cert = x509.load_der_x509_certificate(der)
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate missing required EKU OID {oid}")


def prompt_for_confirmation(peer: str, dialog_program: str) -> bool:
    """Ask the user to authorize a privilege-elevation request. Returns True if approved.

    `dialog_program` picks the confirmation mechanism explicitly (one of
    "swiftdialog", "osascript", "zenity") -- set via config, not
    auto-detected. Detecting swiftDialog at request time meant spawning a
    throwaway "dialog" subprocess before the real one on every single
    request, which noticeably delayed the prompt appearing.
    """
    if dialog_program == "swiftdialog":
        res = subprocess.run(
            [
                "dialog",
                "--title", "Privilege Elevation",
                "--message", f"A process on **{peer}** is requesting privilege elevation.",
                "--icon", "SF=lock.shield.fill,colour=accent,weight=medium",
                "--iconsize", "80",
                "--iconalttext", "Authentication required",
                "--button1text", "Authorize",
                "--button2text", "Deny",
                "--width", "520",
                "--height", "280",
                "--ontop",
                "--blurscreen",
                "--messagefont", "size=16",
                "--titlefont", "size=22,weight=heavy",
                "--centericon",
                "--messagealignment", "center",
                "--position", "center",
            ],
            capture_output=True,
        )
        return res.returncode == 0

    if dialog_program == "osascript":
        script = (
            f'display dialog {json.dumps(f"Allow privilege elevation on {peer}?")} '
            f'with title {json.dumps(f"sudo authentication for {peer}")} with icon caution '
            'buttons {"No", "Yes"} default button "Yes" cancel button "No"'
        )
        res = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
        )
        return res.returncode == 0

    if dialog_program == "zenity":
        return not subprocess.run(
            [
                "zenity",
                "--title",
                f"sudo authentication for {peer}",
                "--question",
                "--text",
                f"Allow privilege elevation on {peer}?",
                "--ok-label",
                "Authorize",
                "--cancel-label",
                "Deny",
            ]
        ).returncode

    raise ValueError(f"unknown dialog_program: {dialog_program!r}")


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


def tartarus_name_for_id(vm_id: int) -> Optional[str]:
    """id -> name via tartarus's own state dir (~/.local/state/tartarus/<name>/cid)."""
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


def tartarus_id_for_ip(ip: str) -> Optional[int]:
    """Linux: static bridge subnet 10.200.0.<id>, no lookup needed. macOS:
    `arp -an` -> MAC -> last octet is the id (vmnet-shared gives guests a
    DHCP IP unknown ahead of time, so ARP is the only host-side way to
    correlate it)."""
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


def resolve_tartarus_name(peer) -> Optional[str]:
    """`peer` is a VSOCK CID (int) or a TCP peer IP (str)."""
    if isinstance(peer, int):
        return tartarus_name_for_id(peer)
    vm_id = tartarus_id_for_ip(peer)
    if vm_id is None:
        return None
    return tartarus_name_for_id(vm_id)


def get_resolution_mode(config: dict) -> str:
    mode = config.get("resolution")
    if mode in ("none", "certificate", "tartarus"):
        return mode
    mtls = config.get("mtls")
    return "certificate" if isinstance(mtls, dict) and mtls.get("enable", False) else "tartarus"


def get_peer_name(sock, resolution: str) -> str:
    peer = sock.getpeername()[0]
    raw = f"cid {peer}" if isinstance(peer, int) else str(peer)

    if resolution == "none":
        return raw

    if resolution == "certificate" and hasattr(sock, "getpeercert"):
        cert = sock.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName")
            if cn:
                return cn
            for san_type, san_value in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    return san_value

    if resolution == "tartarus":
        name = resolve_tartarus_name(peer)
        if name:
            return name

    return raw


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
            print(f"sudo-auth-proxy: {e}", file=sys.stderr)
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


class Handler(StreamRequestHandler):
    def handle(self) -> None:
        config = getattr(self.server, "_config", {})
        set_debug(config)
        mtls = config.get("mtls", {})
        use_cert = isinstance(mtls, dict) and mtls.get("enable", False)

        # Enforce peer EKU OID on server side, once per connection -- the
        # peer's certificate/identity doesn't change across the multiple
        # sequential auth requests a persistent (proxied) connection may
        # carry.
        if use_cert:
            peer_oid = mtls.get("peer_required_oid")
            if peer_oid and hasattr(self.request, "getpeercert"):
                der = self.request.getpeercert(binary_form=True)
                if der:
                    try:
                        verify_cert_der(der, peer_oid, "Peer")
                    except (ValueError, RuntimeError) as e:
                        print(f"sudo-auth-proxy: {e}", file=sys.stderr)
                        return

        resolution = get_resolution_mode(config)
        peer = get_peer_name(self.request, resolution)
        dialog_program = config.get("dialog_program") or ("swiftdialog" if sys.platform == "darwin" else "zenity")
        print(f"sudo-auth-proxy server: connection from {peer} ({self.client_address})", flush=True)

        # Loop over multiple sequential auth requests on the same connection
        # (not just one) so a persistent caller (the guest-side reuse proxy)
        # can keep its already-completed TLS handshake warm across many
        # `sudo` invocations instead of reconnecting for each one. A one-shot
        # caller sends exactly one request line and closes right after
        # reading its response, which this loop sees as clean EOF on the
        # next readline() and returns, exactly as before.
        while True:
            t0 = time.monotonic()
            line = self.rfile.readline()
            if not line:
                break
            _debug(f"server: request {line.strip()!r} from {peer}")
            ret = prompt_for_confirmation(peer, dialog_program)
            response = b"1\n" if ret else b"0\n"
            try:
                self.wfile.write(response)
                self.wfile.flush()
            except Exception:
                break
            _debug(f"server: replied to {peer} in {_ms(time.monotonic() - t0)}")


def server_get_request(self):
    sock, addr = TCPServer.get_request(self)
    print(f"sudo-auth-proxy server: accepted TCP connection from {addr}", flush=True)
    if self.ssl_context:
        try:
            sock = self.ssl_context.wrap_socket(sock, server_side=True)
        except ssl.SSLError as e:
            print(f"SSL handshake failed from {addr}: {e}", file=sys.stderr)
            sock.close()
            raise
    return sock, addr


def get_transport_family(transport: str) -> int:
    if transport == "vsock":
        if not hasattr(socket, "AF_VSOCK"):
            raise RuntimeError("VSOCK not supported on this platform")
        return socket.AF_VSOCK
    return socket.AF_INET


def run_server(config: dict) -> None:
    set_debug(config)
    transport = config.get("transport", "vsock")
    port = config.get("port", 65001)
    ssl_ctx = create_ssl_context(config, server=True)
    family = get_transport_family(transport)

    if transport == "vsock":
        bind = (config.get("cid", 2), port)
    else:
        bind = (config.get("host", "127.0.0.1"), port)

    server_class = type(
        "ProxyServer",
        (ThreadingMixIn, TCPServer),
        {
            "address_family": family,
            "ssl_context": ssl_ctx,
            "_config": config,
            "get_request": server_get_request,
        },
    )

    server = server_class(bind, Handler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        print(
            f"sudo-auth-proxy server listening on {bind} (transport={transport}, tls={ssl_ctx is not None})",
            flush=True,
        )
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


class ThreadedUnixServer(ThreadingMixIn, UnixStreamServer):
    allow_reuse_address = True


class PersistentConnection:
    """A single persistent mTLS connection to the remote sudo-auth-proxy
    server, shared across every local (PAM-invoked) request relayed through
    the proxy's unix socket -- so the handshake is only paid once instead of
    on every single `sudo` invocation. Connected eagerly at startup (see
    `run_proxy`) and reconnected once transparently on failure. Only one
    request is ever in flight at a time -- enforced by `lock`.
    """

    def __init__(self, config: dict):
        self.config = config
        self.lock = threading.Lock()
        self.sock = None

    def _address(self):
        transport = self.config.get("transport", "vsock")
        if transport == "vsock":
            return (self.config.get("cid", 2), self.config.get("port", 65001))
        host = self.config.get("host", "127.0.0.1")
        if host == "_gateway":
            host = resolve_default_gateway()
        return (host, self.config.get("port", 65001))

    def _connect(self):
        t0 = time.monotonic()
        transport = self.config.get("transport", "vsock")
        family = get_transport_family(transport)
        addr = self._address()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.connect(addr)
        t1 = time.monotonic()
        ssl_ctx = create_ssl_context(self.config, server=False)
        if ssl_ctx:
            server_hostname = addr[0] if transport == "tcp" else None
            sock = ssl_ctx.wrap_socket(sock, server_hostname=server_hostname)
            mtls = self.config.get("mtls", {})
            peer_oid = mtls.get("peer_required_oid")
            if peer_oid:
                der = sock.getpeercert(binary_form=True)
                if der:
                    verify_cert_der(der, peer_oid, "Server")
        t2 = time.monotonic()
        _debug(f"proxy: connect={_ms(t1 - t0)} tls={_ms(t2 - t1)}")
        return sock

    def ensure_connected(self) -> None:
        with self.lock:
            if self.sock is None:
                try:
                    self.sock = self._connect()
                except Exception as e:
                    print(
                        f"sudo-auth-proxy: initial connection failed ({e}); will retry on first request",
                        file=sys.stderr,
                    )

    def request(self, line: bytes) -> bytes:
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
                    self.sock.sendall(line)
                    data = b""
                    while b"\n" not in data:
                        chunk = self.sock.recv(64)
                        if not chunk:
                            raise ConnectionError("remote closed the connection")
                        data += chunk
                    _debug(f"proxy: roundtrip={_ms(time.monotonic() - t0)}")
                    return data
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


def _run_via_proxy(proxy_socket_path: str) -> None:
    """Relay one auth request through the local reuse-proxy daemon. Raises
    on any connection problem (proxy not running) so the caller can fall
    back to a direct connection; exits the process on a real decision."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(proxy_socket_path)
        s.sendall(b"auth\n")
        data = b""
        while b"\n" not in data:
            chunk = s.recv(64)
            if not chunk:
                raise ConnectionError("proxy closed the connection")
            data += chunk
    finally:
        s.close()

    if data.startswith(b"2"):
        # Proxy's own remote connection is down -- not a real denial. Raise
        # so the caller (run_client) falls back to a direct connection,
        # exactly as it would if this local socket weren't there at all.
        raise ConnectionError("proxy's remote connection is unavailable")

    _debug(f"via proxy: final decision: {'approved' if data.startswith(b'1') else 'denied'} (data={data!r})")
    if data.startswith(b"1"):
        sys.exit(0)
    else:
        sys.exit(1)


def run_client(config: dict) -> None:
    proxy_socket = config.get("proxy_socket")
    if proxy_socket:
        proxy_path = expand_socket_path(proxy_socket)
        try:
            _run_via_proxy(proxy_path)
            return
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            _debug(f"proxy socket {proxy_path} unavailable ({e}); falling back to direct connection")

    transport = config.get("transport", "vsock")
    host = config.get("host", "127.0.0.1")
    port = config.get("port", 65001)
    cid = config.get("cid", 2)
    _debug(f"direct: transport={transport} host={host!r} port={port} cid={cid}")
    ssl_ctx = create_ssl_context(config, server=False)
    _debug(f"ssl_ctx created: {ssl_ctx is not None}")
    mtls = config.get("mtls", {})

    if transport == "tcp" and host == "_gateway":
        try:
            host = resolve_default_gateway()
            _debug(f"resolved _gateway -> {host}")
        except Exception as e:
            _debug(f"gateway resolution failed: {e!r}")
            print(f"sudo-auth-proxy client: failed to resolve default gateway: {e}", file=sys.stderr)
            sys.exit(1)

    family = get_transport_family(transport)

    if transport == "vsock":
        addr = (cid, port)
    else:
        addr = (host, port)

    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        _debug(f"connecting to {addr!r}")
        s.connect(addr)
        _debug("tcp connected")
        if ssl_ctx:
            server_hostname = host if transport == "tcp" else None
            _debug(f"starting TLS handshake, server_hostname={server_hostname!r}")
            s = ssl_ctx.wrap_socket(s, server_hostname=server_hostname)
            _debug("TLS handshake OK")

            # Enforce peer EKU OID on client side
            peer_oid = mtls.get("peer_required_oid")
            if peer_oid:
                der = s.getpeercert(binary_form=True)
                if der:
                    try:
                        verify_cert_der(der, peer_oid, "Server")
                        _debug("peer OID check OK")
                    except (ValueError, RuntimeError) as e:
                        _debug(f"peer OID check FAILED: {e!r}")
                        print(f"sudo-auth-proxy: {e}", file=sys.stderr)
                        s.close()
                        sys.exit(1)

        s.sendall(b"auth\n")
        data = b""
        while b"\n" not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        _debug(f"received: {data!r}")
    except Exception as e:
        _debug(f"connection failed: {e!r}")
        print(f"sudo-auth-proxy client: connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            s.close()
        except Exception:
            pass

    _debug(f"final decision: {'approved' if data.startswith(b'1') else 'denied'} (data={data!r})")
    if data.startswith(b"1"):
        sys.exit(0)
    else:
        sys.exit(1)


def run_proxy(config: dict) -> None:
    listen_path = expand_socket_path(config.get("proxy_socket") or DEFAULT_PROXY_SOCKET)
    listen = Path(listen_path)
    listen.parent.mkdir(parents=True, exist_ok=True)
    if listen.exists():
        listen.unlink()

    remote = PersistentConnection(config)
    remote.ensure_connected()

    class ProxyHandler(StreamRequestHandler):
        def handle(self) -> None:
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                try:
                    response = remote.request(line)
                except Exception as e:
                    # The persistent connection's own reconnect-once retry
                    # already failed -- the remote is genuinely down (e.g.
                    # mid-restart), not a denial. b"2\n" tells the client to
                    # retry with a direct connection instead of treating this
                    # as sudo being denied.
                    print(f"sudo-auth-proxy: proxy request failed: {e}", file=sys.stderr)
                    response = b"2\n"
                try:
                    self.wfile.write(response)
                    self.wfile.flush()
                except Exception:
                    break

    old_umask = os.umask(0o111)
    try:
        server = ThreadedUnixServer(str(listen), ProxyHandler)
    finally:
        os.umask(old_umask)
    # Any local user's `sudo` invocation may need to reach this socket (the
    # PAM hook runs as the invoking user, not root, and sudo isn't limited to
    # one user), so it's left world-connectable -- matching the
    # already-world-readable posture of /etc/sudo-auth-proxy/config.toml.
    os.chmod(listen, 0o666)

    print(
        f"sudo-auth-proxy proxy listening on unix:{listen} "
        f"(forwarding to transport={config.get('transport', 'vsock')})",
        flush=True,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sudo-auth-proxy",
        description="Proxy sudo authentication prompts between hosts.",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the TOML configuration file.",
    )
    args = parser.parse_args()

    set_debug({})  # env-var only; config isn't loaded yet
    _debug(f"main() entered: argv={sys.argv!r} uid={os.getuid()} euid={os.geteuid()} config_path={args.config!r}")

    try:
        config = load_config(args.config)
    except Exception as e:
        _debug(f"load_config FAILED: {e!r}")
        raise
    set_debug(config)
    _debug(f"config loaded: mode={config.get('mode')!r}")
    mode = config.get("mode", "server")

    if mode == "server":
        run_server(config)
    elif mode == "client":
        run_client(config)
    elif mode == "proxy":
        run_proxy(config)
    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _debug("process started")
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:
        import traceback
        _debug(f"UNCAUGHT EXCEPTION: {e!r}\n{traceback.format_exc()}")
        raise

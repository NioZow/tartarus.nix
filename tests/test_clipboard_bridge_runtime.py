"""Runtime regressions for clipboard-bridge admin targeting.

These tests drive a real server subprocess over plaintext Unix and TCP
listeners. They use only the standard library so they run under the development
Python (which lacks ``cryptography``); TLS paths are covered by the Nix-built
package in a separate integration step.

Covered regressions:

* an admin ``get`` with ``json = true`` and ``target`` must return only the
  requested target, never every client slot (D1);
* a friendly-name target must resolve through ``[[tcp_vm]]``/``[[vm]]`` and the
  registered clients instead of creating a phantom name-keyed slot (D6).
"""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "clipboard-bridge"
    / "clipboard-bridge.py"
)

NONE_SECURITY = """\
[listeners.security]
transport_encryption = "none"
client_auth = "none"
server_auth = "none"
"""


def _free_tcp_port() -> int:
    """Return a currently unused loopback TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "server.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _read_response(sock: socket.socket) -> dict:
    """Read one newline-delimited JSON response."""
    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
    assert buffer, "server closed the connection without a response"
    return json.loads(buffer.split(b"\n", 1)[0].decode("utf-8"))


def _request_unix(socket_path: Path, payload: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(socket_path))
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        return _read_response(sock)


def _request_tcp(
    address: tuple[str, int], payload: dict, *, source: str | None = None
) -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        if source is not None:
            sock.bind((source, 0))
        sock.connect(address)
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        return _read_response(sock)


def _wait_until_ready(process: subprocess.Popen, socket_path: Path) -> None:
    """Wait for the admin socket, failing with the server log if it exits."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                "clipboard-bridge server exited early:\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        if socket_path.exists():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.connect(str(socket_path))
                return
            except OSError:
                pass
        time.sleep(0.02)
    process.kill()
    raise AssertionError("clipboard-bridge server did not bind its admin socket")


def _start_server(
    config_path: Path, admin_socket: Path
) -> subprocess.Popen:
    process = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--config",
            str(config_path),
            "serve",
            "--no-notify",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_until_ready(process, admin_socket)
    return process


def _stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    process.communicate()


def test_admin_json_get_with_target_returns_only_that_target(
    tmp_path: Path,
) -> None:
    """A target-scoped rule must not leak other slots through ``json = true``."""
    admin_socket = tmp_path / "admin.sock"
    config = _write_config(
        tmp_path,
        f"""\
mode = "server"

[[listeners]]
type = "unix"
name = "admin"
socket = {json.dumps(str(admin_socket))}
admin = true
resolution = "none"

{NONE_SECURITY}
[[rule]]
match.listeners = ["admin"]
match.action = ["set"]
match.target = ["dev", "other"]
policy = "allow"

[[rule]]
match.listeners = ["admin"]
match.action = ["get"]
match.target = ["dev"]
policy = "allow"
""",
    )

    process = _start_server(config, admin_socket)
    try:
        assert (
            _request_unix(
                admin_socket, {"action": "set", "target": "dev", "data": "DEV"}
            )["status"]
            == "ok"
        )
        assert (
            _request_unix(
                admin_socket,
                {"action": "set", "target": "other", "data": "OTHER"},
            )["status"]
            == "ok"
        )

        targeted = _request_unix(
            admin_socket, {"action": "get", "target": "dev", "json": True}
        )
        assert targeted["status"] == "ok"
        assert set(targeted["data"]) == {"dev"}
        assert targeted["data"]["dev"]["data"] == "DEV"
    finally:
        _stop_server(process)


def test_friendly_name_target_resolves_through_the_tcp_vm_map(
    tmp_path: Path,
) -> None:
    """A pre-registration ``set target=notes`` must not create a phantom slot."""
    admin_socket = tmp_path / "admin.sock"
    port = _free_tcp_port()
    # 127.0.0.10 stands in for the design's 10.201.0.10: it is bindable on the
    # loopback /8 without CAP_NET_ADMIN, and it exercises the same source-IP ->
    # [[tcp_vm]] name resolution.
    guest_source = "127.0.0.10"
    guest_id = f"tcp:{guest_source}"
    config = _write_config(
        tmp_path,
        f"""\
mode = "server"

[[tcp_vm]]
ip = {json.dumps(guest_source)}
name = "notes"

[[listeners]]
type = "tcp"
name = "guest"
host = "127.0.0.1"
port = {port}
resolution = "tartarus"

{NONE_SECURITY}
[[listeners]]
type = "unix"
name = "admin"
socket = {json.dumps(str(admin_socket))}
admin = true
resolution = "none"

{NONE_SECURITY}
[[rule]]
match.listeners = ["admin"]
policy = "allow"
""",
    )

    process = _start_server(config, admin_socket)
    try:
        early = _request_unix(
            admin_socket, {"action": "set", "target": "notes", "data": "EARLY"}
        )
        assert early["status"] == "ok"

        stored = _request_unix(admin_socket, {"action": "get", "json": True})
        assert stored["status"] == "ok"
        assert set(stored["data"]) == {guest_id}
        assert stored["data"][guest_id]["data"] == "EARLY"

        address = ("127.0.0.1", port)
        assert (
            _request_tcp(
                address, {"action": "register"}, source=guest_source
            )["status"]
            == "ok"
        )
        assert (
            _request_tcp(
                address, {"action": "set", "data": "REAL"}, source=guest_source
            )["status"]
            == "ok"
        )

        by_name = _request_unix(
            admin_socket, {"action": "get", "target": "notes"}
        )
        assert by_name["status"] == "ok"
        assert by_name["data"] == "REAL"

        by_id = _request_unix(
            admin_socket, {"action": "get", "target": guest_id}
        )
        assert by_id["status"] == "ok"
        assert by_id["data"] == "REAL"

        slots = _request_unix(admin_socket, {"action": "get", "json": True})
        assert set(slots["data"]) == {guest_id}
    finally:
        _stop_server(process)

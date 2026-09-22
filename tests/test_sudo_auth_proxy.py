"""Tests for ``sudo-auth-proxy`` (redesign Phases 1-6).

Behaviours covered:

1. the NDJSON framing -- newline-delimited compact JSON (doc §6.1): one object
   per ``\\n``-terminated line, a 64 KiB cap enforced before parsing, and a
   strict fail-closed parse (unknown/missing ``v``/``type``, missing required
   fields, malformed frames and trailing data all rejected; unknown top-level
   keys ignored);
2. the ``unix`` transport -- a single AF_UNIX listener whose socket is ``0600``
   in a ``0700`` directory (both owned by the server user), a client that only
   ever uses ``$SUDO_AUTH_PROXY_SOCK`` (and fails closed when it is absent), and
   one listener serving concurrent sessions;
3. mTLS EKU enforcement -- ``verify_cert_der`` / ``verify_cert_file`` accept a
   certificate carrying the required extended-key-usage OID and reject one that
   does not (skipped cleanly when ``cryptography`` is unavailable);
4. dialog enrichment and sanitisation (Phase 7, doc §11) -- ``Confirmation``
   carries the verified requester identity, its ACL label, and the sanitised
   session metadata; ``prompt_for_confirmation`` builds the expected argv for
   ``swiftdialog``, ``osascript`` and ``zenity`` (with ``--no-markup``,
   JSON encoding and swiftDialog markup escaping respectively) and maps the
   child return code to a boolean. The NFC + allow-list sanitiser is exercised
   with hostile inputs (newlines, ANSI/control, bidi overrides, swiftDialog
   markup, ``%``, very long strings) and is asserted to run before logging. The
   command/argv is never shown, read or logged (review log S5);
5. Phase 2 client hardening -- the ``SUDO_AUTH_PROXY_ACTIVE`` recursion guard
   (doc §10.4), the selector ``lstat``/ownership/symlink checks (doc §9.2) and
   the Linux ``SO_PEERCRED`` -> ``/proc/<pid>/exe`` ``sshd`` peer-process check
   (doc §9.2, T21), the last exercised with fake sockets and a fake ``/proc``
   root (no real ``sshd``/``ssh`` is involved anywhere);
6. Phase 5 permission hardening (doc §9; review logs F6/F12) -- the server
   refuses a symlink or non-owned bind target, the peer-uid authorization
   ``authorize_unix_peer`` fails closed on a foreign uid (Linux) and degrades
   with a documented weaker guarantee on Darwin, and ``src/tartarus/ca.py``
   emits client private keys ``0600`` rather than the historic ``0644``;
7. Phase 6 fast-fail/timeout semantics (doc §10.1-§10.5, §6.7; review logs
   NF4, Rank 5/R7, F5) -- ``resolve_read_timeouts`` maps ``decision_timeout =
   0`` to an unbounded tail, a silent Unix peer is bounded by ``recv_timeout``
   rather than hanging until the decision, an unreachable/closed peer fails
   within the connect bound, a numeric host never triggers DNS, and the client
   logs ``denied`` distinctly from ``unavailable`` (the exit code stays
   collapsed because ``pam_exec`` cannot branch on it).

The legacy ``auth\\n`` -> ``1\\n`` line protocol is gone (Phase 0's
characterization of it was frozen in git); these tests pin the Phase 1 contract
instead. The service is a standalone script rather than an importable package
module, so it is loaded by path with ``importlib``; importing it has no side
effects. No real dialog is ever spawned; the dialog tests monkeypatch
``subprocess.run``. The transport tests bind real AF_UNIX sockets under
``tmp_path`` and monkeypatch only the confirmation dialog; the Phase 6
fast-fail tests additionally bind ephemeral AF_INET sockets on ``127.0.0.1``.

Run from the package root::

    python -m pytest tests/test_sudo_auth_proxy.py -v
"""

from __future__ import annotations

import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Iterator, Sequence

import pytest

SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "sources"
    / "sudo-auth-proxy.py"
)

# `src/` so the Phase 5 ca.py permission test can import the real ``tartarus``
# package (``ca.py`` uses package-relative imports and cannot be loaded by path).
SRC_PATH = Path(__file__).resolve().parents[1] / "src"

# arbitrary extended-key-usage OIDs used by the EKU tests; the exact values do
# not matter, only that one is required and the other is not.
REQUIRED_OID = "1.3.6.1.5.5.7.3.2"  # id-kp-clientAuth
OTHER_OID = "1.3.6.1.5.5.7.3.1"  # id-kp-serverAuth

# the fake AF_INET peer address the handler reports under resolution = "none".
FAKE_PEER = "127.0.0.1"


@pytest.fixture(scope="session")
def sap() -> types.ModuleType:
    """Load the standalone ``sudo-auth-proxy.py`` script as a module."""
    spec = importlib.util.spec_from_file_location(
        "sudo_auth_proxy_under_test", SOURCE_PATH
    )
    assert spec is not None and spec.loader is not None, f"cannot load {SOURCE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _isolate_sudo_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the recursion guard and ``SUDO_UID`` from leaking between tests.

    ``run_client`` sets ``SUDO_AUTH_PROXY_ACTIVE`` in ``os.environ`` -- the test
    process is that process -- and the selector/peer helpers read ``SUDO_UID``,
    so clearing both around every test keeps them independent. monkeypatch
    restores any original values on teardown.
    """
    monkeypatch.delenv("SUDO_AUTH_PROXY_ACTIVE", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)


# --- NDJSON framing helpers -----------------------------------------------


def _nonce() -> str:
    """A valid 16+-byte base64 nonce."""
    return base64.b64encode(b"n" * 32).decode("ascii")


def _request_obj(sap: types.ModuleType, **overrides: Any) -> dict:
    fields: dict[str, Any] = {
        "service": "sudo",
        "target_user": "root",
        "invoking_user": "user",
        "rhost": "",
        "tty": "/dev/pts/0",
        "cwd": "/home/user",
        "client_version": "1",
        "guest_hint": "vault",
    }
    fields.update(overrides)
    return sap.build_request(fields.pop("nonce", _nonce()), **fields)


def _frame(sap: types.ModuleType, obj: Any) -> bytes:
    """Serialise ``obj`` exactly the way the production writer does."""
    buffer = io.BytesIO()
    sap.write_message(buffer, obj)
    return buffer.getvalue()


def _decode(sap: types.ModuleType, raw: bytes) -> dict:
    return sap.read_message(io.BytesIO(raw))


# --- Phase 3 security helpers ----------------------------------------------


def _server_security(keys: Any, **overrides: Any) -> dict:
    """A valid server-side ``[security]`` block trusting the test requester key."""
    security: dict[str, Any] = {
        "transport_encryption": "none",
        "client_auth": "ssh",
        "server_auth": "signature",
        "trusted_keys": [keys.client_public],
        "server_signing_key": keys.server_private,
    }
    security.update(overrides)
    return security


def _client_security(keys: Any, **overrides: Any) -> dict:
    """A valid client-side ``[security]`` block carrying the test requester key."""
    security: dict[str, Any] = {
        "transport_encryption": "none",
        "client_auth": "ssh",
        "server_auth": "signature",
        "ssh_signing_key": keys.client_private,
        "trusted_server_keys": [keys.server_public],
    }
    security.update(overrides)
    return security


def _signed_request(sap: types.ModuleType, keys: Any, **overrides: Any) -> dict:
    """Build a request and attach a real SSH ``client_auth`` signature."""
    request = _request_obj(sap, **overrides)
    security = sap.build_security(_client_config(keys), "client")
    sap.attach_client_auth(request, security)
    return request


def _fingerprint(sap: types.ModuleType, public_line: str) -> str:
    """The ``SHA256:...`` fingerprint of an OpenSSH public-key line."""
    return sap.parse_openssh_public_key(public_line)[1]


def _acl_list(*fingerprints: str) -> dict:
    """A ``mode = "list"`` ACL; no arguments is an intentional deny-all list."""
    return {"mode": "list", "trusted_keys": list(fingerprints)}


def _acl_for(sap: types.ModuleType, keys: Any) -> dict:
    """The default allow-list ACL used by the server-side exchange helpers."""
    return _acl_list(_fingerprint(sap, keys.client_public))



def test_request_round_trips_as_one_compact_line(sap: types.ModuleType) -> None:
    request = _request_obj(sap)
    raw = _frame(sap, request)

    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert b" " not in raw  # compact separators: no pretty-printing on the wire
    assert _decode(sap, raw) == request
    assert sap.parse_request(_decode(sap, raw)) == request


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_response_round_trips(sap: types.ModuleType, decision: str) -> None:
    nonce = _nonce()
    raw = _frame(sap, sap.build_response(nonce, decision))

    assert sap.parse_response(_decode(sap, raw), nonce) == decision


def test_oversize_frame_rejected(sap: types.ModuleType) -> None:
    oversize = b"{" + b"a" * (sap.MAX_MESSAGE_BYTES + 10) + b"}\n"

    with pytest.raises(sap.ProtocolError, match="exceeds"):
        sap.read_message(io.BytesIO(oversize))


def test_frame_at_limit_accepted(sap: types.ModuleType) -> None:
    # JSON string of exactly MAX_MESSAGE_BYTES-? ... build one that ends exactly
    # at the cap: `{"x":"<pad>"}` is `len(pad) + 8` bytes.
    pad = "a" * (sap.MAX_MESSAGE_BYTES - 8)
    raw = json.dumps({"x": pad}, separators=(",", ":")).encode("utf-8") + b"\n"
    assert len(raw) == sap.MAX_MESSAGE_BYTES + 1

    assert sap.read_message(io.BytesIO(raw)) == {"x": pad}


def test_malformed_json_rejected(sap: types.ModuleType) -> None:
    with pytest.raises(sap.ProtocolError, match="not valid JSON"):
        sap.read_message(io.BytesIO(b"not-json\n"))


def test_trailing_data_rejected(sap: types.ModuleType) -> None:
    raw = _frame(sap, _request_obj(sap))[:-1] + b" trailing\n"

    with pytest.raises(sap.ProtocolError, match="not valid JSON"):
        sap.read_message(io.BytesIO(raw))


def test_non_object_frame_rejected(sap: types.ModuleType) -> None:
    with pytest.raises(sap.ProtocolError, match="not a JSON object"):
        sap.read_message(io.BytesIO(b"[1,2,3]\n"))


def test_eof_raises_connection_closed(sap: types.ModuleType) -> None:
    with pytest.raises(sap.ConnectionClosed):
        sap.read_message(io.BytesIO(b""))


def test_non_utf8_frame_rejected(sap: types.ModuleType) -> None:
    with pytest.raises(sap.ProtocolError, match="UTF-8"):
        sap.read_message(io.BytesIO(b"\xff\xfe\n"))


def test_unknown_type_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    message["type"] = "something_else"

    with pytest.raises(sap.ProtocolError, match="expected type"):
        sap.parse_request(message)


def test_missing_version_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    del message["v"]

    with pytest.raises(sap.ProtocolError, match="missing or non-integer 'v'"):
        sap.parse_request(message)


def test_unsupported_version_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    message["v"] = 2

    with pytest.raises(sap.ProtocolError, match="unsupported protocol version"):
        sap.parse_request(message)


def test_boolean_version_rejected(sap: types.ModuleType) -> None:
    # JSON `true` decodes to a bool, which Python would treat as int 1.
    message = _request_obj(sap)
    message["v"] = True

    with pytest.raises(sap.ProtocolError, match="missing or non-integer 'v'"):
        sap.parse_request(message)


def test_missing_required_field_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    del message["target_user"]

    with pytest.raises(sap.ProtocolError, match="missing required field 'target_user'"):
        sap.parse_request(message)


def test_short_nonce_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    message["nonce"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(sap.ProtocolError, match="at least 16 bytes"):
        sap.parse_request(message)


def test_invalid_base64_nonce_rejected(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    message["nonce"] = "not base64!!"

    with pytest.raises(sap.ProtocolError, match="not valid base64"):
        sap.parse_request(message)


def test_unknown_top_level_key_ignored(sap: types.ModuleType) -> None:
    message = _request_obj(sap)
    message["future_field"] = {"anything": True}

    assert sap.parse_request(message)["future_field"] == {"anything": True}


def test_response_nonce_mismatch_rejected(sap: types.ModuleType) -> None:
    good = _nonce()
    response = sap.build_response("b3RoZXI=", "allow")

    with pytest.raises(sap.ProtocolError, match="nonce does not match"):
        sap.parse_response(response, good)


@pytest.mark.parametrize("decision", ["maybe", "", 1, None])
def test_invalid_decision_rejected(sap: types.ModuleType, decision: Any) -> None:
    nonce = _nonce()
    response = sap.build_response(nonce, decision)

    with pytest.raises(sap.ProtocolError, match="'decision'"):
        sap.parse_response(response, nonce)


# --- handler over in-memory streams (no socket bound) ---------------------


class _FakeRequestSocket:
    """Minimal stand-in for the accepted socket, enough for peer resolution."""

    def __init__(self, peer: tuple[str, int]) -> None:
        self._peer = peer

    def getpeername(self) -> tuple[str, int]:
        return self._peer


class _FakeWriter:
    """Capture every write the handler performs on its response stream."""

    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, chunk: bytes) -> int:
        self.data += chunk
        return len(chunk)

    def flush(self) -> None:
        return None


def _exchange(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    decisions: Sequence[bool],
    request_bytes: bytes,
    keys: Any,
    acl: Any = None,
) -> tuple[list[bytes], list[tuple[str, str]]]:
    """Drive the real server-side ``Handler`` over fake request/file objects.

    No socket is bound and no connection is made: the handler reads the request
    bytes from an in-memory ``BytesIO`` and writes its framed response(s) into a
    recording writer, exactly as it would over a socket. The server config
    carries a real SSH trust root and host signing key, so authentication and
    response signing are exercised end to end. ``acl`` defaults to a list that
    authorizes the test requester; pass an explicit ``{"mode": "list"}`` (empty)
    to exercise the fail-closed default.

    Returns ``(frames, prompts)`` where ``frames`` is the list of complete NDJSON
    frames the handler wrote, in order. An authenticated+authorized request
    yields ``[auth_pending, auth_response]`` (audit A2); an ACL denial or an
    authentication failure yields ``[auth_response]`` or ``[]`` respectively.
    """

    config = {
        "resolution": "none",
        "dialog_program": "zenity",
        "transport": "tcp",
        "security": _server_security(keys),
        "acl": _acl_for(sap, keys) if acl is None else acl,
    }
    fake_server = types.SimpleNamespace(
        _config=config,
        _transport=sap.CallbackTransport(config, "tcp"),
        _security=sap.build_security(config, "server"),
    )
    decision_iterator = iter(decisions)
    prompts: list[tuple[Any, str]] = []

    def fake_prompt(confirmation: Any, program: str) -> bool:
        prompts.append((confirmation, program))
        return next(decision_iterator)

    monkeypatch.setattr(sap, "prompt_for_confirmation", fake_prompt)

    handler = object.__new__(sap.Handler)
    handler.request = _FakeRequestSocket((FAKE_PEER, 12345))
    handler.client_address = (FAKE_PEER, 12345)
    handler.server = fake_server
    handler.rfile = io.BytesIO(request_bytes)
    writer = _FakeWriter()
    handler.wfile = writer
    handler.handle()

    raw = bytes(writer.data)
    frames = [line + b"\n" for line in raw.split(b"\n") if line]
    return frames, prompts


@pytest.mark.parametrize(
    ("approved", "expected_decision"),
    [(True, "allow"), (False, "deny")],
)
def test_handler_answers_auth_request(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
    expected_decision: str,
    keymaterial: Any,
) -> None:
    request = _signed_request(sap, keymaterial)
    frames, prompts = _exchange(
        sap, monkeypatch, [approved], _frame(sap, request), keymaterial
    )

    # audit A2: the first frame is the immediate pre-dialog ack, the second the
    # signed decision. Both echo the request nonce.
    assert len(frames) == 2
    pending = _decode(sap, frames[0])
    assert pending["type"] == "auth_pending"
    assert pending["nonce"] == request["nonce"]
    sap.parse_pending(pending, request["nonce"])
    parsed = _decode(sap, frames[1])
    assert parsed["type"] == "auth_response"
    assert parsed["nonce"] == request["nonce"]
    assert parsed["decision"] == expected_decision
    assert parsed["request_digest"] == sap.compute_request_digest(request)
    assert sap.parse_response(parsed, request["nonce"]) == expected_decision
    # the response is signed by the configured host key
    assert parsed["server_auth"]["method"] == "signature"

    assert len(prompts) == 1
    confirmation, program = prompts[0]
    assert program == "zenity"
    # the dialog context carries the verified identity and metadata. The
    # identity is sanitised before rendering (doc §11.2), and the random test
    # fingerprint may contain `+`/`/`, which the allow-list maps to `?` -- so
    # compare against the sanitiser's output, never the raw key_id.
    assert confirmation.peer == FAKE_PEER
    assert confirmation.identity == sap.sanitize_field(request["client_auth"]["key_id"])
    assert confirmation.target_user == "root"
    assert confirmation.transport == "tcp"


def test_handler_malformed_frame_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, keymaterial: Any
) -> None:
    frames, prompts = _exchange(sap, monkeypatch, [], b"not-json\n", keymaterial)

    assert frames == []
    assert prompts == []


def test_handler_oversize_frame_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, keymaterial: Any
) -> None:
    oversize = b"{" + b"a" * (sap.MAX_MESSAGE_BYTES + 10) + b"}\n"
    frames, prompts = _exchange(sap, monkeypatch, [], oversize, keymaterial)

    assert frames == []
    assert prompts == []


# --- unix transport (real single listener) --------------------------------


@contextlib.contextmanager
def _unix_server(
    sap: types.ModuleType, sock_path: Path, keys: Any
) -> Iterator[tuple[Any, Any]]:
    """Start a real single-socket unix server under ``sock_path``.

    The server validates an SSH requester credential and signs its response
    (``server_auth = "signature"``), so the round-trip tests exercise the real
    Phase 3 authentication path, not a bypass.
    """
    config = {
        "transport": "unix",
        "socket": str(sock_path),
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "resolution": "none",
        "dialog_program": "zenity",
        "security": _server_security(keys),
        "acl": _acl_for(sap, keys),
    }
    transport = sap.UnixTransport(config)
    server = transport.listen(sap.Handler)
    server._security = sap.build_security(config, "server")
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield transport, server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        transport.cleanup()


def _client_config(keys: Any) -> dict:
    return {
        "transport": "unix",
        "resolution": "none",
        "dialog_program": "zenity",
        "connect_timeout": 0.5,
        # Generous Phase 6 bounds so a legitimate client/server round-trip is
        # never tripped by the first-byte timeout; the timing tests override
        # these with small explicit values.
        "recv_timeout": 5.0,
        "decision_timeout": 5,
        "security": _client_security(keys),
    }


def test_unix_server_round_trip(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    # The peer here is a Python test server, not sshd; neutralise the Linux
    # peer-process check (it is exercised directly further down).
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config(keymaterial))

    assert exc.value.code == 0


def test_unix_server_deny_exits_nonzero(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: False)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config(keymaterial))

    assert exc.value.code == 1


def test_unix_client_without_selector_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    # A config `socket` must never be used as a client fallback: without the
    # selector the client fails before opening anything.
    monkeypatch.delenv("SUDO_AUTH_PROXY_SOCK", raising=False)
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)

    config = _client_config(keymaterial)
    config["socket"] = str(tmp_path / "should-not-be-used.sock")
    with pytest.raises(SystemExit) as exc:
        sap.run_client(config)

    assert exc.value.code == 1
    assert not (tmp_path / "should-not-be-used.sock").exists()


def test_unix_server_one_listener_serves_concurrent_sessions(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
    # The guard is process-global and these clients share one process; in
    # production each pam_exec invocation is a separate process. Neutralise it
    # so the concurrency of the *listener* is what is under test.
    monkeypatch.setattr(sap, "recursion_guard_active", lambda: False)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        results: list[Any] = []

        def run_one() -> None:
            try:
                sap.run_client(_client_config(keymaterial))
                results.append("no-exit")
            except SystemExit as exc:
                results.append(exc.code)

        threads = [threading.Thread(target=run_one) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

    assert sorted(results) == [0, 0]


def test_unix_socket_and_directory_permissions(
    sap: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"

    with _unix_server(sap, sock_path, keymaterial):
        socket_info = os.lstat(sock_path)
        directory_info = os.lstat(sock_path.parent)

        # socket: 0600, ours, and actually a socket
        assert stat.S_ISSOCK(socket_info.st_mode)
        assert stat.S_IMODE(socket_info.st_mode) == 0o600
        assert socket_info.st_uid == os.getuid()
        assert socket_info.st_gid == os.getgid()

        # parent directory: 0700 and owner-only
        assert stat.S_ISDIR(directory_info.st_mode)
        assert stat.S_IMODE(directory_info.st_mode) == 0o700
        assert directory_info.st_uid == os.getuid()
        assert directory_info.st_gid == os.getgid()


def test_unix_refuses_symlink_bind(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    real = tmp_path / "real.sock"
    real.touch()
    link = tmp_path / "link.sock"
    link.symlink_to(real)

    transport = sap.UnixTransport({"transport": "unix", "socket": str(link)})
    with pytest.raises(RuntimeError, match="symlink"):
        transport.listen(sap.Handler)


def test_unix_refuses_regular_file_bind(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "run" / "server.sock"
    target.parent.mkdir(parents=True)
    target.write_text("not a socket")

    transport = sap.UnixTransport({"transport": "unix", "socket": str(target)})
    with pytest.raises(RuntimeError, match="not a socket"):
        transport.listen(sap.Handler)


def test_unix_refuses_non_owned_bind(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A real socket owned by us, reported under a foreign uid, is refused."""
    target = tmp_path / "run" / "server.sock"
    target.parent.mkdir(parents=True)
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.bind(str(target))
        real_lstat = os.lstat
        other_uid = os.getuid() + 1

        def fake_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
            info = real_lstat(path, *args, **kwargs)
            if os.fspath(path) == str(target):
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=other_uid)
            return info

        monkeypatch.setattr(sap.os, "lstat", fake_lstat)
        transport = sap.UnixTransport({"transport": "unix", "socket": str(target)})
        with pytest.raises(RuntimeError, match=f"not owned by uid {os.getuid()}"):
            transport.listen(sap.Handler)
    finally:
        probe.close()


# --- Phase 2: recursion guard, selector lstat, Linux peer check -----------


def test_run_client_recursion_guard_blocks_reentry(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SUDO_AUTH_PROXY_ACTIVE", "1")

    def must_not_connect(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("connect must not run under the recursion guard")

    monkeypatch.setattr(sap.UnixTransport, "connect", must_not_connect)

    with pytest.raises(SystemExit) as exc:
        sap.run_client({"transport": "unix", "resolution": "none"})

    assert exc.value.code == 1


def test_run_client_sets_recursion_guard_while_running(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config(keymaterial))

    assert exc.value.code == 0
    assert os.environ.get("SUDO_AUTH_PROXY_ACTIVE") == "1"


def test_run_client_refuses_non_sshd_peer(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keymaterial: Any
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: False)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config(keymaterial))

    assert exc.value.code == 1


def test_selector_lstat_accepts_owned_socket(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    sock_path = tmp_path / "selector.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(sock_path))
        assert sap.verify_selector_socket(str(sock_path)) is None
    finally:
        listener.close()


def test_selector_lstat_rejects_symlink(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "target.sock"
    target.touch()
    link = tmp_path / "link.sock"
    link.symlink_to(target)

    with pytest.raises(RuntimeError, match="symlink"):
        sap.verify_selector_socket(str(link))


def test_selector_lstat_rejects_non_socket(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    regular = tmp_path / "regular"
    regular.write_text("not a socket")

    with pytest.raises(RuntimeError, match="not a socket"):
        sap.verify_selector_socket(str(regular))


def test_selector_lstat_rejects_wrong_owner(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "selector.sock"
    path.touch()
    other_uid = os.getuid() + 1

    def fake_lstat(_path: str) -> types.SimpleNamespace:
        return types.SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=other_uid)

    monkeypatch.setattr(sap.os, "lstat", fake_lstat)

    # the message names the *expected* owner (this process uid), not the actual
    with pytest.raises(RuntimeError, match=f"not owned by uid {os.getuid()}"):
        sap.verify_selector_socket(str(path))


def test_selector_lstat_uses_sudo_uid(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "selector.sock"
    path.touch()
    other_uid = os.getuid() + 1

    def fake_lstat(_path: str) -> types.SimpleNamespace:
        return types.SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=other_uid)

    monkeypatch.setattr(sap.os, "lstat", fake_lstat)
    monkeypatch.setenv("SUDO_UID", str(other_uid))

    assert sap.verify_selector_socket(str(path)) is None


class _FakePeerSocket:
    """Stand-in whose ``getsockopt`` returns a canned SO_PEERCRED payload."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def getsockopt(self, _level: int, _option: int, _size: int) -> bytes:
        return self._payload


def _peer_cred(pid: int, uid: int | None = None, gid: int | None = None) -> bytes:
    return struct.pack(
        "3i",
        pid,
        os.getuid() if uid is None else uid,
        os.getgid() if gid is None else gid,
    )


def _fake_proc_exe(proc_root: Path, pid: int, target: str) -> None:
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True)
    (pid_dir / "exe").symlink_to(target)


class _FakeStatResult:
    """Minimal ``os.stat_result`` stand-in (uid/gid/mode only)."""

    def __init__(self, *, uid: int, gid: int, mode: int) -> None:
        self.st_uid = uid
        self.st_gid = gid
        self.st_mode = mode


def _fake_stat(uid: int, gid: int = 0, mode: int = 0o100755):
    """An injectable ``stat_fn`` reporting a fixed owner/gid/mode.

    The suite runs unprivileged, so it cannot create the root-owned file the
    production check requires; injecting the stat result tests the ownership
    decision directly (audit A7).
    """

    def _stat(_path: str) -> _FakeStatResult:
        return _FakeStatResult(uid=uid, gid=gid, mode=mode)

    return _stat


def test_verify_unix_peer_accepts_sshd(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    # A regular file named `sshd` that the peer cannot replace: root-owned and
    # not the peer's own file (audit A7). Real sshd is root-owned while the
    # forwarding process runs as the guest user, so this is the legitimate case.
    target = tmp_path / "sshd"
    target.write_bytes(b"# not a real sshd, just a name fixture\n")
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, str(target))

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42, uid=12345, gid=12345)),
        proc_root=str(proc_root),
        stat_fn=_fake_stat(uid=0, gid=0, mode=0o100755),
    ) is True


def test_verify_unix_peer_rejects_same_uid_readonly_sshd(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """The Round-2 A7 bypass: a same-UID `sshd` file, chmod 0555, is rejected.

    The previous check accepted any root-or-foreign read-only regular file, so a
    same-UID attacker copying their payload to `sshd` and making it read-only
    passed. Requiring root ownership and rejecting the peer's own file closes it.
    """
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, str(tmp_path / "sshd"))
    peer_uid = os.getuid()

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42, uid=peer_uid, gid=os.getgid())),
        proc_root=str(proc_root),
        stat_fn=_fake_stat(uid=peer_uid, gid=os.getgid(), mode=0o100555),
    ) is False


def test_verify_unix_peer_rejects_non_root_owned_sshd(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    """A regular read-only `sshd` owned by a *non-root* uid is not trusted (A7)."""
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, str(tmp_path / "sshd"))

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42, uid=12345, gid=12345)),
        proc_root=str(proc_root),
        stat_fn=_fake_stat(uid=54321, gid=54321, mode=0o100555),
    ) is False


def test_verify_unix_peer_rejects_peer_writable_binary(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    # A same-UID peer owns and can write its own copy: the basename-only check
    # used to accept this (audit A7).
    target = tmp_path / "sshd"
    target.write_bytes(b"# peer-writable fixture\n")
    target.chmod(0o700)
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, str(target))

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42)), proc_root=str(proc_root)
    ) is False


def test_verify_unix_peer_rejects_world_writable_binary(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    # Root-owned but world-writable is still not trusted; inject the stat so the
    # world-writable branch is exercised directly (the own/root checks pass).
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, str(tmp_path / "sshd"))

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42, uid=12345, gid=12345)),
        proc_root=str(proc_root),
        stat_fn=_fake_stat(uid=0, gid=0, mode=0o100777),
    ) is False


def test_verify_unix_peer_rejects_deleted_exe(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    # The kernel marks a replaced/upgraded target " (deleted)"; it is not the
    # system sshd, so the check fails closed.
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, "/usr/sbin/sshd (deleted)")

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42)), proc_root=str(proc_root)
    ) is False


def test_verify_unix_peer_allows_explicit_allowlisted_path(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    # An operator can supply the real sshd path(s); the allow-list bypasses the
    # ownership heuristic without weakening the basename/marker checks.
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, "/nix/store/xxx-openssh/bin/sshd")

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42)),
        proc_root=str(proc_root),
        sshd_allowlist=frozenset({"/nix/store/xxx-openssh/bin/sshd"}),
    ) is True


def test_verify_unix_peer_rejects_other_exe(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    proc_root = tmp_path / "proc"
    _fake_proc_exe(proc_root, 42, "/usr/bin/python3")

    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42)), proc_root=str(proc_root)
    ) is False


def test_verify_unix_peer_none_when_proc_missing(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    assert sap.verify_unix_peer_is_sshd(
        _FakePeerSocket(_peer_cred(42)), proc_root=str(tmp_path / "absent")
    ) is None


def test_verify_unix_peer_none_without_so_peercred(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)

    assert sap.verify_unix_peer_is_sshd(_FakePeerSocket(_peer_cred(42))) is None


# --- Phase 5: peer-uid authorization (doc §9.1; review log F12) -----------
#
# A separate local user must not reach the handler even though the socket is
# the server user's. Linux reads SO_PEERCRED and fails closed; Darwin can only
# return uid/gid (residual R11), so a readable uid must still match and an
# unavailable check degrades to the path/ownership guarantee instead of a
# silent accept.


def test_unix_peer_cred_reads_so_peercred(sap: types.ModuleType) -> None:
    assert sap._unix_peer_cred(_FakePeerSocket(_peer_cred(42))) == (
        42,
        os.getuid(),
        os.getgid(),
    )


def test_authorize_unix_peer_accepts_same_uid(sap: types.ModuleType) -> None:
    assert sap.authorize_unix_peer(_FakePeerSocket(_peer_cred(42))) == os.getuid()


def test_authorize_unix_peer_refuses_foreign_uid(sap: types.ModuleType) -> None:
    payload = struct.pack("3i", 42, os.getuid() + 1, os.getgid())

    with pytest.raises(RuntimeError, match="not the server user"):
        sap.authorize_unix_peer(_FakePeerSocket(payload))


def test_authorize_unix_peer_fails_closed_without_credential_on_linux(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED is Linux-only; Darwin degrades instead")
    monkeypatch.setattr(sap, "_unix_peer_cred", lambda *_a, **_k: None)

    with pytest.raises(RuntimeError, match="cannot read the unix peer"):
        sap.authorize_unix_peer(_FakePeerSocket(_peer_cred(42)))


def test_authorize_unix_peer_degrades_when_darwin_check_unavailable(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Darwin cannot report a peer credential, so the weaker path/ownership
    # guarantee applies (residual R11) rather than a hard refusal.
    monkeypatch.setattr(sap, "_darwin_peer_uid", lambda _sock: None)

    assert sap.authorize_unix_peer(_FakePeerSocket(b""), platform="darwin") is None


def test_darwin_peer_uid_reads_local_peercred(sap: types.ModuleType) -> None:
    # struct xucred begins with (cr_version, cr_uid); the fallback reads it via
    # LOCAL_PEERCRED even though CPython's socket has no getpeereid.
    payload = struct.pack("2i", 0, 4242)

    assert sap._darwin_peer_uid(_FakePeerSocket(payload)) == 4242


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to connect as another uid")
def test_authorize_unix_peer_refuses_real_foreign_uid(sap: types.ModuleType) -> None:
    """A real SO_PEERCRED read from a process that dropped to another uid.

    Skipped unless root, because only root can create a listener another user
    may connect to and drop to that user. The listener lives in a
    world-traversable directory (the pytest tmp dir is 0700) with a 0777 socket,
    since connecting to an AF_UNIX socket requires write permission on it.
    """
    import pwd
    import tempfile

    try:
        other_uid = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no 'nobody' user to drop to")
    if other_uid == os.getuid():
        pytest.skip("'nobody' is this process's uid")

    work = Path(tempfile.mkdtemp(prefix="sap-peer-", dir="/tmp"))
    sock_path = work / "peer.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(sock_path))
        os.chmod(work, 0o711)
        os.chmod(sock_path, 0o777)
        listener.listen(1)

        child = os.fork()
        if child == 0:
            try:
                os.setgroups([])
                os.setgid(other_uid)
                os.setuid(other_uid)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(sock_path))
                client.close()
            except BaseException:
                pass
            finally:
                os._exit(0)

        connection, _ = listener.accept()
        try:
            with pytest.raises(RuntimeError, match="not the server user"):
                sap.authorize_unix_peer(connection)
        finally:
            connection.close()
        assert os.WIFEXITED(os.waitpid(child, 0)[1])
    finally:
        listener.close()
        shutil.rmtree(work, ignore_errors=True)


# --- mTLS EKU enforcement -------------------------------------------------


@pytest.fixture(scope="session")
def crypto() -> types.ModuleType:
    """Skip the crypto tests cleanly when ``cryptography`` is not installed."""
    return pytest.importorskip("cryptography")


def _write_ed25519_keypair(directory: Path, name: str):
    """Generate an Ed25519 keypair; return ``(private_path, public_line)``."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_path = directory / f"{name}.key"
    private_path.write_bytes(private_bytes)
    public_line = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return str(private_path), public_line


@pytest.fixture(scope="session")
def keymaterial(crypto: types.ModuleType, tmp_path_factory: pytest.TempPathFactory):
    """Ed25519 requester + host signing keys shared by the Phase 3 tests.

    The requester private key is written as PEM (the loader also accepts
    OpenSSH); the public lines are inline OpenSSH keys so they can be used
    directly as a keyring entry. ``keymaterial`` is session-scoped so the
    key-generation cost is paid once.
    """
    directory = tmp_path_factory.mktemp("sap-keys")
    client_private, client_public = _write_ed25519_keypair(directory, "client")
    server_private, server_public = _write_ed25519_keypair(directory, "server")
    return types.SimpleNamespace(
        client_private=client_private,
        client_public=client_public,
        server_private=server_private,
        server_public=server_public,
    )



def _build_cert(oid: str | None):
    """Build a self-signed certificate, optionally carrying one EKU OID."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sudo-auth-proxy-test")])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if oid is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid)]),
            critical=False,
        )
    # Ed25519 signs with algorithm=None; passing a hash raises on modern
    # cryptography.
    return builder.sign(key, None)


def _cert_der(oid: str | None) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return _build_cert(oid).public_bytes(Encoding.DER)


def _cert_pem(oid: str | None) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return _build_cert(oid).public_bytes(Encoding.PEM)


def test_verify_cert_der_accepts_required_eku(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    assert sap.verify_cert_der(_cert_der(REQUIRED_OID), REQUIRED_OID, "Peer") is None


def test_verify_cert_der_rejects_wrong_eku(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    with pytest.raises(ValueError, match="missing required EKU OID"):
        sap.verify_cert_der(_cert_der(OTHER_OID), REQUIRED_OID, "Peer")


def test_verify_cert_der_rejects_absent_eku(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    with pytest.raises(ValueError, match="missing required EKU OID"):
        sap.verify_cert_der(_cert_der(None), REQUIRED_OID, "Peer")


def test_verify_cert_file_accepts_required_eku(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    cert_path = tmp_path / "local.pem"
    cert_path.write_bytes(_cert_pem(REQUIRED_OID))

    assert sap.verify_cert_file(str(cert_path), REQUIRED_OID, "Local") is None


def test_verify_cert_file_rejects_wrong_eku(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    cert_path = tmp_path / "local.pem"
    cert_path.write_bytes(_cert_pem(OTHER_OID))

    with pytest.raises(ValueError, match="missing required EKU OID"):
        sap.verify_cert_file(str(cert_path), REQUIRED_OID, "Local")


# --- Phase 7: dialog enrichment + sanitisation (doc §11) -------------------
#
# Every field shown in a dialog or written to a log is attacker-influenced and
# must pass the NFC + allow-list sanitiser first (doc §11.1-§11.2; review logs
# NF2/NF8/T12/T17). The helpers below build the same `Confirmation` the handler
# builds, so the argv assertions run over the real sanitised payload.

# each entry records the argv and keyword arguments passed to subprocess.run.
RunCall = tuple[Sequence[str], dict[str, Any]]


def _install_fake_run(
    monkeypatch: pytest.MonkeyPatch, returncode: int
) -> list[RunCall]:
    """Replace ``subprocess.run`` with a recorder; never spawn a dialog."""
    calls: list[RunCall] = []

    def fake_run(
        argv: Sequence[str], *args: Any, **kwargs: Any
    ) -> types.SimpleNamespace:
        calls.append((list(argv), dict(kwargs)))
        return types.SimpleNamespace(returncode=returncode)

    # the script calls ``subprocess.run`` through the module-level name, so
    # patching the shared ``subprocess`` module object is what it observes.
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _confirmation(
    sap: types.ModuleType,
    *,
    peer: str = "vault",
    identity: str = "SHA256:AbCdEf",
    label: str = "vault",
    transport: str = "unix",
    now: float = 1_700_000_000,
    **request_overrides: Any,
) -> Any:
    """Build the handler's sanitised dialog context for a test.

    ``request_overrides`` are passed to ``_request_obj`` so a test can inject a
    hostile ``tty``/``cwd``/``guest_hint`` without hand-writing a request.
    """
    request = _request_obj(sap, **request_overrides)
    return sap.build_confirmation(
        peer=peer,
        identity=identity,
        label=label,
        request=request,
        transport=transport,
        now=now,
    )


@pytest.mark.parametrize(
    ("returncode", "approved"),
    [(0, True), (1, False)],
)
def test_swiftdialog_argument_construction(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    approved: bool,
) -> None:
    calls = _install_fake_run(monkeypatch, returncode)
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "swiftdialog") is approved

    argv, kwargs = calls[0]
    assert argv[0] == "dialog"
    assert (
        "--title" in argv and argv[argv.index("--title") + 1] == "Privilege Elevation"
    )
    message = argv[argv.index("--message") + 1]
    # the verified identity, its label and the session metadata are shown
    assert "SHA256:AbCdEf" in message
    assert "vault" in message
    assert "user -> root" in message
    assert "Service: sudo" in message
    # ...and the command/argv is absent (review log S5)
    assert "command" not in message.lower()
    assert "cmdline" not in message.lower()
    assert kwargs.get("capture_output") is True


@pytest.mark.parametrize(
    ("returncode", "approved"),
    [(0, True), (1, False)],
)
def test_osascript_argument_construction(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    approved: bool,
) -> None:
    calls = _install_fake_run(monkeypatch, returncode)
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "osascript") is approved

    argv, kwargs = calls[0]
    assert argv[0] == "osascript"
    assert argv[1] == "-e"
    script = argv[2]
    # the message is JSON-encoded before it is embedded in the AppleScript
    assert json.dumps(sap.confirmation_message(confirmation)) in script
    assert json.dumps("sudo authentication for vault") in script
    assert "SHA256:AbCdEf" in json.dumps(sap.confirmation_message(confirmation))
    assert kwargs.get("capture_output") is True


@pytest.mark.parametrize(
    ("returncode", "approved"),
    [(0, True), (1, False), (7, False)],
)
def test_zenity_argument_construction(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    approved: bool,
) -> None:
    calls = _install_fake_run(monkeypatch, returncode)
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "zenity") is approved

    argv, kwargs = calls[0]
    assert argv[0] == "zenity"
    assert "--question" in argv
    # markup is explicitly disabled (doc §11.2)
    assert "--no-markup" in argv
    assert (
        "--title" in argv
        and argv[argv.index("--title") + 1] == "sudo authentication for vault"
    )
    assert "--text" in argv
    text = argv[argv.index("--text") + 1]
    assert text == sap.confirmation_message(confirmation)
    assert "SHA256:AbCdEf" in text
    assert "user -> root" in text
    assert "command" not in text.lower()
    # zenity is not invoked with capture_output (its dialog is seen, not parsed).
    assert "capture_output" not in kwargs


def test_unknown_dialog_program_raises(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_fake_run(monkeypatch, 0)
    confirmation = _confirmation(sap)

    with pytest.raises(ValueError, match="unknown dialog_program"):
        sap.prompt_for_confirmation(confirmation, "kdialog")

    assert calls == []


# -- Phase 7: sanitiser unit behaviour (doc §11.2) --------------------------


def test_sanitize_field_preserves_allow_list(sap: types.ModuleType) -> None:
    assert (
        sap.sanitize_field("user_1@host:/tmp-dir/file.name ")
        == "user_1@host:/tmp-dir/file.name "
    )


def test_sanitize_field_replaces_newlines_and_control(sap: types.ModuleType) -> None:
    assert sap.sanitize_field("new\nline") == "new?line"
    assert sap.sanitize_field("tab\there") == "tab?here"
    assert sap.sanitize_field("ansi\x1b[31m") == "ansi??31m"
    # a percent is not in the allow-list (it has no shell meaning here, but the
    # allow-list is uniform for every field)
    assert sap.sanitize_field("percent%") == "percent?"


def test_sanitize_field_neutralises_swiftdialog_markup(sap: types.ModuleType) -> None:
    assert sap.sanitize_field("star*bracket[x](y)") == "star?bracket?x??y?"


def test_sanitize_field_neutralises_bidi_overrides(sap: types.ModuleType) -> None:
    # U+202E RIGHT-TO-LEFT OVERRIDE and U+202A LEFT-TO-RIGHT EMBEDDING
    assert sap.sanitize_field("ab\u202ecd") == "ab?cd"
    assert sap.sanitize_field("\u202aabc") == "?abc"


def test_sanitize_field_nfc_collapses_equivalent_sequences(
    sap: types.ModuleType,
) -> None:
    # NFC first: the decomposed (A + U+030A) and precomposed (U+00C5) forms
    # collapse to one code point, which the allow-list then maps to `?`.
    assert sap.sanitize_field("A\u030a") == sap.sanitize_field("\u00c5") == "?"


def test_sanitize_field_caps_length(sap: types.ModuleType) -> None:
    assert len(sap.sanitize_field("a" * 5000)) == sap.SANITIZE_MAX_LENGTH


def test_sanitize_field_coerces_non_strings(sap: types.ModuleType) -> None:
    assert sap.sanitize_field(None) == ""
    assert sap.sanitize_field(42) == "42"


def test_swiftdialog_escape_runs_after_allow_list(sap: types.ModuleType) -> None:
    # the escape pass turns the raw markup into literal characters...
    assert sap.escape_swiftdialog_markup("*[x](y)") == "\\*\\[x\\]\\(y\\)"
    # ...but after sanitisation there is nothing left for it to escape
    sanitised = sap.sanitize_field("*[x](y)")
    assert sap.escape_swiftdialog_markup(sanitised) == sanitised


@pytest.mark.parametrize("program", ["zenity", "osascript", "swiftdialog"])
def test_hostile_fields_never_reach_dialog_argv(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, program: str
) -> None:
    """A crafted field cannot smuggle markup/control/newlines into the argv."""
    calls = _install_fake_run(monkeypatch, 0)
    hostile = "x\ny\rz\x1b[31m*\u202e"
    confirmation = _confirmation(
        sap,
        peer=hostile,
        identity=hostile,
        label=hostile,
        transport=hostile,
        service=hostile,
        target_user=hostile,
        # a very long field must be capped before it reaches argv
        invoking_user=hostile + "L" * 5000,
        tty=hostile,
        rhost=hostile,
        cwd=hostile,
    )

    sap.prompt_for_confirmation(confirmation, program)

    argv, _ = calls[0]
    joined = "\n".join(argv)
    # the hostile code points are gone...
    assert "\r" not in joined
    assert "\x1b" not in joined
    assert "\u202e" not in joined
    assert "*" not in joined
    # ...the field's newline became `?` (so it cannot forge a dialog/log line)...
    assert "x?y?z" in joined
    # ...the length cap was applied...
    assert "L" * (sap.SANITIZE_MAX_LENGTH + 1) not in joined
    # ...and the sanitiser's replacement is what the backend sees
    assert "?" in joined


# -- Phase 7: sanitisation before logging + command never read (S5/NF8) ------


def test_request_fields_are_sanitized_before_logging(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    keymaterial: Any,
    capsys: pytest.CaptureFixture,
) -> None:
    """The server's debug log carries only sanitised fields (review log NF8)."""
    monkeypatch.setenv("SUDO_AUTH_PROXY_DEBUG", "1")
    # `set_debug` mutates the module global; record and restore it.
    monkeypatch.setattr(sap, "debug_enabled", False)
    request = _signed_request(
        sap,
        keymaterial,
        tty="/dev/pts/0\nEVIL\r\x1b[31m",
        invoking_user="user\u202e",
        guest_hint="hi\nthere",
    )

    _exchange(sap, monkeypatch, [True], _frame(sap, request), keymaterial)
    err = capsys.readouterr().err

    # a newline in a field cannot start a forged log record
    assert "\nEVIL" not in err
    assert "\x1b" not in err
    assert "\u202e" not in err
    # the sanitised surrogate is logged instead
    assert "?EVIL" in err
    assert "hi?there" in err
    # never the raw request bytes
    assert '"v":1' not in err


def test_command_is_never_read_or_logged() -> None:
    """The command/argv is deliberately absent from the protocol (S5)."""
    source = SOURCE_PATH.read_text()
    assert "cmdline" not in source
    assert "PR_SET_MM" not in source
    assert "shell=True" not in source


def test_confirmation_shows_verified_identity_and_omits_command(
    sap: types.ModuleType,
) -> None:
    request = _request_obj(sap, guest_hint="ignored")
    confirmation = sap.build_confirmation(
        peer="vault",
        identity="SHA256:abc",
        label="alice-laptop",
        request=request,
        transport="unix",
        now=1_700_000_000,
    )

    message = sap.confirmation_message(confirmation)

    assert "alice-laptop (SHA256:abc)" in message
    assert "user -> root" in message
    assert "Service: sudo" in message
    assert "TTY: /dev/pts/0" in message
    assert "CWD: /home/user" in message
    assert "2023-11-14T22:13:20Z" in message
    assert confirmation.request_id in message
    assert "command" not in message.lower()
    assert "cmdline" not in message.lower()


def test_build_confirmation_sanitizes_every_field(sap: types.ModuleType) -> None:
    hostile = "a\nb\x1b[31m*\u202e"
    request = {
        "nonce": "AAAA+BBB",
        "service": hostile,
        "target_user": hostile,
        "invoking_user": hostile,
        "rhost": hostile,
        "tty": hostile,
        "cwd": hostile,
        "guest_hint": hostile,
    }

    confirmation = sap.build_confirmation(
        peer=hostile,
        identity=hostile,
        label=hostile,
        request=request,
        transport=hostile,
        now=1_700_000_000,
    )

    for value in vars(confirmation).values():
        assert "\n" not in value
        assert "\r" not in value
        assert "\x1b" not in value
        assert "\u202e" not in value
        assert "*" not in value
    # the base64 `+` in the request id is not in the allow-list either
    assert confirmation.request_id == "AAAA?BBB"


# --- Phase 3: canonicalisation, domain separation, auth blocks -------------
#
# The security model is an explicit three-knob matrix (`transport_encryption`,
# `server_auth`, `client_auth`). These tests pin the fail-closed rules, the
# canonical transcript (domain label + sorted compact JSON), real SSH/X.509
# sign/verify, and the client-side replay/freshness checks. They use only
# ephemeral keys generated in-process; no real key or network is involved.


def test_canonical_bytes_are_sorted_and_compact(sap: types.ModuleType) -> None:
    assert sap.canonical_bytes({"b": 1, "a": {"z": 2, "y": 3}}) == b'{"a":{"y":3,"z":2},"b":1}'


def test_domain_label_is_the_project_label(sap: types.ModuleType) -> None:
    assert sap.DOMAIN_LABEL == b"tartarus/sudo-auth-proxy/v1"
    assert b"SAP-v1" not in sap.DOMAIN_LABEL


def test_request_digest_ignores_the_signature_field(sap: types.ModuleType) -> None:
    request = {
        "v": 1,
        "type": "auth_request",
        "nonce": _nonce(),
        "client_auth": {"method": "ssh", "alg": "ssh-ed25519", "key_id": "k", "signature": "AAA"},
    }
    tampered = copy.deepcopy(request)
    tampered["client_auth"]["signature"] = "BBB"

    assert sap.compute_request_digest(request) == sap.compute_request_digest(tampered)


# --- config validation (fail closed, no downgrade) ------------------------


def test_security_defaults_for_unix_and_vsock(sap: types.ModuleType) -> None:
    for transport in ("unix", "vsock"):
        assert sap.validate_security_config({"transport": transport}) == {
            "transport_encryption": "none",
            "client_auth": "ssh",
            "server_auth": "signature",
        }


def test_security_defaults_tcp_to_mtls(sap: types.ModuleType) -> None:
    assert sap.validate_security_config({"transport": "tcp"}) == {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }


def test_security_mtls_forces_both_auths_to_transport(sap: types.ModuleType) -> None:
    resolved = sap.validate_security_config(
        {
            "transport": "tcp",
            "security": {
                "transport_encryption": "mtls",
                "client_auth": "transport",
                "server_auth": "transport",
            },
        }
    )
    assert resolved["client_auth"] == "transport"
    assert resolved["server_auth"] == "transport"


def test_security_mtls_rejects_server_signature(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="server_auth must be 'transport'"):
        sap.validate_security_config(
            {
                "transport": "tcp",
                "security": {
                    "transport_encryption": "mtls",
                    "client_auth": "transport",
                    "server_auth": "signature",
                },
            }
        )


def test_security_mtls_rejects_ssh_signature_layered_on_certificate(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="client_auth must be"):
        sap.validate_security_config(
            {
                "transport": "tcp",
                "security": {
                    "transport_encryption": "mtls",
                    "client_auth": "ssh",
                    "server_auth": "transport",
                },
            }
        )


def test_security_rejects_ssh_plus_x509_list(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="exactly one"):
        sap.validate_security_config(
            {"transport": "unix", "security": {"client_auth": ["ssh", "x509"]}}
        )


def test_security_rejects_mixed_client_auth_string(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="mixes methods"):
        sap.validate_security_config(
            {"transport": "unix", "security": {"client_auth": "ssh+x509"}}
        )


def test_security_transport_auth_requires_mtls(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="requires transport_encryption"):
        sap.validate_security_config(
            {"transport": "unix", "security": {"client_auth": "transport"}}
        )


def test_security_mtls_enable_conflicts_with_explicit_none(sap: types.ModuleType) -> None:
    # No runtime downgrade: an mTLS deployment may not be reconfigured to
    # plaintext by a conflicting key.
    with pytest.raises(sap.SecurityConfigError, match="refusing to downgrade"):
        sap.validate_security_config(
            {
                "transport": "tcp",
                "mtls": {"enable": True},
                "security": {"transport_encryption": "none"},
            }
        )


def test_security_tcp_none_is_permitted_but_warns(
    sap: types.ModuleType, capsys: pytest.CaptureFixture
) -> None:
    resolved = sap.validate_security_config(
        {
            "transport": "tcp",
            "security": {
                "transport_encryption": "none",
                "client_auth": "ssh",
                "server_auth": "signature",
            },
        }
    )
    err = capsys.readouterr().err

    assert resolved["transport_encryption"] == "none"
    assert "insecure" in err


def test_security_server_auth_none_warns(
    sap: types.ModuleType, capsys: pytest.CaptureFixture
) -> None:
    sap.validate_security_config(
        {"transport": "unix", "security": {"server_auth": "none"}}
    )

    assert "server_auth = 'none' is not recommended" in capsys.readouterr().err


def test_security_no_runtime_downgrade_leaves_values_fixed(sap: types.ModuleType) -> None:
    config = {
        "transport": "vsock",
        "mtls": {"enable": True},
        "security": {"client_auth": "transport", "server_auth": "transport"},
    }
    resolved = sap.validate_security_config(config)

    assert resolved == {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }
    # validation is pure: it never rewrites the operator's config in place
    assert "transport_encryption" not in config["security"]


# --- SSH requester auth ----------------------------------------------------


def test_ssh_ed25519_round_trip(sap: types.ModuleType, keymaterial: Any) -> None:
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    block = request["client_auth"]
    assert block["method"] == "ssh"
    assert block["alg"] == "ssh-ed25519"
    assert block["key_id"] == sap.ssh_fingerprint(
        sap.load_private_key_file(keymaterial.client_private).public_key()
    )
    assert sap.authenticate_request(request, server) == block["key_id"]


def test_ssh_tampered_request_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    request["cwd"] = "/somewhere/else"  # changed after signing

    with pytest.raises(sap.AuthError, match="signature verification failed"):
        sap.authenticate_request(request, server)


def test_ssh_wrong_key_id_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    request["client_auth"]["key_id"] = "SHA256:not-a-trusted-key"

    with pytest.raises(sap.AuthError, match="does not match the presented public key"):
        sap.authenticate_request(request, server)


def test_ssh_missing_presented_public_key_rejected(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    # A Phase-3 client that relied on the server keyring and did not send its
    # key material must fail closed now that authorization is fingerprint-based.
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    del request["client_auth"]["public_key"]

    with pytest.raises(sap.AuthError, match="missing client_auth.public_key"):
        sap.authenticate_request(request, server)


def test_ssh_absent_alg_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    del request["client_auth"]["alg"]

    with pytest.raises(sap.AuthError, match="absent or invalid client_auth.alg"):
        sap.authenticate_request(request, server)


def test_ssh_unknown_alg_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    request["client_auth"]["alg"] = "ssh-rsa"  # SHA-1: never accepted

    with pytest.raises(sap.AuthError, match="unknown client_auth.alg"):
        sap.authenticate_request(request, server)


def test_ssh_rsa_round_trip(sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "rsa.key"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_line = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    client = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "ssh",
                "server_auth": "none",
                "ssh_signing_key": str(private_path),
            },
        },
        "client",
    )
    server = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "ssh",
                "server_auth": "none",
                "trusted_keys": [public_line],
            },
        },
        "server",
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    assert request["client_auth"]["alg"] == "rsa-sha2-256"
    assert sap.authenticate_request(request, server) == request["client_auth"]["key_id"]


def test_ssh_fingerprint_matches_ssh_keygen(
    sap: types.ModuleType, keymaterial: Any, tmp_path: Path
) -> None:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        pytest.skip("ssh-keygen is not available")
    public_path = tmp_path / "requester.pub"
    public_path.write_text(keymaterial.client_public + "\n")
    result = subprocess.run(
        [ssh_keygen, "-lf", str(public_path)], capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip(f"ssh-keygen cannot read the key: {result.stderr.strip()}")

    theirs = result.stdout.split()[1]
    ours = sap.parse_openssh_public_key(keymaterial.client_public)[1]
    assert theirs == ours


# --- X.509 requester auth --------------------------------------------------


def _make_ca():
    """A self-signed Ed25519 CA with BasicConstraints CA:true."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sap-test-ca")])
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
        .sign(key, None)
    )
    return cert, key


def _issue_leaf(
    ca_cert,
    ca_key,
    *,
    oid: str | None,
    key=None,
    cn: str = "sap-leaf",
    not_before=None,
    not_after=None,
):
    """Issue a leaf certificate from the CA, optionally carrying one EKU OID.

    ``not_before``/``not_after`` override the (valid) default window so the
    ACL tests can issue an expired certificate.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = key or ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = not_before or (now - datetime.timedelta(minutes=1))
    not_after = not_after or (now + datetime.timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if oid is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid)]), critical=False
        )
    return builder.sign(ca_key, None), key


def _write_pem(path: Path, cert) -> None:
    from cryptography.hazmat.primitives import serialization

    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key) -> None:
    from cryptography.hazmat.primitives import serialization

    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture()
def x509_material(crypto: types.ModuleType, tmp_path: Path):
    """A CA + EKU leaf written to disk plus the matching security blocks."""
    ca_cert, ca_key = _make_ca()
    leaf_cert, leaf_key = _issue_leaf(ca_cert, ca_key, oid=REQUIRED_OID)
    _write_pem(tmp_path / "ca.crt", ca_cert)
    _write_pem(tmp_path / "client.crt", leaf_cert)
    _write_key(tmp_path / "client.key", leaf_key)
    return types.SimpleNamespace(
        tmp_path=tmp_path,
        ca_cert=ca_cert,
        ca_key=ca_key,
        leaf_cert=leaf_cert,
        leaf_key=leaf_key,
    )


def _x509_security(material: Any, oid: str = REQUIRED_OID) -> tuple[dict, dict]:
    server = {
        "transport_encryption": "none",
        "client_auth": "x509",
        "server_auth": "none",
        "ca_file": str(material.tmp_path / "ca.crt"),
        "client_required_oid": oid,
    }
    client = {
        "transport_encryption": "none",
        "client_auth": "x509",
        "server_auth": "none",
        "client_cert": str(material.tmp_path / "client.crt"),
        "client_key": str(material.tmp_path / "client.key"),
    }
    return server, client


def test_x509_round_trip(sap: types.ModuleType, x509_material: Any) -> None:
    server_sec, client_sec = _x509_security(x509_material)
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    server = sap.build_security({"transport": "unix", "security": server_sec}, "server")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    assert request["client_auth"]["method"] == "x509"
    assert request["client_auth"]["alg"] == "ed25519"
    assert sap.authenticate_request(request, server) == request["client_auth"]["key_id"]


def test_x509_tampered_request_rejected(sap: types.ModuleType, x509_material: Any) -> None:
    server_sec, client_sec = _x509_security(x509_material)
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    server = sap.build_security({"transport": "unix", "security": server_sec}, "server")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    request["service"] = "su"

    with pytest.raises(sap.AuthError, match="signature verification failed"):
        sap.authenticate_request(request, server)


def test_x509_wrong_ca_rejected(sap: types.ModuleType, x509_material: Any) -> None:
    other_ca, other_key = _make_ca()
    other_path = x509_material.tmp_path / "other-ca.crt"
    _write_pem(other_path, other_ca)
    server_sec, client_sec = _x509_security(x509_material)
    server_sec = dict(server_sec)
    server_sec["ca_file"] = str(other_path)
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    server = sap.build_security({"transport": "unix", "security": server_sec}, "server")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    with pytest.raises(sap.AuthError, match="no trusted issuer"):
        sap.authenticate_request(request, server)


def test_x509_missing_eku_rejected(sap: types.ModuleType, tmp_path: Path) -> None:
    ca_cert, ca_key = _make_ca()
    leaf_cert, leaf_key = _issue_leaf(ca_cert, ca_key, oid=None)
    _write_pem(tmp_path / "ca.crt", ca_cert)
    _write_pem(tmp_path / "client.crt", leaf_cert)
    _write_key(tmp_path / "client.key", leaf_key)
    server = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "ca_file": str(tmp_path / "ca.crt"),
                "client_required_oid": REQUIRED_OID,
            },
        },
        "server",
    )
    client = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "client_cert": str(tmp_path / "client.crt"),
                "client_key": str(tmp_path / "client.key"),
            },
        },
        "client",
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    with pytest.raises(sap.AuthError, match="missing required EKU OID"):
        sap.authenticate_request(request, server)


# --- response signing, freshness and replay --------------------------------


def _response_pair(sap: types.ModuleType, keymaterial: Any):
    client = sap.build_security(_client_config(keymaterial), "client")
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial)}, "server"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)
    response = sap.build_response(
        request["nonce"], "allow", request=request, security=server, approver="host-user"
    )
    return client, request, response


def test_response_sign_verify_round_trip(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)

    assert response["server_auth"]["method"] == "signature"
    assert sap.verify_response(response, request, client, set()) == "allow"


def test_response_tampered_decision_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["decision"] = "deny"

    with pytest.raises(sap.AuthError, match="signature verification failed"):
        sap.verify_response(response, request, client, set())


def test_response_tampered_digest_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["request_digest"] = "0" * 64

    with pytest.raises(sap.ProtocolError, match="request_digest"):
        sap.verify_response(response, request, client, set())


def test_response_wrong_nonce_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["nonce"] = base64.b64encode(b"other" * 8).decode()

    with pytest.raises(sap.ProtocolError, match="nonce does not match"):
        sap.verify_response(response, request, client, set())


def test_response_expired_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["issued_at"] = 1
    response["expires_at"] = 2

    with pytest.raises(sap.ProtocolError, match="expired"):
        sap.verify_response(response, request, client, set())


def test_response_replay_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    consumed: set = set()

    assert sap.verify_response(response, request, client, consumed) == "allow"
    # A second response for the same nonce is refused (single-use nonce).
    with pytest.raises(sap.AuthError, match="already been consumed"):
        sap.verify_response(response, request, client, consumed)


def test_response_unknown_alg_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["server_auth"]["alg"] = "ssh-rsa"

    with pytest.raises(sap.AuthError, match="unknown or absent server_auth.alg"):
        sap.verify_response(response, request, client, set())


def test_response_absent_alg_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    del response["server_auth"]["alg"]

    with pytest.raises(sap.AuthError, match="unknown or absent server_auth.alg"):
        sap.verify_response(response, request, client, set())


def test_response_wrong_key_id_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    response["server_auth"]["key_id"] = "SHA256:not-the-host-key"

    with pytest.raises(sap.AuthError, match="not in the trusted keyring"):
        sap.verify_response(response, request, client, set())


def test_response_missing_signature_rejected(sap: types.ModuleType, keymaterial: Any) -> None:
    client, request, response = _response_pair(sap, keymaterial)
    del response["server_auth"]["signature"]

    with pytest.raises(sap.AuthError, match="missing server_auth.signature"):
        sap.verify_response(response, request, client, set())


# --- X.509 chain building (intermediate CAs) -------------------------------


def _issue_ca(parent_cert, parent_key, *, path_length=None, cn: str = "sap-intermediate"):
    """Issue a CA certificate (BasicConstraints CA:true) from `parent_cert`."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(parent_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .sign(parent_key, None)
    )
    return cert, key


def test_x509_intermediate_chain_accepted(sap: types.ModuleType, tmp_path: Path) -> None:
    root, root_key = _make_ca()
    intermediate, intermediate_key = _issue_ca(root, root_key)
    leaf, leaf_key = _issue_leaf(intermediate, intermediate_key, oid=REQUIRED_OID)
    # The client sends leaf + intermediate; the root is the trust anchor.
    chain_pem = b"".join(
        cert.public_bytes(_crypto_pem()) for cert in (leaf, intermediate)
    )
    (tmp_path / "ca.crt").write_bytes(root.public_bytes(_crypto_pem()))
    (tmp_path / "client.crt").write_bytes(chain_pem)
    _write_key(tmp_path / "client.key", leaf_key)

    server = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "ca_file": str(tmp_path / "ca.crt"),
                "client_required_oid": REQUIRED_OID,
            },
        },
        "server",
    )
    client = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "client_cert": str(tmp_path / "client.crt"),
                "client_key": str(tmp_path / "client.key"),
            },
        },
        "client",
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    assert sap.authenticate_request(request, server) == request["client_auth"]["key_id"]


def _crypto_pem():
    from cryptography.hazmat.primitives import serialization

    return serialization.Encoding.PEM


# --- fail-closed configuration / key material ------------------------------


def test_build_security_missing_signing_key_fails_closed(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    config = {
        "transport": "unix",
        "security": {
            "transport_encryption": "none",
            "client_auth": "ssh",
            "server_auth": "none",
            "ssh_signing_key": str(tmp_path / "absent.key"),
        },
    }

    with pytest.raises(sap.SecurityConfigError, match="cannot read private key"):
        sap.build_security(config, "client")


def test_build_security_rejects_bare_fingerprint_keyring(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    # A fingerprint cannot verify a host signature, so the `[security]`
    # host-key keyring still rejects bare fingerprints; fingerprints belong in
    # the `[acl]`, which is an authorization list, not a verification keyring.
    config = {
        "transport": "unix",
        "security": {
            "transport_encryption": "none",
            "client_auth": "ssh",
            "server_auth": "signature",
            "ssh_signing_key": keymaterial.client_private,
            "trusted_server_keys": ["SHA256:AbCdEf123"],
        },
    }

    with pytest.raises(sap.SecurityConfigError, match="not bare"):
        sap.build_security(config, "client")


def test_run_client_missing_signing_key_exits_nonzero(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "recursion_guard_active", lambda: False)
    config = {
        "transport": "tcp",
        "security": {
            "transport_encryption": "none",
            "client_auth": "ssh",
            "server_auth": "none",
            "ssh_signing_key": "/nonexistent/sap/key",
        },
    }

    with pytest.raises(SystemExit) as exc:
        sap.run_client(config)

    assert exc.value.code == 1


# --- Phase 4: authorization / trust roots (ACL) ----------------------------
#
# The `[acl]` decides who may use the mechanism. It is evaluated AFTER the
# cryptographic verification of `client_auth` and BEFORE any dialog, and it
# matches ONLY the verified credential (SSH fingerprint, X.509/mTLS SPKI, or a
# CA chain + EKU). Metadata (`target_user`, `rhost`, `tty`, `guest_hint`, ...)
# never influences the decision (doc §8; review logs S11/NF6).

# a syntactically valid fingerprint of a 32-byte SHA-256 digest that no test
# key produces, so it can never match a real credential.
_UNLISTED_FINGERPRINT = "SHA256:" + base64.b64encode(b"\x00" * 32).decode().rstrip("=")


def _server_with_acl(
    sap: types.ModuleType, keys: Any, acl: dict, security: Any = None
) -> Any:
    """Build a server `SecurityConfig` with the given `[acl]` (default ssh)."""
    config = {
        "transport": "unix",
        "security": _server_security(keys) if security is None else security,
        "acl": acl,
    }
    return sap.build_security(config, "server")


def _transport_server(sap: types.ModuleType, acl: dict) -> Any:
    """A server whose requester credential is the mTLS transport certificate."""
    security = {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }
    return sap.build_security(
        {"transport": "unix", "security": security, "acl": acl}, "server"
    )


def _ca_path(material: Any) -> str:
    return str(material.tmp_path / "ca.crt")


# -- ACL config validation ---------------------------------------------------


def test_acl_absent_is_deny_all_list(sap: types.ModuleType) -> None:
    acl = sap.load_acl_config({})

    assert acl.mode == "list"
    assert acl.trusted_keys == frozenset()
    assert acl.trusted_fingerprints == frozenset()
    assert sap.acl_allows_any(acl) is False


@pytest.mark.parametrize("mode", ["open", "", None, ["list"], 1])
def test_acl_unknown_mode_rejected(sap: types.ModuleType, mode: Any) -> None:
    with pytest.raises(sap.SecurityConfigError, match="acl.mode"):
        sap.load_acl_config({"acl": {"mode": mode}})


def test_acl_ca_requires_ca_file(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="requires acl.ca_file"):
        sap.load_acl_config({"acl": {"mode": "ca", "required_oid": REQUIRED_OID}})


def test_acl_ca_requires_required_oid(sap: types.ModuleType, tmp_path: Path) -> None:
    ca_cert, _ = _make_ca()
    ca_path = tmp_path / "ca.crt"
    _write_pem(ca_path, ca_cert)

    with pytest.raises(sap.SecurityConfigError, match="requires acl.required_oid"):
        sap.load_acl_config({"acl": {"mode": "ca", "ca_file": str(ca_path)}})


def test_acl_ca_rejects_trusted_keys(sap: types.ModuleType, tmp_path: Path) -> None:
    ca_cert, _ = _make_ca()
    ca_path = tmp_path / "ca.crt"
    _write_pem(ca_path, ca_cert)

    # no `ca` + `list` combination: a CA mode must not also carry SSH pins
    with pytest.raises(sap.SecurityConfigError, match="no ca.list combination"):
        sap.load_acl_config(
            {
                "acl": {
                    "mode": "ca",
                    "ca_file": str(ca_path),
                    "required_oid": REQUIRED_OID,
                    "trusted_keys": [_UNLISTED_FINGERPRINT],
                }
            }
        )


def test_acl_list_rejects_ca_file(sap: types.ModuleType, tmp_path: Path) -> None:
    with pytest.raises(sap.SecurityConfigError, match="must not set ca_file"):
        sap.load_acl_config(
            {"acl": {"mode": "list", "ca_file": str(tmp_path / "ca.crt")}}
        )


@pytest.mark.parametrize(
    "entry",
    ["MD5:abcd", "SHA256:", "SHA256:notbase64!!", "SHA256:AAAA", 123],
)
def test_acl_rejects_malformed_fingerprint(sap: types.ModuleType, entry: Any) -> None:
    with pytest.raises(sap.SecurityConfigError, match="trusted_keys"):
        sap.load_acl_config({"acl": {"mode": "list", "trusted_keys": [entry]}})


def test_acl_normalizes_padded_fingerprint(sap: types.ModuleType) -> None:
    body = base64.b64encode(b"\x01" * 32).decode().rstrip("=")

    acl = sap.load_acl_config(
        {"acl": {"mode": "list", "trusted_keys": [f"SHA256:{body}="]}}
    )

    assert acl.trusted_keys == frozenset({f"SHA256:{body}"})


def test_acl_labels_must_be_string_map(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="labels"):
        sap.load_acl_config(
            {"acl": {"mode": "list", "labels": {_UNLISTED_FINGERPRINT: 3}}}
        )


def test_acl_ca_with_ssh_client_auth_rejected(
    sap: types.ModuleType, keymaterial: Any, tmp_path: Path
) -> None:
    ca_cert, _ = _make_ca()
    ca_path = tmp_path / "ca.crt"
    _write_pem(ca_path, ca_cert)

    with pytest.raises(sap.SecurityConfigError, match="cannot authorize client_auth = 'ssh'"):
        _server_with_acl(
            sap,
            keymaterial,
            {"mode": "ca", "ca_file": str(ca_path), "required_oid": REQUIRED_OID},
        )


# -- mode = "list" -----------------------------------------------------------


def test_acl_list_allows_listed_ssh_fingerprint(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    fingerprint = _fingerprint(sap, keymaterial.client_public)
    server = _server_with_acl(sap, keymaterial, _acl_list(fingerprint))
    request = _signed_request(sap, keymaterial)

    verified = sap.authenticate_request(request, server)

    assert verified == fingerprint
    assert sap.authorize_request(request, server, verified) == fingerprint


def test_acl_list_denies_unlisted_but_valid_signature(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    # The signature is genuine, but the key is not listed: authentication
    # succeeds and authorization still refuses (a verified key is not trusted).
    server = _server_with_acl(sap, keymaterial, _acl_list(_UNLISTED_FINGERPRINT))
    request = _signed_request(sap, keymaterial)

    verified = sap.authenticate_request(request, server)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, server, verified)


def test_acl_list_empty_denies_everyone(sap: types.ModuleType, keymaterial: Any) -> None:
    server = _server_with_acl(sap, keymaterial, _acl_list())
    request = _signed_request(sap, keymaterial)

    verified = sap.authenticate_request(request, server)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, server, verified)


def test_acl_label_is_display_only(sap: types.ModuleType, keymaterial: Any) -> None:
    fingerprint = _fingerprint(sap, keymaterial.client_public)
    acl = {
        "mode": "list",
        "trusted_keys": [fingerprint],
        "labels": {fingerprint: "vault"},
    }
    server = _server_with_acl(sap, keymaterial, acl)
    request = _signed_request(sap, keymaterial)

    verified = sap.authenticate_request(request, server)

    assert sap.authorize_request(request, server, verified) == "vault"


def test_acl_decision_ignores_request_metadata(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    fingerprint = _fingerprint(sap, keymaterial.client_public)
    allow_server = _server_with_acl(sap, keymaterial, _acl_list(fingerprint))
    deny_server = _server_with_acl(sap, keymaterial, _acl_list())
    metadata = {
        "target_user": "daemon",
        "invoking_user": "mallory",
        "rhost": "10.9.9.9",
        "tty": "/dev/pts/7",
        "guest_hint": "evil",
    }
    request = _signed_request(sap, keymaterial, **metadata)

    verified = sap.authenticate_request(request, allow_server)
    assert sap.authorize_request(request, allow_server, verified) == fingerprint

    # the same metadata must not rescue an unlisted credential either
    denied = sap.authenticate_request(request, deny_server)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, deny_server, denied)


# -- ACL is enforced before the dialog ---------------------------------------


def test_handler_acl_denial_is_signed_and_never_prompts(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, keymaterial: Any
) -> None:
    request = _signed_request(sap, keymaterial)
    frames, prompts = _exchange(
        sap, monkeypatch, [], _frame(sap, request), keymaterial, acl=_acl_list()
    )

    assert prompts == []
    # A denial is answered without a dialog, so there is no `auth_pending`; the
    # sole frame is the signed deny (audit A2).
    assert len(frames) == 1
    parsed = _decode(sap, frames[0])
    assert parsed["type"] == "auth_response"
    assert parsed["decision"] == "deny"
    assert parsed["nonce"] == request["nonce"]
    assert parsed["server_auth"]["method"] == "signature"
    # the deny is a genuine, request-bound signed response
    client = sap.build_security(_client_config(keymaterial), "client")
    assert sap.verify_response(parsed, request, client, set()) == "deny"


def test_handler_untrusted_but_valid_signature_no_prompt(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, keymaterial: Any
) -> None:
    request = _signed_request(sap, keymaterial)
    frames, prompts = _exchange(
        sap,
        monkeypatch,
        [],
        _frame(sap, request),
        keymaterial,
        acl=_acl_list(_UNLISTED_FINGERPRINT),
    )

    assert prompts == []
    assert len(frames) == 1
    assert _decode(sap, frames[0])["decision"] == "deny"


def test_handler_authentication_failure_never_prompts(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, keymaterial: Any
) -> None:
    request = _signed_request(sap, keymaterial)
    request["cwd"] = "/tampered"  # signature no longer covers the body
    frames, prompts = _exchange(
        sap, monkeypatch, [], _frame(sap, request), keymaterial
    )

    # authentication runs before the ACL; a bad signature is never answered
    assert frames == []
    assert prompts == []


# -- mode = "ca" -------------------------------------------------------------


def test_acl_ca_allows_chained_cert(
    sap: types.ModuleType, x509_material: Any
) -> None:
    server_sec, client_sec = _x509_security(x509_material)
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": _ca_path(x509_material), "required_oid": REQUIRED_OID},
        security=server_sec,
    )
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    verified = sap.authenticate_request(request, server)

    assert sap.authorize_request(request, server, verified) == verified


def test_acl_ca_denies_wrong_ca(sap: types.ModuleType, x509_material: Any) -> None:
    other_ca, _ = _make_ca()
    other_path = x509_material.tmp_path / "other-ca.crt"
    _write_pem(other_path, other_ca)
    server_sec, client_sec = _x509_security(x509_material)
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": str(other_path), "required_oid": REQUIRED_OID},
        security=server_sec,
    )
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    verified = sap.authenticate_request(request, server)
    with pytest.raises(sap.AuthError, match="no trusted issuer"):
        sap.authorize_request(request, server, verified)


def test_acl_ca_denies_missing_eku_at_acl_layer(
    sap: types.ModuleType, x509_material: Any
) -> None:
    # The security layer requires REQUIRED_OID (the leaf has it), so
    # authentication passes; the ACL requires a *different* OID and refuses.
    server_sec, client_sec = _x509_security(x509_material)
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": _ca_path(x509_material), "required_oid": OTHER_OID},
        security=server_sec,
    )
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    verified = sap.authenticate_request(request, server)
    with pytest.raises(sap.AuthError, match="missing required EKU OID"):
        sap.authorize_request(request, server, verified)


def test_acl_ca_optional_spki_pin(sap: types.ModuleType, x509_material: Any) -> None:
    server_sec, client_sec = _x509_security(x509_material)
    spki = sap.spki_fingerprint(x509_material.leaf_cert.public_key())
    client = sap.build_security({"transport": "unix", "security": client_sec}, "client")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    # a matching pin does not change the CA-mode allow
    server_ok = _server_with_acl(
        sap,
        x509_material,
        {
            "mode": "ca",
            "ca_file": _ca_path(x509_material),
            "required_oid": REQUIRED_OID,
            "trusted_fingerprints": [spki],
        },
        security=server_sec,
    )
    verified = sap.authenticate_request(request, server_ok)
    assert sap.authorize_request(request, server_ok, verified) == verified

    # a mismatched pin narrows the CA trust to a deny
    server_bad = _server_with_acl(
        sap,
        x509_material,
        {
            "mode": "ca",
            "ca_file": _ca_path(x509_material),
            "required_oid": REQUIRED_OID,
            "trusted_fingerprints": [_UNLISTED_FINGERPRINT],
        },
        security=server_sec,
    )
    mismatched = sap.authenticate_request(request, server_bad)
    with pytest.raises(sap.AuthError, match="SPKI is not in the authorization list"):
        sap.authorize_request(request, server_bad, mismatched)


def test_acl_ca_denies_expired_cert(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    import datetime

    ca_cert, ca_key = _make_ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf, leaf_key = _issue_leaf(
        ca_cert,
        ca_key,
        oid=REQUIRED_OID,
        not_before=now - datetime.timedelta(days=2),
        not_after=now - datetime.timedelta(days=1),
    )
    _write_pem(tmp_path / "ca.crt", ca_cert)
    _write_pem(tmp_path / "client.crt", leaf)
    _write_key(tmp_path / "client.key", leaf_key)
    server = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "ca_file": str(tmp_path / "ca.crt"),
                "client_required_oid": REQUIRED_OID,
            },
            "acl": {
                "mode": "ca",
                "ca_file": str(tmp_path / "ca.crt"),
                "required_oid": REQUIRED_OID,
            },
        },
        "server",
    )
    client = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "x509",
                "server_auth": "none",
                "client_cert": str(tmp_path / "client.crt"),
                "client_key": str(tmp_path / "client.key"),
            },
        },
        "client",
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    with pytest.raises(sap.AuthError, match="outside its validity window"):
        sap.authenticate_request(request, server)


# -- mTLS transport credential pinning (NF6) ---------------------------------


def test_acl_list_pins_mtls_spki(sap: types.ModuleType, crypto: types.ModuleType) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = _build_cert(REQUIRED_OID)
    der = cert.public_bytes(Encoding.DER)
    spki = sap.spki_fingerprint(cert.public_key())
    request = _request_obj(sap)
    request["client_auth"] = {"method": "transport"}
    server = _transport_server(sap, {"mode": "list", "trusted_fingerprints": [spki]})

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    assert verified == spki
    assert sap.authorize_request(request, server, verified, peer_cert_der=der) == spki

    other_der = _build_cert(REQUIRED_OID).public_bytes(Encoding.DER)
    mismatched = sap.authenticate_request(request, server, peer_cert_der=other_der)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, server, mismatched, peer_cert_der=other_der)


def test_acl_ca_authorizes_mtls_cert(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    ca_cert, ca_key = _make_ca()
    leaf, _ = _issue_leaf(ca_cert, ca_key, oid=REQUIRED_OID)
    _write_pem(tmp_path / "ca.crt", ca_cert)
    der = leaf.public_bytes(Encoding.DER)
    request = _request_obj(sap)
    request["client_auth"] = {"method": "transport"}
    server = _transport_server(
        sap,
        {"mode": "ca", "ca_file": str(tmp_path / "ca.crt"), "required_oid": REQUIRED_OID},
    )

    verified = sap.authenticate_request(request, server, peer_cert_der=der)

    assert sap.authorize_request(request, server, verified, peer_cert_der=der) == verified


# --- Phase 5: ca.py key-file permissions (doc §9.2; review log F12) --------


def test_ca_client_key_is_0600_not_0644(tmp_path: Path) -> None:
    """A generated X.509 client private key must never be world-readable.

    ``ca.py`` historically chmod'ed the key ``0644``; this runs the real
    generation (CA + client key/cert, using ``openssl``) against a temp
    directory and pins the key at ``0600`` while the public certificate stays
    ``0644``. The permissive umask only guards against an OpenSSL that creates
    key files more openly than the current one; the explicit chmod is what the
    assertion really tests.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    if str(SRC_PATH) not in sys.path:
        sys.path.insert(0, str(SRC_PATH))
    from tartarus import ca
    from tartarus.config import Config

    config = Config(
        user="user",
        home_dir=tmp_path,
        flake_path=tmp_path / "nixcfg",
        system="x86_64-linux",
        state_root=tmp_path / "state",
        ssh_dir=tmp_path / ".ssh",
        ssh_ca_dir=tmp_path / "ssh-ca",
        x509_ca_dir=tmp_path / "x509-ca",
    )

    old_umask = os.umask(0o022)
    try:
        ca._ensure_x509_ca(config)
        ca._ensure_x509_client_cert(config, "microvm", "sap-guest")
    finally:
        os.umask(old_umask)

    guest_dir = ca.x509_machine_dir(config, "microvm", "sap-guest")

    assert stat.S_IMODE(os.lstat(guest_dir / "client.key").st_mode) == 0o600
    assert stat.S_IMODE(os.lstat(guest_dir / "client.crt").st_mode) == 0o644


# --- Phase 6: PAM fast-fail and timeout semantics --------------------------
#
# The PAM hook runs on every sudo, so a stale or silent peer must not stall the
# stack. `recv_timeout` bounds the first response bytes (review log NF4); the
# connect/handshake bound covers an unreachable or half-open TCP peer; and a
# numeric host never triggers DNS (doc §10.2). `decision_timeout = 0` means
# wait indefinitely. `pam_exec` collapses exit codes, so the `denied` vs
# `unavailable` distinction is logging-only (doc §6.7, review log F5).


def test_decision_timeout_zero_means_wait(sap: types.ModuleType) -> None:
    assert sap.resolve_read_timeouts(
        {"recv_timeout": 0.5, "decision_timeout": 0}
    ) == (0.5, None)

    recv_first_byte, tail = sap.resolve_read_timeouts(
        {"recv_timeout": 0.25, "decision_timeout": 30}
    )

    assert recv_first_byte == 0.25
    assert isinstance(tail, float)
    assert tail == 30.0


def test_read_timeouts_fall_back_on_bad_values(sap: types.ModuleType) -> None:
    # A malformed hand-written config must not crash the hook: both values fall
    # back to their defaults rather than raising.
    recv_first_byte, tail = sap.resolve_read_timeouts(
        {"recv_timeout": "nope", "decision_timeout": "bad"}
    )

    assert recv_first_byte == sap.DEFAULT_RECV_TIMEOUT
    assert tail == float(sap.DEFAULT_DECISION_TIMEOUT)


def test_receive_timeout_bounds_a_silent_unix_peer(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    keymaterial: Any,
) -> None:
    """A listening-but-never-accepting peer must not hang the read.

    On Linux a *bound-but-not-listening* socket refuses the connect immediately
    (see the next test), so this test deliberately uses a **listening** socket
    that never calls ``accept()``: ``connect()`` succeeds, the request write is
    buffered by the kernel, and without the Phase 6 first-byte bound the client
    would block on ``read()`` until ``decision_timeout`` (120s). The bound must
    be the short ``recv_timeout`` instead (review log NF4).
    """
    sock_path = tmp_path / "silent.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(sock_path))
        listener.listen(1)
        monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        config = _client_config(keymaterial)
        config.update(connect_timeout=0.2, recv_timeout=0.3, decision_timeout=120)

        start = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            sap.run_client(config)
        elapsed = time.monotonic() - start
    finally:
        listener.close()

    assert exc.value.code == 1
    # bounded well under the decision timeout; a 120s wait would blow past both
    assert elapsed < 1.5
    assert elapsed < 120 * 0.5
    # and roughly the first-byte bound, proving the bound was actually applied
    assert elapsed >= 0.3 * 0.5


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="AF_UNIX connect to a bound-but-not-listening socket fails differently on macOS",
)
def test_unbound_unix_socket_fails_fast(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    keymaterial: Any,
) -> None:
    """A bound but never-``listen()``ed socket fails fast (Linux: ECONNREFUSED).

    Do not assert a lower bound: on Linux the refusal is immediate, and the
    point is only that the client returns non-zero without waiting.
    """
    sock_path = tmp_path / "unbound.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(sock_path))
        monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        config = _client_config(keymaterial)
        config.update(connect_timeout=0.2, recv_timeout=0.3, decision_timeout=120)

        start = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            sap.run_client(config)
        elapsed = time.monotonic() - start
    finally:
        listener.close()

    assert exc.value.code == 1
    assert elapsed < 1.5


def test_closed_tcp_port_fails_within_connect_timeout(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    keymaterial: Any,
) -> None:
    """A refused TCP connect returns within the bound instead of hanging.

    The port is chosen by binding to port 0 and closing, so another process
    could in principle race us onto it; the assertions stay tolerant (non-zero
    exit, fast) rather than assuming a specific errno.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()

    config = {
        "transport": "tcp",
        "host": "127.0.0.1",
        "port": port,
        "resolution": "none",
        "dialog_program": "zenity",
        "connect_timeout": 0.2,
        "recv_timeout": 0.3,
        "decision_timeout": 120,
        "security": _client_security(keymaterial),
    }

    start = time.monotonic()
    with pytest.raises(SystemExit) as exc:
        sap.run_client(config)
    elapsed = time.monotonic() - start

    assert exc.value.code == 1
    assert elapsed < 1.5


def test_numeric_host_does_not_invoke_dns(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A numeric address is connected to literally and never resolved (doc §10.2)."""

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("DNS must not be resolved for a numeric host")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)

    assert sap.is_numeric_host("127.0.0.1") is True
    assert sap.is_numeric_host("::1") is True
    assert sap.is_numeric_host("example.test") is False

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        transport = sap.CallbackTransport(
            {
                "transport": "tcp",
                "host": "127.0.0.1",
                "port": port,
                "security": {
                    "transport_encryption": "none",
                    "client_auth": "ssh",
                    "server_auth": "none",
                },
            },
            "tcp",
        )
        sock = transport.connect()
        try:
            assert sock is not None
        finally:
            sock.close()
    finally:
        listener.close()


def test_denied_is_logged_distinctly_from_unavailable(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    keymaterial: Any,
    capsys: pytest.CaptureFixture,
) -> None:
    """`deny` logs ``denied``; a failure logs ``unavailable`` (doc §6.7)."""
    # unavailable: a listening-but-silent peer trips the receive bound
    silent_path = tmp_path / "silent-log.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(silent_path))
        listener.listen(1)
        monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(silent_path))
        config = _client_config(keymaterial)
        config.update(connect_timeout=0.2, recv_timeout=0.2, decision_timeout=120)
        with pytest.raises(SystemExit):
            sap.run_client(config)
        unavailable_err = capsys.readouterr().err
    finally:
        listener.close()

    assert "unavailable" in unavailable_err
    assert "denied" not in unavailable_err

    # denied: a real server answering a genuine, signed deny. The first
    # `run_client` set the process-global recursion guard directly in
    # `os.environ` (in production each invocation is a fresh process), so clear
    # it before the second call.
    monkeypatch.delenv("SUDO_AUTH_PROXY_ACTIVE", raising=False)
    deny_path = tmp_path / "deny-log.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: False)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
    with _unix_server(sap, deny_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(deny_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config(keymaterial))
    denied_err = capsys.readouterr().err

    assert exc.value.code == 1
    assert "denied" in denied_err
    assert "unavailable" not in denied_err


# ==========================================================================
# Phase 9 audit-fix regression tests (A2, A3, A6, A9, A10, A11, A13, A1)
# ==========================================================================


def _running_unix_server(sap: types.ModuleType, sock_path: Path, config: dict):
    """Start a real single-socket unix server with an explicit config dict.

    Returns ``(transport, server, thread)``; the caller must shut the server
    down (see :func:`_stop_server`). Used by the resource-bound tests, which need
    to set ``server_read_timeout``/``max_connections`` directly.
    """
    transport = sap.UnixTransport(config)
    server = transport.listen(sap.Handler)
    server._security = sap.build_security(config, "server")
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    return transport, server, thread


def _stop_server(transport: Any, server: Any, thread: threading.Thread) -> None:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    transport.cleanup()


# -- A2: default recv_timeout + pending ack ---------------------------------


def test_default_recv_timeout_survives_slow_human_via_pending_frame(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    keymaterial: Any,
) -> None:
    """The shipped 0.5 s first-frame bound must not abort a slower human.

    Before the ``auth_pending`` sentinel the first byte *was* the human's
    answer, so the shipped ``recv_timeout = 0.5`` aborted every approval slower
    than half a second (audit A2). With the sentinel the ack arrives promptly
    and the final decision is read under ``decision_timeout``; this drives a
    server whose dialog takes 1.0 s with ``recv_timeout = 0.5`` and asserts the
    client still succeeds.
    """
    sock_path = tmp_path / "run" / "server.sock"

    def slow_prompt(_confirmation: Any, _program: str) -> bool:
        time.sleep(1.0)
        return True

    monkeypatch.setattr(sap, "prompt_for_confirmation", slow_prompt)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path, keymaterial):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        config = _client_config(keymaterial)
        config.update(recv_timeout=0.5, decision_timeout=120)
        start = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            sap.run_client(config)
        elapsed = time.monotonic() - start

    assert exc.value.code == 0
    assert elapsed >= 1.0  # the client really waited for the slow human


def test_pending_frame_must_match_the_request_nonce(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    """An ack for another nonce (or a bad/missing type) is rejected (A2)."""
    request = _signed_request(sap, keymaterial)
    other = base64.b64encode(b"o" * 32).decode()

    # a valid ack passes
    sap.parse_pending(sap.build_pending(request["nonce"]), request["nonce"])

    with pytest.raises(sap.ProtocolError, match="auth_pending"):
        sap.parse_pending(sap.build_pending(other), request["nonce"])
    with pytest.raises(sap.ProtocolError):
        sap.parse_pending({"v": 1, "type": "auth_response", "nonce": request["nonce"]}, request["nonce"])
    with pytest.raises(sap.ProtocolError):
        sap.parse_pending({"v": 1, "type": "auth_pending"}, request["nonce"])


# -- A3: pre-auth connection bounds -----------------------------------------


def test_idle_preauth_connection_is_dropped(
    sap: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    """A peer that connects and sends nothing is dropped within the bound (A3).

    The accepted socket carries ``server_read_timeout``; without it each idle
    pre-auth connection would hold a handler thread forever. The client here
    connects and sends no byte, then ``recv`` returns EOF when the server times
    the read out and closes.
    """
    sock_path = tmp_path / "run" / "server.sock"
    config = {
        "transport": "unix",
        "socket": str(sock_path),
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "resolution": "none",
        "dialog_program": "zenity",
        "server_read_timeout": 0.3,
        "max_connections": 4,
        "security": _server_security(keymaterial),
        "acl": _acl_for(sap, keymaterial),
    }
    transport, server, thread = _running_unix_server(sap, sock_path, config)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(sock_path))
        client.settimeout(3.0)
        start = time.monotonic()
        data = client.recv(1)
        elapsed = time.monotonic() - start
    finally:
        client.close()
        _stop_server(transport, server, thread)

    assert data == b""  # EOF: the server closed the timed-out connection
    assert elapsed < 2.0
    assert elapsed >= 0.15  # it waited for the read timeout, not an instant drop


def test_connection_limit_refuses_over_cap_peer(
    sap: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    """Over-cap connections are refused before a handler thread is spawned (A3)."""
    sock_path = tmp_path / "run" / "server.sock"
    config = {
        "transport": "unix",
        "socket": str(sock_path),
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "resolution": "none",
        "dialog_program": "zenity",
        "server_read_timeout": 5.0,
        "max_connections": 1,
        "security": _server_security(keymaterial),
        "acl": _acl_for(sap, keymaterial),
    }
    transport, server, thread = _running_unix_server(sap, sock_path, config)
    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # occupy the single slot with an idle (but live) connection
        first.connect(str(sock_path))
        first.settimeout(3.0)
        # give the accept loop a moment to spawn the first handler and take the
        # semaphore, then the over-cap peer is refused
        time.sleep(0.2)
        second.connect(str(sock_path))
        second.settimeout(3.0)
        assert second.recv(1) == b""
    finally:
        first.close()
        second.close()
        _stop_server(transport, server, thread)


# -- N2: the TLS handshake must not serialise the accept loop ----------------


def test_stalled_tls_handshake_does_not_block_the_accept_loop(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    crypto: types.ModuleType,
) -> None:
    """A stalled handshake must consume a worker, not the accept loop (N2).

    Before the fix `get_request` wrapped the socket on the single
    `serve_forever` accept thread, so one silent TLS client blocked every other
    accept for up to ``server_read_timeout``. The handshake now runs in the
    per-connection handler thread, so two silent clients must be *inside*
    ``SSLContext.wrap_socket`` at the same time; the recorder's concurrency peak
    is the observable difference (it stays at 1 if the accept loop is
    serialised).
    """
    import ssl as ssl_module

    ca_cert, ca_key = _make_ca()
    server_cert, server_key = _issue_leaf(ca_cert, ca_key, oid=None, cn="sap-server")
    _write_pem(tmp_path / "ca.crt", ca_cert)
    _write_pem(tmp_path / "server.crt", server_cert)
    _write_key(tmp_path / "server.key", server_key)

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()

    config = {
        "transport": "tcp",
        "host": "127.0.0.1",
        "port": port,
        "resolution": "none",
        "dialog_program": "zenity",
        "server_read_timeout": 3.0,
        "max_connections": 8,
        "security": {
            "transport_encryption": "mtls",
            "client_auth": "transport",
            "server_auth": "transport",
        },
        "mtls": {
            "enable": True,
            "ca_file": str(tmp_path / "ca.crt"),
            "cert_file": str(tmp_path / "server.crt"),
            "key_file": str(tmp_path / "server.key"),
        },
        "acl": {"mode": "list", "trusted_keys": []},
    }

    state = {"active": 0, "peak": 0, "calls": 0}
    counter_lock = threading.Lock()
    original_wrap = ssl_module.SSLContext.wrap_socket

    def counting_wrap(self, sock, *args, **kwargs):
        with counter_lock:
            state["active"] += 1
            state["calls"] += 1
            state["peak"] = max(state["peak"], state["active"])
        try:
            return original_wrap(self, sock, *args, **kwargs)
        finally:
            with counter_lock:
                state["active"] -= 1

    monkeypatch.setattr(ssl_module.SSLContext, "wrap_socket", counting_wrap)

    transport = sap.CallbackTransport(config, "tcp")
    server = transport.listen(sap.Handler)
    server._security = sap.build_security(config, "server")
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()

    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        first.connect(("127.0.0.1", port))
        deadline = time.monotonic() + 1.0
        while state["calls"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        # Offer the second silent client while the first handshake is stalled.
        second.connect(("127.0.0.1", port))
        deadline = time.monotonic() + 2.0
        while state["peak"] < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert state["peak"] >= 2
    finally:
        first.close()
        second.close()
        _stop_server(transport, server, thread)


# -- A6: X.509 end-entity + critical-extension constraints ------------------


def _issue_leaf_ext(ca_cert: Any, ca_key: Any, *, oid: str | None, extensions: list):
    """Issue a leaf from the CA with extra ``(extension, critical)`` pairs."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sap-extra-leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if oid is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid)]), critical=False
        )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(ca_key, None), key


def test_x509_rejects_unknown_critical_extension(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """A CRITICAL extension we cannot process is rejected (RFC 5280; A6)."""
    from cryptography import x509
    from cryptography.x509.oid import ObjectIdentifier

    ca_cert, ca_key = _make_ca()
    unknown = x509.UnrecognizedExtension(
        ObjectIdentifier("1.2.3.4.5.6.7.8.9"), b"\x05\x00"
    )
    leaf, _ = _issue_leaf_ext(ca_cert, ca_key, oid=REQUIRED_OID, extensions=[(unknown, True)])

    with pytest.raises(sap.AuthError, match="critical extension"):
        sap.verify_x509_chain([leaf], [ca_cert], REQUIRED_OID)


def test_x509_accepts_unknown_noncritical_extension(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """A non-critical unknown extension is still acceptable (A6)."""
    from cryptography import x509
    from cryptography.x509.oid import ObjectIdentifier

    ca_cert, ca_key = _make_ca()
    unknown = x509.UnrecognizedExtension(
        ObjectIdentifier("1.2.3.4.5.6.7.8.9"), b"\x05\x00"
    )
    leaf, _ = _issue_leaf_ext(ca_cert, ca_key, oid=REQUIRED_OID, extensions=[(unknown, False)])

    assert sap.verify_x509_chain([leaf], [ca_cert], REQUIRED_OID) is leaf


def test_x509_rejects_ca_certificate_as_end_entity(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """A CA certificate (BasicConstraints CA:TRUE) is not a valid leaf (A6)."""
    ca_cert, _ = _make_ca()

    with pytest.raises(sap.AuthError, match="asserts CA"):
        sap.verify_x509_chain([ca_cert], [ca_cert], REQUIRED_OID)


def test_x509_rejects_leaf_without_digital_signature(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """A leaf KeyUsage without digitalSignature is rejected when present (A6)."""
    from cryptography import x509

    ca_cert, ca_key = _make_ca()
    no_digest = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    leaf, _ = _issue_leaf_ext(
        ca_cert, ca_key, oid=REQUIRED_OID, extensions=[(no_digest, False)]
    )

    with pytest.raises(sap.AuthError, match="digital signatures"):
        sap.verify_x509_chain([leaf], [ca_cert], REQUIRED_OID)


def test_x509_accepts_leaf_with_digital_signature(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """A leaf KeyUsage with digitalSignature is accepted (A6)."""
    from cryptography import x509

    ca_cert, ca_key = _make_ca()
    digest_only = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    leaf, _ = _issue_leaf_ext(
        ca_cert, ca_key, oid=REQUIRED_OID, extensions=[(digest_only, False)]
    )

    assert sap.verify_x509_chain([leaf], [ca_cert], REQUIRED_OID) is leaf


# -- A9: non-ASCII protocol strings fail cleanly ----------------------------


def test_secure_equals_tolerates_non_ascii(sap: types.ModuleType) -> None:
    assert sap.secure_equals("abc", "abc") is True
    assert sap.secure_equals("abc", "abd") is False
    # must not raise TypeError (review A9)
    assert sap.secure_equals("SHA256:caf\u00e9", "SHA256:cafe") is False
    assert sap.secure_equals(None, "abc") is False
    assert sap.secure_equals("abc", 1) is False


def test_non_ascii_key_id_raises_auth_error(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    request = _signed_request(sap, keymaterial)
    request["client_auth"]["key_id"] = "SHA256:caf\u00e9"
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial), "acl": _acl_for(sap, keymaterial)},
        "server",
    )

    with pytest.raises(sap.AuthError, match="key_id"):
        sap.authenticate_request(request, server)


def test_non_ascii_response_nonce_raises_protocol_error(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    request = _signed_request(sap, keymaterial)
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(keymaterial), "acl": _acl_for(sap, keymaterial)},
        "server",
    )
    response = sap.build_response(
        request["nonce"], "allow", request=request, security=server
    )
    response["nonce"] = "caf\u00e9"
    client = sap.build_security(_client_config(keymaterial), "client")

    with pytest.raises(sap.ProtocolError, match="nonce"):
        sap.verify_response(response, request, client)


def test_non_ascii_pending_nonce_raises_protocol_error(
    sap: types.ModuleType,
) -> None:
    pending = {"v": 1, "type": "auth_pending", "nonce": "caf\u00e9"}

    with pytest.raises(sap.ProtocolError, match="nonce"):
        sap.parse_pending(pending, _nonce())


# -- A10: mode is required ---------------------------------------------------


def test_main_requires_mode_and_never_starts_a_server(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(sap, "load_config", lambda _path: {})
    monkeypatch.setattr(
        sap, "run_server", lambda _config: pytest.fail("a server must not start")
    )
    monkeypatch.setattr(sys, "argv", ["sudo-auth-proxy", "--config", "x"])

    with pytest.raises(SystemExit) as exc:
        sap.main()

    assert exc.value.code == 1
    assert "mode" in capsys.readouterr().err


# -- A13: dialogs are serialised --------------------------------------------


def test_dialog_prompts_are_serialised(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent prompts must not overlap (doc §11.3/T11; audit A13)."""
    active = 0
    peak = 0
    counter_lock = threading.Lock()

    def fake_run(_argv: Sequence[str], *_args: Any, **_kwargs: Any) -> Any:
        nonlocal active, peak
        with counter_lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.1)
        with counter_lock:
            active -= 1
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    confirmation = _confirmation(sap)
    results: list[bool] = []

    def prompt_once() -> None:
        results.append(sap.prompt_for_confirmation(confirmation, "zenity"))

    threads = [threading.Thread(target=prompt_once) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert results == [True, True, True, True]
    assert peak == 1  # the global dialog lock serialised them


# -- A11: ca.py re-applies key modes on every ensure call -------------------
#
# The generation itself is covered above; these assert the remediation path for
# *pre-existing* keys, which the historic ca.py skipped (audit A11).


def _ca_test_config(tmp_path: Path):
    if str(SRC_PATH) not in sys.path:
        sys.path.insert(0, str(SRC_PATH))
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


def test_ca_reapplies_0600_to_preexisting_keys(tmp_path: Path) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    from tartarus import ca

    config = _ca_test_config(tmp_path)
    ca._ensure_x509_ca(config)
    ca._ensure_x509_host_cert(config)
    ca._ensure_x509_client_cert(config, "microvm", "stale")

    keys = [
        ca._x509_ca_key(config),
        ca._x509_host_key(config),
        ca.x509_machine_dir(config, "microvm", "stale") / "client.key",
    ]
    for key in keys:
        key.chmod(0o644)  # simulate an upgrade from the historic 0644

    # re-running the ensure path must tighten them again
    ca._ensure_x509_ca(config)
    ca._ensure_x509_host_cert(config)
    ca._ensure_x509_client_cert(config, "microvm", "stale")

    for key in keys:
        assert stat.S_IMODE(os.lstat(key).st_mode) == 0o600, key


# --- client_auth = "none" / acl.mode = "none" -------------------------------
#
# Disabling requester authentication is an explicit two-knob decision: every
# server must pair `client_auth = "none"` with `acl.mode = "none"` (and vice
# versa). These tests pin the resolution, the warned fail-open behaviour, the
# fixed sentinel identity, and every mismatch the XOR rejects.


def _none_client_config() -> dict:
    """A client that deliberately sends no requester credential."""
    return {
        "transport": "unix",
        "security": {
            "transport_encryption": "none",
            "client_auth": "none",
            "server_auth": "none",
        },
    }


def _none_server_config() -> dict:
    """A server that accepts unauthenticated requests through `acl.mode = "none"`."""
    return {
        "transport": "unix",
        "security": {
            "transport_encryption": "none",
            "client_auth": "none",
            "server_auth": "none",
        },
        "acl": {"mode": "none"},
    }


def test_client_auth_none_validate_accepts(sap: types.ModuleType) -> None:
    resolved = sap.validate_security_config(_none_client_config())

    assert resolved == {
        "transport_encryption": "none",
        "client_auth": "none",
        "server_auth": "none",
    }


def test_client_auth_none_warns_loudly_on_tcp(
    sap: types.ModuleType, capsys: pytest.CaptureFixture
) -> None:
    sap.validate_security_config(
        {
            "transport": "tcp",
            "security": {
                "transport_encryption": "none",
                "client_auth": "none",
                "server_auth": "signature",
            },
        }
    )
    err = capsys.readouterr().err

    assert "client_auth = 'none'" in err
    assert "does NOT authenticate" in err
    assert "strongly discouraged on tcp" in err


def test_client_auth_none_rejected_under_mtls(sap: types.ModuleType) -> None:
    # mTLS already forces client_auth = "transport"; "none" must not be a way
    # to opt out of the certificate that authenticates the channel.
    with pytest.raises(sap.SecurityConfigError, match="client_auth = 'none'"):
        sap.validate_security_config(
            {
                "transport": "tcp",
                "security": {
                    "transport_encryption": "mtls",
                    "client_auth": "none",
                    "server_auth": "transport",
                },
            }
        )


def test_client_auth_none_end_to_end(sap: types.ModuleType) -> None:
    client = sap.build_security(_none_client_config(), "client")
    request = _request_obj(sap)
    sap.attach_client_auth(request, client)

    assert request["client_auth"] == {"method": "none"}
    assert client.client_signing_key is None

    server = sap.build_security(_none_server_config(), "server")
    verified = sap.authenticate_request(request, server)

    assert verified == sap.NONE_IDENTITY == "none"
    assert sap.authorize_request(request, server, verified) == "none"
    # an unauthenticated ACL always "allows" (it is the explicit opt-in)
    assert sap.acl_allows_any(server.acl) is True


def test_build_security_none_requires_none_acl(sap: types.ModuleType) -> None:
    config = _none_server_config()
    config["acl"] = {"mode": "list", "trusted_keys": [_UNLISTED_FINGERPRINT]}

    with pytest.raises(sap.SecurityConfigError, match="requires acl.mode = 'none'"):
        sap.build_security(config, "server")


def test_build_security_none_acl_requires_none_client_auth(
    sap: types.ModuleType, keymaterial: Any
) -> None:
    # The mirror image: an unauthenticated ACL may not be paired with a
    # credential the server would otherwise authenticate.
    config = {
        "transport": "unix",
        "security": _server_security(keymaterial),
        "acl": {"mode": "none"},
    }

    with pytest.raises(sap.SecurityConfigError, match="requires client_auth = 'none'"):
        sap.build_security(config, "server")


def test_load_acl_none_rejects_trust_material(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="must not set trusted_keys"):
        sap.load_acl_config(
            {"acl": {"mode": "none", "trusted_keys": [_UNLISTED_FINGERPRINT]}}
        )


def test_authorize_none_requires_none_acl(sap: types.ModuleType) -> None:
    # A hand-built (or mutated) config that pairs "none" auth with a list ACL
    # must still refuse rather than treat the sentinel as a listed fingerprint.
    server = sap.build_security(_none_server_config(), "server")
    server.acl = sap.AclConfig(mode="list")
    request = _request_obj(sap)
    sap.attach_client_auth(
        request, sap.build_security(_none_client_config(), "client")
    )

    with pytest.raises(sap.AuthError, match="requires acl.mode = 'none'"):
        sap.authorize_request(request, server, sap.NONE_IDENTITY)


def test_authorize_none_acl_requires_none_client_auth(sap: types.ModuleType) -> None:
    server = sap.build_security(_none_server_config(), "server")
    server.client_auth = "ssh"

    with pytest.raises(sap.AuthError, match="requires client_auth = 'none'"):
        sap.authorize_request(_request_obj(sap), server, sap.NONE_IDENTITY)


# --- client_auth = "ssh" signed through the SSH agent -----------------------
#
# A minimal in-test agent speaks the length-prefixed protocol over a temporary
# Unix socket and signs with a real `cryptography` key. The wire constants are
# spelled out locally (not read from the module under test) so the test checks
# the protocol independently. `ssh_agent`/`ssh_agent_socket`/`ssh_key` are the
# new `[security]` keys; no private key file is ever read by the client.

# SSH agent protocol (draft-miller-ssh-agent)
_AGENT_FAILURE = 5
_AGENTC_REQUEST_IDENTITIES = 11
_AGENT_IDENTITIES_ANSWER = 12
_AGENTC_SIGN_REQUEST = 13
_AGENT_SIGN_RESPONSE = 14
_AGENT_RSA_SHA2_256 = 2


class _FakeSshAgent:
    """A minimal SSH agent over AF_UNIX for the client's agent-signing path.

    ``identities`` maps an SSH wire key blob to its private key. ``fail`` makes
    every request answer ``SSH_AGENT_FAILURE`` so the fail-closed path is
    exercised; ``omit`` returns an empty identity list so the configured key
    cannot be found. Each request is one connection, matching the client.
    """

    def __init__(
        self,
        socket_path: Path,
        identities: dict,
        *,
        fail: bool = False,
        omit: bool = False,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.identities = identities
        self.fail = fail
        self.omit = omit
        self.sign_flags: Any = None
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(self.socket_path))
        self._listener.listen(4)
        self._listener.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def __enter__(self) -> "_FakeSshAgent":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._listener.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                try:
                    self._handle(connection)
                except (OSError, KeyError, ValueError):
                    pass

    @staticmethod
    def _read_exact(connection: Any, count: int) -> bytes:
        buffer = bytearray()
        while len(buffer) < count:
            chunk = connection.recv(count - len(buffer))
            if not chunk:
                raise ValueError("client closed early")
            buffer += chunk
        return bytes(buffer)

    @classmethod
    def _read_string(cls, payload: bytes, offset: int):
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        return payload[offset : offset + length], offset + length

    @staticmethod
    def _string(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    def _send(self, connection: Any, payload: bytes) -> None:
        connection.sendall(struct.pack(">I", len(payload)) + payload)

    def _handle(self, connection: Any) -> None:
        (length,) = struct.unpack(">I", self._read_exact(connection, 4))
        payload = self._read_exact(connection, length)
        if self.fail:
            self._send(connection, bytes([_AGENT_FAILURE]))
            return
        kind = payload[0]
        if kind == _AGENTC_REQUEST_IDENTITIES:
            blobs = [] if self.omit else list(self.identities)
            body = bytes([_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", len(blobs))
            body += b"".join(self._string(blob) + self._string(b"test") for blob in blobs)
            self._send(connection, body)
        elif kind == _AGENTC_SIGN_REQUEST:
            key_blob, offset = self._read_string(payload, 1)
            data, offset = self._read_string(payload, offset)
            (self.sign_flags,) = struct.unpack(">I", payload[offset : offset + 4])
            signature_blob = self._sign(self.identities[key_blob], data, self.sign_flags)
            self._send(
                connection,
                bytes([_AGENT_SIGN_RESPONSE]) + self._string(signature_blob),
            )
        else:
            self._send(connection, bytes([_AGENT_FAILURE]))

    @staticmethod
    def _sign(private_key: Any, data: bytes, flags: int) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return _FakeSshAgent._string(b"ssh-ed25519") + _FakeSshAgent._string(
                private_key.sign(data)
            )
        if isinstance(private_key, rsa.RSAPrivateKey):
            # the client must request SHA-256 through the agent flag
            assert flags == _AGENT_RSA_SHA2_256, flags
            signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
            return _FakeSshAgent._string(b"rsa-sha2-256") + _FakeSshAgent._string(
                signature
            )
        raise ValueError("unsupported test key")


def _agent_client_config(socket_path: Path, ssh_key: str, **overrides: Any) -> dict:
    """A client `[security]` block signing `ssh` through the agent at `socket_path`."""
    security: dict[str, Any] = {
        "transport_encryption": "none",
        "client_auth": "ssh",
        "server_auth": "none",
        "ssh_agent": True,
        "ssh_agent_socket": str(socket_path),
        "ssh_key": ssh_key,
    }
    security.update(overrides)
    return {"transport": "unix", "security": security}


def _assert_agent_block_verifies(
    sap: types.ModuleType, request: dict, public_key: Any, *, key_id: str
) -> None:
    """Verify an agent-signed block exactly like the server does."""
    block = request["client_auth"]
    assert block["method"] == "ssh"
    assert block["key_id"] == key_id
    assert block["public_key"] == base64.b64encode(
        sap.ssh_public_blob(public_key)
    ).decode()
    sap.verify_bytes(
        public_key,
        block["alg"],
        sap.signing_payload(request, "client_auth"),
        base64.b64decode(block["signature"]),
    )


def test_ssh_agent_ed25519_signs_and_verifies(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    private_key = sap.load_private_key_file(keymaterial.client_private)
    blob = sap.ssh_public_blob(private_key.public_key())
    key_id = sap.ssh_fingerprint(private_key.public_key())
    socket_path = tmp_path / "agent.sock"

    with _FakeSshAgent(socket_path, {blob: private_key}) as agent:
        client = sap.build_security(
            _agent_client_config(socket_path, keymaterial.client_public), "client"
        )
        assert client.client_signing_key is None
        assert client.client_signing_agent_socket == str(socket_path)
        request = _request_obj(sap)
        sap.attach_client_auth(request, client)

    assert request["client_auth"]["alg"] == "ssh-ed25519"
    _assert_agent_block_verifies(sap, request, private_key.public_key(), key_id=key_id)
    assert agent.sign_flags == 0

    # the server verifies and authorizes the agent-signed request unchanged
    server = sap.build_security(
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "ssh",
                "server_auth": "none",
                "trusted_keys": [keymaterial.client_public],
            },
            "acl": {"mode": "list", "trusted_keys": [key_id]},
        },
        "server",
    )
    assert sap.authenticate_request(request, server) == key_id
    assert sap.authorize_request(request, server, key_id) == key_id


def test_ssh_agent_rsa_requests_sha256(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_line = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    blob = sap.ssh_public_blob(private_key.public_key())
    key_id = sap.ssh_fingerprint(private_key.public_key())
    socket_path = tmp_path / "agent.sock"

    with _FakeSshAgent(socket_path, {blob: private_key}) as agent:
        client = sap.build_security(
            _agent_client_config(socket_path, public_line), "client"
        )
        request = _request_obj(sap)
        sap.attach_client_auth(request, client)

    assert request["client_auth"]["alg"] == "rsa-sha2-256"
    assert agent.sign_flags == _AGENT_RSA_SHA2_256
    _assert_agent_block_verifies(sap, request, private_key.public_key(), key_id=key_id)


def test_ssh_agent_uses_ssh_auth_sock_default(
    sap: types.ModuleType,
    crypto: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_line = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    socket_path = tmp_path / "agent.sock"
    monkeypatch.setenv("SSH_AUTH_SOCK", str(socket_path))

    with _FakeSshAgent(socket_path, {sap.ssh_public_blob(private_key.public_key()): private_key}):
        client = sap.build_security(
            _agent_client_config(socket_path, public_line, ssh_agent_socket=None),
            "client",
        )

    # `ssh_agent = true` with no explicit socket falls back to $SSH_AUTH_SOCK.
    assert client.client_signing_agent_socket == str(socket_path)


def test_ssh_agent_missing_key_in_agent_fails_closed(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    other = sap.load_private_key_file(keymaterial.server_private)
    socket_path = tmp_path / "agent.sock"

    with _FakeSshAgent(
        socket_path, {sap.ssh_public_blob(other.public_key()): other}
    ):
        client = sap.build_security(
            _agent_client_config(socket_path, keymaterial.client_public), "client"
        )
        request = _request_obj(sap)

        with pytest.raises(sap.AuthError, match="does not hold the configured key"):
            sap.attach_client_auth(request, client)


def test_ssh_agent_unset_socket_fails_closed(
    sap: types.ModuleType,
    crypto: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    keymaterial: Any,
) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    config = _agent_client_config(Path("/nonexistent/agent.sock"), keymaterial.client_public)
    del config["security"]["ssh_agent_socket"]

    with pytest.raises(sap.SecurityConfigError, match="SSH_AUTH_SOCK"):
        sap.build_security(config, "client")


def test_ssh_agent_unreachable_socket_fails_closed(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    # A configured socket that does not exist is a runtime failure at signing
    # time (build_security only records the path), and must fail closed.
    client = sap.build_security(
        _agent_client_config(tmp_path / "missing.sock", keymaterial.client_public),
        "client",
    )
    request = _request_obj(sap)

    with pytest.raises(sap.AuthError, match="cannot talk to the SSH agent"):
        sap.attach_client_auth(request, client)


def test_ssh_agent_failure_response_fails_closed(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path, keymaterial: Any
) -> None:
    private_key = sap.load_private_key_file(keymaterial.client_private)
    socket_path = tmp_path / "agent.sock"

    with _FakeSshAgent(
        socket_path, {sap.ssh_public_blob(private_key.public_key()): private_key}, fail=True
    ):
        client = sap.build_security(
            _agent_client_config(socket_path, keymaterial.client_public), "client"
        )
        request = _request_obj(sap)

        with pytest.raises(sap.AuthError, match="refused to list"):
            sap.attach_client_auth(request, client)


def test_ssh_agent_requires_ssh_key(sap: types.ModuleType, tmp_path: Path) -> None:
    config = _agent_client_config(tmp_path / "agent.sock", "")
    del config["security"]["ssh_key"]

    with pytest.raises(sap.SecurityConfigError, match="ssh_key"):
        sap.build_security(config, "client")


def test_load_config_resolves_ssh_agent_paths(sap: types.ModuleType, tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[security]\nssh_key = "keys/id.pub"\nssh_agent_socket = "run/agent.sock"\n'
    )

    loaded = sap.load_config(str(config_path))

    assert loaded["security"]["ssh_key"] == str(tmp_path / "keys" / "id.pub")
    assert loaded["security"]["ssh_agent_socket"] == str(tmp_path / "run" / "agent.sock")


def test_load_config_leaves_inline_ssh_key_untouched(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    inline = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleexampleexampleexample comment"
    config_path = tmp_path / "config.toml"
    config_path.write_text(f'[security]\nssh_key = "{inline}"\n')

    loaded = sap.load_config(str(config_path))

    assert loaded["security"]["ssh_key"] == inline

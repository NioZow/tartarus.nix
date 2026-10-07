"""Tests for ``sudo-auth-proxy`` (redesign Phases 1-6).

**Authentication is mTLS-only.** The SSH-key, ssh-agent and application-layer
X.509 request signatures and the host-signed responses were removed, together
with their Nix options, TOML keys, keyrings and wire fields; the three security
knobs are now `transport_encryption` plus `client_auth`/`server_auth`, each of
which is `"transport"` or `"none"`. Tests that need an authenticated credential
drive the mTLS path (a real CA-issued leaf certificate passed as the peer DER,
or the pinned leaf SPKI); tests that only need to exercise framing, routing and
timing use the explicit unauthenticated pairing (`"none"` on all three knobs
with the matching `acl.mode = "none"`).

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
7. authorization (Phase 4, doc §8) -- `acl.mode` resolution and validation,
   `mode = "list"` SPKI pinning, `mode = "ca"` chain + EKU enforcement, the
   `"none"` XOR with `client_auth`, and the ACL running *before* any dialog;
8. Phase 6 fast-fail/timeout semantics (doc §10.1-§10.5, §6.7; review logs
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
import tomllib
import types
from pathlib import Path
from typing import Any, Iterator, Sequence

import pytest

SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "nix"
    / "packages"
    / "sudo-auth-proxy"
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


@pytest.fixture(autouse=True)
def _reset_zenity_probe(monkeypatch: pytest.MonkeyPatch, sap: types.ModuleType) -> None:
    """Forget the cached `--extra-button` probe before each test.

    The probe is cached for the life of a *server* process, and one pytest run
    hosts many of them: without this reset the first zenity test would answer for
    every later one, including the tests that simulate an older zenity.
    """
    monkeypatch.setattr(sap, "_zenity_extra_button_support", None)


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


# --- security helpers ------------------------------------------------------
#
# Authentication is mTLS-only: the three knobs are `transport_encryption` plus
# the two auths, and the only two values an auth knob can take are "transport"
# and "none". Most tests here exercise the *unauthenticated* pairing (a private
# transport, `client_auth = "none"` + `acl.mode = "none"`), because it needs no
# certificates and keeps the focus on framing, routing and timeouts; the mTLS
# path is covered by the dedicated helpers and tests below.


def _server_security(*_unused: Any, **overrides: Any) -> dict:
    """A valid server-side ``[security]`` block for a private callback transport."""
    security: dict[str, Any] = {
        "transport_encryption": "none",
        "client_auth": "none",
        "server_auth": "none",
    }
    security.update(overrides)
    return security


def _client_security(*_unused: Any, **overrides: Any) -> dict:
    """A valid client-side ``[security]`` block for a private callback transport."""
    security: dict[str, Any] = {
        "transport_encryption": "none",
        "client_auth": "none",
        "server_auth": "none",
    }
    security.update(overrides)
    return security


def _mtls_server_security(**overrides: Any) -> dict:
    """The mTLS server-side block (both auths are forced to ``transport``)."""
    security: dict[str, Any] = {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }
    security.update(overrides)
    return security


def _authed_request(sap: types.ModuleType, **overrides: Any) -> dict:
    """Build a request and attach its ``client_auth`` marker block.

    No key material is involved: the block is a one-field marker (`"transport"`
    or `"none"`), because mTLS is the only authentication mechanism (doc §6.5).
    """
    request = _request_obj(sap, **overrides)
    security = sap.build_security(_client_config(), "client")
    sap.attach_client_auth(request, security)
    return request


def _mtls_client_config(**overrides: Any) -> dict:
    """A client config whose credential is the (channel) mTLS certificate."""
    config: dict[str, Any] = {
        "transport": "unix",
        "security": _mtls_server_security(),
    }
    config.update(overrides)
    return config


def _spki(sap: types.ModuleType, cert: Any) -> str:
    """The ``SHA256:...`` leaf SPKI fingerprint a ``mode = "list"`` ACL pins."""
    return sap.spki_fingerprint(cert.public_key())


def _acl_list(*fingerprints: str) -> dict:
    """A ``mode = "list"`` ACL; no arguments is an intentional deny-all list."""
    return {"mode": "list", "trusted_fingerprints": list(fingerprints)}


def _acl_for(sap: types.ModuleType, keys: Any = None) -> dict:
    """The default allow-any ACL used by the unauthenticated exchange helpers.

    `client_auth = "none"` has no credential to authorize, so the matching ACL
    is `mode = "none"`; the Python enforces that pairing as a fail-closed XOR.
    """
    return {"mode": "none"}


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
    """Minimal stand-in for the accepted socket, enough for peer resolution.

    `peer_cert_der` makes it look like an mTLS-wrapped socket: the handler reads
    the verified peer certificate from it exactly as it would from a real
    `ssl.SSLSocket`, so the mTLS credential path is exercised without a channel.
    """

    def __init__(self, peer: tuple[str, int], peer_cert_der: bytes | None = None) -> None:
        self._peer = peer
        self._peer_cert_der = peer_cert_der

    def getpeername(self) -> tuple[str, int]:
        return self._peer

    def getpeercert(self, binary_form: bool = False):
        if not binary_form:
            raise AssertionError("the handler must ask for the DER form")
        return self._peer_cert_der


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
    keys: Any = None,
    acl: Any = None,
    *,
    security: Any = None,
    peer_cert_der: bytes | None = None,
) -> tuple[list[bytes], list[tuple[Any, str]]]:
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
        "security": security if security is not None else _server_security(keys),
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
    handler.request = _FakeRequestSocket((FAKE_PEER, 12345), peer_cert_der)
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
) -> None:
    request = _authed_request(sap)
    frames, prompts = _exchange(sap, monkeypatch, [approved], _frame(sap, request))

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
    # no `server_auth` block: the response is authenticated by the mTLS channel,
    # or explicitly not at all (doc §6.5)
    assert "server_auth" not in parsed

    assert len(prompts) == 1
    confirmation, program = prompts[0]
    assert program == "zenity"
    # the dialog context carries the verified identity and metadata. With
    # `client_auth = "none"` there is no credential, so the identity is the
    # fixed NONE_IDENTITY sentinel -- which the summary renders as
    # "Unauthenticated requester" rather than printing the sentinel (doc §11.4).
    assert confirmation.peer == FAKE_PEER
    assert confirmation.identity == sap.NONE_IDENTITY
    assert "Unauthenticated requester" in sap.confirmation_summary(confirmation)
    assert confirmation.target_user == "root"
    assert confirmation.transport == "tcp"


def test_handler_malformed_frame_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    frames, prompts = _exchange(sap, monkeypatch, [], b"not-json\n")

    assert frames == []
    assert prompts == []


def test_handler_oversize_frame_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversize = b"{" + b"a" * (sap.MAX_MESSAGE_BYTES + 10) + b"}\n"
    frames, prompts = _exchange(sap, monkeypatch, [], oversize)

    assert frames == []
    assert prompts == []


# --- unix transport (real single listener) ---

def _client_config() -> dict:
    """The client-side counterpart of :func:`_unix_server`."""
    return {
        "transport": "unix",
        "resolution": "none",
        "dialog_program": "zenity",
        "connect_timeout": 0.5,
        # Generous bounds so a legitimate client/server round-trip is never
        # tripped by the first-byte timeout; the timing tests override these
        # with small explicit values.
        "recv_timeout": 5.0,
        "decision_timeout": 5,
        "security": _client_security(),
    }

# --- unix transport (real single listener) --------------------------------


@contextlib.contextmanager
def _unix_server(
    sap: types.ModuleType, sock_path: Path
) -> Iterator[tuple[Any, Any]]:
    """Start a real single-socket unix server under ``sock_path``.

    The config is the unauthenticated pairing (`transport_encryption = "none"`,
    `client_auth`/`server_auth` = `"none"` and the matching `acl.mode = "none"`),
    so the round-trip tests exercise the real request/response path over a real
    socket without needing certificates. The mTLS path is covered separately.
    """
    config = {
        "transport": "unix",
        "socket": str(sock_path),
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "resolution": "none",
        "dialog_program": "zenity",
        "security": _server_security(),
        "acl": _acl_for(sap),
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


def test_unix_server_round_trip(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    # The peer here is a Python test server, not sshd; neutralise the Linux
    # peer-process check (it is exercised directly further down).
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config())

    assert exc.value.code == 0


def test_unix_server_deny_exits_nonzero(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: False)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config())

    assert exc.value.code == 1


def test_unix_client_without_selector_fails_closed(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A config `socket` must never be used as a client fallback: without the
    # selector the client fails before opening anything.
    monkeypatch.delenv("SUDO_AUTH_PROXY_SOCK", raising=False)
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)

    config = _client_config()
    config["socket"] = str(tmp_path / "should-not-be-used.sock")
    with pytest.raises(SystemExit) as exc:
        sap.run_client(config)

    assert exc.value.code == 1
    assert not (tmp_path / "should-not-be-used.sock").exists()


def test_unix_server_one_listener_serves_concurrent_sessions(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)
    # The guard is process-global and these clients share one process; in
    # production each pam_exec invocation is a separate process. Neutralise it
    # so the concurrency of the *listener* is what is under test.
    monkeypatch.setattr(sap, "recursion_guard_active", lambda: False)

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        results: list[Any] = []

        def run_one() -> None:
            try:
                sap.run_client(_client_config())
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
    sap: types.ModuleType, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"

    with _unix_server(sap, sock_path):
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

    transport = sap.UnixTransport(
        {"transport": "unix", "socket": str(link), "security": _server_security()}
    )
    with pytest.raises(RuntimeError, match="symlink"):
        transport.listen(sap.Handler)


def test_unix_refuses_regular_file_bind(
    sap: types.ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "run" / "server.sock"
    target.parent.mkdir(parents=True)
    target.write_text("not a socket")

    transport = sap.UnixTransport(
        {"transport": "unix", "socket": str(target), "security": _server_security()}
    )
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
        transport = sap.UnixTransport(
            {"transport": "unix", "socket": str(target), "security": _server_security()}
        )
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
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: None)

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config())

    assert exc.value.code == 0
    assert os.environ.get("SUDO_AUTH_PROXY_ACTIVE") == "1"


def test_run_client_refuses_non_sshd_peer(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sock_path = tmp_path / "run" / "server.sock"
    monkeypatch.setattr(sap, "prompt_for_confirmation", lambda _peer, _program: True)
    monkeypatch.setattr(sap, "verify_unix_peer_is_sshd", lambda *_a, **_k: False)

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config())

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
        # Deliberately reachable by another uid: the child below must be able to
        # connect as `nobody` for the authorization check to have anything to
        # refuse. The socket lives in a private pytest temp dir, not a shared one.
        os.chmod(work, 0o711)  # noqa: S103 -- traverse-only, so the child can reach it
        os.chmod(sock_path, 0o777)  # noqa: S103 -- connectable, then refused
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
            except BaseException:  # noqa: BLE001, S110 -- the child exits either way
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
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    *,
    stdout: bytes = b"",
    stdout_sequence: Sequence[bytes] | None = None,
    returncode_sequence: Sequence[int] | None = None,
    extra_button: bool = True,
) -> list[RunCall]:
    """Replace ``subprocess.run`` with a recorder; never spawn a dialog.

    ``returncode`` is used for every call unless ``stdout_sequence`` /
    ``returncode_sequence`` are given, in which case call *n* takes the *n*-th
    entry of each. The ``osascript`` backend decides what the approver pressed by
    reading ``button returned:<name>`` from stdout, and the ``zenity`` backend
    reads the label zenity prints for its extra button, so those tests drive both
    backends from here.

    ``extra_button`` answers the zenity capability probe (``--help-all``): a
    modern zenity advertises ``--extra-button``, an older one does not. Probe
    calls are recorded but never consume the sequences -- the sequences describe
    the *dialogs*, which is what the tests are about.
    """
    calls: list[RunCall] = []
    stdout_by_call = list(stdout_sequence) if stdout_sequence is not None else None
    returncode_by_call = (
        list(returncode_sequence) if returncode_sequence is not None else None
    )

    def fake_run(
        argv: Sequence[str], *args: Any, **kwargs: Any
    ) -> types.SimpleNamespace:
        calls.append((list(argv), dict(kwargs)))
        if "--help-all" in argv:
            probe_out = b"--extra-button\n" if extra_button else b""
            return types.SimpleNamespace(returncode=0, stdout=probe_out)

        index = len(calls) - 1 - _probe_count(calls, exclude_last=True)
        out = (
            stdout_by_call[index]
            if stdout_by_call is not None and index < len(stdout_by_call)
            else stdout
        )
        code = (
            returncode_by_call[index]
            if returncode_by_call is not None and index < len(returncode_by_call)
            else returncode
        )
        return types.SimpleNamespace(returncode=code, stdout=out)

    # the script calls ``subprocess.run`` through the module-level name, so
    # patching the shared ``subprocess`` module object is what it observes.
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _probe_count(calls: list[RunCall], *, exclude_last: bool = False) -> int:
    """How many recorded calls are zenity capability probes."""
    recorded = calls[:-1] if exclude_last else calls
    return sum(1 for argv, _kwargs in recorded if "--help-all" in argv)


def _dialog_calls(calls: list[RunCall]) -> list[RunCall]:
    """The dialog invocations, i.e. everything but the capability probe."""
    return [call for call in calls if "--help-all" not in call[0]]


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
    # the prompt itself is the condensed summary (doc §11.4)
    message = argv[argv.index("--message") + 1]
    assert message == sap.escape_swiftdialog_markup(
        sap.confirmation_summary(confirmation)
    )
    assert "vault requests root via sudo" in message
    assert "on vault" in message
    # ...and the full field block is reachable behind the info button
    assert argv[argv.index("--infobuttontext") + 1] == "Details"
    details = argv[argv.index("--info") + 1]
    # swiftDialog interprets its own markup, so the block is escaped for it
    assert details == sap.escape_swiftdialog_markup(
        sap.confirmation_message(confirmation)
    )
    assert "SHA256:AbCdEf" in details
    assert "user -> root" in details
    # the command/argv is absent from both (review log S5)
    assert "command" not in message.lower()
    assert "cmdline" not in message.lower()
    assert "command" not in details.lower()
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
    """The first dialog shows the summary; only `Authorize` allows.

    `returncode` drives the dialog: 0 means a button was pressed (the button
    name is read from stdout), 1 means it was cancelled/closed.
    """
    stdout = b"button returned:Authorize\n" if returncode == 0 else b""
    calls = _install_fake_run(monkeypatch, returncode, stdout=stdout)
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "osascript") is approved

    argv, kwargs = calls[0]
    assert argv[0] == "osascript"
    assert argv[1] == "-e"
    script = argv[2]
    # the summary is JSON-encoded before it is embedded in the AppleScript
    assert json.dumps(sap.confirmation_summary(confirmation)) in script
    assert json.dumps("sudo authentication for vault") in script
    assert json.dumps(sap.confirmation_message(confirmation)) not in script
    # a third button opens the detail block rather than deciding anything
    assert "Details" in script
    assert kwargs.get("capture_output") is True


def test_osascript_details_button_shows_the_block_then_decides(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Details` must never be mistaken for a decision (doc §11.4)."""
    calls = _install_fake_run(
        monkeypatch,
        0,
        stdout_sequence=[
            b"button returned:Details\n",
            b"button returned:Deny\n",
        ],
    )
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "osascript") is False

    assert len(calls) == 2
    details_script = calls[1][0][2]
    assert json.dumps(sap.confirmation_message(confirmation)) in details_script
    assert "display dialog" in details_script


def test_osascript_details_then_authorize_allows(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_run(
        monkeypatch,
        0,
        stdout_sequence=[
            b"button returned:Details\n",
            b"button returned:Authorize\n",
        ],
    )
    confirmation = _confirmation(sap)

    assert sap.prompt_for_confirmation(confirmation, "osascript") is True


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

    (argv, kwargs) = _dialog_calls(calls)[0]
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
    # The default view stays the condensed summary; the field block is behind
    # Details (doc §11.4).
    assert text == sap.confirmation_summary(confirmation)
    assert "vault requests root via sudo" in text
    assert "command" not in text.lower()
    # An explicit width keeps the prompt wider than it is tall: zenity otherwise
    # wraps at 60 characters and produces a narrow, cramped column. The height is
    # deliberately left to the content.
    assert argv[argv.index("--width") + 1] == str(sap.ZENITY_DIALOG_WIDTH)
    assert "--height" not in argv
    # The Details affordance is offered, unambiguous by stdout (see the flow
    # tests below), and only its label -- never a decision -- rides on it.
    assert argv[argv.index("--extra-button") + 1] == sap.ZENITY_DETAILS_LABEL
    assert argv[argv.index("--ok-label") + 1] == "Authorize"
    assert "stderr" not in kwargs


def test_zenity_details_button_shows_the_block_then_decides(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pressing Details opens a second dialog carrying the full block (doc §11.4).

    The reported gap: the summary names the peer but not the terminal, so there
    was no way to see *which* pty was asking. zenity prints an extra button's
    label on stdout (its exit code is the cancellation code), so the label is
    what identifies the press.
    """
    calls = _install_fake_run(
        monkeypatch,
        returncode=1,
        stdout_sequence=[b"Details\n", b""],
        returncode_sequence=[1, 0],
    )
    confirmation = _confirmation(sap, tty="/dev/pts/7", cwd="/home/user")

    assert sap.prompt_for_confirmation(confirmation, "zenity") is True

    dialogs = _dialog_calls(calls)
    assert len(dialogs) == 2
    first, _second = dialogs
    assert first[1].get("stdout") is subprocess.PIPE
    assert first[0][first[0].index("--text") + 1] == sap.confirmation_summary(confirmation)

    argv, _kwargs = dialogs[1]
    text = argv[argv.index("--text") + 1]
    assert text == sap.confirmation_message(confirmation)
    assert "TTY        /dev/pts/7" in text  # the pty the summary does not show
    assert "CWD        /home/user" in text
    # The field block gets the same explicit width as the prompt, so the labelled
    # rows read across instead of stacking into a column.
    assert argv[argv.index("--width") + 1] == str(sap.ZENITY_DIALOG_WIDTH)
    assert "--height" not in argv
    # Deny takes the focus in the detail dialog: the block is request metadata.
    assert "--default-cancel" in argv
    assert argv[argv.index("--ok-label") + 1] == "Authorize"


def test_zenity_details_never_authorizes_by_itself(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Details is not a decision, even if the exit code says otherwise.

    zenity exits 1 for the extra button, but the code must not *rely* on that: a
    zero code alongside the Details label still means "show me more", so the
    second dialog decides. Here the second dialog denies.
    """
    calls = _install_fake_run(
        monkeypatch,
        returncode=1,
        stdout_sequence=[b"Details\n", b""],
        returncode_sequence=[0, 1],
    )

    assert sap.prompt_for_confirmation(_confirmation(sap), "zenity") is False
    assert len(_dialog_calls(calls)) == 2


def test_zenity_details_carries_only_sanitised_fields(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The block behind Details went through the same allow-list (doc §11.2)."""
    calls = _install_fake_run(
        monkeypatch,
        returncode=1,
        stdout_sequence=[b"Details\n", b""],
        returncode_sequence=[1, 0],
    )
    confirmation = _confirmation(sap, tty="/dev/pts/0\nevil: injected")

    assert sap.prompt_for_confirmation(confirmation, "zenity") is True

    text = _dialog_calls(calls)[1][0]
    detail_text = text[text.index("--text") + 1]
    lines = detail_text.split("\n")
    # The injected newline became `?`, so the TTY stays on its own single label
    # line: a field can never forge a second line of the block.
    assert "TTY        /dev/pts/0?evil: injected" in lines
    assert sum(1 for line in lines if line.startswith("TTY")) == 1


def test_zenity_without_extra_button_keeps_the_summary_only_prompt(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zenity that cannot add a button still prompts exactly as it always did.

    An unknown option would make zenity exit non-zero with empty stdout, which
    this module reads as a deny -- so a summary-only backend must never be sent
    `--extra-button`.
    """
    calls = _install_fake_run(monkeypatch, returncode=0, extra_button=False)

    assert sap.prompt_for_confirmation(_confirmation(sap), "zenity") is True

    dialogs = _dialog_calls(calls)
    assert len(dialogs) == 1
    argv, kwargs = dialogs[0]
    assert "--extra-button" not in argv
    assert argv[argv.index("--text") + 1] == sap.confirmation_summary(_confirmation(sap))
    # unchanged from before the affordance existed: no output is parsed at all
    assert kwargs == {}


def test_zenity_probe_is_cached_and_absence_is_not_fatal(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The capability probe runs once per process and degrades on any failure."""
    calls = _install_fake_run(monkeypatch, returncode=0)

    sap.prompt_for_confirmation(_confirmation(sap), "zenity")
    sap.prompt_for_confirmation(_confirmation(sap), "zenity")

    probes = [call for call in calls if "--help-all" in call[0]]
    assert len(probes) == 1

    # A zenity that cannot even be executed (or hangs past the probe bound) is
    # "no support", which is the old prompt rather than a denial.
    monkeypatch.setattr(sap, "_zenity_extra_button_support", None)

    def explode(argv: Sequence[str], *args: Any, **kwargs: Any) -> Any:
        if "--help-all" in argv:
            raise FileNotFoundError("zenity")
        return types.SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(subprocess, "run", explode)

    assert sap.prompt_for_confirmation(_confirmation(sap), "zenity") is True
    assert sap.zenity_supports_extra_button() is False


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

    # The dialog invocation, not the zenity capability probe that precedes it.
    argv, _ = _dialog_calls(calls)[0]
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
    capsys: pytest.CaptureFixture,
) -> None:
    """The server's debug log carries only sanitised fields (review log NF8)."""
    monkeypatch.setenv("SUDO_AUTH_PROXY_DEBUG", "1")
    # `set_debug` mutates the module global; record and restore it.
    monkeypatch.setattr(sap, "debug_enabled", False)
    request = _authed_request(
        sap,
        tty="/dev/pts/0\nEVIL\r\x1b[31m",
        invoking_user="user\u202e",
        guest_hint="hi\nthere",
    )

    _exchange(sap, monkeypatch, [True], _frame(sap, request))
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
    summary = sap.confirmation_summary(confirmation)

    # the summary names the requester by its label and stays two lines long
    assert summary.splitlines()[0] == "alice-laptop requests root via sudo"
    assert len(summary.splitlines()) == 2
    # the detailed block still carries the verified identity separately
    assert "Requester  alice-laptop" in message
    assert "Identity   SHA256:abc" in message
    assert "user -> root" in message
    assert "TTY        /dev/pts/0" in message
    assert "CWD        /home/user" in message
    assert "2023-11-14T22:13:20Z" in message
    assert confirmation.request_id in message
    assert "command" not in message.lower()
    assert "command" not in summary.lower()
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


def test_signature_machinery_is_gone(sap: types.ModuleType) -> None:
    """The removed signature layer must not linger as dead code or state.

    mTLS is the only authentication mechanism, so there is no signing key, no
    domain-separation label and no signature transcript any more (doc §6.4).
    """
    for attribute in (
        "DOMAIN_LABEL",
        "SSH_SIGNATURE_ALGS",
        "X509_SIGNATURE_ALGS",
        "signing_payload",
        "without_signature",
        "sign_bytes",
        "verify_bytes",
        "ssh_fingerprint",
        "load_private_key_file",
        "ssh_agent_sign",
        "parse_cert_chain_b64",
    ):
        assert not hasattr(sap, attribute), attribute


def test_request_digest_covers_the_whole_request(sap: types.ModuleType) -> None:
    """Nothing is stripped before hashing: there is no signature field to strip."""
    request = {
        "v": 1,
        "type": "auth_request",
        "nonce": _nonce(),
        "client_auth": {"method": "transport"},
    }
    tampered = copy.deepcopy(request)
    tampered["client_auth"]["method"] = "none"

    assert sap.compute_request_digest(request) != sap.compute_request_digest(tampered)


# --- configuration schema (exact keys, doc §7.9/§15.1) ---------------------
#
# The reported failure this covers: a config whose `transport_encryption`,
# `client_auth` and `server_auth` lines sit *above* the `[security]` header has
# no `[security]` knobs at all (TOML scopes a key to the nearest preceding table
# header). Under the old "unknown keys are ignored" policy that was reported as
# `transport_encryption = 'none' requires an explicit client_auth = 'none'`,
# naming exactly what the operator had already written. The schema check runs
# first and names the real problem: the key and the table it belongs to.

EXAMPLE_CONFIG_PATH = (
    Path(__file__).resolve().parents[1] / "examples" / "sudo-auth-proxy-server.toml"
)


def _flat_unauthenticated_config() -> dict:
    """The reported config: the auth knobs written above the `[security]` header."""
    return {
        "mode": "server",
        "transport": "vsock",
        "cid": 2,
        "port": 65012,
        "dialog_program": "zenity",
        "transport_encryption": "none",
        "client_auth": "none",
        "server_auth": "none",
        "response_ttl": 30,
        "clock_skew": 5,
        "acl": {"mode": "none"},
    }


def test_schema_flags_a_security_key_written_above_its_table(
    sap: types.ModuleType,
) -> None:
    """A flattened `[security]` block is a placement error, not a missing knob."""
    with pytest.raises(sap.SecurityConfigError) as exc:
        sap.validate_config_schema(
            _flat_unauthenticated_config(),
            source="/etc/sudo-auth-proxy/config.toml",
        )

    message = str(exc.value)
    assert "client_auth" in message
    assert "[security]" in message
    assert "top level" in message
    assert "/etc/sudo-auth-proxy/config.toml" in message


def test_build_security_reports_the_placement_before_the_knob(
    sap: types.ModuleType,
) -> None:
    """The regression: the misleading "requires an explicit client_auth" is gone.

    Both knobs *are* written in this config, so complaining that they are missing
    (and never mentioning where they went) is the failure mode under test.
    """
    with pytest.raises(sap.SecurityConfigError) as exc:
        sap.build_security(_flat_unauthenticated_config(), "server")

    assert "[security]" in str(exc.value)
    assert "refusing to disable authentication implicitly" not in str(exc.value)


def test_schema_accepts_the_same_config_with_a_security_table(
    sap: types.ModuleType,
) -> None:
    """Moving those five lines under `[security]` is the whole fix."""
    config = _flat_unauthenticated_config()
    security = {
        key: config.pop(key)
        for key in (
            "transport_encryption",
            "client_auth",
            "server_auth",
            "response_ttl",
            "clock_skew",
        )
    }
    config["security"] = security

    sap.validate_config_schema(config)
    resolved = sap.build_security(config, "server")

    assert resolved.transport_encryption == "none"
    assert resolved.client_auth == "none"
    assert resolved.acl.mode == "none"


def test_schema_rejects_an_unknown_key_and_suggests_the_real_one(
    sap: types.ModuleType,
) -> None:
    config = {"mode": "server", "transport": "vsock", "max_connection": 64}

    with pytest.raises(sap.SecurityConfigError, match="max_connections"):
        sap.validate_config_schema(config)


def test_schema_rejects_a_top_level_key_inside_a_table(
    sap: types.ModuleType,
) -> None:
    """The mirror image: a top-level key belongs above every table header."""
    config = {
        "mode": "server",
        "transport": "vsock",
        "security": dict(_server_security(), socket="/run/sudo-auth-proxy/x.sock"),
    }

    with pytest.raises(sap.SecurityConfigError) as exc:
        sap.validate_config_schema(config)

    message = str(exc.value)
    assert "socket" in message
    assert "top level" in message


@pytest.mark.parametrize(
    ("table", "key"),
    [
        ("security", "ssh_signing_key"),
        ("security", "server_signing_key"),
        ("acl", "trusted_keys"),
        ("mtls", "client_required_oid"),
    ],
)
def test_schema_rejects_removed_keys(
    sap: types.ModuleType, table: str, key: str
) -> None:
    """Removed mechanisms leave no live keys; a stale one is never ignored."""
    config = {"mode": "server", "transport": "vsock", table: {key: "x"}}

    with pytest.raises(sap.SecurityConfigError, match=key):
        sap.validate_config_schema(config)


def test_schema_rejects_a_non_table_sub_table(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match=r"\[security\] must be a table"):
        sap.validate_config_schema({"mode": "server", "security": "none"})


def test_schema_allows_the_acl_labels_map(sap: types.ModuleType) -> None:
    """`acl.labels` is the one free-form table: fingerprints -> display labels."""
    fingerprint = "SHA256:" + base64.b64encode(b"x" * 32).decode()
    config = {
        "mode": "server",
        "transport": "tcp",
        "security": _mtls_server_security(),
        "acl": {
            "mode": "list",
            "trusted_fingerprints": [fingerprint],
            "labels": {fingerprint: "vault"},
        },
    }

    sap.validate_config_schema(config)
    # labels are keyed by the *normalised* fingerprint (base64 padding stripped),
    # which is what `spki_fingerprint` produces when it verifies a credential.
    assert sap.build_security(config, "server").acl.labels == {
        fingerprint.rstrip("="): "vault"
    }


def test_schema_accepts_a_full_server_and_client_config(
    sap: types.ModuleType,
) -> None:
    """Every key the Nix modules emit is in the schema (they must not drift)."""
    server = {
        "mode": "server",
        "transport": "vsock",
        "cid": 2,
        "port": 65012,
        "socket": "%t/sudo-auth-proxy/server.sock",
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "connect_timeout": 0.2,
        "decision_timeout": 120,
        "recv_timeout": 0.5,
        "max_connections": 64,
        "server_read_timeout": 10.0,
        "dialog_program": "zenity",
        "resolution": "tartarus",
        "debug": False,
        "security": _server_security(),
        "acl": _acl_for(sap),
        "mtls": {
            "enable": True,
            "ca_file": "/etc/tartarus/x509/ca.crt",
            "cert_file": "/etc/tartarus/x509/server.crt",
            "key_file": "/etc/tartarus/x509/server.key",
            "required_oid": "1.3.6.1.4.1.99999.1.1",
            "peer_required_oid": "1.3.6.1.4.1.99999.1.2",
        },
    }
    client = {
        "mode": "client",
        "transport": "vsock",
        "cid": 2,
        "port": 65012,
        "socket": "%t/sudo-auth-proxy/server.sock",
        "socket_dir_mode": "0700",
        "socket_mode": "0600",
        "connect_timeout": 0.2,
        "decision_timeout": 120,
        "recv_timeout": 0.5,
        "approver": "user",
        "client_version": "1",
        "guest_hint": "vault",
        "debug": False,
        "security": _client_security(),
    }

    sap.validate_config_schema(server)
    sap.validate_config_schema(client)


def test_shipped_example_config_matches_the_schema(sap: types.ModuleType) -> None:
    """The copy-me example in `examples/` must stay copy-pasteable.

    It is the file the standalone-server instructions tell an operator to install
    as `~/.config/sudo-auth-proxy/config.toml` (doc §15.1), so a key it drops or
    misspells would be a startup failure on a machine with no Nix to rebuild it.
    """
    with open(EXAMPLE_CONFIG_PATH, "rb") as handle:
        config = tomllib.load(handle)

    sap.validate_config_schema(config, source=str(EXAMPLE_CONFIG_PATH))
    security = sap.build_security(config, "server")

    # The example is the unauthenticated standalone pairing: it may only run if
    # it says so on all three knobs and pairs `client_auth = "none"` with
    # `acl.mode = "none"`.
    assert security.transport_encryption == "none"
    assert security.client_auth == "none"
    assert security.server_auth == "none"
    assert security.acl.mode == "none"


# --- config validation (fail closed, no downgrade) ------------------------


def test_security_none_requires_explicit_auth_knobs(sap: types.ModuleType) -> None:
    """Turning authentication off must be written down, not inherited.

    Before the mTLS-only refactor an unset knob defaulted to the working
    `ssh`/`signature` pair. There is no working pair to default to any more,
    and defaulting to "no authentication" would be a silent downgrade.
    """
    for transport in ("unix", "vsock"):
        with pytest.raises(
            sap.SecurityConfigError, match="refusing to disable authentication implicitly"
        ):
            sap.validate_security_config({"transport": transport})

    with pytest.raises(
        sap.SecurityConfigError, match="refusing to disable authentication implicitly"
    ):
        sap.validate_security_config(
            {
                "transport": "unix",
                "security": {"transport_encryption": "none", "client_auth": "none"},
            }
        )


def test_security_defaults_tcp_to_mtls(sap: types.ModuleType) -> None:
    assert sap.validate_security_config({"transport": "tcp"}) == {
        "transport_encryption": "mtls",
        "client_auth": "transport",
        "server_auth": "transport",
    }


def test_security_explicit_none_pair_is_accepted(sap: types.ModuleType) -> None:
    for transport in ("unix", "vsock"):
        assert sap.validate_security_config(
            {
                "transport": transport,
                "security": {
                    "transport_encryption": "none",
                    "client_auth": "none",
                    "server_auth": "none",
                },
            }
        ) == {
            "transport_encryption": "none",
            "client_auth": "none",
            "server_auth": "none",
        }


def test_security_mtls_forces_both_auths_to_transport(sap: types.ModuleType) -> None:
    resolved = sap.validate_security_config(
        {"transport": "tcp", "security": {"transport_encryption": "mtls"}}
    )

    assert resolved["client_auth"] == "transport"
    assert resolved["server_auth"] == "transport"


def test_security_mtls_rejects_a_non_transport_server_auth(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="server_auth must be"):
        sap.validate_security_config(
            {
                "transport": "tcp",
                "security": {
                    "transport_encryption": "mtls",
                    "client_auth": "transport",
                    "server_auth": "none",
                },
            }
        )


def test_security_mtls_rejects_a_non_transport_client_auth(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="client_auth must be"):
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


def test_security_rejects_the_removed_auth_methods(sap: types.ModuleType) -> None:
    """`ssh`/`x509`/`signature` are gone, not merely deprecated."""
    for method in ("ssh", "x509", "signature"):
        with pytest.raises(sap.SecurityConfigError, match="client_auth"):
            sap.validate_security_config(
                {"transport": "unix", "security": {"client_auth": method}}
            )
        with pytest.raises(sap.SecurityConfigError, match="server_auth"):
            sap.validate_security_config(
                {"transport": "unix", "security": {"server_auth": method}}
            )


def test_security_enum_values_are_the_mtls_pair(sap: types.ModuleType) -> None:
    assert sap.CLIENT_AUTH_METHODS == ("transport", "none")
    assert sap.SERVER_AUTH_METHODS == ("transport", "none")


def test_security_rejects_a_non_string_client_auth(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="client_auth must be a single string"):
        sap.validate_security_config(
            {"transport": "unix", "security": {"client_auth": ["transport", "none"]}}
        )
    with pytest.raises(sap.SecurityConfigError, match="server_auth must be a single string"):
        sap.validate_security_config(
            {"transport": "unix", "security": {"server_auth": ["transport"]}}
        )


def test_security_transport_auth_requires_mtls(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="requires transport_encryption"):
        sap.validate_security_config(
            {
                "transport": "unix",
                "security": {
                    "transport_encryption": "none",
                    "client_auth": "transport",
                    "server_auth": "none",
                },
            }
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
                "client_auth": "none",
                "server_auth": "none",
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
        {
            "transport": "unix",
            "security": {
                "transport_encryption": "none",
                "client_auth": "none",
                "server_auth": "none",
            },
        }
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


# --- response freshness, digest binding and replay -------------------------
#
# There is no response signature any more (mTLS is the only authentication
# mechanism), but the *binding* checks are what stop a decision from being
# re-pointed at another request or replayed, so they are still covered here.


def _response_pair(sap: types.ModuleType, security: Any = None):
    """A (client security, request, response) triple with no signature involved."""
    security = security or sap.build_security(
        {"transport": "vsock", "security": _client_security()}, "client"
    )
    request = _request_obj(sap)
    sap.attach_client_auth(request, security)
    response = sap.build_response(
        request["nonce"], "allow", request=request, security=security, approver="host-user"
    )
    return security, request, response


def test_response_carries_no_authentication_block(sap: types.ModuleType) -> None:
    """The removed `server_auth` signature must not reappear on the wire."""
    _, _, response = _response_pair(sap)

    assert "server_auth" not in response
    assert "signature" not in response


def test_response_round_trip(sap: types.ModuleType) -> None:
    client, request, response = _response_pair(sap)

    assert sap.verify_response(response, request, client, set()) == "allow"


def test_response_tampered_decision_rejected(sap: types.ModuleType) -> None:
    """The decision itself is what arrives; nothing re-authenticates it."""
    client, request, response = _response_pair(sap)
    response["decision"] = "maybe"

    with pytest.raises(sap.ProtocolError, match="invalid 'decision'"):
        sap.verify_response(response, request, client, set())


def test_response_tampered_digest_rejected(sap: types.ModuleType) -> None:
    client, request, response = _response_pair(sap)
    response["request_digest"] = "0" * 64

    with pytest.raises(sap.ProtocolError, match="request_digest"):
        sap.verify_response(response, request, client, set())


def test_response_digest_binds_every_request_field(sap: types.ModuleType) -> None:
    """A response for one request must not verify against a mutated one."""
    client, request, response = _response_pair(sap)
    mutated = dict(request, service="su")

    with pytest.raises(sap.ProtocolError, match="request_digest"):
        sap.verify_response(response, mutated, client, set())


def test_response_wrong_nonce_rejected(sap: types.ModuleType) -> None:
    client, request, response = _response_pair(sap)
    response["nonce"] = base64.b64encode(b"other" * 8).decode()

    with pytest.raises(sap.ProtocolError, match="nonce does not match"):
        sap.verify_response(response, request, client, set())


def test_response_expired_rejected(sap: types.ModuleType) -> None:
    client, request, response = _response_pair(sap)
    response["issued_at"] = 1
    response["expires_at"] = 2

    with pytest.raises(sap.ProtocolError, match="expired"):
        sap.verify_response(response, request, client, set())


def test_response_replay_rejected(sap: types.ModuleType) -> None:
    client, request, response = _response_pair(sap)
    consumed: set = set()

    assert sap.verify_response(response, request, client, consumed) == "allow"
    # A second response for the same nonce is refused (single-use nonce).
    with pytest.raises(sap.AuthError, match="already been consumed"):
        sap.verify_response(response, request, client, consumed)


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


def test_x509_intermediate_chain_accepted(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """`verify_x509_chain` still walks an explicit multi-cert chain to the root."""
    root, root_key = _make_ca()
    intermediate, intermediate_key = _issue_ca(root, root_key)
    leaf, _leaf_key = _issue_leaf(intermediate, intermediate_key, oid=REQUIRED_OID)

    assert (
        sap.verify_x509_chain([leaf, intermediate], [root], REQUIRED_OID).subject
        == leaf.subject
    )


def test_x509_intermediate_chain_requires_the_intermediate(
    sap: types.ModuleType, crypto: types.ModuleType
) -> None:
    """mTLS supplies the peer LEAF only, so a multi-tier CA cannot validate.

    `ssl` exposes just the peer certificate, which is why `acl.mode = "ca"` is
    documented as single-tier (audit A12). This pins that limitation: given the
    leaf alone, the verifier refuses to guess the intermediate.
    """
    root, root_key = _make_ca()
    intermediate, intermediate_key = _issue_ca(root, root_key)
    leaf, _leaf_key = _issue_leaf(intermediate, intermediate_key, oid=REQUIRED_OID)

    with pytest.raises(sap.AuthError, match="no trusted issuer"):
        sap.verify_x509_chain([leaf], [root], REQUIRED_OID)


def _crypto_pem():
    from cryptography.hazmat.primitives import serialization

    return serialization.Encoding.PEM


# --- certificate material (mTLS) ------------------------------------------
#
# The ACL and EKU tests need a real CA plus a leaf that chains to it, written
# to disk so the `[acl] ca_file` / `[mtls]` paths can be exercised as configured.


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
# --- Phase 4: authorization / trust roots (ACL) ----------------------------
#
# The `[acl]` decides who may use the mechanism. It is evaluated AFTER the
# cryptographic verification of `client_auth` and BEFORE any dialog, and it
# matches ONLY the verified credential: the mTLS leaf SPKI fingerprint, or a
# CA chain + EKU. Metadata (`target_user`, `rhost`, `tty`, `guest_hint`, ...)
# never influences the decision (doc §8; review logs S11/NF6).

# a syntactically valid fingerprint of a 32-byte SHA-256 digest that no test
# key produces, so it can never match a real credential.
_UNLISTED_FINGERPRINT = "SHA256:" + base64.b64encode(b"\x00" * 32).decode().rstrip("=")


def _server_with_acl(sap: types.ModuleType, _material: Any, acl: dict) -> Any:
    """Build a server `SecurityConfig` whose credential is the mTLS peer cert."""
    config = {"transport": "unix", "security": _mtls_server_security(), "acl": acl}
    return sap.build_security(config, "server")


def _transport_server(sap: types.ModuleType, acl: dict) -> Any:
    """A server whose requester credential is the mTLS transport certificate."""
    return _server_with_acl(sap, None, acl)


def _ca_path(material: Any) -> str:
    return str(material.tmp_path / "ca.crt")


def _leaf_der(material: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return material.leaf_cert.public_bytes(Encoding.DER)


def _mtls_request(sap: types.ModuleType, **overrides: Any) -> dict:
    """An mTLS request: the channel certificate is the credential."""
    request = _request_obj(sap, **overrides)
    request["client_auth"] = {"method": "transport"}
    return request


# -- ACL config validation ---------------------------------------------------


def test_acl_absent_is_deny_all_list(sap: types.ModuleType) -> None:
    acl = sap.load_acl_config({})

    assert acl.mode == "list"
    assert acl.trusted_fingerprints == frozenset()
    assert acl.ca_file is None
    assert acl.required_oid is None
    assert sap.acl_allows_any(acl) is False


@pytest.mark.parametrize("mode", ["open", "", None, ["list"], 1])
def test_acl_unknown_mode_rejected(sap: types.ModuleType, mode: Any) -> None:
    with pytest.raises(sap.SecurityConfigError, match="acl.mode"):
        sap.load_acl_config({"acl": {"mode": mode}})


def test_acl_ca_requires_ca_file(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="requires acl.ca_file"):
        sap.load_acl_config({"acl": {"mode": "ca", "required_oid": REQUIRED_OID}})


def test_acl_ca_requires_required_oid(
    sap: types.ModuleType, tmp_path: Path, crypto: types.ModuleType
) -> None:
    ca_cert, _ = _make_ca()
    ca_path = tmp_path / "ca.crt"
    _write_pem(ca_path, ca_cert)

    with pytest.raises(sap.SecurityConfigError, match="requires acl.required_oid"):
        sap.load_acl_config({"acl": {"mode": "ca", "ca_file": str(ca_path)}})


def test_acl_rejects_the_removed_trusted_keys(sap: types.ModuleType) -> None:
    """`[acl] trusted_keys` (SSH fingerprints) went with `client_auth = "ssh"`

It is no longer *ignored*, which is what used to make a stale key a silent
no-op: the schema refuses it, so the operator is told to migrate the entry to
`trusted_fingerprints` instead of left believing it still authorizes someone.
"""
    with pytest.raises(sap.SecurityConfigError, match="trusted_keys"):
        sap.build_security(
            {
                "transport": "unix",
                "security": _server_security(),
                "acl": {"mode": "list", "trusted_keys": ["SHA256:x"]},
            },
            "server",
        )

    # What the schema-clean spelling of that list means: an empty one denies.
    acl = sap.load_acl_config({"acl": {"mode": "list"}})
    assert acl.trusted_fingerprints == frozenset()
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(
            _mtls_request(sap), _server_with_acl(sap, None, _acl_list()), "SHA256:x"
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
    with pytest.raises(sap.SecurityConfigError, match="trusted_fingerprints"):
        sap.load_acl_config(
            {"acl": {"mode": "list", "trusted_fingerprints": [entry]}}
        )


def test_acl_normalizes_padded_fingerprint(sap: types.ModuleType) -> None:
    body = base64.b64encode(b"\x01" * 32).decode().rstrip("=")

    acl = sap.load_acl_config(
        {"acl": {"mode": "list", "trusted_fingerprints": [f"SHA256:{body}="]}}
    )

    assert acl.trusted_fingerprints == frozenset({f"SHA256:{body}"})


def test_acl_labels_must_be_string_map(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="labels"):
        sap.load_acl_config(
            {"acl": {"mode": "list", "labels": {_UNLISTED_FINGERPRINT: 3}}}
        )


# -- mode = "list" -----------------------------------------------------------


def test_acl_list_allows_listed_mtls_spki(
    sap: types.ModuleType, x509_material: Any
) -> None:
    spki = _spki(sap, x509_material.leaf_cert)
    server = _server_with_acl(sap, x509_material, _acl_list(spki))
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)

    assert verified == spki
    assert sap.authorize_request(request, server, verified, peer_cert_der=der) == spki


def test_acl_list_denies_unlisted_but_valid_certificate(
    sap: types.ModuleType, x509_material: Any
) -> None:
    # The certificate is genuine and chains to nothing in particular, but its
    # SPKI is not listed: authentication succeeds and authorization refuses.
    server = _server_with_acl(sap, x509_material, _acl_list(_UNLISTED_FINGERPRINT))
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, server, verified, peer_cert_der=der)


def test_acl_list_empty_denies_everyone(sap: types.ModuleType, x509_material: Any) -> None:
    server = _server_with_acl(sap, x509_material, _acl_list())
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, server, verified, peer_cert_der=der)


def test_acl_label_is_display_only(sap: types.ModuleType, x509_material: Any) -> None:
    spki = _spki(sap, x509_material.leaf_cert)
    acl = {
        "mode": "list",
        "trusted_fingerprints": [spki],
        "labels": {spki: "vault"},
    }
    server = _server_with_acl(sap, x509_material, acl)
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)

    assert sap.authorize_request(request, server, verified, peer_cert_der=der) == "vault"


def test_acl_decision_ignores_request_metadata(
    sap: types.ModuleType, x509_material: Any
) -> None:
    spki = _spki(sap, x509_material.leaf_cert)
    allow_server = _server_with_acl(sap, x509_material, _acl_list(spki))
    deny_server = _server_with_acl(sap, x509_material, _acl_list())
    metadata = {
        "target_user": "daemon",
        "invoking_user": "mallory",
        "rhost": "10.9.9.9",
        "tty": "/dev/pts/7",
        "guest_hint": "evil",
    }
    request = _mtls_request(sap, **metadata)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, allow_server, peer_cert_der=der)
    assert sap.authorize_request(request, allow_server, verified, peer_cert_der=der) == spki

    # the same metadata must not rescue an unlisted certificate either
    denied = sap.authenticate_request(request, deny_server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="not in the authorization list"):
        sap.authorize_request(request, deny_server, denied, peer_cert_der=der)


# -- ACL is enforced before the dialog ---------------------------------------


def test_handler_acl_denial_is_never_prompted(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, x509_material: Any
) -> None:
    """An authenticated-but-unauthorized mTLS request is denied without a dialog."""
    der = _leaf_der(x509_material)
    request = _mtls_request(sap)
    frames, prompts = _exchange(
        sap,
        monkeypatch,
        [],
        _frame(sap, request),
        acl=_acl_list(),
        security=_mtls_server_security(),
        peer_cert_der=der,
    )

    assert prompts == []
    # A denial is answered without a dialog, so there is no `auth_pending`; the
    # sole frame is the deny (audit A2).
    assert len(frames) == 1
    parsed = _decode(sap, frames[0])
    assert parsed["type"] == "auth_response"
    assert parsed["decision"] == "deny"
    assert parsed["nonce"] == request["nonce"]
    # the deny is a genuine, request-bound response
    client = sap.build_security(_mtls_client_config(), "client")
    assert sap.verify_response(parsed, request, client, set()) == "deny"


def test_handler_acl_allows_listed_mtls_certificate_and_prompts(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, x509_material: Any
) -> None:
    """The full mTLS flow: a verified, authorized request reaches the dialog."""
    der = _leaf_der(x509_material)
    spki = _spki(sap, x509_material.leaf_cert)
    request = _mtls_request(sap)
    frames, prompts = _exchange(
        sap,
        monkeypatch,
        [True],
        _frame(sap, request),
        acl=_acl_list(spki),
        security=_mtls_server_security(),
        peer_cert_der=der,
    )

    assert len(prompts) == 1
    confirmation, _program = prompts[0]
    # the dialog shows the *verified* SPKI (sanitised) as the requester
    assert confirmation.identity == sap.sanitize_field(spki)
    assert _decode(sap, frames[1])["decision"] == "allow"


def test_handler_wrong_mtls_certificate_never_prompts(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch, x509_material: Any
) -> None:
    """A genuine certificate whose SPKI is not pinned is denied, silently."""
    der = _leaf_der(x509_material)
    request = _mtls_request(sap)
    frames, prompts = _exchange(
        sap,
        monkeypatch,
        [],
        _frame(sap, request),
        acl=_acl_list(_UNLISTED_FINGERPRINT),
        security=_mtls_server_security(),
        peer_cert_der=der,
    )

    assert prompts == []
    assert len(frames) == 1
    assert _decode(sap, frames[0])["decision"] == "deny"


# -- mode = "ca" -------------------------------------------------------------


def test_acl_ca_allows_chained_cert(sap: types.ModuleType, x509_material: Any) -> None:
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": _ca_path(x509_material), "required_oid": REQUIRED_OID},
    )
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)

    assert sap.authorize_request(request, server, verified, peer_cert_der=der) == verified


def test_acl_ca_denies_wrong_ca(sap: types.ModuleType, x509_material: Any) -> None:
    other_ca, _ = _make_ca()
    other_path = x509_material.tmp_path / "other-ca.crt"
    _write_pem(other_path, other_ca)
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": str(other_path), "required_oid": REQUIRED_OID},
    )
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="no trusted issuer"):
        sap.authorize_request(request, server, verified, peer_cert_der=der)


def test_acl_ca_denies_missing_eku_at_acl_layer(
    sap: types.ModuleType, x509_material: Any
) -> None:
    # The transport layer enforces the peer OID from `[mtls].peer_required_oid`;
    # the ACL requires a *different* OID and refuses on its own.
    server = _server_with_acl(
        sap,
        x509_material,
        {"mode": "ca", "ca_file": _ca_path(x509_material), "required_oid": OTHER_OID},
    )
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="missing required EKU OID"):
        sap.authorize_request(request, server, verified, peer_cert_der=der)


def test_acl_ca_optional_spki_pin(sap: types.ModuleType, x509_material: Any) -> None:
    spki = _spki(sap, x509_material.leaf_cert)
    request = _mtls_request(sap)
    der = _leaf_der(x509_material)

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
    )
    verified = sap.authenticate_request(request, server_ok, peer_cert_der=der)
    assert sap.authorize_request(request, server_ok, verified, peer_cert_der=der) == verified

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
    )
    mismatched = sap.authenticate_request(request, server_bad, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="SPKI is not in the authorization list"):
        sap.authorize_request(request, server_bad, mismatched, peer_cert_der=der)


def test_acl_ca_denies_expired_cert(
    sap: types.ModuleType, crypto: types.ModuleType, tmp_path: Path
) -> None:
    import datetime

    from cryptography.hazmat.primitives.serialization import Encoding

    ca_cert, ca_key = _make_ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf, _leaf_key = _issue_leaf(
        ca_cert,
        ca_key,
        oid=REQUIRED_OID,
        not_before=now - datetime.timedelta(days=2),
        not_after=now - datetime.timedelta(days=1),
    )
    _write_pem(tmp_path / "ca.crt", ca_cert)
    der = leaf.public_bytes(Encoding.DER)
    server = _server_with_acl(
        sap,
        None,
        {"mode": "ca", "ca_file": str(tmp_path / "ca.crt"), "required_oid": REQUIRED_OID},
    )
    request = _mtls_request(sap)

    verified = sap.authenticate_request(request, server, peer_cert_der=der)
    with pytest.raises(sap.AuthError, match="outside its validity window"):
        sap.authorize_request(request, server, verified, peer_cert_der=der)


# -- mTLS transport credential pinning (NF6) ---------------------------------


def test_acl_list_pins_mtls_spki(sap: types.ModuleType, crypto: types.ModuleType) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = _build_cert(REQUIRED_OID)
    der = cert.public_bytes(Encoding.DER)
    spki = sap.spki_fingerprint(cert.public_key())
    request = _mtls_request(sap)
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
    request = _mtls_request(sap)
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
        config = _client_config()
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
        config = _client_config()
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
        "security": _client_security(),
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
                "security": _client_security(),
            },
            "tcp",
        )
        sock = transport.connect()
        assert sock is not None
        sock.close()
    finally:
        listener.close()


def test_denied_is_logged_distinctly_from_unavailable(
    sap: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
        config = _client_config()
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
    with _unix_server(sap, deny_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(deny_path))
        with pytest.raises(SystemExit) as exc:
            sap.run_client(_client_config())
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

    with _unix_server(sap, sock_path):
        monkeypatch.setenv("SUDO_AUTH_PROXY_SOCK", str(sock_path))
        config = _client_config()
        config.update(recv_timeout=0.5, decision_timeout=120)
        start = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            sap.run_client(config)
        elapsed = time.monotonic() - start

    assert exc.value.code == 0
    assert elapsed >= 1.0  # the client really waited for the slow human


def test_pending_frame_must_match_the_request_nonce(
    sap: types.ModuleType
) -> None:
    """An ack for another nonce (or a bad/missing type) is rejected (A2)."""
    request = _authed_request(sap)
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
    sap: types.ModuleType, tmp_path: Path
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
        "security": _server_security(),
        "acl": _acl_for(sap),
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
    sap: types.ModuleType, tmp_path: Path
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
        "security": _server_security(),
        "acl": _acl_for(sap),
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
        "acl": {"mode": "list", "trusted_fingerprints": []},
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
    sap: types.ModuleType
) -> None:
    request = _authed_request(sap)
    # a non-ASCII method can never equal the configured ASCII one; the
    # comparison must fail closed instead of raising a TypeError (review A9).
    request["client_auth"]["method"] = "caf\u00e9"
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(), "acl": _acl_for(sap)},
        "server",
    )

    with pytest.raises(sap.AuthError, match="does not match the configured"):
        sap.authenticate_request(request, server)


def test_non_ascii_response_nonce_raises_protocol_error(
    sap: types.ModuleType
) -> None:
    request = _authed_request(sap)
    server = sap.build_security(
        {"transport": "unix", "security": _server_security(), "acl": _acl_for(sap)},
        "server",
    )
    response = sap.build_response(
        request["nonce"], "allow", request=request, security=server
    )
    response["nonce"] = "caf\u00e9"
    client = sap.build_security(_client_config(), "client")

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
        return types.SimpleNamespace(returncode=0, stdout=b"")

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
                "server_auth": "none",
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
    with pytest.raises(sap.SecurityConfigError, match="client_auth must be"):
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

    server = sap.build_security(_none_server_config(), "server")
    verified = sap.authenticate_request(request, server)

    assert verified == sap.NONE_IDENTITY == "none"
    assert sap.authorize_request(request, server, verified) == "none"
    # an unauthenticated ACL always "allows" (it is the explicit opt-in)
    assert sap.acl_allows_any(server.acl) is True


def test_build_security_none_requires_none_acl(sap: types.ModuleType) -> None:
    config = _none_server_config()
    config["acl"] = {"mode": "list", "trusted_fingerprints": [_UNLISTED_FINGERPRINT]}

    with pytest.raises(sap.SecurityConfigError, match="requires acl.mode = 'none'"):
        sap.build_security(config, "server")


def test_build_security_none_acl_requires_none_client_auth(
    sap: types.ModuleType
) -> None:
    # The mirror image: an unauthenticated ACL may not be paired with a
    # credential the server would otherwise authenticate.
    config = {
        "transport": "unix",
        "security": _mtls_server_security(),
        "acl": {"mode": "none"},
    }

    with pytest.raises(sap.SecurityConfigError, match="requires client_auth = 'none'"):
        sap.build_security(config, "server")


def test_load_acl_none_rejects_trust_material(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="must not set trusted_fingerprints"):
        sap.load_acl_config(
            {"acl": {"mode": "none", "trusted_fingerprints": [_UNLISTED_FINGERPRINT]}}
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
    server.client_auth = "transport"

    with pytest.raises(sap.AuthError, match="requires client_auth = 'none'"):
        sap.authorize_request(_request_obj(sap), server, sap.NONE_IDENTITY)


# --- resolution: mode selection and the mofos resolver ----------------------


def test_get_resolution_mode_defaults_follow_mtls(sap: types.ModuleType) -> None:
    assert sap.get_resolution_mode({}) == "tartarus"
    assert sap.get_resolution_mode({"mtls": {"enable": True}}) == "certificate"


@pytest.mark.parametrize("mode", ["none", "certificate", "tartarus", "mofos"])
def test_get_resolution_mode_accepts_known_modes(
    sap: types.ModuleType, mode: str
) -> None:
    assert sap.get_resolution_mode({"resolution": mode}) == mode


def test_get_resolution_mode_ignores_unknown(sap: types.ModuleType) -> None:
    """An unknown value falls back to the mTLS-aware default, never passes through."""
    assert sap.get_resolution_mode({"resolution": "bogus"}) == "tartarus"


def _mofos_payload() -> str:
    return json.dumps(
        [
            {
                "id": 4,
                "name": "template-nixos",
                "cid": 4,
                "ipv4_address": "192.168.90.147",
            },
            {"id": 5, "name": "stream", "cid": 5, "ipv4_address": "192.168.90.148"},
        ]
    )


def _mofos_ok(*_args: Any, **_kwargs: Any) -> Any:
    return types.SimpleNamespace(returncode=0, stdout=_mofos_payload(), stderr="")


def test_resolve_mofos_name_by_cid(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "_mofos_cache", None)
    recorded: dict = {}

    def fake_run(argv: Any, **_kwargs: Any) -> Any:
        recorded["argv"] = argv
        return _mofos_ok()

    monkeypatch.setattr(sap.subprocess, "run", fake_run)
    assert sap.resolve_mofos_name(5) == "stream"
    assert recorded["argv"] == ["mofos", "ls", "--json"]


def test_resolve_mofos_name_by_ip(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "_mofos_cache", None)
    monkeypatch.setattr(sap.subprocess, "run", _mofos_ok)
    assert sap.resolve_mofos_name("192.168.90.147") == "template-nixos"


def test_resolve_mofos_name_unknown_returns_none(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "_mofos_cache", None)
    monkeypatch.setattr(sap.subprocess, "run", _mofos_ok)
    assert sap.resolve_mofos_name(99) is None
    assert sap.resolve_mofos_name("10.0.0.1") is None


def test_resolve_mofos_name_missing_binary_is_cosmetic(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "_mofos_cache", None)

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError("mofos")

    monkeypatch.setattr(sap.subprocess, "run", boom)
    assert sap.resolve_mofos_name(4) is None


def test_resolve_mofos_name_caches_the_listing(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sap, "_mofos_cache", None)
    calls = {"n": 0}

    def counting(*_args: Any, **_kwargs: Any) -> Any:
        calls["n"] += 1
        return _mofos_ok()

    monkeypatch.setattr(sap.subprocess, "run", counting)
    assert sap.resolve_mofos_name(4) == "template-nixos"
    assert sap.resolve_mofos_name(5) == "stream"
    assert calls["n"] == 1


def test_get_peer_name_uses_mofos_for_the_peer(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Sock:
        def getpeername(self) -> tuple[int, int]:
            return (5, 0)

    transport = sap.CallbackTransport({"transport": "tcp"}, "tcp")
    monkeypatch.setattr(sap, "_mofos_cache", None)
    monkeypatch.setattr(sap.subprocess, "run", _mofos_ok)
    assert sap.get_peer_name(_Sock(), "mofos", transport) == "stream"


# --- acl rule engine --------------------------------------------------------


def test_parse_rules_reads_selectors_and_preserves_order(
    sap: types.ModuleType,
) -> None:
    acl = sap.load_acl_config(
        {
            "acl": {
                "mode": "none",
                "rule": [
                    {"identity": "gram", "target_user": "root", "policy": "allow"},
                    {"identity": "*", "policy": "deny"},
                ],
            }
        }
    )

    assert [rule.policy for rule in acl.rules] == ["allow", "deny"]
    assert acl.rules[0].identity == "gram"
    assert acl.rules[0].target_user == "root"
    assert acl.rules[0].service == "*"


def test_parse_rules_defaults_to_ask_and_star(sap: types.ModuleType) -> None:
    acl = sap.load_acl_config({"acl": {"mode": "list", "rule": [{}]}})

    assert acl.rules[0].policy == "ask"
    assert acl.rules[0].identity == "*"


@pytest.mark.parametrize(
    "entry", [{"policy": "maybe"}, {"identity": 3}, "nope"]
)
def test_parse_rules_rejects_bad_entries(
    sap: types.ModuleType, entry: Any
) -> None:
    with pytest.raises(sap.SecurityConfigError):
        sap.load_acl_config({"acl": {"mode": "list", "rule": [entry]}})


def test_parse_rules_rejects_an_unknown_key(sap: types.ModuleType) -> None:
    with pytest.raises(sap.SecurityConfigError, match="unknown key"):
        sap.load_acl_config(
            {"acl": {"mode": "list", "rule": [{"ident": "x"}]}}
        )


def test_evaluate_rules_first_match_wins(sap: types.ModuleType) -> None:
    acl = sap.load_acl_config(
        {
            "acl": {
                "mode": "list",
                "rule": [
                    {"identity": "gram", "policy": "deny"},
                    {"identity": "gram", "policy": "allow"},
                ],
            }
        }
    )

    policy = sap.evaluate_rules(
        acl.rules,
        identities=("gram",),
        target_user="root",
        invoking_user="user",
        service="sudo",
    )
    assert policy == "deny"


def test_evaluate_rules_matches_any_identity_candidate(
    sap: types.ModuleType,
) -> None:
    acl = sap.load_acl_config(
        {"acl": {"mode": "list", "rule": [{"identity": "template-*", "policy": "allow"}]}}
    )
    identities = sap.identity_candidates(
        requester="SHA256:abc", label="", peer="template-nixos"
    )

    assert sap.evaluate_rules(
        acl.rules,
        identities=identities,
        target_user="root",
        invoking_user="user",
        service="sudo",
    ) == "allow"


def test_evaluate_rules_matches_target_and_service(sap: types.ModuleType) -> None:
    acl = sap.load_acl_config(
        {
            "acl": {
                "mode": "list",
                "rule": [{"identity": "*", "service": "su", "policy": "deny"}],
            }
        }
    )

    assert sap.evaluate_rules(
        acl.rules,
        identities=("vault",),
        target_user="root",
        invoking_user="user",
        service="su",
    ) == "deny"
    assert sap.evaluate_rules(
        acl.rules,
        identities=("vault",),
        target_user="root",
        invoking_user="user",
        service="sudo",
    ) == "ask"


def test_evaluate_rules_defaults_to_ask(sap: types.ModuleType) -> None:
    assert sap.evaluate_rules(
        (), identities=(), target_user="root", invoking_user="user", service="sudo"
    ) == "ask"


def test_identity_candidates_include_label_peer_and_credential(
    sap: types.ModuleType,
) -> None:
    assert sap.identity_candidates(
        requester="SHA256:abc", label="alice", peer="template"
    ) == ("alice", "template", "SHA256:abc")


def test_handler_rule_allow_answers_without_a_dialog(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _authed_request(sap)
    acl = {"mode": "none", "rule": [{"identity": "*", "policy": "allow"}]}

    frames, prompts = _exchange(sap, monkeypatch, [], _frame(sap, request), acl=acl)

    assert prompts == []
    assert len(frames) == 1
    parsed = _decode(sap, frames[0])
    assert parsed["type"] == "auth_response"
    assert parsed["decision"] == "allow"


def test_handler_rule_deny_answers_without_a_dialog(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _authed_request(sap)
    acl = {"mode": "none", "rule": [{"identity": "*", "policy": "deny"}]}

    frames, prompts = _exchange(sap, monkeypatch, [], _frame(sap, request), acl=acl)

    assert prompts == []
    assert _decode(sap, frames[0])["decision"] == "deny"


def test_handler_rule_ask_still_prompts(
    sap: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _authed_request(sap)
    acl = {"mode": "none", "rule": [{"identity": "someone-else", "policy": "allow"}]}

    frames, prompts = _exchange(
        sap, monkeypatch, [True], _frame(sap, request), acl=acl
    )

    assert len(prompts) == 1
    assert _decode(sap, frames[-1])["decision"] == "allow"


# --- sudo target display ----------------------------------------------------


def test_effective_target_user_defaults_sudo_to_root(sap: types.ModuleType) -> None:
    assert sap.effective_target_user("sudo", "user", "user") == "root"
    assert sap.effective_target_user("sudo", "", "user") == "root"


def test_effective_target_user_keeps_explicit_targets(
    sap: types.ModuleType,
) -> None:
    assert sap.effective_target_user("sudo", "www-data", "user") == "www-data"
    assert sap.effective_target_user("su", "root", "user") == "root"


def test_build_confirmation_shows_root_for_sudo(sap: types.ModuleType) -> None:
    request = _request_obj(sap, target_user="user", invoking_user="user")
    confirmation = sap.build_confirmation(
        peer="vault", identity="none", label="", request=request, transport="vsock"
    )

    assert confirmation.target_user == "root"
    assert "user -> root" in sap.confirmation_message(confirmation)

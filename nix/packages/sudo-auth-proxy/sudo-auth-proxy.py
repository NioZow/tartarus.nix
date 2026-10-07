#!/usr/bin/env python3

import argparse
import base64
import binascii
import contextlib
import datetime
import difflib
import hashlib
import hmac
import io
import json
import os
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
import types
import unicodedata
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from socketserver import (
    BaseServer,
    StreamRequestHandler,
    TCPServer,
    ThreadingMixIn,
    UnixStreamServer,
)
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    import cryptography.x509 as x509

DEFAULT_CONFIG_PATH = "/etc/sudo-auth-proxy/config.toml"

# The server binds exactly ONE socket per transport (redesign Phase 1, review
# logs S1/S2). For `unix` that is a single AF_UNIX path; `%t` is expanded to a
# per-user runtime directory by `expand_socket_path`. There is deliberately no
# per-guest server socket and no reuse-proxy socket (`DEFAULT_PROXY_SOCKET` and
# `mode = "proxy"` are gone).
DEFAULT_SOCKET = "%t/sudo-auth-proxy/server.sock"
DEFAULT_SOCKET_MODE = 0o600
DEFAULT_SOCKET_DIR_MODE = 0o700

# Fast-fail: the PAM hook runs on *every* `sudo`, so an unreachable peer must
# not stall the stack (doc §10.2). With the pre-dialog acknowledgement frame
# (`auth_pending`, review A2) the first frame arrives promptly after the server
# authenticates and authorizes the request, so `recv_timeout` keeps its short
# stale-socket fast-fail role while the human wait is bounded by
# `decision_timeout` (`0` = wait indefinitely). `resolve_read_timeouts`
# resolves the receive pair; `Transport.connect` applies the connect bound.
DEFAULT_CONNECT_TIMEOUT = 0.2
DEFAULT_DECISION_TIMEOUT = 120
DEFAULT_RECV_TIMEOUT = 0.5

# Server-side resource bounds (doc §9.1; audit A3). An accepted connection may
# not hold a handler thread forever before it has authenticated: the socket gets
# `server_read_timeout` for the pre-auth request read (and for the TLS
# handshake), and at most `max_connections` handler threads run at once. Both
# are operator-tunable; the defaults are generous enough for a desktop host but
# refuse an unbounded pre-auth connection flood.
DEFAULT_SERVER_READ_TIMEOUT = 10.0
DEFAULT_MAX_CONNECTIONS = 64


def resolve_read_timeouts(config: dict) -> tuple[float, float | None]:
    """Return (first_frame_timeout, tail_timeout) for the client's frame reads.

    `recv_timeout` (default 0.5s, `first_frame_timeout`) bounds the wait for the
    **first frame** of the exchange. With the pre-dialog acknowledgement
    (`auth_pending`, review A2) that frame is written immediately after the
    server authenticates and authorizes the request, so a short bound still
    gives fast-fail for a stale/silent peer (review log NF4) *and* does not
    bound the human wait. It also bounds a direct denial, which the server
    answers without a dialog. `tail_timeout` (`decision_timeout`, `0` = wait
    indefinitely -> `None`) bounds the final `auth_response`, which is where the
    human's decision arrives. See `read_decision` for how the two are used.

    The conversions are defensive: a malformed value in a hand-written config
    must not crash the hook, so a bad `recv_timeout`/`decision_timeout` falls
    back to its default rather than raising. The generated TOML already emits
    a float and an int, so this only guards against operator error.
    """
    try:
        recv_first_frame = float(config.get("recv_timeout", DEFAULT_RECV_TIMEOUT))
    except (TypeError, ValueError):
        recv_first_frame = float(DEFAULT_RECV_TIMEOUT)
    try:
        decision = int(config.get("decision_timeout", DEFAULT_DECISION_TIMEOUT))
    except (TypeError, ValueError):
        decision = int(DEFAULT_DECISION_TIMEOUT)
    # `decision_timeout == 0` means "wait indefinitely" (doc §10.2).
    tail = None if decision == 0 else float(decision)
    return recv_first_frame, tail

# Newline-delimited compact JSON (NDJSON) protocol (doc §6.1). One object per
# `\n`-terminated UTF-8 line; the size cap is enforced *before* parsing so a
# hostile peer cannot make us buffer an unbounded line. There is no legacy
# line protocol and no auto-detection (review logs S6/S7).
PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
CLIENT_VERSION = "1"

# The pre-dialog acknowledgement frame (doc §6.2a; audit A2). After a request is
# authenticated AND authorized, the server sends this before it blocks on the
# human, so the client can read the *first* frame under the short
# `recv_timeout` (preserving stale-socket fast-fail, NF4) and read the final
# `auth_response` under `decision_timeout` (the human window). It is a v1 frame
# type alongside `auth_request`/`auth_response`; an unknown type is still
# rejected. The frame is intentionally unauthenticated: it never carries a
# decision, so it is not a trust boundary. Its only jobs are (1) to prove the
# request reached a live server and (2) to echo the nonce so a frame from
# another exchange cannot be mistaken for this request's ack.
PENDING_TYPE = "auth_pending"

# The three explicit security knobs (doc §7.2-§7.5; review log S13). Exactly one
# value each; `transport_encryption = "mtls"` forces both auths to "transport"
# and nothing is layered on top. `"none"` disables requester authentication
# entirely and is only meaningful paired with `acl.mode = "none"` (see
# `build_security`/`validate_security_config`): it exists so a fully
# unauthenticated deployment is an explicit, warned, conscious choice instead of
# an accident.
#
# mTLS is the ONLY authentication/signature mechanism (doc §7). The former
# `client_auth = "ssh"` (SSH-key or ssh-agent signatures) and
# `client_auth = "x509"` (application-layer certificate signatures) and the
# `server_auth = "signature"` (host-signed responses) paths were removed
# entirely, together with their keyrings, signature algorithms, domain
# separation label and wire fields. `"transport"` means "identity comes from the
# mTLS handshake"; `"none"` means "no authentication, explicitly chosen".
TRANSPORT_ENCRYPTIONS = ("none", "mtls")
CLIENT_AUTH_METHODS = ("transport", "none")
SERVER_AUTH_METHODS = ("transport", "none")

# Authorization (`[acl]`) modes (doc §8.1; redesign Phase 4). Exactly one mode:
# `"list"` pins credential fingerprints (mTLS leaf SPKI); `"ca"` accepts any
# credential that chains to a configured CA and carries the service EKU. There
# is deliberately no `ca`+`list` combination and no wildcard: an empty trust
# list denies all (doc §8.3). `"none"` authorizes every request because there is
# no credential to authorize; it is rejected unless `client_auth = "none"` (XOR).
ACL_MODES = ("list", "ca", "none")

# The `[acl]` rule engine (`[[acl.rule]]`). Rules refine the *approval* decision
# once the ACL has already authorized the credential: each rule matches the
# requester's identity (the resolved friendly name, the ACL label, the verified
# fingerprint or `none`), the target/invoking user and the PAM service with
# glob patterns, and names the policy to apply. They are evaluated in file order
# and the first match wins, exactly like `ssh-agent-proxy`'s rule list -- there
# is no merging between rules. The policies are:
#   `ask`   show the confirmation dialog (the default when no rule matches);
#   `allow` reply allow without a dialog;
#   `deny`  reply deny without a dialog.
# `"*"` (or an absent selector) matches anything. Rules inspect only data the
# server already trusts for display (`target_user`/`invoking_user`/`service` are
# self-reported and never authorization inputs), so they can never *grant* a
# credential the ACL rejected -- the ACL runs first and is the gate.
RULE_POLICIES = ("allow", "ask", "deny")
CONFIG_RULE_KEYS = frozenset(
    {
        "identity",
        "target_user",
        "invoking_user",
        "service",
        "policy",
    }
)

# The fixed identity returned by `authenticate_request` when requester
# authentication is deliberately disabled (`client_auth = "none"`). It is a
# non-credential sentinel: it names "no authenticated requester" and can never
# collide with a real `SHA256:` fingerprint or an X.509/mTLS SPKI.
NONE_IDENTITY = "none"

# Response freshness (doc §6.6). A response is valid from `issued_at` to
# `expires_at`, with a small clock-skew allowance in both directions. The
# binding is `nonce + request_digest`; a correct decision is valid regardless of
# clock as long as the client accepts it exactly once.
DEFAULT_RESPONSE_TTL = 30
DEFAULT_CLOCK_SKEW = 5


# Recursion guard for nested privilege elevation (doc §10.4). Set for the
# duration of a client run and checked on entry, so `sudo` inside `sudo` (or
# `su` inside `sudo`) does not loop or double-prompt. It is preserved across
# `sudo` only by the guest's mandated
# `Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"` sudoers entry (doc §4.3;
# review log B2).
RECURSION_GUARD_ENV = "SUDO_AUTH_PROXY_ACTIVE"

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


class ProtocolError(Exception):
    """A frame or field violated the NDJSON protocol; callers must fail closed.

    The framing contract is strict: an unknown `v`/`type`, a missing required
    field, a malformed frame or trailing data is rejected rather than guessed
    at, so a peer can never talk this process into parsing something it did not
    intend to accept.
    """


class ConnectionClosed(Exception):
    """The peer closed the connection cleanly before sending a frame (EOF)."""


class AuthError(Exception):
    """An authentication or authorization check failed; callers must fail closed.

    Raised for a missing/malformed `client_auth` block, a method the server is
    not configured for, `client_auth = "transport"` without mTLS, an ACL that
    rejects the verified credential, or an unverifiable certificate chain. There
    is deliberately no "skip verification" path: a caller that catches this
    rejects the message rather than trusting it.
    """


class SecurityConfigError(Exception):
    """The `[security]` configuration is invalid or internally inconsistent.

    Raised (and, at the top level, turned into a non-zero exit) rather than
    silently downgrading: a transport configured for mTLS never falls back to
    plaintext, and the auth methods under mTLS are fixed to `"transport"`.
    """



# --- canonicalisation and domain separation (doc §6.4) --------------------


def canonical_bytes(obj: dict) -> bytes:
    """Return the canonical JSON encoding of `obj` (doc §6.4).

    Canonical means: compact separators (no insignificant whitespace), keys
    sorted at every level, UTF-8, and non-ASCII preserved (`ensure_ascii=False`)
    so the byte stream is stable and unambiguous across peers.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_request_digest(request: dict) -> str:
    """SHA-256 (hex) over the canonical request.

    The digest binds the whole request — including the `client_auth` method —
    into the response, so a server cannot answer a different request than the
    one it authenticated. Requests carry no signature any more (authentication
    is the mTLS channel, doc §7), so the digest is computed over the request as
    it arrived.
    """
    return hashlib.sha256(canonical_bytes(request)).hexdigest()


def secure_equals(left: object, right: object) -> bool:
    """Constant-time equality for two protocol strings, tolerant of non-ASCII.

    `hmac.compare_digest` raises `TypeError` when either argument is a non-ASCII
    ``str``. A hostile peer can therefore turn a malformed `key_id`/`nonce` into
    an unhandled traceback instead of a clean `AuthError`/`ProtocolError`
    (review A9). Compare the UTF-8 encodings instead: the comparison stays
    constant-time for the ASCII values the protocol actually uses, and any
    non-ASCII byte simply cannot equal an expected ASCII fingerprint/nonce, so
    the caller fails closed via its normal mismatch path. Non-string values are
    never equal.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# --- framing helpers (NDJSON, doc §6.1) ------------------------------------


def build_request(
    nonce: str,
    *,
    service: str,
    target_user: str,
    invoking_user: str,
    rhost: str,
    tty: str,
    cwd: str,
    client_version: str,
    guest_hint: str = "",
) -> dict:
    """Build a versioned `auth_request` object.

    The session metadata is built here; `attach_client_auth` adds the
    `client_auth` marker block to this same dict before it is sent (the
    canonicalisation/digest helpers live next to `read_message`/`write_message`,
    which is why the object shape is built in one place).
    """
    return {
        "v": PROTOCOL_VERSION,
        "type": "auth_request",
        "nonce": nonce,
        "service": service,
        "target_user": target_user,
        "invoking_user": invoking_user,
        "rhost": rhost,
        "tty": tty,
        "cwd": cwd,
        "client_version": client_version,
        "guest_hint": guest_hint,
    }


def build_response(
    nonce: str,
    decision: str,
    *,
    request: dict | None = None,
    security: "SecurityConfig | None" = None,
    approver: str = "",
) -> dict:
    """Build a versioned `auth_response`.

    With no `request`/`security` this returns the minimal Phase-1 response used
    by the framing tests. In production the handler passes both: the response
    then carries `request_digest` (binding it to the authenticated request), an
    `issued_at`/`expires_at` freshness window and the informational `approver`.
    There is no `server_auth` block: the response is authenticated by the mTLS
    channel, or explicitly not at all (`server_auth = "none"`), and the removed
    `"signature"` method is gone (doc §7.2).
    """
    response: dict = {
        "v": PROTOCOL_VERSION,
        "type": "auth_response",
        "nonce": nonce,
        "decision": decision,
    }
    if request is not None:
        response["request_digest"] = compute_request_digest(request)
    if security is not None:
        issued_at = int(time.time())
        response["issued_at"] = issued_at
        response["expires_at"] = issued_at + security.response_ttl
        if approver:
            response["approver"] = approver
    return response


def build_pending(nonce: str) -> dict:
    """Build the pre-dialog acknowledgement frame (doc §6.2a; audit A2).

    Sent only after the requester credential has been verified and the `[acl]`
    authorized it, immediately before the dialog is raised. It echoes the
    request nonce and carries no decision, so it is not authenticated (see
    `PENDING_TYPE`): the client's trust in the eventual `allow` rests entirely on
    the mTLS channel.
    """
    return {
        "v": PROTOCOL_VERSION,
        "type": PENDING_TYPE,
        "nonce": nonce,
    }


def write_message(fileobj, msg: dict) -> None:
    """Serialise `msg` as one compact, `\\n`-terminated UTF-8 line.

    Compact separators and `ensure_ascii=False` keep the wire form canonical
    and small; the size cap is checked so we never emit a frame the peer must
    reject.
    """
    encoded = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"frame exceeds the {MAX_MESSAGE_BYTES}-byte limit")
    fileobj.write(encoded + b"\n")
    fileobj.flush()


def read_message(fileobj) -> dict:
    """Read exactly one NDJSON frame and return the parsed JSON object.

    Raises `ConnectionClosed` on EOF and `ProtocolError` on anything that is
    not a single well-formed object: an over-long line (the cap is applied to
    the raw bytes before decoding), invalid UTF-8, invalid JSON (which already
    covers trailing data), or a non-object. Unknown top-level keys are *not*
    rejected here -- they are ignored for forward compatibility; the typed
    validators below reject unknown/missing `v`/`type` and missing fields.
    """
    line = fileobj.readline(MAX_MESSAGE_BYTES + 1)
    if not line:
        raise ConnectionClosed()
    if not line.endswith(b"\n"):
        # readline() hit its cap without finding a newline: the frame is longer
        # than we are willing to parse. Reject and let the caller close.
        raise ProtocolError(f"frame exceeds the {MAX_MESSAGE_BYTES}-byte limit")
    payload = line[:-1]
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("frame is not valid UTF-8") from error
    try:
        message = json.loads(text)
    except json.JSONDecodeError as error:
        # json.loads rejects trailing data after the object, so this also
        # catches `{...}garbage`.
        raise ProtocolError(f"frame is not valid JSON: {error.msg}") from error
    if not isinstance(message, dict):
        raise ProtocolError("frame is not a JSON object")
    return message


def read_frame(fileobj, sock, timeout: float | None) -> dict:
    """Read one NDJSON frame from a buffered socket reader under `timeout`.

    `fileobj` **must** be the buffered reader over `sock` (``sock.makefile("rb")``
    or ``StreamRequestHandler.rfile``). One client exchange now carries two
    frames -- the immediate ``auth_pending`` acknowledgement and the final
    ``auth_response`` (doc §6.2a; audit A2) -- and, when the server answers
    quickly, both can arrive in one TCP segment. A raw ``recv`` would consume
    the second frame's bytes and discard them; a buffered reader stops at the
    first newline and keeps the remainder for the next `read_frame`. This is why
    the client wraps its socket in a reader before the exchange.

    `timeout` is applied to the raw socket for the duration of the read:
    `recv_timeout` bounds the first frame (stale-socket fast-fail, NF4) and
    `decision_timeout` (the human window; `None` = wait) bounds the final one. A
    `socket.timeout`/`OSError` is intentionally left to propagate so the caller
    logs it as `unavailable`.
    """
    sock.settimeout(timeout)
    return read_message(fileobj)


def validate_envelope(message: dict, expected_type: str) -> None:
    """Check `v` and `type` strictly.

    `type(...) is not int` (rather than `isinstance`) also rejects JSON
    booleans, which Python would otherwise treat as integers 0/1.
    """
    if type(message.get("v")) is not int:
        raise ProtocolError("missing or non-integer 'v'")
    if message["v"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version {message['v']!r}")
    if message.get("type") != expected_type:
        raise ProtocolError(f"expected type {expected_type!r}, got {message.get('type')!r}")


def _validate_nonce(nonce: object) -> None:
    """Require a base64 string decoding to at least 16 random bytes (doc §6.2)."""
    if not isinstance(nonce, str) or not nonce:
        raise ProtocolError("missing or invalid 'nonce'")
    try:
        raw = base64.b64decode(nonce, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtocolError("'nonce' is not valid base64") from error
    if len(raw) < 16:
        raise ProtocolError("'nonce' must decode to at least 16 bytes")


# `guest_hint` is optional (doc §6.2 marks it self-reported/display-only); the
# remaining fields are required for a well-formed request.
REQUEST_REQUIRED_FIELDS = (
    "nonce",
    "service",
    "target_user",
    "invoking_user",
    "rhost",
    "tty",
    "cwd",
    "client_version",
)


def parse_request(message: dict) -> dict:
    """Validate and return an `auth_request` object (raises `ProtocolError`)."""
    validate_envelope(message, "auth_request")
    for name in REQUEST_REQUIRED_FIELDS:
        if name not in message:
            raise ProtocolError(f"missing required field {name!r}")
        if not isinstance(message[name], str):
            raise ProtocolError(f"field {name!r} must be a string")
    _validate_nonce(message["nonce"])
    if "guest_hint" in message and not isinstance(message["guest_hint"], str):
        raise ProtocolError("field 'guest_hint' must be a string")
    return message


def parse_response(message: dict, expected_nonce: str) -> str:
    """Validate an `auth_response` against the request nonce; return the decision.

    The nonce comparison is constant-time (`secure_equals`). A response for any
    other nonce is rejected -- a captured old `allow` can never satisfy a fresh
    request (doc §6.6; `verify_response` adds the `request_digest`, decision and
    freshness checks on top).
    """
    validate_envelope(message, "auth_response")
    nonce = message.get("nonce")
    if not secure_equals(nonce, expected_nonce):
        raise ProtocolError("response nonce does not match the request")
    decision = message.get("decision")
    if decision not in ("allow", "deny"):
        raise ProtocolError("missing or invalid 'decision'")
    return decision


def parse_pending(message: dict, expected_nonce: str) -> None:
    """Validate an `auth_pending` acknowledgement (doc §6.2a; audit A2).

    Strict, fail-closed validation: the envelope must be exactly the v1
    `auth_pending` type and its `nonce` must equal the request's. The frame
    carries no decision, so there is nothing else to accept; an unknown or
    missing `nonce` is a `ProtocolError` and the client treats it as
    `unavailable`.
    """
    validate_envelope(message, PENDING_TYPE)
    nonce = message.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ProtocolError("missing or invalid 'nonce' in auth_pending")
    if not secure_equals(nonce, expected_nonce):
        raise ProtocolError("auth_pending nonce does not match the request")


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

    # Top-level mtls paths are resolved so a hand-written config can use
    # paths relative to the config file. `[security]` holds no paths any more:
    # the removed ssh/x509/signature methods owned every key reference, and
    # mTLS carries its own `[mtls]` section.
    mtls = config.get("mtls")
    if isinstance(mtls, dict):
        for key in ("ca_file", "cert_file", "key_file"):
            if key in mtls and mtls[key]:
                mtls[key] = resolve(mtls[key])

    # `[acl]` (doc §8): `ca_file` is a path like every other; the fingerprint
    # lists are opaque strings (never paths) and are left untouched.
    acl = config.get("acl")
    if isinstance(acl, dict) and acl.get("ca_file"):
        acl["ca_file"] = resolve(acl["ca_file"])

    return config


# --- configuration schema (doc §7.9, §15.1) -------------------------------
#
# The **whole file** is checked against this schema before anything else runs:
# every key, at every level, must be one the implementation actually reads. A
# typo (`max_connection`) and a key written on the wrong side of a table header
# are therefore startup errors instead of lines that are quietly skipped -- a
# service that backs a PAM hook must never run with a knob the operator believes
# is set but that nothing read.
#
# The misplacement case is why this exists. TOML assigns a key to the **nearest
# preceding `[table]` header**, so a config whose `transport_encryption`/
# `client_auth`/`server_auth` lines sit *above* `[security]` has no `[security]`
# knobs at all. Under the previous "unknown keys are ignored" policy that was
# reported as `transport_encryption = 'none' requires an explicit client_auth =
# 'none'` -- which names the one thing the operator had already written, and not
# the placement that made it invisible. Naming the key *and* the table it belongs
# to is the whole point (doc §7.5, §7.9).

# Every key the implementation reads, per namespace.
CONFIG_TOP_LEVEL_KEYS = frozenset(
    {
        # role and transport selection
        "mode",
        "transport",
        "cid",
        "host",
        "port",
        # listener / selector paths and their modes
        "socket",
        "socket_dir_mode",
        "socket_mode",
        # timeouts and server-side pre-auth resource bounds
        "connect_timeout",
        "decision_timeout",
        "recv_timeout",
        "max_connections",
        "server_read_timeout",
        # interactive behaviour
        "dialog_program",
        "resolution",
        "debug",
        # request metadata a client config carries
        "approver",
        "client_version",
        "guest_hint",
        # sub-tables
        "security",
        "acl",
        "mtls",
        # internal: the `SecurityConfig` cache `build_security` writes back
        "_security",
    }
)

CONFIG_SECURITY_KEYS = frozenset(
    {
        "transport_encryption",
        "client_auth",
        "server_auth",
        "response_ttl",
        "clock_skew",
    }
)

# `labels` is a fingerprint -> display-label map; it is the one free-form table,
# so its keys are fingerprints and are deliberately not schema keys themselves.
CONFIG_ACL_KEYS = frozenset(
    {
        "mode",
        "trusted_fingerprints",
        "ca_file",
        "required_oid",
        "labels",
        "rule",
    }
)

CONFIG_MTLS_KEYS = frozenset(
    {
        "enable",
        "ca_file",
        "cert_file",
        "key_file",
        "required_oid",
        "peer_required_oid",
    }
)

CONFIG_TABLE_KEYS = {
    "security": CONFIG_SECURITY_KEYS,
    "acl": CONFIG_ACL_KEYS,
    "mtls": CONFIG_MTLS_KEYS,
}

# Below this length a fuzzy match has more false positives than value (`post`
# must not be answered with `host`), so short typos get the plain message.
CONFIG_SUGGESTION_MIN_LENGTH = 4


def _table_names_for(key: str) -> list[str]:
    """Return the `[tables]` that read `key` (empty for an unknown or top key)."""
    return sorted(
        name for name, keys in CONFIG_TABLE_KEYS.items() if key in keys
    )


def _owner_phrase(key: str) -> str | None:
    """Where `key` is read from, as a phrase (`None` when nothing reads it)."""
    tables = _table_names_for(key)
    if tables:
        return " in " + " or ".join(f"[{name}]" for name in tables)
    if key in CONFIG_TOP_LEVEL_KEYS:
        return " at the top level"
    return None


def _suggest_key(key: str, allowed: frozenset) -> str | None:
    """The misspelled key's real name, when there is an obvious one."""
    if len(key) < CONFIG_SUGGESTION_MIN_LENGTH:
        return None
    matches = difflib.get_close_matches(key.lower(), sorted(allowed), n=1, cutoff=0.75)
    return matches[0] if matches else None


def _join_names(names: list[str]) -> str:
    """``['a']`` -> ``'a'``; ``['a', 'b']`` -> ``'a' and 'b'``."""
    quoted = [repr(name) for name in names]
    if len(quoted) == 1:
        return quoted[0]
    return ", ".join(quoted[:-1]) + f" and {quoted[-1]}"


def _suggestion_hint(key: str, allowed: frozenset) -> str:
    """``; did you mean 'x'?``, when there is an obvious spelling to offer."""
    suggestion = _suggest_key(key, allowed)
    return f"; did you mean {suggestion!r}?" if suggestion else ""


def _unknown_keys_sentence(
    where_phrase: str, keys: list[str], allowed: frozenset
) -> str:
    """One sentence for the unknown keys refused at the same place."""
    if len(keys) == 1:
        # A single typo is worth the guess; a list of them is not.
        return (
            f"unknown key {_join_names(keys)} {where_phrase}"
            f"{_suggestion_hint(keys[0], allowed)}"
        )
    return f"unknown keys {where_phrase}: {_join_names(keys)}"


def validate_config_schema(config: dict, *, source: str | None = None) -> None:
    """Refuse any key the implementation does not read (doc §7.9, §15.1).

    Fail-closed and exact: the top level and the `[security]`, `[acl]` and
    `[mtls]` tables are each checked against their allowed key set, so both a
    typo and a misplaced key (a `[security]` key written above the `[security]`
    header, say) stop the process with a message naming the key and the table it
    belongs to. Unknown keys are **not** ignored: that policy is what turned a
    flattened `[security]` block into a misleading "requires an explicit
    client_auth = 'none'" error instead of a diagnosable one.

    `acl.labels` is the single free-form table (fingerprint -> label); only its
    own key, never its contents, is part of the schema. Values are still typed
    where they are used (`_positive_int`, `_parse_mode`, the knob validators), so
    this checks *names*; `source` is the config path, when the caller knows it, so
    the message can name the file to edit. Every offending key is reported, and
    keys refused for the same reason share one sentence: a flattened `[security]`
    block is five misplaced keys, and five copies of the same paragraph help
    nobody.
    """
    # (owner, where) -> keys, so the five keys of one flattened table collapse
    # into a single sentence; `where` is kept per group because the same owner can
    # be wrong in more than one place.
    misplaced: dict[tuple[str, str], list[str]] = {}
    unknown: dict[str, list[str]] = {}
    allowed_at: dict[str, frozenset] = {}
    broken_tables: list[str] = []

    def inspect(keys: dict, where_phrase: str, allowed: frozenset) -> None:
        for key in sorted(set(keys) - allowed):
            owner = _owner_phrase(key)
            if owner is None:
                unknown.setdefault(where_phrase, []).append(key)
                allowed_at[where_phrase] = allowed
            else:
                misplaced.setdefault((owner, where_phrase), []).append(key)

    inspect(config, "at the top level", CONFIG_TOP_LEVEL_KEYS)
    for name, allowed in CONFIG_TABLE_KEYS.items():
        table = config.get(name)
        if table is None:
            continue
        if not isinstance(table, dict):
            # Nothing to inspect: a scalar where a table belongs would fail in the
            # reader with a far worse message.
            broken_tables.append(f"[{name}] must be a table")
            continue
        inspect(table, f"inside [{name}]", allowed)

    sentences = list(broken_tables)
    sentences.extend(
        f"{_join_names(keys)} must be written{owner}, not {where_phrase}"
        for (owner, where_phrase), keys in misplaced.items()
    )
    if misplaced:
        sentences.append(
            "TOML assigns every key to the nearest preceding [table] header"
        )
    sentences.extend(
        _unknown_keys_sentence(where_phrase, keys, allowed_at[where_phrase])
        for where_phrase, keys in unknown.items()
    )
    if unknown:
        sentences.append(
            "the file is validated against an exact schema: a key the service "
            "does not read is refused, never ignored"
        )

    if sentences:
        source_suffix = f" in {source}" if source else ""
        raise SecurityConfigError("; ".join(sentences) + source_suffix)


# --- security model: validation, keyrings, auth blocks (doc §7) -----------


@dataclass(frozen=True)
class Rule:
    """One `[[acl.rule]]` approval rule (the `[acl]` rule engine).

    A rule refines the *approval* decision after the ACL has authorized the
    credential. Its selectors are glob patterns (`fnmatch`); `"*"` or an empty
    selector matches anything. `identity` is matched against every identity
    candidate the server has for the connection (the resolved friendly name, the
    ACL label, the verified fingerprint, or the `none` sentinel), and
    `target_user`/`invoking_user`/`service` against the (self-reported) request
    metadata. Rules never *grant* anything the ACL denied: the ACL runs first
    and is the authorization gate. Evaluated in file order, first match wins.
    """

    identity: str = "*"
    target_user: str = "*"
    invoking_user: str = "*"
    service: str = "*"
    policy: str = "ask"

    def matches(
        self,
        *,
        identities: "frozenset[str] | tuple[str, ...]",
        target_user: str,
        invoking_user: str,
        service: str,
    ) -> bool:
        """True when every selector matches the supplied connection context."""
        if not _any_pattern_matches(self.identity, identities):
            return False
        return (
            _pattern_matches(self.target_user, target_user)
            and _pattern_matches(self.invoking_user, invoking_user)
            and _pattern_matches(self.service, service)
        )


def _pattern_matches(pattern: str, value: str) -> bool:
    """Glob-match one selector; `"*"` or an empty pattern matches anything."""
    if not pattern or pattern == "*":
        return True
    return bool(fnmatchcase(value, pattern))


def _any_pattern_matches(pattern: str, values) -> bool:
    """Glob-match a selector against any of `values` (empty matches anything)."""
    if not pattern or pattern == "*":
        return True
    return any(_pattern_matches(pattern, value) for value in values)


@dataclass
class AclConfig:
    """The validated `[acl]` authorization policy for one server (doc §8).

    This is the *authorization* layer, distinct from the cryptographic
    `[security]` authentication: it decides whether an already-verified
    credential may use the mechanism at all. It matches **only** cryptographic
    material (mTLS leaf SPKI fingerprints and CA chains); metadata such as
    `PAM_USER`, `PAM_TTY`, `rhost` or `guest_hint` is never consulted for
    authorization (review log S11). The `rules` list is a separate *approval*
    refinement evaluated after authorization (see `Rule`).

    - `mode = "list"`: a credential is eligible only when its mTLS leaf SPKI
      fingerprint is in `trusted_fingerprints`. An empty set denies everyone;
      there is no wildcard.
    - `mode = "ca"`: any mTLS credential that chains to `ca_file` and carries
      `required_oid` is eligible; `trusted_fingerprints` optionally additionally
      pins the leaf SPKI.

    `labels` maps a fingerprint to a display/log label only. It is never an
    authorization input and is never accepted from the requester.
    """

    mode: str = "list"
    trusted_fingerprints: frozenset = field(default_factory=frozenset)
    ca_file: str | None = None
    required_oid: str | None = None
    labels: dict = field(default_factory=dict)
    rules: tuple = field(default_factory=tuple)


@dataclass
class SecurityConfig:
    """The validated `[security]` model for one role.

    `transport_encryption`, `client_auth` and `server_auth` are the three
    explicit knobs (doc §7). Nothing else needs loading: authentication is the
    mTLS channel (or the explicit absence of it), so there is no signing key,
    keyring or certificate material to read here any more.
    """

    transport: str
    transport_encryption: str
    client_auth: str
    server_auth: str
    response_ttl: int = DEFAULT_RESPONSE_TTL
    clock_skew: int = DEFAULT_CLOCK_SKEW
    # server role
    acl: AclConfig | None = None


def validate_security_config(config: dict) -> dict:
    """Validate `[security]` and return the resolved three knobs.

    This is pure (no file access) so it can be unit-tested and called before a
    single byte is sent. It applies the fail-closed rules of doc §7.5:

    - `transport_encryption` defaults to `"mtls"` on `tcp` and `"none"` on
      `vsock`/`unix`; `mtls.enable = true` is treated as `"mtls"`.
    - Under `mtls`, **both** `client_auth` and `server_auth` are `"transport"`;
      anything else is rejected. mTLS is the only authentication mechanism left
      (doc §7).
    - `client_auth = "transport"` / `server_auth = "transport"` require mTLS.
    - With `transport_encryption = "none"` there is no mechanism to fall back
      on, so a missing knob is an **error**, not a silent `"none"`: turning
      authentication off must be written down explicitly on both knobs. The
      pairing with `acl.mode = "none"` is enforced by `build_security`.
    - `tcp` + `"none"` is permitted but warned as insecure.

    Nothing here ever *downgrades*: the resolved values are final for the
    process and are never recomputed from the network.
    """
    security = config.get("security")
    if security is None:
        security = {}
    if not isinstance(security, dict):
        raise SecurityConfigError("'[security]' must be a table")

    transport = config.get("transport", "tcp")
    mtls = config.get("mtls")
    mtls_enabled = isinstance(mtls, dict) and bool(mtls.get("enable", False))

    transport_encryption = security.get("transport_encryption")
    if transport_encryption is None:
        if mtls_enabled or transport == "tcp":
            transport_encryption = "mtls"
        else:
            transport_encryption = "none"
    if transport_encryption not in TRANSPORT_ENCRYPTIONS:
        raise SecurityConfigError(
            f"unknown transport_encryption {transport_encryption!r} "
            f"(expected one of {', '.join(TRANSPORT_ENCRYPTIONS)})"
        )
    if mtls_enabled and transport_encryption != "mtls":
        # No silent downgrade from an enabled mTLS deployment (doc §7.4).
        raise SecurityConfigError(
            "mtls.enable = true conflicts with transport_encryption "
            f"= {transport_encryption!r}; refusing to downgrade"
        )

    client_auth = security.get("client_auth")
    server_auth = security.get("server_auth")
    if client_auth is not None and not isinstance(client_auth, str):
        raise SecurityConfigError("client_auth must be a single string")
    if server_auth is not None and not isinstance(server_auth, str):
        raise SecurityConfigError("server_auth must be a single string")
    if client_auth is not None and client_auth not in CLIENT_AUTH_METHODS:
        raise SecurityConfigError(
            f"unknown client_auth {client_auth!r} "
            f"(expected one of {', '.join(CLIENT_AUTH_METHODS)})"
        )
    if server_auth is not None and server_auth not in SERVER_AUTH_METHODS:
        raise SecurityConfigError(
            f"unknown server_auth {server_auth!r} "
            f"(expected one of {', '.join(SERVER_AUTH_METHODS)})"
        )

    if transport_encryption == "mtls":
        if client_auth not in (None, "transport"):
            raise SecurityConfigError(
                f"under transport_encryption = 'mtls', client_auth must be "
                f"'transport', not {client_auth!r} (mTLS forces it)"
            )
        if server_auth not in (None, "transport"):
            raise SecurityConfigError(
                f"under transport_encryption = 'mtls', server_auth must be "
                f"'transport', not {server_auth!r} (mTLS forces it)"
            )
        client_auth = "transport"
        server_auth = "transport"
    else:
        if client_auth == "transport":
            raise SecurityConfigError(
                "client_auth = 'transport' requires transport_encryption = 'mtls'"
            )
        if server_auth == "transport":
            raise SecurityConfigError(
                "server_auth = 'transport' requires transport_encryption = 'mtls'"
            )
        if client_auth is None or server_auth is None:
            # There is no weak-but-working default left: the only value left to
            # fall back on is "none", and silently disabling authentication is
            # exactly what this design refuses to do (doc §7.5).
            missing = [
                name
                for name, value in (
                    ("client_auth", client_auth),
                    ("server_auth", server_auth),
                )
                if value is None
            ]
            raise SecurityConfigError(
                "transport_encryption = 'none' requires an explicit "
                + " and ".join(f"{name} = 'none'" for name in missing)
                + " (refusing to disable authentication implicitly; use "
                "transport_encryption = 'mtls' to authenticate)"
            )

    if transport_encryption == "none" and transport == "tcp":
        print(
            "sudo-auth-proxy: WARNING: transport_encryption = 'none' on tcp is "
            "insecure (the channel is MITM-able and nothing authenticates the "
            "decision)",
            file=sys.stderr,
        )
    if server_auth == "none":
        extra = " and is strongly discouraged on tcp" if transport == "tcp" else ""
        print(
            f"sudo-auth-proxy: WARNING: server_auth = 'none' is not recommended{extra}; "
            "the client cannot tell a genuine response from an injected one",
            file=sys.stderr,
        )
    if client_auth == "none":
        extra = " and is strongly discouraged on tcp" if transport == "tcp" else ""
        print(
            f"sudo-auth-proxy: WARNING: client_auth = 'none' does NOT authenticate "
            f"the requester{extra}; any process that can reach the socket may trigger "
            "a prompt",
            file=sys.stderr,
        )

    return {
        "transport_encryption": transport_encryption,
        "client_auth": client_auth,
        "server_auth": server_auth,
    }


def _normalize_fingerprint(fingerprint: object, kind: str) -> str:
    """Return a validated `SHA256:<base64>` fingerprint, padding stripped.

    `ssh-keygen -lf` emits fingerprints without base64 padding, but the doc's
    examples show a trailing `=`; both are accepted and normalised to the
    unpadded form so a list entry always compares equal to a computed one. The
    decoded digest must be exactly 32 bytes (SHA-256); anything else fails
    closed rather than being treated as a never-matching string.
    """
    if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
        raise SecurityConfigError(
            f"{kind} entries must be 'SHA256:...' fingerprints, got {fingerprint!r}"
        )
    body = fingerprint[len("SHA256:") :].rstrip("=")
    if not body:
        raise SecurityConfigError(f"{kind} entry {fingerprint!r} has no digest")
    padded = body + "=" * (-len(body) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SecurityConfigError(
            f"{kind} entry {fingerprint!r} is not valid base64"
        ) from error
    if len(raw) != 32:
        raise SecurityConfigError(
            f"{kind} entry {fingerprint!r} is not a SHA-256 digest"
        )
    return "SHA256:" + body


def _fingerprint_set(entries: object, kind: str) -> frozenset:
    """Validate a `[acl]` fingerprint list into a frozen set (never a string)."""
    if entries is None:
        return frozenset()
    if not isinstance(entries, list):
        raise SecurityConfigError(f"[acl] {kind} must be a list of fingerprints")
    return frozenset(_normalize_fingerprint(entry, kind) for entry in entries)


def _parse_rules(entries: object) -> tuple:
    """Validate the `[[acl.rule]]` list into `Rule` objects (first match wins).

    Each entry is a table; only `identity`/`target_user`/`invoking_user`/
    `service`/`policy` are read, and an unknown key is a startup error (the same
    fail-closed policy as the rest of the schema). `policy` is exactly one of
    `allow`/`ask`/`deny`. Order is preserved: the first matching rule wins, and
    no rule matching means `ask` (`evaluate_rules`).
    """
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise SecurityConfigError("[acl] rule must be an array of tables")
    rules = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SecurityConfigError(f"acl.rule[{index}] must be a table")
        unknown = sorted(set(entry) - CONFIG_RULE_KEYS)
        if unknown:
            raise SecurityConfigError(
                f"acl.rule[{index}] has unknown key(s): "
                + ", ".join(repr(key) for key in unknown)
            )
        policy = entry.get("policy", "ask")
        if policy not in RULE_POLICIES:
            raise SecurityConfigError(
                f"acl.rule[{index}] policy must be one of "
                f"{', '.join(RULE_POLICIES)}, got {policy!r}"
            )
        selectors = {}
        for key in ("identity", "target_user", "invoking_user", "service"):
            value = entry.get(key, "*")
            if not isinstance(value, str):
                raise SecurityConfigError(
                    f"acl.rule[{index}] {key} must be a string pattern"
                )
            selectors[key] = value or "*"
        rules.append(Rule(policy=policy, **selectors))
    return tuple(rules)


def load_acl_config(config: dict) -> AclConfig:
    """Validate the server `[acl]` table into an `AclConfig` (doc §8).

    Fail-closed defaults: no `[acl]` table at all is a valid deny-all `"list"`
    policy, so a server never starts open by accident. `mode` is exactly one of
    `"list"`/`"ca"`/`"none"`; mixing the modes (a `"ca"` mode with
    `trusted_fingerprints`+`ca_file` omitted, a `"list"` mode with
    `ca_file`/`required_oid`, or a `"none"` mode with any trust material) is
    rejected rather than guessed. `"none"` is only reachable because
    `client_auth = "none"` needs an explicit ACL that deliberately authorizes
    unauthenticated requests (`build_security` enforces the pairing). In `"ca"`
    mode the CA must be readable at load time. The optional `[[acl.rule]]` list
    is the *approval* refinement (`_parse_rules`); it is accepted under every
    mode, including `"none"`, because it never authorizes a credential.
    """
    raw = config.get("acl")
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SecurityConfigError("'[acl]' must be a table")

    mode = raw.get("mode", "list")
    if not isinstance(mode, str) or mode not in ACL_MODES:
        raise SecurityConfigError(
            f"unknown acl.mode {mode!r} (expected one of {', '.join(ACL_MODES)})"
        )

    trusted_fingerprints = _fingerprint_set(
        raw.get("trusted_fingerprints"), "trusted_fingerprints"
    )
    ca_file = raw.get("ca_file")
    required_oid = raw.get("required_oid")
    rules = _parse_rules(raw.get("rule"))

    if mode == "none":
        # There is no credential to authorize, so any trust material is a
        # contradiction (and almost certainly a copy-paste mistake): reject it
        # rather than silently ignore a pin the operator believes is enforced.
        forbidden = [
            name
            for name, present in (
                ("trusted_fingerprints", bool(trusted_fingerprints)),
                ("ca_file", bool(ca_file)),
                ("required_oid", bool(required_oid)),
            )
            if present
        ]
        if forbidden:
            raise SecurityConfigError(
                "acl.mode = 'none' must not set "
                + ", ".join(forbidden)
                + " (there is no credential to authorize)"
            )
        return AclConfig(mode="none", rules=rules)

    raw_labels = raw.get("labels") or {}
    if not isinstance(raw_labels, dict) or any(
        not isinstance(value, str) for value in raw_labels.values()
    ):
        raise SecurityConfigError("acl.labels must be a table of string labels")
    labels = {
        _normalize_fingerprint(key, "labels"): value
        for key, value in raw_labels.items()
    }

    if mode == "ca":
        if not isinstance(ca_file, str) or not ca_file:
            raise SecurityConfigError("acl.mode = 'ca' requires acl.ca_file")
        if not isinstance(required_oid, str) or not required_oid:
            raise SecurityConfigError("acl.mode = 'ca' requires acl.required_oid")
        # Fail fast if the CA cannot be read; authorization reloads it per use.
        _load_trusted_ca_certs(ca_file)
    else:
        if ca_file or required_oid:
            raise SecurityConfigError(
                "acl.mode = 'list' must not set ca_file/required_oid "
                "(use acl.mode = 'ca')"
            )

    return AclConfig(
        mode=mode,
        trusted_fingerprints=trusted_fingerprints,
        ca_file=ca_file,
        required_oid=required_oid,
        labels=labels,
        rules=rules,
    )


def acl_allows_any(acl: AclConfig | None) -> bool:
    """True when an ACL could authorize at least one credential.

    Used only to warn at startup that a deny-all policy is in effect; it never
    grants anything and is deliberately conservative.
    """
    if acl is None:
        return False
    if acl.mode == "none":
        # An unauthenticated ACL authorizes every request: there is no
        # credential to match, so it never reaches the deny-all default.
        return True
    if acl.mode == "ca":
        return bool(acl.ca_file and acl.required_oid)
    return bool(acl.trusted_fingerprints)


def identity_candidates(
    *,
    requester: str,
    label: str = "",
    peer: str = "",
) -> tuple:
    """The strings an `[[acl.rule]]` `identity` selector may match.

    The server has several names for the same connection: the resolved friendly
    name (`peer`, from `resolution`), the operator's ACL `label`, the verified
    credential (`requester`, an mTLS SPKI fingerprint or the `none` sentinel).
    A rule may target any of them, so all non-empty candidates are returned. The
    order is display-name first so an exact name matches before a fingerprint.
    """
    seen: list = []
    for value in (label, peer, requester):
        if value and value not in seen:
            seen.append(value)
    return tuple(seen)


def evaluate_rules(
    rules,
    *,
    identities,
    target_user: str,
    invoking_user: str,
    service: str,
) -> str:
    """Return the policy of the first matching `[[acl.rule]]`, else `"ask"`.

    Rules are the *approval* layer: they run only after `authorize_request` has
    accepted the credential, so they can never grant access the ACL denied. The
    default with no rules (or no match) is `"ask"` -- the historical behaviour of
    always prompting.
    """
    for rule in rules or ():
        if rule.matches(
            identities=identities,
            target_user=target_user,
            invoking_user=invoking_user,
            service=service,
        ):
            return rule.policy
    return "ask"


def authorize_request(
    request: dict,
    security: "SecurityConfig",
    verified_identity: str,
    *,
    peer_cert_der: bytes | None = None,
) -> str:
    """Apply the `[acl]` to an already-authenticated request (doc §8).

    Called **after** `authenticate_request` and **before** the dialog. It reads
    only the verified credential: the mTLS leaf SPKI, or the CA chain the
    transport already proved. Metadata fields (`target_user`, `invoking_user`,
    `rhost`, `tty`, `guest_hint`, ...) are never inspected, so no self-reported
    value can influence the decision (review log S11). Returns the display label
    when one is configured, else the verified fingerprint; raises `AuthError`
    (fail closed) otherwise.

    `acl.mode = "none"` is the one mode that inspects no credential at all: it
    authorizes every request because `client_auth = "none"` leaves nothing to
    verify. It is accepted only when the configured `client_auth` is also
    `"none"`, so an unauthenticated ACL can never be paired with a credential
    the rest of the server would authenticate.
    """
    acl = security.acl
    if acl is None:
        raise AuthError("no [acl] authorization policy is configured")

    if security.client_auth == "none":
        # Unauthenticated mode: there is no credential to inspect. The pairing
        # with `acl.mode = "none"` is enforced by `build_security`; a caller
        # that assembles the config by hand still fails closed here.
        if acl.mode != "none":
            raise AuthError(
                "client_auth = 'none' requires acl.mode = 'none' "
                "(an unauthenticated request has no credential to authorize)"
            )
        return acl.labels.get(verified_identity, verified_identity)
    if acl.mode == "none":
        # The mirror image: an unauthenticated ACL may never be attached to a
        # credential the rest of the server would authenticate.
        raise AuthError(
            "acl.mode = 'none' requires client_auth = 'none' "
            "(an unauthenticated ACL cannot authorize a credential)"
        )

    if acl.mode == "list":
        # The mTLS leaf SPKI is the only credential left; an empty set denies
        # everyone.
        if verified_identity not in acl.trusted_fingerprints:
            raise AuthError(
                f"credential {verified_identity} is not in the authorization list"
            )
    else:  # acl.mode == "ca"
        ca_file = acl.ca_file
        required_oid = acl.required_oid
        if not ca_file or not required_oid:
            # Unreachable through `load_acl_config`, which requires both; a
            # caller that assembles the policy by hand fails closed here
            # instead of raising somewhere deeper.
            raise AuthError("acl.mode = 'ca' requires acl.ca_file and acl.required_oid")
        if not peer_cert_der:
            raise AuthError(
                "mTLS peer certificate is required to authorize a transport credential"
            )
        ca_certs = _load_trusted_ca_certs(ca_file)
        leaf = verify_x509_chain([_load_der_cert(peer_cert_der)], ca_certs, required_oid)
        if acl.trusted_fingerprints:
            # Optional additional pin on top of the CA chain.
            spki = spki_fingerprint(leaf.public_key())
            if spki not in acl.trusted_fingerprints:
                raise AuthError("certificate SPKI is not in the authorization list")

    return acl.labels.get(verified_identity, verified_identity)


def build_security(config: dict, role: str) -> SecurityConfig:
    """Validate the config and assemble the `SecurityConfig` for `role`.

    Loaded lazily per process and cached on the config dict. mTLS is the only
    authentication mechanism (doc §7), so there is no key material to load here
    any more: the TLS layer reads `[mtls]` itself, and the one thing that still
    needs validating is the server's `[acl]` authorization policy and its XOR
    pairing with `client_auth = "none"`. A configuration error is fatal, never a
    "run unauthenticated" path: the caller turns `SecurityConfigError` into a
    non-zero exit.
    """
    cached = config.get("_security")
    if isinstance(cached, SecurityConfig):
        return cached

    # Exact schema first (doc §7.9): an unknown or misplaced key must be reported
    # as itself, *before* `validate_security_config` can complain about the empty
    # value it left behind -- a `[security]` key written above the `[security]`
    # header is the classic case, and it used to be reported as "requires an
    # explicit client_auth = 'none'" even though that key was right there.
    validate_config_schema(config)
    normalized = validate_security_config(config)
    raw = config.get("security")
    if not isinstance(raw, dict):
        raw = {}
    security = SecurityConfig(
        transport=config.get("transport", "tcp"),
        response_ttl=int(raw.get("response_ttl", DEFAULT_RESPONSE_TTL)),
        clock_skew=int(raw.get("clock_skew", DEFAULT_CLOCK_SKEW)),
        **normalized,
    )

    if role == "server":
        # Authorization policy (doc §8). Loaded for every server and defaulting
        # to deny-all `"list"`; the mTLS handshake proves the credential, the
        # ACL decides who may use the mechanism.
        security.acl = load_acl_config(config)
        # Disabling requester authentication must be an explicit, conscious
        # choice on *both* knobs: `client_auth = "none"` is meaningless (and
        # dangerous) without an ACL that deliberately authorizes it, and an
        # unauthenticated ACL must never be attached to an authenticated
        # credential. Require exactly one of the two, i.e. their XOR.
        if security.client_auth == "none" and security.acl.mode != "none":
            raise SecurityConfigError(
                "client_auth = 'none' requires acl.mode = 'none' "
                "(unauthenticated requests need an explicit unauthenticated ACL)"
            )
        if security.acl.mode == "none" and security.client_auth != "none":
            raise SecurityConfigError(
                "acl.mode = 'none' requires client_auth = 'none' "
                "(an unauthenticated ACL cannot authorize a credential)"
            )

    config["_security"] = security
    return security


def attach_client_auth(request: dict, security: SecurityConfig) -> dict:
    """Attach the `client_auth` block on `request` (doc §6.4-§6.5).

    There is nothing to sign any more: the block is a one-field marker naming
    the mechanism. Under mTLS the method is `"transport"` and the credential is
    the channel identity (the TLS client certificate); under the explicit
    `client_auth = "none"` the block is `{"method": "none"}` and no credential
    is carried at all. The server rejects any other method.
    """
    method = security.client_auth
    if method not in ("transport", "none"):  # pragma: no cover - enum is validated
        raise AuthError(f"unknown client_auth method {method!r}")
    request["client_auth"] = {"method": method}
    return request


def authenticate_request(
    request: dict,
    security: SecurityConfig,
    *,
    peer_cert_der: bytes | None = None,
) -> str:
    """Verify the requester credential on `request`; return the verified identity.

    This is *authentication only*: proving the requester holds the certificate
    the mTLS handshake accepted. Whether that identity may use the mechanism is
    decided separately by `authorize_request` against the `[acl]` (doc §8); an
    accepted handshake on an unlisted certificate is therefore necessary but
    never sufficient.

    Fails closed (`AuthError`) on a missing block, a method that does not match
    the configured `client_auth`, or `client_auth = "transport"` without mTLS.
    There is no branch that returns success without verifying (doc §7.3).

    For `transport` the mTLS handshake already verified the chain; the leaf SPKI
    fingerprint is returned so `mode = "list"` can pin it (review log NF6). For
    `none` there is no credential to check: the method can only match when
    `security.client_auth == "none"` (enforced just below), and the fixed
    `NONE_IDENTITY` sentinel is returned. The ACL still runs and must be the
    matching `"none"` mode.
    """
    block = request.get("client_auth")
    if not isinstance(block, dict):
        raise AuthError("missing client_auth block")
    method = block.get("method")
    if method != security.client_auth:
        raise AuthError(
            f"client_auth method {method!r} does not match the configured {security.client_auth!r}"
        )
    if method == "none":
        # Only reachable when the configured method is "none"; there is nothing
        # to verify. The pairing with `acl.mode = "none"` is enforced by
        # `build_security` (and again by `authorize_request`).
        return NONE_IDENTITY
    if security.transport_encryption != "mtls":
        raise AuthError("client_auth = 'transport' requires transport_encryption = 'mtls'")
    if peer_cert_der:
        leaf = _load_der_cert(peer_cert_der)
        return spki_fingerprint(leaf.public_key())
    return "transport"


def _check_response_freshness(response: dict, security: SecurityConfig) -> None:
    """Enforce the response's `issued_at`/`expires_at` window (doc §6.6)."""
    issued = response.get("issued_at")
    expires = response.get("expires_at")
    if type(issued) is not int or type(expires) is not int:
        raise ProtocolError("missing or invalid issued_at/expires_at")
    if expires <= issued:
        raise ProtocolError("response expires_at is not after issued_at")
    now = int(time.time())
    if issued > now + security.clock_skew:
        raise ProtocolError("response is not yet valid")
    if now > expires + security.clock_skew:
        raise ProtocolError("response has expired")


def verify_response(
    response: dict,
    request: dict,
    security: SecurityConfig,
    consumed_nonces: set | None = None,
) -> str:
    """Verify an `auth_response` against the request and return the decision.

    Checks, in order: the response envelope, the nonce echo, the
    `request_digest`, the decision and the freshness window. The response is
    authenticated by the mTLS channel when `server_auth = "transport"`; with the
    explicit `server_auth = "none"` nothing authenticates it, which is exactly
    what that setting asks for (and why it warns). `consumed_nonces` (if given)
    enforces the client's single-use nonce: the second response for a nonce is
    rejected (doc §6.6, review log S9).
    """
    validate_envelope(response, "auth_response")
    nonce = response.get("nonce")
    expected_nonce = request.get("nonce")
    if not secure_equals(nonce, expected_nonce):
        raise ProtocolError("response nonce does not match the request")
    digest = response.get("request_digest")
    if not secure_equals(digest, compute_request_digest(request)):
        raise ProtocolError("response request_digest does not match the request")
    decision = response.get("decision")
    if decision not in ("allow", "deny"):
        raise ProtocolError("missing or invalid 'decision'")
    _check_response_freshness(response, security)

    if consumed_nonces is not None:
        if nonce in consumed_nonces:
            raise AuthError("response nonce has already been consumed")
        consumed_nonces.add(nonce)
    return decision


def expand_socket_path(path: str) -> str:
    """Expand placeholder prefixes in a unix socket path.

    `~` expands to the user's home directory. `%t/` expands to a per-user
    runtime directory ($XDG_RUNTIME_DIR on Linux, the Darwin per-user temp
    dir on macOS via `getconf DARWIN_USER_TEMP_DIR`) -- checked platform-first
    since a stray XDG_RUNTIME_DIR env var (e.g. exported for Linux
    compatibility in a dotfiles setup) can point at a directory that simply
    doesn't exist on macOS. Anything else is returned unchanged.
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
                # `/tmp` is the documented macOS user-temp fallback when getconf
                # cannot answer. Nothing sensitive is created here -- the path
                # only ever holds this service's socket.
                if result.returncode == 0:
                    runtime_dir = result.stdout.strip()
                else:
                    runtime_dir = "/tmp"  # noqa: S108 -- macOS user-temp fallback
            except OSError:
                runtime_dir = "/tmp"  # noqa: S108 -- getconf unavailable
        else:
            runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        return os.path.join(runtime_dir, path[3:])
    return path


def _parse_mode(value: object, default: int) -> int:
    """Accept a mode as either an int (0o600) or an octal string ("0600").

    The Nix module emits the mode options as strings (they are user-facing
    `"0700"`-style values), while a hand-written TOML may use an integer; both
    are supported so a dropped config does not silently widen permissions.
    """
    if value is None:
        return default
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(str(value), 8)
    except ValueError:
        return default


def _positive_int(value: object, default: int) -> int:
    """Coerce a config value to a positive int, falling back to `default`.

    A hand-written `max_connections = 0` (or a non-numeric value) must not turn
    the cap into "refuse everything"; it falls back to the safe default (audit
    A3). The generated TOML always emits a positive int.
    """
    if isinstance(value, bool) or value is None:
        return default
    try:
        parsed = int(value)  # type: ignore[arg-type]  # runtime-guarded above
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _positive_float(value: object, default: float) -> float:
    """Coerce a config value to a positive float, falling back to `default`.

    Like `_positive_int`: a non-positive or malformed `server_read_timeout`
    falls back to the default rather than disabling the bound (audit A3).
    """
    if isinstance(value, bool) or value is None:
        return default
    try:
        parsed = float(value)  # type: ignore[arg-type]  # runtime-guarded above
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _chmod(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as error:
        print(f"sudo-auth-proxy: could not chmod {path} to {mode:o}: {error}", file=sys.stderr)


# cryptography.x509 costs ~500-700ms to import (Rust extension + a long
# submodule chain) -- deferred to first actual use so invocations that never
# touch a certificate (early argument errors, plaintext client calls) don't
# pay for it, since this module is invoked fresh by pam_exec on every sudo.
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


def _require_x509():
    """Return the `cryptography.x509` module or raise (never return None).

    `cryptography` is the one third-party dependency and is supplied by the
    package's Python environment (`python3.withPackages`, see
    `nix/packages/sudo-auth-proxy/default.nix`), so it is present at runtime; the
    language server simply cannot see into that environment. Centralising the
    "is it importable at all" decision here keeps the call sites free of
    Optional handling.
    """
    x509_module = _load_x509()
    if x509_module is None:  # pragma: no cover - deployment-dependent
        raise AuthError("the cryptography library is required for certificate verification")
    return x509_module


# --- cryptographic primitives (doc §7) ------------------------------------
#
# `cryptography` is imported lazily, like x509 above: it is a Rust extension
# with a long submodule chain, and the process is spawned fresh by pam_exec on
# every `sudo`. Error paths that never reach authentication stay fast; only the
# paths that actually sign or verify pay the import.

_crypto_ns = None


def _crypto() -> types.SimpleNamespace:
    """Return a cached namespace of the cryptography pieces we use."""
    global _crypto_ns
    if _crypto_ns is None:
        try:
            from cryptography import x509 as x509_mod
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )
        except ImportError as error:  # pragma: no cover - deployment-dependent
            raise AuthError(
                "the cryptography library is required for certificate verification"
            ) from error
        _crypto_ns = types.SimpleNamespace(
            x509=x509_mod,
            hashes=hashes,
            ec=ec,
            ed25519=ed25519,
            rsa=rsa,
            Encoding=Encoding,
            PublicFormat=PublicFormat,
        )
    return _crypto_ns


def _b64e(data: bytes) -> str:
    """Encode bytes as standard base64 (used for certificate fingerprints)."""
    return base64.b64encode(data).decode("ascii")


def spki_fingerprint(public_key) -> str:
    """`SHA256:` fingerprint of an X.509 SubjectPublicKeyInfo (padding stripped)."""
    c = _crypto()
    der = public_key.public_bytes(c.Encoding.DER, c.PublicFormat.SubjectPublicKeyInfo)
    return "SHA256:" + _b64e(hashlib.sha256(der).digest()).rstrip("=")


def _cert_is_ca(cert) -> bool:
    """True if the certificate asserts BasicConstraints CA (path length ignored)."""
    c = _crypto()
    try:
        constraints = cert.extensions.get_extension_for_class(c.x509.BasicConstraints).value
    except c.x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)


def _cert_path_length(cert) -> int | None:
    """The BasicConstraints `path_length`, or None when unset/unreadable."""
    c = _crypto()
    try:
        constraints = cert.extensions.get_extension_for_class(c.x509.BasicConstraints).value
    except c.x509.ExtensionNotFound:
        return None
    return constraints.path_length


def _cert_allows_cert_sign(cert) -> bool:
    """True unless the certificate has a KeyUsage extension without keyCertSign."""
    c = _crypto()
    try:
        usage = cert.extensions.get_extension_for_class(c.x509.KeyUsage).value
    except c.x509.ExtensionNotFound:
        return True
    return bool(usage.key_cert_sign)


def _cert_allows_digital_signature(cert) -> bool:
    """True unless the certificate has a KeyUsage extension without digitalSignature.

    RFC 5280 §4.2.1.3: when the extension is present, a certificate used to
    verify an application signature must assert `digitalSignature`. A leaf with
    a KeyUsage that omits it is rejected (audit A6); an absent extension is
    accepted (it imposes no restriction).
    """
    c = _crypto()
    try:
        usage = cert.extensions.get_extension_for_class(c.x509.KeyUsage).value
    except c.x509.ExtensionNotFound:
        return True
    return bool(usage.digital_signature)


def _cert_has_unrecognized_critical_extension(cert) -> bool:
    """True when the certificate carries a CRITICAL extension we cannot process.

    RFC 5280 §4.2 requires a relying party to reject a certificate with a
    critical extension it does not understand. `cryptography` exposes unknown
    OIDs as `UnrecognizedExtension`; a *critical* one of those is rejected
    (audit A6). Known extensions are handled (or deliberately ignored) by the
    explicit chain/KeyUsage/EKU checks, so only truly unrecognized critical
    extensions fail here.
    """
    c = _crypto()
    try:
        extensions = list(cert.extensions)
    except Exception as error:  # pragma: no cover - malformed extension encoding
        raise AuthError(f"cannot parse certificate extensions: {error}") from error
    return any(
        extension.critical
        and isinstance(extension.value, c.x509.UnrecognizedExtension)
        for extension in extensions
    )


def _verify_cert_signed_by(child, issuer_public_key) -> None:
    """Verify `child`'s signature with `issuer_public_key` (Ed25519/RSA/ECDSA)."""
    c = _crypto()
    try:
        if isinstance(issuer_public_key, c.ed25519.Ed25519PublicKey):
            issuer_public_key.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(issuer_public_key, c.rsa.RSAPublicKey):
            issuer_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                child.signature_algorithm_parameters,
                child.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, c.ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                c.ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            raise AuthError("unsupported certificate signing key type")
    except AuthError:
        raise
    except Exception as error:
        raise AuthError("certificate signature verification failed") from error


def _load_trusted_ca_certs(ca_file: str) -> list:
    """Load the trusted CA certificate(s) from `ca_file` (PEM)."""
    c = _crypto()
    try:
        return c.x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
    except Exception as error:
        raise SecurityConfigError(f"cannot load CA file {ca_file}: {error}") from error


def _load_der_cert(der: bytes):
    """Parse a DER certificate (the mTLS peer leaf) or raise `AuthError`."""
    c = _crypto()
    try:
        return c.x509.load_der_x509_certificate(der)
    except Exception as error:
        raise AuthError(f"cannot parse peer certificate: {error}") from error


def verify_x509_chain(chain: list, ca_certs: list, required_oid: str, *, max_depth: int = 8):
    """Validate `chain` (leaf first) to a trusted CA and enforce the leaf EKU.

    Chain building is explicit and linear: each certificate must be signed by a
    CA that is either in the supplied chain or the trust store, every link's
    validity window is checked, and issuers must assert BasicConstraints CA.
    The leaf must carry `required_oid`, be an end entity (not `CA:TRUE`), and —
    when it has a KeyUsage extension — assert `digitalSignature`; every link is
    rejected if it carries an unrecognized critical extension (audit A6). Any
    failure raises `AuthError`, so an unverifiable certificate is never
    accepted.
    """
    c = _crypto()
    now = datetime.datetime.now(datetime.timezone.utc)
    trusted = {cert.fingerprint(c.hashes.SHA256()): cert for cert in ca_certs}
    leaf = chain[0]
    # End-entity constraints on the leaf (audit A6). A CA certificate presented
    # as the client leaf would otherwise be accepted because its own BasicConstraints
    # are never inspected once the chain terminates.
    if _cert_is_ca(leaf):
        raise AuthError("end-entity certificate asserts CA (BasicConstraints CA:TRUE)")
    if not _cert_allows_digital_signature(leaf):
        raise AuthError("end-entity certificate key usage forbids digital signatures")
    current = leaf
    seen: set = set()
    for _ in range(max_depth + 1):
        if not (current.not_valid_before_utc <= now <= current.not_valid_after_utc):
            raise AuthError("certificate is outside its validity window")
        if _cert_has_unrecognized_critical_extension(current):
            raise AuthError("certificate carries an unrecognized critical extension")
        fingerprint = current.fingerprint(c.hashes.SHA256())
        if fingerprint in trusted:
            break
        candidates = [cert for cert in (chain[1:] + ca_certs) if cert.subject == current.issuer]
        issuer = None
        for candidate in candidates:
            try:
                _verify_cert_signed_by(current, candidate.public_key())
            except AuthError:
                continue
            # The number of non-self-issued intermediates strictly below the
            # issuer is `len(seen)`; a CA's path_length must allow that many.
            path_length = _cert_path_length(candidate)
            if path_length is not None and path_length < len(seen):
                continue
            issuer = candidate
            break
        if issuer is None:
            raise AuthError("no trusted issuer found for certificate")
        if not _cert_is_ca(issuer):
            raise AuthError("certificate issuer does not assert CA")
        if not _cert_allows_cert_sign(issuer):
            raise AuthError("certificate issuer key usage forbids certificate signing")
        if fingerprint in seen:
            raise AuthError("certificate chain loop detected")
        seen.add(fingerprint)
        current = issuer
    else:
        raise AuthError("certificate chain exceeds the maximum depth")
    if not _cert_has_oid(leaf, required_oid):
        raise AuthError(f"client certificate missing required EKU OID {required_oid}")
    return leaf


def _cert_has_oid(cert: "x509.Certificate", oid: str) -> bool:
    x509 = _require_x509()
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return any(eku.dotted_string == oid for eku in ekus)
    except x509.ExtensionNotFound:
        return False


def verify_cert_file(path: str, oid: str, label: str) -> None:
    x509 = _require_x509()
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate {path} missing required EKU OID {oid}")


def verify_cert_der(der: bytes, oid: str, label: str) -> None:
    x509 = _require_x509()
    cert = x509.load_der_x509_certificate(der)
    if not _cert_has_oid(cert, oid):
        raise ValueError(f"{label} certificate missing required EKU OID {oid}")


def _verify_peer_oid(sock, config: dict, label: str) -> None:
    """Enforce the configured peer EKU OID on a TLS-wrapped socket.

    Identity on the callback transports is the certificate, not a hostname
    (the peer address is a VSOCK CID or a DHCP lease, not a name), so the EKU
    OID is the real trust check. This must run *after* the handshake, on the
    wrapped socket, which is why it is not part of `create_ssl_context`.
    """
    mtls = config.get("mtls")
    if not isinstance(mtls, dict):
        return
    peer_oid = mtls.get("peer_required_oid")
    if not peer_oid:
        return
    der = sock.getpeercert(binary_form=True)
    if der:
        verify_cert_der(der, peer_oid, label)


# --- Phase 7: dialog context and sanitisation (doc §11) --------------------
#
# Everything that reaches a dialog or a log line is attacker-influenced: the
# request fields come from the guest, the credential label comes from the
# verifier, and the peer label is derived from the transport. All of it goes
# through one allow-list sanitiser *before* it is rendered or logged, so a
# crafted field cannot inject swiftDialog markup, AppleScript, terminal
# control/ANSI sequences, Unicode bidi overrides, or extra log lines (doc
# §11.2; review logs NF2/NF8/T12/T17). The command/argv is deliberately absent
# from the protocol, so this module never shows it and never reads a process's
# argument vector out of `/proc` (doc §5.4; review log S5).

# The only characters a sanitised field may contain (doc §11.2), plus a literal
# space. Everything else becomes `?`, which removes newlines, tabs, control
# characters, ANSI escapes, bidi overrides and markup in a single pass.
SANITIZE_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_.:/@- "
)

# A hard cap applied after the allow-list pass, so an attacker cannot make the
# dialog or a log record arbitrarily large (doc §11.2, "cap lengths").
SANITIZE_MAX_LENGTH = 256


def sanitize_field(value: object, *, max_length: int = SANITIZE_MAX_LENGTH) -> str:
    """Return `value` normalised (NFC) and stripped to the display allow-list.

    The order matters (doc §11.2): Unicode-normalise **first** so visually
    identical sequences collapse to one form, then keep only
    ``[A-Za-z0-9_.:/@-]`` and a single space, replacing every other code point
    with ``?``. This is an allow-list, not a deny-list, so anything unanticipated
    (newlines, tabs, ANSI escapes, U+202E bidi overrides, emoji, markup) is
    neutralised without having to enumerate it. The result is capped at
    `max_length` characters.

    Non-strings are coerced defensively -- `None` becomes `""` and anything
    else is stringified -- so a malformed field can never raise on the logging
    path.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    normalized = unicodedata.normalize("NFC", value)
    cleaned = "".join(
        character if character in SANITIZE_ALLOWED else "?" for character in normalized
    )
    return cleaned[:max_length]


def escape_swiftdialog_markup(text: str) -> str:
    """Backslash-escape the characters swiftDialog interprets as markdown.

    Applied **after** :func:`sanitize_field` (doc §11.2): the allow-list already
    removes ``* [ ] ( )`` (they become ``?``), so in practice this is a
    belt-and-braces second pass. It remains because swiftDialog is the one
    backend that interprets its own markup, and a future widening of the
    allow-list must not silently reintroduce dialog injection (review log NF2).
    """
    for character in "*[]()":
        text = text.replace(character, "\\" + character)
    return text


# The request fields that are attacker-influenced and must be sanitised before
# they are logged (doc §11.2; review log NF8). The command is not in the
# protocol at all (doc §5.4), so it cannot be logged by accident.
SANITIZED_REQUEST_FIELDS = (
    "service",
    "target_user",
    "invoking_user",
    "rhost",
    "tty",
    "cwd",
    "client_version",
    "guest_hint",
)


def sanitize_request_fields(request: dict) -> dict:
    """Return the log-safe projection of an `auth_request` (doc §11.2/NF8).

    Never returns raw request bytes: every string field is passed through
    :func:`sanitize_field`, so a crafted `tty`/`guest_hint` cannot forge a log
    line, inject an ANSI/control sequence, or split a record.
    """
    return {
        field: sanitize_field(request.get(field))
        for field in SANITIZED_REQUEST_FIELDS
    }


def effective_target_user(service: str, target_user: str, invoking_user: str) -> str:
    """Best-effort target account for display and rule matching.

    `sudo` runs its PAM `auth` stack as the **invoking** user (it calls
    ``pam_start(service, invoking_user)`` and only switches ``PAM_USER`` to the
    runas user for the account/session phases), so ``PAM_USER`` repeats the
    invoking user instead of naming the target. For ``sudo`` the target defaults
    to ``root``; ``su``/``login`` set ``PAM_USER`` to the account, so they are
    used verbatim. This is a display/rule-matching helper only: the raw
    ``target_user`` still travels in the request and is bound into its digest,
    and a `sudo -u <other>` target is not visible to an auth-phase module.
    """
    if service == "sudo" and (not target_user or target_user == invoking_user):
        return "root"
    return target_user


@dataclass
class Confirmation:
    """The sanitised, display-ready context for one confirmation dialog.

    Built by :func:`build_confirmation` from the *verified* identity plus the
    (now sanitised) request metadata. No field here is raw request data: each
    value has already been through :func:`sanitize_field`, so a backend can
    render the dataclass without re-checking anything (doc §11.1-§11.2).
    `target_user` has additionally been normalised by
    :func:`effective_target_user` (so a `sudo` dialog shows `root`, not the
    invoking user repeated).
    """

    peer: str
    identity: str
    label: str
    invoking_user: str
    target_user: str
    service: str
    tty: str
    rhost: str
    cwd: str
    request_id: str
    timestamp: str
    transport: str


def build_confirmation(
    *,
    peer: str,
    identity: str,
    label: str,
    request: dict,
    transport: str,
    now: float | None = None,
) -> Confirmation:
    """Assemble and sanitise the context shown to the approver (doc §11.1).

    `identity` is the verified credential (SSH/X.509 fingerprint) and `label`
    is the operator-configured ACL label for it; both are sanitised like every
    other field even though they are not attacker-chosen. `request` supplies
    the session metadata (invoking/target user, service, tty, rhost, cwd) and
    `transport` names the byte path. The request id is a short nonce prefix and
    the timestamp is the server's clock at dialog time.
    """
    nonce = request.get("nonce")
    request_id = nonce[:8] if isinstance(nonce, str) else ""
    moment = time.time() if now is None else now
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment))
    service = request.get("service")
    service_text = service if isinstance(service, str) else ""
    invoking = request.get("invoking_user")
    invoking_text = invoking if isinstance(invoking, str) else ""
    target = request.get("target_user")
    target_text = target if isinstance(target, str) else ""
    return Confirmation(
        peer=sanitize_field(peer),
        identity=sanitize_field(identity),
        label=sanitize_field(label),
        invoking_user=sanitize_field(invoking_text),
        target_user=sanitize_field(
            effective_target_user(service_text, target_text, invoking_text)
        ),
        service=sanitize_field(service),
        tty=sanitize_field(request.get("tty")),
        rhost=sanitize_field(request.get("rhost")),
        cwd=sanitize_field(request.get("cwd")),
        request_id=sanitize_field(request_id),
        timestamp=sanitize_field(timestamp),
        transport=sanitize_field(transport),
    )


def confirmation_summary(confirmation: Confirmation) -> str:
    """Render the condensed prompt shown by default (doc §11.4).

    Two short lines: who is asking for what, and where it lands. Everything
    else — tty, cwd, request id, timestamp, the verified fingerprint behind a
    configured label — is *context*, not a decision input, so it moves to
    :func:`confirmation_message` and is reached through the dialog's expand
    affordance (or the server log) instead of being dumped at the approver.

    The requester line degrades explicitly for an unauthenticated request
    rather than printing the raw `NONE_IDENTITY` sentinel.
    """
    requester = confirmation.label or confirmation.identity
    if confirmation.identity in ("", NONE_IDENTITY):
        requester = "Unauthenticated requester"
    where = confirmation.peer or "unknown peer"
    if confirmation.rhost and confirmation.rhost != confirmation.peer:
        where = f"{where} (from {confirmation.rhost})"
    return "\n".join(
        [
            f"{requester} requests {confirmation.target_user} via {confirmation.service}",
            f"on {where} ({confirmation.transport})",
        ]
    )


def confirmation_message(confirmation: Confirmation) -> str:
    """Render the full, field-labelled context block for a confirmation dialog.

    This is the *detailed* view (doc §11.4): the label/value rows behind the
    dialog's expand affordance, and the same text the server logs. Every
    interpolated value has already been sanitised by :func:`build_confirmation`;
    this function only arranges literals, so it can never introduce
    attacker-controlled text. The command/argv is not shown: it is spoofable and
    is not part of the protocol at all (doc §5.4, §11.1).
    """
    requester = confirmation.label or confirmation.identity
    if confirmation.identity in ("", NONE_IDENTITY):
        requester = "Unauthenticated requester"
        identity = "unverified (client_auth = none)"
    else:
        identity = confirmation.identity or "unknown"
    lines = [
        f"Requester  {requester}",
        f"Identity   {identity}",
        f"Request    {confirmation.invoking_user} -> {confirmation.target_user} via {confirmation.service}",
        f"Peer       {confirmation.peer}",
        f"Transport  {confirmation.transport}",
    ]
    if confirmation.rhost:
        lines.append(f"Remote     {confirmation.rhost}")
    if confirmation.tty:
        lines.append(f"TTY        {confirmation.tty}")
    if confirmation.cwd:
        lines.append(f"CWD        {confirmation.cwd}")
    lines.append(f"Request id {confirmation.request_id} ({confirmation.timestamp})")
    return "\n".join(lines)


# One dialog is shown at a time (doc §11.3, T11; audit A13). This is a UI
# expectation, not a security boundary -- only credentialed requesters reach a
# dialog -- but serialising prompts keeps two concurrent requests from stacking
# two modal windows on the approver's desktop and makes the T11 wording true.
_dialog_lock = threading.Lock()

# The Details affordance on zenity (doc §11.4). zenity's extra button exits with
# the **cancellation** code (1 in 3.x and 4.x: zenity's `util.c` keeps it "for
# backwards compatibility with zenity <= 3.x"), so the exit code alone cannot
# tell "show me more" from "deny" -- which is why this backend used to get the
# summary with no way to expand it. What *is* unambiguous: zenity prints the
# extra button's label on stdout when it is pressed and prints nothing for
# OK/Cancel, so the label is the signal. That is the same stdout-based trick the
# osascript path already uses for its three buttons.
ZENITY_DETAILS_LABEL = "Details"

# Explicit dialog width, in pixels (doc §11.4). zenity's own default is to wrap
# the label at 60 characters (`gtk_label_set_max_width_chars (text, 60)` in its
# `msg.c`), so the two-line summary and the ten-line field block both come out as
# a narrow column -- taller than it is wide, which reads as a cramped prompt. A
# width makes the text widget request that many pixels, so fewer lines wrap and
# the dialog grows sideways instead of downwards; `--height` is deliberately not
# passed, so it still fits its content. 520 matches the swiftDialog layout on
# macOS, so both backends look like the same prompt.
ZENITY_DIALOG_WIDTH = 520

# Bound on the one-shot capability probe below. A prompt must never depend on a
# subprocess that can hang: without a bound, a wedged `zenity --help-all` would
# stall the PAM hook (the guest would see `unavailable`) instead of falling back
# to the summary-only dialog.
ZENITY_PROBE_TIMEOUT = 5.0
_zenity_extra_button_support: bool | None = None


def zenity_supports_extra_button() -> bool:
    """Whether the `zenity` on PATH accepts `--extra-button` (probed once).

    `--extra-button` exists in both zenity 3.x and 4.x, but the prompt must not
    *depend* on it: an unknown option makes zenity exit non-zero with nothing on
    stdout, which this module reads as a deny, so a backend without the flag
    would deny every request. Probing keeps that case at today's behaviour (the
    summary alone, the field block in the log) instead of a silent denial.

    The answer is cached for the life of the process: the server is long-lived
    and shows many prompts, while the client never shows a dialog at all. Any
    failure to run zenity -- absent, not executable, or wedged -- counts as
    "no", which degrades to exactly the old prompt rather than failing it.
    """
    global _zenity_extra_button_support
    if _zenity_extra_button_support is None:
        try:
            probe = subprocess.run(
                ["zenity", "--help-all"],
                capture_output=True,
                timeout=ZENITY_PROBE_TIMEOUT,
            )
            _zenity_extra_button_support = b"--extra-button" in probe.stdout
        except (OSError, subprocess.SubprocessError):
            _zenity_extra_button_support = False
    return _zenity_extra_button_support


def prompt_for_confirmation(confirmation: Confirmation, dialog_program: str) -> bool:
    """Ask the user to authorize a privilege-elevation request. Returns True if approved.

    `confirmation` carries only sanitised fields (doc §11.2) and `dialog_program`
    picks the confirmation mechanism explicitly (one of "swiftdialog",
    "osascript", "zenity") -- set via config, not auto-detected.

    The prompt is shown as a two-line summary (doc §11.4). The full field block
    stays reachable, never in the approver's face:

    - ``swiftdialog``: summary in ``--message``, the details behind an info
      button (``--info`` + ``--infobuttontext``).
    - ``osascript``: summary with a third ``Details`` button that opens a second
      dialog; the button pressed is read from stdout, so ``Details`` can never be
      mistaken for a decision.
    - ``zenity``: summary with a ``Details`` extra button when the installed
      zenity accepts one (probed; see `zenity_supports_extra_button`). Pressing
      it opens a second dialog showing the block, and only an explicit
      ``Authorize`` there allows. The button is identified by the label zenity
      prints on **stdout**, because its exit code for an extra button is the
      cancellation code -- so like the osascript path, ``Details`` can never be
      mistaken for a decision. Without the extra button the prompt is the
      summary alone and the block stays in the server log (``debug = true``).

    Prompts are serialised by `_dialog_lock`, so one dialog is shown at a time
    (doc §11.3, T11; audit A13). There is deliberately no rate-limit, backoff,
    circuit-breaker or "remember this request" state here or anywhere else
    (review log S12): every call shows a dialog, and a deny is always explicit
    and logged.
    """
    summary = confirmation_summary(confirmation)
    details = confirmation_message(confirmation)
    with _dialog_lock:
        return _prompt_for_confirmation(confirmation, summary, details, dialog_program)


def _prompt_for_confirmation(
    confirmation: Confirmation, summary: str, details: str, dialog_program: str
) -> bool:
    """Dispatch the (already serialised and rendered) prompt to its backend."""
    if dialog_program == "swiftdialog":
        res = subprocess.run(
            [
                "dialog",
                "--title", "Privilege Elevation",
                "--message", escape_swiftdialog_markup(summary),
                # The expandable half: an info button holding the full block.
                "--info", escape_swiftdialog_markup(details),
                "--infobuttontext", "Details",
                "--icon", "SF=lock.shield.fill,colour=accent,weight=medium",
                "--iconsize", "80",
                "--iconalttext", "Authentication required",
                "--button1text", "Authorize",
                "--button2text", "Deny",
                "--width", "520",
                "--height", "240",
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
        title = f"sudo authentication for {confirmation.peer}"
        first = subprocess.run(
            [
                "osascript",
                "-e",
                f'display dialog {json.dumps(summary)} '
                f'with title {json.dumps(title)} '
                'with icon caution buttons {"Deny", "Details", "Authorize"} '
                'default button "Authorize" cancel button "Deny"',
            ],
            capture_output=True,
        )
        if first.returncode != 0:
            return False
        if b"Details" in first.stdout:
            # The approver asked for more context: show the field block and ask
            # again. Only an explicit "Authorize" in this second dialog allows.
            second = subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display dialog {json.dumps(details)} '
                    f'with title {json.dumps(title)} '
                    'with icon caution buttons {"Deny", "Authorize"} '
                    'default button "Deny" cancel button "Deny"',
                ],
                capture_output=True,
            )
            return second.returncode == 0 and b"Authorize" in second.stdout
        return b"Authorize" in first.stdout

    if dialog_program == "zenity":
        title = f"sudo authentication for {confirmation.peer}"
        argv = [
            "zenity",
            "--title",
            title,
            "--question",
            "--no-markup",
            "--width",
            str(ZENITY_DIALOG_WIDTH),
            "--text",
            summary,
            "--ok-label",
            "Authorize",
            "--cancel-label",
            "Deny",
        ]
        if not zenity_supports_extra_button():
            return not subprocess.run(argv).returncode

        # Only *stdout* is captured: stderr stays inherited so a GTK/display error
        # still reaches the journal, and the one thing parsed is the label zenity
        # prints for an extra button.
        first = subprocess.run(
            argv + ["--extra-button", ZENITY_DETAILS_LABEL],
            stdout=subprocess.PIPE,
        )
        if ZENITY_DETAILS_LABEL.encode("utf-8") not in first.stdout:
            return first.returncode == 0

        # The approver asked for more context: show the field block and ask again
        # (doc §11.4). Only an explicit "Authorize" in this second dialog allows,
        # and Deny takes the focus because the block is request metadata, not a
        # decision input.
        _debug(f"zenity: {ZENITY_DETAILS_LABEL} requested; showing the detail block")
        second = subprocess.run(
            [
                "zenity",
                "--title",
                f"{title} -- details",
                "--question",
                "--no-markup",
                "--width",
                str(ZENITY_DIALOG_WIDTH),
                "--text",
                details,
                "--ok-label",
                "Authorize",
                "--cancel-label",
                "Deny",
                "--default-cancel",
            ]
        )
        return second.returncode == 0

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


def tartarus_name_for_id(vm_id: int) -> str | None:
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
    except Exception as error:  # noqa: BLE001 -- best-effort name lookup
        # Any failure here (no state directory, permissions, races) just means
        # the CID has no known name; resolution is cosmetic.
        _debug(f"tartarus name lookup failed: {error!r}")
    return None


def tartarus_id_for_ip(ip: str) -> int | None:
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


def resolve_tartarus_name(peer) -> str | None:
    """`peer` is a VSOCK CID (int) or a TCP peer IP (str)."""
    if isinstance(peer, int):
        return tartarus_name_for_id(peer)
    vm_id = tartarus_id_for_ip(peer)
    if vm_id is None:
        return None
    return tartarus_name_for_id(vm_id)


# `mofos` resolution: `mofos ls --json` prints a JSON array of VM objects
# (`{"cid": 4, "name": "template-nixos", "ipv4_address": "192.168.90.147",
# ...}`). The connecting peer is matched to a VM by VSOCK CID (int peer) or by
# `ipv4_address` (TCP peer), and the VM's `name` becomes the friendly name shown
# in the prompt. The listing is cached briefly so a burst of `sudo` prompts does
# not fork `mofos` per request; a missing binary, a non-zero exit or malformed
# JSON simply yields no name (resolution is cosmetic and never gates anything).
MOFOS_CACHE_TTL = 30
MOFOS_TIMEOUT = 10.0
_mofos_cache: tuple | None = None


def _mofos_vms() -> list:
    """Return `mofos ls --json` as a list of dicts (cached for `MOFOS_CACHE_TTL`)."""
    global _mofos_cache
    now = time.time()
    if _mofos_cache is not None and now - _mofos_cache[0] < MOFOS_CACHE_TTL:
        return _mofos_cache[1]
    vms: list = []
    try:
        result = subprocess.run(
            ["mofos", "ls", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=MOFOS_TIMEOUT,
        )
        if result.returncode != 0:
            _debug(f"mofos ls failed: {result.stderr.strip()}")
        else:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, list):
                vms = [entry for entry in parsed if isinstance(entry, dict)]
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        _debug(f"mofos resolution failed: {error!r}")
    _mofos_cache = (now, vms)
    return vms


def resolve_mofos_name(peer) -> str | None:
    """`peer` (VSOCK CID int, or TCP peer IP str) -> the mofos VM name."""
    if peer is None:
        return None
    for vm in _mofos_vms():
        matched = (
            vm.get("cid") == peer
            if isinstance(peer, int)
            else vm.get("ipv4_address") == peer
        )
        if matched:
            name = vm.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def get_resolution_mode(config: dict) -> str:
    mode = config.get("resolution")
    if mode in ("none", "certificate", "tartarus", "mofos"):
        return mode
    mtls = config.get("mtls")
    return "certificate" if isinstance(mtls, dict) and mtls.get("enable", False) else "tartarus"


# --- transport abstraction -------------------------------------------------
#
# The plan (§4) reduces the transports to a small interface used by the
# baseline client, server and peer-name resolution: `connect`, `listen` and
# `peer_uid`. Three implementations exist: `vsock` and `tcp` (the guest dials
# the host; "callback") and `unix` (the host dials the guest through an SSH
# RemoteForward). The client opens a fresh connection per invocation on every
# transport -- there is no persistent/reuse connection any more (S2).


# AF_UNIX peer credentials (doc §9.1; review log F12). Linux exposes the full
# `SO_PEERCRED` ucred (pid, uid, gid). Darwin has no `SO_PEERCRED`: it offers
# `getpeereid(3)` and `LOCAL_PEERCRED`, both of which return only uid/gid and no
# pid. The uid is what authorization checks; the pid is used only by the Linux
# `sshd` peer-process check above.
LOCAL_PEERCRED = 0x001  # Darwin `SOL_LOCAL` socket option


def _darwin_peer_uid(sock) -> int | None:
    """Best-effort uid of an AF_UNIX peer on Darwin (doc §9.1; residual R11).

    Darwin cannot give us `SO_PEERCRED`, only a uid/gid pair. `getpeereid(3)` is
    tried first (via `ctypes`, since CPython's `socket` does not wrap it), then
    `LOCAL_PEERCRED`, whose `struct xucred` begins with `cr_version` then
    `cr_uid` -- reading the first two ints is enough for the uid. Returns
    `None` when neither call is available, so the caller can rely on the
    path/ownership checks and `server_auth` instead of treating "unavailable" as
    "allowed" (doc §12.5 T25).
    """
    try:
        import ctypes

        # `CDLL(None)` resolves symbols already loaded into the process, which
        # on Darwin includes libSystem's `getpeereid`.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.getpeereid.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        libc.getpeereid.restype = ctypes.c_int
        uid = ctypes.c_uint()
        gid = ctypes.c_uint()
        if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0:
            return int(uid.value)
    except (AttributeError, OSError, ValueError):
        pass
    try:
        # struct xucred: cr_version (int), cr_uid (uid_t), ... -- the first two
        # ints are (version, uid), so the full 76-byte struct is not needed.
        _version, uid = struct.unpack(
            "2i", sock.getsockopt(0, LOCAL_PEERCRED, struct.calcsize("2i"))
        )
        return uid
    except (OSError, struct.error, AttributeError):
        return None


def _unix_peer_cred(sock, *, platform: str | None = None):
    """Return `(pid, uid, gid)` for an AF_UNIX peer, or `None` if unavailable.

    Linux reads the authoritative `SO_PEERCRED` ucred. Darwin has no pid and
    only a best-effort uid (pid/gid are reported as `-1`). Any other platform --
    or a failed syscall -- returns `None` so the caller can decide whether a
    missing credential is fatal (Linux) or merely weaker (Darwin, R11).
    """
    if platform is None:
        platform = sys.platform
    if platform != "darwin" and hasattr(socket, "SO_PEERCRED"):
        try:
            size = struct.calcsize("3i")
            pid, uid, gid = struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
            )
            return pid, uid, gid
        except (OSError, struct.error):
            return None
    if platform == "darwin":
        uid = _darwin_peer_uid(sock)
        if uid is None:
            return None
        return -1, uid, -1
    return None


def _unix_peer_uid(sock) -> int | None:
    """Best-effort uid of an AF_UNIX peer, or None when unavailable.

    Retained for the connection log. Authorization goes through
    :func:`authorize_unix_peer`, which fails closed on Linux; this helper never
    gates anything.
    """
    cred = _unix_peer_cred(sock)
    return cred[1] if cred is not None else None


def authorize_unix_peer(
    sock, *, expected_uid: int | None = None, platform: str | None = None
) -> int | None:
    """Refuse an AF_UNIX peer that is not the server user (doc §9.1; F12).

    Linux: `SO_PEERCRED` is authoritative, so a **missing credential or a
    different uid fails closed** (`RuntimeError`) -- another local user can
    never reach the handler.

    Darwin: `getpeereid`/`LOCAL_PEERCRED` yields only a uid, and when the call
    is unavailable there is no portable way to check. A uid we *can* read must
    still match; when none is available we surface the weaker path/ownership
    guarantee (residual R11, doc §12.5 T25) and rely on `server_auth` -- we do
    not pretend the check passed.

    Returns the verified uid, or `None` when the platform cannot report one
    (Darwin). Raises `RuntimeError` on a uid mismatch, or when the credential
    is unavailable on a platform (Linux) that is expected to provide one.
    """
    if expected_uid is None:
        expected_uid = os.getuid()
    if platform is None:
        platform = sys.platform
    cred = _unix_peer_cred(sock, platform=platform)
    if cred is None:
        if platform == "darwin" or not hasattr(socket, "SO_PEERCRED"):
            # No portable peer credential: degrade to the path/ownership checks
            # and server authentication rather than accept an identity we cannot
            # verify at all (R11).
            _debug(
                "unix peer credential unavailable; relying on path/ownership "
                "checks and server authentication (residual R11)"
            )
            return None
        raise RuntimeError(
            "cannot read the unix peer's credentials; refusing the connection"
        )
    _pid, uid, _gid = cred
    if uid != expected_uid:
        raise RuntimeError(
            f"unix peer uid {uid} is not the server user uid {expected_uid}"
        )
    return uid


def _peer_cannot_replace(
    path: str, peer_uid: int, peer_gid: int, *, stat_fn=os.stat
) -> bool:
    """True when ``path`` looks like a system ``sshd`` the peer cannot replace.

    The basename-only ``sshd`` check was trivially bypassed by a same-UID
    process copying any binary to a file named ``sshd`` (audit A7). Requiring
    only "not writable in place" was *still* bypassed by a same-UID attacker
    who owns the file and makes it read-only (``chmod 0555``), which the Round 2
    re-audit probe confirmed returns ``True``. This check therefore requires the
    resolved target to be a regular file owned by **root** (uid 0) and *not* by
    the peer uid: the real ``sshd`` binary is root-owned while the forwarding
    ``sshd`` process runs as the guest login user, so a same-UID attacker's own
    copy is rejected even when read-only. A non-existent or non-regular target
    is rejected (fail closed).

    This only *raises the bar*. It is a path/ownership heuristic, not a
    kernel-attested identity: a same-UID attacker can still win the
    non-atomic selector race and redirect the client to a *different legitimate
    tunnel* (accepted residual R6, made harder by the per-session token R9), and
    a root attacker owns the binary anyway. It stops the trivial A7 forgery, not
    a compromised host/sshd.

    ``stat_fn`` is injectable so the ownership decision is testable without
    root (the suite cannot create root-owned files).
    """
    try:
        info = stat_fn(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    # Root-owned and not the peer's own file: a same-UID binary -- even one
    # made read-only (the chmod 0555 bypass) -- fails here.
    if info.st_uid == peer_uid:
        return False
    if info.st_uid != 0:
        return False
    mode = info.st_mode
    if info.st_gid == peer_gid and (mode & stat.S_IWGRP):
        return False
    return not (mode & stat.S_IWOTH)


def verify_unix_peer_is_sshd(
    sock,
    proc_root: str = "/proc",
    *,
    sshd_allowlist: frozenset | None = None,
    stat_fn=os.stat,
) -> bool | None:
    """Return True iff an AF_UNIX peer is a trusted local ``sshd`` process.

    Linux-only hardening against a same-UID process redirecting the client to a
    *different* legitimate tunnel (doc §9.2, review log T21; audit A7). It reads
    the peer pid/uid/gid from ``SO_PEERCRED``, resolves ``/proc/<pid>/exe``, and:

    1. rejects a binary whose name carries the kernel's ``" (deleted)"`` marker
       (a replaced/upgraded target is not the system sshd);
    2. requires the basename to be ``sshd``;
    3. unless an explicit ``sshd_allowlist`` of resolved paths is supplied,
       requires the target to be a regular file owned by **root** and *not* by
       the peer (see :func:`_peer_cannot_replace`), so a same-UID attacker's own
       read-only copy named ``sshd`` is rejected (the Round 2 A7 remainder).

    Returns ``None`` when the check is unavailable -- no ``SO_PEERCRED``
    (e.g. macOS), a missing ``/proc``, an unreadable ``exe``, or a peer that
    already exited -- so the caller degrades gracefully to the path/ownership
    checks (residual R11). Returns ``False`` when the pid is live but its
    executable is not a trusted ``sshd``; the caller treats that as fail closed.

    ``proc_root``, ``sshd_allowlist`` and ``stat_fn`` are injectable so the
    logic is testable without a real ``/proc`` or root-owned files; production
    uses the defaults (no allow-list, real ``os.stat``, so the root-ownership
    check is what runs). This control only raises the bar: R6 (same-UID
    misrouting to another legitimate tunnel) and R9 (non-atomic selector bind)
    remain accepted residuals.
    """
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        size = struct.calcsize("3i")
        pid, peer_uid, peer_gid = struct.unpack(
            "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        )
    except (OSError, struct.error, TypeError):
        return None
    if pid <= 0:
        return None
    try:
        exe = os.readlink(os.path.join(proc_root, str(pid), "exe"))
    except OSError:
        # The peer exited between connect and now, or there is no /proc: we
        # cannot name its executable, so we cannot assert it is sshd. Degrade
        # (None) rather than fail closed on an unavailable check.
        return None
    if exe.endswith(" (deleted)"):
        return False
    if os.path.basename(exe) != "sshd":
        return False
    if sshd_allowlist is not None:
        return exe in sshd_allowlist
    return _peer_cannot_replace(exe, peer_uid, peer_gid, stat_fn=stat_fn)


def _assert_owner_only(path: str, mode: int, kind: str, *, expect_dir: bool = False) -> None:
    """Fail closed when `path` is not owned by us or is not at `mode`.

    Used to *verify* that a chmod actually took effect: a failed or ineffective
    chmod must abort the bind/server start rather than leave a world-accessible
    socket or directory behind. `expect_dir` additionally asserts the type, so a
    path swapped for a non-directory is caught.
    """
    try:
        info = os.lstat(path)
    except OSError as error:
        raise RuntimeError(f"cannot stat {kind} {path}: {error}") from error
    if info.st_uid != os.getuid():
        raise RuntimeError(f"{kind} {path} is not owned by uid {os.getuid()}")
    actual = stat.S_IMODE(info.st_mode)
    if actual != mode:
        raise RuntimeError(f"{kind} {path} has mode {actual:04o}, expected {mode:04o}")
    if expect_dir and not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{kind} {path} is not a directory")


def _prepare_unix_socket(path: str, dir_mode: int) -> None:
    """Create/verify the parent dir and remove a stale socket before bind.

    Hardening for doc §9.1: the parent directory is forced to `dir_mode`
    (`0700` by default) and *verified* owner-only; a bind target that is a
    symlink, a non-socket, or a socket owned by another uid is refused, and only
    a socket we own is unlinked. The bind itself then runs under `umask 0177`
    with an explicit chmod and a second verification in
    :meth:`UnixTransport.post_bind`.

    **TOCTOU (review log F6):** these `lstat` checks are not atomic with
    `bind()`, so a same-UID process can still swap the path in the window
    between the check and the bind. On Linux, opening the parent with
    `O_PATH | O_NOFOLLOW` narrows the window but cannot make `bind()` atomic;
    the real protections are the `0700` directory, the `SO_PEERCRED` uid check
    on accept and `server_auth` -- not winning this race (doc §9.1, §9.3).
    """
    target = Path(path)
    parent = target.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise RuntimeError(f"refusing to bind {path}: parent {parent} is a symlink")
    # `socket_dir_mode` is enforced even when the directory already existed,
    # so a loosened directory does not persist across restarts.
    _chmod(str(parent), dir_mode)
    _assert_owner_only(str(parent), dir_mode, "socket directory", expect_dir=True)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"refusing to bind {path}: path is a symlink")
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(f"refusing to bind {path}: path exists and is not a socket")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"refusing to bind {path}: socket is not owned by uid {os.getuid()}")
    os.unlink(path)


class Transport:
    """Base class: one dial method and one single-socket listener per instance."""

    name = "transport"
    callback = False

    def __init__(self, config: dict) -> None:
        self.config = config
        self.connect_timeout = float(config.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT))
        # The receive pair is resolved once here (defensively) and re-resolved
        # on demand by `read_timeouts()`. `self.decision_timeout` is the human
        # window -- `None` when `decision_timeout = 0` -- i.e. exactly the value
        # `read_frame` consumes for the final `auth_response`, not the raw config
        # integer.
        self.recv_timeout, self.decision_timeout = resolve_read_timeouts(config)

    # -- client side --

    def family(self) -> int:
        return socket.AF_INET

    def address(self):
        raise NotImplementedError

    def tls_server_name(self) -> str | None:
        """SNI/hostname for the client TLS wrap; None where there is no name."""
        return None

    def read_timeouts(self) -> tuple[float, float | None]:
        """The (first-frame, decision) bounds for the client's two frame reads."""
        return resolve_read_timeouts(self.config)

    def connect(self) -> socket.socket:
        """Dial the peer with a short connect timeout and optional mTLS.

        The short bound covers both the TCP connect and the TLS handshake: a
        peer that accepts the connection but never completes TLS would
        otherwise hang unbounded and stall every `sudo` (doc §10.2). The
        timeout is kept through `wrap_socket` and only cleared once the
        connection is usable; the request/response exchange is bounded
        separately by `read_frame`'s per-frame timeouts.
        """
        sock = socket.socket(self.family(), socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        try:
            sock.connect(self.address())
            ssl_ctx = create_ssl_context(self.config, server=False)
            if ssl_ctx is not None:
                # `wrap_socket` performs the handshake and `_verify_peer_oid`
                # checks the peer EKU, both under the same short timeout, so a
                # half-open/hung peer fails fast instead of hanging.
                sock = ssl_ctx.wrap_socket(sock, server_hostname=self.tls_server_name())
                _verify_peer_oid(sock, self.config, "Server")
        except BaseException:
            sock.close()
            raise
        # Restore blocking mode for the exchange; the read carries its own
        # first-byte and tail bounds (Phase 6).
        sock.settimeout(None)
        return sock

    # -- server side --

    def server_base(self) -> type[BaseServer]:
        return UnixStreamServer

    def prepare_bind(self) -> None:
        """Check/clean the bind target before `bind()` (unix only)."""

    def bind_umask(self) -> int | None:
        """umask to hold across `bind()`, or None to leave it untouched."""
        return None

    def post_bind(self, server) -> None:
        """Fix up the listener after `bind()` (unix permissions, TCP reuse)."""

    def listen(self, handler_cls):
        """Bind the single listening socket and return a threaded server.

        Bounds the pre-authentication resource a peer can consume (audit A3):
        handler threads are daemon threads, at most `max_connections` run at
        once (over-cap connections are refused before a thread is spawned), and
        `server_read_timeout` bounds each accepted socket so an idle pre-auth
        peer is dropped instead of holding a thread forever. The TLS handshake
        runs in the handler thread (`Handler.setup`), not in the accept loop, so
        a stalled handshake consumes one capped worker rather than blocking all
        accepts (Round 2 audit N2).
        """
        ssl_ctx = create_ssl_context(self.config, server=True)
        self.prepare_bind()
        max_connections = _positive_int(
            self.config.get("max_connections"), DEFAULT_MAX_CONNECTIONS
        )
        read_timeout = _positive_float(
            self.config.get("server_read_timeout"), DEFAULT_SERVER_READ_TIMEOUT
        )
        server_class = type(
            "SudoAuthProxyServer",
            (ThreadingMixIn, self.server_base()),
            {
                "address_family": self.family(),
                "ssl_context": ssl_ctx,
                # Daemon threads + no join-on-close: a handler must never block
                # shutdown, and the read timeout already bounds its life.
                "daemon_threads": True,
                "block_on_close": False,
                "_config": self.config,
                "_transport": self,
                "_server_read_timeout": read_timeout,
                "_sap_max_connections": max_connections,
                "_sap_semaphore": threading.BoundedSemaphore(max_connections),
                "request_queue_size": max_connections,
                "get_request": server_get_request,
                "process_request": server_process_request,
                "shutdown_request": server_shutdown_request,
                "handle_error": server_handle_error,
            },
        )
        umask = self.bind_umask()
        old_umask = os.umask(umask) if umask is not None else None
        try:
            server = server_class(self.address(), handler_cls)
        finally:
            if old_umask is not None:
                os.umask(old_umask)
        self.post_bind(server)
        return server

    def cleanup(self) -> None:
        """Release transport resources on shutdown (unix unlinks its socket)."""

    # -- identity --

    def peer_label(self, sock) -> str:
        return "peer"

    def tartarus_peer(self, sock):
        """The VSOCK CID / IP used for `resolution = "tartarus"`, or None."""
        return None

    def authorize_peer(self, sock) -> int | None:
        """Authorize the accepted peer's OS identity; raise to refuse.

        Only the `unix` transport has a meaningful local-uid check (doc §9.1);
        callback transports dial from a network peer with no OS identity to
        compare, so this is a no-op there.
        """
        return None

    def peer_uid(self, sock) -> int | None:
        return None

    def describe(self) -> str:
        return f"{self.name}:{self.address()!r}"


def is_numeric_host(host: str) -> bool:
    """True when `host` is an IPv4/IPv6 numeric literal (never resolved).

    Pure predicate over `inet_pton`, so it neither resolves nor touches the
    network. It exists so the fast path can be asserted directly: an address
    that is already numeric must never trigger DNS (doc §10.2).
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


class CallbackTransport(Transport):
    """`vsock` / `tcp`: the guest dials the host (unchanged call direction)."""

    callback = True

    def __init__(self, config: dict, name: str) -> None:
        super().__init__(config)
        self.name = name
        if name == "vsock" and not hasattr(socket, "AF_VSOCK"):
            raise RuntimeError("VSOCK not supported on this platform")
        self._family = socket.AF_VSOCK if name == "vsock" else socket.AF_INET

    def family(self) -> int:
        return self._family

    def address(self):
        port = int(self.config.get("port", 65001))
        if self.name == "vsock":
            return (int(self.config.get("cid", 2)), port)
        host = self.config.get("host", "127.0.0.1")
        if host == "_gateway":
            host = resolve_default_gateway()
        # A numeric literal is passed to `connect()` verbatim; the resolver
        # treats it as a numeric host and never performs a DNS lookup, so
        # there is no resolution stall on this fast path (doc §10.2). A
        # non-numeric host does resolve, which remains the documented
        # trade-off; `_gateway` above is resolved from /proc, not DNS.
        return (host, port)

    def tls_server_name(self) -> str | None:
        return str(self.address()[0]) if self.name == "tcp" else None

    def server_base(self) -> type[TCPServer]:
        return TCPServer

    def post_bind(self, server) -> None:
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def peer_label(self, sock) -> str:
        peer = sock.getpeername()[0]
        return f"cid {peer}" if isinstance(peer, int) else str(peer)

    def tartarus_peer(self, sock):
        return sock.getpeername()[0]

    def describe(self) -> str:
        return f"{self.name}:{self.address()!r} (callback)"


class UnixTransport(Transport):
    """AF_UNIX transport for the host-dials-guest (SSH RemoteForward) path.

    Server: binds the single `socket` path after the stale/ownership/symlink
    checks and with `umask 0177` then an explicit `socket_mode` chmod, and
    verifies both the directory and socket modes/ownership (doc §9.1). Client:
    dials the path it is constructed with -- in production that is
    `$SUDO_AUTH_PROXY_SOCK` (the per-session selector), never the config
    `socket` key and never a fallback (Phase 2 formalises the resolution;
    Phase 1 already refuses to guess).
    """

    name = "unix"
    callback = False

    def __init__(self, config: dict, path: str | None = None) -> None:
        super().__init__(config)
        if path is None:
            path = expand_socket_path(config.get("socket") or DEFAULT_SOCKET)
        self.path = path
        self._bound_ino: int | None = None

    def family(self) -> int:
        return socket.AF_UNIX

    def address(self):
        return self.path

    def tls_server_name(self) -> str | None:
        return None

    def server_base(self):
        return UnixStreamServer

    def prepare_bind(self) -> None:
        dir_mode = _parse_mode(self.config.get("socket_dir_mode"), DEFAULT_SOCKET_DIR_MODE)
        _prepare_unix_socket(self.path, dir_mode)

    def bind_umask(self) -> int | None:
        # 0177 leaves the freshly bound socket at 0600 before the explicit
        # chmod, so there is never a window where it is group/world-accessible.
        return 0o177

    def post_bind(self, server) -> None:
        mode = _parse_mode(self.config.get("socket_mode"), DEFAULT_SOCKET_MODE)
        _chmod(self.path, mode)
        # The umask already created the socket at 0600; this verification makes a
        # failed chmod fatal instead of silently leaving it wider (doc §9.1).
        _assert_owner_only(self.path, mode, "socket")
        try:
            self._bound_ino = os.lstat(self.path).st_ino
        except OSError:
            self._bound_ino = None

    def cleanup(self) -> None:
        """Unlink the socket this instance bound (never a successor's)."""
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return
        if (
            self._bound_ino is not None
            and info.st_ino == self._bound_ino
            and stat.S_ISSOCK(info.st_mode)
        ):
            with contextlib.suppress(OSError):
                os.unlink(self.path)

    def peer_label(self, sock) -> str:
        try:
            peer = sock.getpeername()
        except OSError:
            peer = None
        if isinstance(peer, str) and peer:
            return peer
        return "local"

    def authorize_peer(self, sock) -> int | None:
        """Refuse a local peer whose uid is not the server user (doc §9.1)."""
        return authorize_unix_peer(sock)

    def peer_uid(self, sock) -> int | None:
        return _unix_peer_uid(sock)

    def describe(self) -> str:
        return f"unix:{self.path}"


def make_transport(config: dict) -> Transport:
    """Build the transport named by `config["transport"]` (default `tcp`)."""
    name = config.get("transport", "tcp")
    if name == "unix":
        return UnixTransport(config)
    if name in ("tcp", "vsock"):
        return CallbackTransport(config, name)
    raise ValueError(f"unknown transport: {name!r}")


def get_peer_name(sock, resolution: str, transport: Transport | None) -> str:
    """Human label for a connection, honouring the configured resolution mode.

    The raw label comes from the transport (`cid N` for VSOCK, the address for
    TCP, the socket path/`local` for unix); `certificate` prefers the verified
    peer CN/SAN, `tartarus` falls back to the local VM bookkeeping and `mofos`
    to `mofos ls --json`, both correlating a CID/IP when the transport provides
    one.
    """
    raw = transport.peer_label(sock) if transport is not None else "peer"

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

    if resolution == "tartarus" and transport is not None:
        peer = transport.tartarus_peer(sock)
        if peer is not None:
            name = resolve_tartarus_name(peer)
            if name:
                return name

    if resolution == "mofos" and transport is not None:
        peer = transport.tartarus_peer(sock)
        if peer is not None:
            name = resolve_mofos_name(peer)
            if name:
                return name

    return raw


def create_ssl_context(config: dict, *, server: bool) -> ssl.SSLContext | None:
    """Build the mTLS context, or None when the channel is not encrypted.

    The decision is driven by the validated `transport_encryption`, not by the
    legacy `mtls.enable` flag alone, so a transport configured for mTLS can
    never silently return None and downgrade to plaintext (doc §7.4). When mTLS
    is required but the certificate configuration is missing, this exits
    non-zero rather than continuing unencrypted.
    """
    try:
        normalized = validate_security_config(config)
    except SecurityConfigError as error:
        print(f"sudo-auth-proxy: {error}", file=sys.stderr)
        sys.exit(1)
    if normalized["transport_encryption"] != "mtls":
        return None

    mtls = config.get("mtls")
    if not isinstance(mtls, dict):
        print(
            "sudo-auth-proxy: transport_encryption = 'mtls' but there is no [mtls] "
            "certificate configuration; refusing to run unencrypted",
            file=sys.stderr,
        )
        sys.exit(1)

    ca_file = mtls.get("ca_file")
    cert_file = mtls.get("cert_file")
    key_file = mtls.get("key_file")

    if not (
        isinstance(ca_file, str)
        and ca_file
        and isinstance(cert_file, str)
        and cert_file
        and isinstance(key_file, str)
        and key_file
    ):
        print(
            "mTLS enabled but ca_file, cert_file, and key_file must all be paths",
            file=sys.stderr,
        )
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
        # Peer identity here is enforced by the EKU OID check (in
        # `_verify_peer_oid`, against the shared CA), not by hostname/IP
        # matching -- the guest's host address is a DHCP lease under macOS
        # vmnet-shared (or a VSOCK CID, not a hostname at all) and the server
        # cert's CN is a template name, not an address, so standard hostname
        # verification can never succeed here and isn't the actual trust
        # mechanism in use.
        context.check_hostname = False
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class Handler(StreamRequestHandler):
    def setup(self) -> None:
        """Complete the TLS handshake in this per-connection thread.

        `server_get_request` returns the raw accepted socket; the handshake runs
        here, **after** `server_process_request` has taken a `max_connections`
        slot, rather than on the single `serve_forever` accept thread (Round 2
        audit N2). A peer that stalls the handshake therefore consumes one
        capped worker instead of blocking every other accept, and
        `server_read_timeout` bounds the handshake. `ssl.SSLContext.wrap_socket`
        performs the handshake eagerly, so no cleartext byte is read before the
        wrap.
        """
        server = self.server
        sock = self.request
        read_timeout = getattr(server, "_server_read_timeout", None)
        if read_timeout is not None:
            with contextlib.suppress(OSError):
                sock.settimeout(read_timeout)
        ssl_context = getattr(server, "ssl_context", None)
        if ssl_context is not None:
            try:
                sock = ssl_context.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError) as error:
                print(
                    f"SSL handshake failed from {self.client_address}: {error}",
                    file=sys.stderr,
                )
                with contextlib.suppress(OSError):
                    sock.close()
                raise
            # Hand the wrapped socket to the base setup so `rfile`/`wfile` are
            # built over it; re-apply the read timeout lost by the wrap.
            self.request = sock
            if read_timeout is not None:
                with contextlib.suppress(OSError):
                    sock.settimeout(read_timeout)
        super().setup()

    def handle(self) -> None:
        config = getattr(self.server, "_config", {})
        set_debug(config)
        transport = getattr(self.server, "_transport", None)

        # The security model is validated and its keys loaded once for the
        # listener (`run_server` attaches it); fall back to building it here so
        # the handler is still correct when driven directly. A config error is
        # fatal per connection and fails closed.
        security = getattr(self.server, "_security", None)
        if security is None:
            try:
                security = build_security(config, "server")
            except (SecurityConfigError, AuthError) as error:
                print(f"sudo-auth-proxy server: {error}", file=sys.stderr)
                return
        use_cert = security.transport_encryption == "mtls"

        # Enforce peer EKU OID on server side, once per connection -- the
        # peer's certificate/identity doesn't change across the requests a
        # connection may carry. The DER is kept for the ACL too: `mode = "list"`
        # pins the leaf SPKI and `mode = "ca"` re-validates the chain.
        peer_cert_der: bytes | None = None
        if use_cert and hasattr(self.request, "getpeercert"):
            peer_cert_der = self.request.getpeercert(binary_form=True)
            mtls = config.get("mtls", {})
            peer_oid = mtls.get("peer_required_oid") if isinstance(mtls, dict) else None
            if peer_oid and peer_cert_der:
                try:
                    verify_cert_der(peer_cert_der, peer_oid, "Peer")
                except (ValueError, RuntimeError) as e:
                    print(f"sudo-auth-proxy: {e}", file=sys.stderr)
                    return

        resolution = get_resolution_mode(config)
        # The peer label is derived from the transport (a name, address or
        # certificate CN) and is display/log-only: it never gates anything, so
        # it is sanitised once here and every later use is already safe (doc
        # §11.2; review log NF8).
        peer = sanitize_field(get_peer_name(self.request, resolution, transport))
        # Refuse a local peer that is not the server user before reading a
        # single byte (doc §9.1; review log F12). Linux `SO_PEERCRED` is
        # authoritative and fails closed; Darwin degrades to the weaker
        # path/ownership guarantee (residual R11) rather than accept silently.
        if transport is not None:
            try:
                transport.authorize_peer(self.request)
            except RuntimeError as error:
                print(
                    f"sudo-auth-proxy server: refused connection from {peer}: {error}",
                    file=sys.stderr,
                )
                return
        dialog_program = config.get("dialog_program") or ("swiftdialog" if sys.platform == "darwin" else "zenity")
        peer_uid = transport.peer_uid(self.request) if transport is not None else None
        uid_note = "" if peer_uid is None else f", uid={peer_uid}"
        print(
            f"sudo-auth-proxy server: connection from {peer} ({self.client_address}{uid_note})",
            flush=True,
        )

        # One client invocation sends one request and closes; a malformed frame
        # or a failed authentication ends the connection immediately (fail
        # closed) rather than trying to resynchronise a stream we no longer
        # trust or answer an unauthenticated request.
        while True:
            t0 = time.monotonic()
            try:
                message = read_message(self.rfile)
            except ConnectionClosed:
                break
            except ProtocolError as e:
                print(f"sudo-auth-proxy server: malformed frame from {peer}: {e}", file=sys.stderr)
                break
            except OSError as e:
                # The accepted socket carries `server_read_timeout`, so an idle
                # pre-auth peer hits this instead of holding the thread forever
                # (audit A3). Fail closed and let the connection close.
                print(
                    f"sudo-auth-proxy server: no request from {peer}: {e}",
                    file=sys.stderr,
                )
                break
            try:
                request = parse_request(message)
            except ProtocolError as e:
                print(f"sudo-auth-proxy server: malformed request from {peer}: {e}", file=sys.stderr)
                break
            # Authentication first (prove the credential), then authorization
            # (the `[acl]` decides whether that *verified* credential may
            # proceed). The ACL runs before any dialog and matches only the
            # credential, never the request metadata (doc §8; review log S11).
            try:
                requester = authenticate_request(request, security, peer_cert_der=peer_cert_der)
            except AuthError as e:
                print(f"sudo-auth-proxy server: rejected request from {peer}: {e}", file=sys.stderr)
                break
            try:
                label = authorize_request(
                    request, security, requester, peer_cert_der=peer_cert_der
                )
            except AuthError as e:
                # Fail closed but not silently: an authenticated requester the
                # ACL rejects gets an explicit deny (signed when configured).
                print(f"sudo-auth-proxy server: denied request from {peer}: {e}", file=sys.stderr)
                response = build_response(
                    request["nonce"],
                    "deny",
                    request=request,
                    security=security,
                    approver=config.get("approver") or os.environ.get("USER", ""),
                )
                with contextlib.suppress(ProtocolError, OSError):
                    write_message(self.wfile, response)
                break
            # Approval refinement (`[[acl.rule]]`). The ACL above authorized the
            # credential; these rules only decide whether to auto-allow,
            # auto-deny or prompt, matching the resolved identity plus the
            # (self-reported) request metadata. An auto-decision answers
            # immediately, exactly like an ACL denial, so the client's
            # first-frame bound still applies and no dialog is raised.
            policy = evaluate_rules(
                security.acl.rules if security.acl else (),
                identities=identity_candidates(
                    requester=requester, label=label, peer=peer
                ),
                target_user=effective_target_user(
                    request.get("service", ""),
                    request.get("target_user", ""),
                    request.get("invoking_user", ""),
                ),
                invoking_user=request.get("invoking_user", ""),
                service=request.get("service", ""),
            )
            if policy in ("allow", "deny"):
                print(
                    f"sudo-auth-proxy server: rule {policy} for {peer} "
                    f"(requester={sanitize_field(requester)!r})",
                    file=sys.stderr,
                )
                response = build_response(
                    request["nonce"],
                    policy,
                    request=request,
                    security=security,
                    approver=config.get("approver") or os.environ.get("USER", ""),
                )
                with contextlib.suppress(ProtocolError, OSError):
                    write_message(self.wfile, response)
                break
            # The request is authenticated AND authorized, and no rule decided
            # it: acknowledge it immediately, *before* blocking on the human, so
            # the client's short first-frame bound stays short and the human wait
            # is bounded by `decision_timeout` (doc §6.2a; audit A2). The frame
            # carries no decision and is not signed; it is validated only by
            # nonce.
            try:
                write_message(self.wfile, build_pending(request["nonce"]))
            except (ProtocolError, OSError):
                # The peer hung up between its request and the ack; nothing to
                # answer, so do not raise a dialog for a request nobody awaits.
                break
            # Build the sanitised dialog context from the *verified* identity
            # and label plus the request metadata (doc §11.1). The command is
            # not part of the protocol, so it can neither be shown nor logged
            # (doc §5.4; review log S5).
            confirmation = build_confirmation(
                peer=peer,
                identity=requester,
                label=label,
                request=request,
                transport=getattr(transport, "name", "unknown"),
            )
            # NF8: log only the sanitised projection of the request, never the
            # raw fields or bytes, so a crafted field cannot forge a log line or
            # inject control/ANSI sequences.
            _debug(
                f"server: request from {peer} "
                f"(requester={confirmation.identity!r}, "
                f"label={confirmation.label!r}, "
                f"fields={sanitize_request_fields(request)!r})"
            )
            allowed = prompt_for_confirmation(confirmation, dialog_program)
            response = build_response(
                request["nonce"],
                "allow" if allowed else "deny",
                request=request,
                security=security,
                approver=config.get("approver") or os.environ.get("USER", ""),
            )
            try:
                write_message(self.wfile, response)
            except (ProtocolError, OSError):
                break
            _debug(f"server: replied to {peer} in {_ms(time.monotonic() - t0)}")


def server_process_request(self, request, client_address):
    """Spawn a handler thread only while under `max_connections` (audit A3).

    A pre-authentication flood must not create an unbounded number of handler
    threads. The semaphore is acquired non-blocking before the thread is
    spawned; an over-cap peer is refused here (its socket closed) instead of
    being queued. The slot is released by `server_shutdown_request`, which the
    handler thread (or `BaseServer`) calls exactly once per accepted request.
    """
    if not self._sap_semaphore.acquire(blocking=False):
        print(
            f"sudo-auth-proxy server: refusing connection from {client_address}: "
            f"connection limit ({self._sap_max_connections}) reached",
            file=sys.stderr,
            flush=True,
        )
        with contextlib.suppress(OSError):
            request.close()
        return
    ThreadingMixIn.process_request(self, request, client_address)


def server_shutdown_request(self, request):
    """Close a request and return its concurrency slot (audit A3)."""
    try:
        TCPServer.shutdown_request(self, request)
    finally:
        self._sap_semaphore.release()


def server_get_request(self):
    """Accept a connection and return the raw socket with a read bound.

    The TLS handshake deliberately does **not** happen here. `get_request` runs
    on the single `serve_forever` accept thread, so wrapping here let one peer
    stall the handshake and block *every* other accept for up to
    `server_read_timeout` (Round 2 audit N2). The raw socket is handed to
    `process_request`, which takes a `max_connections` slot before spawning the
    handler thread; `Handler.setup` performs the handshake there, so a stalled
    handshake consumes one capped worker instead of the accept loop. The read
    timeout set here still bounds the accept and is re-applied after the wrap.
    """
    sock, addr = TCPServer.get_request(self)
    read_timeout = getattr(self, "_server_read_timeout", None)
    if read_timeout is not None:
        with contextlib.suppress(OSError):
            sock.settimeout(read_timeout)
        print(f"sudo-auth-proxy server: accepted TCP connection from {addr}", flush=True)
    return sock, addr


def server_handle_error(self, request, client_address):
    """Report a per-connection failure without a traceback for expected ones.

    With the TLS handshake in the handler thread (audit N2), a peer that stalls
    or aborts the handshake is routine, not a server bug; the default
    `BaseServer.handle_error` would dump a traceback for every such connection.
    Expected transport errors are logged as a single line instead; anything
    else still goes through the default reporting.
    """
    error = sys.exc_info()[1]
    if isinstance(
        error, (ssl.SSLError, ConnectionError, TimeoutError, socket.timeout)
    ):
        print(
            f"sudo-auth-proxy server: connection from {client_address} failed: {error}",
            file=sys.stderr,
        )
        return
    BaseServer.handle_error(self, request, client_address)


def run_server(config: dict) -> None:
    set_debug(config)
    try:
        security = build_security(config, "server")
    except (SecurityConfigError, AuthError) as error:
        print(f"sudo-auth-proxy server: {error}", file=sys.stderr)
        sys.exit(1)
    transport = make_transport(config)
    server = transport.listen(Handler)
    # `listen` builds a dynamic `SudoAuthProxyServer` class, so `setattr` is the
    # honest way to hang the per-listener security model on it: `Handler.handle`
    # reads it back with `getattr`, and a static checker cannot see the attribute
    # on a class that only exists at runtime.
    setattr(server, "_security", security)  # noqa: B010 -- dynamic class attribute
    tls_enabled = getattr(server, "ssl_context", None) is not None
    if not acl_allows_any(security.acl):
        print(
            "sudo-auth-proxy server: WARNING: the [acl] allows nobody "
            "(empty trust list); every request will be denied",
            file=sys.stderr,
        )
    try:
        print(
            f"sudo-auth-proxy server listening on {transport.describe()} "
            f"(transport={transport.name}, tls={tls_enabled})",
            flush=True,
        )
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    finally:
        server.server_close()
        transport.cleanup()


def collect_request_fields() -> dict:
    """Snapshot the PAM/session metadata that goes into the request.

    `pam_exec` exports the PAM items it was given as environment variables
    (PAM_SERVICE, PAM_USER, PAM_RUSER, PAM_RHOST, PAM_TTY), so the client can
    build the request without needing extra arguments. All values are
    best-effort strings -- Phase 1 carries them; Phase 3 binds them with the
    signature and Phase 7 sanitises them before display.
    """
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    invoking_user = (
        os.environ.get("PAM_RUSER")
        or os.environ.get("SUDO_USER")
        or os.environ.get("USER")
        or os.environ.get("LOGNAME")
        or ""
    )
    return {
        "service": os.environ.get("PAM_SERVICE", ""),
        "target_user": os.environ.get("PAM_USER", ""),
        "invoking_user": invoking_user,
        "rhost": os.environ.get("PAM_RHOST", ""),
        "tty": os.environ.get("PAM_TTY", ""),
        "cwd": cwd,
    }


def recursion_guard_active() -> bool:
    """True when this client would re-enter an already-running proxy session.

    The guard (``SUDO_AUTH_PROXY_ACTIVE``) is set by
    :func:`activate_recursion_guard` while the client runs and is preserved
    across ``sudo`` by the guest's mandated
    ``Defaults env_keep += "SUDO_AUTH_PROXY_ACTIVE"`` sudoers entry (doc §4.3,
    §10.4). If it is already set, a nested ``sudo``/``su`` is allowed to fail
    fast (PAM continues) instead of opening a second dialog.
    """
    return bool(os.environ.get(RECURSION_GUARD_ENV))


def activate_recursion_guard() -> None:
    """Mark this process tree as already going through the proxy.

    Sets the guard for the current client process. Its propagation to a nested
    ``sudo`` depends entirely on the deployed ``sudoers env_keep`` entry
    (doc §10.4; review log B2) -- without that entry ``env_reset`` strips it.
    """
    os.environ[RECURSION_GUARD_ENV] = "1"


def verify_selector_socket(path: str) -> None:
    """Best-effort ``lstat`` validation of the `unix` selector before connect.

    Refuses a symlink, a non-socket, or a socket not owned by the expected
    user (the invoking user from ``SUDO_UID``, else this process's uid), raising
    ``RuntimeError`` so the caller fails closed. This is deliberately the same
    shape as the server-side bind check.

    The check is **not** atomic with ``connect()`` (TOCTOU, review log F6): a
    same-UID peer can still swap the path in between. It raises the bar; the
    Linux ``SO_PEERCRED`` peer-process check and ``server_auth`` are what do
    not depend on winning that race (doc §9.2).
    """
    uid_env = os.environ.get("SUDO_UID")
    expected_uid = int(uid_env) if uid_env else os.getuid()
    try:
        info = os.lstat(path)
    except OSError as error:
        raise RuntimeError(f"cannot stat selector socket {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"refusing selector {path}: path is a symlink")
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(f"refusing selector {path}: path is not a socket")
    if info.st_uid != expected_uid:
        raise RuntimeError(
            f"refusing selector {path}: socket is not owned by uid {expected_uid}"
        )


def _fail_unavailable(reason: str) -> "NoReturn":
    """Print the `unavailable` reason and exit non-zero (doc §6.7).

    `pam_exec.so` collapses any non-zero exit to one generic failure, so the
    exit code cannot carry the denied/unavailable distinction; the message
    can, and is what the logs show. There is deliberately no separate exit
    code for `denied` (PAM could not act on it, and it would only invite
    false confidence).

    The `NoReturn` annotation is load-bearing for more than typing: it is what
    tells the type checker (and the reader) that every caller's `sock`,
    `response` and `request` are bound after this call, which is exactly the
    control flow this function implements.
    """
    print(f"sudo-auth-proxy client: unavailable: {reason}", file=sys.stderr)
    sys.exit(1)


def run_client(config: dict) -> None:
    # Recursion guard first, before any work: a nested elevation must not open a
    # second dialog or connect at all. Exit non-zero so PAM continues (doc
    # §10.4; the guard's survival across `sudo` is enforced by the guest's
    # mandated sudoers env_keep).
    if recursion_guard_active():
        print(
            "sudo-auth-proxy client: SUDO_AUTH_PROXY_ACTIVE is set; refusing to re-enter",
            file=sys.stderr,
        )
        sys.exit(1)
    activate_recursion_guard()

    transport = make_transport(config)
    if transport.name == "unix":
        # The selector is the only acceptable source for the guest-side socket
        # path (doc §4.3). There is no static-config fallback and no /proc
        # lookup: a process without the selector fails closed.
        selector = os.environ.get("SUDO_AUTH_PROXY_SOCK")
        if not selector:
            print(
                "sudo-auth-proxy client: SUDO_AUTH_PROXY_SOCK is not set; refusing to guess a socket path",
                file=sys.stderr,
            )
            sys.exit(1)
        transport = UnixTransport(config, path=selector)
        # Best-effort lstat checks before connecting; fail closed (doc §9.2).
        try:
            verify_selector_socket(transport.path)
        except RuntimeError as error:
            _debug(f"selector check failed: {error!r}")
            print(f"sudo-auth-proxy client: {error}", file=sys.stderr)
            sys.exit(1)

    # Validate the security model and load this role's keys before opening
    # anything; a missing key or an invalid combination is fatal (fail closed,
    # no unauthenticated request).
    try:
        security = build_security(config, "client")
    except (SecurityConfigError, AuthError) as error:
        print(f"sudo-auth-proxy client: {error}", file=sys.stderr)
        sys.exit(1)

    _debug(f"client: transport={transport.name} target={transport.describe()!r}")

    try:
        sock = transport.connect()
    except Exception as e:  # noqa: BLE001 -- any connect failure means "unavailable"
        _debug(f"connection failed: {e!r}")
        _fail_unavailable(f"connection failed: {e}")

    if transport.name == "unix":
        # Linux-only routing hardening: require the connected peer's executable
        # to be sshd (doc §9.2, review log T21). `None` means the check is
        # unavailable (macOS has no /proc) and we degrade to the path checks
        # above; `False` means the peer is live but is not sshd, so fail closed.
        peer_is_sshd = verify_unix_peer_is_sshd(sock)
        if peer_is_sshd is False:
            try:
                sock.close()
            except Exception as error:  # noqa: BLE001 -- closing is best-effort
                _debug(f"sock.close() failed: {error!r}")
            _debug("unix peer executable is not sshd; refusing to use the tunnel")
            print(
                "sudo-auth-proxy client: connected unix peer is not sshd; refusing",
                file=sys.stderr,
            )
            sys.exit(1)

    nonce = base64.b64encode(os.urandom(32)).decode("ascii")
    response = None
    request = None
    try:
        fields = collect_request_fields()
        request = build_request(
            nonce,
            service=fields["service"],
            target_user=fields["target_user"],
            invoking_user=fields["invoking_user"],
            rhost=fields["rhost"],
            tty=fields["tty"],
            cwd=fields["cwd"],
            client_version=config.get("client_version") or CLIENT_VERSION,
            guest_hint=config.get("guest_hint") or socket.gethostname(),
        )
        # Sign (ssh/x509) or mark the request as channel-authenticated (mTLS)
        # before it leaves the process.
        attach_client_auth(request, security)
        # Serialise through `write_message` so the frame size cap is still
        # enforced, then send the bytes with `sendall`.
        outbound = io.BytesIO()
        write_message(outbound, request)
        sock.sendall(outbound.getvalue())
        recv_timeout, decision_timeout = transport.read_timeouts()
        # Read through a buffered reader: one exchange carries two frames
        # (`auth_pending` then `auth_response`) and the server may emit both in
        # one segment, so a raw `recv` could swallow the second frame (see
        # `read_frame`). The per-frame timeout still gives stale-socket
        # fast-fail on the first frame (review log NF4).
        rfile = sock.makefile("rb")
        try:
            # Phase 1: the first frame is normally the immediate `auth_pending`
            # ack (doc §6.2a; audit A2), bounded by the short `recv_timeout`. It
            # can also be a direct `auth_response`: the ACL answers a denial
            # without raising a dialog, and a pre-A2 server sends no ack at all.
            first = read_frame(rfile, sock, recv_timeout)
            if first.get("type") == PENDING_TYPE:
                # Validate the ack strictly (matching nonce) and then wait for
                # the final decision under `decision_timeout` -- the human window
                # (`0` = wait). The first byte of the final frame is the human's
                # answer, so the decision bound applies here, not the short
                # first-frame bound that just proved the server is alive.
                parse_pending(first, request["nonce"])
                response = read_frame(rfile, sock, decision_timeout)
            else:
                # A direct response; validated as an `auth_response` below. A
                # missing/unknown type fails closed there.
                response = first
        finally:
            rfile.close()
    except (ProtocolError, AuthError, ConnectionClosed, OSError) as e:
        _debug(f"request failed: {e!r}")
        _fail_unavailable(f"no valid decision: {e}")
    finally:
        try:
            sock.close()
        except Exception as error:  # noqa: BLE001 -- closing is best-effort
            _debug(f"sock.close() failed: {error!r}")

    consumed_nonces: set = set()
    try:
        decision = verify_response(response, request, security, consumed_nonces)
    except (ProtocolError, AuthError) as e:
        _debug(f"response rejected: {e!r}")
        _fail_unavailable(f"no valid decision: {e}")

    _debug(f"final decision: {decision}")
    if decision == "allow":
        sys.exit(0)
    # A valid human `deny`: log it distinctly from `unavailable`. PAM cannot
    # branch on this (both are non-zero), so the distinction is logging-only
    # (doc §6.7); `pam_exec` collapses the exit code.
    print("sudo-auth-proxy client: denied", file=sys.stderr)
    sys.exit(1)


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
    # The whole file is validated against the exact schema first, so a typo or a
    # key on the wrong side of a TOML table header is named here rather than
    # surfacing as a missing-knob error further down (doc §7.9). This runs before
    # the `mode` check so `Mode = "server"` reports the misspelled key instead of
    # "missing required 'mode'".
    try:
        validate_config_schema(config, source=args.config)
    except SecurityConfigError as error:
        print(f"sudo-auth-proxy: {error}", file=sys.stderr)
        sys.exit(1)
    # `mode` is required and fail-closed (audit A10): a hand-written config that
    # forgets it must not silently start a listener. The generated TOML always
    # emits a mode, so this only guards against operator error.
    mode = config.get("mode")
    if mode is None:
        print(
            "sudo-auth-proxy: missing required 'mode' key (expected 'client' or 'server')",
            file=sys.stderr,
        )
        sys.exit(1)

    if mode == "server":
        run_server(config)
    elif mode == "client":
        run_client(config)
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

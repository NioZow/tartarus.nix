#!/usr/bin/env python3
"""Root guest helper for tartarus runtime mounts.

The host stages a directory under /run/tartarus-mount/staging/<id>; this
helper accepts only an opaque id from the client and performs the final bind,
read-only bind or overlay mount inside the guest. It never accepts a source
path from the client.
"""

import argparse
import grp
import json
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

RUN_DIR = Path("/run/tartarus-mount")
SOCKET_PATH = RUN_DIR / "control.sock"
STATE_FILE = RUN_DIR / "state.json"
STAGING_DIR = RUN_DIR / "staging"
OVERLAY_DIR = RUN_DIR / "overlays"

MOUNT_USER = os.environ.get("TARTARUS_MOUNT_USER", "user")
MOUNT_GROUP = os.environ.get("TARTARUS_MOUNT_GROUP", "users")

MOUNT_BIN = shutil.which("mount") or "mount"
UMOUNT_BIN = shutil.which("umount") or "umount"

ID_RE = re.compile(r"[A-Za-z0-9_-]+")
MODES = ("rw", "ro", "overlay")
FORBIDDEN_TARGETS = ("/", "/proc", "/sys", "/dev", "/run/tartarus-mount")
MAX_REQUEST = 1024 * 1024


def validate_id(value):
    """Return a validated staging id or raise ValueError."""
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"invalid mount id: {value!r}")
    return value


def validate_target(target):
    """Normalize and validate a guest mount target."""
    if not isinstance(target, str) or not target:
        raise ValueError("mount target must be a non-empty string")
    normalized = os.path.normpath(target)
    if not os.path.isabs(normalized):
        raise ValueError(f"mount target must be absolute: {target!r}")
    for forbidden in FORBIDDEN_TARGETS:
        if normalized == forbidden or (forbidden != "/" and normalized.startswith(forbidden + "/")):
            raise ValueError(f"refusing reserved mount target: {normalized}")
    return normalized


def read_state(path):
    """Read the mount state, returning [] when missing or malformed."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def write_state(path, entries):
    """Atomically write the mount state with restrictive permissions."""
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory,
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise RuntimeError(str(exc)) from exc
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise RuntimeError(detail or f"command failed: {' '.join(command)}")
    return result


def _uid_gid(user, group):
    return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid


def _chown_tree(path, uid, gid):
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid, gid)


def _same_record(entry, identifier, target, mode):
    return (
        isinstance(entry, dict)
        and entry.get("id") == identifier
        and entry.get("target") == target
        and entry.get("mode") == mode
    )


def mount_op(id, target, mode, *, staging_dir, overlay_dir, state_file, user, group):
    """Perform one mount operation and record it."""
    identifier = validate_id(id)
    target = validate_target(target)
    if mode not in MODES:
        raise ValueError(f"invalid mount mode: {mode!r}")

    source = os.path.join(os.fspath(staging_dir), identifier)
    if not os.path.isdir(source):
        raise RuntimeError(f"staging path does not exist: {source}")

    entries = read_state(state_file)
    for entry in entries:
        if _same_record(entry, identifier, target, mode):
            return entry
        if isinstance(entry, dict) and entry.get("target") == target:
            raise RuntimeError(f"target is already managed: {target}")

    if os.path.ismount(target):
        raise RuntimeError(f"target is already a mountpoint: {target}")

    if not os.path.isdir(target):
        os.makedirs(target)
        uid, gid = _uid_gid(user, group)
        os.chown(target, uid, gid)

    if mode == "rw":
        _run([MOUNT_BIN, "--bind", source, target])
    elif mode == "ro":
        _run([MOUNT_BIN, "--bind", source, target])
        _run([MOUNT_BIN, "-o", "remount,ro,bind", target])
    else:
        overlay = os.path.join(os.fspath(overlay_dir), identifier)
        upper = os.path.join(overlay, "upper")
        work = os.path.join(overlay, "work")
        os.makedirs(upper, exist_ok=True)
        os.makedirs(work, exist_ok=True)
        uid, gid = _uid_gid(user, group)
        _chown_tree(overlay, uid, gid)
        options = f"lowerdir={source},upperdir={upper},workdir={work},userxattr"
        _run([MOUNT_BIN, "-t", "overlay", "overlay", "-o", options, target])

    entry = {
        "id": identifier,
        "target": target,
        "mode": mode,
        "stage": source,
    }
    entries.append(entry)
    write_state(state_file, entries)
    return entry


def umount_op(target, *, overlay_dir, state_file):
    """Unmount a managed target and drop its record."""
    target = validate_target(target)
    entries = read_state(state_file)
    record = next(
        (entry for entry in entries if isinstance(entry, dict) and entry.get("target") == target),
        None,
    )
    if record is None:
        raise RuntimeError(f"target is not managed: {target}")

    try:
        _run([UMOUNT_BIN, target])
    except RuntimeError:
        _run([UMOUNT_BIN, "-l", target])

    if record.get("mode") == "overlay":
        overlay = os.path.join(os.fspath(overlay_dir), str(record.get("id", "")))
        shutil.rmtree(overlay, ignore_errors=True)

    remaining = [entry for entry in entries if entry is not record]
    write_state(state_file, remaining)
    return record


def list_op(state_file):
    """Return live mount records, persisting the filtered state."""
    entries = read_state(state_file)
    live = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("target"), str)
        and os.path.ismount(entry["target"])
    ]
    write_state(state_file, live)
    return live


def _allowed_uid():
    try:
        return pwd.getpwnam(MOUNT_USER).pw_uid
    except KeyError:
        return None


def _peer_uid(connection):
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _peer_allowed(connection):
    uid = _peer_uid(connection)
    return uid == 0 or uid == _allowed_uid()


def _send(connection, response):
    connection.sendall(json.dumps(response, sort_keys=True).encode("utf-8") + b"\n")


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    op = request.get("op")
    if op == "mount":
        entry = mount_op(
            request.get("id"),
            request.get("target"),
            request.get("mode"),
            staging_dir=STAGING_DIR,
            overlay_dir=OVERLAY_DIR,
            state_file=STATE_FILE,
            user=MOUNT_USER,
            group=MOUNT_GROUP,
        )
        return {"ok": True, "mount": entry}
    if op == "umount":
        record = umount_op(
            request.get("target"),
            overlay_dir=OVERLAY_DIR,
            state_file=STATE_FILE,
        )
        return {"ok": True, "removed": record}
    if op == "list":
        return {"ok": True, "mounts": list_op(STATE_FILE)}
    raise ValueError(f"unknown operation: {op!r}")


def _handle_connection(connection):
    if not _peer_allowed(connection):
        _send(connection, {"ok": False, "error": "permission denied"})
        return
    data = b""
    while b"\n" not in data and len(data) <= MAX_REQUEST:
        chunk = connection.recv(65536)
        if not chunk:
            break
        data += chunk
    line = data.split(b"\n", 1)[0]
    try:
        request = json.loads(line.decode("utf-8"))
        response = dispatch(request)
    except (ValueError, RuntimeError, KeyError, TypeError, OSError) as exc:
        response = {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to a client
        response = {"ok": False, "error": str(exc)}
    _send(connection, response)


def serve():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    try:
        gid = grp.getgrnam(MOUNT_GROUP).gr_gid
    except KeyError:
        gid = os.getgid()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    os.chmod(SOCKET_PATH, 0o660)
    os.chown(SOCKET_PATH, 0, gid)
    server.listen(16)

    def stop(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                _handle_connection(connection)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.close()
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
    return 0


def _request(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(SOCKET_PATH))
        client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        data = b""
        while b"\n" not in data and len(data) <= MAX_REQUEST:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8"))


def _print(response):
    print(json.dumps(response, indent=2, sort_keys=True))


def client_mount(args):
    response = _request({"op": "mount", "id": args.id, "target": args.target, "mode": args.mode})
    _print(response)
    return 0 if response.get("ok") else 1


def client_umount(args):
    response = _request({"op": "umount", "target": args.target})
    _print(response)
    return 0 if response.get("ok") else 1


def client_list(_args):
    response = _request({"op": "list"})
    _print(response)
    return 0 if response.get("ok") else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="tartarus-mount",
        description="Runtime mount helper for tartarus guests",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="run the control socket server")
    serve_parser.set_defaults(func=lambda _args: serve())

    mount_parser = subparsers.add_parser("mount", help="mount a staged directory")
    mount_parser.add_argument("id")
    mount_parser.add_argument("target")
    mount_parser.add_argument("mode", choices=MODES)
    mount_parser.set_defaults(func=client_mount)

    umount_parser = subparsers.add_parser("umount", help="unmount a managed target")
    umount_parser.add_argument("target")
    umount_parser.set_defaults(func=client_umount)

    list_parser = subparsers.add_parser("list", help="list live runtime mounts")
    list_parser.set_defaults(func=client_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

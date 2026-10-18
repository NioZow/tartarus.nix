"""Runtime mounts: attach host folders to already-running guests.

This module implements ``tartarus mount``, ``tartarus unmount`` and
``tartarus mounts``: spec parsing, target validation, the per-guest
runtime-mount state file, listing/status, and lifecycle cleanup.

For VMs, mount records are staged on the host with ``sudo mount --bind`` and
attached inside the guest through the ``tartarus-mount`` helper. For
containers, records are staged under the guest root and attached inside the
container's mount namespace (with idmapped binds when ownership requires it,
and an overlay view for read-write mounts of read-only shares). Successful
mounts are recorded with ``id``, ``kind``, ``source``, ``target``, ``mode``
and (for VMs) ``stage``; unmounting and guest teardown release the stages.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import ctn, process, ssh, system
from .config import Config
from .errors import TartarusError
from .output import ok, print_table, warn

STATE_NAME = "runtime-mounts.json"
STAGING_NAME = "mounts"
RESERVED_TARGETS = ("/", "/proc", "/sys", "/dev", "/run/tartarus-mount")

MOUNT_HELPER = "/run/current-system/sw/bin/tartarus-mount"
GUEST_STAGING = "/run/tartarus-mount/staging"

# Every tartarus guest uses this account and home (nix/guest/build.nix).
GUEST_HOME = "/home/user"


def parse_spec(value: str, *, cwd: Path | None = None) -> tuple[Path, str]:
    """Split ``HOST_PATH:GUEST_PATH`` into a resolved host dir and a target.

    The split happens on the first ``:``; colons are therefore not supported
    inside either path. Relative host paths are resolved against ``cwd`` (the
    caller's cwd by default) and ``~`` is expanded on both sides -- on the
    guest side, ``~`` means the guest home (``/home/user``), not the host
    user's home. The host path must be an existing directory (symlinks are
    resolved).
    """
    if ":" not in value:
        raise TartarusError(
            f"invalid mount spec {value!r}: expected HOST_PATH:GUEST_PATH"
        )
    host_part, _, guest_part = value.partition(":")
    if not host_part:
        raise TartarusError(
            f"invalid mount spec {value!r}: host path is empty "
            "(expected HOST_PATH:GUEST_PATH)"
        )
    if not guest_part:
        raise TartarusError(
            f"invalid mount spec {value!r}: guest path is empty "
            "(expected HOST_PATH:GUEST_PATH)"
        )

    target = validate_target(guest_part)

    base = Path(cwd) if cwd is not None else Path.cwd()
    source = Path(host_part).expanduser()
    if not source.is_absolute():
        source = base / source
    try:
        source = source.resolve(strict=True)
    except FileNotFoundError:
        raise TartarusError(
            f"host path does not exist: {host_part!r} "
            f"(resolved to {source})"
        ) from None
    except OSError as exc:
        raise TartarusError(f"cannot resolve host path {host_part!r}: {exc}") from exc

    if not source.is_dir():
        raise TartarusError(f"host path is not a directory: {source}")

    return source, target


def expand_guest_path(target: str, *, guest_home: str = GUEST_HOME) -> str:
    """Expand a leading ``~`` to the guest home, leaving other paths alone."""
    if target == "~":
        return guest_home
    if target.startswith("~/"):
        return guest_home + target[1:]
    if target.startswith("~"):
        raise TartarusError(
            f"guest path {target!r}: only '~' and '~/' expand to the guest home "
            f"({guest_home})"
        )
    return target


def validate_target(target: str, *, guest_home: str = GUEST_HOME) -> str:
    """Normalize and validate a guest mount point, returning its clean form."""
    if not target:
        raise TartarusError("guest path is empty")
    target = expand_guest_path(target, guest_home=guest_home)
    if not target.startswith("/"):
        raise TartarusError(
            f"guest path must be absolute: {target!r} (expected a path like /home/user/src)"
        )

    normalized = os.path.normpath(target)
    for reserved in RESERVED_TARGETS:
        if normalized == reserved or (
            reserved != "/" and normalized.startswith(reserved + "/")
        ):
            raise TartarusError(
                f"guest path {normalized!r} is reserved for the runtime-mount "
                "mechanism; choose a different mount point"
            )
    return normalized


def resolve_mode(*, read_only: bool, overlay: bool) -> str:
    """Map the two mode flags to the wire mode string."""
    if read_only and overlay:
        raise TartarusError("--read-only and --overlay are mutually exclusive")
    if overlay:
        return "overlay"
    if read_only:
        return "ro"
    return "rw"


def staging_root(config: Config, name: str) -> Path:
    """Host staging directory shared with the guest (``<state>/<name>/mounts``)."""
    return config.state_dir(name) / STAGING_NAME


def state_path(config: Config, name: str) -> Path:
    """Per-guest runtime-mount state file."""
    return config.state_dir(name) / STATE_NAME


def read_state(config: Config, name: str) -> list[dict]:
    """Return the guest's recorded mounts; missing or malformed state is ``[]``."""
    path = state_path(config, name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def write_state(config: Config, name: str, entries: list[dict]) -> None:
    """Atomically replace the guest's state file with ``entries`` (mode 0600)."""
    path = state_path(config, name)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2)
            fh.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def append_record(config: Config, name: str, record: dict) -> None:
    """Append one mount record to the guest's state file."""
    entries = read_state(config, name)
    entries.append(record)
    write_state(config, name, entries)


def find_record(config: Config, name: str, target: str) -> dict | None:
    """Return the record for ``target`` on ``name``, or ``None``."""
    for record in read_state(config, name):
        if record.get("target") == target:
            return record
    return None


def remove_record(config: Config, name: str, target: str) -> None:
    """Drop the record for ``target`` (idempotent)."""
    entries = [record for record in read_state(config, name) if record.get("target") != target]
    write_state(config, name, entries)


def _status_for(config: Config, guest: str, record: dict) -> str:
    """``"running"`` or ``"stale"`` for one record, based on its guest kind."""
    kind = record.get("kind")
    if kind not in ("vm", "container"):
        found = config.find_guest(guest)
        kind = found.kind if found is not None else None

    if kind == "vm":
        return "running" if ssh.is_running(config, guest) else "stale"

    if kind == "container":
        found = config.find_guest(guest)
        if found is not None and found.host is not None:
            if not ssh.is_running(config, found.host):
                return "stale"
            state = ctn.nested_state(config, found.host, guest)
            return "running" if state == "running" else "stale"
        return "running" if ctn.is_running(guest) else "stale"

    return "stale"


def collect_mounts(config: Config, name: str | None = None) -> list[dict]:
    """Every recorded runtime mount, annotated with ``guest`` and ``status``.

    With a name, only that guest's records are returned. Without one, the scan
    spans enabled guests plus every state directory that has a state file,
    deduplicated and sorted.
    """
    if name is not None:
        names = [name]
    else:
        candidates = {guest.name for guest in config.enabled_guests}
        try:
            entries = list(config.state_root.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if entry.is_dir() and (entry / STATE_NAME).is_file():
                candidates.add(entry.name)
        names = sorted(candidates)

    records: list[dict] = []
    for guest in names:
        for record in read_state(config, guest):
            annotated = dict(record)
            annotated["guest"] = guest
            annotated["status"] = _status_for(config, guest, record)
            records.append(annotated)
    return records


def action_mount(
    config: Config,
    name: str,
    spec: str,
    *,
    kind: str = "vm",
    read_only: bool = False,
    overlay: bool = False,
    no_idmap: bool = False,
) -> None:
    """Implement ``tartarus mount``."""
    source, target = parse_spec(spec)
    mode = resolve_mode(read_only=read_only, overlay=overlay)

    if find_record(config, name, target) is not None:
        raise TartarusError(
            f"'{target}' already has a runtime mount on '{name}'; unmount it first"
        )

    if kind == "vm":
        record = _mount_vm(config, name, source, target, mode)
    else:
        record = _mount_container(
            config, name, source, target, mode, no_idmap=no_idmap
        )

    append_record(config, name, record)
    ok(f"Mounted {source} at {target} on '{name}' ({mode}).")


def action_unmount(config: Config, name: str, target: str, *, kind: str = "vm") -> None:
    """Implement ``tartarus unmount`` (alias ``umount``)."""
    target = validate_target(target)
    record = find_record(config, name, target)
    if record is None:
        raise TartarusError(f"no runtime mount at '{target}' on guest '{name}'")

    if kind == "vm":
        _unmount_vm(config, name, record)
    else:
        _unmount_container(config, name, record)

    remove_record(config, name, target)
    ok(f"Unmounted '{target}' from '{name}'.")


def action_mounts(
    config: Config, name: str | None = None, json_output: bool = False
) -> None:
    """Implement ``tartarus mounts``."""
    records = collect_mounts(config, name)
    if json_output:
        print(json.dumps(records, indent=2))
        return
    if not records:
        print("No runtime mounts.")
        return

    rows = [
        [
            str(record.get("guest", "-")),
            str(record.get("target", "-")),
            str(record.get("source", "-")),
            str(record.get("mode", "-")),
            str(record.get("status", "-")),
        ]
        for record in records
    ]
    print_table(["GUEST", "GUEST PATH", "HOST PATH", "MODE", "STATUS"], rows)


def cleanup_container_mounts(config: Config, name: str) -> None:
    """Drop a container's state file and empty staging dir (no sudo, idempotent)."""
    try:
        state_path(config, name).unlink()
    except FileNotFoundError:
        pass

    try:
        staging_root(config, name).rmdir()
    except OSError:
        pass


def cleanup_vm_mounts(config: Config, name: str) -> None:
    """Release every VM staging bind and drop the runtime-mount state.

    Runs after the guest is down (stop/restart) or before a fresh launch, so it
    must tolerate stale state from an unclean exit and host reboots. Never
    raises: a failure is warned and the state file is still removed so cleanup
    can never keep a guest running.
    """
    root = staging_root(config, name)
    try:
        records = read_state(config, name)
        for record in records:
            stage = record.get("stage")
            if stage:
                stage_path = Path(stage)
            elif record.get("id"):
                stage_path = root / str(record["id"])
            else:
                continue
            _release_stage(stage_path)

        # Catch staging directories left behind without a state record (e.g.
        # after the process died between mkdir and write_state).
        try:
            leftovers = list(root.iterdir())
        except OSError:
            leftovers = []
        for entry in leftovers:
            if entry.is_dir():
                _release_stage(entry)
    except Exception as exc:  # noqa: BLE001 - cleanup must never raise
        warn(f"could not fully clean runtime mounts for '{name}': {exc}")
    finally:
        try:
            state_path(config, name).unlink(missing_ok=True)
        except OSError as exc:
            warn(f"could not remove runtime-mount state for '{name}': {exc}")
        try:
            root.rmdir()
        except OSError:
            pass


def _release_stage(stage: Path) -> None:
    """Release a host staging bind (if any) and remove its directory.

    Only invokes ``sudo`` when the path is actually a mountpoint, so cleanup
    never prompts when there is nothing to release.
    """
    if os.path.ismount(stage):
        result = process.run_sudo_capture(["umount", str(stage)])
        if result.returncode != 0:
            lazy = process.run_sudo_capture(["umount", "-l", str(stage)])
            if lazy.returncode != 0:
                detail = (lazy.stderr or lazy.stdout or "").strip()
                warn(
                    f"could not release staging mount {stage}"
                    + (f": {detail}" if detail else "")
                )
    shutil.rmtree(stage, ignore_errors=True)


def _mount_vm(
    config: Config, name: str, source: Path, target: str, mode: str
) -> dict:
    """Stage a host directory and mount it in a running VM."""
    if system.is_darwin():
        raise TartarusError(
            "runtime mounts for MicroVMs are not supported on macOS/vfkit "
            "(vfkit has no device hotplug and macOS has no bind mounts). "
            "Use a Linux host, or pass --mount at launch time."
        )

    if not ssh.is_running(config, name):
        raise TartarusError(
            f"'{name}' is not running. Start it first: tartarus start {name}"
        )

    preflight = ssh.run_remote(
        config,
        name,
        [
            "sh",
            "-c",
            f"test -x {MOUNT_HELPER} && test -d {GUEST_STAGING}",
        ],
    )
    if preflight.returncode != 0:
        detail = (preflight.stderr or preflight.stdout or "").strip()
        raise TartarusError(
            f"'{name}' does not have the runtime-mount helper or staging share"
            + (f" ({detail})" if detail else "")
            + f"; rebuild and restart it once: tartarus restart {name} -u"
        )

    root = staging_root(config, name)
    root.mkdir(parents=True, exist_ok=True)

    identifier = ""
    stage: Path | None = None
    for _ in range(10):
        identifier = secrets.token_hex(4)
        candidate = root / identifier
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        stage = candidate
        break
    if stage is None:
        raise TartarusError(
            f"could not allocate a unique staging directory under {root}"
        )

    def _fail(result, what: str) -> None:
        detail = (result.stderr or result.stdout or "").strip()
        _release_stage(stage)
        raise TartarusError(what + (f": {detail}" if detail else ""))

    bind = process.run_sudo_capture(["mount", "--bind", str(source), str(stage)])
    if bind.returncode != 0:
        _fail(bind, f"failed to stage {source} on {stage}")

    if mode in ("ro", "overlay"):
        remount = process.run_sudo_capture(
            ["mount", "-o", "remount,ro,bind", str(stage)]
        )
        if remount.returncode != 0:
            _fail(remount, f"failed to make {stage} read-only")

    helper = ssh.run_remote(
        config, name, [MOUNT_HELPER, "mount", identifier, target, mode]
    )
    if helper.returncode != 0:
        _fail(helper, f"guest '{name}' failed to mount '{target}'")

    return {
        "id": identifier,
        "kind": "vm",
        "source": str(source),
        "target": target,
        "mode": mode,
        "stage": str(stage),
    }


def _unmount_vm(config: Config, name: str, record: dict) -> None:
    """Ask the VM to unmount and release the host staging bind."""
    if ssh.is_running(config, name):
        try:
            result = ssh.run_remote(
                config, name, [MOUNT_HELPER, "umount", record["target"]]
            )
        except TartarusError as exc:
            warn(f"could not ask '{name}' to unmount '{record['target']}': {exc}")
        else:
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                warn(
                    f"could not ask '{name}' to unmount '{record['target']}'"
                    + (f": {detail}" if detail else "")
                )

    stage = record.get("stage")
    if stage:
        stage_path = Path(stage)
    else:
        stage_path = staging_root(config, name) / str(record.get("id", ""))
    _release_stage(stage_path)


def _nested_host(config: Config, name: str) -> str | None:
    """The container-host VM ``name`` runs inside, or ``None`` when native."""
    guest = config.find_guest(name)
    return guest.host if guest is not None and guest.kind == "container" else None


def _command_detail(result: subprocess.CompletedProcess) -> str:
    """Best human-readable detail from a failed command result."""
    return (result.stderr or result.stdout or "").strip()


def _first_child_pid(pid: int) -> int:
    """First positive child of ``pid`` from ``/proc/<pid>/task/<pid>/children``."""
    try:
        raw = Path(f"/proc/{pid}/task/{pid}/children").read_text(encoding="utf-8")
    except OSError:
        return 0
    for token in raw.split():
        try:
            child = int(token)
        except ValueError:
            continue
        if child > 0:
            return child
    return 0


def container_leader(name: str) -> int:
    """PID of a running container's init process.

    ``machinectl`` reports the leader directly. When it is unavailable (or
    returns nothing useful), ``systemctl`` reports the nspawn *monitor* PID
    instead; the container init is the monitor's first child.
    """
    try:
        result = subprocess.run(
            ["machinectl", "show", name, "-p", "Leader", "--value"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        result = None

    if result is not None and result.returncode == 0:
        try:
            leader = int(result.stdout.strip())
        except ValueError:
            leader = 0
        if leader > 0:
            return leader

    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "-p",
                "MainPID",
                "--value",
                f"container@{name}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TartarusError(
            f"cannot resolve the leader PID for container '{name}': {exc}"
        ) from exc

    monitor = 0
    if result.returncode == 0:
        try:
            monitor = int(result.stdout.strip())
        except ValueError:
            monitor = 0
    if monitor > 0:
        child = _first_child_pid(monitor)
        return child if child > 0 else monitor

    detail = _command_detail(result)
    raise TartarusError(
        f"cannot resolve the leader PID for container '{name}' "
        "(machinectl and systemctl both failed); is it running?"
        + (f": {detail}" if detail else "")
    )


def read_id_map(path: Path) -> tuple[int, int] | None:
    """Parse the first ``inner outer [count]`` line of a uid/gid map file."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 2:
            return None
        try:
            return int(fields[0]), int(fields[1])
        except ValueError:
            return None
    return None


def needs_idmap(leader: int) -> bool:
    """Whether the container's first UID/GID mapping is shifted.

    Identity maps (``0 0 ...``) need a plain bind. Unknown or unreadable maps
    are treated as identity so the default path still works; ownership may
    then resolve to ``nobody``/``nogroup`` inside the container.
    """
    mappings: list[tuple[int, int]] = []
    unreadable = False
    for kind in ("uid", "gid"):
        mapping = read_id_map(Path(f"/proc/{leader}/{kind}_map"))
        if mapping is None:
            unreadable = True
        else:
            mappings.append(mapping)

    if any(inner != 0 or outer != 0 for inner, outer in mappings):
        return True

    if unreadable:
        warn(
            f"could not read the uid/gid map for container leader {leader}; "
            "using a plain bind (ownership may appear as nobody/nogroup)"
        )
    return False


def _namespace_run(
    leader: int,
    argv: list[str],
    *,
    preserve_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess:
    """Run ``argv`` in the container's mount and user namespaces as root."""
    cmd = [
        "nsenter",
        "-t",
        str(leader),
        "-m",
        "-U",
        "-S",
        "0",
        "-G",
        "0",
        "-r",
        f"/proc/{leader}/root",
        "--",
        *argv,
    ]
    if preserve_fds:
        # sudo --preserve-fds=N keeps fds 3..3+N-1; 0-2 are always preserved.
        count = max(preserve_fds) - 2
        cmd = [f"--preserve-fds={count}", *cmd]
    return process.run_sudo_capture(cmd, pass_fds=preserve_fds)


def _container_release_stage(leader: int, stage_inner: str) -> None:
    """Best-effort unmount and removal of a container staging directory."""
    for argv in (["umount", stage_inner], ["rm", "-rf", stage_inner]):
        try:
            result = _namespace_run(leader, argv)
        except Exception as exc:  # noqa: BLE001 - cleanup must never raise
            warn(f"could not release '{stage_inner}' inside the container: {exc}")
            continue
        if result.returncode != 0:
            detail = _command_detail(result)
            warn(
                f"could not release '{stage_inner}' inside the container"
                + (f": {detail}" if detail else "")
            )


def _mount_container(
    config: Config,
    name: str,
    source: Path,
    target: str,
    mode: str,
    *,
    no_idmap: bool = False,
) -> dict:
    """Bind a host directory into a running container's mount namespace."""
    nested = _nested_host(config, name)
    if nested is not None:
        raise TartarusError(
            f"'{name}' is a nested container inside container-host VM "
            f"'{nested}'; runtime mounts are not supported for nested "
            "containers because the host source path is not visible inside "
            "the container-host VM."
        )

    if not ctn.is_running(name):
        raise TartarusError(
            f"'{name}' is not running. Start it first: "
            f"tartarus --container start {name}"
        )

    leader = container_leader(name)
    identifier = secrets.token_hex(4)
    stage_inner = f"{GUEST_STAGING}/{identifier}"
    overlay_inner = f"/run/tartarus-mount/overlays/{identifier}"

    prepared = _namespace_run(
        leader,
        [
            "mkdir",
            "-p",
            "/run/tartarus-mount/staging",
            "/run/tartarus-mount/overlays",
        ],
    )
    if prepared.returncode != 0:
        detail = _command_detail(prepared)
        raise TartarusError(
            f"failed to prepare the runtime-mount directories in '{name}'"
            + (f": {detail}" if detail else "")
        )

    try:
        fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise TartarusError(f"cannot open host source {source}: {exc}") from exc

    try:
        shifted = needs_idmap(leader)
        if no_idmap:
            idmap = False
            if shifted:
                warn(
                    f"--no-idmap: '{target}' keeps a plain bind; ownership "
                    "inside the container may appear as nobody/nogroup"
                )
        else:
            idmap = shifted

        def _fail(result: subprocess.CompletedProcess, what: str) -> None:
            _container_release_stage(leader, stage_inner)
            detail = _command_detail(result)
            raise TartarusError(what + (f": {detail}" if detail else ""))

        bind = ["mount", "--bind"]
        if idmap:
            bind += ["--map-users=0:0:65536", "--map-groups=0:0:65536"]
        bind += [f"/proc/self/fd/{fd}", stage_inner]

        staged = _namespace_run(leader, bind, preserve_fds=(fd,))
        if staged.returncode != 0:
            if idmap:
                warn(
                    f"idmapped bind failed for '{source}' (the source "
                    "filesystem may not support idmapped mounts); retrying "
                    "with a plain bind (ownership may appear as "
                    "nobody/nogroup)"
                )
                plain = [
                    "mount",
                    "--bind",
                    f"/proc/self/fd/{fd}",
                    stage_inner,
                ]
                staged = _namespace_run(leader, plain, preserve_fds=(fd,))
                if staged.returncode != 0:
                    _fail(
                        staged,
                        f"failed to bind {source} into '{name}'",
                    )
            else:
                _fail(staged, f"failed to bind {source} into '{name}'")

        if mode in ("ro", "overlay"):
            remount = _namespace_run(
                leader, ["mount", "-o", "remount,ro,bind", stage_inner]
            )
            if remount.returncode != 0:
                _fail(
                    remount,
                    f"failed to make the staging bind for '{target}' read-only",
                )

        exists = _namespace_run(leader, ["test", "-d", target])
        if exists.returncode != 0:
            made = _namespace_run(leader, ["mkdir", "-p", target])
            if made.returncode != 0:
                _fail(made, f"failed to create mount target '{target}' in '{name}'")
            owned = _namespace_run(leader, ["chown", "user:users", target])
            if owned.returncode != 0:
                _fail(owned, f"failed to chown mount target '{target}' in '{name}'")

        if mode == "rw":
            mounted = _namespace_run(
                leader, ["mount", "--bind", stage_inner, target]
            )
        elif mode == "ro":
            mounted = _namespace_run(
                leader, ["mount", "--bind", stage_inner, target]
            )
            if mounted.returncode == 0:
                mounted = _namespace_run(
                    leader, ["mount", "-o", "remount,ro,bind", target]
                )
        else:
            dirs = _namespace_run(
                leader,
                ["mkdir", "-p", f"{overlay_inner}/upper", f"{overlay_inner}/work"],
            )
            if dirs.returncode != 0:
                _fail(dirs, f"failed to create overlay directories for '{target}'")
            owned = _namespace_run(leader, ["chown", "-R", "user:users", overlay_inner])
            if owned.returncode != 0:
                _fail(owned, f"failed to chown overlay directories for '{target}'")
            mounted = _namespace_run(
                leader,
                [
                    "mount",
                    "-t",
                    "overlay",
                    "overlay",
                    "-o",
                    f"lowerdir={stage_inner},upperdir={overlay_inner}/upper,"
                    f"workdir={overlay_inner}/work,userxattr",
                    target,
                ],
            )

        if mounted.returncode != 0:
            _fail(mounted, f"failed to mount '{target}' in '{name}'")

        return {
            "id": identifier,
            "kind": "container",
            "source": str(source),
            "target": target,
            "mode": mode,
            "stage": stage_inner,
        }
    finally:
        os.close(fd)


def _unmount_container(config: Config, name: str, record: dict) -> None:
    """Unmount a container's runtime bind inside its namespace."""
    if not ctn.is_running(name):
        return

    leader = container_leader(name)
    target = record["target"]

    result = _namespace_run(leader, ["umount", target])
    if result.returncode != 0:
        detail = _command_detail(result)
        warn(
            f"could not unmount '{target}' in '{name}'"
            + (f": {detail}" if detail else "")
            + "; retrying lazily"
        )
        lazy = _namespace_run(leader, ["umount", "-l", target])
        if lazy.returncode != 0:
            detail = _command_detail(lazy)
            warn(
                f"could not lazily unmount '{target}' in '{name}'"
                + (f": {detail}" if detail else "")
            )

    if record.get("mode") == "overlay":
        _namespace_run(
            leader,
            ["rm", "-rf", f"/run/tartarus-mount/overlays/{record.get('id', '')}"],
        )

    stage = record.get("stage") or f"{GUEST_STAGING}/{record.get('id', '')}"
    _container_release_stage(leader, stage)

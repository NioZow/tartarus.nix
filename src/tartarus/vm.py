"""MicroVM actions: list/status/start/spawn/stop/restart/logs/ssh/cid/ip/proxy/build.

Ported from the original single-file script. The flake being built is always
the **user's** flake (``flake_ref``), never tartarus's own repo, and guest
state lives under ``config.state_root``.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import pty
import shutil
import signal
import subprocess
import time
from pathlib import Path

from . import ca, ssh, system
from .config import Config
from .nix import eval as nix_eval
from .nix import flake
from .output import c, die, info, ok, print_table, warn
from .process import run_quiet

# Guards infinite recursion when a dependency cycle exists at runtime.
_STARTING: set[str] = set()


def _ensure_dependencies(config: Config, name: str) -> None:
    """Start any `requires` dependencies before ``name``."""
    guest = config.guest(name, "vm")
    if guest is None:
        return
    for dep in guest.requires:
        if ssh.is_running(config, dep):
            continue
        if dep in _STARTING:
            continue
        dep_guest = config.require_guest(dep)
        if dep_guest.kind == "container":
            from . import ctn  # lazy to avoid a circular import

            ctn.action_start(config, dep)
        else:
            action_start(config, dep, mounts=[])


def mount_type(value: str) -> str:
    if ":" not in value or value.split(":", 1)[1] == "":
        raise argparse.ArgumentTypeError(f"--mount expects HOST_PATH:GUEST_PATH, got '{value}'")
    return value


def build_mounts_json(mounts: list[str]) -> str:
    shares = []
    for mount in mounts:
        src, _, dst = mount.partition(":")
        if not dst:
            die(f"--mount expects HOST_PATH:GUEST_PATH, got '{mount}'")
        src_path = Path(src)
        if src_path.is_dir():
            src = str(src_path.resolve())
        shares.append({"source": src, "mountPoint": dst})
    return json.dumps(shares)


def status_word(running: bool) -> str:
    return c("32", "running") if running else c("90", "stopped")


def instance_info(config: Config, name: str, kind: str) -> dict:
    state = config.state_dir(name)
    running = ssh.is_running(config, name)
    pid = cid = None
    if running:
        pid = (state / "microvm.pid").read_text().strip()
        cid_file = state / "cid"
        cid = cid_file.read_text().strip() if cid_file.exists() else None
    return {
        "name": name,
        "type": kind,
        "status": "running" if running else "stopped",
        "pid": pid,
        "cid": cid,
    }


def collect_instances(config: Config) -> list[dict]:
    # `list` must enumerate only guests enabled on this host: config.toml is the
    # authoritative enabled set (the flake's outputs are generated from it).
    templates = [name for name in flake.list_templates(config, "vm") if config.guest(name, "vm") is not None]
    entries = [instance_info(config, name, "template") for name in templates]

    if config.state_root.is_dir():
        for entry in sorted(config.state_root.iterdir()):
            if not entry.is_dir():
                continue
            name = entry.name
            match = flake.INSTANCE_RE.match(name)
            if match and match.group(1) in templates:
                entries.append(instance_info(config, name, "instance"))

    return entries


def action_list(config: Config, json_output: bool) -> None:
    entries = collect_instances(config)

    if json_output:
        print(json.dumps(entries, indent=2))
        return

    if not entries:
        print("No MicroVMs defined.")
        return

    rows = [
        [e["name"], status_word(e["status"] == "running"), e["type"], e["pid"] or "-", e["cid"] or "-"]
        for e in entries
    ]
    print_table(["NAME", "STATUS", "TYPE", "PID", "CID"], rows)


def action_status(config: Config, name: str | None) -> None:
    if not name:
        action_list(config, False)
        return
    flake.require_template(config, "vm", flake.base_name(config, "vm", name))
    state = config.state_dir(name)
    if ssh.is_running(config, name):
        pid = (state / "microvm.pid").read_text().strip()
        cid_file = state / "cid"
        cid = cid_file.read_text().strip() if cid_file.exists() else "?"
        print(f"{name}: {status_word(True)} (pid {pid}, cid {cid})")
        print(f"  console log: {state / 'console.log'}")
    else:
        print(f"{name}: {status_word(False)}")


def next_instance_name(config: Config, base: str) -> str:
    """First ``<base>-<N>`` (N from 2) that isn't currently running.

    Reuses a previously-stopped instance's own name/state dir rather than
    always growing N, so repeated spawn/stop cycles don't leak numbers.
    """
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if not ssh.is_running(config, candidate):
            return candidate
    die(f"no free instance number for '{base}'")


def _build_runner(config: Config, name: str, mounts: list[str]) -> tuple[Path, int | None]:
    base = flake.base_name(config, "vm", name)
    state = config.state_dir(name)
    state.mkdir(parents=True, exist_ok=True)

    # The guest flake mounts $HOME/shared/<name>; for the canonical instance a
    # rebuild's tmpfiles rule already made it, but numbered instances aren't
    # known at rebuild time, so the hypervisor would otherwise fail with no
    # such source directory for its share.
    config.shared_dir(name).mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["MICROVM_EXTRA_SHARES"] = build_mounts_json(mounts)
    # Pin the guest's `user` uid to the invoking user's so virtiofs ownership
    # matches transparently on both sides.
    env["TARTARUS_HOST_UID"] = str(os.getuid())

    cid: int | None = None
    if name != base:
        # Numbered instance: pin its hostname suffix and CID explicitly so
        # this eval of `base` produces an independent, uniquely-addressed VM.
        env["MICROVM_INSTANCE_SUFFIX"] = name[len(base) + 1 :]
        cid = ssh.alloc_cid(config)
        env["MICROVM_ID_OVERRIDE"] = str(cid)
    else:
        env.pop("MICROVM_INSTANCE_SUFFIX", None)
        env.pop("MICROVM_ID_OVERRIDE", None)

    attr = flake.packages_attr(config, base)

    info(f"Building '{name}'...")
    nix_eval.build(flake.flake_ref(config), attr, state / "result", env=env)
    return state / "result", cid


def action_build(config: Config, name: str, mounts: list[str]) -> None:
    base = flake.base_name(config, "vm", name)
    flake.require_template(config, "vm", base)
    result, _cid = _build_runner(config, name, mounts)
    ok(f"'{name}' built. Result: {result}")


def action_start(config: Config, name: str, mounts: list[str]) -> None:
    base = flake.base_name(config, "vm", name)
    flake.require_template(config, "vm", base)

    ca.ensure_vm_certs(config, base)

    if ssh.is_running(config, name):
        pid = (config.state_dir(name) / "microvm.pid").read_text().strip()
        warn(f"'{name}' is already running (pid {pid}).")
        return

    _STARTING.add(name)
    try:
        _ensure_dependencies(config, name)
    finally:
        _STARTING.discard(name)

    result, cid = _build_runner(config, name, mounts)
    state = result.parent

    # Clear stale bookkeeping from a previous run before launching (only safe
    # here, after the running check above).
    (state / "microvm.pid").unlink(missing_ok=True)
    (state / "cid").unlink(missing_ok=True)

    if cid is None:
        cid = flake.guest_id(config, "vm", base)
    (state / "cid").write_text(f"{cid}\n")

    # macOS uses vfkit (Virtualization.framework), which brings its own
    # user-mode NAT/DHCP; Linux keeps QEMU with the trs0 bridge. Either way
    # `microvm-run` runs as the invoking user, never root.
    console_log = open(state / "console.log", "wb")
    run_cmd = [str(state / "result/bin/microvm-run")]

    # vfkit's non-graphical console puts stdin into termios raw mode, which
    # needs a real tty. A PTY slave satisfies it without an interactive
    # console; guest output still goes to console_log. QEMU has no such
    # requirement, so Linux keeps the plain DEVNULL.
    #
    # The master must outlive this CLI process: vfkit makes the slave its
    # controlling terminal, so when the master closes the kernel hangs up the
    # slave and vfkit stops the VM. Python fds are close-on-exec (PEP 446), so
    # inheriting them via close_fds=False is not enough -- clear CLOEXEC and
    # pass both ends explicitly, letting vfkit hold the master for the VM's
    # whole lifetime.
    pty_fds = pty.openpty() if platform.system() == "Darwin" else None
    stdin = pty_fds[1] if pty_fds else subprocess.DEVNULL
    if pty_fds:
        for fd in pty_fds:
            os.set_inheritable(fd, True)
    proc = subprocess.Popen(
        run_cmd,
        cwd=state,
        stdout=console_log,
        stderr=subprocess.STDOUT,
        stdin=stdin,
        start_new_session=True,
        pass_fds=tuple(pty_fds) if pty_fds else (),
    )
    console_log.close()
    (state / "microvm.pid").write_text(f"{proc.pid}\n")

    ok(f"'{name}' started (pid {proc.pid}, cid {cid}). Console: {state / 'console.log'}")


def action_spawn(config: Config, template: str, name_override: str | None, mounts: list[str]) -> None:
    flake.require_template(config, "vm", template)
    name = name_override or next_instance_name(config, template)
    info(f"Spawning new '{template}' instance: {name}")
    action_start(config, name, mounts)


def action_stop(config: Config, name: str, purge: bool, debug: bool = False) -> None:
    flake.require_template(config, "vm", flake.base_name(config, "vm", name))
    state = config.state_dir(name)

    if not ssh.is_running(config, name):
        warn(f"'{name}' is not running.")
    else:
        shutdown_bin = state / "result/bin/microvm-shutdown"
        if shutdown_bin.exists():
            run_quiet([str(shutdown_bin)], cwd=state, debug=debug)

        pid = int((state / "microvm.pid").read_text().strip())
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            # Still alive after a graceful ACPI shutdown attempt -- force it.
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        # On Linux, the rootless-virtiofsd preStart backgrounds a virtiofsd
        # per share before exec'ing qemu -- they share qemu's process group
        # (start_new_session=True makes pid double as pgid), but a graceful
        # shutdown only asks qemu to exit, leaving them orphaned. No-op on
        # macOS/vfkit.
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        ok(f"'{name}' stopped.")

    if purge:
        shutil.rmtree(state, ignore_errors=True)
        ok(f"Purged state for '{name}'.")
    else:
        (state / "microvm.pid").unlink(missing_ok=True)
        for sock in state.glob("*.sock"):
            sock.unlink(missing_ok=True)


def action_restart(config: Config, name: str, debug: bool = False) -> None:
    action_stop(config, name, purge=False, debug=debug)
    action_start(config, name, mounts=[])


def action_logs(config: Config, name: str) -> None:
    ssh.exec_logs(config, name)


def action_ssh(config: Config, name: str, start: bool = False) -> None:
    base = flake.base_name(config, "vm", name)
    flake.require_template(config, "vm", base)
    if start and not ssh.is_running(config, name):
        action_start(config, name, mounts=[])
    ca.ensure_vm_certs(config, base)
    ssh.exec_ssh(config, name)


def dispatch(config: Config, args) -> None:
    system.maybe_reexec_for_kvm_group()
    if args.command == "list":
        action_list(config, args.json)
    elif args.command == "status":
        action_status(config, args.name)
    elif args.command == "start":
        action_start(config, args.name, args.mounts)
    elif args.command == "build":
        action_build(config, args.name, args.mounts)
    elif args.command == "spawn":
        action_spawn(config, args.template, args.name, args.mounts)
    elif args.command == "stop":
        action_stop(config, args.name, args.purge, args.debug)
    elif args.command == "restart":
        action_restart(config, args.name, args.debug)
    elif args.command == "logs":
        action_logs(config, args.name)
    elif args.command == "ssh":
        action_ssh(config, args.name, args.start)
    elif args.command == "cid":
        ssh.action_cid(config, args.name)
    elif args.command == "proxy":
        ssh.action_proxy(config, args.name)
    elif args.command == "ip":
        ssh.action_ip(config, args.name)
    elif args.command == "proxy-ip":
        ssh.action_proxy_ip(config, args.name)

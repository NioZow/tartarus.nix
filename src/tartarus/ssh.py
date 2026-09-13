"""Guest reachability and client SSH material.

Covers three things the original script kept together:

* the shared ``~/.ssh/tartarus`` client key and ``known_hosts_trs`` CA trust;
* locating a running VM (recorded VSOCK CID, deterministic MAC -> ARP IP);
* the ``proxy`` / ``proxy-ip`` / ``ip`` actions consumed by nixcfg's
  ``modules/programs/user/ssh.nix`` as ``ProxyCommand`` targets.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import NoReturn

from . import system
from .config import Config
from .nix import flake
from .output import die, info, note
from .process import run_quiet

KNOWN_HOSTS_TRS_NAME = "known_hosts_trs"
USER_SSH_KEY_NAME = "tartarus"

# A freshly started MicroVM needs a moment to bring up its interface and get a
# DHCP lease; until then the host ARP table has no entry for its MAC. Poll
# instead of failing the first `ssh` that races the guest's boot.
ARP_WAIT_SECONDS = 20.0
ARP_POLL_INTERVAL = 0.5


def user_ssh_key(config: Config) -> Path:
    return config.ssh_dir / USER_SSH_KEY_NAME


def known_hosts_trs(config: Config) -> Path:
    return config.ssh_dir / KNOWN_HOSTS_TRS_NAME


def ensure_user_ssh_key(config: Config) -> None:
    """Generate ``~/.ssh/tartarus`` (Ed25519, no passphrase) if missing.

    This is the shared client key used to authenticate to all MicroVMs and
    containers; the matching public key is baked into guest builds.
    """
    key = user_ssh_key(config)
    if key.exists():
        return
    info("Generating MicroVM user SSH key...")
    key.parent.mkdir(parents=True, exist_ok=True)
    run_quiet(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(key),
            "-N",
            "",
            "-C",
            f"microvm-{config.user}@{socket.gethostname()}",
        ],
        check=True,
    )
    key.chmod(0o600)
    (key.parent / f"{key.name}.pub").chmod(0o644)


def ensure_known_hosts_trs(config: Config, ca_pub: Path) -> None:
    """Trust the tartarus CA for ``*.trs`` in ``~/.ssh/known_hosts_trs``.

    Idempotent -- the file is rewritten only when its content changes.
    """
    if not ca_pub.exists():
        return

    pubkey = ca_pub.read_text().strip()
    content = f"@cert-authority *.trs {pubkey}\n"
    target = known_hosts_trs(config)

    if not target.exists() or target.read_text() != content:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def pid_alive(pidfile: Path) -> bool:
    if not pidfile.exists():
        return False
    try:
        pid = int(pidfile.read_text().strip())
    except ValueError:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but isn't ours -- still alive.
        return True
    return True


def is_running(config: Config, name: str) -> bool:
    return pid_alive(config.state_dir(name) / "microvm.pid")


def used_cids(config: Config) -> set[int]:
    used: set[int] = set()
    if not config.state_root.is_dir():
        return used
    for entry in config.state_root.iterdir():
        if not entry.is_dir() or not is_running(config, entry.name):
            continue
        cid_file = entry / "cid"
        if cid_file.exists():
            used.add(int(cid_file.read_text().strip()))
    return used


def alloc_cid(config: Config) -> int:
    used = used_cids(config)
    for cid in range(system.VM_EPHEMERAL_CID_MIN, system.VM_EPHEMERAL_CID_MAX + 1):
        if cid not in used:
            return cid
    die(
        "no free ephemeral VSOCK CID left "
        f"({system.VM_EPHEMERAL_CID_MIN}-{system.VM_EPHEMERAL_CID_MAX} all in use)"
    )


def resolve_cid(config: Config, name: str) -> str:
    """Resolve an instance's VSOCK CID by name, with or without ``.trs``.

    Prefers a running instance's recorded cid file (correct for both the
    canonical instance and any spawned one) and otherwise falls back to the
    template's declarative id, so ``ssh <name>.trs`` resolves before the VM
    has ever been started.
    """
    if name.endswith(".trs"):
        name = name[: -len(".trs")]
    base = flake.base_name(config, "vm", name)
    flake.require_template(config, "vm", base)

    cid_file = config.state_dir(name) / "cid"
    if cid_file.exists():
        return cid_file.read_text().strip()

    if name != base:
        die(f"'{name}' has never been started -- no recorded VSOCK CID (spawn it first)")

    return str(flake.guest_id(config, "vm", base))


def normalize_mac(mac: str) -> str:
    # "2:0:0:0:0:7" (macOS `arp -a`) == "02:00:00:00:00:07" (qemu): strip
    # leading zeros per octet and lowercase so both spellings match.
    return ":".join(f"{int(octet, 16):x}" for octet in mac.split(":") if octet)


def arp_ip_for_mac(arp_output: str, mac_want: str) -> str | None:
    """Find the IP listed for ``mac_want`` in ``arp -an`` output.

    Handles both the macOS format (``? (192.168.64.7) at 2:0:0:0:0:7 ...``)
    and the Linux format (``foo (10.200.0.7) at 02:00:00:00:00:07 ...``).
    """
    want = normalize_mac(mac_want)
    for line in arp_output.splitlines():
        match = re.search(r"\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)", line, re.IGNORECASE)
        if not match:
            continue
        if normalize_mac(match.group(2)) == want:
            return match.group(1)
    return None


def resolve_running_ip(config: Config, name: str) -> str:
    """Resolve the host-reachable IP of a running MicroVM via the ARP table."""
    if name.endswith(".trs"):
        name = name[: -len(".trs")]

    if not is_running(config, name):
        die(f"'{name}' is not running. Start it first: tartarus start {name}")

    state = config.state_dir(name)
    guest_id: int | None = None
    if (state / "cid").exists():
        try:
            guest_id = int((state / "cid").read_text().strip())
        except ValueError:
            guest_id = None

    if guest_id is None:
        base = flake.base_name(config, "vm", name)
        flake.require_template(config, "vm", base)
        guest_id = flake.guest_id(config, "vm", base)

    mac = system.guest_mac(guest_id)
    # -n: skip reverse-DNS on every entry (plain `arp -a` blocks on lookups
    # that always fail for local bridge/vmnet addresses). Output format is
    # identical since none of these addresses have reverse DNS.
    deadline = time.monotonic() + ARP_WAIT_SECONDS
    announced = False
    while True:
        arp_result = subprocess.run(["arp", "-an"], capture_output=True, text=True)
        if arp_result.returncode != 0:
            die(f"failed to run `arp -an`: {arp_result.stderr.strip()}")
        ip = arp_ip_for_mac(arp_result.stdout, mac)
        if ip is not None:
            return ip
        if time.monotonic() >= deadline:
            break
        if not announced:
            note(f"waiting for '{name}' to get a network address (mac {mac})...")
            announced = True
        time.sleep(ARP_POLL_INTERVAL)
    die(f"no ARP entry for '{name}' (mac {mac}) -- is it running and has it gotten a network address?")


def action_cid(config: Config, name: str) -> None:
    print(resolve_cid(config, name))


def action_ip(config: Config, name: str) -> None:
    print(resolve_running_ip(config, name))


def action_proxy(config: Config, name: str) -> NoReturn:
    """Resolve ``name``'s VSOCK CID and exec socat (Linux ssh ProxyCommand)."""
    cid = resolve_cid(config, name)
    os.execvp("socat", ["socat", "-", f"VSOCK-CONNECT:{cid}:22"])


def action_proxy_ip(config: Config, name: str) -> NoReturn:
    """Resolve ``name``'s host-reachable IP and proxy to port 22 (Darwin)."""
    ip = resolve_running_ip(config, name)
    os.execvp("nc", ["nc", ip, "22"])


def exec_ssh(config: Config, name: str) -> NoReturn:
    """Exec ``ssh`` into a running VM instance.

    Canonical instances use the host's static ssh config entry; numbered
    instances route over VSOCK by hand with ``HostKeyAlias`` pinned to the
    base template (all instances share the template's host key/cert).
    """
    base = flake.base_name(config, "vm", name)
    flake.require_template(config, "vm", base)
    if not is_running(config, name):
        die(f"'{name}' is not running. Start it first: tartarus start {name}")

    if name == base:
        os.execvp("ssh", ["ssh", name])

    cid = resolve_cid(config, name)
    known_hosts = config.ssh_dir / "known_hosts"
    static_hosts = config.ssh_dir / "known_hosts_static"
    os.execvp(
        "ssh",
        [
            "ssh",
            "-o",
            f"ProxyCommand=socat - VSOCK-CONNECT:{cid}:22",
            "-o",
            f"HostKeyAlias={base}.trs",
            "-o",
            f"UserKnownHostsFile={known_hosts} {static_hosts} {known_hosts_trs(config)}",
            "-o",
            f"IdentityFile={user_ssh_key(config)}",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={config.ssh_dir}/controlmaster/%r@%h:%p",
            "-o",
            "StreamLocalBindUnlink=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-l",
            "user",
            name,
        ],
    )


def exec_logs(config: Config, name: str) -> NoReturn:
    flake.require_template(config, "vm", flake.base_name(config, "vm", name))
    log = config.state_dir(name) / "console.log"
    if not log.exists():
        die(f"no console log for '{name}' (has it been started?)")
    os.execvp("tail", ["tail", "-f", str(log)])

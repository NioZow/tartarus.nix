"""Host/system detection, the thread-safe Nix invocation constants, and the
pure id -> network-identity formulas from ``nix/lib/ids.nix``.

Mirroring the Nix formulas here keeps CIDs/IPs/MACs a pure function of a
guest's id, so the CLI never needs a ``nix eval`` just to locate a running
guest (PLAN.md §6).
"""

from __future__ import annotations

import grp
import os
import platform
import shlex
import shutil
import sys

NIX_FLAGS = ["--extra-experimental-features", "nix-command flakes"]


def extra_nix_args() -> list[str]:
    """Extra flags appended to every internal ``nix`` invocation.

    The only intended use is the dev path: while ``tartarus.nix`` is an
    untracked nested repo, nixcfg's ``git+file://`` copy cannot see it, so the
    caller passes ``--override-input tartarus path:/abs/path/to/tartarus.nix``
    via ``TARTARUS_NIX_EXTRA_FLAGS`` (shell-split) and the CLI forwards it to
    the ``nix eval``/``nix build`` calls for the *user's* flake.
    """
    raw = os.environ.get("TARTARUS_NIX_EXTRA_FLAGS", "")
    return shlex.split(raw) if raw else []

# Flake-attribute prefixes: nixosConfigurations (and, for VMs, packages) are
# namespaced by guest kind so a VM and a container can reuse the same name.
VM_PREFIX = "vm-"
CTN_PREFIX = "ctn-"

VM_BRIDGE = "trs0"
VM_SUBNET = "10.200.0.0/24"
VM_HOST_IP = "10.200.0.1"

CTN_BRIDGE = "trs1"
CTN_SUBNET = "10.201.0.0/24"
CTN_HOST_IP = "10.201.0.1"

DARWIN_GATEWAY = "192.168.64.1"

# Ephemeral pools for numbered/ad-hoc instances, outside the declarative
# reservations (static 3-100, auto from 101). Mirrors the original script.
VM_EPHEMERAL_CID_MIN = 150
VM_EPHEMERAL_CID_MAX = 254
CTN_EPHEMERAL_ID_MIN = 150
CTN_EPHEMERAL_ID_MAX = 254


def detect_system() -> str:
    """The guest (Linux) system to build for, not the host's own system."""
    env = os.environ.get("TARTARUS_SYSTEM")
    if env:
        return env
    machine = platform.machine()
    system = platform.system()
    if system == "Darwin":
        return "aarch64-linux" if machine == "arm64" else "x86_64-linux"
    if machine == "aarch64":
        return "aarch64-linux"
    if machine in ("x86_64", "amd64"):
        return "x86_64-linux"
    return "x86_64-linux"


def is_darwin() -> bool:
    return platform.system() == "Darwin"


def maybe_reexec_for_kvm_group() -> None:
    """Re-exec once under ``sg kvm`` when the current shell predates a rebuild
    that added the user to the ``kvm`` group.

    qemu reads the CA-signed SSH host key straight off disk via an
    unprivileged share (``chgrp kvm``), so the process launching qemu needs
    the group active. A just-finished rebuild does not update an already-open
    shell's supplementary groups, so re-exec to pick them up.
    """
    if os.environ.get("TARTARUS_REEXEC") == "1":
        return
    if shutil.which("sg") is None:
        return
    try:
        grp.getgrnam("kvm")
    except KeyError:
        return

    group_names = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    if "kvm" in group_names:
        return

    env = dict(os.environ)
    env["TARTARUS_REEXEC"] = "1"
    cmd = shlex.join([sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]])
    os.execvpe("sg", ["sg", "kvm", "-c", cmd], env)


# ---------------------------------------------------------------------------
# id -> network identity (mirrors nix/lib/ids.nix)
# ---------------------------------------------------------------------------


def vm_ip(guest_id: int) -> str:
    return f"10.200.0.{guest_id}"


def vm_ip_nat(guest_id: int) -> str:
    # DHCP is broken under vfkit, so Darwin guests get deterministic static
    # IPs; +42 keeps them above the leases macOS hands out in the lower range.
    return f"192.168.64.{guest_id + 42}"


def ctn_ip(guest_id: int) -> str:
    return f"10.201.0.{guest_id}"


def guest_ip(guest_id: int) -> str:
    """The guest's deterministic host-reachable IP (static on both platforms)."""
    return vm_ip_nat(guest_id) if is_darwin() else vm_ip(guest_id)


def guest_mac(guest_id: int) -> str:
    """The guest's ethernet MAC, exactly as ``ids.nix`` derives it."""
    return f"02:00:00:00:00:{guest_id:02x}"


def mk_cid(guest_id: int) -> int:
    """The VSOCK context ID is just the guest id on Linux."""
    return guest_id

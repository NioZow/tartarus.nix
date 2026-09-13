"""Argument parser and entry point (``tartarus.cli:main``)."""

from __future__ import annotations

import argparse
from typing import Sequence

from . import ctn, vm
from .config import Config, load_config
from .ctn import CTN_CONF_DIR
from .errors import TartarusError
from .nix import flake
from .output import die


def add_command_parser(sub: argparse._SubParsersAction) -> None:
    """One flat command set, shared by MicroVMs and containers.

    ``--container`` on the top-level parser picks which guest kind each command
    acts on, defaulting to MicroVMs.
    """

    p = sub.add_parser("list", help="show every defined guest (and any numbered instances) and whether it's running")
    p.add_argument("--json", action="store_true", help="print as JSON instead of a table")

    p = sub.add_parser("status", help="detailed status (all, or just one)")
    p.add_argument("name", nargs="?", help="instance name (template or template-N)")

    p = sub.add_parser("start", help="build (if needed) and launch a guest in the background")
    p.add_argument("name", help="template name (canonical instance) or an existing instance name")
    p.add_argument(
        "--mount",
        dest="mounts",
        action="append",
        default=[],
        type=vm.mount_type,
        metavar="HOST_PATH:GUEST_PATH",
        help="ad-hoc 9p share chosen at launch time (repeatable; MicroVMs only)",
    )

    p = sub.add_parser("build", help="build (if needed) a guest without starting it")
    p.add_argument("name", help="template name (canonical instance) or an existing instance name")
    p.add_argument(
        "--mount",
        dest="mounts",
        action="append",
        default=[],
        type=vm.mount_type,
        metavar="HOST_PATH:GUEST_PATH",
        help="ad-hoc 9p share chosen at launch time (repeatable; MicroVMs only)",
    )

    p = sub.add_parser("spawn", help="start an additional, independent instance of a template")
    p.add_argument("template", help="template to spawn a new instance of")
    p.add_argument("--name", help="use this exact instance name instead of auto-numbering <template>-<N>")
    p.add_argument(
        "--mount",
        dest="mounts",
        action="append",
        default=[],
        type=vm.mount_type,
        metavar="HOST_PATH:GUEST_PATH",
        help="ad-hoc 9p share chosen at launch time (repeatable; MicroVMs only)",
    )

    p = sub.add_parser("stop", help="gracefully shut a running guest down")
    p.add_argument("name", help="instance name")
    p.add_argument(
        "--purge",
        action="store_true",
        help="also wipe the instance's state (MicroVM: state dir incl. writable nix-store overlay; "
        "container: destroy its nixos-container registration)",
    )
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show the shutdown command's raw output instead of just the final status line",
    )

    p = sub.add_parser("restart", help="stop, then start")
    p.add_argument("name", help="instance name")
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show the shutdown command's raw output instead of just the final status line",
    )

    p = sub.add_parser("logs", help="tail the guest's log (MicroVM: console log; container: systemd journal)")
    p.add_argument("name", help="instance name")

    p = sub.add_parser("ssh", help="SSH into a running instance")
    p.add_argument("name", help="instance name (base template or template-N)")

    p = sub.add_parser("cid", help="print a MicroVM instance's VSOCK CID (resolves by name, running or not)")
    p.add_argument("name", help="instance name, with or without a trailing '.trs'")

    p = sub.add_parser(
        "proxy", help="resolve a MicroVM instance's CID and exec socat -- for use as an ssh ProxyCommand"
    )
    p.add_argument("name", help="instance name, with or without a trailing '.trs' (ssh's %%h)")

    p = sub.add_parser("ip", help="print a running MicroVM's host-reachable IP (macOS: vmnet DHCP address via ARP)")
    p.add_argument("name", help="instance name, with or without a trailing '.trs'")

    p = sub.add_parser(
        "proxy-ip",
        help="proxy stdin/stdout to a running MicroVM's vmnet IP:22 -- darwin ProxyCommand (mirrors `proxy` for VSOCK)",
    )
    p.add_argument("name", help="instance name, with or without a trailing '.trs' (ssh's %%h)")


def build_parser(config) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tartarus",
        description="Run MicroVMs and containers defined in your own flake, on the fly.",
        epilog=(
            f"User flake: {config.flake_path}/flake.nix\n"
            f"Config: {config.config_path or '(defaults; ~/.config/tartarus/config.toml not found)'}\n"
            f"VM state dir: {config.state_root}/<name>/\n"
            f"Container conf dir: {CTN_CONF_DIR}/<name>.conf"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--container",
        action="store_true",
        help="operate on containers instead of MicroVMs (the default)",
    )
    parser.add_argument("--config", metavar="PATH", help="path to config.toml (default: ~/.config/tartarus/config.toml)")
    parser.add_argument("--flake", metavar="PATH", help="override the user's flake root (from config.toml)")
    parser.add_argument("--user", metavar="NAME", help="override the configured user name")
    parser.add_argument("--system", metavar="SYSTEM", help="override the guest system (e.g. aarch64-linux)")
    parser.add_argument("--state-root", dest="state_root", metavar="PATH", help="override the runtime state root")
    parser.add_argument(
        "--log",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable/disable logging (overrides config.toml)",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    add_command_parser(sub)
    return parser


def _overrides(args: argparse.Namespace) -> dict:
    return {
        "config": args.config,
        "flake": args.flake,
        "user": args.user,
        "system": args.system,
        "state_root": args.state_root,
        "log": args.log,
    }


def guard_guest(config: Config, args: argparse.Namespace) -> None:
    """Refuse to act on a guest that isn't enabled on this host.

    Centralised here so every command that names a guest (via ``name`` or, for
    ``spawn``, ``template``) is validated before any nix build/lookup, state-dir
    creation or SSH. All-guests commands (``list``, nameless ``status``) carry no
    name and are governed by :meth:`Config.require_guest` only when they do.
    """
    name = getattr(args, "template", None) or getattr(args, "name", None)
    if name:
        config.require_guest(name, "container" if args.container else "vm")


def main(argv: Sequence[str] | None = None) -> None:
    try:
        # Resolve without CLI flags first so --help can show the real paths.
        parser = build_parser(load_config())
        args = parser.parse_args(argv)

        config = load_config(_overrides(args))

        if args.container and args.command in ("cid", "proxy", "ip", "proxy-ip"):
            raise TartarusError(
                "'cid', 'proxy', 'ip' and 'proxy-ip' are MicroVM-only (VSOCK/vmnet) and have no container equivalent"
            )

        guard_guest(config, args)

        flake.require_flake(config)

        if args.container:
            ctn.dispatch(config, args)
        else:
            vm.dispatch(config, args)
    except TartarusError as exc:
        die(str(exc))

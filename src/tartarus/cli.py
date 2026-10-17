"""Argument parser and entry point (``tartarus.cli:main``)."""

from __future__ import annotations

import argparse
from typing import Sequence

from . import ca, ctn, listing, vm
from .config import Config, load_config
from .ctn import CTN_CONF_DIR
from .errors import TartarusError
from .nix import flake
from .output import die, ok


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"expected a non-negative integer, got {value!r}")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"expected a non-negative number, got {value!r}")
    return number


def add_command_parser(sub: argparse._SubParsersAction) -> None:
    """One flat command set, shared by MicroVMs and containers.

    ``--container`` on the top-level parser picks which guest kind each command
    acts on, defaulting to MicroVMs.
    """

    p = sub.add_parser("list", help="show every enabled guest (MicroVMs and containers) and whether it's running")
    p.add_argument("--json", action="store_true", help="print as JSON instead of a table")
    p.add_argument("-t", "--tree", action="store_true", help="nest containers under their container-host VM")
    p.add_argument(
        "-c",
        "--container",
        dest="list_container",
        action="store_true",
        help="only containers, native and nested (the global -c before the subcommand also works)",
    )
    p.add_argument("--vm", action="store_true", help="only MicroVMs (default: MicroVMs and containers)")

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
        help="ad-hoc host share chosen at launch time (repeatable; MicroVMs only)",
    )
    p.add_argument(
        "-u",
        "--upgrade",
        action="store_true",
        help="rebuild from the current flake instead of reusing the existing build",
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
        help="ad-hoc host share chosen at launch time (repeatable; MicroVMs only)",
    )
    p.add_argument(
        "-u",
        "--upgrade",
        action="store_true",
        help="rebuild from the current flake instead of reusing the existing build",
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
        help="ad-hoc host share chosen at launch time (repeatable; MicroVMs only)",
    )
    p.add_argument(
        "-u",
        "--upgrade",
        action="store_true",
        help="rebuild from the current flake instead of reusing the existing build",
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
    p.add_argument(
        "-u",
        "--upgrade",
        action="store_true",
        help="rebuild from the current flake instead of reusing the existing build",
    )

    p = sub.add_parser("logs", help="tail the guest's log (MicroVM: console log; container: systemd journal)")
    p.add_argument("name", help="instance name")

    p = sub.add_parser("ssh", help="SSH into a running instance")
    p.add_argument("name", help="instance name (base template or template-N)")
    p.add_argument(
        "-s",
        "--start",
        action="store_true",
        help="start the instance first if it isn't already running",
    )
    p.add_argument(
        "-r",
        "--retry",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help="retry a failed connection N times (default: config `ssh.retries`, 5)",
    )
    p.add_argument(
        "--retry-delay",
        type=_non_negative_float,
        default=None,
        metavar="SECONDS",
        help="seconds to wait between retries (default: config `ssh.retry_delay`, 2)",
    )

    p = sub.add_parser("cid", help="print a MicroVM instance's VSOCK CID (resolves by name, running or not)")
    p.add_argument("name", help="instance name, with or without a trailing '.trs'")

    p = sub.add_parser(
        "proxy", help="resolve a MicroVM instance's CID and exec socat -- for use as an ssh ProxyCommand"
    )
    p.add_argument("name", help="instance name, with or without a trailing '.trs' (ssh's %%h)")

    p = sub.add_parser(
        "ip",
        help="print a running guest's host-reachable IP (MicroVM: static vmnet/trs0 address; "
        "native container: its trs1 address; nested container: refused)",
    )
    p.add_argument("name", help="instance name, with or without a trailing '.trs'")

    p = sub.add_parser(
        "proxy-ip",
        help="proxy stdin/stdout to a running MicroVM's vmnet IP:22 -- darwin ProxyCommand (mirrors `proxy` for VSOCK)",
    )
    p.add_argument("name", help="instance name, with or without a trailing '.trs' (ssh's %%h)")

    p = sub.add_parser("ca", help="manage the shared guest CA material")
    ca_sub = p.add_subparsers(dest="ca_command", required=True)
    q = ca_sub.add_parser(
        "ensure",
        help="create/refresh a guest's CA-signed SSH host key and X509 client cert without starting it",
    )
    q.add_argument("name", help="guest name (template or instance)")


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
        default=None,
        help="force the container path; when omitted, a named guest's kind is inferred from config.toml",
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


def resolve_kind(config: Config, args: argparse.Namespace) -> None:
    """Fill ``args.container`` from the named guest's kind when ``--container`` is absent.

    ``--container`` is tri-state: explicit ``True`` forces the container path,
    ``None`` means "infer". A command that names a single guest (by ``name`` or,
    for ``spawn``, ``template``) is routed to that guest's own kind, so e.g.
    ``tartarus start inner`` needs no flag. Commands with no name (``status``,
    nameless) keep the default MicroVM path unless ``--container`` is explicit.
    ``list`` is handled before this (it spans both kinds), so it never reaches
    here.
    """
    if args.container is not None:
        return
    name = getattr(args, "template", None) or getattr(args, "name", None)
    guest = config.find_guest(name) if name else None
    args.container = bool(guest is not None and guest.kind == "container")


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


def _list_kind(args: argparse.Namespace) -> str | None:
    """The kind filter for ``list``: ``"vm"``, ``"container"`` or ``None`` (both).

    ``list`` accepts its own ``-c/--container`` (``list_container``) as well as
    the global one (written before the subcommand, ``container``), so either
    spelling narrows to containers.
    """
    only_container = bool(args.container) or getattr(args, "list_container", False)
    if only_container and args.vm:
        raise TartarusError("list: --vm and --container are mutually exclusive")
    if only_container:
        return "container"
    if args.vm:
        return "vm"
    return None


def main(argv: Sequence[str] | None = None) -> None:
    try:
        # Resolve without CLI flags first so --help can show the real paths.
        parser = build_parser(load_config())
        args = parser.parse_args(argv)

        config = load_config(_overrides(args))

        # `list` spans both kinds, so it runs before the VM/container routing.
        if args.command == "list":
            flake.require_flake(config)
            listing.action_list(
                config, json_output=args.json, tree=args.tree, kind=_list_kind(args)
            )
            return

        resolve_kind(config, args)

        # `ca ensure` only materialises the guest's CA files; it needs neither
        # the flake nor a running guest, so it is handled before the
        # build/lifecycle routing. NixOS calls it from `container@<name>`'s
        # preStart so the CA bind mounts exist before nspawn resolves them.
        if args.command == "ca":
            kind = "container" if args.container else "vm"
            guest = config.require_guest(args.name, kind)
            if guest.host is not None:
                raise TartarusError(
                    f"'{guest.name}' runs inside container-host VM '{guest.host}'; "
                    "its CA material is provisioned by that VM, not this host"
                )
            if kind == "container":
                ca.ensure_ctn_certs(config, guest.name)
            else:
                ca.ensure_vm_certs(config, guest.name)
            ok(f"CA material for '{guest.name}' is ready.")
            return

        if args.container and args.command in ("cid", "proxy", "proxy-ip"):
            raise TartarusError(
                "'cid', 'proxy' and 'proxy-ip' are MicroVM-only (VSOCK/vmnet) and have no container equivalent"
            )

        guard_guest(config, args)

        flake.require_flake(config)

        if args.container:
            ctn.dispatch(config, args)
        else:
            vm.dispatch(config, args)
    except TartarusError as exc:
        die(str(exc))

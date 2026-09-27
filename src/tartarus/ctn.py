"""Container actions: list/status/start/spawn/stop/restart/logs/ssh/build.

Containers are systemd-nspawn guests. Canonical instances are provisioned
host-side (``nixos-container`` registration, CA-signed host key, bind mounts)
while numbered/ad-hoc instances are created on the fly from the user's flake
(``nixosConfigurations.ctn-<name>``).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import NoReturn

from . import ca, ssh, system
from .config import Config
from .errors import TartarusError
from .nix import eval as nix_eval
from .nix import flake
from .output import c, die, info, ok, print_table, warn
from .process import run_sudo, run_sudo_quiet

# nixos-container's own config/state dirs once stateVersion >= 22.05: prefixed
# with "nixos-" to avoid colliding with podman/OCI's /etc/containers.
CTN_CONF_DIR = Path("/etc/nixos-containers")
_CTN_SKIP_CONF = {"libpod.conf", "containers.conf", "registries.conf"}

# Guards infinite recursion when a dependency cycle exists at runtime.
_STARTING: set[str] = set()


def _ensure_dependencies(config: Config, name: str) -> None:
    """Start any `requires` dependencies before ``name``."""
    guest = config.guest(name, "container")
    if guest is None:
        return
    for dep in guest.requires:
        if is_running(dep):
            continue
        if dep in _STARTING:
            continue
        dep_guest = config.require_guest(dep)
        if dep_guest.kind == "vm":
            from . import vm  # lazy to avoid a circular import

            vm.action_start(config, dep, mounts=[])
        else:
            action_start(config, dep)


def status_word(state: str) -> str:
    code = {"running": "32", "stopped": "90", "not provisioned": "33"}.get(state, "0")
    return c(code, state)


def list_templates(config: Config) -> list[str]:
    # `list` must enumerate only guests enabled on this host: config.toml is the
    # authoritative enabled set (the flake's outputs are generated from it).
    return [name for name in flake.list_templates(config, "container") if config.guest(name, "container") is not None]


def require_template(config: Config, name: str) -> None:
    flake.require_template(config, "container", name)


def base_name(config: Config, name: str) -> str:
    return flake.base_name(config, "container", name)


def list_conf_names() -> set[str]:
    if not CTN_CONF_DIR.is_dir():
        return set()
    return {f.stem for f in CTN_CONF_DIR.glob("*.conf") if f.name not in _CTN_SKIP_CONF}


def is_running(name: str) -> bool:
    result = subprocess.run(["systemctl", "is-active", "--quiet", f"container@{name}"])
    return result.returncode == 0


# The stable current-system symlink the container-host VM's root SSH login and
# this CLI use, so the command resolves without depending on root's non-login
# PATH (nix/guest/container-host.nix).
VM_SYSTEMCTL = "/run/current-system/sw/bin/systemctl"


def nested_host(config: Config, name: str) -> str | None:
    """The container-host VM name if `name` is a nested container, else None."""
    base = base_name(config, name)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        return guest.host
    return None


def _ssh_vm(
    config: Config, host: str, argv: list[str], user: str | None = None
) -> subprocess.CompletedProcess:
    """Run `argv` on the container-host VM `host` over SSH (non-interactive).

    BatchMode keeps a probe/start/stop from hanging on a password or host-key
    prompt: the host's ssh config already routes `<host>` (ProxyCommand), and
    the VM trusts the shared MicroVM client key for both the login user and
    root (nix/guest/container-host.nix), so mutating commands can run as `root`
    over key-only SSH.

    ``argv`` is joined into the remote command by ssh itself, which concatenates
    every post-host argument with spaces. A bare command (``["systemctl", "x"]``)
    is therefore fine, but a shell *script* must be passed as a single element
    (``[script]``) -- ``["sh", "-c", script]`` would be sent as
    ``sh -c printf ...`` and the remote ``sh`` would keep only the first token.
    """
    target = f"{user}@{host}" if user else host
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", target, *argv],
        capture_output=True,
        text=True,
        check=False,
    )


def nested_state(config: Config, host: str, name: str) -> str:
    """The state of a nested container's own unit inside its host VM."""
    result = _ssh_vm(config, host, [VM_SYSTEMCTL, "is-active", f"container@{name}"])
    return "running" if result.stdout.strip() == "active" else "stopped"


def nested_states(config: Config, host: str, names: list[str]) -> dict[str, str]:
    """Batch `nested_state` for several containers in one SSH round-trip."""
    names = [n for n in sorted(names) if re.fullmatch(r"[A-Za-z0-9_.-]+", n)]
    if not names:
        return {}
    script = "; ".join(
        f'printf "%s " "{n}"; {VM_SYSTEMCTL} is-active "container@{n}" 2>/dev/null || true'
        for n in names
    )
    # One element: ssh joins argv with spaces and the remote login shell runs the
    # string, so wrapping it as ["sh", "-c", script] would truncate it after the
    # first token (dropping the first name's state).
    result = _ssh_vm(config, host, [script])
    states = {n: "stopped" for n in names}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == "active":
            states[fields[0]] = "running"
    return states


def nested_systemctl(config: Config, host: str, verb: str, name: str) -> subprocess.CompletedProcess:
    """Run `systemctl <verb> container@<name>` as root inside the host VM.

    Root logs in over key-only SSH with the shared MicroVM client key
    (nix/guest/container-host.nix), so no passwordless-sudo grant is needed.
    """
    return _ssh_vm(config, host, [VM_SYSTEMCTL, verb, f"container@{name}"], user="root")


def read_local_address(name: str) -> str | None:
    conf = CTN_CONF_DIR / f"{name}.conf"
    if not conf.exists():
        return None
    match = re.search(r"^LOCAL_ADDRESS=(.+)$", conf.read_text(), re.MULTILINE)
    return match.group(1) if match else None


def used_ids() -> set[int]:
    used: set[int] = set()
    for name in list_conf_names():
        addr = read_local_address(name)
        if addr and addr.startswith("10.201.0."):
            used.add(int(addr.rsplit(".", 1)[1]))
    return used


def alloc_id() -> int:
    used = used_ids()
    for identifier in range(system.CTN_EPHEMERAL_ID_MIN, system.CTN_EPHEMERAL_ID_MAX + 1):
        if identifier not in used:
            return identifier
    die(
        "no free ephemeral container ID left "
        f"({system.CTN_EPHEMERAL_ID_MIN}-{system.CTN_EPHEMERAL_ID_MAX} all in use)"
    )


def next_instance_name(base: str) -> str:
    """First ``<base>-<N>`` (N from 2) not already registered."""
    existing = list_conf_names()
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if candidate not in existing:
            return candidate
    die(f"no free instance number for '{base}'")


def instance_info(
    config: Config,
    name: str,
    kind: str,
    host: str | None = None,
    states: dict[str, str] | None = None,
) -> dict:
    if host is not None:
        # A nested container has no `nixos-container` registration (and thus no
        # `/etc/nixos-containers/<name>.conf`) on the host; its unit lives inside
        # its container-host VM, so its state is queried there (`states` is a
        # batched pre-fetch; a lone call falls back to a direct query).
        if states is not None and name in states:
            status = states[name]
        else:
            status = nested_state(config, host, name)
        return {
            "name": name,
            "type": kind,
            "status": status,
            "address": None,
            "host": host,
        }
    if name not in list_conf_names():
        return {"name": name, "type": kind, "status": "not provisioned", "address": None, "host": host}
    return {
        "name": name,
        "type": kind,
        "status": "running" if is_running(name) else "stopped",
        "address": read_local_address(name),
        "host": host,
    }


def _host_of_by_template(config: Config, templates: list[str]) -> dict[str, str | None]:
    """Map each container template to its `host` pointer (`None` if native).

    Resolved once per template so `list`/`status` never re-run a nix eval for
    every table row just to read a name already present in config.toml.
    """
    host_of: dict[str, str | None] = {}
    for name in templates:
        guest = config.guest(name, "container")
        host_of[name] = guest.host if guest is not None else None
    return host_of


def collect_instances(config: Config) -> list[dict]:
    templates = list_templates(config)
    host_of = _host_of_by_template(config, templates)

    # Batch the nested-container unit states: one SSH round-trip per host VM
    # rather than one per container.
    names_by_host: dict[str, list[str]] = {}
    for name in templates:
        host = host_of[name]
        if host is not None:
            names_by_host.setdefault(host, []).append(name)
    states: dict[str, str] = {}
    for host, names in names_by_host.items():
        states.update(nested_states(config, host, names))

    entries = [instance_info(config, name, "template", host_of[name], states) for name in templates]

    extra = sorted(
        name for name in list_conf_names() if base_name(config, name) != name and base_name(config, name) in templates
    )
    entries += [
        instance_info(config, name, "instance", host_of.get(base_name(config, name)), states) for name in extra
    ]

    return entries


def action_list(config: Config, json_output: bool) -> None:
    entries = collect_instances(config)

    if json_output:
        print(json.dumps(entries, indent=2))
        return

    if not entries:
        print("No containers defined.")
        return

    rows = [
        [e["name"], status_word(e["status"]), e["type"], e["address"] or "-", e["host"] or "-"] for e in entries
    ]
    print_table(["NAME", "STATUS", "TYPE", "ADDRESS", "HOST"], rows)


def action_status(config: Config, name: str | None) -> None:
    if not name:
        action_list(config, False)
        return
    base = base_name(config, name)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        # A nested container is not registered with `nixos-container` on the
        # host; its unit lives inside its container-host VM. Report the unit's
        # own state there.
        state = nested_state(config, guest.host, name)
        print(f"{name}: nested in container-host VM '{guest.host}' ({status_word(state)})")
        return
    if name not in list_conf_names():
        print(f"{name}: {status_word('not provisioned')}")
        return
    state = "running" if is_running(name) else "stopped"
    addr = read_local_address(name)
    print(f"{name}: {status_word(state)}" + (f" ({addr})" if addr else ""))


def create_adhoc(config: Config, name: str, base: str) -> None:
    suffix = name[len(base) + 1 :] if name != base else name
    container_id = alloc_id()
    env_args = [
        f"HOME={config.home_dir}",
        f"PATH={os.environ.get('PATH', '')}",
        f"CONTAINER_INSTANCE_SUFFIX={suffix if name != base else ''}",
        f"CONTAINER_ID_OVERRIDE={container_id}",
    ]
    info(f"Building and creating '{name}' (id {container_id}) from template '{base}'...")
    run_sudo(
        [
            "env",
            *env_args,
            "nixos-container",
            "create",
            name,
            "--flake",
            f"{flake.flake_ref(config)}#{system.CTN_PREFIX}{base}",
            "--bridge",
            system.CTN_BRIDGE,
            "--host-address",
            system.CTN_HOST_IP,
            "--local-address",
            system.ctn_ip(container_id),
            "--auto-start",
        ]
    )
    ok(f"'{name}' created and started (id {container_id}).")
    print("    Note: ad-hoc instances have no bind-mounted shares and no CA-signed SSH")
    print(f"    cert (only the canonical '{base}' does).")


def action_start(config: Config, name: str, upgrade: bool = False) -> None:
    base = base_name(config, name)
    require_template(config, base)

    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        # Nested container: no `nixos-container` registration and no own unit on
        # the host. Its unit lives inside the container-host VM, so bring the VM
        # up (starting it also provisions the inner certs) and then start the
        # container's `container@<name>` unit over SSH.
        #
        # When the host VM is already up there is nothing to build or certify:
        # skip the cert pass (which otherwise touches every inner) and go
        # straight to the unit.
        if not ssh.is_running(config, guest.host):
            from . import vm  # lazy to avoid a circular import

            ca.ensure_ctn_certs(config, base)
            info(f"'{name}' runs inside container-host VM '{guest.host}'; ensuring the VM is up...")
            vm.action_start(config, guest.host, mounts=[], upgrade=upgrade)
        if nested_state(config, guest.host, name) == "running":
            warn(f"'{name}' is already running.")
            return
        result = nested_systemctl(config, guest.host, "start", name)
        if result.returncode != 0:
            die(f"failed to start '{name}' in container-host VM '{guest.host}': {result.stderr.strip()}")
        ok(f"'{name}' started.")
        return

    if name not in list_conf_names():
        if name != base:
            create_adhoc(config, name, base)
            return
        die(
            f"'{name}' is not provisioned on this host. Enable it in your tartarus "
            "configuration (tartarus.guests.<name> with kind = \"container\") and "
            "rebuild first -- that's what reserves its ID, CA-signed SSH cert, and "
            "bind mounts."
        )

    if is_running(name):
        warn(f"'{name}' is already running.")
        return

    _STARTING.add(name)
    try:
        _ensure_dependencies(config, name)
    finally:
        _STARTING.discard(name)

    ca.ensure_ctn_certs(config, base)
    run_sudo(["systemctl", "start", f"container@{name}"])
    ok(f"'{name}' started.")


def action_build(config: Config, name: str, upgrade: bool = False) -> None:
    base = base_name(config, name)
    require_template(config, base)

    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        # A nested container is built as part of its container-host VM's one
        # NixOS build (P2); there is no standalone `ctn-<name>` build to run.
        from . import vm  # lazy to avoid a circular import

        info(f"'{name}' is built as part of container-host VM '{guest.host}'.")
        vm.action_build(config, guest.host, mounts=[], upgrade=upgrade)
        return

    state = config.state_dir(name)
    state.mkdir(parents=True, exist_ok=True)
    nix_eval.build(flake.flake_ref(config), flake.ctn_config_attr(base), state / "result")
    ok(f"'{name}' built. Result: {state / 'result'}")


def action_spawn(config: Config, template: str, name_override: str | None) -> None:
    base = base_name(config, template)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        raise TartarusError(
            f"'{template}' is a nested container inside container-host VM "
            f"'{guest.host}'; ad-hoc instances are not supported. Add another "
            "declarative container to that VM's container set and rebuild."
        )
    name = name_override or next_instance_name(template)
    if name in list_conf_names():
        die(f"instance '{name}' already exists -- use `tartarus --container start {name}` instead")
    info(f"Spawning new '{template}' instance: {name}")
    create_adhoc(config, name, template)


def action_stop(config: Config, name: str, purge: bool, debug: bool = False) -> None:
    base = base_name(config, name)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        # Nested container: stop its own `container@<name>` unit inside the
        # container-host VM. A `--purge` has no meaning here -- the container is
        # declarative, owned by the VM's configuration.
        if purge:
            die(f"'{name}' is a nested container inside container-host VM '{guest.host}'; --purge is not supported. Remove it from the VM's container set and rebuild instead.")
        if not ssh.is_running(config, guest.host):
            warn(f"'{name}' is not running (container-host VM '{guest.host}' is down).")
            return
        result = nested_systemctl(config, guest.host, "stop", name)
        if result.returncode != 0:
            die(f"failed to stop '{name}' in container-host VM '{guest.host}': {result.stderr.strip()}")
        ok(f"'{name}' stopped.")
        return

    if name not in list_conf_names():
        warn(f"'{name}' does not exist.")
        return

    if is_running(name):
        run_sudo_quiet(["systemctl", "stop", f"container@{name}"], debug=debug)
        ok(f"'{name}' stopped.")
    else:
        warn(f"'{name}' is not running.")

    if purge:
        run_sudo_quiet(["nixos-container", "destroy", name], debug=debug)
        base = base_name(config, name)
        note = f" (re-provisioned on the next rebuild since '{base}' is canonical)" if name == base else ""
        ok(f"Purged '{name}'{note}.")


def action_restart(config: Config, name: str) -> None:
    base = base_name(config, name)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        # Nested container: restart its own `container@<name>` unit inside the
        # container-host VM (starting the VM first if it is down).
        if not ssh.is_running(config, guest.host):
            from . import vm  # lazy to avoid a circular import

            ca.ensure_ctn_certs(config, base)
            vm.action_start(config, guest.host, mounts=[], upgrade=False)
        result = nested_systemctl(config, guest.host, "restart", name)
        if result.returncode != 0:
            die(f"failed to restart '{name}' in container-host VM '{guest.host}': {result.stderr.strip()}")
        ok(f"'{name}' restarted.")
        return
    if name not in list_conf_names():
        die(f"'{name}' has never been created -- use `tartarus --container start` or `spawn` first")
    ca.ensure_ctn_certs(config, base)
    run_sudo(["systemctl", "restart", f"container@{name}"])
    ok(f"'{name}' restarted.")


def action_logs(config: Config, name: str) -> NoReturn:
    base = base_name(config, name)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        raise TartarusError(
            f"'{name}' is a nested container inside container-host VM "
            f"'{guest.host}'; it has no host-side journal. Read the VM's log "
            f"instead: tartarus logs {guest.host}"
        )
    os.execvp("journalctl", ["journalctl", "-u", f"container@{name}", "-f"])


def _ssh_nested(config: Config, base: str, host: str, start: bool) -> NoReturn:
    """Exec ``ssh`` into a nested container through its container-host VM.

    The container has no host-reachable address of its own, so the connection
    is jumped through the VM's sshd:

    * the target stays the **bare** ``<base>`` (never ``<base>.trs``) so it
      does not match the consumer's ``Host *.trs`` wildcard / ``ProxyCommand``;
    * ``-o HostName=<base>`` pins the connection hostname to the container's
      name so it resolves on the jump host (the VM's ``networking.hosts``
      entry), overriding any native-container Host block that would otherwise
      point it at a host-bridge IP;
    * ``-o ProxyJump=<host>.trs`` reaches the VM through that wildcard. Modern
      OpenSSH implements the jump as a child ``ssh -W <base>:22 <host>.trs``
      (verified on 10.3), so these ``-o`` options apply only to the target and
      never leak onto the jump's own host-key check;
    * ``-o HostKeyAlias=<base>.trs`` makes the ``@cert-authority *.trs`` line in
      ``known_hosts_trs`` apply, matching the CA-signed ``<base>.trs``
      principal;
    * the client key and ControlMaster plumbing mirror a native container.
    """
    from . import vm  # lazy to avoid a circular import

    if start:
        vm.action_start(config, host, mounts=[])
    elif not ssh.is_running(config, host):
        raise TartarusError(
            f"container-host VM '{host}' is not running; start it first: "
            f"tartarus start {host} (or pass --start)"
        )
    ca.ensure_ctn_certs(config, base)
    os.execvp(
        "ssh",
        [
            "ssh",
            "-o",
            f"HostName={base}",
            "-o",
            f"ProxyJump={host}.trs",
            "-o",
            f"HostKeyAlias={base}.trs",
            "-o",
            f"UserKnownHostsFile={ssh.known_hosts_trs(config)}",
            "-i",
            str(config.ssh_dir / "containers"),
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
            base,
        ],
    )


def action_ssh(config: Config, name: str, start: bool = False) -> NoReturn:
    base = base_name(config, name)
    require_template(config, base)
    guest = config.guest(base, "container")
    if guest is not None and guest.host is not None:
        _ssh_nested(config, base, guest.host, start)
    if start and not is_running(name):
        action_start(config, name)
    if not is_running(name):
        die(f"'{name}' is not running. Start it first: tartarus --container start {name}")

    if name == base:
        # Canonical instance: the host's ssh config already routes `ssh <name>`
        # using the CA-trusted host key baked in at rebuild time.
        ca.ensure_ctn_certs(config, base)
        os.execvp("ssh", ["ssh", name])

    # Numbered/custom instance: no static ssh_config entry and no CA-signed
    # cert -- connect by IP and trust its freshly-generated host key on first
    # connect, recorded separately from the CA-trusted known_hosts.
    addr = read_local_address(name)
    if addr is None:
        die(f"no recorded address for '{name}' in {CTN_CONF_DIR}/{name}.conf")
    known_hosts = str(config.ssh_dir / "known_hosts_containers_adhoc")
    os.execvp(
        "ssh",
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            f"IdentityFile={config.ssh_dir / 'containers'}",
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
            addr,
        ],
    )


def dispatch(config: Config, args) -> None:
    if args.command == "list":
        action_list(config, args.json)
    elif args.command == "status":
        action_status(config, args.name)
    elif args.command == "start":
        action_start(config, args.name, upgrade=getattr(args, "upgrade", False))
    elif args.command == "build":
        action_build(config, args.name, upgrade=getattr(args, "upgrade", False))
    elif args.command == "spawn":
        action_spawn(config, args.template, args.name)
    elif args.command == "stop":
        action_stop(config, args.name, args.purge, args.debug)
    elif args.command == "restart":
        action_restart(config, args.name)
    elif args.command == "logs":
        action_logs(config, args.name)
    elif args.command == "ssh":
        action_ssh(config, args.name, args.start)

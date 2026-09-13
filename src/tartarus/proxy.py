"""HTTP proxy endpoint resolution (host vs guest).

PHASE 3 SEAM. The Squid transport itself is Phase 5; this module only answers
"which address:port does a guest of kind ``vm``/``container`` use to reach the
proxy", mirroring the placement rules in PLAN.md §3.5. No filtering lives
here -- that is per guest and generated in Nix.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import system
from .config import Config
from .errors import TartarusError


@dataclass(frozen=True)
class ProxyEndpoint:
    """A reachable proxy address for one guest kind."""

    host: str
    port: int

    def url(self, scheme: str = "http") -> str:
        return f"{scheme}://{self.host}:{self.port}"


def resolve(config: Config, kind: str = "vm") -> ProxyEndpoint:
    """Resolve the proxy endpoint a guest of ``kind`` should use.

    ``location = "host"`` binds the trs bridge (or the vmnet gateway on
    Darwin); a guest-named location routes to that guest's static VM IP
    (Linux-only by assertion, PLAN.md §3.3).
    """
    if not config.proxy.enable:
        raise TartarusError("the tartarus proxy is not enabled in config.toml")

    if config.proxy.location == "host":
        if config.system.endswith("-darwin"):
            host = system.DARWIN_GATEWAY
        else:
            host = system.VM_HOST_IP if kind == "vm" else system.CTN_HOST_IP
        return ProxyEndpoint(host=host, port=config.proxy.port)

    guest = config.guest(config.proxy.location)
    if guest is None:
        raise TartarusError(
            f"proxy location '{config.proxy.location}' is not an enabled guest in config.toml"
        )
    if guest.kind != "vm":
        raise TartarusError(f"proxy location '{guest.name}' must be a vm guest")
    if guest.id is None:
        raise TartarusError(
            f"no id recorded for vm guest '{guest.name}' in config.toml; rebuild your host to regenerate it"
        )

    return ProxyEndpoint(host=system.vm_ip(guest.id), port=config.proxy.port)

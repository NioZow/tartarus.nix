"""``tartarus``: run MicroVMs and containers defined in *your* flake.

The CLI is guest-kind-agnostic: ``--container`` switches the same flat command
set from MicroVMs (the default) to systemd-nspawn containers. The flake being
built is always the user's own (``config.toml``), never tartarus's repo.
"""

from __future__ import annotations

__version__ = "0.1.0"

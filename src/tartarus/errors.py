"""Exceptions raised by the tartarus package.

Library code raises :class:`TartarusError` for expected, user-facing failures
so the CLI can render a single clean message instead of a traceback. Anything
else bubbling up is a genuine bug.
"""

from __future__ import annotations


class TartarusError(Exception):
    """An expected, user-facing failure."""

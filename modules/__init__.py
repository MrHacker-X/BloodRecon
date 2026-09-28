"""Legacy modules/ import shim — the real modules live in bloodrecon/modules/.

Only here so old checkouts (and muscle memory) keep working; new code
should import from ``bloodrecon.modules``.
"""
import importlib
import sys

from bloodrecon.modules import *  # noqa: F401,F403
from bloodrecon.modules import registry  # noqa: F401

# re-export each module for `from modules import ip_lookup` style imports
_SUBMODULES = [m["module"] for m in registry.REGISTRY] + ["colors", "registry"]
for _sub in _SUBMODULES:  # pragma: no cover
    try:
        sys.modules[__name__ + "." + _sub] = importlib.import_module(
            "bloodrecon.modules." + _sub
        )
    except ImportError:
        pass

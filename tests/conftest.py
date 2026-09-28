"""Offline, color-free, deterministic test environment."""
import os

# Must be set BEFORE bloodrecon is imported anywhere: color support is
# decided at import time.
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"
os.environ.pop("BLOODRECON_FORCE_COLOR", None)
os.environ.pop("BLOODRECON_THEME", None)  # legacy env, ignored anyway

import pytest

from bloodrecon.modules import colors


@pytest.fixture(autouse=True)
def _reset_theme_state():
    """Every test starts from the default theme with colors disabled."""
    colors.disable_colors()
    colors.set_theme("blood")
    yield
    colors.disable_colors()

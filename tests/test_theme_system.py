"""Theme system: lifecycle, purity, and export-surface regression tests."""
import pytest

from bloodrecon.modules import colors


ALL_ROLE_COLORS = [
    "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE", "BLACK",
]


def test_legacy_colors_cover_expected_surface():
    for name in ALL_ROLE_COLORS + ["RESET_ALL"]:
        assert hasattr(colors, name), f"legacy export missing: {name}"


def test_import_star_exports_everything_in_all():
    ns = {}
    exec("from bloodrecon.modules.colors import *", ns)
    missing = [n for n in colors.__all__ if n not in ns]
    assert not missing, f"import * misses: {missing}"


def test_disable_strips_ansi_from_legacy_colors():
    colors.disable_colors()
    for name in ALL_ROLE_COLORS:
        assert "\x1b[" not in getattr(colors, name), f"{name} leaked ANSI"


def test_disable_strips_reset_sequences():
    colors.disable_colors()
    assert "\x1b[" not in colors.RESET_ALL


def test_single_palette_identity():
    """The one professional palette is active and the only one offered."""
    colors.enable_colors()
    assert colors.available_themes() == ["pro"]
    assert colors.current_theme() == "pro"


def test_legacy_theme_names_are_accepted_and_ignored(monkeypatch):
    monkeypatch.setenv("BLOODRECON_FORCE_COLOR", "1")
    colors.enable_colors()
    for legacy in ("blood", "matrix", "ice", "mono"):
        colors.set_theme(legacy)
        assert colors.current_theme() == "pro"
        assert "\x1b[" in colors.RED  # still colored
    colors.set_theme("pro")
    assert "\x1b[" in colors.RED


def test_enable_rebuilds_colors_after_disable():
    colors.enable_colors()
    colored = colors.RED
    colors.disable_colors()
    assert colors.RED == ""
    colors.enable_colors()
    assert colors.RED == colored

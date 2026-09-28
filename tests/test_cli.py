"""CLI surface: dispatch wiring, argument parsing, offline module execution."""
import pytest

from bloodrecon import cli
from bloodrecon.modules import registry

ALL_FLAGS = {e["flag"] for e in registry.REGISTRY}


def _flags():
    p = cli.build_parser()
    return {a.option_strings[0] for a in p._actions if a.option_strings}


def test_registry_has_every_expected_field():
    for e in registry.REGISTRY:
        assert e["module"] and e["func"] and e["flag"] and e["example"], e


def test_every_module_callable_exists():
    for e in registry.REGISTRY:
        mod = __import__(f"bloodrecon.modules.{e['module']}", fromlist=[e["func"]])
        assert callable(getattr(mod, e["func"], None)), (
            f"{e['module']}.{e['func']} missing"
        )


def test_all_registry_flags_in_parser():
    flags = _flags()
    missing = ALL_FLAGS - flags
    assert not missing, f"registry flags missing from argparse: {missing}"


def test_parser_has_utility_flags():
    flags = _flags()
    for f in ("--interactive", "--themes", "--version", "--no-color"):
        assert f in flags, f"parser missing {f}"


def test_theme_flag_removed():
    flags = _flags()
    assert "--theme" not in flags, "single palette: --theme should be gone"


def test_no_flag_collisions():
    assert len(ALL_FLAGS) == len(set(ALL_FLAGS)), "duplicate flags in registry"


@pytest.mark.parametrize(
    "args,expect",
    [
        (["--temp-email", "test@10minutemail.com"], "TEMPORARY"),
        (["--useragent", "Mozilla/5.0 Chrome/120.0"], "Google Chrome"),
        (["--dork", "example.com"], "Dorks"),
        (["--maps", "https://www.google.com/maps/@51.5,-0.1,15z"], "DMS"),
    ],
)
def test_offline_module_runs(args, expect, capsys):
    rc = cli.main(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert expect in out


@pytest.mark.parametrize(
    "args",
    [
        ["--temp-email", "zzz###"],
        ["--useragent", "zzz###"],
        ["--dork", ""],
        ["--dork", "   "],
        ["--maps", "zzz###"],
    ],
)
def test_invalid_input_never_crashes_or_steals_stdin(args, capsys):
    rc = cli.main(args)
    out = capsys.readouterr()
    assert rc in (0, 1, 2), f"unexpected exit code: {rc}"
    combined = out.out + out.err
    assert "Traceback" not in combined
    assert combined.strip(), "no user feedback at all"


def test_empty_target_is_rejected_cleanly(capsys):
    rc = cli.main(["--dork", ""])
    out = capsys.readouterr()
    assert rc == 2
    assert "--dork" in out.out


# ---------------------------------------------------------------------------
# Menu layout invariant: every rendered row must match the border width
# ---------------------------------------------------------------------------

import io
from contextlib import redirect_stdout


def _render_menu(width):
    cli._W = lambda: width
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.display_menu()
    return buf.getvalue().splitlines()


@pytest.mark.parametrize("width", [140, 120, 100, 80, 72, 71, 60, 45])
def test_menu_rows_align_with_borders(width):
    lines = _render_menu(width)
    edge = next(len(l) for l in lines if l.startswith("╔"))
    rows = [l for l in lines if "║" in l]
    assert rows, "menu rendered no rows"
    off = [l for l in rows if len(l) != edge]
    assert not off, f"rows off-border at width {width}: {[len(l) for l in off]}"


def test_menu_footer_inside_box_at_min_width():
    lines = _render_menu(46)  # min_w for single column
    edge = next(len(l) for l in lines if l.startswith("╔"))
    footer = [l for l in lines if "[0] Exit" in l]
    assert footer and len(footer[0]) <= edge


def test_show_list_lists_all_modules(capsys):
    rc = cli.main(["--list"])
    out = capsys.readouterr().out
    assert rc == 0
    for entry in registry.REGISTRY:
        assert entry["flag"] in out, f"--list missing {entry['flag']}"


def test_interactive_help_and_quit(monkeypatch, capsys):
    answers = iter(["?", "0"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    rc = cli.main(["--interactive"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "--ip" in out and "Thank you for using" in out


def test_interactive_about_waits_for_enter(monkeypatch, capsys):
    # a -> about screen, "" -> press enter to continue, 0 -> exit
    answers = iter(["a", "", "0"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    rc = cli.main(["--interactive"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ABOUT BLOODRECON" in out
    # about must finish before exit; without the Enter pause the "" would be
    # consumed as the next menu choice and we would never reach "0"
    assert "Thank you for using" in out

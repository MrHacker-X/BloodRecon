"""Package-level checks: version sync, imports, entry points."""
import re
from pathlib import Path

import bloodrecon
from bloodrecon import cli


def test_version_format():
    assert re.fullmatch(r"\d+\.\d+\.\d+", bloodrecon.__version__)


def test_version_matches_pyproject():
    root = Path(__file__).resolve().parent.parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "pyproject.toml has no static version"
    assert m.group(1) == bloodrecon.__version__, (
        "pyproject version and bloodrecon.__version__ are out of sync"
    )


def test_main_importable_from_both_paths():
    assert callable(bloodrecon.main)
    assert callable(cli.main)


def test_legacy_shim_is_import_light():
    """The root bloodrecon.py shim must not import the package on import."""
    root = Path(__file__).resolve().parent.parent
    src = (root / "bloodrecon.py").read_text(encoding="utf-8")
    assert "from bloodrecon.cli import main" in src
    assert src.index("if __name__") < src.index("from bloodrecon.cli import main")


def test_console_script_declared():
    root = Path(__file__).resolve().parent.parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'bloodrecon = "bloodrecon.cli:main"' in text

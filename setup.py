"""Build hooks for BloodRecon.

Keeps a local Shodan ``config.py`` (if someone still has a leftover in the
source tree) out of the wheel. Metadata and package layout live in
``pyproject.toml``; this file only customises ``build_py``.
"""
from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

_SKIP_MODULES = {("bloodrecon.modules", "config")}


class build_py(_build_py):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [m for m in modules if (m[0], m[1]) not in _SKIP_MODULES]


setup(cmdclass={"build_py": build_py})

#!/usr/bin/env python3
"""Backwards-compatible launcher — the real package lives in bloodrecon/.

Keep this module import-light: build tools may resolve the name
``bloodrecon`` against THIS file before the bloodrecon/ package.
"""
if __name__ == "__main__":
    import sys

    from bloodrecon.cli import main

    sys.exit(main())

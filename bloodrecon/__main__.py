"""`python -m bloodrecon` entry point."""
import sys

from bloodrecon.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        from bloodrecon.modules.colors import print_warning

        print()
        print_warning("Interrupted by user")
        sys.exit(130)

"""Allow ``python -m header_checker``."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

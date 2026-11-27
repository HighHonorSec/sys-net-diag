"""Module entrypoint for `python -m sys_net_diag`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

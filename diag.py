#!/usr/bin/env python3
"""Direct script entrypoint for sys-net-diag."""

import sys

from sys_net_diag.cli import main

if __name__ == "__main__":
    sys.exit(main())

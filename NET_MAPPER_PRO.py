#!/usr/bin/env python3
"""
NetMapperPro entry point.

The scanner now lives in the netmapper/ package beside this file. This script
stays so that the documented commands and `import NET_MAPPER_PRO as mapper`
(used by the web app) keep working unchanged.
"""

import sys
from pathlib import Path

# `python -I` leaves this script's own folder off sys.path, so add it
# explicitly. This is the repo folder, never the current working directory.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from netmapper import *  # noqa: E402,F401,F403  re-export for the web app
from netmapper import __all__  # noqa: E402,F401
from netmapper.cli import main  # noqa: E402

if __name__ == "__main__":
    main()

"""``python -m tgmint`` — thin wrapper around :func:`tgmint.cli.main`.

Runs today, before pyproject's ``[project.scripts]`` wiring lands: the
module exists, so ``python -m tgmint <command>`` works from any
checkout with ``src/`` on the path (or an installed wheel).
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

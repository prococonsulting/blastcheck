"""
`python -m blastcheck` entry point.

The CLI itself lives in cli.py, not here. PyInstaller deliberately refuses to
bundle a package's `__main__` submodule — it would collide with the frozen
application's own `__main__` — so a CLI implemented in this file cannot be
packaged as a single-file binary at all. The build succeeds and the binary dies
on its first import, which is the worst way for that to be discovered.
"""
import sys

from .cli import _entry

if __name__ == "__main__":
    sys.exit(_entry())

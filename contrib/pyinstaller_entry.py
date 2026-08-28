"""
PyInstaller entry script.

Not importable as `blastcheck.__main__`: PyInstaller refuses to bundle a
package's `__main__` submodule, because the frozen application defines its own.
This file exists so the single-file binary has a top-level script to start from
that reaches the real CLI by ordinary import.
"""
import sys

from blastcheck.cli import _entry

if __name__ == "__main__":
    sys.exit(_entry())

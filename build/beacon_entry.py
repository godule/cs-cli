#!/usr/bin/env python3
"""Entrypoint for PyInstaller-compiled beacon binary.

This module imports the self-contained beacon (from the cscli package) and
invokes its main() with runtime-provided arguments (server URL, key, etc.).
PyInstaller bundles all of cs.* into the binary, so no files need shipping.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__) if not sys.frozen
                        else sys.executable)
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for p in (_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from cs.client.beacon import main, Beacon  # noqa: E402


if __name__ == "__main__":
    main()

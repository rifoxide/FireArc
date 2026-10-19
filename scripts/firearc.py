#!/usr/bin/env python3
"""Run the FireArc project CLI directly from a checkout, without installation."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from firearc.cli import main

if __name__ == "__main__":
    main()

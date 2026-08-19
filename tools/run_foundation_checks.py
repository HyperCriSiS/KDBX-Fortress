#!/usr/bin/env python3
"""Run the dependency-free, fast Phase-0 foundation checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COMMANDS = [
    [sys.executable, "tools/validate_form_fixtures.py", "--self-test"],
    [sys.executable, "tools/validate_form_fixtures.py"],
    [sys.executable, "tools/check_rust_core_policy.py", "--self-test"],
    [sys.executable, "tools/check_rust_core_policy.py"],
    [sys.executable, "tools/validate_kdbx_fixtures.py"],
    [sys.executable, "tools/validate_kdbx_fixtures.py", "--self-test"],
    [sys.executable, "tools/verify_negative_kdbx_derivations.py"],
]


def main() -> None:
    for command in COMMANDS:
        subprocess.run(command, cwd=ROOT, check=True)
    print("Foundation checks OK")


if __name__ == "__main__":
    main()

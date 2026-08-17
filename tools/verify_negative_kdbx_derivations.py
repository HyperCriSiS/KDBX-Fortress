#!/usr/bin/env python3
"""Verify that committed negative KDBX fixtures are deterministic mutations.

The negative corpus must remain reproducible from a known-good synthetic fixture;
otherwise a binary replacement could silently change the failure class under test.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "kdbx"


def main() -> None:
    good = (FIXTURES / "basic-kdbx4.kdbx").read_bytes()
    truncated = (FIXTURES / "truncated-header-kdbx4.kdbx").read_bytes()
    bad_signature = (FIXTURES / "bad-signature-kdbx4.kdbx").read_bytes()

    if truncated != good[:8]:
        raise SystemExit(
            "truncated-header-kdbx4.kdbx is not the first 8 bytes of basic-kdbx4.kdbx"
        )

    if len(bad_signature) != len(good):
        raise SystemExit("bad-signature-kdbx4.kdbx changed fixture length")
    if bad_signature[1:] != good[1:]:
        raise SystemExit(
            "bad-signature-kdbx4.kdbx modifies bytes outside the first signature byte"
        )
    if bad_signature[0] == good[0]:
        raise SystemExit("bad-signature-kdbx4.kdbx does not corrupt the signature")

    print("negative KDBX derivations are deterministic")


if __name__ == "__main__":
    main()

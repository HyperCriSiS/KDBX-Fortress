# KDBX3 Format300 fixture license audit

Status: evidence audit only; fixture import remains blocked pending authoritative license coverage.

## Scope

This audit checks the official `keepassxreboot/keepassxc` Git tree for fixture-scoped licensing evidence relevant to `tests/data/Format300.kdbx`.

## Verified repository evidence

- Repository: `keepassxreboot/keepassxc`
- Branch inspected: `develop`
- Fixture: `tests/data/Format300.kdbx`
- Fixture Git blob: `dc67f35a11ec8caf49583798280aa883657436e2`
- Fixture size: 2014 bytes
- The recursively inspected `tests` tree contains no `LICENSE`, `COPYING`, or `README` file under `tests/` or `tests/data/` that assigns a fixture-specific license to `Format300.kdbx`.
- The repository root contains multiple distinct license texts, including GPL-2, GPL-3, LGPL, BSD, MIT, CC0 and OFL license files. Their presence alone is therefore not sufficient evidence to assign one of them specifically to this binary test fixture.
- The introducing history anchor remains `18d3fe55f883d000b499804e22590f0c86399a63`; the presence of GPL-licensed source/test code in that commit is contextual evidence, not a fixture-specific license grant.

## Decision

Do **not** import `Format300.kdbx` into KDBX Fortress yet. The fixture remains blocked until authoritative evidence establishes that redistribution of the exact binary fixture is compatible with this repository's licensing policy.

Once license coverage is established, the next required steps remain:

1. import the exact upstream bytes;
2. compute and record a cryptographic SHA-256 of the imported file;
3. independently open/validate the fixture with password `a` using a second KDBX implementation;
4. record the expected semantic contents and validation result before treating it as a compatibility oracle.

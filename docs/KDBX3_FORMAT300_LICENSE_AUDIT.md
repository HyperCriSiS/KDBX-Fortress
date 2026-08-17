# KDBX3 Format300 fixture license audit

Status: evidence audit only; fixture import remains blocked pending authoritative license coverage.

## Scope

This audit checks the official `keepassxreboot/keepassxc` Git tree and history for licensing evidence relevant to `tests/data/Format300.kdbx`.

## Verified repository evidence

- Repository: `keepassxreboot/keepassxc`
- Current upstream commit inspected: `0e1510d71ab63ce1edddb71257bce34a7cee2f0d`
- Fixture: `tests/data/Format300.kdbx`
- Current fixture Git blob: `dc67f35a11ec8caf49583798280aa883657436e2`
- Fixture size: 2014 bytes
- The recursively inspected `tests` tree contains no `LICENSE`, `COPYING`, or `README` file under `tests/` or `tests/data/` that assigns a fixture-specific license to `Format300.kdbx`.
- The repository root contains multiple distinct license texts, including GPL-2, GPL-3, LGPL, BSD, MIT, CC0 and OFL license files. Their presence alone is therefore not sufficient evidence to assign one of them specifically to this binary test fixture.
- The current root `COPYING` uses file-scoped copyright/license mappings for exceptions and third-party material, so root license-file presence must not be treated as an automatic fixture assignment.

## Historical evidence around the fixture introduction

- `Format300.kdbx` was introduced by Felix Geyer in upstream commit `18d3fe55f883d000b499804e22590f0c86399a63` on 2012-09-25 together with the format-3.00 reader test.
- That commit tests the fixture with password `a` and expects root group `Format300` and database name `Test Database Format 0x00030000`.
- The same introducing commit adds/changes reader and test-support source files carrying explicit GNU GPL version 2 or version 3 licensing notices. This is strong contextual evidence for the surrounding contribution, but the binary fixture itself carries no inline notice.
- Before the fixture was introduced, upstream commit `a3d8c1a4d2ece9c2f9f21724ce06979989e6ec17` (2012-04-24) shows the repository `COPYING` copyright-format data with the project-level/default license entry `License: GPL-2 or GPL-3`, followed by more-specific `Files:` mappings for material under other licenses.
- Earlier commit `50e5b247405d64de0b89a1f9bca15f592182c4b4` (2012-01-05) already shows the same default `License: GPL-2 or GPL-3` entry before the specific file exceptions.
- The initial repository import `3e3c23e4adc743b1346c20a02f01faac2e6ced6c` likewise states that KeePassX is redistributable/modifiable under GPL version 2 or version 3.

## Licensing conclusion

The historical evidence now strongly supports that `Format300.kdbx` was created inside a GPL-2-or-GPL-3 project contribution whose surrounding test implementation was explicitly GPL-2/3. However, the evidence collected so far does **not** include an unambiguous fixture-specific `Files:` mapping, per-file notice, or later upstream statement explicitly assigning the exact binary `tests/data/Format300.kdbx` to that license.

Therefore KDBX Fortress must not represent the fixture-specific redistribution question as conclusively resolved yet. This is intentionally conservative: the historical project-level license context is recorded, but it is not promoted into a stronger legal claim than the upstream metadata directly proves.

## Decision

Do **not** import `Format300.kdbx` into KDBX Fortress yet. The fixture remains blocked until authoritative evidence establishes redistribution coverage of the exact binary fixture, or an alternative independently generated/clearly licensed KDBX3 oracle is selected.

Once license coverage is established, the next required steps remain:

1. import the exact approved fixture bytes;
2. compute and record a cryptographic SHA-256 of the imported file;
3. independently open/validate the fixture with password `a` using a second KDBX implementation;
4. record the expected semantic contents and validation result before treating it as a compatibility oracle.

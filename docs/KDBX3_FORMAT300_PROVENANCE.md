# KeePassXC `Format300.kdbx` provenance anchor

## Verified upstream anchor

This document records only facts verified against the official `keepassxreboot/keepassxc` GitHub repository before importing the binary fixture.

- Upstream repository: `keepassxreboot/keepassxc`
- Upstream branch inspected: `develop`
- Upstream file: `tests/data/Format300.kdbx`
- Git blob object ID: `dc67f35a11ec8caf49583798280aa883657436e2`
- Blob size: 2014 bytes
- Upstream history anchor: commit `18d3fe55f883d000b499804e22590f0c86399a63`
- Upstream semantic oracle: `tests/TestKdbx3.cpp` (Git blob object ID `df76a55de0b366a6bd43212a58d5ada0c60adb43` at the originally inspected tree)

The blob ID was re-verified directly from the Git tree at the history anchor `18d3fe55f883d000b499804e22590f0c86399a63` and from current `develop`; both resolve `tests/data/Format300.kdbx` to `dc67f35a11ec8caf49583798280aa883657436e2`. The previously recorded `2a71e8c3c2cc9bb1e68f86badda6b36fb4ffa107` value is not the file blob and must not be used as a provenance identifier.

The Git blob object ID above is **not** the fixture SHA-256 required by `docs/FIXTURE_PROVENANCE.md`. A cryptographic SHA-256 must be calculated from the exact imported bytes and recorded before the fixture is accepted.

## License-context evidence

Git history shows that `tests/data/Format300.kdbx` first entered upstream in commit `18d3fe55f883d000b499804e22590f0c86399a63` on 2012-09-25. The same commit added and modified reader/test code, including `src/streams/StoreDataStream.cpp` and `src/streams/StoreDataStream.h`; those source files carry an explicit GNU GPL version 2 or, at the recipient's option, version 3 notice.

This is useful repository- and commit-level licensing context, but it is **not** treated as a fixture-specific grant. The binary fixture itself has no embedded textual license notice in the Git object metadata exposed through GitHub. The fixture-specific license requirement therefore remains open until an authoritative upstream policy or maintainer statement clearly covers test data/fixtures.

## Upstream expected semantics

The upstream KDBX3 test establishes these observable expectations for `Format300.kdbx`:

- Credential: password `a`.
- Format: KDBX 3.0.
- Root group name: `Format300`.
- Root contains one child group and one direct entry.
- First child group: `Recycle Bin`.
- Recycle Bin is enabled and its configured UUID matches that group.
- Root entry title: `Sample Entry`.
- Root entry username: `User Name`.
- Root entry URL: `http://www.somesite.com/`.
- Nested group `General` contains two child groups and no direct entries.
- Nested group `Windows` contains no child groups and no direct entries.

These expectations come from KeePassXC's own `TestKdbx3.cpp`; they are an upstream semantic oracle, not yet an independent-reader validation for KDBX Fortress.

## Acceptance items still open

The binary fixture is intentionally **not** imported by this change. Before it can become the KDBX3 compatibility oracle, the repository policy still requires:

- confirm and record license/provenance applicable specifically to the upstream fixture;
- import the exact upstream bytes and calculate/pin their SHA-256;
- verify with at least one independent reader that the file is KDBX3 and opens with the documented credential;
- record the complete fixture manifest fields required by `docs/FIXTURE_PROVENANCE.md`;
- run the repository fixture validator in CI.

KeePassXC contains `COPYING` plus multiple component license files, so a fixture-specific license is not inferred merely from repository-level license files. The introduction commit's GPL-marked source files are recorded above as additional context only, not as closure of this requirement.

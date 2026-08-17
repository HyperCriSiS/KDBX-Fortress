# KeePassXC `Format300.kdbx` provenance anchor

## Verified upstream anchor

This document records only facts verified against the official `keepassxreboot/keepassxc` GitHub repository before importing the binary fixture.

- Upstream repository: `keepassxreboot/keepassxc`
- Upstream branch inspected: `develop`
- Upstream file: `tests/data/Format300.kdbx`
- Git blob object ID: `2a71e8c3c2cc9bb1e68f86badda6b36fb4ffa107`
- Upstream history anchor: commit `18d3fe55f883d000b499804e22590f0c86399a63`
- Upstream semantic oracle: `tests/TestKdbx3.cpp` (Git blob object ID `df76a55de0b366a6bd43212a58d5ada0c60adb43` at the inspected `develop` tree)

The Git blob object ID above is **not** the fixture SHA-256 required by `docs/FIXTURE_PROVENANCE.md`. A cryptographic SHA-256 must be calculated from the exact imported bytes and recorded before the fixture is accepted.

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

KeePassXC contains `COPYING` plus multiple component license files, so a fixture-specific license is not inferred merely from repository-level license files.

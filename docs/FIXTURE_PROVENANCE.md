# KDBX fixture provenance and acceptance policy

## Purpose

The compatibility corpus is security-critical test input. A fixture is only useful when its origin, expected behavior, credentials and derivation are reproducible and independently checkable. This document defines the acceptance rules for adding KDBX fixtures to the repository.

## Required metadata

Every positive fixture must record, directly or through the fixture manifest:

- KDBX major version and relevant format options.
- Cipher and KDF, including meaningful KDF parameters where applicable.
- Credential type used to open it (password, keyfile, composite credentials).
- Expected groups, entries and relevant feature payloads such as attachments, history, Unicode and custom data.
- SHA-256 of the committed fixture.
- Generator and generator version, or a precise upstream provenance reference.
- At least one independent reader used as a compatibility oracle when practical.

Every negative/adversarial fixture must additionally record:

- The valid source fixture or deterministic construction procedure it derives from.
- The exact mutation performed.
- The expected failure class.
- A check that the mutation did not unintentionally alter unrelated bytes when the fixture is derivative.

## Trusted fixture sources

Fixtures may be accepted from the following sources, in descending preference:

1. Deterministically generated local fixtures whose generator command/script is kept in the repository and whose output can be verified by an independent KDBX implementation.
2. Upstream fixtures from established KDBX implementations such as KeePassXC or KeePass when the exact source revision and license/provenance are recorded.
3. Small synthetic derivatives of an accepted fixture for negative testing, provided the derivation is deterministic and automatically verified.

Do not add an opaque binary copied from an unknown download, issue attachment or personal password database.

## KDBX3 acceptance gate

The first KDBX3 fixture must not be fabricated by manually editing KDBX4 bytes. It must be produced by a known implementation capable of writing KDBX3 or taken from an established upstream test corpus with clear provenance. Before it becomes a compatibility oracle:

1. Record the producing implementation/version or upstream revision.
2. Verify that at least one independent reader identifies it as KDBX3 and opens it with the documented credentials.
3. Record expected semantic contents in the fixture manifest.
4. Pin its SHA-256.
5. Run the repository fixture validator in CI.

Only after this baseline exists should KDBX3-specific keyfile, KDF, cipher, history and adversarial variants be added.

## Keyfile and composite-credential fixtures

Keyfiles are committed only when they are synthetic test material and contain no real secret. The manifest must identify whether a fixture requires password-only, keyfile-only or composite credentials. Tests must include wrong-password, wrong-keyfile and missing-keyfile failure cases without exposing credential material in logs.

## Interoperability oracle

A fixture used to claim KDBX compatibility should be checked with at least two independent implementations where practical. The project implementation under test never counts as its own oracle. Round-trip tests must distinguish:

- readable by reference implementation;
- readable by KDBX Fortress;
- written by KDBX Fortress and reopened by KDBX Fortress;
- written by KDBX Fortress and reopened by an independent implementation.

## Repository hygiene

Fixtures must contain synthetic identities and credentials only. Do not include personal URLs, emails, passwords, tokens or exported real vault data. Any generator or fixture metadata added to the repository must pass the normal secret-scanning and Foundation checks.

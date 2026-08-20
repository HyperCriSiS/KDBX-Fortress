# KDBX Compatibility Fixture Matrix

## Purpose

This document defines the deterministic interoperability corpus that must exist before KDBX Fortress exposes production vault operations to Android. It is intentionally engine-neutral: the same fixtures and acceptance criteria are used to evaluate an upstream Rust dependency, a hardened fork, or an independent orchestration layer.

## Reference implementations

Every fixture category should have at least one independently generated oracle from a non-Rust implementation where practical. Preferred references are KeePassXC and KeePass 2.x. Fixtures inherited from `keepass-rs` / `keepass-ng` are useful regression inputs but do not count as independent interoperability evidence because those projects belong to the same implementation family.

## Deterministic fixture matrix

| ID | Format | KDF | Outer cipher | Required content | Required assertion |
| --- | --- | --- | --- | --- | --- |
| `kdbx3-aes-aeskdf-basic` | KDBX 3.1 | AES-KDF | AES-256 | groups, entries, protected password, custom fields | open + exact metadata/secret values |
| `kdbx4-aes-argon2id-basic` | KDBX 4.x | Argon2id | AES-256 | groups, entries, protected password, custom fields | open + exact metadata/secret values |
| `kdbx4-chacha-argon2id-basic` | KDBX 4.x | Argon2id | ChaCha20 | same logical dataset as AES fixture | open + exact metadata/secret values |
| `kdbx4-keyfile` | KDBX 4.x | Argon2id | AES-256 | password + keyfile credentials | correct keyfile succeeds; wrong/missing keyfile fails |
| `kdbx4-attachments` | KDBX 4.x | Argon2id | AES-256 | small binary attachment and empty attachment | attachment metadata and bytes preserved |
| `kdbx4-custom-data` | KDBX 4.1 | Argon2id | AES-256 | custom database/group/entry data and unknown-but-preservable fields | round trip without silent loss |
| `kdbx4-history` | KDBX 4.x | Argon2id | AES-256 | entry history plus protected fields | history retained after round trip |
| `kdbx4-unicode` | KDBX 4.x | Argon2id | AES-256 | Unicode titles, usernames, URLs, notes and custom fields | exact UTF-8 round trip |
| `kdbx4-empty-edge` | KDBX 4.0 | Argon2d | AES-256 | empty strings, missing optional fields, empty groups | no invented values or crashes |
| `kdbx4-large-bounded` | KDBX 4.0 | Argon2d | AES-256 | 65,536-byte Notes value and deterministic 262,144-byte attachment | exact content preserved; exact configured boundary accepted; one-byte-lower ceilings reject with typed errors |

## Negative and adversarial corpus

The corpus must also include deterministic failures:

- wrong password;
- wrong keyfile;
- truncated header;
- truncated encrypted payload;
- invalid header field lengths;
- unsupported KDBX version;
- unsupported cipher/KDF identifier;
- corrupt authentication/integrity data;
- excessive Argon2 parameters beyond configured resource limits;
- compressed payload that would exceed decompression limits;
- oversized attachment/custom-data declarations;
- malformed XML / invalid nesting;
- duplicate or otherwise invalid identifiers where the selected engine has defined behavior.

Every negative fixture must fail closed with a stable `VaultError` category and must not panic.

### Materialized accepted-edge reference fixtures

The Phase 0 accepted corpus now includes two KDBX 4.0 edge fixtures materialized with pinned KeePass 2.61.1/KPScript/KeePassLib rather than the Fortress serializer:

- `kdbx4-empty-edge.kdbx.b64`: empty `Synthetic` group plus a `Blank Fields` entry whose optional string values are empty/omitted; the read assertion forbids invented non-empty values.
- `kdbx4-large-bounded.kdbx.b64`: exact 65,536-byte Notes value plus deterministic 262,144-byte `payload.bin`; Fortress accepts the exact configured field/attachment ceilings and rejects one-byte-lower field, per-attachment and aggregate-attachment ceilings through typed errors.

Their decoded SHA-256 values and creator/version metadata are fixed in `test-fixtures/kdbx/manifest.json`. This closes the remaining positive fixture-matrix materialization gaps; the separate full-corpus no-panic/no-regression gate remains required.

### Integrated adversarial-gate status

`rust/vault-core/tests/kdbx_full_corpus.rs` now integrates the manifest-backed corpus with deterministic derived failure cases. It currently covers:

- every KDBX fixture declared in `test-fixtures/kdbx/manifest.json`;
- wrong password and missing key-file rejection;
- unsupported major KDBX version;
- invalid outer-header field length;
- unsupported outer-cipher and KDF identifiers;
- truncated encrypted payload;
- corrupted header authentication and encrypted-payload integrity;
- representative input, Argon2, decompressed-payload, group-depth, entry-count, field-size, custom-data, per-attachment and aggregate-attachment resource ceilings;
- a `catch_unwind` boundary around corpus, credential, derived-malformation and resource-limit cases so an engine panic cannot silently satisfy the gate.

The remaining adversarial classes before this gate can be marked complete are **authenticated malformed decrypted XML / invalid nesting** and **duplicate or otherwise invalid identifiers where the pinned engine exposes defined behavior**. These require authenticated post-decrypt inputs rather than arbitrary ciphertext mutation so the XML/parser path is actually exercised.

`catch_unwind` is not treated as proof of bounded allocation. Allocation/work boundedness comes from the independently enforced pre-decrypt KDF/input limits, bounded decompression/attachment expansion and post-decrypt structure/value ceilings, each with fail-closed tests.


## Read compatibility gate

A candidate engine is acceptable for the initial read-only core only when:

1. all positive fixtures open successfully and expose the expected values;
2. all negative fixtures fail deterministically without panic or unbounded allocation;
3. KDF/cipher parameters are surfaced accurately enough for diagnostics and future save support;
4. protected values are not exposed by list/search APIs;
5. the engine can be wrapped without leaking Android/JNI concerns into `vault-core`;
6. parser/resource limits can be enforced before attacker-controlled work becomes unbounded.

## Round-trip gate

The normative format/version policy is defined in `docs/KDBX_WRITE_POLICY.md`. In particular, KDBX 4.0 must not be silently upgraded to 4.1, and KDBX 3.1 remains read-only in the initial write envelope.

Write support remains disabled until all fixtures that the selected engine claims to preserve satisfy:

- open → serialize → reopen returns the same logical database content;
- protected values remain protected;
- KDF/cipher settings are not silently weakened;
- attachments remain byte-identical;
- history/custom data are preserved where supported;
- unknown-but-preservable fields are not silently discarded; when the tolerant parser encounters not-yet-modeled XML, the engine must record that fact and serialization must fail before output is written until preservation support exists;
- KeePassXC and KeePass 2.x can independently reopen representative produced databases;
- a failed serialization never produces a partial success artifact.

Byte-for-byte equality is not required because salts/nonces and representation details may legitimately change. Logical equivalence and independent implementation interoperability are required.

As of Phase 0, representative Fortress-produced KDBX 4.1 outputs are reopened automatically by both KeePassXC and pinned KeePass 2.61.1/KPScript 2.61.1 in Foundation CI; this reference-tool gate remains additive to the Fortress-owned semantic assertions.

## Fixture provenance

Each fixture must have a sidecar manifest containing at least:

```text
id
creator implementation + version
KDBX version
KDF + parameters
outer cipher
credential description using synthetic values only
expected groups/entries/fields/attachments
expected failure category for negative fixtures
SHA-256 of the fixture
```

Real user vaults or credentials must never be committed.

## Engine evaluation use

The same corpus is used to compare candidate strategies. A candidate is not selected because it has the broadest advertised feature list; it is selected only after the required matrix passes and its API permits KDBX Fortress's resource limits, protected-value boundary, explicit lock semantics and future round-trip requirements.

# KDBX Write Compatibility Policy

Status: Phase 0 compatibility decision. This policy constrains all future production save/edit APIs until deliberately revised through reviewed interoperability evidence.

## Objective

KDBX Fortress must never turn a successful read into a lossy or unexpectedly upgraded write. Opening support and writing support are therefore separate capabilities. A vault is writable only when Fortress has positive preservation evidence for its format/features and independent reference implementations can reopen Fortress-produced output.

## Initial writable format envelope

The first production-writable format target is **KDBX 4.1 only**.

For a KDBX 4.1 database, a future save path may be enabled only when all of the following are true:

- the database uses a supported KDF, outer cipher and credential composition;
- all encountered metadata/features are inside the proven preservation matrix;
- the save keeps KDBX 4.1 unless the user deliberately selects a different supported migration in a future policy;
- KDF/cipher settings are preserved unless the user deliberately changes them through an explicit security-setting operation;
- serialization succeeds completely before storage replacement begins;
- Fortress can reopen the output and the independent reference-tool gate is green.

A successfully opened database that does not satisfy these conditions remains read-only.

## KDBX 4.0 policy

KDBX 4.0 is supported for bounded reading, but **normal save is not allowed with the current serializer**.

The pinned serializer rejects direct KDBX 4.0 output. Fortress must not work around this by silently setting the version to 4.1 during an ordinary save.

A future UI may offer an **explicit KDBX 4.0 → 4.1 migration** only after the Phase 0/2 migration gates are complete. The operation must:

1. identify the source as KDBX 4.0 before edits are accepted;
2. explain that the output format will become KDBX 4.1;
3. require a deliberate migration action rather than treating migration as Save;
4. preserve the existing KDF/cipher and credential composition unless separately changed by the user;
5. run the complete semantic-preservation checks applicable to the vault;
6. write atomically; the first production implementation should prefer creating a distinct migrated output until atomic replacement/conflict handling is proven;
7. reopen the result through Fortress and satisfy the independent reference-tool gate before the migration capability is released.

Until then, KDBX 4.0 remains read-only in production.

## KDBX 3.x policy

KDBX 3.1 remains a supported bounded **read** format. It is not a production write target for the pinned engine, which does not provide KDBX 3 serialization.

Fortress will not implement an implicit KDBX 3 → 4.1 conversion as a substitute for missing KDBX 3 serialization. A KDBX 3 migration path can be considered later only as a separately named, independently validated conversion operation with its own preservation matrix.

Therefore the Phase 0 KDBX 3 write-support question is explicitly scoped as **read-only; no save/migration support in the initial write envelope**.

## Unknown and partially supported metadata

Unknown or not-yet-proven metadata must bias toward preservation and read-only behavior:

- unknown data must never be silently dropped merely because the visible entry fields are understood;
- the pinned Fortress `keepass-rs` fork keeps XML parsing tolerant for reads, but records Serde paths for XML fields that are not modeled by the current object model;
- any non-empty ignored-XML path set makes the database ineligible for serialization: the engine returns `UnpreservedXmlFields` before writing any output bytes;
- the ignored values themselves are not claimed to be preserved; therefore a future production UI must surface the vault as read-only rather than offering a lossy Save;
- if a later adapter learns to preserve a previously ignored field, that field may leave the read-only set only after explicit round-trip/reference-tool coverage is added;
- KDBX 4.1 features such as custom-data modification times, group tags and other minor-version additions belong in the preservation matrix before they are writable;
- byte-for-byte equality is not required where salts, nonces or equivalent representation details are expected to change, but logical semantics must remain equivalent.

## Reference-tool requirement

No production write API may be enabled from Rust/JNI until Fortress-produced outputs are independently reopened by both reference families required by the compatibility matrix:

- **KeePassXC**: automated CI reopening is required for representative synthetic KDBX 4.1 outputs, including password-only and password + key-file credentials.
- **KeePass 2.x**: an automated or otherwise reproducible independent reopening check is still required before production writing is enabled.

Reference-tool success is an additional gate; it does not replace Fortress-owned semantic assertions.

## Current implementation consequence

The `save_kdbx4` engine feature remains test-only. The pinned engine now carries the ignored-XML diagnostic/fail-closed save gate, but production `keepass` dependency configuration remains read-only until the remaining reference-tool/corpus gates are complete and a reviewed production write API is introduced in a later phase.

## Compatibility rationale

KeePass defines KDBX 4.1 as a minor-format extension of KDBX 4 and explicitly notes that unsupported newer minor-version items may be ignored with possible data loss; applications are advised to warn in that situation. KeePass also introduced 4.1 through a compatibility-conscious migration phase rather than treating the minor upgrade as semantically invisible. Fortress therefore treats 4.0 → 4.1 as an explicit migration, not an implementation detail.

Primary references:

- https://keepass.info/help/kb/kdbx.html
- https://keepass.info/help/kb/kdbx_4.html
- https://keepass.info/help/kb/kdbx_4.1.html
- https://github.com/keepassxreboot/keepassxc/blob/develop/docs/man/keepassxc-cli.1.adoc

# Rust KDBX engine evaluation

Status: Phase 0 decision — initial engine selected for read integration; write support remains gated.

## Decision

Use **`sseemayer/keepass-rs` / crates.io `keepass`** as the initial KDBX engine, behind the KDBX Fortress Vault Core boundary.

Initial pin:

- crate: `keepass`
- version: `0.13.18`
- default features: disabled
- `save_kdbx4`: **disabled initially**
- license: MIT

The crate is an implementation dependency, not the Vault Core API. Android/Kotlin code must never depend on its public types directly.

`ssrlive/keepass-ng` remains a useful related research source but is not an independent validation oracle. The two repositories share substantial ancestry and currently even share identical portions of their manifest/source history.

## Why this strategy

The current `keepass-rs` line provides the strongest fit among the reviewed Rust candidates for the required compatibility surface while avoiding a new KDBX parser/crypto implementation from scratch.

Observed upstream support includes:

- KDB, KDBX3 and KDBX4 parsing;
- AES-KDF, Argon2d and Argon2id;
- AES-256, ChaCha20 and Twofish outer-cipher handling;
- Salsa20 and ChaCha20 protected-value streams;
- password and key-file composite keys;
- attachments/binary pools;
- entry/group/database custom data;
- protected and unprotected custom fields;
- KDBX 4.1 metadata/features;
- malformed-file tests;
- KDBX4 save/round-trip tests;
- generated-database checks with KeePass/KPScript and KeePassXC CLI.

The upstream project is actively maintained. This is important, but maintenance activity is not treated as a security proof.

## Read-first integration

Fortress deliberately starts with **read-only use** of the engine.

The first integration gate is executable parsing of project-owned deterministic fixtures. The engine is pinned in `rust/vault-core/Cargo.toml`, and `rust/vault-core/tests/kdbx_read_compat.rs` verifies:

- a project-generated KDBX 3.1 / AES-KDF / AES-256-CBC fixture opens, reports the expected KDF/cipher configuration and preserves a Salsa20-protected password plus a custom field;
- the basic KDBX4 fixture opens and exposes the expected credential fields;
- the Unicode KDBX4 fixture preserves expected Unicode text;
- truncated headers are rejected;
- invalid KDBX signatures are rejected.

This read corpus now covers both KDBX3/AES-KDF and KDBX4 paths. Remaining Phase 0 engine validation still includes the broader cipher/KDF matrix and round-trip preservation gates before write support can be considered.

## Why writing stays disabled

Upstream writing is explicitly feature-gated as KDBX4-only. Its `Database::save` rejects KDB/KDBX2/KDBX3 database versions.

More importantly, a password manager must not infer round-trip safety merely because known fields can be serialized. A parsed object model can lose unknown or unsupported metadata when it is serialized from scratch.

Therefore Fortress will not enable `save_kdbx4` in production until its own independent round-trip/interoperability corpus proves preservation for the supported surface, including at least:

- protected/unprotected standard and custom fields;
- custom data at database/group/entry levels;
- attachments and binary pools;
- icons/custom icons;
- tags and ordering;
- timestamps/history/deleted objects;
- KDBX 4.1 fields;
- databases written by reference KeePass implementations.

For KDBX3 inputs, the eventual product behavior must be explicit. Fortress must not silently rewrite or upgrade a KDBX3 database merely because the selected engine only writes KDBX4.

## Security hardening requirements

Selecting `keepass-rs` does **not** delegate Fortress's security policy to the dependency.

Before attacker-controlled expensive work, Fortress must enforce explicit resource budgets for:

- AES-KDF rounds;
- Argon2 memory, iterations and parallelism;
- compressed/decompressed payload size and expansion ratio;
- XML nesting/size and element counts;
- attachment/binary sizes and aggregate decoded data;
- entry/group/history counts where they can cause pathological allocation or traversal.

The reviewed Argon2 path consumes KDF values supplied by the database and does not constitute the Fortress budget policy by itself. If the public upstream API cannot enforce the required limits before expensive work, Fortress will either contribute the necessary hooks upstream or carry a minimal reviewed hardening patch/fork. Removing the resource limits is not an acceptable workaround.

## Dependency boundary

All engine-specific objects remain inside Rust.

The public Vault Core surface continues to use:

- opaque vault/entry/group handles;
- Fortress-owned DTOs for non-secret metadata;
- explicit protected-value retrieval;
- Fortress-owned error taxonomy;
- explicit lock/invalidation semantics.

This lets the engine be replaced or forked later without changing Android-facing contracts.

## Validation oracles

The selected engine must never validate itself as the only oracle.

Independent validation will include project-generated fixtures plus reference tools/implementations such as KeePass and KeePassXC. `keepass-ng` is not counted as an independent oracle because of its shared lineage with `keepass-rs`.

## Rejected alternatives

### Adopt `keepass-ng` instead

Rejected as the primary engine because it is from the same code family and does not provide meaningful implementation diversity. It remains useful for issue/history comparison.

### Build a new KDBX implementation from low-level crypto crates

Rejected for the initial product. Reimplementing container parsing, KDF handling, protected streams, XML mapping, binary pools, key files and format-version edge cases would create a substantially larger security and interoperability surface without a demonstrated benefit.

### Copy OneKeePass's database core

Rejected. OneKeePass is a learning source only. Fortress keeps its own narrowly defined Vault Core and does not copy/port its source.

## Decision gates going forward

1. [x] Current deterministic KDBX4 read/rejection tests pass in Foundation CI.
2. [x] Project-generated KDBX3/AES-KDF fixture and read test pass in Foundation CI.
3. [ ] Add resource-budget enforcement before production open/decrypt is exposed to Android.
4. Keep the engine behind an internal adapter/handle boundary.
5. Enable write support only after independent round-trip and reference-tool validation.
6. Reassess the exact dependency revision before the first public prerelease and apply the normal license/security dependency review gate.

# Rust KDBX engine evaluation

Status: Phase 0 decision record. Reassess before the first public release.

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

- KDBX 3 and KDBX 4 reading;
- AES-KDF, Argon2d and Argon2id;
- AES-256 and ChaCha20 outer encryption;
- Salsa20/ChaCha20 protected inner values;
- compression;
- binary attachments;
- common KDBX metadata;
- keyfiles and challenge-response key material.

Its parser is also substantially more structured than using a C++/JNI KeePass port as the primary engine.

## Validation already performed

The pinned engine is now exercised through project-owned deterministic fixtures and executable Rust tests rather than being accepted solely from API inspection.

Current verified read behavior includes:

- a deterministic KDBX 3.1 AES-KDF/AES-256-CBC fixture opens and exposes the expected title, username, password, URL, notes and custom-field values;
- a deterministic KDBX4 Argon2d/AES-256-CBC fixture opens and exposes expected protected/unprotected fields;
- a deterministic KDBX4 Argon2id/AES-256-CBC fixture opens and exposes the expected credential fields;
- a deterministic KDBX4 fixture using Argon2id plus ChaCha20 outer encryption opens and exposes the expected credential fields;
- a deterministic KDBX4 attachment/custom-data fixture preserves two binary-pool attachments, including protected/unprotected state and exact bytes, and preserves `CustomData` at database, group and entry levels;
- a deterministic KDBX4 composite-key fixture opens only with the required password plus the exact 32-byte raw keyfile; missing/wrong password and missing/wrong keyfile combinations are rejected;
- the Unicode KDBX4 fixture preserves expected Unicode text;
- truncated headers are rejected;
- invalid KDBX signatures are rejected.

This read corpus now covers KDBX3/AES-KDF plus KDBX4 Argon2d/AES-256-CBC, KDBX4 Argon2id/AES-256-CBC and KDBX4 Argon2id/ChaCha20 paths, KDBX4 binary-pool attachments and `CustomData` at database/group/entry levels, and password + raw-32-byte-keyfile composite credentials. Remaining Phase 0 engine validation is dominated by resource-budget hardening and independent round-trip/reference-tool preservation gates before production open/write support can be considered.

### Keyfile-format note

The pinned `keepass = 0.13.18` parser accepts raw 32-byte, 64-character hexadecimal, XML v1 and XML v2 keyfile inputs. The reviewed XML v2 parser explicitly does **not** validate the XML `Hash` attribute in this version. Fortress therefore uses a deterministic raw-32-byte keyfile for the first composite-key acceptance gate instead of treating XML-v2 integrity as verified. XML keyfile interoperability can be added later as a separate fixture, but it must not be described as hash-validated unless the dependency or Fortress performs that validation explicitly.

## Why writing stays disabled

Upstream writing is explicitly feature-gated as KDBX4-only. Its `Database::save` rejects KDB/KDBX2/KDBX3 database versions.

More importantly, a password manager must not infer round-trip safety merely because known fields can be serialized. A parsed object model can lose unknown or unsupported metadata when it is serialized from scratch.

Therefore Fortress will not enable `save_kdbx4` in production until its own independent round-trip/interoperability corpus proves preservation for the supported surface, including at least:

- protected/unprotected standard and custom fields;
- custom data at database/group/entry levels;
- attachments and binary pools;
- icons/custom icons;
- tags and ordering;
- history and deleted objects;
- KDF/cipher settings;
- unknown/custom metadata where preservation is expected.

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

The first Fortress-owned pre-decrypt gate is now implemented outside `keepass-rs`: it bounds encrypted input size, outer-header and KDF-dictionary scanning, AES-KDF rounds, Argon2 memory/iterations/parallelism and a checked memory-by-iteration work budget before the selected engine is invoked. It returns typed Fortress-owned errors and does not require credentials or decrypted payload access. The materialized KDBX3, Argon2d and Argon2id fixtures plus targeted excessive/malformed cases pass this gate in Foundation CI, including required Android Rust target checks.

This does **not** complete the resource-budget requirement. Decompression/expansion limits and post-decrypt XML/structure/attachment/count limits remain mandatory before production open is exposed. If the public upstream API cannot enforce those remaining limits early enough, Fortress will either contribute the necessary hooks upstream or carry a minimal reviewed hardening patch/fork. Removing the resource limits is not an acceptable workaround.

## Dependency boundary

All engine-specific objects remain inside Rust.

The public Vault Core surface continues to use:

- opaque vault/entry/group handles;
- Fortress-owned DTOs for non-secret metadata;
- explicit protected-value retrieval;
- Fortress-owned error taxonomy;
- explicit lock/invalidation semantics.

This lets the engine be replaced or forked later without changing Android-facing contracts.

## Take / reject / borrow

### Use `keepass-rs` as an internal parser/crypto dependency

Accepted, with the constraints in this document.

### Enable its write feature immediately

Rejected. `save_kdbx4` remains disabled until the independent round-trip gate is complete.

### Expose `keepass` crate types through JNI

Rejected. The crate remains hidden behind Fortress-owned handles and DTOs.

### Treat `keepass-ng` as an independent oracle

Rejected. It is too closely related to the selected engine for independent compatibility validation.

### Copy OneKeePass's database core

Rejected. OneKeePass is a learning source only. Fortress keeps its own narrowly defined Vault Core and does not copy/port its source.

## Decision gates going forward

1. [x] Current deterministic KDBX4 read/rejection tests pass in Foundation CI.
2. [x] Project-generated KDBX3/AES-KDF fixture and read test pass in Foundation CI.
3. [x] Project-generated KDBX4 Argon2id/ChaCha20 fixture and read test pass in Foundation CI, including Android ARM64/x86_64 Rust target checks.
4. [x] Project-generated KDBX4 Argon2id/AES-256-CBC fixture and read test pass in Foundation CI, including Android ARM64/x86_64 Rust target checks.
5. [x] Project-generated KDBX4 binary-pool attachment and database/group/entry `CustomData` fixture passes exact read-preservation tests in Foundation CI, including Android ARM64/x86_64 Rust target checks.
6. [x] Project-generated KDBX4 password + raw-32-byte-keyfile composite-key fixture passes positive/negative credential tests in Foundation CI, including Android ARM64/x86_64 Rust target checks.
7. [ ] Complete resource-budget enforcement before production open/decrypt is exposed to Android.
   - [x] Fortress-owned pre-decrypt input/outer-header/KDF gate with typed failures, AES/Argon2 ceilings and overflow-safe combined-work checks.
   - [ ] Decompression/expansion and post-decrypt structure/attachment/count ceilings.
8. Keep the engine behind an internal adapter/handle boundary.
9. Enable write support only after independent round-trip and reference-tool validation.
10. Reassess the exact dependency revision before the first public prerelease and apply the normal license/security dependency review gate.

# Vault Core API Contract

## Purpose

The Rust vault core is the sole owner of KDBX parsing, cryptographic operations and unlocked vault state. Kotlin/Android orchestrates UI and platform services through a narrow bridge. This document defines the intended semantic boundary before production KDBX implementation begins.

## Design rules

- Kotlin receives opaque vault handles, not pointers and not full plaintext database snapshots.
- Every operation validates the handle and fails after lock.
- Secret-returning APIs are explicit and separate from metadata APIs.
- Rust errors cross the bridge as stable error codes plus sanitized diagnostics; Rust panics must never unwind across FFI.
- No Android, network, clipboard, logging or storage-provider dependency is allowed inside `rust/vault-core`.
- KDBX bytes are supplied by the caller and returned by save/export operations; Android file I/O remains outside the core.
- Mutating operations are transactional at the core API level: a failed mutation must not leave partially mutated serialized output.

## Core types

### `VaultHandle`

Opaque process-local identifier with generation checking. It is **not a pointer** and is never persisted. Lock/drop invalidates it.

The Phase-0 handle foundation uses a positive 63-bit integer representation suitable for a future JNI `jlong` / Kotlin `Long` bridge:

- low 32 bits: one-based registry slot token; zero is invalid;
- next 31 bits: non-zero generation;
- top bit: always zero, so a valid raw handle never becomes a negative Java/Kotlin `Long`.

Bridge callers must treat this value as opaque process-local capability metadata. It must not be logged, persisted, exported, placed in Android intents/bundles, or interpreted as an address. Raw decoding validates the representation before registry lookup. Every registry operation then validates slot, generation and liveness. A stale, locked, out-of-range or malformed handle maps to the same stable invalid-handle category rather than leaking registry state.

The registry is explicitly bounded. Lock immediately drops the Rust-owned session value and advances its generation; repeated lock is a no-op. Reusing a vacant slot therefore produces a different handle, so a copied stale handle cannot revive. Generation exhaustion permanently retires the slot instead of wrapping. `lock_all` is likewise idempotent and drops every live Rust-owned value. Handle `Debug` output is redacted.

This foundation is implemented independently of production KDBX state and JNI. The registry remains internal until the concrete Rust vault-owner API is introduced after the secret-memory gate.

### `EntryId` / `GroupId`

Stable identifiers mapped to KDBX UUIDs. Kotlin must not rely on list indexes as identity.

### `VaultSummary`

Non-secret metadata required for the UI, for example database name, root group identity and compatibility/version information.

### `EntrySummary`

Non-secret list/search representation: identifier, title, username/display metadata, URL metadata, icon/group identity and flags indicating presence of protected fields/attachments/TOTP. It must not contain password/TOTP seed/attachment bytes.

### `SecretField`

Short-lived secret response for one explicitly requested protected value. Bridge implementations should minimize copies and provide an explicit release/clear operation when the binding technology permits it.

### `VaultError`

Stable categories at minimum: invalid credentials, unsupported format/feature, corrupt input, resource limit, stale/invalid handle, not found, conflict/precondition, serialization failure and internal error. Diagnostics must not contain decrypted secrets.

## Pre-open resource preflight

Before a future production `open_vault` invokes the selected KDBX engine, Fortress applies a non-secret preflight for encrypted input size and outer-header/KDF resource limits. It does not accept credentials, derive keys or decrypt payload bytes. Decompression and post-decrypt structure limits remain part of the Phase 0 gate.

## Lifecycle API

Conceptual API; exact language binding may differ while preserving semantics.

```text
open_vault(kdbx_bytes, credentials, limits) -> VaultHandle + VaultSummary
create_vault(options, credentials) -> VaultHandle + VaultSummary
lock_vault(handle) -> void
is_handle_valid(handle) -> bool
```

Requirements:
- `open_vault` runs the completed Fortress resource policy before expensive engine/KDF work, then performs complete authentication/integrity validation before exposing unlocked content.
- credential material is not retained longer than necessary to derive/open required keys.
- `lock_vault` is idempotent, immediately drops the Rust-owned vault session value and invalidates all future reads/mutations for that handle.
- slot reuse must advance the generation; a stale handle must never become valid again. Generation exhaustion retires the slot rather than wrapping.
- malformed/stale/already-locked handles must not expose whether a registry slot exists.
- the unlocked-session registry has an explicit capacity bound; capacity failure must not disturb existing live sessions.
- resource limits are explicit for hostile KDBX inputs.

## Read API

```text
list_groups(handle, parent_group_id) -> [GroupSummary]
list_entries(handle, group_id) -> [EntrySummary]
search_entries(handle, query, options) -> [EntrySummary]
get_entry_metadata(handle, entry_id) -> EntryMetadata
get_secret_field(handle, entry_id, field_name) -> SecretField
list_attachments(handle, entry_id) -> [AttachmentSummary]
read_attachment(handle, entry_id, attachment_id, limits) -> bytes
```

Rules:
- search/list APIs must not return password values or TOTP seeds.
- protected values are retrieved only through explicit secret APIs.
- attachment reads enforce size limits.

## Mutation API

```text
create_group(handle, parent_group_id, group_patch) -> GroupId
update_group(handle, group_id, group_patch) -> void
delete_group(handle, group_id, policy) -> void

create_entry(handle, group_id, entry_patch) -> EntryId
update_entry(handle, entry_id, entry_patch) -> void
move_entry(handle, entry_id, target_group_id) -> void
delete_entry(handle, entry_id, policy) -> void

set_secret_field(handle, entry_id, field_name, secret_value) -> void
remove_secret_field(handle, entry_id, field_name) -> void
set_attachment(handle, entry_id, attachment_name, bytes, limits) -> AttachmentId
remove_attachment(handle, entry_id, attachment_id) -> void
```

Patch objects must distinguish “unchanged”, “set empty” and “remove”; nullable bridge values alone are insufficient for every KDBX field.

## Save / round-trip API

```text
serialize_vault(handle, credentials_or_key_policy, save_options) -> bytes + SaveMetadata
```

The Android layer is responsible for atomic provider/file replacement. The core is responsible for producing a complete authenticated KDBX image.

Required guarantees before write support is considered production-ready:
- supported KDBX3/KDBX4 fixtures round-trip without silent field loss;
- unknown/custom data that the selected engine can preserve is retained;
- KDF/cipher settings are not silently weakened;
- serialization failure leaves the currently unlocked in-memory model usable and does not emit a partial “success”.

## Quick unlock boundary

Android Keystore/biometric functionality remains outside the core. If quick unlock later wraps key material, Kotlin supplies the unwrapped short-lived key material through a dedicated open/unlock path; the vault core never calls Android Keystore directly.

## Autofill boundary

The Rust core may expose entry matching/search primitives over normalized metadata, but it does not inspect Android `AssistStructure`, package identities, WebView origins or browser APIs. The Kotlin Autofill layer establishes the requesting identity/origin and asks the core for candidates. Secret retrieval occurs only after a candidate has been selected for the current request.

## FFI safety requirements

- Centralize all exported functions in one bridge module/crate layer rather than annotating arbitrary core functions.
- No borrowed Rust references live across calls.
- All buffers have explicit length and ownership conventions.
- All integer conversions are checked.
- All handles are validated against a registry/generation. Raw handle values are opaque positive integers, never native pointers.
- The high bit of the current raw-handle encoding remains zero so JNI/Kotlin signed integer conversion cannot reinterpret a valid handle as negative.
- Handle values are redacted from Rust `Debug` output and must not be logged by bridge code.
- Catch panics at the outer FFI boundary and translate them to `VaultError::Internal`.
- Every `unsafe` block has a documented invariant and targeted tests.

## Initial implementation sequence

1. [x] Implement the opaque generation-checked handle registry + idempotent lock semantics without production KDBX parsing/JNI integration.
2. [ ] Complete the secret-buffer zeroization/memory-hygiene gate before decrypted vault state is retained behind handles.
3. [ ] Integrate the registry into a concrete Rust vault owner and add read-only `open_vault` against deterministic KDBX fixtures.
4. [ ] Add the Kotlin/JNI wrapper, group/entry metadata listing and explicit single-secret retrieval with stable sanitized errors.
5. [ ] Add lifecycle/concurrency/property/fuzz coverage around the concrete owner/bridge boundary.
6. [ ] Only then add mutation and serialization/round-trip support.

### Current handle-registry implementation evidence

The first tranche is deliberately smaller than the full lifecycle API. It currently proves:

- structurally checked raw-handle decoding with no pointer interpretation;
- stale-handle rejection after slot reuse;
- idempotent single-handle and global lock;
- immediate destruction of the Rust-owned registered value on lock;
- explicit registry-capacity failure without disturbing live values;
- mutable access only through the current generation;
- slot retirement on generation exhaustion rather than wraparound;
- destruction of remaining live values when the registry itself is dropped;
- redacted handle `Debug` output.

It does **not** yet claim production KDBX ownership, JNI exposure, secret-memory zeroization, concurrency semantics, or Android lifecycle integration.

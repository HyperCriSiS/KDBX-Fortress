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

The Phase-0 handle foundation uses a positive 63-bit integer representation that is now carried by the bounded JNI adapter as `jlong` / Kotlin `Long`:

- low 32 bits: one-based registry slot token; zero is invalid;
- next 31 bits: non-zero generation;
- top bit: always zero, so a valid raw handle never becomes a negative Java/Kotlin `Long`.

Bridge callers must treat this value as opaque process-local capability metadata. It must not be logged, persisted, exported, placed in Android intents/bundles, or interpreted as an address. Raw decoding validates the representation before registry lookup. Every registry operation then validates slot, generation and liveness. A stale, locked, out-of-range or malformed handle maps to the same stable invalid-handle category rather than leaking registry state.

The registry is explicitly bounded. Lock immediately drops the Rust-owned session value and advances its generation; repeated lock is a no-op. Reusing a vacant slot therefore produces a different handle, so a copied stale handle cannot revive. Generation exhaustion permanently retires the slot instead of wrapping. `lock_all` is likewise idempotent and drops every live Rust-owned value. Handle `Debug` output is redacted.

The registry remains internal to Rust. The concrete `VaultCore` owner and Android/JNI ABI v4 expose only opaque handle values plus bounded lifecycle and metadata-summary operations; slot/generation structure and decrypted database values are never exported.

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

Before the current bounded `open_vault` path invokes the selected KDBX engine, Fortress applies a non-secret preflight for encrypted input size and outer-header/KDF resource limits. The Android adapter also checks the Java KDBX array length before creating the additional Rust copy. Preflight itself does not accept credentials, derive keys or decrypt payload bytes; decompression and post-decrypt structure limits remain enforced by the authenticated bounded-open path.

## Lifecycle API

Conceptual core API. Android/JNI ABI v4 retains the proven `open`, `lock`, `lock-all` and `is-valid` lifecycle operations and adds one metadata-only read channel; create, secret-read and mutation operations remain unexposed.

```text
open_vault(kdbx_bytes, credentials, limits) -> VaultHandle + VaultSummary
create_vault(options, credentials) -> VaultHandle + VaultSummary
lock_vault(handle) -> void
lock_all_vaults() -> void
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

The first production read tranche is metadata-only. `VaultCore` exposes bounded `read_vault_summary`, `read_group_summary` and `read_entry_summary` operations over a live `VaultHandle`. Group and entry identity is a copied 16-byte KDBX UUID (`MetadataId`), never a list index or native pointer.

The Android/JNI adapter ABI v4 adds exactly one read export:

```text
nativeReadMetadata(handle, request_kind, optional_target_uuid_16) -> byte[]
```

The response uses the versioned `KFM1` binary envelope: four-byte magic, signed 32-bit status and one-byte payload kind followed by a bounded payload. The adapter rejects responses above 256 KiB; Kotlin independently validates the same ceiling, every length/count, UTF-8 field boundary, boolean encoding, expected payload kind and exact end-of-buffer consumption. Error envelopes contain only magic/status/kind and no partial metadata or engine diagnostic text. `NotFound` is frozen as adapter status `-12`.

Default Rust metadata ceilings are 16 KiB per normal text field, 128 tags, 1024 bytes per tag, 4096 direct child groups and 4096 direct child entries. Kotlin applies matching or stricter decode ceilings.

Current summary contents:

- `VaultSummary`: optional database name, root group UUID, group/entry/attachment counts and the non-secret ignored-XML-presence flag.
- `GroupSummary`: group UUID, optional parent UUID, group name, direct child-group UUIDs and direct entry UUIDs.
- `EntrySummary`: entry UUID, parent-group UUID, title, username, URL, tags, password-present flag, TOTP-present flag and attachment count.

Explicitly excluded from this metadata model and wire format are password values, OTP seeds/URIs/codes, notes, arbitrary/custom fields, attachment names and attachment bytes. The JNI source-policy gate also forbids direct secret-content access in the adapter crate; summary extraction stays in `vault-core`. Protected values remain reserved for a later explicit secret API with separate byte ownership and release/clear semantics.

Future conceptual operations such as search, explicit secret retrieval and attachment reads remain outside ABI v4:

```text
search_entries(handle, query, options) -> [EntrySummary]
get_secret_field(handle, entry_id, field_name) -> SecretField
list_attachments(handle, entry_id) -> [AttachmentSummary]
read_attachment(handle, entry_id, attachment_id, limits) -> bytes
```

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
2. [x] Complete the secret-buffer zeroization/memory-hygiene gate before decrypted vault state is retained behind handles.
3. [x] Integrate the registry into a concrete Rust vault owner and add bounded read-only `open_vault` against deterministic KDBX fixtures.
4. [x] Add the executable Android/Kotlin caller and the bounded JNI lifecycle wrapper (`open`/`lock`/`is-valid`) with byte-oriented credentials, opaque handles and stable sanitized errors.
5. [x] Complete the JNI/lifecycle hardening tranche around the concrete owner/bridge boundary.
   - [x] Contain owner-operation panics while the Rust owner mutex is held and fail closed by locking every live vault before returning the frozen panic status.
   - [x] Recover from an already-poisoned owner by locking all retained vaults before clearing poison and resuming service.
   - [x] Prove malformed/stale handles remain sanitized and cannot affect a newly reused registry slot/generation.
   - [x] Prove an actual Android foreground → background transition reaches `Activity.onStop()` and invalidates multiple live Rust-owned vaults through the bounded `lock-all` export.
   - [x] Add deterministic lifecycle/concurrency/property/fuzz coverage: 20,000 model-based registry transitions, 100,000 raw-handle fuzz inputs and eight concurrent owner workers over real KDBX sessions pass the full Foundation gate.
6. [x] Complete the Phase 1 Android foundation before widening JNI: production/shared/smoke modules, Material 3/Compose navigation shell, scoped SAF document selection and built-APK no-broad-storage-permission gate.
7. [x] Add the first bounded **metadata-only** read tranche through a deliberately versioned JNI surface: vault summary plus group/entry summaries, with explicit result/size ceilings and no secret values.
8. [ ] Consume the proven metadata summaries in production group/entry browsing without duplicating decrypted vault state in Kotlin.
9. [ ] After metadata browsing is proven, add explicit single-secret retrieval as a separate audited tranche with short-lived byte ownership and clear/release semantics.
10. [ ] Only then add mutation and production serialization/round-trip exposure.

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

The registry foundation is now supplemented by deterministic model/property and raw-handle fuzz coverage plus concurrent owner-level lifecycle stress. Android lifecycle integration is proven in the JNI hardening tranche, and the full stress gate passes before any broader read API is introduced.


## Concrete Rust vault owner — implemented Phase 0 tranche

The platform-neutral core now exposes `VaultCore` as the sole owner of live decrypted vault sessions. `VaultCore::new(max_open_vaults)` configures an explicit bounded registry; no global registry or singleton is introduced.

`VaultCore::open_vault(data, credentials, limits)` uses only the existing bounded credential-aware KDBX open path. Preflight, authenticated engine parsing/decompression and post-decrypt structural validation complete before a `VaultHandle` is returned. The decrypted `keepass::Database` is moved into a private `VaultSession` and never returned to the caller. If registry insertion fails because capacity is exhausted, the freshly opened database is dropped before the capacity error returns.

Lifecycle behavior proven by unit tests and the full Foundation gate:

- an accepted vault produces only an opaque generation-checked `VaultHandle`;
- wrong credentials fail before any live handle is created;
- explicit capacity failure leaves existing live vaults untouched;
- `lock_vault` is idempotent and immediately drops the private Rust owner;
- a stale handle remains invalid after the slot is reused with a new generation;
- `lock_all` is idempotent and invalidates every live owner;
- the same owner code passes KeePassXC/KeePass interoperability and Android ARM64/x86_64 compilation.

`VaultCoreError` exposes only typed Fortress errors (`Open`, `CapacityExceeded`, `InvalidHandle`) and carries no decrypted content or registry details. `VaultSession` is intentionally private and has no public `Debug` surface.

This core-owner tranche is now consumed by the bounded Android/JNI lifecycle + metadata adapter described below. Android lifecycle-triggered global locking and deterministic concurrent owner stress are proven by the adapter hardening gate; bounded metadata summaries are now exposed, while secret retrieval, mutation operations, raw database references and pointers remain outside the boundary.


## Android/JNI lifecycle + metadata adapter — implemented Phase 0/1 tranche

Adapter ABI 4 exposes exactly six `NativeBridge` native methods: the non-secret capability probe, bounded `open`, `lock`, `lock-all`, `is-valid`, and the single metadata-only `nativeReadMetadata` channel. `rust/vault-core` remains JNI/Android-free; the separate `rust/android-jni` crate owns the process-local bridge `VaultCore`.

The current ingress and ownership contract is deliberately narrow:

- Java/Kotlin supplies KDBX, password and optional key-file material as byte arrays, never immutable secret strings; password and key-file components are nullable so absence is distinct from an explicitly empty component.
- the adapter rejects a KDBX array beyond the Fortress encrypted-input ceiling before the JNI-to-Rust copy, bounds password bytes to 4 KiB, key-file bytes to 1 MiB, and allows at most four simultaneously open vault owners;
- successful opens return only positive opaque process-local handles; open/lock failures use frozen negative adapter status codes, while `is-valid` returns `1`/`0` except for an internal adapter failure;
- KDBX engine diagnostics are collapsed into sanitized categories rather than copied into Kotlin;
- Rust copies of credential byte vectors are moved immediately into `VaultCredentials` zeroizing owners;
- owner operations are panic-contained while the Rust mutex is still held; a contained panic immediately executes `lock_all`, so decrypted sessions do not survive the failing operation and no panic payload crosses JNI;
- an already-poisoned bridge-owner mutex also fails closed by locking all retained vaults before poison is cleared and service resumes with the stable internal-error category;
- malformed handles remain sanitized, and stale handles cannot revive or affect a newly reused registry slot/generation;
- the JNI source-policy and binary-symbol gates allow exactly the six approved ABI-v4 exports and continue to forbid network dependencies, opportunistic JNI growth, direct password/OTP/attachment-content reads in the adapter and additional unsafe code paths;
- metadata reads use the `KFM1` bounded binary envelope and stable `NotFound = -12` status, with no partial payload on failure and no secret values in successful summaries.

The Android emulator gate packages a deterministic KDBX fixture and now proves the lifecycle boundary in two stages. The baseline gate proves `open → is-valid → lock → stale`. The ABI-v3 hardening gate first verifies malformed-handle behavior, then keeps two real KDBX vault handles simultaneously live, writes an app-private `READY` marker only after both are confirmed valid, and has the external harness send the emulator Home key. `PASS` is written exclusively from `Activity.onStop()` after Rust `lock-all` invalidates both handles. The stale-generation/slot-reuse case remains a Rust-level deterministic test so the Android smoke does not duplicate expensive KDF work. Decrypted `Database` objects, entry fields, registry internals and native pointers never cross the boundary.

The dedicated panic/poison/stale-handle/Android-lifecycle proof and deterministic lifecycle/concurrency/property/fuzz stress gate are complete. The Phase 1 Android module/native-library, Compose/navigation and scoped-SAF foundation is complete, and ABI v4 now adds only the single bounded metadata-read channel. The emulator smoke traverses Vault → Root → Group → Entry metadata through Kotlin/JNI/Rust before the existing foreground → background `lock-all` proof. Explicit secret retrieval remains a later, separate audited tranche; the immediate Phase-1 consumer is production group/entry browsing over metadata summaries.

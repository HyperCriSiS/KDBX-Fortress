# ADR 0003: Bounded metadata-only Android read boundary

Status: Accepted

## Context

Phase 1 needs enough decrypted vault information to render groups and entry lists on Android, while the Rust vault core must remain the sole owner of the decrypted KDBX database. Expanding JNI into many field-specific getters would enlarge the audit surface, make versioning harder and create opportunities for secret fields to cross the boundary accidentally. Returning a full plaintext database snapshot to Kotlin is explicitly out of scope.

## Decision

KDBX Fortress uses adapter ABI v4 for the first read tranche. ABI v4 retains the five proven lifecycle exports and adds exactly one native operation, `nativeReadMetadata(handle, request, targetId)`. The binary-symbol CI gate freezes this six-export surface.

The read operation returns a versioned bounded binary envelope identified by `KFM1`. It carries a stable status and one of three successful payload kinds: vault summary, group summary or entry summary. Group/entry targets are copied 16-byte KDBX UUIDs, not indexes, pointers or additional native object handles.

Rust applies explicit metadata ceilings before encoding, and the adapter refuses a response above 256 KiB. Kotlin independently validates the response ceiling, magic, status, kind, all lengths/counts and exact payload exhaustion. Failure responses contain no partial record or engine diagnostic text. A missing UUID maps to the frozen sanitized `NotFound = -12` adapter status.

The metadata allowlist is intentionally narrow. Entry summaries may contain title, username and URL only when the corresponding KDBX source field is unprotected; a protected source value is withheld as absent instead of being dereferenced into Kotlin. Tags and only boolean/count indicators for password, OTP and attachments may also be returned. Password and OTP presence is determined from field-key existence only, so the metadata path never reads those secret values. Password values, OTP seeds/URIs/codes, notes, custom fields, attachment names and attachment bytes are excluded. Source-policy CI forbids direct password/OTP/attachment-content reads in the JNI adapter and also forbids secret-revealing `Entry` convenience getters in the `vault-core` metadata module.

## Consequences

- Kotlin can traverse the vault hierarchy without owning or duplicating the decrypted database model.
- The JNI audit surface grows by one operation rather than many getters.
- Wire-format changes require deliberate ABI/wire-version evolution instead of silently changing Java object layouts.
- Metadata reads remain valid only while the opaque generation-checked vault handle is live; existing lock and `lock-all` semantics immediately terminate further reads.
- Production group/entry browsing can now be built without adding a secret API.
- Explicit secret retrieval remains a later, separately audited byte-oriented tranche with short-lived ownership and clear/release semantics.

## Verification

The Foundation gate covers formatting, Clippy, unit tests, KDBX interoperability and Android target checks. Its fast Rust-core source policy rejects secret-revealing entry getters in the metadata module, and unit coverage proves protected values are withheld rather than copied. The JNI boundary gate mechanically verifies the exact six exported native symbols. The Android runtime smoke packages the shared bridge, validates the APK permission boundary, traverses Vault → Root → Group → Entry metadata using the deterministic KDBX fixture, and then proves the existing foreground → background `lock-all` invalidates live Rust-owned vault sessions.

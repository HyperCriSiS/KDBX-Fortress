# OneKeePass Mobile Research — Lessons for KDBX Fortress

Status: Phase 0 research record. This document captures architectural and behavioral lessons only. No OneKeePass source code, assets, or implementation is copied, ported, or reused.

## Scope and reviewed upstream snapshots

The review focused on the Android/mobile integration and the Rust core boundary relevant to KDBX Fortress.

Reviewed upstream snapshots:

- OneKeePass/mobile: `ba14115a4f31cd26a68892824262edcbeea8bba3` (2026-07-10), commit `Autofill matching fixes (#61)`
- OneKeePass/onekeepass-core: `7f1b6b2655d7f4c388bb100a2de3e9bbaf2b8fd5` (2026-08-05), commit `Locked db content encryption, csv import enhancements,group cloning (#36)`

Primary upstream references:

- <https://github.com/OneKeePass/mobile>
- <https://github.com/OneKeePass/onekeepass-core>
- <https://github.com/OneKeePass/mobile/issues/19>
- <https://github.com/OneKeePass/mobile/issues/28>
- <https://github.com/OneKeePass/mobile/issues/33>
- <https://github.com/OneKeePass/mobile/issues/56>

The reviewed project is GPL-licensed. This research is deliberately clean-room in character: observations are translated into requirements, invariants, test cases, and design constraints, not implementation text.

## Architecture observed

OneKeePass/mobile uses a layered cross-platform architecture:

- React Native and ClojureScript for a substantial part of the mobile UI and application flow.
- Kotlin for Android platform services and Android-specific integration.
- Swift for iOS platform integration.
- A Rust FFI layer (`db-service-ffi`) using UniFFI-generated bindings.
- A separate Rust project (`onekeepass-core`) containing KDBX/database logic and other shared services.

This validates the general feasibility of a Kotlin/mobile shell around a Rust database core. It also demonstrates the importance of making the FFI boundary explicit rather than allowing platform code to reach arbitrary core internals.

### Lesson for Fortress

Keep the already chosen Kotlin + isolated Rust Vault Core architecture, but make the Fortress boundary stricter:

- Rust Vault Core owns decrypted KDBX state and cryptographic operations.
- Android owns platform APIs, UI, lifecycle, Autofill, Credential Manager, storage adapters, and network-capable integrations.
- Cross-boundary calls must use small typed DTOs/handles and explicit result/error contracts.
- No callback or convenience feature may silently expand the Vault Core's permission or network surface.

## Autofill target identification and field parsing

The Android Autofill implementation parses `AssistStructure` / `ViewNode` data, including package identity, `webDomain` / `webScheme`, Autofill hints, HTML input metadata, Android input types, view IDs, and human-readable hints.

A useful separation is visible between **target identity** and **field classification**:

- web origin/domain data is used to identify the target site,
- text hints, IDs, and input types are used to classify username/password fields.

The parser also includes fallback heuristics for incomplete forms, such as password-only stages in multi-step authentication.

### Lessons for Fortress

1. `webDomain` / origin information is authoritative for browser/web identity when available.
2. Android package identity is authoritative for native-app identity.
3. View titles, labels, hints, IDs, and visible text are evidence for **field semantics only**, never trusted proof of site identity.
4. Multi-step login flows must be first-class test cases, not accidental parser behavior.
5. Ambiguous target identity must reduce confidence or fail closed rather than broadening credential exposure.

This reinforces the decision that KDBX Fortress must not depend on window-title URL hacks or Accessibility scraping for normal operation.

## Central matching authority

OneKeePass's Rust core contains a shared URL matching service used across mobile Autofill and browser-oriented integration. The observed matching model includes:

- exact host matching as the strongest web match,
- registrable-domain matching using the Public Suffix List for sibling subdomains,
- scheme boundaries,
- protection against phishing-style suffix hosts,
- correct public-suffix boundaries such as separate `*.github.io` registrable domains,
- multiple entry URLs via an additional-URL field,
- Android package URI matching,
- normalization between `android://...` and KeePass-ecosystem `androidapp://...` identifiers,
- deterministic ranking between URL sources and host-match strength,
- focused tests for malformed URLs, IPs, paths, schemes, subdomains, public suffixes, and Android app identifiers.

A user-selected native-app fill can also be used to learn an explicit app association for future matching.

### Lessons for Fortress

- Maintain **one matching authority** shared by `AutofillService`, Credential Manager, manual selection, and future integrations.
- Parse URLs structurally; never use string suffix matching for trust decisions.
- Use a maintained Public Suffix List implementation for registrable-domain calculations.
- Rank exact origin/host above broader registrable-domain matches.
- Preserve meaningful scheme boundaries.
- Support multiple URLs per entry without turning them into an unstructured substring search.
- Support KeePass ecosystem Android app tokens for interoperability.
- Learn app associations only from an explicit, user-authorized event and retain enough provenance to let the user inspect/revoke them later.
- Keep matching deterministic and exhaustively fixture-tested.

## Credential Manager and passkeys

OneKeePass/mobile registers an Android Credential Provider for passkeys. Its provider extracts WebAuthn request data such as `rpId`, finds matching passkeys, and routes the request into an authentication activity.

A notable observed behavior is that the provider can intentionally offer a generic unlock/credential entry even when no reliable `rpId` or matching passkey is available.

### Lesson for Fortress: deliberately do not copy this behavior

For a password manager, absence of reliable relying-party identity is a security boundary, not merely a UX inconvenience.

KDBX Fortress must therefore:

- never expose unrelated passkeys when the relying party cannot be established,
- never turn `no match` into a generic credential disclosure path,
- distinguish `vault locked`, `target unknown`, `target known but no match`, and `matching credential exists`,
- fail closed when target identity is missing or contradictory,
- allow manual recovery only through an explicit flow that preserves the target/security context and does not silently associate unrelated credentials.

Password Autofill and passkey Credential Manager support evolve through separate Android paths. Fortress must not assume that implementing one automatically covers the other.

## Autofill request lifecycle and concurrency

The observed mobile implementation keeps request-related Autofill state for later completion after authentication. This is understandable because Android Autofill often spans service and activity lifecycles, but mutable shared request state can become dangerous when requests overlap or become stale.

### Lessons for Fortress

- Give every fill/authentication flow an explicit request/session ID.
- Bind parsed target identity, requested fields, and the resulting credential selection to that session.
- Reject completion of stale, replaced, cancelled, or mismatched sessions.
- Do not let a later Autofill request overwrite state still referenced by an earlier authentication activity.
- Include background/foreground, rotation/activity recreation, process recreation, cancellation, and rapid app switching in regression tests.

## Save flows

In the reviewed Android Autofill service, `onSaveRequest` is not a complete credential-save implementation.

### Lesson for Fortress

Saving new or changed credentials needs its own threat model and tests, including new login, password change with old/new/confirmation fields, multi-step forms, multiple accounts for one site, target identity changes, vault lock before commit, duplicate/update disambiguation, and explicit confirmation before creating a new app association.

## Storage Access Framework and provider behavior

OneKeePass/mobile uses Android's Storage Access Framework and persisted URI permissions, and passes file descriptors into the Rust layer for database I/O. The implementation contains provider-specific handling notes, including differences between open/create flows and cloud document providers.

The public issue history provides an especially useful failure class:

- Issue #19 reports a OneDrive-backed database opened from the app's recent list remaining stale while explicitly reopening the same provider document returned the current content.
- Issues #28 and #33 show that document-provider capabilities and UX differ between opening and creating files and between cloud providers.

### Lessons for Fortress

Treat storage as a hostile/variable adapter boundary rather than as a normal local file path:

- Keep SAF/provider logic outside the Vault Core.
- Model durable document identity separately from a transient file descriptor.
- Revalidate external metadata/content freshness before writes and at appropriate reopen/resume boundaries.
- Do not assume that a persisted URI guarantees fresh bytes.
- Do not assume all `DocumentsProvider` implementations support the same create/write/rename/replace semantics.
- Define atomic-write and recovery behavior per storage capability.
- Detect external modification before overwrite whenever technically possible.
- Add real-provider tests for local SAF and representative cloud providers.
- Include stale-cache reproduction tests based on the OneDrive issue class.

This supports Fortress's rule that storage adapters may perform platform/network work while the Vault Core itself remains offline.

## Locking and in-memory secret state

The latest reviewed OneKeePass core explicitly changed locked database behavior so that entry contents are encrypted when locking, attachments are encrypted/zeroized, and locked or empty database state is prevented from being saved incorrectly.

### Lessons for Fortress

A lock operation must be a **secret-state transition**, not a UI flag:

- invalidate secret-bearing handles,
- zeroize plaintext buffers where practicable,
- drop or cryptographically protect cached secret material,
- ensure attachments and derived secret data follow the same policy as ordinary fields,
- prevent writes from invalid/locked internal state,
- test unlock → use → lock → stale-handle/access attempts explicitly.

Fortress should keep the stronger invariant that the Kotlin/UI layer never owns the canonical decrypted vault state.

## Android Keystore / biometric wrapping

OneKeePass uses Android Keystore AES-GCM operations as part of its secure-key support. The reviewed code demonstrates a useful platform/core split, but also illustrates why `AndroidKeyStore` must not be treated as a complete security policy by itself.

### Lessons for Fortress

- Use Android Keystore only through a narrow platform-owned key-wrapping/unlock abstraction.
- Explicitly define whether a key requires user authentication, its authentication timeout, invalidation behavior, and acceptable hardware security levels.
- Detect and surface hardware-backed / StrongBox availability rather than assuming it.
- Never log key objects, raw credential request material, plaintext secrets, or sensitive exception context.
- Biometric convenience must not weaken the master-key derivation or Vault Core boundary.

## Network capability and core scope

OneKeePass's shared Rust core contains not only KDBX/database logic but also services such as remote storage and favicon handling.

### Lesson for Fortress: deliberately use a narrower core

Do **not** copy that scope into KDBX Fortress. The Vault Core must remain network-incapable by architecture and build policy:

- no HTTP client,
- no DNS/network stack dependency,
- no favicon/icon downloading,
- no remote-storage implementation,
- no telemetry,
- no Internet permission dependency.

Remote storage, icon providers, breach checks, favicon retrieval, or similar convenience services belong in replaceable Android-side modules with privacy-minimized APIs.

## Background lifetime

OneKeePass issue #56 requests a persistent notification/foreground-style approach to keep the app/database alive in the background. This is useful evidence of a real UX demand, but it should not define Fortress's default security behavior.

### Lessons for Fortress

- Optimize unlock latency without keeping plaintext vault state alive indefinitely.
- Make lock timeout and biometric re-unlock predictable.
- Do not use a permanent unlocked foreground service as the default solution to Android process/lifecycle behavior.
- Any future keep-alive mode must be opt-in, explicit about its security tradeoff, and still honor hard lock boundaries.

## Testing lessons

The OneKeePass core has focused Rust tests for matching, merge behavior, and recent lock/unlock behavior. The mobile repository exposes integration surfaces whose failure modes cannot be covered by pure unit tests alone.

KDBX Fortress should retain its stronger layered test strategy:

- Rust unit/property tests for KDBX parsing, crypto, matching, and state invariants.
- Serialized fixtures for Autofill field/target parsing.
- Android instrumentation tests for service/activity/session behavior.
- Real-browser tests across Chromium and Gecko families.
- Real Credential Manager/passkey tests on supported Android versions.
- Real SAF/cloud-provider freshness and conflict tests.
- Regression fixtures derived from public KeePassDX, KeePass2Android, and OneKeePass issue classes.

## Derived Fortress invariants

1. **Single match authority:** all credential surfaces use one normalized matching engine.
2. **Trusted target identity:** origin/package evidence is separated from field heuristics.
3. **Fail closed:** unknown target or no credential match never becomes a generic secret-disclosure path.
4. **Explicit associations:** app ↔ entry/domain links require a user-authorized event and are revocable.
5. **Session binding:** every Autofill/Credential Manager flow is bound to an immutable request context.
6. **Lock means secret removal/protection:** stale handles cannot keep plaintext reachable.
7. **Storage is untrusted/variable:** provider freshness and conflict behavior are verified before destructive writes.
8. **Vault Core is offline:** network-capable convenience features cannot enter the Rust security boundary.
9. **Platform keystore is a primitive, not a policy:** authentication/hardware guarantees are explicit and testable.
10. **Integration tests are mandatory:** Android/browser/provider behavior is verified on real implementations, not inferred from API conformance.

## Result

The OneKeePass/mobile research does not justify replacing KDBX Fortress's architecture. It validates several existing decisions and contributes concrete edge cases and regression requirements, especially for centralized matching, Public Suffix List handling, Android app associations, request-session isolation, cloud-provider freshness, locked-state secret handling, and fail-closed passkey behavior.

No upstream source code is imported by this research task.

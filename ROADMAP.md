# KDBX Fortress Roadmap

This file is the **single authoritative roadmap and status source** for the repository.

Other documents under `docs/`, including research notes, ADRs, compatibility matrices, threat models and API contracts, may explain or constrain work, but they do not replace the phase/status decisions recorded here. If another document conflicts with this file, reconcile the documents deliberately before implementation continues.

The acceptance criteria and scope in this file are normative unless changed deliberately through a reviewed roadmap update.

## Current status

Status: **Phase 0 in progress; the initial read-only KDBX engine is selected and substantial compatibility coverage is proven, but production parsing is still blocked on resource-budget enforcement and round-trip/reference-tool validation.**

Repository state verified on `main` at `8f9f622fcd8b4e1ac98a6a1b7f982f9acfdd9966`:

- The Rust core is an isolated `cdylib`/JNI scaffold and pins `keepass = 0.13.18` as the initial read-only KDBX engine behind an engine-neutral validation approach.
- Deterministic generated fixtures and executable Rust tests cover KDBX 3.1 and KDBX 4 variants, including AES-KDF, Argon2d, Argon2id, AES-256-CBC, ChaCha20 outer encryption, protected fields, Unicode, attachments, `CustomData`, and password + raw-32-byte key-file composite credentials.
- Negative coverage includes malformed/truncated headers, invalid signatures and incorrect credential combinations.
- Fixture hashes/manifests are validated in CI; required Android Rust targets and exported native symbols are checked by the foundation workflow.
- The latest `Foundation` workflow and CodeQL scan on `main` are green for the verified commit above.
- `main` is protected; recent work uses short-lived feature/test branches and pull requests before integration.
- There are currently no open repository issues and no published releases.
- There is not yet a production Android application module, production vault-read JNI API, write path, Autofill implementation or release artifact.

## Phase 0 — Prove the KDBX/core approach

Goal: prove a bounded, interoperable and auditable Rust KDBX core before exposing production vault operations to Android.

- [x] Select the initial **read-only validation** KDBX strategy behind the Rust core: pin `keepass = 0.13.18` behind an internal adapter boundary while write support remains disabled pending interoperability gates.
  - [x] Evaluate maintained Rust KDBX candidates against the required format/crypto matrix.
  - [x] Record license, maintenance, Android/JNI integration, preserved metadata, resource-budget implications and take/reject/borrow decisions.
  - [x] Define an engine-neutral positive/negative fixture matrix, independent reference-oracle requirement and read/round-trip acceptance gates in `docs/KDBX_COMPATIBILITY_MATRIX.md`.
  - [ ] Materialize synthetic KDBX fixtures plus manifests/SHA-256 across the **remaining** compatibility matrix; fixtures must be project-generated or otherwise redistributable.
    - [x] Materialize a deterministic KDBX 3.1 fixture covering AES-KDF, AES-256-CBC, Salsa20-protected password, notes and a custom field; validate decoded SHA-256 values.
    - [x] Materialize a deterministic KDBX 4 Unicode fixture and exercise the pinned Rust read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2d and AES-256-CBC outer encryption; validate hashes and executable read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2id and AES-256-CBC outer encryption; validate hashes and executable read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2id and ChaCha20 outer encryption; validate hashes and executable read path.
    - [x] Materialize and exercise a deterministic KDBX 4 fixture covering attachments and `CustomData`, including protected/unprotected binary-pool data and database/group/entry metadata preservation on read.
    - [x] Materialize and exercise a generated KDBX 4 fixture requiring a composite password plus external raw-32-byte key file; validate database/key-file SHA-256 values, sidecar size and positive/negative credential combinations through the pinned Rust engine.
  - [x] Add executable read-compatibility tests for the currently materialized positive fixtures and malformed-header/signature/credential negative cases.
  - [ ] Add executable round-trip/interoperability tests before enabling write support, including independent reference-tool validation and semantic-preservation assertions.
  - [ ] Enforce explicit Fortress-owned resource limits **before production parsing/decryption**: input size, Argon2 memory/time/parallelism policy, recursion/depth, entry/field/attachment counts and sizes, and decompression ceilings. Rejections must be typed and safe.
    - [x] Add a Fortress-owned pre-decrypt preflight that checks the KDBX signature/version plus bounded outer-header/KDF metadata without credentials or decrypted payload access.
    - [x] Expose an input-size gate usable before full-file allocation and bound outer-header/KDF-dictionary scanning.
    - [x] Enforce KDBX3/KDBX4 AES-KDF round ceilings and KDBX4 Argon2 memory/iterations/parallelism plus checked memory-by-iteration work ceilings before the selected KDBX engine is invoked.
    - [x] Return typed Fortress-owned rejection reasons for malformed/unsupported/excessive preflight inputs; verified against the materialized KDBX3, Argon2d and Argon2id fixtures plus targeted negative cases.
    - [ ] Enforce remaining post-decrypt structural budgets: recursion/XML depth and element counts, entry/group/history counts, field/attachment sizes and aggregate decoded data.
    - [ ] Enforce compressed/decompressed payload ceilings and expansion-ratio limits before unbounded decompression/allocation is possible.
  - [ ] Validate the chosen engine/adapter against the full accepted corpus with no panics, no unbounded allocation and no format regressions.
- [ ] Define the stable Rust handle/API model and Kotlin wrapper while preserving the invariant that decrypted vault state remains inside Rust.
- [ ] Add explicit memory hygiene for composite keys and sensitive secret buffers, including zeroization wrappers where upstream types retain owned secret material.
- [ ] Extend the JNI contract beyond the smoke boundary only after engine selection, parser limits and error semantics are proven.
- [x] Build/upload compiled Rust `.so` artifacts for the required Android targets in CI.
- [x] Validate native symbol/export linkage in CI.
- [x] Keep the Rust dependency policy auditable with locked/pinned dependencies and automated review/update tooling.
- [x] Block known-vulnerable build-tool/runtime prerequisites through CI policy.
- [x] Keep secret scanning/push protection and CodeQL/security scanning active for the repository.

**Phase 0 gate:** the same hashed fixtures must open/read through the Rust core on host and required Android Rust targets; wrong passwords/key files and corrupt/malformed inputs must fail safely; no production read path may cross JNI until parsing/resource limits are verified.

**Phase 0 exit:** representative accepted KDBX 3/KDBX 4 vaults open and round-trip without semantic loss, resource budgets are enforced, memory/API invariants are implemented, and automated compatibility tests are deterministic and green.

## Phase 1 — App shell and read-only vault access

- [ ] Create the production Android application/modules and wire the verified Rust library into the Android build.
- [ ] Establish the Material/Compose application shell and navigation architecture.
- [ ] Implement create/open file selection through Android Storage Access Framework without broad storage permissions.
- [ ] Expose only the bounded read-only Rust vault API through the stable JNI wrapper.
- [ ] Display groups and entries without duplicating the decrypted database model in Kotlin.
- [ ] Implement search/filtering through Rust-backed handles/queries.
- [ ] Implement controlled clipboard copy with timeout/clear behavior and sensitive-content handling.
- [ ] Implement configurable auto-lock and explicit lock.
- [ ] Lock/clear sensitive state correctly across backgrounding, process/lifecycle changes and task removal.
- [ ] Add screenshot/recents protection for sensitive screens while keeping accessibility trade-offs explicit.
- [ ] Add Android lifecycle/instrumentation tests for lock/invalidation and sensitive-screen behavior.

**Phase 1 exit:** a user can select and unlock a supported local KDBX file, browse/search entries and intentionally retrieve/copy a secret without Autofill, while lifecycle/lock invariants remain intact.

## Phase 2 — Safe local editing and persistence

- [ ] Enable create/save only after the Phase 0 round-trip gate is complete.
- [ ] Implement create/edit/delete/move flows for supported groups and entries.
- [ ] Preserve supported custom fields, protected values, attachments, tags, icons/custom data and ordering semantics covered by the compatibility matrix.
- [ ] Implement SAF-backed atomic save/replace with backup/recovery behavior appropriate to provider capabilities.
- [ ] Detect external file changes/conflicts before overwriting.
- [ ] Implement crash-safe save failure handling and corruption diagnostics.
- [ ] Add database backup/restore and safe export policy without exposing plaintext by default.
- [ ] Keep KDF/cipher settings explicit and never silently weaken database security.
- [ ] Add deterministic read-edit-write-reopen interoperability tests with independent reference validation.

**Phase 2 exit:** supported vaults can be edited and saved without silent semantic loss, with conflict/recovery behavior tested.

## Phase 3 — Android Autofill and Credential Manager

Goal: make credential filling reliable through official Android mechanisms without an Accessibility-Service password-manager fallback.

### Autofill inputs

- [ ] Implement Android `AutofillService` around deterministic app/browser/WebView fixtures and real-device cases.
- [ ] Implement Credential Manager provider integration for supported Android versions and credential types.
- [ ] Normalize AutofillService and Credential Manager requests into one shared target representation rather than duplicating matching logic.

### Target/context resolution

- [ ] Resolve package/application identity, browser identity, component/activity, field semantics/hints/input types and exposed web origin/domain into a normalized non-secret target.
- [ ] Treat verified app↔website association signals separately from user-approved explicit associations.
- [ ] Define exact-origin, exact-host, registrable-domain/subdomain and multiple-entry-URL semantics before automatic suggestions are allowed.
- [ ] Reject or require explicit user selection when a trustworthy origin/domain cannot be established; never guess credentials into an unsafe target.
- [ ] Test malicious/unrelated app-origin claims and domain mismatch/phishing scenarios explicitly.

### Credential matching and presentation

- [ ] Route normalized target context through a single shared matcher/ranker, independent of Android AutofillService vs Credential Manager transport.
- [ ] Rank exact origin/domain and verified association ahead of controlled package/user-approved associations; keep heuristics conservative and explainable.
- [ ] Support multiple accounts for one target, no-match states, manual selection and search fallback.
- [ ] Support KDBX entries with multiple URL associations without silently creating or rewriting mappings.
- [ ] Retrieve/decrypt only the selected secret as late as possible; do not materialize the whole vault in Kotlin.

### Form and lifecycle coverage

- [ ] Cover username+password, password-only, username-only, password-change old/new/confirmation and OTP forms.
- [ ] Cover multi-step login flows where username and password appear on separate screens.
- [ ] Cover absent/incorrect hints, dynamic/delayed fields, custom views and Jetpack Compose.
- [ ] Cover native Android Views, Android System WebView and browser-origin cases explicitly.
- [ ] Cover iframe/embedded login cases to the extent Android/browser APIs expose trustworthy context.
- [ ] Cover locked-vault, no-match, relock-mid-flow, backgrounding, display-off, inactivity, process restart and Activity recreation scenarios.
- [ ] Cover save/update credential flows separately from fill flows.
- [ ] Add TOTP Autofill only after vault secret handling and matching boundaries are stable.

### Browser/system compatibility and regression matrix

- [ ] Maintain explicit real-device/browser coverage for Chrome/Chromium, Firefox, Waterfox Android, Brave, Vanadium, Vivaldi and Android System WebView where installable/testable.
- [ ] Track Android-version/OEM differences where platform behavior materially differs.
- [ ] Add first-class regression cases derived from known KeePassDX/KeePass2Android failure modes rather than treating them as anecdotal bugs.
- [ ] Use Android Autofill compatibility mode only as a measured allowlisted adapter for specific broken clients, never as a universal fallback.
- [ ] Do not add an Accessibility Service as the primary password-manager mechanism.

**Phase 3 exit:** Autofill/Credential Manager works reliably across the documented app/browser/WebView matrix, unsafe origins fail closed, and manual fallback remains available when platform context is insufficient.

## Phase 4 — Hardening, quick unlock and resilience

- [ ] Add optional Android Keystore/biometric quick-unlock only as a convenience layer; the KDBX credential remains the canonical vault credential.
- [ ] Define quick-unlock enrollment, invalidation, biometric-change and recovery behavior explicitly.
- [ ] Ensure quick-unlock material never becomes a cloud recovery secret or silently changes the KDBX credential.
- [ ] Harden clipboard/notifications/recents/screenshots/logging and crash reporting against secret leakage.
- [ ] Add backup/recovery policy for local database files and metadata.
- [ ] Add process-death/reboot/reinstall/restore tests for lock and quick-unlock behavior.
- [ ] Add robust diagnostics for corrupt/unsupported vaults without exposing protected content.

**Phase 4 exit:** convenience unlock and recovery behavior do not weaken the core KDBX trust model, and sensitive Android surfaces are explicitly hardened.

## Phase 5 — Security, compatibility and performance validation

- [ ] Benchmark KDF/open/search/save operations on representative Android hardware and document expected ranges.
- [ ] Tune **new-database** Argon2id defaults against an unlock-latency target and device memory rather than copying a fixed universal preset.
- [ ] Preserve existing database KDF/cipher choices by default; any suggested upgrade/downgrade must be explicit and user-approved.
- [ ] Maintain a compatibility matrix covering supported Android versions, OEMs, browsers, WebViews and KDBX variants.
- [ ] Run full representative KDBX regression corpus, including malformed/corrupt/pathological inputs.
- [ ] Validate memory/resource ceilings under hostile inputs and low-memory conditions.
- [ ] Harden dependency, repository relationship and version pinning policies before release.
- [ ] Perform focused security review of JNI, SAF, clipboard, Autofill, backup and recovery boundaries.
- [ ] Add fuzzing/property testing for parser/adapters and malformed-input handling.
- [ ] Run static/dynamic analysis appropriate to Kotlin/JNI/Rust boundaries.

**Phase 5 exit:** abuse/resource/dependency/recovery objectives are satisfied and documented, with no hidden plaintext or proprietary recovery path.

## Phase 6 — Release and maintenance

- [ ] Produce a release build with reproducible/traceable native and Android artifacts.
- [ ] Document reproducibility expectations and remaining nondeterministic build inputs.
- [ ] Document signing and release-key handling.
- [ ] Prepare store/F-Droid-style metadata and privacy disclosures as applicable.
- [ ] Establish changelog, migration and versioning policy.
- [ ] Publish the supported KDBX feature matrix and known divergences.
- [ ] Run final supply-chain review, dependency audit and artifact checks/signing.
- [ ] Establish dependency/security-update cadence.
- [ ] Document a release/rollback runbook.

**Phase 6 exit:** signed prerelease/release artifacts are reproducible/traceable, documented and ready for real-world testing without bypassing security gates.

## Release gate

A public release is allowed only when all applicable items below are complete:

### Build and verification

- [ ] Release builds succeed from a documented clean environment.
- [ ] Required Android ABI/native artifacts are present and verified.
- [ ] Foundation/Android tests and security checks are green on the release commit.
- [ ] Reproducibility expectations and known nondeterminism are documented.

### Security

- [ ] Threat model and security invariants match the shipped implementation.
- [ ] JNI/FFI unsafe code has focused review and tests.
- [ ] Secrets are not logged, persisted or exposed through Android surfaces unintentionally.
- [ ] Resource/DoS limits are enforced for hostile KDBX inputs.
- [ ] Dependency/license/security review is current for the exact shipped versions.
- [ ] Secret scanning/push protection and static analysis are active and clean.

### Compatibility and data safety

- [ ] Supported KDBX variants are documented and exercised by deterministic fixtures.
- [ ] Reference-tool round-trip tests prove no silent semantic loss for supported write operations.
- [ ] KDBX3 behavior is explicit; no silent incompatible upgrade/rewrite occurs.
- [ ] Autofill/browser/WebView compatibility matrix is documented for the release.
- [ ] Recovery/backup behavior is tested for interrupted/failed writes.

### Packaging and maintenance

- [ ] Version/changelog/tag/release metadata are consistent.
- [ ] Signing/release-key process is documented.
- [ ] Store/F-Droid privacy/permission metadata matches the binary.
- [ ] Rollback and emergency release process is documented.
- [ ] Dependency/security-update cadence is established.

## Branch / PR / release policy

- [x] Protect `main` against force pushes and deletion.
- [x] Use short-lived topic branches and pull requests for non-trivial implementation work.
- [x] Require Foundation and CodeQL/security checks before merging production-relevant changes.
- [ ] Define the long-term release-branch/tag policy.
- [ ] Define versioning and changelog rules.
- [ ] Define required PR checks/review policy for production releases.
- [ ] Define artifact-retention and provenance policy.
- [ ] Define rollback policy.

## Blockers and dependencies

There is no known external organizational blocker and no open GitHub issue currently blocking work. The active blockers are technical gates owned by this project:

1. **Production KDBX open/decrypt remains blocked on completion of Fortress-owned resource-budget enforcement.** Input size and KDF/outer-header abuse are now gated before the selected engine; decompression and post-decrypt structure/attachment ceilings still must be enforced before production open is exposed.
2. **Write support is blocked on round-trip plus independent reference-tool validation.** Current read compatibility is not sufficient evidence for safe KDBX persistence.
3. **Production Android vault operations are blocked on the stable Rust handle/JNI contract and secret-buffer memory hygiene.**
4. **Public release is blocked on completing Phases 0–6 and the release gate, including a fresh dependency/license/security review of the exact versions shipped.**

## Next prioritized work

1. [ ] Complete the remaining Fortress-owned resource-budget gate with post-decrypt structure/attachment limits and decompression ceilings; the pre-decrypt input/KDF preflight is implemented and CI-verified.
2. [ ] Add the round-trip/interoperability harness and independent reference-tool preservation checks required before write support.
3. [ ] Close remaining accepted fixture-matrix gaps and run the full engine/adapter corpus without panics or unbounded allocation.
4. [ ] Define the stable Rust handle/JNI API and zeroization strategy, then expose bounded read-only vault operations to Android.

## Completion status

Status: **in progress**.

KDBX Fortress is **not** fully complete. It may be marked **fully complete** only when Phases 0–6 and every release-gate item are complete, all release-blocking checks are green, and the final release process/artifacts are documented and reproducible. Until then, later runs must continue from the highest-priority unchecked item in this file.

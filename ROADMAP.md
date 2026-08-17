# KDBX Bastion Roadmap

## Project goal

Build a security-first Android password manager that remains interoperable with KeePass/KDBX while using a Kotlin Android application and a narrowly isolated Rust vault core for security-critical vault operations.

## Current status

**Status: in progress — foundation / Phase 0**

The repository currently contains the project documentation baseline, Android/Kotlin↔Rust architecture decisions, a Rust workspace under `rust/` with an initial `vault-core` boundary, KDBX-engine research, form/autofill fixtures, repository policy checks and a green `Foundation` GitHub Actions workflow. There is not yet a production Android application or complete KDBX vault implementation.

`main` is currently the only development branch. This file is the source of truth for project execution until a branch/PR workflow is introduced.

## Completed foundation

- [x] Establish the project identity and scope as a KeePass/KDBX-compatible Android password manager.
- [x] Decide on a Kotlin Android application with an isolated Rust vault core.
- [x] Record the Android platform baseline in ADR 0001.
- [x] Record the Kotlin/Rust interoperability boundary in ADR 0002.
- [x] Create the Rust workspace under `rust/` and initial `rust/vault-core` crate.
- [x] Add policy tooling that constrains the Rust core boundary.
- [x] Add foundation CI and confirm the current `Foundation` workflow is green.
- [x] Add contribution and security documentation.
- [x] Add initial Rust/KDBX engine evaluation research.
- [x] Add form/autofill fixture schema and representative fixtures.

## Phase 0 — security and architecture freeze before production code

- [ ] Commit the final repository license before production implementation begins. Current recommendation: `AGPL-3.0-or-later`, subject to final compatibility review of dependencies and any code reused from upstream/reference projects.
- [x] Write the project threat model covering vault-at-rest, unlocked-memory exposure, clipboard, screenshots/recents, autofill, IPC/JNI/FFI boundaries, backups, storage providers, compromised web content and malicious local apps. See `docs/THREAT_MODEL.md`.
- [x] Define the Rust vault-core API contract: lifecycle/open/create/save/lock, entry/group CRUD, explicit protected-value retrieval, attachments, opaque handle semantics, FFI error handling and zeroization/lifetime rules. See `docs/VAULT_CORE_API.md`.
- [ ] Select the initial KDBX implementation strategy after validating candidate Rust libraries against required KDBX3/KDBX4 compatibility, Argon2/AES-KDF, AES/ChaCha20, protected streams, attachments, custom data and round-trip preservation.
- [ ] Create deterministic KDBX compatibility fixtures and round-trip tests before exposing vault operations to Android.
- [x] Materialize the first synthetic KDBX4 password-only interoperability fixture with manifest/SHA-256 validation; expand the corpus across the remaining compatibility matrix.
  - [x] Define the engine-neutral positive/negative fixture matrix, independent reference-oracle requirement and read/round-trip acceptance gates in `docs/KDBX_COMPATIBILITY_MATRIX.md`.
  - [ ] Materialize the synthetic KDBX fixtures plus sidecar manifests and SHA-256 values.
  - [ ] Add executable read compatibility tests against the selected/shortlisted engine strategy.
  - [ ] Add executable round-trip/interoperability tests before enabling write support.
- [ ] Document the crypto-agility policy. Any post-quantum protection must be additive/optional and must not break standard KDBX interoperability by silently inventing a non-standard database format.
- [ ] Define repository branch/PR/release policy once production implementation starts.

## Phase 1 — minimal vault core

- [ ] Implement handle registry and explicit lock/invalidation semantics independent of the KDBX engine.
- [ ] Implement read-only KDBX open/decrypt in Rust against deterministic fixtures.
- [ ] Expose a minimal safe Kotlin↔Rust bridge with opaque handles; do not expose decrypted database internals as long-lived serialized blobs across FFI.
- [ ] Implement explicit vault lock and sensitive-memory cleanup paths.
- [ ] Implement create/save/round-trip support only after read compatibility is proven.
- [ ] Add fuzz/property tests for KDBX parsing boundaries and malformed input.
- [ ] Add dependency/license/security checks for Rust and Android dependencies.

## Phase 2 — Android application shell

- [ ] Create the Android app module and reproducible debug build.
- [ ] Implement secure local vault selection/open/create flow without autofill yet.
- [ ] Add Android Keystore-backed device protection as an optional convenience layer that never replaces the KDBX master key semantics.
- [ ] Implement lock timeout, lifecycle/background locking, screenshot/recents protection and biometric unlock policy.
- [ ] Add database list/search, group navigation and entry detail/edit flows over the Rust core API.
- [ ] Keep UI state free of unnecessary plaintext secret copies and add tests around lock/lifecycle transitions.

## Phase 3 — Autofill and browser/app matching

- [ ] Implement Android AutofillService around the existing deterministic form fixtures.
- [ ] Define conservative URL/origin/application matching semantics before automatic suggestions.
- [ ] Support username/password, password-only, username-only, password-change and OTP forms represented by current fixtures.
- [ ] Handle WebView/system-view/browser-origin cases explicitly and test them as first-class compatibility scenarios.
- [ ] Add manual selection/search fallback when confidence is insufficient; avoid aggressive false-positive filling.
- [ ] Implement TOTP only after vault secret handling and autofill boundaries are stable.

## Phase 4 — storage, synchronization and resilience

- [ ] Add Storage Access Framework support with atomic save/replace semantics.
- [ ] Define conflict detection and external-change handling before enabling cloud-backed document providers.
- [ ] Add crash-safe writes, backups/recovery policy and corruption diagnostics.
- [ ] Test interoperability and round trips with reference KeePass implementations and representative real databases.

## Phase 5 — hardening and release readiness

- [ ] Complete security review of Rust unsafe/FFI code and Android exported components/permissions.
- [ ] Add static analysis, dependency auditing, secret scanning and reproducible release checks.
- [ ] Validate accessibility, autofill behavior and lifecycle locking across supported Android versions.
- [ ] Document KDBX compatibility limits and any intentionally unsupported features.
- [ ] Create signed prerelease builds only after the threat-model and vault-core security gates are satisfied.

## Validation and completion criteria

- [ ] Foundation, Rust and Android CI remain green on the active development branch.
- [ ] KDBX round-trip fixtures pass without silent data loss for supported features.
- [ ] Security-critical behavior has regression coverage, especially lock/unlock, FFI boundaries, storage writes and autofill origin matching.
- [ ] No non-standard cryptographic extension is enabled by default in a way that breaks KeePass/KDBX compatibility.
- [ ] Real-device validation covers normal apps, browsers and Android WebView/system-view login flows.

## Blockers / dependencies

- Final license selection must precede substantial production code so dependency/reuse choices remain legally compatible.
- The Rust KDBX engine must prove compatibility and round-trip safety before Android UI work depends on it.
- Strong post-quantum claims are blocked on a standards/interoperability design; standard KDBX compatibility remains the primary format constraint.
- Autofill correctness depends on real Android/browser/WebView behavior in addition to fixture-level tests.

## Completion status

**Not fully completed.** The threat model and vault-core API boundary are frozen at documentation level, and the deterministic KDBX compatibility/negative-corpus matrix is now defined. The immediate priority is to resolve the license gate, materialize the synthetic KDBX fixtures, and select/prove the KDBX engine against those acceptance gates before production vault implementation begins.

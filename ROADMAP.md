# KDBX Fortress Roadmap

## Project goal

Build a security-first Android password manager that remains interoperable with KeePass/KDBX while using a Kotlin Android application and a narrowly isolated Rust vault core for security-critical vault operations.

## Current status

**Status: in progress — foundation / Phase 0**

The repository currently contains the project foundation, security/architecture documents, compatibility-fixture infrastructure and CI checks. Production Android/vault implementation has not started yet.

## Phase 0 — security and architecture freeze before production code

- [x] Commit the final repository license as `AGPL-3.0-only`, add `NOTICE` and `TRADEMARKS.md`, and keep project identity/branding rules separate from the source-code license. Dependency and reused-code license compatibility remains a mandatory review gate.
- [x] Write the project threat model covering vault-at-rest, unlocked-memory exposure, clipboard, screenshots/recents, autofill, IPC/JNI/FFI boundaries, backups, storage providers, compromised web content and malicious local apps. See `docs/THREAT_MODEL.md`.
- [x] Define the Rust vault-core API contract: lifecycle/open/create/save/lock, entry/group CRUD, explicit protected-value retrieval, attachments, opaque handle semantics, FFI error handling and zeroization/lifetime rules. See `docs/VAULT_CORE_API.md`.
- [ ] Select the initial KDBX implementation strategy after validating candidate Rust libraries against required KDBX3/KDBX4 compatibility, Argon2/AES-KDF, AES/ChaCha20, protected streams, attachments, custom data and round-trip preservation.
- [x] Research `OneKeePass/mobile` as an external learning source before freezing the mobile architecture: review its architecture, Android/mobile integration patterns, KDBX handling, UX flows, security-relevant design choices and solved edge cases; document applicable lessons for Fortress. This is analysis-only: do not copy, port or reuse OneKeePass source code.
  - Findings: `docs/research/ONEKEEPASS_MOBILE_LESSONS.md`.
  - Reviewed upstream snapshots: OneKeePass/mobile `ba14115a4f31cd26a68892824262edcbeea8bba3` and OneKeePass/onekeepass-core `7f1b6b2655d7f4c388bb100a2de3e9bbaf2b8fd5`.
- [ ] Create deterministic KDBX compatibility fixtures and round-trip tests before exposing vault operations to Android.
- [x] Materialize a deterministic truncated-header KDBX4 negative fixture with SHA-256 manifest metadata and an explicit `expected_failure` contract; validate positive and negative fixture schemas separately (`06ed267b`).
- [x] Materialize a deterministic invalid-signature KDBX4 negative fixture with SHA-256 manifest metadata and an explicit `expected_failure` contract; corrupt the KDBX magic without changing the remainder of the known-good fixture (`21664651`).
- [x] Verify that committed truncated-header and invalid-signature KDBX4 negative fixtures remain deterministic byte-level derivations of the known-good synthetic fixture; run this invariant in Foundation CI (`1caa192d`).
- [x] Materialize the first synthetic KDBX4 password-only interoperability fixture with manifest/SHA-256 validation; expand the corpus across the remaining compatibility matrix.
  - [x] Define the engine-neutral positive/negative fixture matrix, independent reference-oracle requirement and read/round-trip acceptance gates in `docs/KDBX_COMPATIBILITY_MATRIX.md`.
  - [ ] Materialize the synthetic KDBX fixtures plus sidecar manifests and SHA-256 values, including required KDBX3/AES-KDF coverage. Use project-generated fixtures only; upstream fixture files are not required or redistributed.
  - [x] Materialize a KDBX4 Unicode round-trip fixture covering group/title/username/password/URL/notes.
  - [ ] Add executable read compatibility tests against the selected/shortlisted engine strategy.
  - [ ] Add executable round-trip/interoperability tests before enabling write support.
- [x] Document the crypto-agility policy. Non-standard cryptography must never silently replace interoperable KDBX. The only planned multi-cipher extension is a separate optional module targeting compatibility with the established KeePass Desktop `MultiCipher` plugin behavior; no Fortress-proprietary multi-cipher database format is planned. See `docs/CRYPTO_AGILITY.md`.
- [ ] Research and document the KeePass Desktop `MultiCipher` plugin format and exact compatibility contract before implementing the optional Fortress MultiCipher module. Confirm algorithm identifiers, key derivation/second-key handling, stream layout, KDBX header/plugin metadata, version compatibility and independent read/write interoperability with KeePass Desktop + MultiCipher.
- [ ] Define repository branch/PR/release policy once production implementation starts.

## Phase 1 — minimal vault core

- [ ] Implement handle registry and explicit lock/invalidation semantics independent of the KDBX engine.
- [ ] Implement read-only KDBX open/decrypt in Rust against deterministic fixtures.
- [ ] Expose a minimal safe Kotlin↔Rust bridge with opaque handles; do not expose decrypted database internals as long-lived serialized blobs across FFI.
- [ ] Implement explicit vault lock and sensitive-memory cleanup paths.
- [ ] Implement create/save/round-trip support only after read compatibility is proven.
- [ ] Add fuzz/property tests for KDBX parsing boundaries and malformed input.
- [ ] Add dependency/license/security checks for Rust and Android dependencies.
- [ ] Add an optional, separately isolated `MultiCipher` compatibility module only after the KeePass Desktop plugin format has been fully documented and tested. The module must support only configurations that KeePass Desktop + the established MultiCipher plugin can read/write; do not add Fortress-only cipher combinations under this compatibility mode.
- [ ] Keep MultiCipher support disabled by default and make the interoperability impact explicit before database creation/conversion: standard KeePass, KeePassXC, KeePassDX and other ordinary KDBX clients may not open such a database without the corresponding KeePass Desktop plugin support.
- [ ] Provide an explicit, tested migration/export path from MultiCipher-protected databases back to ordinary standard-KDBX encryption without modifying the source vault until the compatible export has reopened and passed integrity checks.

## Phase 2 — Android application shell

- [ ] Create the Android app module and reproducible debug build.
- [x] Research and select a free, redistribution-safe, high-quality and extensive icon source/library for folders, groups, entries and other UI objects.
  - Selected: **Tabler Icons**, initially pinned to upstream `v3.46.0` / commit `8ac7d81b72ece11072ef25ea9fd92e80c6f3c9fc`, under the original MIT license.
  - Decision and implementation constraints: `docs/research/ICON_CATALOG_EVALUATION.md`.
  - Bundle only a small essential baseline icon set; keep the searchable metadata index local and fetch extended icon payloads on demand through a replaceable Android-side provider outside the Vault Core.
  - Never send vault-derived folder/group/entry names or icon-search strings to the provider; resolve locally to provider/version/icon IDs first.
  - Use immutable versioned catalog snapshots, verify expected hashes, sanitize SVG input, preserve third-party notices and provide deterministic offline/cache fallback.
- [ ] Implement secure local vault selection/open/create flow without autofill yet.
- [ ] Add Android Keystore-backed device protection as an optional convenience layer that never replaces the KDBX master key semantics.
- [ ] Implement lock timeout, lifecycle/background locking, screenshot/recents protection and biometric unlock policy.
- [ ] Add database list/search, group navigation and entry detail/edit flows over the Rust core API.
- [ ] Keep UI state free of unnecessary plaintext secret copies and add tests around lock/lifecycle transitions.

## Phase 3 — Autofill, Credential Manager and browser/app matching

### 3.1 Platform integration

- [ ] Implement Android `AutofillService` around the existing deterministic form fixtures.
- [ ] Implement Android Credential Manager provider support as a first-class path rather than treating `AutofillService` as the only integration surface.
- [ ] Route AutofillService and Credential Manager requests through one shared target-normalization and matching engine; do not duplicate security-sensitive matching logic in separate integrations.
- [ ] Keep classic password autofill, Credential Manager password credentials and future passkey support separable so one integration can fail or be disabled without weakening the others.
- [ ] Define a manual invocation/selection path for cases where Android, the browser or the target app does not trigger automatic suggestions reliably.

### 3.2 Target identity and matching

- [ ] Build a deterministic app/browser target model using package identity, verified web origin/domain where available, normalized URLs and explicit user-approved associations.
- [ ] Prefer platform-provided web-domain/origin metadata over window titles, accessibility scraping or heuristic text extraction.
- [ ] Define strict URL normalization and matching rules for scheme, host, port, path, subdomains, IDNs/punycode, IP literals, localhost and custom schemes.
- [ ] Support multiple URLs/domains per entry and explicit app↔domain associations without silently broadening matches.
- [ ] Require explicit user action before creating or broadening an app/domain association learned from an ambiguous context.
- [ ] Treat package identity and signing identity as security boundaries where Android exposes enough information; do not trust display labels alone.
- [ ] Define phishing-resistant mismatch behavior: do not offer credentials merely because page/app text resembles a saved title or domain.

### 3.3 Form classification and fill behavior

- [ ] Classify login, registration, password-change, username-only, password-only, OTP and multi-step flows using platform semantics first and conservative heuristics second.
- [ ] Handle multiple username/password fields, repeated password confirmation fields and forms containing unrelated sensitive inputs.
- [ ] Support multi-step login flows where username and password are requested on different screens/pages without leaking state across unrelated targets.
- [ ] Preserve a short-lived, target-bound pending-fill context only when required; invalidate it on package/origin changes, timeout, lock or explicit cancellation.
- [ ] Add deterministic behavior for WebViews and hybrid apps, including cases where Android cannot provide a trustworthy web origin.
- [ ] Define safe behavior for embedded/custom tabs and browser-mediated login flows where app identity and web identity differ.
- [ ] Never infer a trusted credential target from a window title alone; title-based helpers may only be optional user-visible hints, never an authentication boundary.

### 3.4 Save/update workflow

- [ ] Implement save suggestions for new credentials without creating duplicates on repeated callbacks.
- [ ] Detect changed passwords/usernames and offer explicit update vs create-new choices.
- [ ] Bind save/update prompts to the same normalized target identity model used for filling.
- [ ] Do not persist credentials automatically from ambiguous forms or untrusted target identity.
- [ ] Handle registration→login transitions and password-change flows without overwriting the wrong entry.

### 3.5 OTP/passkeys and advanced credentials

- [ ] Support TOTP storage/display/autofill while keeping seed retrieval explicitly protected.
- [ ] Define whether OTP should be filled automatically, copied manually or require an explicit user gesture per security policy.
- [ ] Add passkey support through Credential Manager only after password-credential integration is stable; keep passkey private-key material behind the vault-core security boundary where technically feasible.
- [ ] Document interoperability limitations for credential types that cannot be represented portably in standard KDBX fields.

### 3.6 Autofill privacy, UX and failure handling

- [ ] Minimize data returned to Android autofill/Credential Manager surfaces until the user selects a credential.
- [ ] Never expose passwords, OTP seeds or protected custom fields in labels, logs, accessibility descriptions or diagnostic telemetry.
- [ ] Define unlock-on-demand behavior when an autofill request arrives while the vault is locked; bind post-unlock continuation to the original target and expire it quickly.
- [ ] Provide clear no-match, ambiguous-match and blocked-for-security states rather than silently filling the closest-looking entry.
- [ ] Add optional per-entry/per-domain autofill disable controls and an app/domain denylist.
- [ ] Ensure autofill UI remains usable with large vaults without loading/decrypting every protected field eagerly.

### 3.7 Autofill regression corpus

- [ ] Build synthetic Android/browser autofill fixtures covering normal native apps, Chromium-family browsers, Firefox-family browsers, WebViews, custom tabs and representative hybrid-app flows.
- [ ] Add fixtures for package/domain disagreement, redirects, subdomain changes, IDN/punycode domains, HTTP↔HTTPS transitions and custom ports.
- [ ] Add fixtures for multi-step login, multiple credential forms on one page, password-change forms, registration forms and OTP fields.
- [ ] Add fixtures for malformed or missing Autofill hints and browser structures that expose incomplete origin metadata.
- [ ] Add fixtures for vault-lock-during-fill, app-switch-during-unlock, stale callbacks, duplicate save callbacks and process recreation.
- [ ] Add regression fixtures/tests derived from known KeePassDX and KeePass2Android failure classes rather than assuming their historical edge cases cannot affect Fortress.

## Phase 4 — interoperability, hardening and release readiness

- [ ] Test interoperability and round trips with reference KeePass implementations and representative real databases.
- [ ] Add dedicated MultiCipher interoperability tests against KeePass Desktop + the established MultiCipher plugin for every supported cipher pairing/key mode before enabling MultiCipher writes.
- [ ] Add corruption/failure-injection tests for partial writes, interrupted saves and invalid KDBX structures.
- [ ] Add backup/atomic-save strategy and verify recovery behavior.
- [ ] Add Android instrumentation tests for vault lifecycle, autofill target binding and unlock continuation.
- [ ] Perform dependency/license/security review before first public prerelease.
- [ ] Perform manual security review of FFI/JNI boundaries and sensitive-memory lifetime.
- [ ] Verify release artifact provenance, version consistency and reproducibility before stable release.

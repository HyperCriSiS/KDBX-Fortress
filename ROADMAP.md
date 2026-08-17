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
- [x] Materialize a deterministic truncated-header KDBX4 negative fixture with SHA-256 manifest metadata and an explicit `expected_failure` contract; validate positive and negative fixture schemas separately (`06ed267b`).
- [x] Materialize a deterministic invalid-signature KDBX4 negative fixture with SHA-256 manifest metadata and an explicit `expected_failure` contract; corrupt the KDBX magic without changing the remainder of the known-good fixture (`21664651`).
- [x] Verify that committed truncated-header and invalid-signature KDBX4 negative fixtures remain deterministic byte-level derivations of the known-good synthetic fixture; run this invariant in Foundation CI (`1caa192d`).
- [x] Materialize the first synthetic KDBX4 password-only interoperability fixture with manifest/SHA-256 validation; expand the corpus across the remaining compatibility matrix.
  - [x] Define the engine-neutral positive/negative fixture matrix, independent reference-oracle requirement and read/round-trip acceptance gates in `docs/KDBX_COMPATIBILITY_MATRIX.md`.
  - [ ] Materialize the synthetic KDBX fixtures plus sidecar manifests and SHA-256 values.
  - [x] Materialize a KDBX4 Unicode round-trip fixture covering group/title/username/password/URL/notes.
  - [ ] Add executable read compatibility tests against the selected/shortlisted engine strategy.
  - [ ] Add executable round-trip/interoperability tests before enabling write support.
- [x] Document the crypto-agility policy. Any post-quantum protection must be additive/optional and must not break standard KDBX interoperability by silently inventing a non-standard database format. See `docs/CRYPTO_AGILITY.md`.
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

## Phase 3 — Autofill, Credential Manager and browser/app matching

### 3.1 Platform integration

- [ ] Implement Android `AutofillService` around the existing deterministic form fixtures.
- [ ] Implement Android Credential Manager provider support as a first-class path rather than treating `AutofillService` as the only integration surface.
- [ ] Route AutofillService and Credential Manager requests through one shared target-normalization and matching engine; do not duplicate security-sensitive matching logic in separate integrations.
- [ ] Keep classic password autofill, Credential Manager password credentials and future passkey support separable so one integration can fail or be disabled without weakening the others.
- [ ] Define a manual invocation/selection path for cases where Android, the browser or the target app does not trigger automatic suggestions reliably.

### 3.2 Normalized target and matching engine

- [ ] Define a normalized target model that can represent package name, component/app identity, trusted web origin, scheme, host, port, registrable domain, field metadata, browser/WebView context and source/confidence of every signal.
- [ ] Define conservative URL/origin/application matching semantics before automatic suggestions.
- [ ] Distinguish exact origin, exact host, subdomain/parent-domain and registrable-domain matches; never silently collapse them into one equivalence class.
- [ ] Support multiple URLs/associations per KDBX entry without breaking standard KDBX interoperability; keep any Bastion-specific metadata additive and round-trip-safe.
- [ ] Support Android package ↔ website/domain associations, distinguishing verified associations from explicit user-approved associations.
- [ ] Define conflict behavior when package identity and reported web origin disagree.
- [ ] Define deterministic ranking when several entries/accounts match the same app or domain.
- [ ] Preserve user choice for ambiguous targets without permanently broadening trust to unrelated origins.
- [ ] Never offer or disclose credentials automatically when the target origin/app identity cannot be established with sufficient confidence.
- [ ] Treat missing, malformed, contradictory or spoofable target metadata as a security condition rather than merely a UX inconvenience.

### 3.3 Form and field recognition

- [ ] Support username/password, password-only, username-only, password-change and OTP forms represented by current fixtures.
- [ ] Support multi-step login flows where username and password appear on separate screens/pages.
- [ ] Handle password-change forms containing old password, new password and confirmation fields without confusing them with normal sign-in.
- [ ] Handle multiple username/password candidates and dynamically inserted fields.
- [ ] Handle fields with correct, missing, incomplete or misleading autofill hints conservatively.
- [ ] Test standard Android Views, Jetpack Compose semantics and custom-view edge cases where the platform exposes reduced or unusual autofill metadata.
- [ ] Handle forms that appear only after navigation, JavaScript execution, delayed rendering or app state changes.
- [ ] Define behavior for embedded/iframe-like login contexts whenever Android/browser APIs expose enough origin information; reject unsafe inference when they do not.
- [ ] Implement TOTP only after vault secret handling and autofill boundaries are stable.

### 3.4 Browser, WebView and system-view compatibility

- [ ] Handle normal apps, browsers, Android System WebView, app-hosted WebViews and system views as distinct compatibility classes.
- [ ] Build and maintain an explicit browser compatibility matrix covering at least Chrome/Chromium, Firefox, Waterfox, Brave, Vanadium/GrapheneOS and Vivaldi where installable on supported test devices.
- [ ] Record for each browser whether trusted origin metadata is available through AutofillService, Credential Manager, both or neither, and which fallback behavior is allowed.
- [ ] Test Android System WebView separately from full browsers; do not assume identical origin exposure or lifecycle behavior.
- [ ] Test app-hosted WebViews where the native package and embedded web origin both matter.
- [ ] Test browsers/WebViews that expose incomplete or no trusted origin and ensure Bastion falls back to explicit selection or refusal instead of guessing from titles/text.
- [ ] Do not depend on accessibility scraping, window-title URL injection or tools such as “Add URL to Window Title” for the normal Android autofill architecture.
- [ ] If a compatibility workaround becomes unavoidable, document it as browser/version-specific, security-review it and keep it outside the core trust model.

### 3.5 Credential Manager and passkey edge cases

- [ ] Define Credential Manager behavior when no matching password credential exists; do not surface unrelated generic vault entries as if they were matches.
- [ ] Define provider behavior when the vault is locked when a Credential Manager request arrives.
- [ ] Ensure unlock followed by credential selection resumes the original request without leaking plaintext into long-lived Android state.
- [ ] Handle cancellation, timeout, process recreation and target-app disappearance during Credential Manager flows.
- [ ] Add passkey/WebAuthn support only after password-credential provider behavior is stable and interoperable.
- [ ] For passkeys, validate relying-party ID/origin constraints independently from password URL matching and never reuse weaker password-domain heuristics.
- [ ] Test “no passkey for this relying party”, multiple passkeys, registration, authentication, cancellation and malformed/unsupported requests.

### 3.6 Vault lifecycle and concurrency during autofill

- [ ] Define behavior when the vault is locked before an autofill request, becomes locked while suggestions are visible, or auto-locks during selection/fill.
- [ ] Invalidate pending credential handles and cached secret material immediately when the vault locks.
- [ ] Test autofill across app switching, background/foreground transitions, screen off/on, device unlock and long inactivity.
- [ ] Test Activity/process recreation and service restart without assuming an in-memory request survives.
- [ ] Handle simultaneous or rapidly repeated autofill requests without cross-target credential leakage or stale suggestions.
- [ ] Ensure one app/browser request can never reuse secret material resolved for another target after navigation or focus changes.

### 3.7 Security and anti-spoofing rules

- [ ] Add explicit tests for malicious or misleading apps attempting to request credentials associated with another package/domain.
- [ ] Treat package name alone as insufficient for web-origin claims unless the association is verified or explicitly approved under the documented policy.
- [ ] Prevent credential suggestions from crossing schemes/origins solely because visible page text, title or field labels resemble a trusted site.
- [ ] Never use window titles, page titles, accessibility text or arbitrary visible strings as authoritative origin identity.
- [ ] Ensure logs and diagnostics never contain passwords, OTP secrets, passkey private material or full sensitive form contents.
- [ ] Make matching confidence/reason diagnosable in a privacy-safe debug mode so compatibility failures can be reproduced without exposing secrets.

### 3.8 Fallback and UX behavior

- [ ] Add manual selection/search fallback when confidence is insufficient; avoid aggressive false-positive filling.
- [ ] Clearly distinguish exact trusted matches, user-associated matches and manual search results in the selection UI where security meaning differs.
- [ ] Support multiple accounts for the same target without arbitrary first-match autofill.
- [ ] Allow explicit one-time selection without automatically creating a permanent app/domain association.
- [ ] Require explicit user action before creating or broadening an app/domain association learned from an ambiguous context.
- [ ] Provide a safe “no matching credential” state instead of displaying unrelated entries merely to avoid an empty result.

### 3.9 Autofill compatibility and regression test matrix

- [ ] Maintain a versioned compatibility matrix covering Android versions supported by the project, device/OEM differences relevant to autofill, browsers, WebViews and representative native apps.
- [ ] Add real-device tests for each major browser family and at least one Chromium-derived browser with Google Play Services and one relevant no-GMS/GrapheneOS scenario where practical.
- [ ] Add regression fixtures/tests derived from known KeePassDX and KeePass2Android failure classes rather than assuming their historical edge cases cannot affect Bastion.
- [ ] Cover at minimum: no autofill suggestion, wrong-site suggestion, wrong-field classification, WebView origin loss, browser-origin disagreement, Credential Manager empty-match behavior, provider callback/response failure, passkey RP mismatch, locked-vault request, stale request after navigation and process/lifecycle restart.
- [ ] Record expected behavior for unsupported platform/browser combinations explicitly so “not supported” cannot be confused with an undetected regression.
- [ ] Require regression tests for every autofill bug that reaches a release whenever the failure can be reproduced deterministically.
- [ ] Do not mark Phase 3 complete until both fixture-level tests and representative real-device/browser validation pass.

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
- [ ] Security-critical behavior has regression coverage, especially lock/unlock, FFI boundaries, storage writes, Credential Manager flows and autofill origin/application matching.
- [ ] Autofill/Credential Manager matching never relies on page/window titles or accessibility text as authoritative identity and fails closed when trustworthy target identity is unavailable.
- [ ] Autofill compatibility is tracked in a versioned matrix and validated on representative native apps, major browser families, Android WebView/system-view flows and relevant lifecycle/lock transitions.
- [ ] Known reproducible KeePassDX/KeePass2Android autofill failure classes have corresponding Bastion regression scenarios where technically applicable.
- [ ] No non-standard cryptographic extension is enabled by default in a way that breaks KeePass/KDBX compatibility.

## Blockers / dependencies

- Final license selection must precede substantial production code so dependency/reuse choices remain legally compatible.
- The Rust KDBX engine must prove compatibility and round-trip safety before Android UI work depends on it.
- Strong post-quantum claims are blocked on a standards/interoperability design; standard KDBX compatibility remains the primary format constraint.
- Autofill correctness depends on real Android/browser/WebView/Credential Manager behavior in addition to fixture-level tests; some target apps may not expose enough trustworthy metadata for safe automatic filling.
- Browser/OEM/platform incompatibilities must degrade to explicit selection or no match rather than unsafe origin guessing; perfect coverage cannot be guaranteed by the password manager alone.

## Completion status

**Not fully completed.** The threat model and vault-core API boundary are frozen at documentation level, and the deterministic KDBX compatibility/negative-corpus matrix is now defined. The immediate priority is to resolve the license gate, materialize the synthetic KDBX fixtures, and select/prove the KDBX engine against those acceptance gates before production vault implementation begins.

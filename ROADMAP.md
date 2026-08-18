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
  - [ ] Materialize the synthetic KDBX fixtures plus sidecar manifests and SHA-256 values across the remaining compatibility matrix. Use project-generated fixtures only; upstream fixture files are not required or redistributed.
    - [x] Materialize a deterministic synthetic KDBX 3.1 fixture covering AES-KDF, AES-256-CBC, Salsa20-protected password data, notes and a custom field; validate the SHA-256 over the decoded binary representation.
  - [x] Materialize a KDBX4 Unicode round-trip fixture covering group/title/username/password/URL/notes.
  - [x] Add executable read compatibility tests against the pinned `keepass = 0.13.18` engine for the currently materialized KDBX3/KDBX4 positive fixtures and malformed-header/signature negative fixtures.
  - [ ] Add executable round-trip/interoperability tests before enabling write support.
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
- [ ] Never silently overwrite an existing credential from an autofill/save callback.
- [ ] Define safe cancellation/retry behavior when the vault locks or target identity changes during save/update.

### 3.5 Credential presentation and fallback

- [ ] Rank suggestions deterministically by exact verified origin, explicit verified association, exact app package binding, normalized KDBX URL host and only then controlled fallback rules.
- [ ] Distinguish exact/verified matches from weak/manual candidates in the UI rather than presenting all results with equal trust.
- [ ] Provide manual search/selection fallback when confidence is insufficient; manual selection must not permanently weaken matching rules unless the user explicitly creates an association.
- [ ] Return no credential suggestion when the target identity is missing, contradictory or unsafe and the user has not explicitly invoked manual selection.
- [ ] Avoid exposing usernames or entry titles to an untrusted target before the matching policy has authorized disclosure.

### 3.6 Locking, lifecycle and concurrency

- [ ] Define behavior when the vault is locked before an autofill request, locks while a request is pending, or is explicitly locked from another app surface.
- [ ] Invalidate pending credential handles and decrypted temporary state immediately when the vault locks.
- [ ] Handle activity/process recreation, background/foreground transitions, display-off/on and long inactivity without retaining stale fill state.
- [ ] Treat concurrent, duplicated and late Autofill/Credential Manager callbacks as normal input; prevent stale callbacks from filling a newly focused or unrelated target.
- [ ] Ensure autofill never silently unlocks the vault or extends a security timeout merely because Android retries a request.

### 3.7 Credential Manager and passkeys

- [ ] Define password credential behavior through Credential Manager separately from classic AutofillService behavior.
- [ ] Add passkey/WebAuthn support only after password matching and vault secret boundaries are stable.
- [ ] Bind passkey lookup to a trustworthy RP ID/origin and reject requests whose RP identity cannot be validated.
- [ ] Do not return arbitrary fallback passkeys merely because no exact RP match exists; manual recovery paths must remain explicit and origin-bound.
- [ ] Treat browser-mediated Credential Manager requests as a privileged compatibility surface requiring browser/origin verification rather than trusting claimed origin metadata blindly.

### 3.8 Autofill compatibility and regression matrix

Every supported release must exercise the applicable cases below. Automated fixtures cover deterministic parsing/matching behavior; real-device tests cover Android/browser behavior that fixtures cannot reproduce.

- [ ] Native Android Views with correct autofill hints.
- [ ] Jetpack Compose credential fields.
- [ ] Custom Views and forms with missing, incomplete or incorrect hints.
- [ ] Chrome/Chromium-family browser logins.
- [ ] Firefox-family browser logins, including Firefox and Waterfox Android.
- [ ] Brave browser login and Credential Manager behavior.
- [ ] Vanadium on GrapheneOS.
- [ ] Vivaldi browser behavior.
- [ ] Android System WebView and representative embedded WebViews.
- [ ] Username/password, username-only and password-only forms.
- [ ] Password-change flows with old/new/confirmation fields.
- [ ] Registration forms containing login-like fields.
- [ ] Multi-step username→password flows.
- [ ] Dynamically inserted/replaced fields after initial page load.
- [ ] Multiple saved accounts for the same origin/app.
- [ ] Multiple URLs/domains associated with one KDBX entry.
- [ ] No matching credential.
- [ ] Locked vault at request time and vault relock during the flow.
- [ ] App switch/background, long inactivity and display off/on during a pending request.
- [ ] Activity recreation and process restart while an autofill flow is pending.
- [ ] Duplicate, concurrent and late platform callbacks.
- [ ] Domain/origin mismatch and phishing look-alikes.
- [ ] Malicious/unrelated app attempting to claim another service's web identity.
- [ ] Explicit user-approved app↔website association and later revocation/change.
- [ ] Missing/untrustworthy web origin: no automatic credential disclosure; manual path only.
- [ ] Embedded/iframe login contexts to the extent Android/browser APIs expose them safely.
- [ ] Save-new vs update-existing credential workflows.
- [ ] Credential Manager password credentials.
- [ ] Passkey creation/use only after the dedicated passkey phase is enabled.
- [ ] Regression fixtures/tests derived from relevant historical KeePassDX and KeePass2Android failures, especially browser-origin, Android-version, passkey and WebView cases.

### 3.9 Phase-3 completion gate

- [ ] No permanent Accessibility Service or window-title URL workaround is required for supported core autofill flows.
- [ ] Automatic credential disclosure occurs only after target identity passes the shared matching policy.
- [ ] Manual fallback remains available without converting weak matches into implicit permanent trust.
- [ ] Deterministic matching tests and the maintained real-device/browser compatibility matrix pass for supported Android versions before Phase 3 is considered complete.
- [ ] Known regressions imported from KeePassDX/KeePass2Android research have dedicated tests or an explicitly documented platform limitation.

## Phase 4 — storage, interoperability hardening and prerelease

- [ ] Integrate Android Storage Access Framework with atomic write/replace semantics where providers permit it.
- [ ] Handle provider capability differences, external modifications and stale-cache/conflict cases explicitly; include regression coverage for sync-provider files that change remotely while a stale local/provider view still exists.
- [ ] Add crash-safe save, backup/recovery behavior and corruption diagnostics.
- [ ] Validate round-trips with KeePass and representative real-world KDBX databases.
- [ ] Complete unsafe/FFI review plus Android exported-component/permission review.
- [ ] Add static analysis, dependency auditing, secret scanning and reproducible release checks.
- [ ] Validate accessibility, autofill and lifecycle behavior across the supported Android compatibility matrix.
- [ ] Document exact KDBX compatibility limits and unsupported fields/features before release.
- [ ] Produce signed prereleases only after security and compatibility gates pass.

## Phase 5 — Post-MVP / optional: Fortress MultiCipher extension

**Priority: deferred / no current priority. This phase does not block the MVP, first prerelease or first stable release. Do not start it until the standard KDBX product path is complete and stable.**

- [ ] Design a separate optional Fortress MultiCipher module only after the standard KDBX implementation, Android app, autofill, storage and release hardening phases are complete.
- [ ] Define a versioned multi-cipher profile/container that composes existing reviewed cryptographic primitives without modifying the standard KDBX path.
- [ ] Specify key separation/derivation, cipher ordering, nonce/IV handling, authenticated metadata, failure semantics and downgrade protection before implementation; multiple individually secure ciphers must not be assumed to form a secure construction automatically.
- [ ] Keep all standard KDBX modes fully interoperable; the MultiCipher mode must require an explicit opt-in and a prominent warning that ordinary KeePass/KeePassXC/KeePassDX/other KDBX clients cannot open that database without compatible support.
- [ ] Provide an explicit conversion/export path from MultiCipher back to standard interoperable KDBX.
- [ ] After the Fortress module is stable, create a dedicated desktop project/adapter that implements the same versioned MultiCipher specification for desktop KeePass use rather than coupling Android development to a desktop plugin.
- [ ] Publish interoperability vectors/specification and independently test Android↔desktop MultiCipher round-trips before considering the extension usable.

## Validation criteria

- Foundation CI remains green on the default branch.
- KDBX interoperability tests prove expected round-trips without silent data loss before write support is enabled.
- Security regression coverage exists for lock/unlock, FFI, storage and autofill-origin boundaries.
- Standard KDBX modes remain interoperable with established clients; any optional post-MVP MultiCipher extension is isolated, explicitly opt-in and never used to redefine ordinary KDBX compatibility.
- Real-device validation includes normal apps, browsers and WebView/system-view cases.

## Blockers / external dependencies

- The initial Rust KDBX engine must pass the project's compatibility corpus before Android UI work depends on it.
- Post-quantum or MultiCipher claims remain gated on concrete standards, threat models and interoperability; neither is a prerequisite for the standard KDBX MVP.
- Autofill correctness depends on real Android/browser/WebView behavior and therefore cannot be proven only with static fixtures.

## Completion

**Project is not fully completed.** The immediate priority is to finish Phase 0 compatibility/engine validation, then begin the minimal read-only Rust vault core. MultiCipher is intentionally deferred until after the standard product path is stable.

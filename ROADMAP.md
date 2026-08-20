# KDBX Fortress Roadmap

This file is the authoritative source of truth for project progress. A task is marked complete only when the repository state or documented project context proves it.

## Project goal

Build a security-first offline Android password manager that treats interoperable `.kdbx` vaults as the only source of truth, keeps cryptographic/database processing inside a Rust boundary, and exposes it to Kotlin through a minimal, auditable JNI/C ABI. The application should reach practical KeePass-class usability while preserving KDBX interoperability and avoiding a proprietary vault format or plaintext bypass.

The acceptance criteria and scope in this file are normative unless changed deliberately through a reviewed roadmap update.

## Current status

Status: **Phase 0 in progress; the bounded KDBX accepted/adversarial corpus gate is complete for the defined Phase-0 surface. It covers every manifest-backed fixture, derived outer-header/version/cipher/KDF, credential, truncation, integrity and representative resource-budget failures, plus cryptographically authenticated malformed decrypted XML, invalid root nesting, invalid UUID encoding and duplicate group/entry UUIDs without escaping Rust panics. The next blockers are the stable Rust handle/API model and explicit secret-buffer memory hygiene/zeroization.**

Roadmap baseline after the corpus-validation tranche: `main` at `ba1b9ef41b06203db7b125086dd9455790a1bb5f`, with the authenticated XML adversarial closure validated on PR #21 before merge.

- The Rust core is an isolated `cdylib`/JNI scaffold and pins the Fortress `keepass-rs` fork at commit `86c53bbb1bf35c3c83d5e25dfa13942e062b9293` (package line based on 0.13.18) as the initial read-validation KDBX engine behind an engine-neutral validation approach. The fork's `test_fixture_tools` raw-XML writer is feature-gated and enabled only for dev/test builds so authenticated malformed decrypted XML can be exercised without widening the production API.
- Deterministic generated fixtures and executable Rust tests cover KDBX 3.1 and KDBX 4 variants, including AES-KDF, Argon2d, Argon2id, AES-256-CBC, ChaCha20 outer encryption, protected fields, Unicode, attachments, `CustomData`, and password + raw-32-byte key-file composite credentials.
- Negative coverage includes malformed/truncated headers, invalid signatures, incorrect credential combinations, derived unsupported version/cipher/KDF cases, truncated encrypted payloads, corrupted header/payload authentication data, representative typed resource-budget failures, and authenticated post-decrypt XML failures covering mismatched tags, invalid Root/Entry nesting, invalid UUID encoding and duplicate group/entry UUIDs.
- Fixture hashes/manifests are validated in CI; required Android Rust targets and exported native symbols are checked by the foundation workflow.
- The bounded decompression/attachment-expansion integration was rebuilt cleanly on current `main` and merged through PR #12 after the full `Foundation` workflow passed, including Rust tests and Android ARM64/x86_64 checks.
- `main` is protected; recent work uses short-lived feature/test branches and pull requests before integration.
- There are currently no open repository issues and no published releases.
- There is not yet a production Android application module, production vault-read JNI API, write path, Autofill implementation or release artifact.

Known engine constraints remain explicit: the pinned engine is currently used for read validation, not as an unconditional production/write commitment. KDBX feature/version coverage, owned secret buffers and unsupported combinations must be contained by Fortress-owned adapters, limits and validation gates before production use.

## Phase 0 — Prove the KDBX/core approach

Goal: prove a bounded, interoperable and auditable Rust KDBX core before exposing production vault operations to Android.

- [x] Select the initial **read-only validation** KDBX strategy behind the Rust core: pin `keepass = 0.13.18` behind an internal adapter boundary while write support remains disabled pending interoperability gates.
  - [x] Evaluate maintained Rust KDBX candidates against the required format/crypto matrix.
  - [x] Record license, maintenance, Android/JNI integration, preserved metadata, resource-budget implications and take/reject/borrow decisions.
  - [x] Define an engine-neutral positive/negative fixture matrix, independent reference-oracle requirement and read/round-trip acceptance gates in `docs/KDBX_COMPATIBILITY_MATRIX.md`.
  - [x] Materialize synthetic/reference KDBX fixtures plus manifests/SHA-256 across the required positive compatibility matrix; fixtures must be project-generated or otherwise redistributable.
    - [x] Materialize a deterministic KDBX 3.1 fixture covering AES-KDF, AES-256-CBC, Salsa20-protected password, notes and a custom field; validate decoded SHA-256 values.
    - [x] Materialize a deterministic KDBX 4 Unicode fixture and exercise the pinned Rust read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2d and AES-256-CBC outer encryption; validate hashes and executable read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2id and AES-256-CBC outer encryption; validate hashes and executable read path.
    - [x] Materialize a deterministic KDBX 4 fixture covering Argon2id and ChaCha20 outer encryption; validate hashes and executable read path.
    - [x] Materialize and exercise a deterministic KDBX 4 fixture covering attachments and `CustomData`, including protected/unprotected binary-pool data and database/group/entry metadata preservation on read.
    - [x] Materialize and exercise a generated KDBX 4 fixture requiring a composite password plus external raw-32-byte key file; validate database/key-file SHA-256 values, sidecar size and positive/negative credential combinations through the pinned Rust engine.
    - [x] Materialize an independent KeePass 2.61.1/KPScript KDBX 4.0 empty/optional-value edge fixture; verify the empty group remains empty and omitted/empty optional strings are not invented during bounded reads.
    - [x] Materialize an independent KeePass 2.61.1/KeePassLib KDBX 4.0 bounded-large fixture with an exact 65,536-byte Notes value and deterministic 262,144-byte attachment; verify exact content, exact-limit acceptance and typed rejection when field/per-attachment/aggregate-attachment ceilings are lowered by one byte.
  - [x] Add executable read-compatibility tests for the currently materialized positive fixtures and malformed-header/signature/credential negative cases.
  - [x] Add executable round-trip/interoperability tests before enabling write support, including independent reference-tool validation and semantic-preservation assertions.
    - [x] Add a test-only KDBX4 serializer characterization harness covering direct KDBX 4.0 save refusal plus explicit 4.0 → 4.1 migration for Argon2id/AES-256, Argon2id/ChaCha20, Unicode values, protected/unprotected attachments, database/group/entry `CustomData`, and password + raw-32-byte key-file credentials. Save support remains enabled only through a dev-dependency feature.
    - [x] Decide and document the supported write policy for KDBX 4.0 versus explicit KDBX 4.1 migration in `docs/KDBX_WRITE_POLICY.md`: initial production writes target KDBX 4.1 only; KDBX 4.0 remains read-only unless the user deliberately invokes a separately validated migration, and ordinary Save must never perform a silent minor-version upgrade.
    - [x] Resolve/scope KDBX 3 write support for the initial write envelope: KDBX 3.1 remains bounded read-only; no implicit KDBX 3 → 4.1 conversion substitutes for the pinned engine's lack of KDBX 3 serialization.
    - [x] Complete the remaining semantic-preservation matrix, including history and unknown/preservable metadata behavior.
      - [x] Preserve entry history across explicit KDBX 4.1 serialization/reopen, including protected password state and non-nested historical snapshots; include the produced history database in the independent KeePassXC reopen gate.
      - [x] Characterize and safely handle unknown/not-yet-modeled XML metadata: the pinned Fortress fork records ignored Serde XML paths during tolerant reads and `Database::save` fails with `UnpreservedXmlFields` before writing any output when such paths exist, preventing silent extension/newer-minor metadata loss while retaining read compatibility.
    - [x] Reopen Fortress-produced outputs with independent KeePass and KeePassXC reference tools before any production write API is enabled.
      - [x] Emit representative serializer outputs from the existing KDBX 4.1 characterization tests and reopen password-only plus password/key-file outputs with `keepassxc-cli` in Foundation CI.
      - [x] Reopen representative Fortress-produced KDBX 4.1 outputs with pinned KeePass 2.61.1/KPScript 2.61.1 on Windows CI after verifying official package sizes and SHA-256 hashes, including password-only and password + raw-32-byte-key-file credentials.
  - [x] Enforce explicit Fortress-owned resource limits **before production parsing/decryption**: input size, Argon2 memory/time/parallelism policy, recursion/depth, entry/field/attachment counts and sizes, and decompression ceilings. Rejections are typed and safe.
    - [x] Pre-decrypt input/outer-header/KDF preflight with typed safe failures, AES-KDF ceilings, Argon2 memory/iterations/parallelism ceilings and an overflow-safe combined-work ceiling.
    - [x] Post-decrypt structure/attachment/count ceilings and decompression/expansion limits.
      - [x] Enforce typed post-decrypt ceilings for group/entry counts, group depth, per-entry fields/history/custom-data/attachment references, per-attachment size and aggregate attachment bytes; validate the gate against the real KDBX3/KDBX4 fixture suite.
      - [x] Bound KDBX3/KDBX4 payload decompression and binary-attachment expansion before untrusted output is fully materialized through the pinned Fortress `keepass-rs` fork; map engine resource failures to typed, non-secret Fortress errors and exercise the limits through the real fixture suite.
  - [x] Validate the chosen engine/adapter against the full accepted/adversarial corpus with no panics, no unbounded allocation and no format regressions.
    - [x] Gate every manifest-backed KDBX fixture through the bounded adapter; accepted files retain expected format/version/content markers while manifest malformed-header/signature cases and incorrect credentials fail closed without an escaping Rust panic.
    - [x] Add deterministic derived adversarial coverage for unsupported major version, invalid outer-header field length, unsupported cipher/KDF identifiers, truncated encrypted payload, corrupted header authentication and corrupted payload integrity; require fail-closed Fortress error categories without escaping Rust panics.
    - [x] Exercise representative input/KDF/decompression/structure/field/custom-data/per-attachment/aggregate-attachment resource ceilings through the integrated corpus gate. `catch_unwind` is only a panic-containment assertion; allocation boundedness is established by the separately enforced preflight, bounded-decompression and post-decrypt resource ceilings plus their fail-closed tests.
    - [x] Add authenticated malformed decrypted XML / invalid nesting coverage and defined invalid-identifier cases. A test-only feature-gated fork helper creates cryptographically valid KDBX 4.1 containers with caller-supplied decrypted XML; a valid control must open, while mismatched XML tags, Entry directly under Root, invalid UUID encoding, duplicate group UUID and duplicate entry UUID deterministically fail closed as engine rejection without an escaping Rust panic.
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
- [ ] Sanitize crashes/logging so secrets, credentials and decrypted field values cannot leak.
- [ ] Add Android instrumentation/E2E coverage for open, browse, search, copy, lock and lifecycle behavior.

**Phase 1 exit:** a usable read-only Android password manager opens supported KDBX files, browses/searches entries and locks safely without moving raw vault state into Kotlin.

## Phase 2 — Safe vault editing and persistence

- [ ] Expose editing through Rust-owned handles/operations rather than mutable duplicate Kotlin models.
- [ ] Create/edit/delete groups and entries.
- [ ] Support standard/custom fields, URLs and password generation.
- [ ] Preserve history, recycle-bin semantics and attachments required for interoperable KDBX editing.
- [ ] Define a deterministic ownership/memory model for edits and sensitive temporary values.
- [ ] Implement atomic save/replace through SAF-compatible storage handling.
- [ ] Detect external file conflicts and prevent silent overwrite/data loss.
- [ ] Prove round-trip preservation across supported KDBX variants and metadata.
- [ ] Implement composite-key/key-file lifecycle and memory hygiene for save operations.
- [ ] Add integration fixtures proving open → modify → save → reopen through Fortress and independent reference tools.

**Phase 2 exit:** supported KDBX vaults can be edited and persisted atomically without semantic loss.

## Phase 3 — Android Autofill framework

- [ ] Implement `AutofillService` with a minimal-permission design.
- [ ] Parse application/web identity defensively and normalize matching inputs.
- [ ] Define deterministic URL/package/domain matching and ranking rules.
- [ ] Handle locked vaults by prompting for the normal unlock path rather than caching plaintext credentials.
- [ ] Provide fast search/selection for ambiguous matches.
- [ ] Return authenticated Autofill datasets/results without leaking unrelated entries.
- [ ] Add denylist/configuration controls for sites/apps where Autofill must not operate.
- [ ] Add security tests for spoofing, cross-app/domain confusion, stale sessions and unintended disclosure.
- [ ] Add instrumentation tests across representative browser and native-app Autofill flows.

**Phase 3 exit:** Autofill is reliable, deterministic and privacy-preserving across supported Android/browser cases.

## Phase 4 — Advanced credential UX and field actions

- [ ] Add TOTP/HOTP support based on interoperable entry metadata.
- [ ] Implement correct formatting, copy and expiry/countdown behavior for OTP values.
- [ ] Make an explicit passkey/WebAuthn strategy decision before implementing passkey write support.
- [ ] Add field-specific actions for username, password, URL, notes, custom fields and OTP.
- [ ] Add safe URL/app/browser launch handling.
- [ ] Add a custom keyboard only if a documented Android/Autofill gap justifies its security and maintenance cost.
- [ ] Define per-field copy/reveal policies and timeout behavior.
- [ ] Cover special/protected/custom field behavior in the UX state matrix.
- [ ] Add integration tests for advanced credential actions.

**Phase 4 exit:** advanced credential actions remain interoperable, deliberate and covered by the same lock/secret-handling model.

## Phase 5 — Hardening, recovery and import/export

- [ ] Define tested Argon2 presets/benchmarks and user-visible handling for vaults exceeding safe device budgets.
- [ ] Add biometric/device-credential wrapping only for a narrowly scoped unlock secret and document its threat model.
- [ ] Define emergency unlock/recovery behavior without plaintext vault dumps.
- [ ] Add explicit read-only/recovery paths for partially unsupported or damaged vaults where safe.
- [ ] Add explicit import paths for selected external formats such as CSV/XML only where semantics can be mapped safely.
- [ ] Add export flows with prominent plaintext-risk warnings and deliberate confirmation.
- [ ] Guarantee temporary-file cleanup for import/export/recovery operations.
- [ ] Define backup/restore behavior that does not create an undocumented second vault format.
- [ ] Review privacy-sensitive logging/crash-reporting behavior and keep telemetry opt-in or absent by default.
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

**Phase 6 exit:** a signed, documented release can be reproduced, audited, upgraded and rolled back using the defined process.

## Release gate

Every item below must be green for a public release:

- [ ] Android lint/static checks.
- [ ] Kotlin/JVM unit tests.
- [ ] Rust unit/integration tests.
- [ ] Android instrumentation tests.
- [ ] Deterministic KDBX fixture validation.
- [ ] KDBX round-trip/reference-tool interoperability suite.
- [ ] Autofill E2E suite.
- [ ] Native-library target/checksum/export verification.
- [ ] Dependency review/audit.
- [ ] License/vulnerability scan.
- [ ] CodeQL/secret-scanning review with no unresolved release-blocking findings.
- [ ] Manual security/lifecycle checklist covering auto-lock, clipboard, backgrounding, temporary data, backup and recovery.

**Rule:** any failing release-gate item blocks release.

## Explicit de-scoping and design principles

- [ ] Do not introduce a proprietary replacement for KDBX as the normal vault format.
- [ ] Do not keep long-lived raw passwords or decrypted KDBX/database state in Kotlin.
- [ ] Do not maintain an independent duplicate database model outside the Rust vault core.
- [ ] Do not add a sync engine before local atomic persistence/conflict handling is proven.
- [ ] Do not provide a plaintext emergency-vault dump as a recovery feature.
- [ ] Do not add a custom keyboard unless a documented capability gap justifies it.
- [ ] Do not add passkey write support until a deliberate compatibility/security decision is recorded.

These are standing constraints rather than implementation-completion claims; they remain unchecked until the release architecture proves continued compliance.

## Branch and release policy

Current verified development workflow:

- [x] Keep `main` protected and integrate recent implementation/test changes through short-lived branches and pull requests.
- [x] Run Foundation and CodeQL/security checks on integrated `main` changes.

Before production release:

- [ ] Define the long-term release-branch/tag policy.
- [ ] Define versioning and changelog rules.
- [ ] Define required PR checks/review policy for production releases.
- [ ] Define artifact-retention and provenance policy.
- [ ] Define rollback policy.

## Blockers and dependencies

There is no known external organizational blocker and no open GitHub issue currently blocking work. The active blockers are technical gates owned by this project:

1. **Production KDBX open/decrypt exposure is now blocked on the stable Rust handle/API model and secret-buffer memory hygiene/zeroization.** The Phase-0 accepted/adversarial corpus, write-policy/round-trip evidence, Fortress-owned resource-budget gates and independent KeePassXC/KeePass reopening gates are complete for the defined surface.
2. **Production Android vault operations are blocked on the stable Rust handle/JNI contract and secret-buffer memory hygiene.**
3. **Production write exposure remains constrained by the documented KDBX 4.1-only initial write envelope and must continue to preserve the established unknown-XML fail-closed and independent-reference interoperability gates as the API grows.**
4. **Public release is blocked on completing Phases 0–6 and the release gate, including a fresh dependency/license/security review of the exact versions shipped.**

## Next prioritized work

1. [ ] Define and implement the stable Rust handle/API model while preserving the invariant that decrypted vault state remains inside Rust.
2. [ ] Define and implement the zeroization/secret-buffer strategy for passwords, composite-key material, key-file bytes and sensitive temporary buffers.
3. [ ] Extend the JNI contract only after the stable handle/API and secret-memory gates are proven, beginning with bounded read-only vault operations.

## Completion status

Status: **in progress**.

KDBX Fortress is **not** fully complete. It may be marked **fully complete** only when Phases 0–6 and every release-gate item are complete, all release-blocking checks are green, and the final release process/artifacts are documented and reproducible. Until then, later runs must continue from the highest-priority unchecked item in this file.

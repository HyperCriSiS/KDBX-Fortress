# KDBX Bastion Threat Model

## Scope

KDBX Bastion is an Android password manager that keeps KeePass/KDBX interoperability as a hard compatibility requirement. The Android application is written in Kotlin; security-critical vault parsing, cryptography and unlocked-vault state belong in the isolated Rust vault core.

This threat model covers the first production architecture. It must be revisited before adding synchronization, browser integration, non-standard cryptography or new exported Android components.

## Security goals

1. A stolen device or copied KDBX file must not reveal vault contents without the user's KDBX credentials.
2. Plaintext secrets should exist only while required for an explicit operation and should not be duplicated across Kotlin/Rust boundaries unnecessarily.
3. Untrusted KDBX files, storage providers, applications and web content must not be able to execute code or obtain unrelated vault data.
4. Autofill must bind suggestions to the intended Android package and, for web content, the verified web origin rather than merely visible text.
5. Save operations must not silently corrupt or lose supported KDBX data.
6. Locking must revoke the application's ability to retrieve secrets from the unlocked vault state.
7. Device convenience protection such as Android Keystore/biometrics must remain an additional local layer and must not silently alter standard KDBX master-key semantics.

## Trust boundaries

### Rust vault core

Trusted for:
- KDBX parsing and serialization.
- key derivation and cryptographic operations.
- ownership of unlocked vault state.
- protected-value handling.
- explicit vault lock and memory cleanup.

The core must not depend on Android UI, network, clipboard, AutofillService or storage-provider APIs.

### Kotlin application

Trusted to orchestrate user interaction and Android platform APIs, but not to retain a second full plaintext copy of the unlocked database. Kotlin receives only the minimum data required for the current UI/autofill operation.

### FFI boundary

Treat all parameters crossing Kotlin/Rust as untrusted. Prefer opaque handles and bounded value objects. Never pass raw pointers, long-lived serialized plaintext vaults or caller-controlled lengths without validation.

### Android platform and other apps

The OS provides process isolation, Keystore, biometric APIs and Autofill plumbing, but other apps, accessibility services, keyboards, overlays, screenshots and clipboard readers may be hostile or compromised.

### Storage providers / cloud sync

KDBX bytes and metadata from Storage Access Framework providers are untrusted input. Providers may return stale, truncated, replaced or concurrently modified files.

### Web content

HTML field labels, DOM structure and visible URLs are attacker-controlled. WebView/browser autofill requires a trustworthy origin supplied by Android/browser integration; field content alone must never establish origin identity.

## Threats and required controls

### Vault at rest

Threats:
- copied KDBX file;
- offline password guessing;
- maliciously modified KDBX;
- rollback to an older vault copy.

Controls:
- preserve standard KDBX KDF/cipher parameters and interoperability;
- validate file structure before allocating attacker-controlled sizes;
- enforce bounded parsing and decompression;
- surface unsupported/corrupt input instead of partially accepting it;
- use atomic writes and detect external changes before overwrite;
- do not weaken KDF parameters automatically.

### Unlocked memory

Threats:
- plaintext duplicated in JVM heap;
- crash dumps/logging;
- use-after-lock through stale references;
- secrets retained longer than necessary.

Controls:
- Rust owns unlocked vault state behind opaque handles;
- return individual values on demand rather than complete database snapshots;
- never log credentials, protected fields, master keys or decrypted attachments;
- use zeroizing containers where meaningful and explicitly clear vault state on lock/drop;
- invalidate handles/generations on lock so stale callers fail closed;
- avoid immutable JVM `String` for secrets when an API can safely use short-lived byte/char buffers; where Android APIs require strings, minimize lifetime and copies.

### Master credentials and local convenience unlock

Threats:
- master password persisted by accident;
- biometric/Keystore wrapper becomes a replacement weak credential;
- replay of stale wrapped key material.

Controls:
- never persist the master password;
- if quick unlock is implemented, wrap only narrowly scoped key material with Android Keystore and bind it to the selected vault identity;
- invalidate quick-unlock material when the KDBX master key or vault identity changes;
- make fallback behavior explicit and fail closed on biometric/Keystore errors.

### Clipboard

Threats:
- other apps read copied passwords;
- secret remains after use.

Controls:
- prefer Autofill over clipboard;
- mark copied content sensitive where supported;
- configurable short auto-clear with ownership checks so unrelated clipboard content is not erased;
- never copy secrets automatically.

### Screenshots and recents

Threats:
- secrets captured by screenshots, screen recording or recent-app previews.

Controls:
- apply secure-window protection on sensitive screens by default;
- ensure recent-app snapshots do not contain unlocked secrets;
- treat user-controlled relaxation, if ever offered, as an explicit security tradeoff.

### Autofill / phishing / confused deputy

Threats:
- filling credentials into the wrong app, look-alike package, iframe or origin;
- hostile WebView presenting misleading labels;
- over-broad domain matching.

Controls:
- use package identity plus verified web origin where available;
- canonicalize hosts and apply conservative exact/subdomain matching rules;
- never infer a trusted origin solely from editable-field text;
- require manual selection when confidence is insufficient;
- distinguish login, password-change, OTP and search/non-auth forms;
- maintain deterministic fixtures plus real-device browser/WebView tests.

### IPC, exported components and intents

Threats:
- another app invokes internal actions or passes malicious URIs/identifiers.

Controls:
- export no component unless required;
- require appropriate Android permissions/intent validation;
- validate all external URIs and document handles;
- never expose an unlocked-vault handle through intents, bundles or persistent state.

### JNI/FFI misuse

Threats:
- invalid handles, integer overflow, oversized buffers, double free, panic crossing FFI.

Controls:
- use opaque numeric handles with generation checking;
- validate lengths and enum values before use;
- convert Rust panics/errors into explicit error results; do not unwind across FFI;
- centralize bridge code and minimize `unsafe`;
- security review every `unsafe` block and exported FFI function.

### KDBX parser attacks

Threats:
- malformed headers/XML;
- zip/decompression bombs;
- extreme Argon2/KDF parameters causing resource exhaustion;
- oversized attachments/custom data.

Controls:
- parser fuzzing and malformed-input corpus;
- explicit resource ceilings with user-visible errors for unreasonable untrusted inputs;
- checked arithmetic for sizes/counts;
- no network access from parser/core;
- preserve unknown-but-supported data on round trip rather than silently dropping it.

### Storage / save / synchronization

Threats:
- partial write or process death corrupts vault;
- concurrent writer overwrites newer data;
- hostile provider swaps document between read/write.

Controls:
- write to a new temporary/document version, flush, validate where feasible, then replace atomically where provider semantics permit;
- compare source identity/version metadata before save;
- keep recovery/backup strategy explicit;
- never silently merge conflicting decrypted databases without a defined conflict model.

### Logs, telemetry and crash reporting

Threats:
- credentials, URLs or vault metadata leave device through diagnostics.

Controls:
- no secret values in logs;
- sanitize exception text crossing parser/FFI boundaries;
- telemetry/crash reporting opt-in or privacy-preserving and documented before release;
- diagnostic export must redact vault contents by construction.

### Backups

Threats:
- Android/cloud backup captures quick-unlock keys or plaintext state.

Controls:
- exclude transient/unlocked state and sensitive local key material from backups;
- treat the encrypted KDBX file separately from app convenience state;
- document restoration behavior and invalidate device-bound quick unlock after restore when appropriate.

### Dependency / supply-chain compromise

Controls:
- pin/review security-critical Rust and Android dependencies;
- Dependabot plus CI security/license checks;
- minimize cryptographic implementations written in-project;
- reproducible release inputs and signed release artifacts;
- no runtime download of executable code.

## Post-quantum / crypto agility

KDBX Bastion must not market standard KDBX encryption as post-quantum secure beyond what its standardized primitives justify. Any future post-quantum layer must be separately threat-modeled, versioned, opt-in/additive and must not silently produce a database that normal KeePass implementations cannot open. Crypto agility is preferred over inventing an undocumented KDBX dialect.

## Security invariants for CI/review

- The Rust vault core has no Android/network/clipboard dependency.
- Production logs contain no secret field values or master credentials.
- Lock invalidates all vault handles and secret retrieval.
- Unsupported/corrupt KDBX input fails closed.
- Autofill never trusts field labels as origin identity.
- Save tests prove round-trip preservation for the supported feature set.
- Any new exported Android component or Rust `unsafe` block requires explicit security review.

## Out of scope for the first milestone

- defending a device with an already compromised kernel/root/hypervisor;
- preventing a user from intentionally exporting/copying a secret;
- transparent multi-writer database merging;
- claiming protection against every future quantum attack while retaining an unchanged standard KDBX format.

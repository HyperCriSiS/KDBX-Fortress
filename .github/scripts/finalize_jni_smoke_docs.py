from pathlib import Path

roadmap = Path("ROADMAP.md")
text = roadmap.read_text(encoding="utf-8")

replacements = [
    (
        "Status: **Phase 0 in progress; the defined KDBX accepted/adversarial corpus gate, opaque generation-checked handle registry, Fortress credential boundary, initial engine-owned secret-memory/zeroization gate and concrete Rust vault-owner lifecycle are complete. The stable handle/API parent remains open until the Kotlin/JNI wrapper is integrated. The next security-critical tranche is the bounded Kotlin/JNI adapter while preserving Rust-only decrypted-state ownership and the proven `lock`/`lock_all` invalidation semantics.**",
        "Status: **Phase 0 in progress; the defined KDBX accepted/adversarial corpus gate, opaque generation-checked handle registry, Fortress credential boundary, initial engine-owned secret-memory/zeroization gate, concrete Rust vault-owner lifecycle, and non-secret Rust/JNI capability boundary are complete. The stable handle/API parent remains open until an executable Android/Kotlin caller and bounded vault-lifecycle JNI operations are proven. The next security-critical tranche is the real Android/Kotlin load-and-call smoke test while preserving Rust-only decrypted-state ownership and the proven `lock`/`lock_all` invalidation semantics.**",
    ),
    (
        "- The first stable-handle tranche provides a positive 63-bit FFI-safe opaque `VaultHandle` and an internal bounded generation-checked registry. Handles are not pointers, raw values are redacted from `Debug`, lock/lock-all immediately drop Rust-owned values, stale handles cannot revive after slot reuse, generation exhaustion retires a slot rather than wrapping, and capacity is explicit. The registry is intentionally not yet wired to KDBX-owned decrypted state or JNI.",
        "- The stable-handle foundation provides a positive 63-bit FFI-safe opaque `VaultHandle` and an internal bounded generation-checked registry. Handles are not pointers, raw values are redacted from `Debug`, lock/lock-all immediately drop Rust-owned values, stale handles cannot revive after slot reuse, generation exhaustion retires a slot rather than wrapping, and capacity is explicit. The registry is now wired to private Rust-owned KDBX `Database` sessions through `VaultCore`; it is intentionally not yet exposed through vault-lifecycle JNI operations.",
    ),
    (
        "  - [ ] Add the bounded Kotlin/JNI wrapper over `VaultCore` without exposing decrypted `Database` values, raw pointers, registry internals, or immutable JVM secret strings.",
        "  - [ ] Add the bounded Kotlin/JNI wrapper over `VaultCore` without exposing decrypted `Database` values, raw pointers, registry internals, or immutable JVM secret strings.\n    - [x] Establish a dedicated `rust/android-jni` non-secret Capability/ABI smoke boundary. The adapter pins `jni = 0.22.4` with default features disabled, has deterministic packed status/value responses, contains Rust panics before the boundary, limits the smoke crate to the `jni` and local `vault-core` dependencies, and keeps `vault-core` JNI/Android-free.\n    - [x] Prove the Rust/JNI smoke library mechanically: host `cdylib` build, exact exported JNI symbol check, full fmt/clippy/test matrix, Android ARM64/x86_64 cross-target checks, KeePassXC reopen and KeePass/KPScript interoperability all pass.\n    - [ ] Add an executable Android/Kotlin smoke caller that loads the native library and validates capability/status decoding on Android. ADR 0002 remains unaccepted until this runtime boundary is proven.\n    - [ ] Only after the Android/Kotlin smoke caller passes, extend the adapter to bounded `open`/`lock`/`is-valid` lifecycle operations using byte-oriented credentials, opaque handles and sanitized stable errors.",
    ),
    (
        "- [ ] Extend the JNI contract beyond the smoke boundary only after engine selection, parser limits and error semantics are proven.",
        "- [ ] Extend the JNI contract beyond the proven non-secret smoke boundary only after the executable Android/Kotlin caller passes; engine selection, parser limits, owner lifecycle and error semantics are already proven prerequisites.",
    ),
    (
        "## Next prioritized work\n\n1. [ ] Add the Kotlin/JNI wrapper over the proven `VaultCore` owner, beginning with bounded open/lock/is-valid operations, byte-oriented credentials, opaque positive handles and stable sanitized errors.\n2. [ ] Prove JNI panic containment, invalid/stale-handle behavior and Android lifecycle lock paths without allowing decrypted database ownership to escape Rust.\n3. [ ] Expand lifecycle/concurrency/property/fuzz coverage before adding metadata/secret retrieval or mutation APIs.",
        "## Next prioritized work\n\n1. [ ] Add the executable Android/Kotlin smoke caller for `NativeBridge.nativeCapabilityProbe`, load the produced native library on Android, and prove capability/status decoding without secrets or vault ownership crossing JNI.\n2. [ ] After that runtime smoke gate passes, extend the JNI adapter over the proven `VaultCore` owner with bounded open/lock/is-valid operations, byte-oriented credentials, opaque positive handles and stable sanitized errors.\n3. [ ] Prove JNI panic containment, invalid/stale-handle behavior and Android lifecycle lock paths without allowing decrypted database ownership to escape Rust; then expand lifecycle/concurrency/property/fuzz coverage before metadata/secret retrieval or mutation APIs.",
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one roadmap match, got {count}: {old[:80]!r}")
    text = text.replace(old, new)

roadmap.write_text(text, encoding="utf-8")

adr = Path("docs/adr/0002-kotlin-rust-interop.md")
adr.write_text("""# ADR 0002 — Kotlin/Rust interop spike

Status: Partially implemented; Rust/JNI smoke boundary proven, executable Android/Kotlin acceptance pending

## Context

KDBX Fortress uses Kotlin for Android/platform integration and Rust for the isolated vault core. The boundary itself is security-sensitive and must remain small.

## Decision direction

Use a tiny dedicated Rust adapter crate for the Android ABI/JNI layer. `vault-core` itself remains platform-neutral and must not depend on Android or JNI crates.

The first tranche is implemented as `rust/android-jni` and exposes only non-secret capability/version data. The proven boundary has these properties:

- `jni` is pinned exactly to `0.22.4` with default features disabled and is confined to the adapter crate;
- `vault-core` remains free of Android/JNI dependencies and continues to forbid unsafe code;
- the adapter exposes one approved JNI symbol for `world.w3b.kdbxfortress.bridge.NativeBridge.nativeCapabilityProbe`;
- capability responses use a deterministic 64-bit status/value encoding and never return secret-bearing strings or Java-owned secret objects;
- Rust panics are contained and mapped to a stable sanitized status before they can cross the JNI boundary;
- source policy limits the smoke adapter to the `jni` and local `vault-core` dependencies and forbids networking and vault-lifecycle/credential APIs in this tranche;
- the adapter passes host `cdylib` construction plus exact exported-symbol verification;
- the workspace passes fmt, Clippy and tests, and the adapter compiles for Android ARM64 and x86_64 alongside the established KeePassXC and KeePass/KPScript interoperability gates.

## Acceptance still pending

This ADR is not yet accepted as the Android interop design until an executable Android/Kotlin smoke caller:

- loads the produced native library in an Android build/runtime;
- invokes `NativeBridge.nativeCapabilityProbe`;
- validates the packed status/value decoding for supported and unsupported requests;
- demonstrates deterministic failure behavior without secrets or decrypted vault ownership crossing JNI.

Only after that runtime gate passes may the adapter grow to bounded vault lifecycle calls such as open/lock/is-valid. Credential transport must remain byte-oriented and short-lived; immutable JVM `String` values are not an acceptable normal secret boundary.

## Rejected for the core

Direct JNI annotations or Android bindings inside `vault-core` are rejected because they would merge the platform boundary with the highest-trust vault code.
""", encoding="utf-8")

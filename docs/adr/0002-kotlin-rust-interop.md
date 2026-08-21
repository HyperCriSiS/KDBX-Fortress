# ADR 0002 — Kotlin/Rust interop spike

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

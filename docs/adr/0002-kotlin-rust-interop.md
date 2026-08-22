# ADR 0002 — Kotlin/Rust interop boundary

Status: Accepted for the Phase-1 baseline

## Context

KDBX Fortress uses Kotlin for Android/platform integration and Rust for the isolated vault core. The boundary itself is security-sensitive and must remain small. Decrypted KDBX database ownership must stay inside Rust; Kotlin may receive only deliberately bounded values and opaque process-local handles.

## Decision

Use a tiny dedicated Rust adapter crate for the Android ABI/JNI layer. `vault-core` itself remains platform-neutral and must not depend on Android or JNI crates.

The implemented boundary lives in `rust/android-jni` and currently uses adapter ABI v3. Its proven properties are:

- `jni` is pinned exactly to `0.22.4` with default features disabled and is confined to the adapter crate;
- `vault-core` remains free of Android/JNI dependencies and continues to forbid unsafe code;
- the adapter exports exactly five approved JNI symbols for `world.w3b.kdbxfortress.bridge.NativeBridge`: capability probe, bounded open, per-handle lock, global lock-all and handle-validity check;
- capability responses use deterministic status/value encoding; lifecycle calls use positive opaque 63-bit handles plus frozen sanitized negative status codes;
- password and key-file transport is byte-oriented, nullable where absence is semantically distinct from empty, explicitly size-bounded, and moved into Fortress zeroizing Rust owners as soon as it crosses JNI;
- immutable JVM `String` values are not an acceptable normal secret boundary;
- decrypted `Database` objects, registry slots/generations, native pointers and secret fields do not cross JNI;
- owner-operation panics are contained while the Rust owner mutex is held and fail closed by locking all live sessions; already-poisoned owner recovery also locks all sessions before service resumes;
- malformed and stale handles cannot affect a newly reused slot/generation;
- source and binary policy permit exactly the approved adapter surface and continue to forbid networking and additional unsafe paths;
- host `cdylib`, exact-symbol, fmt, Clippy, unit/integration, KeePassXC, KeePass/KPScript, Android ARM64/x86_64 and regular CodeQL gates pass on the implemented boundary.

## Android runtime evidence

The executable Android/Kotlin gate is complete:

- the Android build loads the Rust shared library and validates capability/status decoding;
- a deterministic real KDBX fixture proves Kotlin → JNI → Rust open/valid/lock/stale behavior;
- the ABI-v3 lifecycle gate keeps two real Rust-owned vault sessions live, waits for an app-private `READY` marker, sends the emulator Home key, and permits `PASS` only from `Activity.onStop()` after `lock-all` invalidates both handles;
- deterministic stress tests add 20,000 model-based handle-registry transitions, 100,000 raw-handle fuzz inputs and eight concurrent owner workers over real KDBX sessions without stale-handle revival or owner poisoning.

## Phase-1 constraint

This accepted interop design does **not** authorize an unbounded read surface. Phase 1 first creates the production Android modules and wires the already-proven native library. Metadata listing/search and explicit single-secret retrieval may be added only through narrowly scoped operations that preserve Rust-only database ownership, stable sanitized errors and explicit lock semantics. Mutation and persistence remain later gates.

## Rejected for the core

Direct JNI annotations or Android bindings inside `vault-core` are rejected because they would merge the platform boundary with the highest-trust vault code.

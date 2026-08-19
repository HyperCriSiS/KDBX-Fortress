# ADR 0002 — Kotlin/Rust interop spike

Status: Proposed; acceptance requires an executable Android spike

## Context

KDBX Fortress uses Kotlin for Android/platform integration and Rust for the isolated vault core. The boundary itself is security-sensitive and must remain small.

## Proposed direction

Use a tiny dedicated Rust adapter crate for the Android ABI/JNI layer. `vault-core` itself remains platform-neutral and must not depend on Android or JNI crates.

The first spike exposes only non-secret capability/version data. It must demonstrate:

- Android ARM64 and x86_64 builds;
- deterministic error mapping;
- no Android/JNI dependency entering `vault-core`;
- coarse-grained calls rather than getter-by-getter crossings;
- a clear future path for scoped secret release without long-lived plaintext copies in Kotlin.

## Rejected for the core

Direct JNI annotations or Android bindings inside `vault-core` are rejected because they would merge the platform boundary with the highest-trust vault code.

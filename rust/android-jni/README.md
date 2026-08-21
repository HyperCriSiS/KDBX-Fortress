# KDBX Fortress Android JNI adapter

This crate is the dedicated Android/JNI boundary required by ADR 0002. It remains separate from `vault-core` so Android/JNI dependencies never enter the highest-trust platform-neutral crate.

## Current contract

Adapter ABI 2 exposes exactly four native methods for `world.w3b.kdbxfortress.bridge.NativeBridge`:

```text
private static native long nativeCapabilityProbe(int request)
private static native long nativeOpenVault(byte[] kdbx, byte[]? password, byte[]? keyfile)
private static native int nativeLockVault(long handle)
private static native int nativeIsVaultHandleValid(long handle)
```

The capability probe keeps its ABI-1 packed response format. The lifecycle boundary adds only `open`, `lock`, and `is-valid`:

- successful opens return a positive, opaque process-local `long` handle;
- open failures return stable negative lifecycle codes;
- lock returns `0` on success and a negative stable code on failure;
- is-valid returns `1` for live, `0` for invalid/stale, and a negative code only for an internal adapter failure.

No error text from the KDBX engine is copied into Kotlin.

## Bounded ingress

The adapter owns one process-local Rust `VaultCore` with an explicit maximum of four simultaneously unlocked vaults. Before copying Java arrays into Rust it enforces:

- the existing Fortress KDBX input ceiling;
- password bytes: at most 4 KiB;
- key-file bytes: at most 1 MiB.

Nullable password/key-file arrays preserve the distinction between no credential component and an explicitly empty byte array. Java/Kotlin strings are not accepted by the JNI lifecycle API.

Credential vectors are moved into `VaultCredentials` immediately after JNI conversion so Rust-owned copies are zeroized on normal drop paths. A poisoned owner mutex fails closed by locking all retained vaults before the adapter resumes service.

## Security boundary

The adapter still exposes no decrypted database snapshot, entry fields, search, mutation, persistence, networking, logging, raw pointers, or secret-returning operation. `vault-core` remains JNI/Android-free and continues to forbid unsafe code. Handles are process-local capabilities and must not be logged, persisted, or placed in intents/bundles.

The Android runtime smoke app now exercises both the capability probe and a real fixture `open → is-valid → lock → stale` lifecycle round trip on an emulator.

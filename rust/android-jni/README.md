# KDBX Fortress Android JNI adapter

This crate is the dedicated Android/JNI boundary required by ADR 0002. It is deliberately separate from `vault-core` so Android/JNI dependencies never enter the highest-trust platform-neutral crate.

## Current smoke contract

The first tranche exposes exactly one non-secret native method for the future Kotlin class `world.w3b.kdbxfortress.bridge.NativeBridge`:

```text
private static native long nativeCapabilityProbe(int request)
```

Requests:

- `1` — vault-core ABI version;
- `2` — Android/JNI adapter ABI version.

The 64-bit response is deterministic and contains no strings or heap-owned Java objects:

- upper 32 bits — stable adapter status code (`0` success, `1` unsupported request, `2` contained panic);
- lower 32 bits — unsigned capability value on success, otherwise zero.

The entry point catches Rust panics before the JNI boundary. This capability probe does not dereference JNI objects or invoke Java APIs.

## Security boundary

This crate currently has **no** API for passwords, keyfiles, vault bytes, `VaultCore`, handles, decrypted database state, entry fields, mutation, persistence, networking, or logging. `vault-core` remains JNI/Android-free and continues to forbid unsafe code.

The next interop tranche must first prove this shared library from a real Android/Kotlin smoke caller before adding any vault lifecycle operation.

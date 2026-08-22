# Android application modules

The Android build now contains the first production Phase-1 foundation while preserving the already-proven Kotlin/JNI/Rust security boundary.

## Modules

- `:app` is the production Android application module. It currently provides only a deliberately minimal launcher shell, verifies the native ABI/capability boundary on startup, and invokes the existing bounded Rust `lock-all` lifecycle operation when the Activity is backgrounded. It does not yet expose vault metadata, secret retrieval, mutation, persistence, networking, telemetry or Autofill.
- `:native-bridge` is the single Android/Kotlin owner of `world.w3b.kdbxfortress.bridge.NativeBridge`. Both applications depend on this module, preventing the production and test callers from drifting onto different JNI class definitions.
- `:smoke-app` remains a CI-only runtime/lifecycle probe. It opens two deterministic fixture vaults, keeps only opaque handles in Kotlin, waits for an app-private `READY` marker, and reports `PASS` only after a real foreground → background transition causes Rust `lock-all` to invalidate both sessions.

All modules use the Phase-1 platform baseline (`minSdk 26`, `compileSdk 37`; application modules target SDK 37) and Android Gradle Plugin built-in Kotlin support.

## Native library wiring

CI cross-builds `kdbx-fortress-android-jni` and stages the generated `.so` under `:native-bridge`. The Android gate then:

1. assembles both the production and smoke APKs;
2. verifies mechanically that the production APK contains `lib/<abi>/libkdbx_fortress_android_jni.so`;
3. launches the smoke application on an emulator and exercises the same shared `NativeBridge` through Kotlin → JNI → Rust.

The bridge is still ABI v3 and exports only the five approved lifecycle functions: capability probe, bounded open, per-handle lock, global lock-all and handle-validity check. No broader read API is authorized by this module split.

The fixture password used by `:smoke-app` is deterministic test data, not a production credential. Temporary fixture password/KDBX byte arrays are cleared after use, while decrypted database ownership remains inside Rust.

# Android runtime smoke project

This directory is a deliberately minimal CI-only Android application used to prove ADR 0002's Kotlin/Rust runtime and lifecycle boundary before the production Android application or any metadata/secret-returning JNI API is introduced.

The smoke app:

- targets the pinned Android SDK configuration used by CI (`minSdk 26`, `compileSdk 37`, `targetSdk 37`);
- uses the Android Gradle Plugin's built-in Kotlin support;
- packages the Rust `kdbx-fortress-android-jni` shared library and loads it through `System.loadLibrary`;
- verifies non-secret capability/status decoding and malformed-handle behavior through Kotlin → JNI → Rust;
- opens two deterministic test-fixture KDBX vaults with byte-oriented fixture credentials while decrypted database ownership remains entirely inside Rust;
- writes an app-private `READY` marker only after both opaque handles are confirmed live;
- lets the external emulator harness send the Home key, and writes `PASS` only from `Activity.onStop()` after the bounded Rust `lock-all` operation invalidates both live handles;
- clears the temporary Kotlin KDBX/password byte arrays after the fixture opens complete.

The fixture password is deterministic test data, not a production credential.

This module is **not** the production Android application skeleton. It intentionally exposes no metadata listing, secret retrieval, mutation, persistence, networking, telemetry or Autofill API.

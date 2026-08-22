# ADR 0001 — Android platform baseline

Status: Accepted and verified for the Phase-1 baseline

## Decision

- `minSdk`: 26
- `compileSdk`: 37
- `targetSdk`: 37

## Rationale

Android Autofill begins at API 26, which is a core product requirement. Supporting older Android versions would add compatibility work without providing the native Autofill path the application is being designed around.

`compileSdk` and `targetSdk` follow the Phase-1 Android platform baseline. The production `:app`, shared `:native-bridge` and CI-only `:smoke-app` modules now build against this baseline in CI; both application modules target SDK 37 and the shared library preserves `minSdk 26`.

## Consequences

- API-26 Autofill is available throughout the supported range.
- Newer Credential Manager provider features remain capability-gated by Android version.
- Platform-specific behavior is kept in Kotlin Android adapters, not in the Rust vault core.

# ADR 0001 — Android platform baseline

Status: Accepted for the Phase-1 baseline

## Decision

- `minSdk`: 26
- `compileSdk`: 37
- `targetSdk`: 37

## Rationale

Android Autofill begins at API 26, which is a core product requirement. Supporting older Android versions would add compatibility work without providing the native Autofill path the application is being designed around.

`compileSdk` and `targetSdk` follow the current Android platform baseline selected for the first build skeleton and must be re-verified when the Android project is created.

## Consequences

- API-26 Autofill is available throughout the supported range.
- Newer Credential Manager provider features remain capability-gated by Android version.
- Platform-specific behavior is kept in Kotlin Android adapters, not in the Rust vault core.

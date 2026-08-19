# KDBX Fortress — Repository Instructions

Follow the global Codex instructions first.

## Project priorities

- Security, data integrity, KDBX compatibility, and recoverability take precedence over convenience.
- Preserve compatibility with established KeePass/KDBX behavior unless the roadmap explicitly introduces an extension.
- The Android application is Kotlin-based; vault/security-critical core work is isolated in Rust. Keep the Kotlin/Rust boundary narrow and explicit.
- Do not move cryptographic or vault-critical logic into UI/application layers for convenience.
- Treat parsing, serialization, key derivation, memory handling, autofill, URL matching, clipboard handling, storage, migrations, imports/exports, and credential exposure as security-sensitive.

## Change rules

- Do not invent custom cryptography for normal KDBX compatibility.
- Prefer established algorithms and formats already supported by the project.
- Any future project-specific multi-cipher extension must remain isolated from standard KDBX compatibility and must not silently produce files that ordinary KeePass clients are expected to read.
- Add regression tests for format compatibility, migrations, malformed input, and security-sensitive bugs when practical.
- Preserve test fixtures unless deliberately updating a fixture with a documented reason.

## Repository workflow

- Read `README.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `NOTICE`, relevant files under `docs/`, `rust-toolchain.toml`, and build/test tooling before substantial changes.
- Keep `ROADMAP.md` synchronized with verified progress.
- For security-sensitive changes, prefer a focused branch and focused PR.

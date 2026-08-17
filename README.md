# KDBX Fortress

KDBX Fortress is a security-first Android password manager compatible with KeePass/KDBX databases.

The project is a Greenfield implementation focused on reliable Android Autofill, strict credential-target verification, explicit persistence, and a small trusted core.

## Architecture

- **Kotlin** for Android UI and platform integration: Autofill, Credential Manager, IME fallback, lifecycle, Biometric/Keystore, storage, and optional sync.
- **Rust** for the isolated vault core: KDBX parsing/writing, cryptographic orchestration, secret handling, resource limits, merge logic, and vault session state.
- The normal credential fill path is read-only. Persistent associations are explicit operations.
- The core credential path has no network access; networking is isolated to optional sync components.

## Status

Early foundation development. No stable release is available yet.

See [ROADMAP.md](ROADMAP.md) for the current implementation plan.

## License and project identity

The source code is licensed under the **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`). See [LICENSE](LICENSE).

The source-code license does not grant permission to use the **KDBX Fortress** name, official logo, or project branding in a way that implies an official release or endorsement. See [TRADEMARKS.md](TRADEMARKS.md). The term **KDBX** itself is used descriptively for the KeePass database format; this project does not claim exclusive rights to `KDBX` alone.

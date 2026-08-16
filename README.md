# KDBX Bastion

KDBX Bastion is a security-first Android password manager compatible with KeePass/KDBX databases.

The project is a Greenfield implementation focused on reliable Android Autofill, strict credential-target verification, explicit persistence, and a small trusted core.

## Architecture

- **Kotlin** for Android UI and platform integration: Autofill, Credential Manager, IME fallback, lifecycle, Biometric/Keystore, storage, and optional sync.
- **Rust** for the isolated vault core: KDBX parsing/writing, cryptographic orchestration, secret handling, resource limits, merge logic, and vault session state.
- The normal credential fill path is read-only. Persistent associations are explicit operations.
- The core credential path has no network access; networking is isolated to optional sync components.

## Status

Early foundation development. No stable release is available yet.

See [Roadmap.md](Roadmap.md) for the current implementation plan.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).

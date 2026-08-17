# Crypto-agility policy

KDBX Bastion treats standard KDBX interoperability as a hard compatibility boundary. Cryptographic agility may add stronger implementation choices, but it must not silently create a database format that standard KeePass/KDBX implementations cannot read.

## Baseline rules

- Standard KDBX encryption, KDF and integrity primitives remain the default storage format.
- The core must select algorithms from explicit, versioned identifiers and must reject unknown or malformed parameters rather than guessing.
- Algorithm implementations remain behind narrow vault-core interfaces so a primitive can be replaced without changing Android/UI code or exposing key material across the FFI boundary.
- Write support must preserve all supported KDBX parameters on round-trip unless the user explicitly requests a compatible migration.
- Deprecated or weak-but-valid legacy choices may be readable for interoperability, while creation of new vaults can use stronger standard KDBX defaults.

## Optional stronger protection

Any future post-quantum or hybrid protection must be additive and opt-in. It must not masquerade as ordinary KDBX or overwrite the only interoperable copy of a vault with a private extension.

Acceptable designs include a separately versioned envelope or sidecar only after its threat model, recovery semantics, downgrade behavior and interoperability impact are documented. The normal `.kdbx` payload must remain recoverable through the documented compatibility path.

No algorithm may be described as post-quantum secure merely because it is new or non-standard. Such claims require a standardized primitive, a documented security model and an implementation/review path appropriate for secret-storage software.

## Migration and downgrade behavior

- Cryptographic migrations are explicit user operations and must be atomic.
- Before replacing a vault, the new artifact must reopen successfully with the intended credentials and pass integrity checks.
- A failed migration leaves the prior valid vault untouched.
- Importing a vault with stronger/unknown parameters must never silently downgrade it on save.
- Export to a compatibility profile must clearly state which protections or metadata cannot be represented.

## Testing gates

Before a new cryptographic configuration is enabled for writes, the project must have deterministic fixtures for read, write, reopen and independent interoperability where an external implementation exists. Negative tests must cover malformed headers/parameters, authentication failure, excessive resource requests and unsupported algorithm identifiers.

Security-sensitive algorithm or format changes require explicit review and cannot be justified solely by benchmark improvements.

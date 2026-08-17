# Crypto-agility policy

KDBX Fortress treats standard KDBX interoperability as a hard compatibility boundary. Cryptographic agility may add stronger implementation choices, but it must not silently create a database format that standard KeePass/KDBX implementations cannot read.

## Baseline rules

- Standard KDBX encryption, KDF and integrity primitives remain the default storage format.
- The core must select algorithms from explicit, versioned identifiers and must reject unknown or malformed parameters rather than guessing.
- Algorithm implementations remain behind narrow vault-core interfaces so a primitive can be replaced without changing Android/UI code or exposing key material across the FFI boundary.
- Write support must preserve all supported KDBX parameters on round-trip unless the user explicitly requests a compatible migration.
- Deprecated or weak-but-valid legacy choices may be readable for interoperability, while creation of new vaults can use stronger standard KDBX defaults.

## MultiCipher compatibility module

KDBX Fortress may provide an optional, separately isolated `MultiCipher` module for compatibility with the established KeePass Desktop MultiCipher plugin. This is a compatibility feature, not a Fortress-specific cryptographic format.

The current official KeePass plugin catalog describes MultiCipher as using two ciphers for one database and lists AES-256, 3DES-192, ChaCha20 and Salsa20 as supported ciphers. The plugin's own documentation describes two independent keys and a dual-stream construction. Fortress must not infer compatibility from those summaries alone: the exact on-disk format and key-handling behavior must be verified against the plugin source and independent KeePass Desktop read/write tests before implementation is enabled.

Rules for the Fortress MultiCipher module:

- Support only combinations and key modes that are proven interoperable with KeePass Desktop + the established MultiCipher plugin.
- Do not add Fortress-only algorithms, cipher pairings, headers or envelopes under the MultiCipher compatibility label.
- Keep ordinary single-cipher standard KDBX as the default.
- Treat MultiCipher as an explicit opt-in compatibility profile with a strong warning that ordinary KeePass/KDBX clients may not be able to open the resulting database without corresponding plugin support.
- Keep MultiCipher parsing/writing isolated from the standard KDBX path so optional compatibility code cannot silently alter normal vault semantics.
- Before enabling writes, maintain deterministic fixtures for every supported pairing/key mode and verify read, write, reopen and round-trip behavior against KeePass Desktop + MultiCipher.
- Provide an explicit export/migration operation back to ordinary standard-KDBX encryption. The source vault must remain untouched until the standard-KDBX export reopens successfully and passes integrity verification.
- Unknown MultiCipher versions, algorithms, identifiers or metadata must fail closed rather than being approximated or downgraded.

## Other non-standard cryptography

No Fortress-proprietary multi-cipher database format is planned. If a future cryptographic extension outside standard KDBX or established KeePass plugin interoperability is ever considered, it requires a separate architecture/security decision, threat model and migration design before it can enter the roadmap.

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

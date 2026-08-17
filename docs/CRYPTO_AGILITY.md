# Crypto-agility policy

KDBX Fortress treats standard KDBX interoperability as the default compatibility boundary. Ordinary vaults must remain readable by normal KeePass/KDBX implementations.

KDBX Fortress may later offer a separate opt-in `MultiCipher` profile that intentionally goes beyond standard KDBX interoperability. This is a Fortress-defined extension and must never be enabled silently.

## Baseline rules

- Standard KDBX encryption, KDF and integrity primitives remain the default storage format.
- The core must select algorithms from explicit, versioned identifiers and must reject unknown or malformed parameters rather than guessing.
- Algorithm implementations remain behind narrow vault-core interfaces so a primitive can be replaced without changing Android/UI code or exposing key material across the FFI boundary.
- Write support must preserve all supported standard-KDBX parameters on round-trip unless the user explicitly requests a migration.
- Deprecated or weak-but-valid legacy choices may be readable for interoperability, while creation of new standard vaults can use stronger standard KDBX defaults.

## Fortress MultiCipher module

KDBX Fortress may provide an optional, separately isolated `MultiCipher` module that combines multiple established cryptographic primitives in one Fortress-specific protection profile.

This module is not required to be readable by ordinary KeePass, KeePassXC, KeePassDX or other standard KDBX clients. The UI must state this clearly before creating or converting a vault.

The intent is to combine existing, well-studied primitives rather than invent new ciphers. However, the composition itself is a cryptographic protocol and must be treated as security-sensitive design work rather than as a trivial wrapper.

### Construction requirements

Before implementation is enabled, the Fortress MultiCipher format must specify and test at least:

- the exact cipher cascade/construction and processing order;
- supported algorithms and algorithm identifiers;
- versioning and forward/backward compatibility rules;
- domain-separated derivation of independent keys for each cipher layer;
- KDF/key-splitting behavior and how it relates to the ordinary KDBX master-key derivation path;
- independent nonce/IV generation, storage and uniqueness requirements for each layer;
- authenticated metadata covering format version, algorithm selection/order and all parameters relevant to decryption;
- integrity/authentication ordering and failure semantics;
- resistance to algorithm-substitution and downgrade attacks;
- bounded resource requirements for malformed/untrusted inputs;
- atomic migration/export behavior and corruption recovery.

A single raw encryption key must not simply be reused across several algorithms. Where one master secret feeds multiple cryptographic roles, each role/layer must receive independently derived, context-bound key material.

### Compatibility model

- Ordinary single-cipher standard KDBX remains the default.
- Fortress MultiCipher is an explicit opt-in profile.
- Vault creation/conversion must warn that normal KDBX clients will not be able to open the resulting database unless they implement the Fortress MultiCipher specification.
- The source standard-KDBX vault must not be destroyed or overwritten until a converted MultiCipher vault has reopened and passed integrity verification.
- Export back to ordinary standard KDBX must be supported and tested.
- Unknown Fortress MultiCipher versions, algorithms, identifiers or metadata must fail closed rather than being approximated or downgraded.

### Desktop implementation

The canonical format/specification and deterministic test vectors live with KDBX Fortress.

A separate dedicated desktop project may later implement the same Fortress MultiCipher format for desktop KeePass/KDBX workflows. That desktop implementation is a downstream compatibility target, not a prerequisite for defining or implementing the Android module.

The format must therefore be specified independently of Android/Kotlin/Rust implementation details so another implementation can reproduce it byte-for-byte from the public specification and test vectors.

## Other non-standard cryptography

No novel cryptographic primitive should be invented for Fortress MultiCipher. The project may compose established primitives, but any new construction requires explicit architecture/security review, threat-model updates and deterministic test vectors.

No algorithm or composition may be described as post-quantum secure merely because multiple ciphers are combined. Such claims require an appropriate security model and primitives whose relevant security properties support that claim.

## Migration and downgrade behavior

- Cryptographic migrations are explicit user operations and must be atomic.
- Before replacing a vault, the new artifact must reopen successfully with the intended credentials and pass integrity checks.
- A failed migration leaves the prior valid vault untouched.
- Importing a vault with stronger/unknown parameters must never silently downgrade it on save.
- Export to a compatibility profile must clearly state which protections or metadata cannot be represented.

## Testing gates

Before a Fortress MultiCipher configuration is enabled for writes, the project must have deterministic fixtures/test vectors for read, write, reopen, tamper detection, parameter substitution, downgrade attempts and malformed inputs.

When the future desktop implementation exists, bidirectional cross-implementation interoperability becomes an additional release gate.

Security-sensitive algorithm or format changes require explicit review and cannot be justified solely by benchmark improvements.

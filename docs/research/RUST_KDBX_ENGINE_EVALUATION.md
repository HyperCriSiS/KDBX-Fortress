# Rust KDBX engine evaluation

Status: Initial Phase-1 research; no dependency decision yet

## Repositories reviewed

- `sseemayer/keepass-rs`
- `ssrlive/keepass-ng`

## Main finding

The two repositories are closely related members of the same code family. Their directory layout, format/crypto/database modules, fixtures and many tests overlap strongly. They therefore must not be treated as two independent implementations for security validation.

## Useful capabilities observed

The code family contains support and tests around:

- KDB, KDBX3 and KDBX4 parsing;
- KDBX4 writing paths;
- AES/ChaCha20/Twofish combinations represented in fixtures;
- Argon2/Argon2id KDF handling;
- keyfiles and challenge-response/YubiKey-related paths;
- TOTP;
- merge behavior;
- malformed-file tests;
- KDBX 4.1 features;
- round-trip and KeePassXC writer compatibility tests.

## Current conclusion

Do not copy or adopt either engine yet. Before the KDBX implementation phase, compare:

1. direct reuse as a dependency;
2. a reviewed/hardened fork;
3. an independent KDBX orchestration layer using established Rust crypto crates while borrowing only test ideas and interoperability scenarios.

Any selected engine must additionally satisfy KDBX Bastion's hard resource-budget policy before attacker-controlled KDF, decompression, XML, attachment or image work is performed.

Independent interoperability validation must include KeePass/KeePassXC and other implementations, not only these two related Rust repositories.

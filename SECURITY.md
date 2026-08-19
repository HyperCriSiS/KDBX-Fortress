# Security Policy

KDBX Fortress is security-sensitive software. Report suspected vulnerabilities privately through the channel below. Do not publish an exploitable vulnerability, proof-of-concept containing real secrets, or credential database data in a public issue.

## Current project status

KDBX Fortress is in early architecture/foundation development and has no stable release yet.

## Reporting a vulnerability

GitHub Private Vulnerability Reporting is enabled for this repository. Submit suspected exploitable vulnerabilities through [Report a vulnerability](https://github.com/HyperCriSiS/KDBX-Fortress/security/advisories/new).

- do not post live credentials, master passwords, private keys, TOTP seeds, cookies, tokens, or real vault files publicly;
- keep reproductions minimal and use synthetic data; and
- include only the information needed to reproduce and assess the issue.

## Scope of security review

High-priority classes include:

- credential release to the wrong app/origin;
- signing-certificate/origin verification bypass;
- master/session key exposure;
- plaintext secret logging or IPC/navigation transport;
- KDBX parser/KDF resource exhaustion;
- vault corruption/data loss;
- Android Keystore/biometric authorization bypass;
- unintended exported component access;
- sync/network module access to decrypted vault data;
- malicious dependency/build/release compromise.

## Security design documents

The current threat, boundary and compatibility model lives in:

- `docs/THREAT_MODEL.md`
- `docs/VAULT_CORE_API.md`
- `docs/KDBX_COMPATIBILITY_MATRIX.md`
- `docs/FIXTURE_PROVENANCE.md`
- `docs/adr/0002-kotlin-rust-interop.md`

These documents are part of the security boundary and should change with the implementation when assumptions change.

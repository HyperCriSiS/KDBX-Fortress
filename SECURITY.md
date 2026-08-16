# Security Policy

KDBX Bastion is security-sensitive software. Please do not publish an exploitable vulnerability, proof-of-concept containing real secrets, or credential database data in a public issue before a coordinated disclosure path is available.

## Current project status

KDBX Bastion is in early architecture/foundation development and has no stable release yet.

## Reporting a vulnerability

Until a dedicated private security-reporting channel is configured on the final GitHub repository:

- do not post live credentials, master passwords, private keys, TOTP seeds, cookies, tokens, or real vault files publicly;
- keep reproductions minimal and use synthetic data;
- once GitHub Private Vulnerability Reporting is enabled, use that mechanism for suspected exploitable security issues.

The final repository must update this section with the exact private reporting method before the first public alpha/beta.

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

The current threat and invariant model lives in:

- `THREAT_MODEL.md`
- `SECURITY_INVARIANTS.md`
- `MODULE_BOUNDARIES.md`
- `ANDROID_CREDENTIAL_ARCHITECTURE.md`

These documents are part of the security boundary and should change with the implementation when assumptions change.

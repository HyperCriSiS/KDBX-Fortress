# KDBX interoperability fixtures

This directory contains synthetic databases used only for compatibility tests. They contain no real credentials.

`manifest.json` records the fixture password, expected logical content and immutable SHA-256 digest. The first fixture is a minimal KDBX4 password-only database; later fixtures extend the matrix to KDBX3, keyfiles, Argon2id/AES-KDF, ChaCha20, attachments, history, Unicode and negative/adversarial cases.

Validate the corpus with:

```bash
python tools/validate_kdbx_fixtures.py
```

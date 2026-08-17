# KDBX interoperability fixtures

This directory contains synthetic databases used only for compatibility tests. They contain no real credentials.

`manifest.json` records the fixture password, expected logical content and immutable SHA-256 digest. The first fixture is a minimal KDBX4 password-only database; later fixtures extend the matrix to KDBX3, keyfiles, Argon2id/AES-KDF, ChaCha20, attachments, history, Unicode and negative/adversarial cases.

Validate the corpus with:

```bash
python tools/validate_kdbx_fixtures.py
```

`unicode-kdbx4.kdbx` exercises Unicode round-tripping across group, title, username, password, URL and notes.

- `truncated-header-kdbx4.kdbx`: deterministic negative fixture containing only the first 8 bytes of the basic KDBX4 file; future vault engines must reject it as a truncated header without panic.

- `bad-signature-kdbx4.kdbx`: deterministic negative fixture derived from the basic KDBX4 fixture with the first signature byte corrupted; future vault engines must reject it as an invalid KDBX signature without panic.

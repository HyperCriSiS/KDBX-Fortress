# KDBX interoperability fixtures

This directory contains synthetic databases used only for compatibility tests. They contain no real credentials.

`manifest.json` records the fixture password, expected logical content and immutable SHA-256 digest. The first fixture is a minimal KDBX4 password-only database; later fixtures extend the matrix to KDBX3, keyfiles, Argon2id/AES-KDF, ChaCha20, attachments, history, Unicode and negative/adversarial cases.

Validate the corpus with:

```bash
python tools/validate_kdbx_fixtures.py
```

`unicode-kdbx4.kdbx` exercises Unicode round-tripping across group, title, username, password, URL and notes.

`kdbx3-aes-aeskdf-basic.kdbx.b64` is the canonical text representation of a deterministic synthetic KDBX 3.1 database. The validator Base64-decodes it first and verifies the manifest SHA-256 against the materialized KDBX bytes. It covers AES-KDF (6,000 rounds), AES-256-CBC, a Salsa20-protected password, notes and a custom field.

- `truncated-header-kdbx4.kdbx`: deterministic negative fixture containing only the first 8 bytes of the basic KDBX4 file; future vault engines must reject it as a truncated header without panic.

- `bad-signature-kdbx4.kdbx`: deterministic negative fixture derived from the basic KDBX4 fixture with the first signature byte corrupted; future vault engines must reject it as an invalid KDBX signature without panic.

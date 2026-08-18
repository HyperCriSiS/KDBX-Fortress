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

`kdbx4-argon2id-aes.kdbx.b64` deterministically re-wraps the already validated synthetic KDBX4 inner payload with Argon2id and AES-256-CBC outer encryption. The manifest SHA-256 applies to the decoded KDBX bytes, and the Rust compatibility test verifies both the KDF/cipher configuration and expected credential fields.

`kdbx4-argon2id-chacha20.kdbx.b64` deterministically re-wraps the already validated synthetic KDBX4 inner payload with Argon2id and ChaCha20 outer encryption. The manifest SHA-256 applies to the decoded KDBX bytes, and the Rust compatibility test verifies both the KDF/cipher configuration and expected credential fields.

`kdbx4-attachments-custom-data.kdbx.b64` extends the Argon2id/AES synthetic corpus with two KDBX4 binary-pool attachments: one unprotected text attachment and one protected binary attachment. Its executable Rust test verifies exact attachment names/bytes, preservation of the protected/unprotected state, and `CustomData` at database, group and entry levels.

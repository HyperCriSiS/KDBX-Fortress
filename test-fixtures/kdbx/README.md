# KDBX interoperability fixtures

This directory contains synthetic databases used only for compatibility tests. They contain no real credentials.

`manifest.json` records each fixture password, expected logical content, provenance and immutable SHA-256 digest. The corpus combines deterministic project-generated cases with independently generated KeePass reference fixtures and extends the matrix across KDBX3/KDBX4, keyfiles, Argon2d/Argon2id/AES-KDF, AES/ChaCha20, attachments, history, Unicode, empty/optional-value edges, bounded-large inputs and negative/adversarial cases.

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

`kdbx4-composite-key-keyfile.kdbx.b64` requires both the fixture password and `kdbx4-composite-key.raw32.key`. The sidecar is an exact 32-byte raw KeePass keyfile; the validator checks its size and SHA-256 independently. The Rust compatibility test proves the correct composite key opens the database and rejects missing/wrong password or missing/wrong keyfile combinations. Raw-32 is used deliberately for this first keyfile gate because the pinned `keepass = 0.13.18` XML-v2 keyfile parser does not validate the XML `Hash` attribute.

`kdbx4-empty-edge.kdbx.b64` is an independently materialized KeePass 2.61.1/KPScript/KeePassLib KDBX 4.0 fixture. It preserves the template's empty `Synthetic` group and adds `Blank Fields` with empty optional values. The Rust corpus test accepts either omitted or explicitly empty optional fields and rejects invented non-empty values.

`kdbx4-large-bounded.kdbx.b64` is an independently materialized KeePass 2.61.1/KeePassLib KDBX 4.0 fixture with a 65,536-byte `Notes` value and a deterministic 262,144-byte `payload.bin` attachment (`byte[i] = i mod 256`). Its Rust tests verify exact content, accept the fixture at the exact configured field/attachment ceilings, and require typed rejection when those ceilings are lowered by one byte.

# KDBX interoperability fixtures

This directory contains synthetic databases used only for compatibility tests. They contain no real credentials.

`manifest.json` records fixture credentials, expected logical content, immutable SHA-256 digests, provenance evidence, known provenance gaps and exact negative-fixture derivations. The current corpus covers KDBX3, keyfiles, Argon2d/Argon2id, AES-KDF, AES-256-CBC, ChaCha20, attachments, CustomData, Unicode and two header-level negative cases; history coverage remains open.

Validate the corpus with:

```bash
python tools/validate_kdbx_fixtures.py
```

`unicode-kdbx4.kdbx` exercises Unicode preservation on the current Rust read path across group, title, username, password, URL and notes. Fortress write support is disabled, so this is not a Fortress round-trip fixture.

`kdbx3-aes-aeskdf-basic.kdbx.b64` is the canonical text representation of a committed synthetic KDBX 3.1 database. The validator Base64-decodes it first and verifies the manifest SHA-256 against the materialized KDBX bytes. It covers AES-KDF (6,000 rounds), AES-256-CBC, a Salsa20-protected password, notes and a custom field; its generator and independent oracle are not yet recorded.

- `truncated-header-kdbx4.kdbx`: deterministic negative fixture containing only the first 8 bytes of the basic KDBX4 file; future vault engines must reject it as a truncated header without panic.

- `bad-signature-kdbx4.kdbx`: deterministic negative fixture derived from the basic KDBX4 fixture with the first signature byte corrupted; future vault engines must reject it as an invalid KDBX signature without panic.

`kdbx4-argon2id-aes.kdbx.b64` is a committed synthetic KDBX4 fixture using Argon2id and AES-256-CBC outer encryption. The manifest SHA-256 applies to the decoded KDBX bytes, and the Rust compatibility test verifies both the KDF/cipher configuration and expected credential fields.

`kdbx4-argon2id-chacha20.kdbx.b64` is a committed synthetic KDBX4 fixture using Argon2id and ChaCha20 outer encryption. The manifest SHA-256 applies to the decoded KDBX bytes, and the Rust compatibility test verifies both the KDF/cipher configuration and expected credential fields.

`kdbx4-attachments-custom-data.kdbx.b64` extends the Argon2id/AES synthetic corpus with two KDBX4 binary-pool attachments: one unprotected text attachment and one protected binary attachment. Its executable Rust test verifies exact attachment names/bytes, preservation of the protected/unprotected state, and `CustomData` at database, group and entry levels.

`kdbx4-composite-key-keyfile.kdbx.b64` requires both the fixture password and `kdbx4-composite-key.raw32.key`. The sidecar is an exact 32-byte raw KeePass keyfile; the validator checks its size and SHA-256 independently. The Rust compatibility test proves the correct composite key opens the database and rejects missing/wrong password or missing/wrong keyfile combinations. Raw-32 is used deliberately for this first keyfile gate because the pinned `keepass = 0.13.18` XML-v2 keyfile parser does not validate the XML `Hash` attribute.

## Provenance status

The manifest records provenance separately from byte-integrity and read-test status. Every current entry is explicitly marked `incomplete`: fixed hashes and successful Rust reads do not by themselves prove reproducible generation, an independent reader oracle or Fortress write round-tripping.

The historical generator workflows for `basic-kdbx4.kdbx` and `unicode-kdbx4.kdbx` used an unpinned PyKeePass installation. The Unicode workflow reopened its output with PyKeePass itself, which is a same-implementation check rather than an independent oracle. Generator artifacts or versions were not retained for the other positive fixtures; their introduction commits are recorded as evidence without inferring missing provenance.

The two negative fixtures have exact machine-checked derivations in `manifest.json`: the truncated file is the first eight bytes of `basic-kdbx4.kdbx`, and the invalid-signature file XORs byte zero with `0xff`. Their independent rejection-oracle evidence is still open.

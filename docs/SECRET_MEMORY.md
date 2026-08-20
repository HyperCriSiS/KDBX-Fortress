# Secret Memory Hygiene

Status: Phase 0 security boundary. This document defines what KDBX Fortress can and cannot promise about secret bytes in process memory.

## Guarantees implemented at the Fortress boundary

- Password and key-file inputs owned by Fortress use `zeroize::Zeroizing<Vec<u8>>` through `SecretBytes`.
- `VaultCredentials` is deliberately non-`Clone` and its `Debug` output is redacted.
- The preferred bounded-open API accepts `&VaultCredentials`; password bytes are borrowed as UTF-8 only at the narrow conversion point instead of first becoming a Fortress-owned `String`.
- The temporary upstream `DatabaseKey` owns the unavoidable engine copy and is `Zeroize + ZeroizeOnDrop` in the pinned Fortress `keepass-rs` fork.
- Public Fortress errors never include password, key-file, engine error text, decrypted field content, or plaintext snippets.
- Future JNI code must transfer credential bytes into `SecretBytes` as early as possible and must not keep a second long-lived Kotlin/Java `String` representation.

## Fork hardening still required before decrypted vault state is attached to handles

The upstream engine already wipes `DatabaseKey`, and protected entry values use `secrecy::SecretBox`. The current pinned fork still creates additional owned sensitive temporaries during KDBX processing. Before `VaultHandle` owns a decrypted `Database`, the fork must additionally wipe or RAII-wrap, on success and error paths:

- key elements derived from password/key-file/challenge response;
- composite, transformed, master, HMAC and per-block HMAC keys;
- cipher-owned key copies where the RustCrypto type does not itself provide the required drop guarantee;
- decrypted, decompressed and serialized plaintext payload buffers;
- KDBX4 inner random-stream key material;
- unprotected entry/attachment values when their owning database is dropped.

`Database::get_xml` is a legacy plaintext-returning engine helper. Fortress production code must not expose or use it as an API boundary.

## Explicit non-guarantees

Zeroization is defense-in-depth, not a claim that plaintext never existed in RAM. KDBX Fortress cannot reliably erase copies that have already been made by the allocator, operating system, compiler transformations outside `zeroize` guarantees, debugger/root access, crash dumps, swap, hardware snapshots, or opaque scratch/state inside third-party cryptographic and parser implementations.

Hash/HMAC/Argon2, AES/Twofish/Salsa/ChaCha, XML parsing and decompression libraries can hold implementation-internal state. Their lifetime should be kept narrow and their own zeroization behavior audited separately; Fortress must not claim those hidden copies are erased unless the dependency provides such a guarantee.

## Lock invariant for the next lifecycle tranche

A future `VaultHandle::lock` may be treated as a security boundary only after the decrypted vault owner has been audited so dropping it destroys all Fortress/fork-owned sensitive buffers covered above. The existing handle registry already invalidates the handle and drops the owned Rust value immediately; this document deliberately does **not** yet claim that an entire parsed database is comprehensively wiped on lock.

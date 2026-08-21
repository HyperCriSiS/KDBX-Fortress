# Secret Memory Hygiene

Status: Phase 0 security boundary. This document defines what KDBX Fortress can and cannot promise about secret bytes in process memory.

## Guarantees implemented at the Fortress boundary

- Password and key-file inputs owned by Fortress use `zeroize::Zeroizing<Vec<u8>>` through `SecretBytes`.
- `VaultCredentials` is deliberately non-`Clone` and its `Debug` output is redacted.
- The preferred bounded-open API accepts `&VaultCredentials`; password bytes are borrowed as UTF-8 only at the narrow conversion point instead of first becoming a Fortress-owned `String`.
- The temporary upstream `DatabaseKey` owns the unavoidable engine copy and is `Zeroize + ZeroizeOnDrop` in the pinned Fortress `keepass-rs` fork.
- Public Fortress errors never include password, key-file, engine error text, decrypted field content, or plaintext snippets.
- Future JNI code must transfer credential bytes into `SecretBytes` as early as possible and must not keep a second long-lived Kotlin/Java `String` representation.

## Fork hardening now proven for the initial read-only owner boundary

The pinned Fortress `keepass-rs` fork at `bdf81aa77cafdf6651c0909d4dbcceb2a15ad227` completed the defined Phase-0 engine-owned memory-hygiene gate under its full CI matrix. In addition to `DatabaseKey` and protected values, the fork now:

- stores key elements derived from password/key-file/challenge response in zeroizing owners;
- moves transformed, master and KDBX4 HMAC keys into zeroizing byte owners immediately after the fixed-array hash/KDF API boundary;
- zeroizes generated per-block HMAC keys;
- zeroizes decrypted/compressed and decompressed KDBX3/KDBX4 plaintext scratch on success and error paths;
- zeroizes KDBX3 protected-stream and KDBX4 inner-random-stream raw key material;
- enables RustCrypto `zeroize` support for Salsa20 and ChaCha20 state;
- explicitly zeroizes unprotected entry/attachment values when their owning `Value` is dropped.

`Database::get_xml` remains a legacy plaintext-returning engine helper. Fortress production code must not expose or use it as an API boundary.

## Explicit non-guarantees

Zeroization is defense-in-depth, not a claim that plaintext never existed in RAM. KDBX Fortress cannot reliably erase copies that have already been made by the allocator, operating system, compiler transformations outside `zeroize` guarantees, debugger/root access, crash dumps, swap, hardware snapshots, or opaque scratch/state inside third-party cryptographic and parser implementations.

The current SHA/KDF helper APIs return short-lived `hybrid_array::Array` values that do not implement `Zeroize` in the pinned dependency combination. The fixed composite-key array and transient digest/KDF return arrays therefore cannot currently be proven wiped; Fortress moves their sensitive results into zeroizing owners immediately after those API boundaries. More generally, Hash/HMAC/Argon2, AES/Twofish, XML parsing and decompression libraries can retain implementation-internal state outside Fortress ownership. Fortress must not claim those hidden copies are erased unless the dependency itself provides that guarantee. Salsa20 and ChaCha20 are an exception in the pinned fork because their RustCrypto `zeroize` features are explicitly enabled.

## Lock invariant for the next lifecycle tranche

The engine-owned memory-hygiene prerequisites for attaching a decrypted database to the Rust handle registry are now satisfied for the defined initial read-only boundary. The next tranche must introduce a concrete Rust vault owner whose `Drop` path owns the parsed database and any Fortress-side session state, then prove that `VaultHandle::lock`/`lock_all` immediately destroy that owner while invalidating the generation-checked handle. This still does **not** imply total process-memory erasure because the explicit non-guarantees above remain in force.

use std::{
    io::Cursor,
    panic::{AssertUnwindSafe, catch_unwind},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{
    KdbxOpenError, KdbxOpenLimits, KdbxPostDecryptError, KdbxPostDecryptLimits, KdbxPreflightError,
    KdbxResourceLimits, open_kdbx_bounded, preflight_kdbx,
};
use keepass::{Database, DatabaseKey};

const FIXTURE_PASSWORD: &str = "fixture-password";
const KEYFILE: &[u8; 32] =
    include_bytes!("../../../test-fixtures/kdbx/kdbx4-composite-key.raw32.key");
const MANIFEST: &str = include_str!("../../../test-fixtures/kdbx/manifest.json");
const KDBX4_VERSION_HEADER_BYTES: usize = 12;
const KDBX4_CIPHER_FIELD_ID: u8 = 2;
const KDBX4_KDF_FIELD_ID: u8 = 11;
const ARGON2D_UUID: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];

#[derive(Clone, Copy)]
enum FixtureData {
    Raw(&'static [u8]),
    Base64(&'static str),
}

impl FixtureData {
    fn materialize(self) -> Vec<u8> {
        match self {
            Self::Raw(bytes) => bytes.to_vec(),
            Self::Base64(encoded) => STANDARD
                .decode(encoded.split_whitespace().collect::<String>())
                .expect("embedded fixture base64 must decode"),
        }
    }
}

#[derive(Clone, Copy)]
enum CredentialKind {
    Password,
    PasswordAndRaw32Keyfile,
}

#[derive(Clone, Copy)]
struct AcceptedCase {
    name: &'static str,
    data: FixtureData,
    credentials: CredentialKind,
    expected_major: u16,
    expected_minor: u16,
    expected_title: &'static str,
}

const ACCEPTED: &[AcceptedCase] = &[
    AcceptedCase {
        name: "kdbx3-aes-aeskdf-basic.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx3-aes-aeskdf-basic.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 3,
        expected_minor: 1,
        expected_title: "Legacy AES Login",
    },
    AcceptedCase {
        name: "basic-kdbx4.kdbx",
        data: FixtureData::Raw(include_bytes!(
            "../../../test-fixtures/kdbx/basic-kdbx4.kdbx"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Example Login",
    },
    AcceptedCase {
        name: "kdbx4-argon2id-aes.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Example Login",
    },
    AcceptedCase {
        name: "kdbx4-attachments-custom-data.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-attachments-custom-data.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Example Login",
    },
    AcceptedCase {
        name: "kdbx4-composite-key-keyfile.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-composite-key-keyfile.kdbx.b64"
        )),
        credentials: CredentialKind::PasswordAndRaw32Keyfile,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Example Login",
    },
    AcceptedCase {
        name: "kdbx4-argon2id-chacha20.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-argon2id-chacha20.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Example Login",
    },
    AcceptedCase {
        name: "unicode-kdbx4.kdbx",
        data: FixtureData::Raw(include_bytes!(
            "../../../test-fixtures/kdbx/unicode-kdbx4.kdbx"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Anmeldung 🔐 – 東京",
    },
    AcceptedCase {
        name: "kdbx4-empty-edge.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-empty-edge.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Blank Fields",
    },
    AcceptedCase {
        name: "kdbx4-large-bounded.kdbx.b64",
        data: FixtureData::Base64(include_str!(
            "../../../test-fixtures/kdbx/kdbx4-large-bounded.kdbx.b64"
        )),
        credentials: CredentialKind::Password,
        expected_major: 4,
        expected_minor: 0,
        expected_title: "Large Fixture",
    },
];

const REJECTED_FILES: &[(&str, FixtureData, KdbxOpenError)] = &[
    (
        "truncated-header-kdbx4.kdbx",
        FixtureData::Raw(include_bytes!(
            "../../../test-fixtures/kdbx/truncated-header-kdbx4.kdbx"
        )),
        KdbxOpenError::Preflight(KdbxPreflightError::TruncatedVersionHeader),
    ),
    (
        "bad-signature-kdbx4.kdbx",
        FixtureData::Raw(include_bytes!(
            "../../../test-fixtures/kdbx/bad-signature-kdbx4.kdbx"
        )),
        KdbxOpenError::Preflight(KdbxPreflightError::InvalidSignature),
    ),
];

fn database_key(kind: CredentialKind) -> DatabaseKey {
    match kind {
        CredentialKind::Password => DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        CredentialKind::PasswordAndRaw32Keyfile => DatabaseKey::new()
            .with_password(FIXTURE_PASSWORD)
            .with_keyfile(&mut Cursor::new(KEYFILE.as_slice()))
            .expect("embedded raw32 keyfile must parse"),
    }
}

fn assert_marker(database: &Database, expected_title: &str, case_name: &str) {
    assert!(
        database
            .iter_all_entries()
            .any(|entry| entry.get_title() == Some(expected_title)),
        "{case_name}: expected marker entry {expected_title:?}"
    );
}

fn kdbx4_outer_field_range(bytes: &[u8], wanted_id: u8) -> std::ops::Range<usize> {
    assert!(bytes.len() >= KDBX4_VERSION_HEADER_BYTES);
    let mut pos = KDBX4_VERSION_HEADER_BYTES;

    loop {
        let field_id = *bytes.get(pos).expect("KDBX4 outer field id must exist");
        let length_bytes: [u8; 4] = bytes
            .get(pos + 1..pos + 5)
            .expect("KDBX4 outer field length must exist")
            .try_into()
            .expect("KDBX4 outer field length must be four bytes");
        let field_len = u32::from_le_bytes(length_bytes) as usize;
        let value_start = pos + 5;
        let value_end = value_start
            .checked_add(field_len)
            .expect("KDBX4 outer field length must not overflow");
        assert!(
            value_end <= bytes.len(),
            "KDBX4 outer field must fit fixture"
        );

        if field_id == wanted_id {
            return value_start..value_end;
        }
        assert_ne!(field_id, 0, "requested KDBX4 outer field must exist");
        pos = value_end;
    }
}

fn kdbx4_outer_header_end(bytes: &[u8]) -> usize {
    assert!(bytes.len() >= KDBX4_VERSION_HEADER_BYTES);
    let mut pos = KDBX4_VERSION_HEADER_BYTES;

    loop {
        let field_id = *bytes.get(pos).expect("KDBX4 outer field id must exist");
        let length_bytes: [u8; 4] = bytes
            .get(pos + 1..pos + 5)
            .expect("KDBX4 outer field length must exist")
            .try_into()
            .expect("KDBX4 outer field length must be four bytes");
        let field_len = u32::from_le_bytes(length_bytes) as usize;
        let value_end = (pos + 5)
            .checked_add(field_len)
            .expect("KDBX4 outer field length must not overflow");
        assert!(
            value_end <= bytes.len(),
            "KDBX4 outer field must fit fixture"
        );
        pos = value_end;
        if field_id == 0 {
            return pos;
        }
    }
}

fn replace_exact_once(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let offsets: Vec<_> = haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 1, "mutation marker must occur exactly once");
    let start = offsets[0];
    haystack[start..start + replacement.len()].copy_from_slice(replacement);
}

fn manifest_kdbx_names() -> Vec<String> {
    let marker = "\"file\": \"";
    let mut names = Vec::new();
    let mut remaining = MANIFEST;

    while let Some(offset) = remaining.find(marker) {
        remaining = &remaining[offset + marker.len()..];
        let end = remaining
            .find('"')
            .expect("manifest fixture file value must be terminated");
        let name = &remaining[..end];
        if name.ends_with(".kdbx") || name.ends_with(".kdbx.b64") {
            names.push(name.to_owned());
        }
        remaining = &remaining[end + 1..];
    }

    names.sort();
    names.dedup();
    names
}

#[test]
fn full_corpus_gate_covers_every_manifest_kdbx_fixture() {
    let mut covered: Vec<_> = ACCEPTED.iter().map(|case| case.name.to_owned()).collect();
    covered.extend(REJECTED_FILES.iter().map(|(name, _, _)| (*name).to_owned()));
    covered.sort();
    covered.dedup();

    assert_eq!(covered, manifest_kdbx_names());
}

#[test]
fn accepted_manifest_corpus_opens_without_panics_or_format_regressions() {
    for case in ACCEPTED {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let bytes = case.data.materialize();
            let report = preflight_kdbx(&bytes, KdbxResourceLimits::default())
                .unwrap_or_else(|error| panic!("{}: preflight failed: {error:?}", case.name));
            assert_eq!(report.major_version, case.expected_major, "{}", case.name);
            assert_eq!(report.minor_version, case.expected_minor, "{}", case.name);

            let database = open_kdbx_bounded(
                &bytes,
                database_key(case.credentials),
                KdbxOpenLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{}: bounded open failed: {error:?}", case.name));
            assert_marker(&database, case.expected_title, case.name);
        }));

        assert!(
            result.is_ok(),
            "{}: Rust panic escaped corpus case",
            case.name
        );
    }
}

#[test]
fn malformed_manifest_corpus_rejects_with_expected_errors_without_panics() {
    for (name, data, expected) in REJECTED_FILES {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let bytes = data.materialize();
            let error = open_kdbx_bounded(
                &bytes,
                DatabaseKey::new().with_password(FIXTURE_PASSWORD),
                KdbxOpenLimits::default(),
            )
            .expect_err("malformed corpus input must be rejected");
            assert_eq!(&error, expected, "{name}");
        }));

        assert!(
            result.is_ok(),
            "{name}: Rust panic escaped malformed corpus case"
        );
    }
}

#[test]
fn credential_rejections_do_not_panic_or_expose_partial_success() {
    let password_only_cases = [ACCEPTED[0], ACCEPTED[1], ACCEPTED[2], ACCEPTED[5]];
    for case in password_only_cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let bytes = case.data.materialize();
            let error = open_kdbx_bounded(
                &bytes,
                DatabaseKey::new().with_password("definitely-wrong-password"),
                KdbxOpenLimits::default(),
            )
            .expect_err("wrong password must fail closed");
            assert_eq!(error, KdbxOpenError::EngineRejected, "{}", case.name);
        }));
        assert!(
            result.is_ok(),
            "{}: wrong-password path panicked",
            case.name
        );
    }

    let composite = ACCEPTED[4];
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = composite.data.materialize();
        let error = open_kdbx_bounded(
            &bytes,
            DatabaseKey::new().with_password(FIXTURE_PASSWORD),
            KdbxOpenLimits::default(),
        )
        .expect_err("missing keyfile must fail closed");
        assert_eq!(error, KdbxOpenError::EngineRejected);
    }));
    assert!(result.is_ok(), "composite missing-keyfile path panicked");
}

#[test]
fn derived_adversarial_inputs_fail_closed_without_panics() {
    let basic = ACCEPTED[1].data.materialize();
    let mut cases: Vec<(&str, Vec<u8>, KdbxOpenError)> = Vec::new();

    let mut unsupported_version = basic.clone();
    unsupported_version[10..12].copy_from_slice(&5_u16.to_le_bytes());
    cases.push((
        "unsupported-major-version",
        unsupported_version,
        KdbxOpenError::Preflight(KdbxPreflightError::UnsupportedMajorVersion { major: 5 }),
    ));

    let mut invalid_header_length = basic.clone();
    invalid_header_length[13..17].copy_from_slice(&4096_u32.to_le_bytes());
    cases.push((
        "invalid-outer-header-field-length",
        invalid_header_length,
        KdbxOpenError::Preflight(KdbxPreflightError::TruncatedOuterHeader),
    ));

    let mut unsupported_cipher = basic.clone();
    let cipher_range = kdbx4_outer_field_range(&unsupported_cipher, KDBX4_CIPHER_FIELD_ID);
    assert_eq!(cipher_range.len(), 16);
    unsupported_cipher[cipher_range].fill(0xa5);
    cases.push((
        "unsupported-cipher-identifier",
        unsupported_cipher,
        KdbxOpenError::EngineRejected,
    ));

    let mut unsupported_kdf = basic.clone();
    let kdf_range = kdbx4_outer_field_range(&unsupported_kdf, KDBX4_KDF_FIELD_ID);
    replace_exact_once(&mut unsupported_kdf[kdf_range], &ARGON2D_UUID, &[0xa5; 16]);
    cases.push((
        "unsupported-kdf-identifier",
        unsupported_kdf,
        KdbxOpenError::Preflight(KdbxPreflightError::UnsupportedKdf),
    ));

    let mut truncated_payload = basic.clone();
    let header_end = kdbx4_outer_header_end(&truncated_payload);
    assert!(truncated_payload.len() > header_end + 128);
    truncated_payload.truncate(truncated_payload.len() - 64);
    cases.push((
        "truncated-encrypted-payload",
        truncated_payload,
        KdbxOpenError::EngineRejected,
    ));

    let mut corrupt_header_auth = basic.clone();
    let header_end = kdbx4_outer_header_end(&corrupt_header_auth);
    let header_hmac_start = header_end + 32;
    corrupt_header_auth[header_hmac_start] ^= 0x01;
    cases.push((
        "corrupt-header-authentication",
        corrupt_header_auth,
        KdbxOpenError::EngineRejected,
    ));

    let mut corrupt_payload_auth = basic.clone();
    let last = corrupt_payload_auth
        .last_mut()
        .expect("accepted fixture must contain encrypted payload bytes");
    *last ^= 0x01;
    cases.push((
        "corrupt-encrypted-payload-integrity",
        corrupt_payload_auth,
        KdbxOpenError::EngineRejected,
    ));

    for (name, bytes, expected) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let error = open_kdbx_bounded(
                &bytes,
                DatabaseKey::new().with_password(FIXTURE_PASSWORD),
                KdbxOpenLimits::default(),
            )
            .expect_err("derived adversarial input must fail closed");
            assert_eq!(error, expected, "{name}");
        }));
        assert!(result.is_ok(), "{name}: adversarial path panicked");
    }
}

#[test]
fn configured_resource_budgets_fail_closed_without_panics() {
    let basic = ACCEPTED[1].data.materialize();
    let argon2id = ACCEPTED[2].data.materialize();
    let custom_data = ACCEPTED[3].data.materialize();
    let large = ACCEPTED[8].data.materialize();

    let budget_cases: [(&str, &Vec<u8>, KdbxOpenLimits, KdbxOpenError); 9] = [
        (
            "input-size",
            &basic,
            KdbxOpenLimits {
                preflight: KdbxResourceLimits {
                    max_input_bytes: basic.len() as u64 - 1,
                    ..KdbxResourceLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::Preflight(KdbxPreflightError::InputTooLarge {
                actual: basic.len() as u64,
                max: basic.len() as u64 - 1,
            }),
        ),
        (
            "argon2-memory",
            &argon2id,
            KdbxOpenLimits {
                preflight: KdbxResourceLimits {
                    max_argon2_memory_bytes: 65_535,
                    ..KdbxResourceLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::Preflight(KdbxPreflightError::Argon2MemoryTooHigh {
                actual: 65_536,
                max: 65_535,
            }),
        ),
        (
            "decompressed-payload",
            &basic,
            KdbxOpenLimits {
                max_decompressed_payload_bytes: 32,
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::DecompressedPayloadTooLarge { max: 32 },
        ),
        (
            "entry-count",
            &basic,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_entries: 0,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::PostDecrypt(KdbxPostDecryptError::TooManyEntries {
                actual: 1,
                limit: 0,
            }),
        ),
        (
            "field-bytes",
            &large,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_field_bytes: 65_540,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::PostDecrypt(KdbxPostDecryptError::FieldTooLarge {
                actual: 65_541,
                limit: 65_540,
            }),
        ),
        (
            "attachment-expansion",
            &large,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_attachment_bytes: 262_143,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::AttachmentTooLarge { max: 262_143 },
        ),
        (
            "aggregate-attachment-expansion",
            &large,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_total_attachment_bytes: 262_143,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::TotalAttachmentBytesTooLarge { max: 262_143 },
        ),
        (
            "group-depth",
            &basic,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_group_depth: 1,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::PostDecrypt(KdbxPostDecryptError::GroupDepthExceeded {
                actual: 2,
                limit: 1,
            }),
        ),
        (
            "custom-data-items",
            &custom_data,
            KdbxOpenLimits {
                post_decrypt: KdbxPostDecryptLimits {
                    max_custom_data_items_per_node: 0,
                    ..KdbxPostDecryptLimits::default()
                },
                ..KdbxOpenLimits::default()
            },
            KdbxOpenError::PostDecrypt(KdbxPostDecryptError::TooManyCustomDataItems {
                actual: 1,
                limit: 0,
            }),
        ),
    ];

    for (name, bytes, limits, expected) in budget_cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let error = open_kdbx_bounded(
                bytes,
                DatabaseKey::new().with_password(FIXTURE_PASSWORD),
                limits,
            )
            .expect_err("resource-budget case must fail closed");
            assert_eq!(error, expected, "{name}");
        }));
        assert!(result.is_ok(), "{name}: resource-budget path panicked");
    }
}

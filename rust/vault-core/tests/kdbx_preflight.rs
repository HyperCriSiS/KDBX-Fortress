use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{
    KdbxPreflightError, KdbxResourceLimits, KdfField, KdfPreflight, check_kdbx_input_size,
    preflight_kdbx,
};

const KDBX_SIGNATURE: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
const AES_KDBX4_UUID: [u8; 16] = [
    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38,
];
const ARGON2ID_UUID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

#[test]
fn accepts_materialized_kdbx3_fixture() {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx3-aes-aeskdf-basic.kdbx.b64"
    ));
    let report = preflight_kdbx(&bytes, KdbxResourceLimits::default())
        .expect("materialized KDBX3 fixture should satisfy default hard limits");

    assert_eq!(report.major_version, 3);
    assert!(matches!(report.kdf, KdfPreflight::Aes { rounds: 6000 }));
}

#[test]
fn accepts_materialized_argon2d_fixture() {
    let bytes = include_bytes!("../../../test-fixtures/kdbx/basic-kdbx4.kdbx");
    let report = preflight_kdbx(bytes, KdbxResourceLimits::default())
        .expect("materialized Argon2d fixture should satisfy default hard limits");

    assert_eq!(report.major_version, 4);
    assert!(matches!(
        report.kdf,
        KdfPreflight::Argon2d {
            memory_bytes: 67_108_864,
            iterations: 14,
            parallelism: 2
        }
    ));
}

#[test]
fn accepts_materialized_argon2id_fixture() {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
    ));
    let report = preflight_kdbx(&bytes, KdbxResourceLimits::default())
        .expect("materialized Argon2id fixture should satisfy default hard limits");

    assert!(matches!(
        report.kdf,
        KdfPreflight::Argon2id {
            memory_bytes: 65_536,
            iterations: 2,
            parallelism: 1
        }
    ));
}

#[test]
fn size_can_be_rejected_before_loading_or_parsing() {
    let limits = KdbxResourceLimits {
        max_input_bytes: 1024,
        ..KdbxResourceLimits::default()
    };

    assert_eq!(
        check_kdbx_input_size(1025, limits),
        Err(KdbxPreflightError::InputTooLarge {
            actual: 1025,
            max: 1024
        })
    );
}

#[test]
fn rejects_kdbx3_aes_rounds_above_policy() {
    let limits = KdbxResourceLimits {
        max_aes_rounds: 5000,
        ..KdbxResourceLimits::default()
    };
    let header = synthetic_kdbx3(5001);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::AesRoundsTooHigh {
            actual: 5001,
            max: 5000
        })
    );
}

#[test]
fn rejects_kdbx4_aes_rounds_above_policy() {
    let limits = KdbxResourceLimits {
        max_aes_rounds: 10,
        ..KdbxResourceLimits::default()
    };
    let dictionary = aes_dictionary(11);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::AesRoundsTooHigh {
            actual: 11,
            max: 10
        })
    );
}

#[test]
fn rejects_argon2_memory_above_policy() {
    let limits = KdbxResourceLimits {
        max_argon2_memory_bytes: 64 * 1024,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(64 * 1024 + 1, 2, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::Argon2MemoryTooHigh {
            actual: 64 * 1024 + 1,
            max: 64 * 1024
        })
    );
}

#[test]
fn rejects_argon2_iterations_above_policy() {
    let limits = KdbxResourceLimits {
        max_argon2_iterations: 3,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(64 * 1024, 4, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::Argon2IterationsTooHigh { actual: 4, max: 3 })
    );
}

#[test]
fn rejects_argon2_parallelism_above_policy() {
    let limits = KdbxResourceLimits {
        max_argon2_parallelism: 2,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(64 * 1024, 2, 3);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::Argon2ParallelismTooHigh { actual: 3, max: 2 })
    );
}

#[test]
fn rejects_argon2_combined_work_above_policy() {
    let limits = KdbxResourceLimits {
        max_argon2_memory_iterations_bytes: 1000,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(501, 2, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::Argon2WorkTooHigh {
            memory_bytes: 501,
            iterations: 2,
            max_memory_iterations_bytes: 1000
        })
    );
}

#[test]
fn rejects_argon2_combined_work_overflow() {
    let limits = KdbxResourceLimits {
        max_argon2_memory_bytes: u64::MAX,
        max_argon2_iterations: u64::MAX,
        max_argon2_memory_iterations_bytes: u64::MAX,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(u64::MAX, 2, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert!(matches!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::Argon2WorkTooHigh { .. })
    ));
}

#[test]
fn rejects_oversized_kdf_dictionary_before_decoding_entries() {
    let limits = KdbxResourceLimits {
        max_kdf_parameter_bytes: 8,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(64 * 1024, 2, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::KdfParametersTooLarge {
            actual: dictionary.len() as u64,
            max: 8
        })
    );
}

#[test]
fn rejects_outer_header_scan_above_policy() {
    let limits = KdbxResourceLimits {
        max_outer_header_bytes: 16,
        ..KdbxResourceLimits::default()
    };
    let dictionary = argon2id_dictionary(64 * 1024, 2, 1);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, limits),
        Err(KdbxPreflightError::OuterHeaderTooLarge { max: 16 })
    );
}

#[test]
fn rejects_unsupported_kdf_without_exposing_untrusted_bytes() {
    let mut dictionary = Vec::new();
    push_u16(&mut dictionary, 0x0100);
    push_variant_bytes(&mut dictionary, b"$UUID", &[0x55; 16]);
    dictionary.push(0);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, KdbxResourceLimits::default()),
        Err(KdbxPreflightError::UnsupportedKdf)
    );
}

#[test]
fn rejects_missing_required_kdf_field_with_typed_reason() {
    let mut dictionary = Vec::new();
    push_u16(&mut dictionary, 0x0100);
    push_variant_bytes(&mut dictionary, b"$UUID", &ARGON2ID_UUID);
    push_variant_u64(&mut dictionary, b"M", 64 * 1024);
    push_variant_u64(&mut dictionary, b"I", 2);
    dictionary.push(0);
    let header = synthetic_kdbx4(&dictionary);

    assert_eq!(
        preflight_kdbx(&header, KdbxResourceLimits::default()),
        Err(KdbxPreflightError::MissingKdfField {
            field: KdfField::Argon2Parallelism
        })
    );
}

#[test]
fn rejects_truncated_outer_header_without_panicking() {
    let mut header = version_header(4, 0);
    header.push(11);
    push_u32(&mut header, 4096);

    assert_eq!(
        preflight_kdbx(&header, KdbxResourceLimits::default()),
        Err(KdbxPreflightError::TruncatedOuterHeader)
    );
}

#[test]
fn rejects_invalid_signature_before_header_parsing() {
    let mut header = synthetic_kdbx3(6000);
    header[0] ^= 0xff;

    assert_eq!(
        preflight_kdbx(&header, KdbxResourceLimits::default()),
        Err(KdbxPreflightError::InvalidSignature)
    );
}

fn decode_fixture(encoded: &str) -> Vec<u8> {
    STANDARD
        .decode(encoded.split_whitespace().collect::<String>())
        .expect("fixture base64 must be valid")
}

fn synthetic_kdbx3(rounds: u64) -> Vec<u8> {
    let mut data = version_header(3, 1);
    data.push(6);
    push_u16(&mut data, 8);
    data.extend_from_slice(&rounds.to_le_bytes());
    data.push(0);
    push_u16(&mut data, 4);
    data.extend_from_slice(&[0x0d, 0x0a, 0x0d, 0x0a]);
    data
}

fn synthetic_kdbx4(kdf_dictionary: &[u8]) -> Vec<u8> {
    let mut data = version_header(4, 0);
    data.push(11);
    push_u32(&mut data, kdf_dictionary.len() as u32);
    data.extend_from_slice(kdf_dictionary);
    data.push(0);
    push_u32(&mut data, 4);
    data.extend_from_slice(&[0x0d, 0x0a, 0x0d, 0x0a]);
    data
}

fn version_header(major: u16, minor: u16) -> Vec<u8> {
    let mut data = KDBX_SIGNATURE.to_vec();
    push_u16(&mut data, minor);
    push_u16(&mut data, major);
    data
}

fn aes_dictionary(rounds: u64) -> Vec<u8> {
    let mut data = Vec::new();
    push_u16(&mut data, 0x0100);
    push_variant_bytes(&mut data, b"$UUID", &AES_KDBX4_UUID);
    push_variant_u64(&mut data, b"R", rounds);
    data.push(0);
    data
}

fn argon2id_dictionary(memory_bytes: u64, iterations: u64, parallelism: u32) -> Vec<u8> {
    let mut data = Vec::new();
    push_u16(&mut data, 0x0100);
    push_variant_bytes(&mut data, b"$UUID", &ARGON2ID_UUID);
    push_variant_u64(&mut data, b"M", memory_bytes);
    push_variant_u64(&mut data, b"I", iterations);
    push_variant_u32(&mut data, b"P", parallelism);
    data.push(0);
    data
}

fn push_variant_bytes(target: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    target.push(0x42);
    push_u32(target, key.len() as u32);
    target.extend_from_slice(key);
    push_u32(target, value.len() as u32);
    target.extend_from_slice(value);
}

fn push_variant_u64(target: &mut Vec<u8>, key: &[u8], value: u64) {
    target.push(0x05);
    push_u32(target, key.len() as u32);
    target.extend_from_slice(key);
    push_u32(target, 8);
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_variant_u32(target: &mut Vec<u8>, key: &[u8], value: u32) {
    target.push(0x04);
    push_u32(target, key.len() as u32);
    target.extend_from_slice(key);
    push_u32(target, 4);
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

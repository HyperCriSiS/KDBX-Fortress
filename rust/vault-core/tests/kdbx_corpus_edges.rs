use std::{error::Error, io::Error as IoError};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{
    KdbxOpenError, KdbxOpenLimits, KdbxPostDecryptError, KdbxPostDecryptLimits, open_kdbx_bounded,
};
use keepass::{Database, DatabaseKey};

const FIXTURE_PASSWORD: &str = "fixture-password";
const LARGE_NOTES_BYTES: u64 = 65_536;
const NOTES_FIELD_BYTES: u64 = 5 + LARGE_NOTES_BYTES;
const LARGE_ATTACHMENT_BYTES: u64 = 262_144;

fn decode_fixture(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(STANDARD.decode(encoded.trim())?)
}

fn open_with_limits(bytes: &[u8], limits: KdbxOpenLimits) -> Result<Database, KdbxOpenError> {
    open_kdbx_bounded(
        bytes,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        limits,
    )
}

fn open_ok(bytes: &[u8], limits: KdbxOpenLimits) -> Result<Database, Box<dyn Error>> {
    open_with_limits(bytes, limits)
        .map_err(|error| IoError::other(format!("bounded KDBX open failed: {error:?}")).into())
}

fn exact_large_fixture_limits() -> KdbxOpenLimits {
    KdbxOpenLimits {
        post_decrypt: KdbxPostDecryptLimits {
            max_field_bytes: NOTES_FIELD_BYTES,
            max_attachment_bytes: LARGE_ATTACHMENT_BYTES,
            max_total_attachment_bytes: LARGE_ATTACHMENT_BYTES,
            ..KdbxPostDecryptLimits::default()
        },
        ..KdbxOpenLimits::default()
    }
}

#[test]
fn opens_kdbx4_empty_edge_fixture_without_inventing_optional_values() -> Result<(), Box<dyn Error>>
{
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-empty-edge.kdbx.b64"
    ))?;
    let database = open_ok(&bytes, KdbxOpenLimits::default())?;

    let synthetic = database
        .root()
        .group_by_path(&["Synthetic"])
        .ok_or_else(|| IoError::other("Synthetic group must remain present"))?;
    assert_eq!(
        synthetic.entries().count(),
        0,
        "Synthetic group must be empty"
    );

    let entry = database
        .iter_all_entries()
        .find(|entry| entry.get_title() == Some("Blank Fields"))
        .ok_or_else(|| IoError::other("Blank Fields entry must exist"))?;

    assert!(matches!(entry.get_username(), None | Some("")));
    assert!(matches!(entry.get_password(), None | Some("")));
    assert!(matches!(entry.get_url(), None | Some("")));
    assert!(matches!(entry.get("Notes"), None | Some("")));
    Ok(())
}

#[test]
fn opens_kdbx4_large_bounded_fixture_and_preserves_exact_content() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-large-bounded.kdbx.b64"
    ))?;
    let database = open_ok(&bytes, KdbxOpenLimits::default())?;

    let group = database
        .root()
        .group_by_path(&["Synthetic"])
        .ok_or_else(|| IoError::other("Synthetic group must exist"))?;
    let entry = group
        .entry_by_name("Large Fixture")
        .ok_or_else(|| IoError::other("Large Fixture entry must exist"))?;

    assert_eq!(entry.get_username(), Some("large-user"));
    assert_eq!(entry.get_url(), Some("https://large.example.test"));

    let notes = entry
        .get("Notes")
        .ok_or_else(|| IoError::other("Large Fixture Notes must exist"))?;
    assert_eq!(notes.len(), LARGE_NOTES_BYTES as usize);
    assert!(notes.as_bytes().iter().all(|byte| *byte == b'N'));

    let attachment = entry
        .attachment_by_name("payload.bin")
        .ok_or_else(|| IoError::other("payload.bin attachment must exist"))?;
    let attachment_bytes = attachment.data.get();
    assert_eq!(attachment_bytes.len(), LARGE_ATTACHMENT_BYTES as usize);
    for (index, byte) in attachment_bytes.iter().enumerate() {
        assert_eq!(*byte, (index % 256) as u8);
    }
    Ok(())
}

#[test]
fn accepts_large_fixture_at_exact_field_and_attachment_limits() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-large-bounded.kdbx.b64"
    ))?;
    open_ok(&bytes, exact_large_fixture_limits())?;
    Ok(())
}

#[test]
fn rejects_large_fixture_one_byte_below_field_limit() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-large-bounded.kdbx.b64"
    ))?;
    let mut limits = exact_large_fixture_limits();
    limits.post_decrypt.max_field_bytes = NOTES_FIELD_BYTES - 1;

    match open_with_limits(&bytes, limits) {
        Err(KdbxOpenError::PostDecrypt(KdbxPostDecryptError::FieldTooLarge { actual, limit })) => {
            assert_eq!(actual, NOTES_FIELD_BYTES);
            assert_eq!(limit, NOTES_FIELD_BYTES - 1);
        }
        other => panic!("expected field-size rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn rejects_large_fixture_one_byte_below_attachment_limits() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-large-bounded.kdbx.b64"
    ))?;

    let mut per_attachment = exact_large_fixture_limits();
    per_attachment.post_decrypt.max_attachment_bytes = LARGE_ATTACHMENT_BYTES - 1;
    match open_with_limits(&bytes, per_attachment) {
        Err(KdbxOpenError::AttachmentTooLarge { max }) => {
            assert_eq!(max, LARGE_ATTACHMENT_BYTES - 1);
        }
        other => panic!("expected per-attachment rejection, got {other:?}"),
    }

    let mut aggregate = exact_large_fixture_limits();
    aggregate.post_decrypt.max_total_attachment_bytes = LARGE_ATTACHMENT_BYTES - 1;
    match open_with_limits(&bytes, aggregate) {
        Err(KdbxOpenError::TotalAttachmentBytesTooLarge { max }) => {
            assert_eq!(max, LARGE_ATTACHMENT_BYTES - 1);
        }
        other => panic!("expected aggregate-attachment rejection, got {other:?}"),
    }
    Ok(())
}

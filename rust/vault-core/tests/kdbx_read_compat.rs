use std::error::Error;
use std::io::Error as IoError;

use keepass::{Database, DatabaseKey};

const FIXTURE_PASSWORD: &str = "fixture-password";

fn open_fixture(bytes: &[u8]) -> Result<Database, Box<dyn Error>> {
    let mut source = bytes;
    Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    )
    .map_err(|error| IoError::other(error.to_string()).into())
}

#[test]
fn opens_basic_kdbx4_fixture_and_preserves_expected_fields() -> Result<(), Box<dyn Error>> {
    let db = open_fixture(include_bytes!(
        "../../../test-fixtures/kdbx/basic-kdbx4.kdbx"
    ))?;

    let group = db
        .root()
        .group_by_path(&["Synthetic"])
        .ok_or_else(|| IoError::other("Synthetic group must exist"))?;
    let entry = group
        .entry_by_name("Example Login")
        .ok_or_else(|| IoError::other("Example Login entry must exist"))?;

    assert_eq!(entry.get_title(), Some("Example Login"));
    assert_eq!(entry.get_username(), Some("fixture-user"));
    assert_eq!(entry.get_password(), Some("fixture-secret"));
    assert_eq!(entry.get_url(), Some("https://example.test"));

    Ok(())
}

#[test]
fn opens_unicode_kdbx4_fixture_without_text_loss() -> Result<(), Box<dyn Error>> {
    let db = open_fixture(include_bytes!(
        "../../../test-fixtures/kdbx/unicode-kdbx4.kdbx"
    ))?;

    let group = db
        .root()
        .group_by_path(&["Synthetisch-Üñîçødé-测试"])
        .ok_or_else(|| IoError::other("Unicode group must exist"))?;
    let entry = group
        .entry_by_name("Anmeldung 🔐 – 東京")
        .ok_or_else(|| IoError::other("Unicode entry must exist"))?;

    assert_eq!(entry.get_title(), Some("Anmeldung 🔐 – 東京"));
    assert_eq!(entry.get_username(), Some("nützer@example.test"));
    assert_eq!(entry.get_password(), Some("pässwörd-Δ-秘密"));
    assert_eq!(entry.get_url(), Some("https://例え.test/über"));
    assert_eq!(
        entry.get_notes(),
        Some("Unicode interoperability fixture: äöü ß Ελληνικά 日本語 emoji 🚀")
    );

    Ok(())
}

#[test]
fn rejects_truncated_header_fixture() {
    let mut source = &include_bytes!(
        "../../../test-fixtures/kdbx/truncated-header-kdbx4.kdbx"
    )[..];

    let result = Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    );

    assert!(result.is_err(), "truncated KDBX header must be rejected");
}

#[test]
fn rejects_invalid_signature_fixture() {
    let mut source = &include_bytes!(
        "../../../test-fixtures/kdbx/bad-signature-kdbx4.kdbx"
    )[..];

    let result = Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    );

    assert!(result.is_err(), "invalid KDBX signature must be rejected");
}

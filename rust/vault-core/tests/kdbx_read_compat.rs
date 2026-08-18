use std::error::Error;
use std::io::Error as IoError;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use keepass::{
    Database, DatabaseKey,
    config::{KdfConfig, OuterCipherConfig},
    db::CustomDataValue,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

fn open_fixture(bytes: &[u8]) -> Result<Database, Box<dyn Error>> {
    let mut source = bytes;
    Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    )
    .map_err(|error| IoError::other(error.to_string()).into())
}

fn open_base64_fixture(encoded: &str) -> Result<Database, Box<dyn Error>> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|error| IoError::other(error.to_string()))?;
    open_fixture(&bytes)
}

#[test]
fn opens_kdbx3_aes_kdf_fixture_and_preserves_protected_and_custom_fields()
-> Result<(), Box<dyn Error>> {
    let db = open_base64_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx3-aes-aeskdf-basic.kdbx.b64"
    ))?;

    assert!(matches!(
        db.config.kdf_config,
        KdfConfig::Aes { rounds: 6000 }
    ));
    assert!(matches!(
        db.config.outer_cipher_config,
        OuterCipherConfig::AES256
    ));

    let root = db.root();
    let group = root
        .group_by_path(&["Synthetic KDBX3"])
        .ok_or_else(|| IoError::other("Synthetic KDBX3 group must exist"))?;
    let entry = group
        .entry_by_name("Legacy AES Login")
        .ok_or_else(|| IoError::other("Legacy AES Login entry must exist"))?;

    assert_eq!(entry.get_title(), Some("Legacy AES Login"));
    assert_eq!(entry.get_username(), Some("kdbx3-user"));
    assert_eq!(entry.get_password(), Some("kdbx3-fixture-secret"));
    assert_eq!(entry.get_url(), Some("https://legacy.example.test"));
    assert_eq!(entry.get("Notes"), Some("KDBX3 AES-KDF synthetic fixture"));
    assert_eq!(entry.get("FortressCustom"), Some("custom-value"));

    Ok(())
}

#[test]
fn opens_basic_kdbx4_fixture_and_preserves_expected_fields() -> Result<(), Box<dyn Error>> {
    let db = open_fixture(include_bytes!(
        "../../../test-fixtures/kdbx/basic-kdbx4.kdbx"
    ))?;

    assert!(matches!(
        db.config.kdf_config,
        KdfConfig::Argon2 {
            iterations: 14,
            memory: 67_108_864,
            parallelism: 2,
            ..
        }
    ));
    assert!(matches!(
        db.config.outer_cipher_config,
        OuterCipherConfig::AES256
    ));

    let root = db.root();
    let group = root
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
fn opens_kdbx4_argon2id_aes_fixture_and_preserves_expected_fields() -> Result<(), Box<dyn Error>> {
    let db = open_base64_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
    ))?;

    assert!(matches!(
        db.config.kdf_config,
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 65_536,
            parallelism: 1,
            ..
        }
    ));
    assert!(matches!(
        db.config.outer_cipher_config,
        OuterCipherConfig::AES256
    ));

    let root = db.root();
    let group = root
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
fn opens_kdbx4_attachment_and_custom_data_fixture_without_loss() -> Result<(), Box<dyn Error>> {
    let db = open_base64_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-attachments-custom-data.kdbx.b64"
    ))?;

    assert_eq!(db.num_attachments(), 2);
    assert!(matches!(
        db.meta
            .custom_data
            .get("FortressDatabaseCustom")
            .and_then(|item| item.value.as_ref()),
        Some(CustomDataValue::String(value)) if value == "database-custom-value"
    ));

    let root = db.root();
    let group = root
        .group_by_path(&["Synthetic"])
        .ok_or_else(|| IoError::other("Synthetic group must exist"))?;
    assert!(matches!(
        group
            .custom_data
            .get("FortressGroupCustom")
            .and_then(|item| item.value.as_ref()),
        Some(CustomDataValue::String(value)) if value == "group-custom-value"
    ));

    let entry = group
        .entry_by_name("Example Login")
        .ok_or_else(|| IoError::other("Example Login entry must exist"))?;
    assert!(matches!(
        entry
            .custom_data
            .get("FortressEntryCustom")
            .and_then(|item| item.value.as_ref()),
        Some(CustomDataValue::String(value)) if value == "entry-custom-value"
    ));

    let unprotected = entry
        .attachment_by_name("fortress-note.txt")
        .ok_or_else(|| IoError::other("unprotected fixture attachment must exist"))?;
    assert!(!unprotected.data.is_protected());
    assert_eq!(
        unprotected.data.get().as_slice(),
        b"KDBX Fortress synthetic attachment\n"
    );

    let protected = entry
        .attachment_by_name("protected-secret.bin")
        .ok_or_else(|| IoError::other("protected fixture attachment must exist"))?;
    assert!(protected.data.is_protected());
    assert_eq!(
        protected.data.get().as_slice(),
        b"\x00Fortress protected binary\xff\x10"
    );

    let names: Vec<_> = entry.attachments_named().map(|(name, _)| name).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"fortress-note.txt"));
    assert!(names.contains(&"protected-secret.bin"));

    Ok(())
}

#[test]
fn opens_kdbx4_argon2id_chacha20_fixture_and_preserves_expected_fields()
-> Result<(), Box<dyn Error>> {
    let db = open_base64_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-chacha20.kdbx.b64"
    ))?;

    assert!(matches!(
        db.config.kdf_config,
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 65_536,
            parallelism: 1,
            ..
        }
    ));
    assert!(matches!(
        db.config.outer_cipher_config,
        OuterCipherConfig::ChaCha20
    ));

    let root = db.root();
    let group = root
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

    let root = db.root();
    let group = root
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
        entry.get("Notes"),
        Some("Unicode interoperability fixture: äöü ß Ελληνικά 日本語 emoji 🚀")
    );

    Ok(())
}

#[test]
fn rejects_truncated_header_fixture() {
    let mut source = &include_bytes!("../../../test-fixtures/kdbx/truncated-header-kdbx4.kdbx")[..];

    let result = Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    );

    assert!(result.is_err(), "truncated KDBX header must be rejected");
}

#[test]
fn rejects_invalid_signature_fixture() {
    let mut source = &include_bytes!("../../../test-fixtures/kdbx/bad-signature-kdbx4.kdbx")[..];

    let result = Database::open(
        &mut source,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    );

    assert!(result.is_err(), "invalid KDBX signature must be rejected");
}

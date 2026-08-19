use std::error::Error;
use std::io::{Cursor, Error as IoError};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{KdbxOpenLimits, open_kdbx_bounded};
use keepass::{
    Database, DatabaseKey,
    config::{KdfConfig, OuterCipherConfig},
    db::CustomDataValue,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

fn decode_fixture(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    STANDARD
        .decode(encoded.trim())
        .map_err(|error| IoError::other(error.to_string()).into())
}

fn password_key() -> DatabaseKey {
    DatabaseKey::new().with_password(FIXTURE_PASSWORD)
}

fn open_password_fixture(bytes: &[u8]) -> Result<Database, Box<dyn Error>> {
    open_kdbx_bounded(bytes, password_key(), KdbxOpenLimits::default())
        .map_err(|error| IoError::other(format!("bounded KDBX open failed: {error:?}")).into())
}

fn round_trip_password_fixture(bytes: &[u8]) -> Result<Database, Box<dyn Error>> {
    let database = open_password_fixture(bytes)?;
    let mut serialized = Vec::new();
    database
        .save(&mut serialized, password_key())
        .map_err(|error| IoError::other(format!("KDBX save failed: {error}")))?;
    open_password_fixture(&serialized)
}

fn assert_example_entry(database: &Database) -> Result<(), Box<dyn Error>> {
    let root = database.root();
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
fn round_trip_argon2id_aes_preserves_crypto_and_entry_semantics() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
    ))?;
    let database = round_trip_password_fixture(&bytes)?;

    assert!(matches!(
        database.config.kdf_config,
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 65_536,
            parallelism: 1,
            ..
        }
    ));
    assert!(matches!(
        database.config.outer_cipher_config,
        OuterCipherConfig::AES256
    ));
    assert_example_entry(&database)
}

#[test]
fn round_trip_argon2id_chacha20_preserves_crypto_and_entry_semantics() -> Result<(), Box<dyn Error>>
{
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-chacha20.kdbx.b64"
    ))?;
    let database = round_trip_password_fixture(&bytes)?;

    assert!(matches!(
        database.config.kdf_config,
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 65_536,
            parallelism: 1,
            ..
        }
    ));
    assert!(matches!(
        database.config.outer_cipher_config,
        OuterCipherConfig::ChaCha20
    ));
    assert_example_entry(&database)
}

#[test]
fn round_trip_unicode_preserves_utf8_values_exactly() -> Result<(), Box<dyn Error>> {
    let database = round_trip_password_fixture(include_bytes!(
        "../../../test-fixtures/kdbx/unicode-kdbx4.kdbx"
    ))?;

    let root = database.root();
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
fn round_trip_attachments_and_custom_data_preserves_bytes_and_metadata() -> Result<(), Box<dyn Error>>
{
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-attachments-custom-data.kdbx.b64"
    ))?;
    let database = round_trip_password_fixture(&bytes)?;

    assert_eq!(database.num_attachments(), 2);
    assert!(matches!(
        database
            .meta
            .custom_data
            .get("FortressDatabaseCustom")
            .and_then(|item| item.value.as_ref()),
        Some(CustomDataValue::String(value)) if value == "database-custom-value"
    ));

    let root = database.root();
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
    Ok(())
}

#[test]
fn round_trip_composite_password_and_raw32_keyfile_remains_required() -> Result<(), Box<dyn Error>>
{
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-composite-key-keyfile.kdbx.b64"
    ))?;
    let keyfile: &[u8; 32] =
        include_bytes!("../../../test-fixtures/kdbx/kdbx4-composite-key.raw32.key");
    let password = FIXTURE_PASSWORD;

    let make_key = || -> Result<DatabaseKey, Box<dyn Error>> {
        Ok(DatabaseKey::new()
            .with_password(password)
            .with_keyfile(&mut Cursor::new(keyfile.as_slice()))?)
    };

    let database = open_kdbx_bounded(&bytes, make_key()?, KdbxOpenLimits::default())
        .map_err(|error| IoError::other(format!("bounded KDBX open failed: {error:?}")))?;
    let mut serialized = Vec::new();
    database
        .save(&mut serialized, make_key()?)
        .map_err(|error| IoError::other(format!("KDBX save failed: {error}")))?;

    let reopened = open_kdbx_bounded(&serialized, make_key()?, KdbxOpenLimits::default())
        .map_err(|error| IoError::other(format!("bounded KDBX reopen failed: {error:?}")))?;
    assert_example_entry(&reopened)?;

    assert!(
        open_kdbx_bounded(
            &serialized,
            DatabaseKey::new().with_password(password),
            KdbxOpenLimits::default(),
        )
        .is_err(),
        "round-tripped composite-key database must still reject password-only access"
    );
    Ok(())
}

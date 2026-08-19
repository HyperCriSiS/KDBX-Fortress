use std::error::Error;
use std::fs;
use std::io::{Cursor, Error as IoError};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{KdbxOpenLimits, open_kdbx_bounded};
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseVersion, KdfConfig, OuterCipherConfig},
    db::CustomDataValue,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

fn interop_output_dir() -> Result<Option<PathBuf>, Box<dyn Error>> {
    let Some(path) = std::env::var_os("FORTRESS_INTEROP_OUTPUT_DIR") else {
        return Ok(None);
    };

    let path = PathBuf::from(path);
    fs::create_dir_all(&path)?;
    Ok(Some(path))
}

fn maybe_write_interop_artifact(name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let Some(output_dir) = interop_output_dir()? else {
        return Ok(());
    };

    fs::write(output_dir.join(name), bytes)?;
    Ok(())
}

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

fn explicitly_upgrade_kdbx40_to_41(mut database: Database) -> Result<Database, Box<dyn Error>> {
    if database.config.version != DatabaseVersion::KDB4(0) {
        return Err(IoError::other(format!(
            "expected KDBX 4.0 fixture before explicit migration, got {}",
            database.config.version
        ))
        .into());
    }

    database.config.version = DatabaseVersion::KDB4(1);
    Ok(database)
}

fn migrate_to_41_round_trip_password_fixture(
    bytes: &[u8],
    interop_artifact_name: &str,
) -> Result<Database, Box<dyn Error>> {
    let database = explicitly_upgrade_kdbx40_to_41(open_password_fixture(bytes)?)?;
    let mut serialized = Vec::new();
    database
        .save(&mut serialized, password_key())
        .map_err(|error| IoError::other(format!("KDBX 4.1 save failed: {error}")))?;
    maybe_write_interop_artifact(interop_artifact_name, &serialized)?;
    let reopened = open_password_fixture(&serialized)?;
    assert_eq!(reopened.config.version, DatabaseVersion::KDB4(1));
    Ok(reopened)
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
fn serializer_rejects_kdbx40_without_an_explicit_version_migration() -> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
    ))?;
    let database = open_password_fixture(&bytes)?;
    assert_eq!(database.config.version, DatabaseVersion::KDB4(0));

    let mut serialized = Vec::new();
    let error = database
        .save(&mut serialized, password_key())
        .expect_err("the pinned serializer must not silently rewrite KDBX 4.0 as 4.1");

    assert_eq!(error.to_string(), "Unsupported database version");
    assert!(serialized.is_empty());
    Ok(())
}

#[test]
fn explicit_41_migration_argon2id_aes_preserves_crypto_and_entry_semantics()
-> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64"
    ))?;
    let database = migrate_to_41_round_trip_password_fixture(&bytes, "argon2id-aes-41.kdbx")?;

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
fn explicit_41_migration_argon2id_chacha20_preserves_crypto_and_entry_semantics()
-> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-argon2id-chacha20.kdbx.b64"
    ))?;
    let database = migrate_to_41_round_trip_password_fixture(&bytes, "argon2id-chacha20-41.kdbx")?;

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
fn explicit_41_migration_unicode_preserves_utf8_values_exactly() -> Result<(), Box<dyn Error>> {
    let database = migrate_to_41_round_trip_password_fixture(
        include_bytes!("../../../test-fixtures/kdbx/unicode-kdbx4.kdbx"),
        "unicode-41.kdbx",
    )?;

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
fn explicit_41_migration_attachments_and_custom_data_preserves_bytes_and_metadata()
-> Result<(), Box<dyn Error>> {
    let bytes = decode_fixture(include_str!(
        "../../../test-fixtures/kdbx/kdbx4-attachments-custom-data.kdbx.b64"
    ))?;
    let database =
        migrate_to_41_round_trip_password_fixture(&bytes, "attachments-custom-data-41.kdbx")?;

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
fn explicit_41_migration_composite_password_and_raw32_keyfile_remains_required()
-> Result<(), Box<dyn Error>> {
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
    let database = explicitly_upgrade_kdbx40_to_41(database)?;
    let mut serialized = Vec::new();
    database
        .save(&mut serialized, make_key()?)
        .map_err(|error| IoError::other(format!("KDBX 4.1 save failed: {error}")))?;
    maybe_write_interop_artifact("composite-key-41.kdbx", &serialized)?;

    let reopened = open_kdbx_bounded(&serialized, make_key()?, KdbxOpenLimits::default())
        .map_err(|error| IoError::other(format!("bounded KDBX reopen failed: {error:?}")))?;
    assert_eq!(reopened.config.version, DatabaseVersion::KDB4(1));
    assert_example_entry(&reopened)?;

    assert!(
        open_kdbx_bounded(
            &serialized,
            DatabaseKey::new().with_password(password),
            KdbxOpenLimits::default(),
        )
        .is_err(),
        "migrated composite-key database must still reject password-only access"
    );
    Ok(())
}

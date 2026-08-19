use std::error::Error;
use std::io::{Cursor, Error as IoError};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{KdbxPostDecryptLimits, validate_decrypted_database};
use keepass::{
    Database, DatabaseKey,
    config::{KdfConfig, OuterCipherConfig},
};

const FIXTURE_NAME: &str = "kdbx4-composite-key-keyfile.kdbx.b64";
const FIXTURE: &str =
    include_str!("../../../test-fixtures/kdbx/kdbx4-composite-key-keyfile.kdbx.b64");
const KEYFILE: &[u8; 32] =
    include_bytes!("../../../test-fixtures/kdbx/kdbx4-composite-key.raw32.key");
const MANIFEST: &str = include_str!("../../../test-fixtures/kdbx/manifest.json");

fn fixture_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    STANDARD
        .decode(FIXTURE.trim())
        .map_err(|error| IoError::other(error.to_string()).into())
}

fn fixture_password() -> Result<&'static str, Box<dyn Error>> {
    let fixture_marker = format!("\"file\": \"{FIXTURE_NAME}\"");
    let fixture_offset = MANIFEST
        .find(&fixture_marker)
        .ok_or_else(|| IoError::other("composite-key fixture must exist in manifest"))?;
    let fixture_entry = &MANIFEST[fixture_offset..];
    let password_marker = "\"password\": \"";
    let password_offset = fixture_entry
        .find(password_marker)
        .ok_or_else(|| IoError::other("composite-key fixture password must exist in manifest"))?
        + password_marker.len();
    let password_tail = &fixture_entry[password_offset..];
    let password_end = password_tail
        .find('"')
        .ok_or_else(|| IoError::other("composite-key fixture password must be terminated"))?;
    Ok(&password_tail[..password_end])
}

fn composite_key(password: &str, keyfile: &[u8]) -> Result<DatabaseKey, Box<dyn Error>> {
    Ok(DatabaseKey::new()
        .with_password(password)
        .with_keyfile(&mut Cursor::new(keyfile))?)
}

#[test]
fn composite_password_and_raw32_keyfile_is_required() -> Result<(), Box<dyn Error>> {
    assert_eq!(KEYFILE.len(), 32);
    let fixture = fixture_bytes()?;
    let password = fixture_password()?;

    let mut source = fixture.as_slice();
    let db = Database::open(&mut source, composite_key(password, KEYFILE)?)
        .map_err(|error| IoError::other(error.to_string()))?;
    validate_decrypted_database(&db, KdbxPostDecryptLimits::default())
        .map_err(|error| IoError::other(format!("post-decrypt validation failed: {error:?}")))?;

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

    let mut source = fixture.as_slice();
    assert!(
        Database::open(&mut source, DatabaseKey::new().with_password(password)).is_err(),
        "password without required keyfile must be rejected"
    );

    let mut wrong_keyfile = KEYFILE.to_vec();
    wrong_keyfile[0] ^= 0x01;
    let mut source = fixture.as_slice();
    assert!(
        Database::open(&mut source, composite_key(password, &wrong_keyfile)?).is_err(),
        "wrong keyfile must be rejected"
    );

    let mut wrong_password = password.as_bytes().to_vec();
    wrong_password[0] ^= 0x01;
    let wrong_password = String::from_utf8(wrong_password)?;
    let mut source = fixture.as_slice();
    assert!(
        Database::open(&mut source, composite_key(&wrong_password, KEYFILE)?).is_err(),
        "wrong password must be rejected even with correct keyfile"
    );

    let keyfile_only = DatabaseKey::new().with_keyfile(&mut Cursor::new(KEYFILE.as_slice()))?;
    let mut source = fixture.as_slice();
    assert!(
        Database::open(&mut source, keyfile_only).is_err(),
        "keyfile without required password must be rejected"
    );

    Ok(())
}

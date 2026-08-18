use std::error::Error;
use std::io::{Cursor, Error as IoError};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use keepass::{
    Database, DatabaseKey,
    config::{KdfConfig, OuterCipherConfig},
};

const FIXTURE_PASSWORD: &str = "fixture-password";
const FIXTURE: &str =
    include_str!("../../../test-fixtures/kdbx/kdbx4-composite-key-keyfile.kdbx.b64");
const KEYFILE: &[u8; 32] =
    include_bytes!("../../../test-fixtures/kdbx/kdbx4-composite-key.raw32.key");

fn fixture_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    STANDARD
        .decode(FIXTURE.trim())
        .map_err(|error| IoError::other(error.to_string()).into())
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

    let mut source = fixture.as_slice();
    let db = Database::open(&mut source, composite_key(FIXTURE_PASSWORD, KEYFILE)?)
        .map_err(|error| IoError::other(error.to_string()))?;

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
        Database::open(
            &mut source,
            DatabaseKey::new().with_password(FIXTURE_PASSWORD)
        )
        .is_err(),
        "password without required keyfile must be rejected"
    );

    let mut wrong_keyfile = KEYFILE.to_vec();
    wrong_keyfile[0] ^= 0x01;
    let mut source = fixture.as_slice();
    assert!(
        Database::open(
            &mut source,
            composite_key(FIXTURE_PASSWORD, &wrong_keyfile)?
        )
        .is_err(),
        "wrong keyfile must be rejected"
    );

    let mut source = fixture.as_slice();
    assert!(
        Database::open(
            &mut source,
            composite_key("wrong-fixture-password", KEYFILE)?
        )
        .is_err(),
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

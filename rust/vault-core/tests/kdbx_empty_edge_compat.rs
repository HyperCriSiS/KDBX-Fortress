use std::error::Error;
use std::io::Error as IoError;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{KdbxOpenLimits, open_kdbx_bounded};
use keepass::{
    DatabaseKey,
    config::{DatabaseVersion, KdfConfig, OuterCipherConfig},
    db::fields,
};

const FIXTURE_PASSWORD: &str = "fixture-password";
const FIXTURE_B64: &str = include_str!(
    "../../../test-fixtures/kdbx/kdbx4-empty-edge.kdbx.b64"
);

#[test]
fn opens_kdbx4_empty_edge_fixture_without_inventing_values() -> Result<(), Box<dyn Error>> {
    let bytes = STANDARD
        .decode(FIXTURE_B64.trim())
        .map_err(|error| IoError::other(error.to_string()))?;
    let db = open_kdbx_bounded(
        &bytes,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        KdbxOpenLimits::default(),
    )
    .map_err(|error| IoError::other(format!("bounded KDBX open failed: {error:?}")))?;

    assert_eq!(db.config.version, DatabaseVersion::KDB4(1));
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
    let edge_group = root
        .group_by_path(&["Edge Cases"])
        .ok_or_else(|| IoError::other("Edge Cases group must exist"))?;

    let empty = edge_group
        .entry_by_name("Empty Strings")
        .ok_or_else(|| IoError::other("Empty Strings entry must exist"))?;
    assert_eq!(empty.get_username(), Some(""));
    assert_eq!(empty.get_password(), Some(""));
    assert_eq!(empty.get_url(), Some(""));
    assert_eq!(empty.get(fields::NOTES), Some(""));
    assert_eq!(empty.get("EmptyCustom"), Some(""));
    assert!(
        empty
            .fields
            .get(fields::PASSWORD)
            .is_some_and(|value| value.is_protected()),
        "empty password must remain a present protected value"
    );

    let sparse = edge_group
        .entry_by_name("Sparse Entry")
        .ok_or_else(|| IoError::other("Sparse Entry must exist"))?;
    assert_eq!(sparse.get_username(), None);
    assert_eq!(sparse.get_password(), None);
    assert_eq!(sparse.get_url(), None);
    assert_eq!(sparse.get(fields::NOTES), None);

    let fieldless = edge_group
        .entries()
        .find(|entry| entry.fields.is_empty())
        .ok_or_else(|| IoError::other("field-less entry must exist"))?;
    assert_eq!(fieldless.get_title(), None);
    assert_eq!(fieldless.get_username(), None);
    assert_eq!(fieldless.get_password(), None);
    assert_eq!(fieldless.get_url(), None);

    let empty_group = root
        .group_by_path(&["Empty Group"])
        .ok_or_else(|| IoError::other("Empty Group must exist"))?;
    assert!(empty_group.entries().next().is_none());
    assert!(empty_group.groups().next().is_none());

    assert!(
        !db.has_ignored_xml_fields(),
        "the accepted empty-edge fixture must not contain ignored XML"
    );

    Ok(())
}

use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kdbx_fortress_vault_core::{KdbxOpenLimits, open_kdbx_bounded};
use keepass::{
    Database, DatabaseKey,
    config::DatabaseVersion,
    db::fields,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

#[test]
#[ignore = "fixture-generation helper; run only with FORTRESS_FIXTURE_OUTPUT"]
fn generate_kdbx4_empty_edge_fixture() -> Result<(), Box<dyn Error>> {
    let output = std::env::var_os("FORTRESS_FIXTURE_OUTPUT")
        .map(PathBuf::from)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "FORTRESS_FIXTURE_OUTPUT is required"))?;

    let source_bytes = STANDARD.decode(
        include_str!("../../../test-fixtures/kdbx/kdbx4-argon2id-aes.kdbx.b64").trim(),
    )?;
    let source = open_kdbx_bounded(
        &source_bytes,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        KdbxOpenLimits::default(),
    )
    .map_err(|error| IoError::other(format!("source KDBX open failed: {error:?}")))?;

    let mut config = source.config.clone();
    config.version = DatabaseVersion::KDB4(1);
    let mut database = Database::with_config(config);

    database.root_mut().edit(|root| root.name = "Root".into());

    let edge_group_id = database
        .root_mut()
        .add_group()
        .edit(|group| group.name = "Edge Cases".into())
        .id();

    {
        let mut edge_group = database
            .group_mut(edge_group_id)
            .ok_or_else(|| IoError::other("Edge Cases group must exist"))?;

        edge_group.add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Empty Strings");
            entry.set_unprotected(fields::USERNAME, "");
            entry.set_protected(fields::PASSWORD, "");
            entry.set_unprotected(fields::URL, "");
            entry.set_unprotected(fields::NOTES, "");
            entry.set_unprotected("EmptyCustom", "");
        });

        edge_group.add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Sparse Entry");
        });

        edge_group.add_entry();
    }

    database
        .root_mut()
        .add_group()
        .edit(|group| group.name = "Empty Group".into());

    let mut serialized = Vec::new();
    database
        .save(
            &mut serialized,
            DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        )
        .map_err(|error| IoError::other(format!("fixture save failed: {error}")))?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serialized)?;
    Ok(())
}

use std::{
    error::Error,
    io::Error as IoError,
    panic::{AssertUnwindSafe, catch_unwind},
};

use kdbx_fortress_vault_core::{
    KdbxOpenError, KdbxOpenLimits, KdbxResourceLimits, open_kdbx_bounded, preflight_kdbx,
};
use keepass::{
    Database, DatabaseKey,
    config::KdfConfig,
    test_fixture_tools::dump_kdbx4_with_raw_xml,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

const VALID_MINIMAL_XML: &[u8] = br#"<KeePassFile><Meta/><Root><Group><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#;

fn authenticated_kdbx4(raw_xml: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut database = Database::new();
    database.config.kdf_config = KdfConfig::Aes { rounds: 10 };

    let key = DatabaseKey::new().with_password(FIXTURE_PASSWORD);
    let mut output = Vec::new();
    dump_kdbx4_with_raw_xml(&database, &key, raw_xml, &mut output)?;
    Ok(output)
}

fn assert_authenticated_engine_rejection(name: &str, raw_xml: &[u8]) -> Result<(), Box<dyn Error>> {
    let bytes = authenticated_kdbx4(raw_xml)?;
    let report = preflight_kdbx(&bytes, KdbxResourceLimits::default())?;
    assert_eq!(report.major_version, 4, "{name}: generated fixture major version");
    assert_eq!(report.minor_version, 1, "{name}: generated fixture minor version");

    let result = catch_unwind(AssertUnwindSafe(|| {
        open_kdbx_bounded(
            &bytes,
            DatabaseKey::new().with_password(FIXTURE_PASSWORD),
            KdbxOpenLimits::default(),
        )
    }));

    match result {
        Ok(Err(KdbxOpenError::EngineRejected)) => Ok(()),
        Ok(Err(error)) => Err(IoError::other(format!(
            "{name}: authenticated malformed XML reached an unexpected Fortress error: {error:?}"
        ))
        .into()),
        Ok(Ok(_)) => Err(IoError::other(format!(
            "{name}: authenticated malformed XML unexpectedly opened"
        ))
        .into()),
        Err(_) => Err(IoError::other(format!(
            "{name}: Rust panic escaped the authenticated XML parser boundary"
        ))
        .into()),
    }
}

#[test]
fn feature_gated_raw_xml_writer_produces_a_valid_authenticated_control() -> Result<(), Box<dyn Error>> {
    let bytes = authenticated_kdbx4(VALID_MINIMAL_XML)?;
    let report = preflight_kdbx(&bytes, KdbxResourceLimits::default())?;
    assert_eq!(report.major_version, 4);
    assert_eq!(report.minor_version, 1);

    let database = open_kdbx_bounded(
        &bytes,
        DatabaseKey::new().with_password(FIXTURE_PASSWORD),
        KdbxOpenLimits::default(),
    )?;
    assert_eq!(database.root().name, "Root");
    Ok(())
}

#[test]
fn authenticated_malformed_xml_and_identifier_cases_fail_closed_without_panics(
) -> Result<(), Box<dyn Error>> {
    let cases: &[(&str, &[u8])] = &[
        (
            "mismatched-xml-tags",
            br#"<KeePassFile><Meta/><Root><Group><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Name>Root</Name></Root></KeePassFile>"#,
        ),
        (
            "entry-nested-directly-under-root",
            br#"<KeePassFile><Meta/><Root><Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Entry></Root></KeePassFile>"#,
        ),
        (
            "invalid-root-group-uuid",
            br#"<KeePassFile><Meta/><Root><Group><UUID>AA==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#,
        ),
        (
            "duplicate-group-uuid",
            br#"<KeePassFile><Meta/><Root><Group><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Name>Root</Name><Group><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Name>Duplicate</Name></Group></Group></Root></KeePassFile>"#,
        ),
        (
            "duplicate-entry-uuid",
            br#"<KeePassFile><Meta/><Root><Group><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Name>Root</Name><Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Entry><Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Entry></Group></Root></KeePassFile>"#,
        ),
    ];

    for (name, raw_xml) in cases {
        assert_authenticated_engine_rejection(name, raw_xml)?;
    }

    Ok(())
}

from pathlib import Path

ROUNDTRIP_TEST = r'''use std::error::Error;
use std::fs;
use std::io::Error as IoError;
use std::path::PathBuf;

use kdbx_fortress_vault_core::{KdbxOpenLimits, open_kdbx_bounded};
use keepass::{
    Database, DatabaseKey,
    config::DatabaseVersion,
    db::fields,
};

const FIXTURE_PASSWORD: &str = "fixture-password";

fn password_key() -> DatabaseKey {
    DatabaseKey::new().with_password(FIXTURE_PASSWORD)
}

fn open_fixture(bytes: &[u8]) -> Result<Database, Box<dyn Error>> {
    open_kdbx_bounded(bytes, password_key(), KdbxOpenLimits::default())
        .map_err(|error| IoError::other(format!("bounded KDBX open failed: {error:?}")).into())
}

fn maybe_write_interop_artifact(name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let Some(path) = std::env::var_os("FORTRESS_INTEROP_OUTPUT_DIR") else {
        return Ok(());
    };
    let path = PathBuf::from(path);
    fs::create_dir_all(&path)?;
    fs::write(path.join(name), bytes)?;
    Ok(())
}

fn assert_empty_edge_semantics(database: &Database) -> Result<(), Box<dyn Error>> {
    assert_eq!(database.config.version, DatabaseVersion::KDB4(1));
    assert!(
        !database.has_ignored_xml_fields(),
        "accepted empty-edge fixture must not contain ignored XML"
    );

    let root = database.root();
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

    let empty_group = root
        .group_by_path(&["Empty Group"])
        .ok_or_else(|| IoError::other("Empty Group must exist"))?;
    assert!(empty_group.entries().next().is_none());
    assert!(empty_group.groups().next().is_none());
    Ok(())
}

#[test]
fn kdbx41_empty_edge_round_trip_preserves_empty_vs_missing_values() -> Result<(), Box<dyn Error>> {
    let database = open_fixture(include_bytes!(
        "../../../test-fixtures/kdbx/kdbx4-empty-edge.kdbx"
    ))?;
    assert_empty_edge_semantics(&database)?;

    let mut serialized = Vec::new();
    database
        .save(&mut serialized, password_key())
        .map_err(|error| IoError::other(format!("KDBX 4.1 save failed: {error}")))?;
    maybe_write_interop_artifact("empty-edge-41.kdbx", &serialized)?;

    let reopened = open_fixture(&serialized)?;
    assert_empty_edge_semantics(&reopened)
}
'''


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing replacement target: {label}")
    return text.replace(old, new, 1)


Path("rust/vault-core/tests/kdbx_empty_edge_roundtrip.rs").write_text(ROUNDTRIP_TEST)

workflow = Path(".github/workflows/foundation.yml")
text = workflow.read_text()
marker = "\n  empty-edge-fixture-generator:\n"
if marker in text:
    text = text.split(marker, 1)[0].rstrip() + "\n"

if "            empty-edge-41.kdbx\n" not in text:
    text = replace_once(
        text,
        "            history-41.kdbx\n          )",
        "            history-41.kdbx\n            empty-edge-41.kdbx\n          )",
        "KeePassXC list",
    )
if "            'empty-edge-41.kdbx'" not in text:
    text = replace_once(
        text,
        "            'history-41.kdbx'\n          )",
        "            'history-41.kdbx',\n            'empty-edge-41.kdbx'\n          )",
        "KeePass 2.x list",
    )

start = text.find(
    "          & curl.exe --fail --location --retry 3 --retry-delay 2 --output $keepassZip"
)
end_marker = (
    "          Assert-ReferencePackage -Path $kpscriptZip -ExpectedSize 24707 "
    "-ExpectedSha256 '06C9D95332FE7B2730E4E7FD0ABA846C5FA9A1B0CD3119DEFEA9875727A3BFFB'\n"
)
if start != -1:
    end = text.find(end_marker, start)
    if end == -1:
        raise SystemExit("missing reference-download end marker")
    end += len(end_marker)
    verified = r'''          function Get-VerifiedReferencePackage {
            param(
              [Parameter(Mandatory = $true)][string]$BaseUri,
              [Parameter(Mandatory = $true)][string]$Path,
              [Parameter(Mandatory = $true)][long]$ExpectedSize,
              [Parameter(Mandatory = $true)][string]$ExpectedSha256
            )

            for ($attempt = 1; $attempt -le 4; $attempt++) {
              if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
              $separator = if ($BaseUri.Contains('?')) { '&' } else { '?' }
              $uri = "${BaseUri}${separator}fortress_attempt=$attempt"
              & curl.exe --fail --location --retry 2 --retry-all-errors --retry-delay 2 --user-agent 'KDBX-Fortress-CI/1.0' --output $Path $uri
              if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Path)) {
                $item = Get-Item -LiteralPath $Path
                if ($item.Length -eq $ExpectedSize) {
                  $actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
                  if ($actualSha256 -eq $ExpectedSha256) { return }
                }
              }
              Start-Sleep -Seconds (2 * $attempt)
            }
            throw "Unable to obtain verified reference package: $(Split-Path -Leaf $Path)"
          }

          Get-VerifiedReferencePackage -BaseUri 'https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.61.1/KeePass-2.61.1.zip/download?use_mirror=phoenixnap' -Path $keepassZip -ExpectedSize 2898806 -ExpectedSha256 '3952354DB9B117E906F7CD4F9F5591065B95186472370DA47F46F3E246FEA864'
          Get-VerifiedReferencePackage -BaseUri 'https://keepass.info/extensions/v2/kpscript/KPScript-2.61.1.zip' -Path $kpscriptZip -ExpectedSize 24707 -ExpectedSha256 '06C9D95332FE7B2730E4E7FD0ABA846C5FA9A1B0CD3119DEFEA9875727A3BFFB'
'''
    text = text[:start] + verified + text[end:]
workflow.write_text(text)

roadmap = Path("ROADMAP.md")
text = roadmap.read_text()
anchor = (
    "    - [x] Materialize and exercise a generated KDBX 4 fixture requiring a composite password plus "
    "external raw-32-byte key file; validate database/key-file SHA-256 values, sidecar size and "
    "positive/negative credential combinations through the pinned Rust engine.\n"
)
addition = (
    "    - [x] Materialize and exercise a deterministic KDBX 4.1 empty-edge fixture covering "
    "present-but-empty values, absent optional fields, a field-less entry and an empty group; "
    "validate the committed SHA-256 and preserve the distinctions through read, round-trip, "
    "KeePassXC and KeePass 2.x/KPScript checks.\n"
)
if addition not in text:
    text = replace_once(text, anchor, anchor + addition, "ROADMAP empty-edge item")
old = (
    "- Deterministic generated fixtures and executable Rust tests cover KDBX 3.1 and KDBX 4 variants, "
    "including AES-KDF, Argon2d, Argon2id, AES-256-CBC, ChaCha20 outer encryption, protected fields, "
    "Unicode, attachments, `CustomData`, and password + raw-32-byte key-file composite credentials."
)
new = (
    "- Deterministic generated fixtures and executable Rust tests cover KDBX 3.1 and KDBX 4 variants, "
    "including AES-KDF, Argon2d, Argon2id, AES-256-CBC, ChaCha20 outer encryption, protected fields, "
    "Unicode, attachments, `CustomData`, password + raw-32-byte key-file composite credentials, and "
    "empty/missing-field edge semantics."
)
if old in text:
    text = text.replace(old, new, 1)
roadmap.write_text(text)

for temporary in (
    Path(".github/workflows/generate-empty-edge-fixture.yml"),
    Path(".github/workflows/finalize-empty-edge.yml"),
    Path("tools/finalize_empty_edge.py"),
):
    temporary.unlink(missing_ok=True)

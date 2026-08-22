//! Versioned bounded binary wire format for metadata-only JNI reads.

use vault_core::{
    EntrySummary, GroupSummary, MetadataId, MetadataReadError, MetadataReadLimits, VaultCore,
    VaultHandle, VaultSummary,
};

use crate::LifecycleStatus;

pub(crate) const REQUEST_VAULT_SUMMARY: i32 = 1;
pub(crate) const REQUEST_GROUP_SUMMARY: i32 = 2;
pub(crate) const REQUEST_ENTRY_SUMMARY: i32 = 3;

const WIRE_MAGIC: &[u8; 4] = b"KFM1";
const KIND_ERROR: u8 = 0;
const KIND_VAULT: u8 = 1;
const KIND_GROUP: u8 = 2;
const KIND_ENTRY: u8 = 3;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

fn map_error(error: MetadataReadError) -> LifecycleStatus {
    match error {
        MetadataReadError::InvalidHandle => LifecycleStatus::InvalidHandle,
        MetadataReadError::NotFound => LifecycleStatus::NotFound,
        MetadataReadError::LimitExceeded => LifecycleStatus::ResourceLimit,
    }
}

fn envelope(status: LifecycleStatus, kind: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9);
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.extend_from_slice(&(status as i32).to_le_bytes());
    bytes.push(kind);
    bytes
}

pub(crate) fn error_response(status: LifecycleStatus) -> Vec<u8> {
    envelope(status, KIND_ERROR)
}

fn ok_envelope(kind: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.push(kind);
    bytes
}

fn push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), LifecycleStatus> {
    let value = u32::try_from(value).map_err(|_| LifecycleStatus::ResourceLimit)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_id(bytes: &mut Vec<u8>, id: MetadataId) {
    bytes.extend_from_slice(id.as_bytes());
}

fn push_optional_id(bytes: &mut Vec<u8>, id: Option<MetadataId>) {
    match id {
        Some(id) => {
            bytes.push(1);
            push_id(bytes, id);
        }
        None => bytes.push(0),
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), LifecycleStatus> {
    push_u32(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_optional_text(
    bytes: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), LifecycleStatus> {
    match value {
        Some(value) => {
            bytes.push(1);
            push_text(bytes, value)?;
        }
        None => bytes.push(0),
    }
    Ok(())
}

fn finish(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        error_response(LifecycleStatus::ResourceLimit)
    } else {
        bytes
    }
}

fn encode_vault(summary: &VaultSummary) -> Result<Vec<u8>, LifecycleStatus> {
    let mut bytes = ok_envelope(KIND_VAULT);
    push_optional_text(&mut bytes, summary.database_name.as_deref())?;
    push_id(&mut bytes, summary.root_group_id);
    bytes.extend_from_slice(&summary.group_count.to_le_bytes());
    bytes.extend_from_slice(&summary.entry_count.to_le_bytes());
    bytes.extend_from_slice(&summary.attachment_count.to_le_bytes());
    bytes.push(u8::from(summary.has_ignored_xml_fields));
    Ok(finish(bytes))
}

fn encode_group(summary: &GroupSummary) -> Result<Vec<u8>, LifecycleStatus> {
    let mut bytes = ok_envelope(KIND_GROUP);
    push_id(&mut bytes, summary.id);
    push_optional_id(&mut bytes, summary.parent_id);
    push_text(&mut bytes, &summary.name)?;
    push_u32(&mut bytes, summary.child_group_ids.len())?;
    for id in &summary.child_group_ids {
        push_id(&mut bytes, *id);
    }
    push_u32(&mut bytes, summary.entry_ids.len())?;
    for id in &summary.entry_ids {
        push_id(&mut bytes, *id);
    }
    Ok(finish(bytes))
}

fn encode_entry(summary: &EntrySummary) -> Result<Vec<u8>, LifecycleStatus> {
    let mut bytes = ok_envelope(KIND_ENTRY);
    push_id(&mut bytes, summary.id);
    push_id(&mut bytes, summary.parent_group_id);
    push_optional_text(&mut bytes, summary.title.as_deref())?;
    push_optional_text(&mut bytes, summary.username.as_deref())?;
    push_optional_text(&mut bytes, summary.url.as_deref())?;
    push_u32(&mut bytes, summary.tags.len())?;
    for tag in &summary.tags {
        push_text(&mut bytes, tag)?;
    }
    bytes.push(u8::from(summary.has_password));
    bytes.push(u8::from(summary.has_totp));
    bytes.extend_from_slice(&summary.attachment_count.to_le_bytes());
    Ok(finish(bytes))
}

pub(crate) fn read_metadata_response(
    core: &VaultCore,
    handle: VaultHandle,
    request: i32,
    target: Option<MetadataId>,
) -> Vec<u8> {
    let limits = MetadataReadLimits::default();
    let encoded = match request {
        REQUEST_VAULT_SUMMARY if target.is_none() => core
            .read_vault_summary(handle, limits)
            .map_err(map_error)
            .and_then(|summary| encode_vault(&summary)),
        REQUEST_GROUP_SUMMARY => target
            .ok_or(LifecycleStatus::InvalidArgument)
            .and_then(|id| {
                core.read_group_summary(handle, id, limits)
                    .map_err(map_error)
            })
            .and_then(|summary| encode_group(&summary)),
        REQUEST_ENTRY_SUMMARY => target
            .ok_or(LifecycleStatus::InvalidArgument)
            .and_then(|id| {
                core.read_entry_summary(handle, id, limits)
                    .map_err(map_error)
            })
            .and_then(|summary| encode_entry(&summary)),
        _ => Err(LifecycleStatus::InvalidArgument),
    };

    encoded.unwrap_or_else(error_response)
}

#[cfg(test)]
mod tests {
    use super::{
        KIND_ENTRY, KIND_GROUP, KIND_VAULT, REQUEST_ENTRY_SUMMARY, REQUEST_GROUP_SUMMARY,
        REQUEST_VAULT_SUMMARY, WIRE_MAGIC, read_metadata_response,
    };
    use vault_core::{KdbxOpenLimits, MetadataId, VaultCore, VaultCredentials};

    const FIXTURE: &[u8] = include_bytes!("../../../test-fixtures/kdbx/basic-kdbx4.kdbx");
    const PASSWORD: &[u8] = b"fixture-password";

    fn open() -> (VaultCore, vault_core::VaultHandle) {
        let mut core = VaultCore::new(1);
        let credentials = VaultCredentials::new().with_password_bytes(PASSWORD.to_vec());
        let handle = core
            .open_vault(FIXTURE, &credentials, KdbxOpenLimits::default())
            .expect("fixture must open");
        (core, handle)
    }

    fn assert_ok_kind(bytes: &[u8], kind: u8) {
        assert_eq!(&bytes[..4], WIRE_MAGIC);
        assert_eq!(i32::from_le_bytes(bytes[4..8].try_into().expect("status")), 0);
        assert_eq!(bytes[8], kind);
    }

    fn read_id(bytes: &[u8], offset: usize) -> MetadataId {
        MetadataId::from_bytes(bytes[offset..offset + 16].try_into().expect("metadata id"))
    }

    #[test]
    fn wire_returns_bounded_metadata_without_password_value() {
        let (core, handle) = open();
        let vault = read_metadata_response(&core, handle, REQUEST_VAULT_SUMMARY, None);
        assert_ok_kind(&vault, KIND_VAULT);
        assert!(!vault.windows(b"fixture-secret".len()).any(|w| w == b"fixture-secret"));

        let mut root_offset = 10;
        if vault[9] == 1 {
            let name_len = u32::from_le_bytes(vault[10..14].try_into().expect("name length"));
            root_offset = 14 + usize::try_from(name_len).expect("name length fits usize");
        }
        let root_id = read_id(&vault, root_offset);
        let group = read_metadata_response(&core, handle, REQUEST_GROUP_SUMMARY, Some(root_id));
        assert_ok_kind(&group, KIND_GROUP);
        assert!(group.windows(b"Synthetic".len()).any(|w| w == b"Synthetic"));
        assert!(!group.windows(b"fixture-secret".len()).any(|w| w == b"fixture-secret"));

        // Root group: id(16), parent marker(1), name length(4), "Synthetic"(9),
        // child-group count(4), entry count(4), then the first 16-byte entry ID.
        let entry_id = read_id(&group, 9 + 16 + 1 + 4 + 9 + 4 + 4);
        let entry = read_metadata_response(&core, handle, REQUEST_ENTRY_SUMMARY, Some(entry_id));
        assert_ok_kind(&entry, KIND_ENTRY);
        assert!(entry.windows(b"Example Login".len()).any(|w| w == b"Example Login"));
        assert!(entry.windows(b"fixture-user".len()).any(|w| w == b"fixture-user"));
        assert!(!entry.windows(b"fixture-secret".len()).any(|w| w == b"fixture-secret"));
    }

    #[test]
    fn wire_rejects_unknown_request_and_missing_target_without_payload() {
        let (core, handle) = open();
        for response in [
            read_metadata_response(&core, handle, i32::MAX, None),
            read_metadata_response(&core, handle, REQUEST_GROUP_SUMMARY, None),
        ] {
            assert_eq!(&response[..4], WIRE_MAGIC);
            assert!(i32::from_le_bytes(response[4..8].try_into().expect("status")) < 0);
            assert_eq!(response[8], 0);
            assert_eq!(response.len(), 9);
        }
    }
}

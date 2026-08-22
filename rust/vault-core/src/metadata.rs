//! Bounded metadata-only views over Rust-owned decrypted vault state.
//!
//! The types in this module intentionally exclude password values, OTP seeds,
//! notes, custom fields, attachment bytes and the engine's decrypted database
//! model. Callers receive only bounded summaries and opaque 16-byte object IDs.

use keepass::{
    Database,
    db::{fields, EntryRef, GroupRef, Value},
};

/// Fixed byte width of a KeePass object UUID exposed by the metadata API.
pub const METADATA_ID_BYTES: usize = 16;

/// Engine-neutral identifier for one group or entry inside an unlocked vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetadataId([u8; METADATA_ID_BYTES]);

impl MetadataId {
    /// Builds an identifier from its canonical 16 UUID bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; METADATA_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical 16 UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; METADATA_ID_BYTES] {
        &self.0
    }
}

/// Explicit ceilings for one metadata read operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataReadLimits {
    /// Maximum UTF-8 bytes copied for any single title/name/username/URL value.
    pub max_text_bytes: usize,
    /// Maximum number of tags copied from one entry.
    pub max_tags: usize,
    /// Maximum UTF-8 bytes copied for one tag.
    pub max_tag_bytes: usize,
    /// Maximum number of direct child-group IDs returned for one group.
    pub max_child_groups: usize,
    /// Maximum number of direct entry IDs returned for one group.
    pub max_child_entries: usize,
}

impl Default for MetadataReadLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 16 * 1024,
            max_tags: 128,
            max_tag_bytes: 1024,
            max_child_groups: 4096,
            max_child_entries: 4096,
        }
    }
}

/// Sanitized metadata-read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataReadError {
    /// The opaque vault handle is invalid, stale or already locked.
    InvalidHandle,
    /// The requested group or entry identifier does not exist in this vault.
    NotFound,
    /// A configured metadata count/text ceiling would be exceeded.
    LimitExceeded,
}

/// Minimal non-secret vault summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSummary {
    /// Optional database display name.
    pub database_name: Option<String>,
    /// Root-group object identifier.
    pub root_group_id: MetadataId,
    /// Total group count, including the root group.
    pub group_count: u32,
    /// Total entry count.
    pub entry_count: u32,
    /// Total attachment count; attachment bytes are never included.
    pub attachment_count: u32,
    /// Whether the tolerant parser observed unmodeled XML fields.
    pub has_ignored_xml_fields: bool,
}

/// Minimal metadata for one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    /// Group object identifier.
    pub id: MetadataId,
    /// Parent-group identifier, absent for the root group.
    pub parent_id: Option<MetadataId>,
    /// Group display name.
    pub name: String,
    /// Direct child-group identifiers in database order.
    pub child_group_ids: Vec<MetadataId>,
    /// Direct entry identifiers in database order.
    pub entry_ids: Vec<MetadataId>,
}

/// Minimal metadata for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    /// Entry object identifier.
    pub id: MetadataId,
    /// Current parent-group identifier.
    pub parent_group_id: MetadataId,
    /// Optional unprotected entry title. Protected source values are withheld.
    pub title: Option<String>,
    /// Optional unprotected username. Protected source values are withheld.
    pub username: Option<String>,
    /// Optional unprotected URL. Protected source values are withheld.
    pub url: Option<String>,
    /// Entry tags. No custom fields are included.
    pub tags: Vec<String>,
    /// Whether a password field exists. Its value is never inspected here.
    pub has_password: bool,
    /// Whether a raw OTP field exists. Its value is never inspected here.
    pub has_otp: bool,
    /// Attachment count only. Attachment names and bytes are excluded.
    pub attachment_count: u32,
}

fn id_from_group(group: &GroupRef<'_>) -> MetadataId {
    MetadataId::from_bytes(*group.id().uuid().as_bytes())
}

fn id_from_entry(entry: &EntryRef<'_>) -> MetadataId {
    MetadataId::from_bytes(*entry.id().uuid().as_bytes())
}

fn bounded_text(value: &str, maximum: usize) -> Result<String, MetadataReadError> {
    if value.len() > maximum {
        return Err(MetadataReadError::LimitExceeded);
    }
    Ok(value.to_owned())
}

fn bounded_optional_text(
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<String>, MetadataReadError> {
    value.map(|value| bounded_text(value, maximum)).transpose()
}

fn bounded_unprotected_field(
    value: Option<&Value<String>>,
    maximum: usize,
) -> Result<Option<String>, MetadataReadError> {
    match value {
        None | Some(Value::Protected(_)) => Ok(None),
        Some(Value::Unprotected(value)) => bounded_text(value, maximum).map(Some),
    }
}

fn bounded_count(value: usize) -> Result<u32, MetadataReadError> {
    u32::try_from(value).map_err(|_| MetadataReadError::LimitExceeded)
}

pub(crate) fn summarize_vault(
    database: &Database,
    limits: MetadataReadLimits,
) -> Result<VaultSummary, MetadataReadError> {
    let database_name = bounded_optional_text(
        database.meta.database_name.as_deref(),
        limits.max_text_bytes,
    )?;
    let root = database.root();

    Ok(VaultSummary {
        database_name,
        root_group_id: id_from_group(&root),
        group_count: bounded_count(database.num_groups())?,
        entry_count: bounded_count(database.num_entries())?,
        attachment_count: bounded_count(database.num_attachments())?,
        has_ignored_xml_fields: database.has_ignored_xml_fields(),
    })
}

pub(crate) fn summarize_group(
    database: &Database,
    target: MetadataId,
    limits: MetadataReadLimits,
) -> Result<GroupSummary, MetadataReadError> {
    let group = database
        .iter_all_groups()
        .find(|group| id_from_group(group) == target)
        .ok_or(MetadataReadError::NotFound)?;

    let child_group_count = group.group_ids().count();
    if child_group_count > limits.max_child_groups {
        return Err(MetadataReadError::LimitExceeded);
    }
    let entry_count = group.entry_ids().count();
    if entry_count > limits.max_child_entries {
        return Err(MetadataReadError::LimitExceeded);
    }

    let child_group_ids = group
        .group_ids()
        .map(|id| MetadataId::from_bytes(*id.uuid().as_bytes()))
        .collect();
    let entry_ids = group
        .entry_ids()
        .map(|id| MetadataId::from_bytes(*id.uuid().as_bytes()))
        .collect();

    Ok(GroupSummary {
        id: id_from_group(&group),
        parent_id: group.parent().map(|parent| id_from_group(&parent)),
        name: bounded_text(&group.name, limits.max_text_bytes)?,
        child_group_ids,
        entry_ids,
    })
}

pub(crate) fn summarize_entry(
    database: &Database,
    target: MetadataId,
    limits: MetadataReadLimits,
) -> Result<EntrySummary, MetadataReadError> {
    let entry = database
        .iter_all_entries()
        .find(|entry| id_from_entry(entry) == target)
        .ok_or(MetadataReadError::NotFound)?;

    if entry.tags.len() > limits.max_tags {
        return Err(MetadataReadError::LimitExceeded);
    }
    let tags = entry
        .tags
        .iter()
        .map(|tag| bounded_text(tag, limits.max_tag_bytes))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(EntrySummary {
        id: id_from_entry(&entry),
        parent_group_id: id_from_group(&entry.parent()),
        title: bounded_unprotected_field(entry.fields.get(fields::TITLE), limits.max_text_bytes)?,
        username: bounded_unprotected_field(
            entry.fields.get(fields::USERNAME),
            limits.max_text_bytes,
        )?,
        url: bounded_unprotected_field(entry.fields.get(fields::URL), limits.max_text_bytes)?,
        tags,
        has_password: entry.fields.contains_key(fields::PASSWORD),
        has_otp: entry.fields.contains_key(fields::OTP),
        attachment_count: bounded_count(entry.attachments().count())?,
    })
}

#[cfg(test)]
mod tests {
    use super::{MetadataReadError, bounded_unprotected_field};
    use keepass::db::Value;

    #[test]
    fn protected_fields_are_withheld_without_exposing_their_value() {
        let protected = Value::protected("must-not-cross");
        let unprotected = Value::unprotected("visible");

        assert_eq!(bounded_unprotected_field(Some(&protected), 64), Ok(None));
        assert_eq!(
            bounded_unprotected_field(Some(&unprotected), 64),
            Ok(Some("visible".to_owned()))
        );
        assert_eq!(
            bounded_unprotected_field(Some(&unprotected), 3),
            Err(MetadataReadError::LimitExceeded)
        );
        assert_eq!(format!("{protected}"), "[redacted]");
    }
}

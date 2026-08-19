//! Post-decrypt resource validation for an already parsed KDBX database.
//!
//! This module deliberately does not claim to protect the decompression step:
//! `keepass-rs` currently materializes GZip output before returning a `Database`.
//! Production opening therefore remains disabled until that decompression path is
//! bounded inside a Fortress-owned adapter/fork or an upstream hook.

use std::collections::{HashMap, HashSet};

use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, EntryRef, GroupId};

const MIB: u64 = 1024 * 1024;

/// Fortress-owned limits applied to decrypted database structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxPostDecryptLimits {
    pub max_groups: usize,
    pub max_entries: usize,
    pub max_group_depth: usize,
    pub max_fields_per_entry: usize,
    pub max_field_name_bytes: u64,
    pub max_field_bytes: u64,
    pub max_history_entries_per_entry: usize,
    pub max_attachments: usize,
    pub max_attachments_per_entry: usize,
    pub max_attachment_name_bytes: u64,
    pub max_attachment_bytes: u64,
    pub max_total_attachment_bytes: u64,
    pub max_custom_data_items_per_node: usize,
    pub max_custom_data_item_bytes: u64,
}

impl Default for KdbxPostDecryptLimits {
    fn default() -> Self {
        Self {
            max_groups: 10_000,
            max_entries: 100_000,
            max_group_depth: 64,
            max_fields_per_entry: 256,
            max_field_name_bytes: 4 * 1024,
            max_field_bytes: 16 * MIB,
            max_history_entries_per_entry: 128,
            max_attachments: 4_096,
            max_attachments_per_entry: 256,
            max_attachment_name_bytes: 4 * 1024,
            max_attachment_bytes: 64 * MIB,
            max_total_attachment_bytes: 256 * MIB,
            max_custom_data_items_per_node: 256,
            max_custom_data_item_bytes: MIB,
        }
    }
}

/// Non-secret failure returned when decrypted structure exceeds policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxPostDecryptError {
    TooManyGroups { actual: usize, limit: usize },
    TooManyEntries { actual: usize, limit: usize },
    GroupDepthExceeded { actual: usize, limit: usize },
    TooManyFields { actual: usize, limit: usize },
    FieldNameTooLarge { actual: u64, limit: u64 },
    FieldTooLarge { actual: u64, limit: u64 },
    TooManyHistoryEntries { actual: usize, limit: usize },
    TooManyAttachments { actual: usize, limit: usize },
    TooManyEntryAttachments { actual: usize, limit: usize },
    AttachmentNameTooLarge { actual: u64, limit: u64 },
    AttachmentTooLarge { actual: u64, limit: u64 },
    TotalAttachmentBytesExceeded { actual: u64, limit: u64 },
    TooManyCustomDataItems { actual: usize, limit: usize },
    CustomDataItemTooLarge { actual: u64, limit: u64 },
    DuplicateGroupReference,
    InvalidHistoryReference,
    NestedHistory,
    InvalidGroupReference,
    SizeOverflow,
}

/// Validate an already-decrypted database without copying secret values.
///
/// This is a second-stage gate. It complements, but does not replace, the outer
/// header/KDF preflight and the still-required bounded decompression path.
pub fn validate_decrypted_database(
    database: &Database,
    limits: KdbxPostDecryptLimits,
) -> Result<(), KdbxPostDecryptError> {
    let group_count = database.num_groups();
    enforce_count(group_count, limits.max_groups, |actual, limit| {
        KdbxPostDecryptError::TooManyGroups { actual, limit }
    })?;
    enforce_count(
        database.num_entries(),
        limits.max_entries,
        |actual, limit| KdbxPostDecryptError::TooManyEntries { actual, limit },
    )?;
    enforce_count(
        database.num_attachments(),
        limits.max_attachments,
        |actual, limit| KdbxPostDecryptError::TooManyAttachments { actual, limit },
    )?;
    validate_custom_data(&database.meta.custom_data, limits)?;

    let root_id = database.root().id();
    let mut stack: Vec<(GroupId, usize)> = vec![(root_id, 1_usize)];
    let mut visited = HashSet::with_capacity(group_count);
    mark_group_visited(&mut visited, root_id)?;

    while let Some((group_id, depth)) = stack.pop() {
        let group = database
            .group(group_id)
            .ok_or(KdbxPostDecryptError::InvalidGroupReference)?;
        if depth > limits.max_group_depth {
            return Err(KdbxPostDecryptError::GroupDepthExceeded {
                actual: depth,
                limit: limits.max_group_depth,
            });
        }
        validate_custom_data(&group.custom_data, limits)?;
        for child_id in group.group_ids() {
            mark_group_visited(&mut visited, child_id)?;
            stack.push((child_id, next_depth(depth)?));
        }
    }
    if visited.len() != group_count {
        return Err(KdbxPostDecryptError::InvalidGroupReference);
    }

    for entry in database.iter_all_entries() {
        validate_entry_and_history(&entry, limits)?;
    }

    let mut total_attachment_bytes = 0_u64;
    for attachment in database.iter_all_attachments() {
        let size = usize_to_u64(attachment.get().len())?;
        if size > limits.max_attachment_bytes {
            return Err(KdbxPostDecryptError::AttachmentTooLarge {
                actual: size,
                limit: limits.max_attachment_bytes,
            });
        }
        total_attachment_bytes = total_attachment_bytes
            .checked_add(size)
            .ok_or(KdbxPostDecryptError::SizeOverflow)?;
        if total_attachment_bytes > limits.max_total_attachment_bytes {
            return Err(KdbxPostDecryptError::TotalAttachmentBytesExceeded {
                actual: total_attachment_bytes,
                limit: limits.max_total_attachment_bytes,
            });
        }
    }

    Ok(())
}

fn validate_entry_and_history(
    entry: &EntryRef<'_>,
    limits: KdbxPostDecryptLimits,
) -> Result<(), KdbxPostDecryptError> {
    validate_entry_node(entry, limits)?;

    let history_count = entry
        .history
        .as_ref()
        .map_or(0, |history| history.get_entries().len());
    enforce_count(
        history_count,
        limits.max_history_entries_per_entry,
        |actual, limit| KdbxPostDecryptError::TooManyHistoryEntries { actual, limit },
    )?;

    for index in 0..history_count {
        let historical = entry
            .historical(index)
            .ok_or(KdbxPostDecryptError::InvalidHistoryReference)?;
        if historical
            .history
            .as_ref()
            .is_some_and(|history| !history.get_entries().is_empty())
        {
            return Err(KdbxPostDecryptError::NestedHistory);
        }
        validate_entry_node(&historical, limits)?;
    }

    Ok(())
}

fn validate_entry_node(
    entry: &EntryRef<'_>,
    limits: KdbxPostDecryptLimits,
) -> Result<(), KdbxPostDecryptError> {
    enforce_count(
        entry.fields.len(),
        limits.max_fields_per_entry,
        |actual, limit| KdbxPostDecryptError::TooManyFields { actual, limit },
    )?;
    for (name, value) in &entry.fields {
        let name_bytes = usize_to_u64(name.len())?;
        if name_bytes > limits.max_field_name_bytes {
            return Err(KdbxPostDecryptError::FieldNameTooLarge {
                actual: name_bytes,
                limit: limits.max_field_name_bytes,
            });
        }
        let size = checked_size_sum(name_bytes, usize_to_u64(value.get().len())?)?;
        if size > limits.max_field_bytes {
            return Err(KdbxPostDecryptError::FieldTooLarge {
                actual: size,
                limit: limits.max_field_bytes,
            });
        }
    }

    validate_custom_data(&entry.custom_data, limits)?;

    let mut attachment_count = 0_usize;
    for (name, _) in entry.attachments_named() {
        attachment_count = attachment_count
            .checked_add(1)
            .ok_or(KdbxPostDecryptError::SizeOverflow)?;
        let name_bytes = usize_to_u64(name.len())?;
        if name_bytes > limits.max_attachment_name_bytes {
            return Err(KdbxPostDecryptError::AttachmentNameTooLarge {
                actual: name_bytes,
                limit: limits.max_attachment_name_bytes,
            });
        }
    }
    enforce_count(
        attachment_count,
        limits.max_attachments_per_entry,
        |actual, limit| KdbxPostDecryptError::TooManyEntryAttachments { actual, limit },
    )
}

fn validate_custom_data(
    custom_data: &HashMap<String, CustomDataItem>,
    limits: KdbxPostDecryptLimits,
) -> Result<(), KdbxPostDecryptError> {
    enforce_count(
        custom_data.len(),
        limits.max_custom_data_items_per_node,
        |actual, limit| KdbxPostDecryptError::TooManyCustomDataItems { actual, limit },
    )?;

    for (key, item) in custom_data {
        let value_bytes = match &item.value {
            Some(CustomDataValue::String(value)) => usize_to_u64(value.len())?,
            Some(CustomDataValue::Binary(value)) => usize_to_u64(value.len())?,
            None => 0,
        };
        let size = checked_size_sum(usize_to_u64(key.len())?, value_bytes)?;
        if size > limits.max_custom_data_item_bytes {
            return Err(KdbxPostDecryptError::CustomDataItemTooLarge {
                actual: size,
                limit: limits.max_custom_data_item_bytes,
            });
        }
    }

    Ok(())
}

fn mark_group_visited(
    visited: &mut HashSet<GroupId>,
    group_id: GroupId,
) -> Result<(), KdbxPostDecryptError> {
    if visited.insert(group_id) {
        Ok(())
    } else {
        Err(KdbxPostDecryptError::DuplicateGroupReference)
    }
}

fn next_depth(depth: usize) -> Result<usize, KdbxPostDecryptError> {
    depth
        .checked_add(1)
        .ok_or(KdbxPostDecryptError::SizeOverflow)
}

fn checked_size_sum(left: u64, right: u64) -> Result<u64, KdbxPostDecryptError> {
    left.checked_add(right)
        .ok_or(KdbxPostDecryptError::SizeOverflow)
}

fn enforce_count<E>(
    actual: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> E,
) -> Result<(), E> {
    if actual > limit {
        Err(error(actual, limit))
    } else {
        Ok(())
    }
}

fn usize_to_u64(value: usize) -> Result<u64, KdbxPostDecryptError> {
    u64::try_from(value).map_err(|_| KdbxPostDecryptError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use keepass::{
        Database,
        db::{CustomDataItem, CustomDataValue, Entry, Value},
    };

    use super::{
        KdbxPostDecryptError, KdbxPostDecryptLimits, checked_size_sum, mark_group_visited,
        next_depth, validate_decrypted_database,
    };

    #[test]
    fn empty_database_is_within_default_limits() {
        let database = Database::new();
        assert_eq!(
            validate_decrypted_database(&database, KdbxPostDecryptLimits::default()),
            Ok(())
        );
    }

    #[test]
    fn rejects_excessive_group_depth_iteratively() {
        let mut database = Database::new();
        {
            let mut root = database.root_mut();
            root.add_group().add_group().add_group();
        }
        let limits = KdbxPostDecryptLimits {
            max_group_depth: 3,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::GroupDepthExceeded {
                actual: 4,
                limit: 3
            })
        );
    }

    #[test]
    fn rejects_revisited_group_ids_instead_of_looping() {
        let database = Database::new();
        let root_id = database.root().id();
        let mut visited = HashSet::new();

        assert_eq!(mark_group_visited(&mut visited, root_id), Ok(()));
        assert_eq!(
            mark_group_visited(&mut visited, root_id),
            Err(KdbxPostDecryptError::DuplicateGroupReference)
        );
    }

    #[test]
    fn rejects_depth_and_size_overflow() {
        assert_eq!(
            next_depth(usize::MAX),
            Err(KdbxPostDecryptError::SizeOverflow)
        );
        assert_eq!(
            checked_size_sum(u64::MAX, 1),
            Err(KdbxPostDecryptError::SizeOverflow)
        );
    }

    #[test]
    fn rejects_oversized_field_without_exposing_value() {
        let mut database = Database::new();
        database.root_mut().add_entry().fields.insert(
            "Password".to_owned(),
            Value::protected("secret-value".to_owned()),
        );
        let limits = KdbxPostDecryptLimits {
            max_field_bytes: 10,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::FieldTooLarge {
                actual: 20,
                limit: 10
            })
        );
    }

    #[test]
    fn rejects_oversized_field_names() {
        let mut database = Database::new();
        database
            .root_mut()
            .add_entry()
            .fields
            .insert("oversized".to_owned(), Value::unprotected(String::new()));
        let limits = KdbxPostDecryptLimits {
            max_field_name_bytes: 8,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::FieldNameTooLarge {
                actual: 9,
                limit: 8
            })
        );
    }

    #[test]
    fn validates_fields_inside_history_entries() {
        let database = database_with_history_entry(|historical| {
            historical.fields.insert(
                "Password".to_owned(),
                Value::protected("history-secret".to_owned()),
            );
        });
        let limits = KdbxPostDecryptLimits {
            max_field_bytes: 21,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::FieldTooLarge {
                actual: 22,
                limit: 21
            })
        );
    }

    #[test]
    fn rejects_single_oversized_attachment() {
        let mut database = Database::new();
        database
            .root_mut()
            .add_entry()
            .add_attachment("large.bin", Value::unprotected(vec![0_u8; 9]));
        let limits = KdbxPostDecryptLimits {
            max_attachment_bytes: 8,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::AttachmentTooLarge {
                actual: 9,
                limit: 8
            })
        );
    }

    #[test]
    fn rejects_oversized_attachment_names() {
        let mut database = Database::new();
        database
            .root_mut()
            .add_entry()
            .add_attachment("long-name.bin", Value::unprotected(Vec::new()));
        let limits = KdbxPostDecryptLimits {
            max_attachment_name_bytes: 12,
            ..KdbxPostDecryptLimits::default()
        };
        assert_eq!(
            validate_decrypted_database(&database, limits),
            Err(KdbxPostDecryptError::AttachmentNameTooLarge {
                actual: 13,
                limit: 12
            })
        );
    }

    #[test]
    fn validates_custom_data_at_database_group_entry_and_history_levels() {
        let limits = KdbxPostDecryptLimits {
            max_custom_data_item_bytes: 7,
            ..KdbxPostDecryptLimits::default()
        };
        let expected = Err(KdbxPostDecryptError::CustomDataItemTooLarge {
            actual: 8,
            limit: 7,
        });

        let mut database = Database::new();
        database
            .meta
            .custom_data
            .insert("key".to_owned(), string_custom_data("12345"));
        assert_eq!(validate_decrypted_database(&database, limits), expected);

        let mut database = Database::new();
        database
            .root_mut()
            .custom_data
            .insert("key".to_owned(), binary_custom_data(5));
        assert_eq!(validate_decrypted_database(&database, limits), expected);

        let mut database = Database::new();
        database
            .root_mut()
            .add_entry()
            .custom_data
            .insert("key".to_owned(), string_custom_data("12345"));
        assert_eq!(validate_decrypted_database(&database, limits), expected);

        let database = database_with_history_entry(|historical| {
            historical
                .custom_data
                .insert("key".to_owned(), binary_custom_data(5));
        });
        assert_eq!(validate_decrypted_database(&database, limits), expected);
    }

    fn database_with_history_entry(configure: impl FnOnce(&mut Entry)) -> Database {
        let mut database = Database::new();
        {
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            let mut historical = (*entry).clone();
            configure(&mut historical);
            entry.history.get_or_insert_default().add_entry(historical);
        }
        database
    }

    fn string_custom_data(value: &str) -> CustomDataItem {
        CustomDataItem {
            value: Some(CustomDataValue::String(value.to_owned())),
            last_modification_time: None,
        }
    }

    fn binary_custom_data(size: usize) -> CustomDataItem {
        CustomDataItem {
            value: Some(CustomDataValue::Binary(vec![0_u8; size])),
            last_modification_time: None,
        }
    }
}

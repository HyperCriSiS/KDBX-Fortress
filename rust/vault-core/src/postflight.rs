//! Post-decrypt resource validation for an already parsed KDBX database.
//!
//! This module deliberately does not claim to protect the decompression step:
//! `keepass-rs` currently materializes GZip output before returning a `Database`.
//! Production opening therefore remains disabled until that decompression path is
//! bounded inside a Fortress-owned adapter/fork or an upstream hook.

use keepass::Database;

const MIB: u64 = 1024 * 1024;

/// Fortress-owned limits applied to decrypted database structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxPostDecryptLimits {
    pub max_groups: usize,
    pub max_entries: usize,
    pub max_group_depth: usize,
    pub max_fields_per_entry: usize,
    pub max_field_bytes: u64,
    pub max_history_entries_per_entry: usize,
    pub max_attachments: usize,
    pub max_attachments_per_entry: usize,
    pub max_attachment_bytes: u64,
    pub max_total_attachment_bytes: u64,
    pub max_custom_data_items_per_node: usize,
}

impl Default for KdbxPostDecryptLimits {
    fn default() -> Self {
        Self {
            max_groups: 10_000,
            max_entries: 100_000,
            max_group_depth: 64,
            max_fields_per_entry: 256,
            max_field_bytes: 16 * MIB,
            max_history_entries_per_entry: 128,
            max_attachments: 4_096,
            max_attachments_per_entry: 256,
            max_attachment_bytes: 64 * MIB,
            max_total_attachment_bytes: 256 * MIB,
            max_custom_data_items_per_node: 256,
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
    FieldTooLarge { actual: u64, limit: u64 },
    TooManyHistoryEntries { actual: usize, limit: usize },
    TooManyAttachments { actual: usize, limit: usize },
    TooManyEntryAttachments { actual: usize, limit: usize },
    AttachmentTooLarge { actual: u64, limit: u64 },
    TotalAttachmentBytesExceeded { actual: u64, limit: u64 },
    TooManyCustomDataItems { actual: usize, limit: usize },
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
    enforce_count(database.num_groups(), limits.max_groups, |actual, limit| {
        KdbxPostDecryptError::TooManyGroups { actual, limit }
    })?;
    enforce_count(database.num_entries(), limits.max_entries, |actual, limit| {
        KdbxPostDecryptError::TooManyEntries { actual, limit }
    })?;
    enforce_count(
        database.num_attachments(),
        limits.max_attachments,
        |actual, limit| KdbxPostDecryptError::TooManyAttachments { actual, limit },
    )?;

    let mut stack = vec![(database.root(), 1_usize)];
    while let Some((group, depth)) = stack.pop() {
        if depth > limits.max_group_depth {
            return Err(KdbxPostDecryptError::GroupDepthExceeded {
                actual: depth,
                limit: limits.max_group_depth,
            });
        }
        enforce_count(
            group.custom_data.len(),
            limits.max_custom_data_items_per_node,
            |actual, limit| KdbxPostDecryptError::TooManyCustomDataItems { actual, limit },
        )?;
        for child in group.groups() {
            stack.push((child, depth.saturating_add(1)));
        }
    }

    for entry in database.iter_all_entries() {
        enforce_count(
            entry.fields.len(),
            limits.max_fields_per_entry,
            |actual, limit| KdbxPostDecryptError::TooManyFields { actual, limit },
        )?;
        for (name, value) in &entry.fields {
            let size = usize_to_u64(name.len())?
                .checked_add(usize_to_u64(value.get().len())?)
                .ok_or(KdbxPostDecryptError::SizeOverflow)?;
            if size > limits.max_field_bytes {
                return Err(KdbxPostDecryptError::FieldTooLarge {
                    actual: size,
                    limit: limits.max_field_bytes,
                });
            }
        }
        enforce_count(
            entry.custom_data.len(),
            limits.max_custom_data_items_per_node,
            |actual, limit| KdbxPostDecryptError::TooManyCustomDataItems { actual, limit },
        )?;
        let history_count = entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        enforce_count(
            history_count,
            limits.max_history_entries_per_entry,
            |actual, limit| KdbxPostDecryptError::TooManyHistoryEntries { actual, limit },
        )?;
        let attachment_count = entry.attachments_named().count();
        enforce_count(
            attachment_count,
            limits.max_attachments_per_entry,
            |actual, limit| KdbxPostDecryptError::TooManyEntryAttachments { actual, limit },
        )?;
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
    use keepass::{Database, db::Value};

    use super::{KdbxPostDecryptError, KdbxPostDecryptLimits, validate_decrypted_database};

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
}

//! Phase-0 bounded KDBX opening path.
//!
//! This module composes the Fortress preflight, the resource-bounded engine
//! parse/decompression path, and the post-decrypt structure gate. It is not the
//! final JNI/handle API; it exists so the complete parser resource boundary can
//! be exercised before production vault operations are exposed.

use keepass::{
    Database, DatabaseKey,
    db::{DatabaseOpenError, DatabaseOpenLimits, DatabaseResourceLimitError},
};

use crate::{
    KdbxPostDecryptError, KdbxPostDecryptLimits, KdbxPreflightError, KdbxResourceLimits,
    preflight_kdbx, validate_decrypted_database,
};

const MIB: u64 = 1024 * 1024;

/// Fortress-owned limits for the complete Phase-0 KDBX open path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxOpenLimits {
    /// Limits enforced before the selected KDBX engine derives a key or decrypts.
    pub preflight: KdbxResourceLimits,
    /// Maximum bytes produced when expanding the encrypted database payload.
    pub max_decompressed_payload_bytes: u64,
    /// Limits enforced on the decrypted database structure.
    pub post_decrypt: KdbxPostDecryptLimits,
}

impl Default for KdbxOpenLimits {
    fn default() -> Self {
        Self {
            preflight: KdbxResourceLimits::default(),
            max_decompressed_payload_bytes: 512 * MIB,
            post_decrypt: KdbxPostDecryptLimits::default(),
        }
    }
}

/// Typed, non-secret failure returned by the bounded Phase-0 KDBX open path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxOpenError {
    /// The unencrypted preflight rejected the input or declared KDF work.
    Preflight(KdbxPreflightError),
    /// A configured `u64` limit cannot be represented by the current target's `usize`.
    LimitNotRepresentable,
    /// The engine-side input ceiling was exceeded.
    InputTooLarge { max: u64 },
    /// Decompressed database payload exceeded the configured ceiling.
    DecompressedPayloadTooLarge { max: u64 },
    /// A decoded/decompressed binary attachment exceeded the configured ceiling.
    AttachmentTooLarge { max: u64 },
    /// Aggregate decoded/decompressed attachment bytes exceeded the configured ceiling.
    TotalAttachmentBytesTooLarge { max: u64 },
    /// The selected engine rejected the database for a non-resource reason.
    EngineRejected,
    /// The decrypted database structure exceeded a Fortress-owned ceiling.
    PostDecrypt(KdbxPostDecryptError),
}

impl From<KdbxPreflightError> for KdbxOpenError {
    fn from(error: KdbxPreflightError) -> Self {
        Self::Preflight(error)
    }
}

impl From<KdbxPostDecryptError> for KdbxOpenError {
    fn from(error: KdbxPostDecryptError) -> Self {
        Self::PostDecrypt(error)
    }
}

/// Opens a KDBX3/KDBX4 database through all currently required Fortress
/// resource gates.
///
/// The order is deliberate: cheap unencrypted preflight first, then bounded
/// engine parsing/decompression, then decrypted-structure validation. No
/// engine error text or vault field content is copied into the public failure.
pub fn open_kdbx_bounded(
    data: &[u8],
    key: DatabaseKey,
    limits: KdbxOpenLimits,
) -> Result<Database, KdbxOpenError> {
    preflight_kdbx(data, limits.preflight)?;

    let engine_limits = DatabaseOpenLimits {
        max_input_bytes: to_usize(limits.preflight.max_input_bytes)?,
        max_decompressed_payload_bytes: to_usize(limits.max_decompressed_payload_bytes)?,
        max_decompressed_binary_bytes: to_usize(limits.post_decrypt.max_attachment_bytes)?,
        max_total_decompressed_binary_bytes: to_usize(limits.post_decrypt.max_total_attachment_bytes)?,
    };

    let database = Database::parse_with_limits(data, key, engine_limits)
        .map_err(|error| map_engine_error(error, limits))?;

    validate_decrypted_database(&database, limits.post_decrypt)?;
    Ok(database)
}

fn to_usize(value: u64) -> Result<usize, KdbxOpenError> {
    usize::try_from(value).map_err(|_| KdbxOpenError::LimitNotRepresentable)
}

fn map_engine_error(error: DatabaseOpenError, limits: KdbxOpenLimits) -> KdbxOpenError {
    match error {
        DatabaseOpenError::ResourceLimit(DatabaseResourceLimitError::InputBytes { .. }) => {
            KdbxOpenError::InputTooLarge {
                max: limits.preflight.max_input_bytes,
            }
        }
        DatabaseOpenError::ResourceLimit(
            DatabaseResourceLimitError::DecompressedPayloadBytes { .. },
        ) => KdbxOpenError::DecompressedPayloadTooLarge {
            max: limits.max_decompressed_payload_bytes,
        },
        DatabaseOpenError::ResourceLimit(
            DatabaseResourceLimitError::DecompressedBinaryBytes { .. },
        ) => KdbxOpenError::AttachmentTooLarge {
            max: limits.post_decrypt.max_attachment_bytes,
        },
        DatabaseOpenError::ResourceLimit(
            DatabaseResourceLimitError::TotalDecompressedBinaryBytes { .. },
        ) => KdbxOpenError::TotalAttachmentBytesTooLarge {
            max: limits.post_decrypt.max_total_attachment_bytes,
        },
        _ => KdbxOpenError::EngineRejected,
    }
}

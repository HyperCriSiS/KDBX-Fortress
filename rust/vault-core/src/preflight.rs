//! Fortress-owned KDBX preflight validation.
//!
//! This module deliberately parses only the unencrypted KDBX version/outer-header
//! metadata that is required to enforce hard resource ceilings before an
//! expensive key-derivation or decrypt/parse path is entered. It is not a
//! replacement for the selected KDBX engine and it never handles credentials.

const KDBX_SIGNATURE_1: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KDBX_SIGNATURE_2: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];
const VERSION_HEADER_BYTES: usize = 12;

const KDBX3_HEADER_END: u8 = 0;
const KDBX3_TRANSFORM_ROUNDS: u8 = 6;

const KDBX4_HEADER_END: u8 = 0;
const KDBX4_KDF_PARAMETERS: u8 = 11;

const VARIANT_DICTIONARY_VERSION: u16 = 0x0100;
const VARIANT_DICTIONARY_END: u8 = 0x00;
const VARIANT_U32: u8 = 0x04;
const VARIANT_U64: u8 = 0x05;
const VARIANT_BYTES: u8 = 0x42;

const KDF_AES_KDBX3: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const KDF_AES_KDBX4: [u8; 16] = [
    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38,
];
const KDF_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Hard resource ceilings applied before a KDBX parser/decrypt path is entered.
///
/// These are abuse-prevention ceilings, not recommended KDF presets. Device-
/// calibrated UX presets remain a later roadmap item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxResourceLimits {
    /// Maximum accepted encrypted KDBX input size.
    pub max_input_bytes: u64,
    /// Maximum number of bytes scanned as the unencrypted outer header.
    pub max_outer_header_bytes: u64,
    /// Maximum encoded size of the KDBX4 KDF VariantDictionary.
    pub max_kdf_parameter_bytes: u64,
    /// Maximum AES-KDF transform rounds.
    pub max_aes_rounds: u64,
    /// Maximum Argon2 memory request, in bytes.
    pub max_argon2_memory_bytes: u64,
    /// Maximum Argon2 iteration count.
    pub max_argon2_iterations: u64,
    /// Maximum Argon2 degree of parallelism.
    pub max_argon2_parallelism: u32,
    /// Maximum Argon2 memory-by-iteration work budget.
    pub max_argon2_memory_iterations_bytes: u64,
}

impl Default for KdbxResourceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * MIB,
            max_outer_header_bytes: MIB,
            max_kdf_parameter_bytes: 64 * 1024,
            max_aes_rounds: 100_000_000,
            max_argon2_memory_bytes: 512 * MIB,
            max_argon2_iterations: 20,
            max_argon2_parallelism: 8,
            max_argon2_memory_iterations_bytes: 2 * GIB,
        }
    }
}

/// KDF metadata extracted without deriving a key or decrypting vault contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreflight {
    /// AES-KDF as used by KDBX3 or KDBX4.
    Aes {
        /// Declared transform rounds.
        rounds: u64,
    },
    /// Argon2d.
    Argon2d {
        /// Declared memory request in bytes.
        memory_bytes: u64,
        /// Declared iteration count.
        iterations: u64,
        /// Declared degree of parallelism.
        parallelism: u32,
    },
    /// Argon2id.
    Argon2id {
        /// Declared memory request in bytes.
        memory_bytes: u64,
        /// Declared iteration count.
        iterations: u64,
        /// Declared degree of parallelism.
        parallelism: u32,
    },
}

/// Non-secret result of a successful KDBX resource preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxPreflightReport {
    /// KDBX major version found in the version header.
    pub major_version: u16,
    /// KDBX minor version found in the version header.
    pub minor_version: u16,
    /// KDF parameters checked against the supplied resource policy.
    pub kdf: KdfPreflight,
}

/// KDF fields that can be reported without copying untrusted names into errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfField {
    /// `$UUID` KDF identifier.
    Identifier,
    /// `R` AES rounds.
    AesRounds,
    /// `M` Argon2 memory.
    Argon2Memory,
    /// `I` Argon2 iterations.
    Argon2Iterations,
    /// `P` Argon2 parallelism.
    Argon2Parallelism,
}

/// Typed, non-secret failures returned by the preflight boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxPreflightError {
    /// The encrypted input exceeds the configured hard ceiling.
    InputTooLarge { actual: u64, max: u64 },
    /// The input does not have the KDBX signature.
    InvalidSignature,
    /// The version header is incomplete.
    TruncatedVersionHeader,
    /// Only KDBX3 and KDBX4 are currently accepted by the Fortress read plan.
    UnsupportedMajorVersion { major: u16 },
    /// The outer header ended before a complete field could be read.
    TruncatedOuterHeader,
    /// The unencrypted outer header exceeds its scan ceiling.
    OuterHeaderTooLarge { max: u64 },
    /// No KDF metadata was present before the outer-header terminator.
    MissingKdfParameters,
    /// The KDBX4 KDF VariantDictionary itself exceeds its ceiling.
    KdfParametersTooLarge { actual: u64, max: u64 },
    /// The KDBX4 KDF VariantDictionary is malformed or unsupported structurally.
    MalformedKdfParameters,
    /// A required KDF field is absent.
    MissingKdfField { field: KdfField },
    /// A required KDF field has an unexpected encoded type or size.
    InvalidKdfField { field: KdfField },
    /// The KDF UUID is not in the currently accepted KDBX matrix.
    UnsupportedKdf,
    /// AES transform rounds exceed the hard ceiling.
    AesRoundsTooHigh { actual: u64, max: u64 },
    /// Argon2 memory exceeds the hard ceiling.
    Argon2MemoryTooHigh { actual: u64, max: u64 },
    /// Argon2 iterations exceed the hard ceiling.
    Argon2IterationsTooHigh { actual: u64, max: u64 },
    /// Argon2 parallelism exceeds the hard ceiling.
    Argon2ParallelismTooHigh { actual: u32, max: u32 },
    /// The combined Argon2 memory-by-iteration budget exceeds the hard ceiling
    /// or overflows `u64`.
    Argon2WorkTooHigh {
        memory_bytes: u64,
        iterations: u64,
        max_memory_iterations_bytes: u64,
    },
}

/// Checks input size, KDBX version and unencrypted KDF metadata without deriving
/// a key, decrypting payload bytes or invoking the selected KDBX parser.
///
/// Callers that can obtain the encrypted file size before loading it should
/// apply [`check_kdbx_input_size`] first, then call this function on the loaded
/// bytes before any expensive vault operation.
pub fn preflight_kdbx(
    data: &[u8],
    limits: KdbxResourceLimits,
) -> Result<KdbxPreflightReport, KdbxPreflightError> {
    check_kdbx_input_size(data.len() as u64, limits)?;

    if data.len() < VERSION_HEADER_BYTES {
        return Err(KdbxPreflightError::TruncatedVersionHeader);
    }

    if data.get(0..4) != Some(KDBX_SIGNATURE_1.as_slice())
        || data.get(4..8) != Some(KDBX_SIGNATURE_2.as_slice())
    {
        return Err(KdbxPreflightError::InvalidSignature);
    }

    let minor_version = read_u16(data, 8).ok_or(KdbxPreflightError::TruncatedVersionHeader)?;
    let major_version = read_u16(data, 10).ok_or(KdbxPreflightError::TruncatedVersionHeader)?;

    let kdf = match major_version {
        3 => preflight_kdbx3(data, limits)?,
        4 => preflight_kdbx4(data, limits)?,
        major => return Err(KdbxPreflightError::UnsupportedMajorVersion { major }),
    };

    Ok(KdbxPreflightReport {
        major_version,
        minor_version,
        kdf,
    })
}

/// Checks an encrypted KDBX file size before the file is loaded into the vault
/// core. This permits a future SAF/JNI adapter to reject clearly excessive
/// inputs before allocating a full input buffer.
pub fn check_kdbx_input_size(
    input_bytes: u64,
    limits: KdbxResourceLimits,
) -> Result<(), KdbxPreflightError> {
    if input_bytes > limits.max_input_bytes {
        return Err(KdbxPreflightError::InputTooLarge {
            actual: input_bytes,
            max: limits.max_input_bytes,
        });
    }
    Ok(())
}

fn preflight_kdbx3(
    data: &[u8],
    limits: KdbxResourceLimits,
) -> Result<KdfPreflight, KdbxPreflightError> {
    let mut pos = VERSION_HEADER_BYTES;
    let mut rounds = None;

    loop {
        ensure_header_position(pos, limits)?;
        let field_id = *data
            .get(pos)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        let field_len =
            read_u16(data, pos + 1).ok_or(KdbxPreflightError::TruncatedOuterHeader)? as usize;
        let value_start = pos
            .checked_add(3)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        let value_end = value_start
            .checked_add(field_len)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        ensure_header_position(value_end, limits)?;
        let value = data
            .get(value_start..value_end)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        pos = value_end;

        if field_id == KDBX3_HEADER_END {
            break;
        }
        if field_id == KDBX3_TRANSFORM_ROUNDS {
            if rounds.is_some() || value.len() != 8 {
                return Err(KdbxPreflightError::InvalidKdfField {
                    field: KdfField::AesRounds,
                });
            }
            rounds = Some(
                read_u64_from(value).ok_or(KdbxPreflightError::InvalidKdfField {
                    field: KdfField::AesRounds,
                })?,
            );
        }
    }

    let rounds = rounds.ok_or(KdbxPreflightError::MissingKdfParameters)?;
    enforce_aes_rounds(rounds, limits)?;
    Ok(KdfPreflight::Aes { rounds })
}

fn preflight_kdbx4(
    data: &[u8],
    limits: KdbxResourceLimits,
) -> Result<KdfPreflight, KdbxPreflightError> {
    let mut pos = VERSION_HEADER_BYTES;
    let mut kdf = None;

    loop {
        ensure_header_position(pos, limits)?;
        let field_id = *data
            .get(pos)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        let field_len =
            read_u32(data, pos + 1).ok_or(KdbxPreflightError::TruncatedOuterHeader)? as usize;
        let value_start = pos
            .checked_add(5)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        let value_end = value_start
            .checked_add(field_len)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        ensure_header_position(value_end, limits)?;
        let value = data
            .get(value_start..value_end)
            .ok_or(KdbxPreflightError::TruncatedOuterHeader)?;
        pos = value_end;

        if field_id == KDBX4_HEADER_END {
            break;
        }
        if field_id == KDBX4_KDF_PARAMETERS {
            if kdf.is_some() {
                return Err(KdbxPreflightError::MalformedKdfParameters);
            }
            let value_len = value.len() as u64;
            if value_len > limits.max_kdf_parameter_bytes {
                return Err(KdbxPreflightError::KdfParametersTooLarge {
                    actual: value_len,
                    max: limits.max_kdf_parameter_bytes,
                });
            }
            kdf = Some(parse_kdf_variant_dictionary(value, limits)?);
        }
    }

    kdf.ok_or(KdbxPreflightError::MissingKdfParameters)
}

fn ensure_header_position(
    position: usize,
    limits: KdbxResourceLimits,
) -> Result<(), KdbxPreflightError> {
    if position as u64 > limits.max_outer_header_bytes {
        return Err(KdbxPreflightError::OuterHeaderTooLarge {
            max: limits.max_outer_header_bytes,
        });
    }
    Ok(())
}

#[derive(Default)]
struct KdfFields {
    identifier: Option<[u8; 16]>,
    aes_rounds: Option<u64>,
    argon2_memory: Option<u64>,
    argon2_iterations: Option<u64>,
    argon2_parallelism: Option<u32>,
}

fn parse_kdf_variant_dictionary(
    data: &[u8],
    limits: KdbxResourceLimits,
) -> Result<KdfPreflight, KdbxPreflightError> {
    if read_u16(data, 0) != Some(VARIANT_DICTIONARY_VERSION) {
        return Err(KdbxPreflightError::MalformedKdfParameters);
    }

    let mut pos = 2;
    let mut fields = KdfFields::default();

    loop {
        let value_type = *data
            .get(pos)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        pos = pos
            .checked_add(1)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;

        if value_type == VARIANT_DICTIONARY_END {
            if pos != data.len() {
                return Err(KdbxPreflightError::MalformedKdfParameters);
            }
            break;
        }

        let key_len =
            read_u32(data, pos).ok_or(KdbxPreflightError::MalformedKdfParameters)? as usize;
        pos = pos
            .checked_add(4)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        let key_end = pos
            .checked_add(key_len)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        let key = data
            .get(pos..key_end)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        pos = key_end;

        let value_len =
            read_u32(data, pos).ok_or(KdbxPreflightError::MalformedKdfParameters)? as usize;
        pos = pos
            .checked_add(4)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        let value_end = pos
            .checked_add(value_len)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        let value = data
            .get(pos..value_end)
            .ok_or(KdbxPreflightError::MalformedKdfParameters)?;
        pos = value_end;

        match key {
            b"$UUID" => set_identifier(&mut fields, value_type, value)?,
            b"R" => set_u64_field(
                &mut fields.aes_rounds,
                KdfField::AesRounds,
                value_type,
                value,
            )?,
            b"M" => set_u64_field(
                &mut fields.argon2_memory,
                KdfField::Argon2Memory,
                value_type,
                value,
            )?,
            b"I" => set_u64_field(
                &mut fields.argon2_iterations,
                KdfField::Argon2Iterations,
                value_type,
                value,
            )?,
            b"P" => set_u32_field(
                &mut fields.argon2_parallelism,
                KdfField::Argon2Parallelism,
                value_type,
                value,
            )?,
            _ => {}
        }
    }

    let identifier = fields
        .identifier
        .ok_or(KdbxPreflightError::MissingKdfField {
            field: KdfField::Identifier,
        })?;

    if identifier == KDF_AES_KDBX3 || identifier == KDF_AES_KDBX4 {
        let rounds = fields
            .aes_rounds
            .ok_or(KdbxPreflightError::MissingKdfField {
                field: KdfField::AesRounds,
            })?;
        enforce_aes_rounds(rounds, limits)?;
        return Ok(KdfPreflight::Aes { rounds });
    }

    let is_argon2d = identifier == KDF_ARGON2D;
    let is_argon2id = identifier == KDF_ARGON2ID;
    if !is_argon2d && !is_argon2id {
        return Err(KdbxPreflightError::UnsupportedKdf);
    }

    let memory_bytes = fields
        .argon2_memory
        .ok_or(KdbxPreflightError::MissingKdfField {
            field: KdfField::Argon2Memory,
        })?;
    let iterations = fields
        .argon2_iterations
        .ok_or(KdbxPreflightError::MissingKdfField {
            field: KdfField::Argon2Iterations,
        })?;
    let parallelism = fields
        .argon2_parallelism
        .ok_or(KdbxPreflightError::MissingKdfField {
            field: KdfField::Argon2Parallelism,
        })?;

    enforce_argon2(memory_bytes, iterations, parallelism, limits)?;

    if is_argon2d {
        Ok(KdfPreflight::Argon2d {
            memory_bytes,
            iterations,
            parallelism,
        })
    } else {
        Ok(KdfPreflight::Argon2id {
            memory_bytes,
            iterations,
            parallelism,
        })
    }
}

fn set_identifier(
    fields: &mut KdfFields,
    value_type: u8,
    value: &[u8],
) -> Result<(), KdbxPreflightError> {
    if fields.identifier.is_some() || value_type != VARIANT_BYTES || value.len() != 16 {
        return Err(KdbxPreflightError::InvalidKdfField {
            field: KdfField::Identifier,
        });
    }
    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(value);
    fields.identifier = Some(identifier);
    Ok(())
}

fn set_u64_field(
    target: &mut Option<u64>,
    field: KdfField,
    value_type: u8,
    value: &[u8],
) -> Result<(), KdbxPreflightError> {
    if target.is_some() || value_type != VARIANT_U64 || value.len() != 8 {
        return Err(KdbxPreflightError::InvalidKdfField { field });
    }
    *target = Some(read_u64_from(value).ok_or(KdbxPreflightError::InvalidKdfField { field })?);
    Ok(())
}

fn set_u32_field(
    target: &mut Option<u32>,
    field: KdfField,
    value_type: u8,
    value: &[u8],
) -> Result<(), KdbxPreflightError> {
    if target.is_some() || value_type != VARIANT_U32 || value.len() != 4 {
        return Err(KdbxPreflightError::InvalidKdfField { field });
    }
    *target = Some(read_u32_from(value).ok_or(KdbxPreflightError::InvalidKdfField { field })?);
    Ok(())
}

fn enforce_aes_rounds(rounds: u64, limits: KdbxResourceLimits) -> Result<(), KdbxPreflightError> {
    if rounds > limits.max_aes_rounds {
        return Err(KdbxPreflightError::AesRoundsTooHigh {
            actual: rounds,
            max: limits.max_aes_rounds,
        });
    }
    Ok(())
}

fn enforce_argon2(
    memory_bytes: u64,
    iterations: u64,
    parallelism: u32,
    limits: KdbxResourceLimits,
) -> Result<(), KdbxPreflightError> {
    if memory_bytes > limits.max_argon2_memory_bytes {
        return Err(KdbxPreflightError::Argon2MemoryTooHigh {
            actual: memory_bytes,
            max: limits.max_argon2_memory_bytes,
        });
    }
    if iterations > limits.max_argon2_iterations {
        return Err(KdbxPreflightError::Argon2IterationsTooHigh {
            actual: iterations,
            max: limits.max_argon2_iterations,
        });
    }
    if parallelism > limits.max_argon2_parallelism {
        return Err(KdbxPreflightError::Argon2ParallelismTooHigh {
            actual: parallelism,
            max: limits.max_argon2_parallelism,
        });
    }

    let within_work_budget = memory_bytes
        .checked_mul(iterations)
        .is_some_and(|work| work <= limits.max_argon2_memory_iterations_bytes);
    if !within_work_budget {
        return Err(KdbxPreflightError::Argon2WorkTooHigh {
            memory_bytes,
            iterations,
            max_memory_iterations_bytes: limits.max_argon2_memory_iterations_bytes,
        });
    }
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_from(data: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn read_u32_from(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

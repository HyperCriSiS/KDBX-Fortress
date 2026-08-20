//! Fortress-owned credential buffers.
//!
//! Password and key-file bytes stay in Rust-owned zeroizing allocations until
//! the narrow conversion into the KDBX engine's `DatabaseKey`. The engine key
//! is itself zeroized on drop by the pinned Fortress `keepass-rs` fork.

use std::{fmt, io::Cursor};

use keepass::DatabaseKey;
use zeroize::Zeroizing;

/// Owned secret byte buffer that is wiped when dropped.
///
/// The type intentionally exposes no plaintext `Debug`, `Display`, cloning, or
/// string conversion. Future JNI code should transfer credential bytes into
/// this type as early as possible and avoid long-lived Kotlin `String` copies.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of a byte buffer and arranges for it to be zeroized on
    /// every normal Rust drop path.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the secret without allocating another copy.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns whether the secret buffer is empty without exposing its value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([redacted])")
    }
}

/// Credentials supplied to a bounded KDBX open operation.
///
/// No `Clone` implementation is provided deliberately: callers must make an
/// explicit new secret allocation if they truly need another copy.
#[derive(Default)]
pub struct VaultCredentials {
    password: Option<SecretBytes>,
    keyfile: Option<SecretBytes>,
}

impl VaultCredentials {
    /// Creates an empty credential set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds UTF-8 password bytes without creating a `String` at this boundary.
    #[must_use]
    pub fn with_password_bytes(mut self, password: Vec<u8>) -> Self {
        self.password = Some(SecretBytes::new(password));
        self
    }

    /// Adds raw key-file bytes.
    #[must_use]
    pub fn with_keyfile_bytes(mut self, keyfile: Vec<u8>) -> Self {
        self.keyfile = Some(SecretBytes::new(keyfile));
        self
    }

    /// Returns whether no password or key-file material is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.keyfile.is_none()
    }

    pub(crate) fn to_database_key(&self) -> Result<DatabaseKey, VaultCredentialError> {
        let mut key = DatabaseKey::new();

        if let Some(password) = &self.password {
            let password = std::str::from_utf8(password.as_slice())
                .map_err(|_| VaultCredentialError::PasswordNotUtf8)?;
            key = key.with_password(password);
        }

        if let Some(keyfile) = &self.keyfile {
            let mut cursor = Cursor::new(keyfile.as_slice());
            key = key
                .with_keyfile(&mut cursor)
                .map_err(|_| VaultCredentialError::KeyfileRead)?;
        }

        Ok(key)
    }
}

impl fmt::Debug for VaultCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultCredentials")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("keyfile", &self.keyfile.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Typed, non-secret credential conversion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCredentialError {
    /// KeePass passwords are textual; the supplied password bytes were not UTF-8.
    PasswordNotUtf8,
    /// Reading the in-memory key-file bytes into the engine key failed.
    KeyfileRead,
}

#[cfg(test)]
mod tests {
    use super::{VaultCredentialError, VaultCredentials};

    #[test]
    fn debug_output_never_contains_credentials() {
        let credentials = VaultCredentials::new()
            .with_password_bytes(b"fortress-password-sentinel".to_vec())
            .with_keyfile_bytes(b"fortress-keyfile-sentinel".to_vec());

        let debug = format!("{credentials:?}");
        assert!(!debug.contains("fortress-password-sentinel"));
        assert!(!debug.contains("fortress-keyfile-sentinel"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn invalid_password_encoding_is_typed_and_non_secret() {
        let credentials = VaultCredentials::new().with_password_bytes(vec![0xff, 0xfe, 0xfd]);

        assert_eq!(
            credentials.to_database_key(),
            Err(VaultCredentialError::PasswordNotUtf8)
        );
    }

    #[test]
    fn credential_presence_is_reported_without_exposing_values() {
        assert!(VaultCredentials::new().is_empty());
        assert!(
            !VaultCredentials::new()
                .with_password_bytes(Vec::new())
                .is_empty()
        );
    }
}

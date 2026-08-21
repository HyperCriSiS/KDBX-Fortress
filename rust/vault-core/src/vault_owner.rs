//! Concrete Rust-owned unlocked-vault lifecycle boundary.
//!
//! This module is deliberately platform-neutral. It retains decrypted KDBX
//! state only inside a bounded Rust registry and exposes opaque generation-
//! checked handles. JNI and metadata/secret query APIs are separate later
//! tranches.

use keepass::Database;

use crate::{
    KdbxOpenError, KdbxOpenLimits, VaultCredentials, VaultHandle, VaultHandleError,
    handle_registry::VaultHandleRegistry, open_kdbx_bounded_with_credentials,
};

/// Failure returned by the concrete Rust vault owner.
///
/// Variants intentionally carry only typed, non-secret Fortress errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCoreError {
    /// Bounded KDBX opening failed before a live vault handle was created.
    Open(KdbxOpenError),
    /// The configured unlocked-vault registry has no usable capacity left.
    CapacityExceeded,
    /// A handle was structurally invalid, stale, locked, or otherwise unusable.
    InvalidHandle,
}

impl From<VaultHandleError> for VaultCoreError {
    fn from(error: VaultHandleError) -> Self {
        match error {
            VaultHandleError::CapacityExceeded => Self::CapacityExceeded,
            VaultHandleError::InvalidHandle => Self::InvalidHandle,
        }
    }
}

/// Private owner for one decrypted KDBX database.
///
/// The field is intentionally not exposed. Dropping the session drops the
/// engine `Database`, whose Fortress fork now zeroizes the defined owned secret
/// buffers. The remaining process-memory non-guarantees are documented in
/// `docs/SECRET_MEMORY.md`.
struct VaultSession {
    _database: Database,
}

/// Process-local owner for unlocked vault sessions.
///
/// `VaultCore` has explicit capacity and contains no global state. Callers own
/// one instance and receive only opaque [`VaultHandle`] values for opened
/// vaults. Decrypted database state never crosses this boundary.
pub struct VaultCore {
    sessions: VaultHandleRegistry<VaultSession>,
}

impl VaultCore {
    /// Creates an empty vault owner with an explicit maximum number of live
    /// unlocked sessions.
    #[must_use]
    pub const fn new(max_open_vaults: u32) -> Self {
        Self {
            sessions: VaultHandleRegistry::new(max_open_vaults),
        }
    }

    /// Opens and validates a KDBX database and retains it behind an opaque
    /// generation-checked handle.
    ///
    /// Resource preflight, bounded engine parsing/decompression and post-
    /// decrypt structure validation all complete before a handle is exposed.
    /// If registry insertion fails, the freshly opened `Database` is dropped
    /// before this method returns the capacity error.
    pub fn open_vault(
        &mut self,
        data: &[u8],
        credentials: &VaultCredentials,
        limits: KdbxOpenLimits,
    ) -> Result<VaultHandle, VaultCoreError> {
        let database = open_kdbx_bounded_with_credentials(data, credentials, limits)
            .map_err(VaultCoreError::Open)?;
        self.sessions
            .insert(VaultSession {
                _database: database,
            })
            .map_err(VaultCoreError::from)
    }

    /// Returns whether `handle` currently identifies a live Rust-owned vault.
    ///
    /// This is process-local lifecycle state only. It does not expose registry
    /// slot details or decrypted vault content.
    #[must_use]
    pub fn is_handle_valid(&self, handle: VaultHandle) -> bool {
        self.sessions.is_valid(handle)
    }

    /// Idempotently locks one vault.
    ///
    /// A live session is dropped immediately and its generation is advanced.
    /// Invalid, stale, and already-locked handles are indistinguishable no-ops.
    pub fn lock_vault(&mut self, handle: VaultHandle) {
        self.sessions.lock(handle);
    }

    /// Idempotently locks every live vault owned by this core instance.
    pub fn lock_all(&mut self) {
        self.sessions.lock_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{VaultCore, VaultCoreError};
    use crate::{KdbxOpenLimits, VaultCredentials};

    const FIXTURE: &[u8] = include_bytes!("../../../test-fixtures/kdbx/basic-kdbx4.kdbx");
    const PASSWORD: &[u8] = b"fixture-password";

    fn credentials() -> VaultCredentials {
        VaultCredentials::new().with_password_bytes(PASSWORD.to_vec())
    }

    #[test]
    fn open_retains_decrypted_state_only_behind_a_live_handle() {
        let mut core = VaultCore::new(2);
        let handle = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("valid bounded fixture must open behind a handle");

        assert!(core.is_handle_valid(handle));
    }

    #[test]
    fn lock_is_idempotent_and_stale_handle_never_revives_after_reopen() {
        let mut core = VaultCore::new(1);
        let first = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("first fixture open must succeed");

        core.lock_vault(first);
        core.lock_vault(first);
        assert!(!core.is_handle_valid(first));

        let second = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("vacated slot must be reusable with a new generation");

        assert_ne!(first, second);
        assert!(!core.is_handle_valid(first));
        assert!(core.is_handle_valid(second));
    }

    #[test]
    fn lock_all_invalidates_every_live_vault() {
        let mut core = VaultCore::new(2);
        let first = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("first fixture open must succeed");
        let second = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("second fixture open must succeed");

        core.lock_all();
        core.lock_all();

        assert!(!core.is_handle_valid(first));
        assert!(!core.is_handle_valid(second));
    }

    #[test]
    fn capacity_failure_does_not_disturb_existing_live_vault() {
        let mut core = VaultCore::new(1);
        let first = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("first fixture open must succeed");

        let error = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect_err("second live vault must exceed explicit capacity");

        assert_eq!(error, VaultCoreError::CapacityExceeded);
        assert!(core.is_handle_valid(first));
    }

    #[test]
    fn rejected_credentials_never_create_a_live_handle() {
        let mut core = VaultCore::new(1);
        let wrong = VaultCredentials::new().with_password_bytes(b"wrong-password".to_vec());

        let error = core
            .open_vault(FIXTURE, &wrong, KdbxOpenLimits::default())
            .expect_err("wrong password must fail before a handle is exposed");

        assert!(matches!(error, VaultCoreError::Open(_)));
    }
}

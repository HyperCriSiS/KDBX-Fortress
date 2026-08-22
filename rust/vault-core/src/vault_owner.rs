//! Concrete Rust-owned unlocked-vault lifecycle boundary.
//!
//! This module is deliberately platform-neutral. It retains decrypted KDBX
//! state only inside a bounded Rust registry and exposes opaque generation-
//! checked handles. JNI adapter exposure and explicit secret-query APIs remain
//! separate, deliberately gated tranches.

use keepass::Database;

use crate::{
    EntrySummary, GroupSummary, KdbxOpenError, KdbxOpenLimits, MetadataId, MetadataReadError,
    MetadataReadLimits, VaultCredentials, VaultHandle, VaultHandleError, VaultSummary,
    handle_registry::VaultHandleRegistry, metadata, open_kdbx_bounded_with_credentials,
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
    database: Database,
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
            .insert(VaultSession { database })
            .map_err(VaultCoreError::from)
    }

    /// Returns a bounded metadata-only summary for one live vault.
    pub fn read_vault_summary(
        &self,
        handle: VaultHandle,
        limits: MetadataReadLimits,
    ) -> Result<VaultSummary, MetadataReadError> {
        let session = self
            .sessions
            .get(handle)
            .map_err(|_| MetadataReadError::InvalidHandle)?;
        metadata::summarize_vault(&session.database, limits)
    }

    /// Returns a bounded metadata-only summary for one group in a live vault.
    pub fn read_group_summary(
        &self,
        handle: VaultHandle,
        group_id: MetadataId,
        limits: MetadataReadLimits,
    ) -> Result<GroupSummary, MetadataReadError> {
        let session = self
            .sessions
            .get(handle)
            .map_err(|_| MetadataReadError::InvalidHandle)?;
        metadata::summarize_group(&session.database, group_id, limits)
    }

    /// Returns a bounded metadata-only summary for one entry in a live vault.
    pub fn read_entry_summary(
        &self,
        handle: VaultHandle,
        entry_id: MetadataId,
        limits: MetadataReadLimits,
    ) -> Result<EntrySummary, MetadataReadError> {
        let session = self
            .sessions
            .get(handle)
            .map_err(|_| MetadataReadError::InvalidHandle)?;
        metadata::summarize_entry(&session.database, entry_id, limits)
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
    use crate::{
        KdbxOpenLimits, MetadataId, MetadataReadError, MetadataReadLimits, VaultCredentials,
    };

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

    #[test]
    fn metadata_summary_exposes_identity_without_secret_values() {
        let mut core = VaultCore::new(1);
        let handle = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("fixture must open");
        let limits = MetadataReadLimits::default();

        let vault = core
            .read_vault_summary(handle, limits)
            .expect("vault summary must be available");
        assert_eq!(vault.group_count, 2);
        assert_eq!(vault.entry_count, 1);
        assert_eq!(vault.attachment_count, 0);

        let root = core
            .read_group_summary(handle, vault.root_group_id, limits)
            .expect("root summary must be available");
        assert_eq!(root.id, vault.root_group_id);
        assert!(root.parent_id.is_none());
        assert_eq!(root.child_group_ids.len(), 1);
        assert!(root.entry_ids.is_empty());

        let group = core
            .read_group_summary(handle, root.child_group_ids[0], limits)
            .expect("synthetic group summary must be available");
        assert_eq!(group.parent_id, Some(root.id));
        assert_eq!(group.name, "Synthetic");
        assert!(group.child_group_ids.is_empty());
        assert_eq!(group.entry_ids.len(), 1);

        let entry = core
            .read_entry_summary(handle, group.entry_ids[0], limits)
            .expect("entry summary must be available");
        assert_eq!(entry.parent_group_id, group.id);
        assert_eq!(entry.title.as_deref(), Some("Example Login"));
        assert_eq!(entry.username.as_deref(), Some("fixture-user"));
        assert_eq!(entry.url.as_deref(), Some("https://example.test"));
        assert!(entry.has_password);
        assert!(!entry.has_totp);
        assert_eq!(entry.attachment_count, 0);

        let rendered = format!("{entry:?}");
        assert!(!rendered.contains("fixture-secret"));
    }

    #[test]
    fn metadata_reads_reject_stale_and_unknown_ids_without_disturbing_session() {
        let mut core = VaultCore::new(1);
        let handle = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("fixture must open");
        let limits = MetadataReadLimits::default();
        let missing = MetadataId::from_bytes([0xA5; 16]);

        assert_eq!(
            core.read_group_summary(handle, missing, limits),
            Err(MetadataReadError::NotFound)
        );
        assert!(core.is_handle_valid(handle));

        core.lock_vault(handle);
        assert_eq!(
            core.read_vault_summary(handle, limits),
            Err(MetadataReadError::InvalidHandle)
        );
    }

    #[test]
    fn metadata_text_and_child_limits_fail_closed() {
        let mut core = VaultCore::new(1);
        let handle = core
            .open_vault(FIXTURE, &credentials(), KdbxOpenLimits::default())
            .expect("fixture must open");
        let vault = core
            .read_vault_summary(handle, MetadataReadLimits::default())
            .expect("vault summary must be available");
        let root = core
            .read_group_summary(handle, vault.root_group_id, MetadataReadLimits::default())
            .expect("root summary must be available");
        let group_id = root.child_group_ids[0];

        let limits = MetadataReadLimits {
            max_text_bytes: 4,
            ..MetadataReadLimits::default()
        };
        assert_eq!(
            core.read_group_summary(handle, group_id, limits),
            Err(MetadataReadError::LimitExceeded)
        );

        let limits = MetadataReadLimits {
            max_child_entries: 0,
            ..MetadataReadLimits::default()
        };
        assert_eq!(
            core.read_group_summary(handle, group_id, limits),
            Err(MetadataReadError::LimitExceeded)
        );
        assert!(core.is_handle_valid(handle));
    }
}

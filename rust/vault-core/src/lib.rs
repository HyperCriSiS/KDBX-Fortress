//! Platform-neutral Rust vault-core boundary.
//!
//! Phase 0 keeps production KDBX decryption, vault parsing, JNI, Android,
//! persistence, and networking disabled. The core may inspect non-secret outer-
//! header metadata only to enforce Fortress-owned resource limits before any
//! expensive KDF/decrypt path is entered.

mod bounded_open;
mod handle_registry;
mod postflight;
mod preflight;

pub use bounded_open::{KdbxOpenError, KdbxOpenLimits, open_kdbx_bounded};
pub use handle_registry::{VaultHandle, VaultHandleError};
pub use postflight::{KdbxPostDecryptError, KdbxPostDecryptLimits, validate_decrypted_database};
pub use preflight::{
    KdbxPreflightError, KdbxPreflightReport, KdbxResourceLimits, KdfField, KdfPreflight,
    check_kdbx_input_size, preflight_kdbx,
};

/// ABI contract version exposed to future platform adapters.
///
/// The value changes only when the adapter contract becomes incompatible.
pub const CORE_ABI_VERSION: u32 = 1;

/// Non-secret capabilities that a platform adapter may query without opening a
/// vault or creating a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreCapabilities {
    /// Current adapter/core ABI contract version.
    pub abi_version: u32,
}

/// Returns non-secret core capabilities.
#[must_use]
pub const fn capabilities() -> CoreCapabilities {
    CoreCapabilities {
        abi_version: CORE_ABI_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use super::{CORE_ABI_VERSION, capabilities};

    #[test]
    fn capabilities_report_current_abi_version() {
        let reported = capabilities();
        assert_eq!(reported.abi_version, CORE_ABI_VERSION);
    }
}

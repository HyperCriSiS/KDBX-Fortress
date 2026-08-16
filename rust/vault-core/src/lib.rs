//! Platform-neutral Rust vault-core boundary.
//!
//! Phase 1 intentionally contains no vault parsing, cryptography, JNI, Android,
//! persistence, or networking. This crate exists to make the trust boundary
//! mechanically testable before feature code enters it.

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

//! Narrow Android/JNI adapter for KDBX Fortress.
//!
//! This first interop tranche intentionally exposes only non-secret capability
//! information. It does not create a vault owner, accept credentials, expose a
//! [`vault_core::VaultHandle`], or move decrypted state across JNI.

use jni::{
    EnvUnowned,
    objects::JClass,
    sys::{jint, jlong},
};
use std::panic::{UnwindSafe, catch_unwind};

/// ABI version of this Android/JNI adapter contract.
pub const ADAPTER_ABI_VERSION: u32 = 1;

/// Capability request for the platform-neutral vault-core ABI version.
pub const CAPABILITY_CORE_ABI_VERSION: jint = 1;
/// Capability request for the Android/JNI adapter ABI version.
pub const CAPABILITY_ADAPTER_ABI_VERSION: jint = 2;

/// Stable status codes encoded in the upper 32 bits of a capability response.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterStatus {
    /// Request completed successfully; the lower 32 bits contain the value.
    Ok = 0,
    /// The requested capability selector is not part of this adapter ABI.
    UnsupportedRequest = 1,
    /// A Rust panic was contained before it could cross the JNI boundary.
    PanicContained = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilityResponse {
    status: AdapterStatus,
    value: u32,
}

impl CapabilityResponse {
    const fn ok(value: u32) -> Self {
        Self {
            status: AdapterStatus::Ok,
            value,
        }
    }

    const fn error(status: AdapterStatus) -> Self {
        Self { status, value: 0 }
    }

    const fn encode(self) -> jlong {
        ((self.status as jlong) << 32) | (self.value as jlong)
    }
}

const fn capability_response(request: jint) -> CapabilityResponse {
    match request {
        CAPABILITY_CORE_ABI_VERSION => {
            CapabilityResponse::ok(vault_core::capabilities().abi_version)
        }
        CAPABILITY_ADAPTER_ABI_VERSION => CapabilityResponse::ok(ADAPTER_ABI_VERSION),
        _ => CapabilityResponse::error(AdapterStatus::UnsupportedRequest),
    }
}

fn guarded_response<F>(operation: F) -> jlong
where
    F: FnOnce() -> CapabilityResponse + UnwindSafe,
{
    match catch_unwind(operation) {
        Ok(response) => response.encode(),
        Err(_) => CapabilityResponse::error(AdapterStatus::PanicContained).encode(),
    }
}

/// Non-secret JNI capability probe.
///
/// Kotlin/Java contract:
///
/// - class: `world.w3b.kdbxfortress.bridge.NativeBridge`
/// - method: `private static native long nativeCapabilityProbe(int request)`
/// - response upper 32 bits: stable [`AdapterStatus`] code
/// - response lower 32 bits: unsigned capability value when status is `Ok`
///
/// No JNI object is dereferenced and no JNI call is made in this smoke boundary.
/// The environment/class parameters are present only because the JVM supplies
/// them for a static native method.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeCapabilityProbe<
    'local,
>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jint,
) -> jlong {
    guarded_response(|| capability_response(request))
}

#[cfg(test)]
mod tests {
    use super::{
        ADAPTER_ABI_VERSION, AdapterStatus, CAPABILITY_ADAPTER_ABI_VERSION,
        CAPABILITY_CORE_ABI_VERSION, CapabilityResponse, capability_response, guarded_response,
    };

    const fn decode(encoded: i64) -> (u32, u32) {
        (((encoded as u64) >> 32) as u32, encoded as u32)
    }

    #[test]
    fn reports_core_abi_without_secret_state() {
        let (status, value) = decode(capability_response(CAPABILITY_CORE_ABI_VERSION).encode());
        assert_eq!(status, AdapterStatus::Ok as u32);
        assert_eq!(value, vault_core::capabilities().abi_version);
    }

    #[test]
    fn reports_adapter_abi() {
        let (status, value) = decode(capability_response(CAPABILITY_ADAPTER_ABI_VERSION).encode());
        assert_eq!(status, AdapterStatus::Ok as u32);
        assert_eq!(value, ADAPTER_ABI_VERSION);
    }

    #[test]
    fn unsupported_request_has_stable_sanitized_mapping() {
        let (status, value) = decode(capability_response(i32::MAX).encode());
        assert_eq!(status, AdapterStatus::UnsupportedRequest as u32);
        assert_eq!(value, 0);
    }

    #[test]
    fn panic_is_contained_and_mapped_without_payload() {
        let encoded = guarded_response(|| -> CapabilityResponse { panic!("synthetic panic") });
        let (status, value) = decode(encoded);
        assert_eq!(status, AdapterStatus::PanicContained as u32);
        assert_eq!(value, 0);
    }

    #[test]
    fn status_codes_are_frozen_for_the_first_adapter_abi() {
        assert_eq!(AdapterStatus::Ok as u32, 0);
        assert_eq!(AdapterStatus::UnsupportedRequest as u32, 1);
        assert_eq!(AdapterStatus::PanicContained as u32, 2);
    }
}

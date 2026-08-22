//! Narrow Android/JNI adapter for KDBX Fortress.
//!
//! The adapter exposes only non-secret capabilities and the bounded vault
//! lifecycle operations required to keep decrypted database state inside Rust.
//! Kotlin receives opaque process-local handles and stable sanitized status
//! codes; no database snapshots, entry fields, or secret strings cross JNI.

use jni::{
    EnvUnowned, Outcome,
    objects::{JByteArray, JClass},
    sys::{jint, jlong},
};
use std::{
    panic::{AssertUnwindSafe, UnwindSafe, catch_unwind},
    sync::Mutex,
};
use vault_core::{
    KdbxOpenError, KdbxOpenLimits, KdbxPreflightError, VaultCore, VaultCoreError, VaultCredentials,
    VaultHandle,
};

/// ABI version of this Android/JNI adapter contract.
pub const ADAPTER_ABI_VERSION: u32 = 3;

/// Maximum number of simultaneously unlocked vaults owned by the Android adapter.
const MAX_OPEN_VAULTS: u32 = 4;
/// Hard ceiling for password bytes copied across JNI.
const MAX_PASSWORD_BYTES: usize = 4 * 1024;
/// Hard ceiling for key-file bytes copied across JNI.
const MAX_KEYFILE_BYTES: usize = 1024 * 1024;

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

/// Stable negative lifecycle result codes.
///
/// `nativeOpenVault` returns a positive opaque handle on success and one of
/// these negative values on failure. `nativeLockVault` returns zero on success
/// and a negative value on failure. `nativeIsVaultHandleValid` returns one for
/// a live handle, zero for an invalid/stale handle, and a negative value only
/// for an internal adapter failure.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStatus {
    InvalidArgument = -1,
    JniError = -2,
    InvalidCredentialMaterial = -3,
    InvalidInput = -4,
    UnsupportedFormat = -5,
    ResourceLimit = -6,
    OpenRejected = -7,
    CapacityExceeded = -8,
    InvalidHandle = -9,
    Internal = -10,
    PanicContained = -11,
}

impl LifecycleStatus {
    const fn as_jint(self) -> jint {
        self as jint
    }

    const fn as_jlong(self) -> jlong {
        self as jlong
    }
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

static VAULT_CORE: Mutex<VaultCore> = Mutex::new(VaultCore::new(MAX_OPEN_VAULTS));

const fn capability_response(request: jint) -> CapabilityResponse {
    match request {
        CAPABILITY_CORE_ABI_VERSION => {
            CapabilityResponse::ok(vault_core::capabilities().abi_version)
        }
        CAPABILITY_ADAPTER_ABI_VERSION => CapabilityResponse::ok(ADAPTER_ABI_VERSION),
        _ => CapabilityResponse::error(AdapterStatus::UnsupportedRequest),
    }
}

fn guarded_capability_response<F>(operation: F) -> jlong
where
    F: FnOnce() -> CapabilityResponse + UnwindSafe,
{
    match catch_unwind(operation) {
        Ok(response) => response.encode(),
        Err(_) => CapabilityResponse::error(AdapterStatus::PanicContained).encode(),
    }
}

fn guarded_jint<F>(operation: F) -> jint
where
    F: FnOnce() -> jint + UnwindSafe,
{
    match catch_unwind(operation) {
        Ok(response) => response,
        Err(_) => LifecycleStatus::PanicContained.as_jint(),
    }
}

fn with_core_mutex<T>(
    owner: &Mutex<VaultCore>,
    operation: impl FnOnce(&mut VaultCore) -> T,
) -> Result<T, LifecycleStatus> {
    let mut core = match owner.lock() {
        Ok(core) => core,
        Err(poisoned) => {
            // A panic while the owner mutex was held may have left the session
            // registry in an unknown intermediate state. Fail closed: drop every
            // Rust-owned decrypted database before clearing poison.
            let mut core = poisoned.into_inner();
            core.lock_all();
            drop(core);
            owner.clear_poison();
            return Err(LifecycleStatus::Internal);
        }
    };

    match catch_unwind(AssertUnwindSafe(|| operation(&mut core))) {
        Ok(value) => Ok(value),
        Err(_) => {
            // Contain panics while the owner is still held so no decrypted
            // session survives the failing operation and the mutex is not
            // poisoned by this controlled boundary.
            core.lock_all();
            Err(LifecycleStatus::PanicContained)
        }
    }
}

fn with_vault_core<T>(operation: impl FnOnce(&mut VaultCore) -> T) -> Result<T, LifecycleStatus> {
    with_core_mutex(&VAULT_CORE, operation)
}

fn map_open_error(error: VaultCoreError) -> LifecycleStatus {
    match error {
        VaultCoreError::CapacityExceeded => LifecycleStatus::CapacityExceeded,
        VaultCoreError::InvalidHandle => LifecycleStatus::InvalidHandle,
        VaultCoreError::Open(error) => match error {
            KdbxOpenError::Credential(_) => LifecycleStatus::InvalidCredentialMaterial,
            KdbxOpenError::Preflight(
                KdbxPreflightError::UnsupportedMajorVersion { .. }
                | KdbxPreflightError::UnsupportedKdf,
            ) => LifecycleStatus::UnsupportedFormat,
            KdbxOpenError::Preflight(
                KdbxPreflightError::InputTooLarge { .. }
                | KdbxPreflightError::OuterHeaderTooLarge { .. }
                | KdbxPreflightError::KdfParametersTooLarge { .. }
                | KdbxPreflightError::AesRoundsTooHigh { .. }
                | KdbxPreflightError::Argon2MemoryTooHigh { .. }
                | KdbxPreflightError::Argon2IterationsTooHigh { .. }
                | KdbxPreflightError::Argon2ParallelismTooHigh { .. }
                | KdbxPreflightError::Argon2WorkTooHigh { .. },
            )
            | KdbxOpenError::LimitNotRepresentable
            | KdbxOpenError::InputTooLarge { .. }
            | KdbxOpenError::DecompressedPayloadTooLarge { .. }
            | KdbxOpenError::AttachmentTooLarge { .. }
            | KdbxOpenError::TotalAttachmentBytesTooLarge { .. }
            | KdbxOpenError::PostDecrypt(_) => LifecycleStatus::ResourceLimit,
            KdbxOpenError::Preflight(_) => LifecycleStatus::InvalidInput,
            KdbxOpenError::EngineRejected => LifecycleStatus::OpenRejected,
        },
    }
}

fn open_vault_on_core(core: &mut VaultCore, data: &[u8], credentials: &VaultCredentials) -> jlong {
    match core.open_vault(data, credentials, KdbxOpenLimits::default()) {
        Ok(handle) => jlong::try_from(handle.as_raw())
            .ok()
            .filter(|raw| *raw > 0)
            .unwrap_or_else(|| LifecycleStatus::Internal.as_jlong()),
        Err(error) => map_open_error(error).as_jlong(),
    }
}

fn open_vault_response(data: &[u8], credentials: VaultCredentials) -> jlong {
    match with_vault_core(|core| open_vault_on_core(core, data, &credentials)) {
        Ok(response) => response,
        Err(status) => status.as_jlong(),
    }
}

fn decode_handle(raw: jlong) -> Result<VaultHandle, LifecycleStatus> {
    if raw <= 0 {
        return Err(LifecycleStatus::InvalidHandle);
    }

    VaultHandle::from_raw(raw as u64).map_err(|_| LifecycleStatus::InvalidHandle)
}

fn lock_vault_on_core(core: &mut VaultCore, raw: jlong) -> jint {
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(status) => return status.as_jint(),
    };

    core.lock_vault(handle);
    0
}

fn lock_vault_response(raw: jlong) -> jint {
    match with_vault_core(|core| lock_vault_on_core(core, raw)) {
        Ok(response) => response,
        Err(status) => status.as_jint(),
    }
}

fn is_handle_valid_on_core(core: &VaultCore, raw: jlong) -> jint {
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(_) => return 0,
    };

    if core.is_handle_valid(handle) { 1 } else { 0 }
}

fn is_handle_valid_response(raw: jlong) -> jint {
    match with_vault_core(|core| is_handle_valid_on_core(core, raw)) {
        Ok(response) => response,
        Err(status) => status.as_jint(),
    }
}

fn lock_all_vaults_response() -> jint {
    match with_vault_core(VaultCore::lock_all) {
        Ok(()) => 0,
        Err(status) => status.as_jint(),
    }
}

/// Non-secret JNI capability probe.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeCapabilityProbe<
    'local,
>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jint,
) -> jlong {
    guarded_capability_response(|| capability_response(request))
}

/// Opens one bounded KDBX byte buffer and retains decrypted state only in Rust.
///
/// `password` and `keyfile` are nullable Java `byte[]` references. Their Rust
/// copies are moved directly into zeroizing `VaultCredentials` allocations.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeOpenVault<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    kdbx: JByteArray<'local>,
    password: JByteArray<'local>,
    keyfile: JByteArray<'local>,
) -> jlong {
    let outcome = env.with_env(|env| -> jni::errors::Result<jlong> {
        if kdbx.as_raw().is_null() {
            return Ok(LifecycleStatus::InvalidArgument.as_jlong());
        }

        let limits = KdbxOpenLimits::default();
        if kdbx.len(env)? as u64 > limits.preflight.max_input_bytes {
            return Ok(LifecycleStatus::ResourceLimit.as_jlong());
        }
        if !password.as_raw().is_null() && password.len(env)? > MAX_PASSWORD_BYTES {
            return Ok(LifecycleStatus::ResourceLimit.as_jlong());
        }
        if !keyfile.as_raw().is_null() && keyfile.len(env)? > MAX_KEYFILE_BYTES {
            return Ok(LifecycleStatus::ResourceLimit.as_jlong());
        }

        let data = env.convert_byte_array(&kdbx)?;
        let mut credentials = VaultCredentials::new();

        if !password.as_raw().is_null() {
            credentials = credentials.with_password_bytes(env.convert_byte_array(&password)?);
        }
        if !keyfile.as_raw().is_null() {
            credentials = credentials.with_keyfile_bytes(env.convert_byte_array(&keyfile)?);
        }

        Ok(open_vault_response(&data, credentials))
    });

    match outcome.into_outcome() {
        Outcome::Ok(response) => response,
        Outcome::Err(_) => LifecycleStatus::JniError.as_jlong(),
        Outcome::Panic(_) => LifecycleStatus::PanicContained.as_jlong(),
    }
}

/// Idempotently locks one structurally valid opaque vault handle.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeLockVault<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jint {
    guarded_jint(|| lock_vault_response(handle))
}

/// Returns `1` for a live handle, `0` for invalid/stale handles, or a negative
/// stable lifecycle code for an internal adapter failure.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeIsVaultHandleValid<
    'local,
>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jint {
    guarded_jint(|| is_handle_valid_response(handle))
}

/// Locks every live Rust-owned vault. Intended for Android lifecycle transitions
/// such as the app moving to the background. The operation is idempotent.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeLockAllVaults<
    'local,
>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jint {
    guarded_jint(lock_all_vaults_response)
}

#[cfg(test)]
mod tests {
    use super::{
        ADAPTER_ABI_VERSION, AdapterStatus, CAPABILITY_ADAPTER_ABI_VERSION,
        CAPABILITY_CORE_ABI_VERSION, CapabilityResponse, LifecycleStatus, capability_response,
        guarded_capability_response, guarded_jint, is_handle_valid_on_core, lock_vault_on_core,
        map_open_error, open_vault_on_core, with_core_mutex,
    };
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Mutex,
    };
    use vault_core::{
        KdbxOpenError, KdbxPreflightError, VaultCore, VaultCoreError, VaultCredentials,
    };

    const FIXTURE: &[u8] = include_bytes!("../../../test-fixtures/kdbx/basic-kdbx4.kdbx");
    const PASSWORD: &[u8] = b"fixture-password";

    fn credentials() -> VaultCredentials {
        VaultCredentials::new().with_password_bytes(PASSWORD.to_vec())
    }

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
        let encoded =
            guarded_capability_response(|| -> CapabilityResponse { panic!("synthetic panic") });
        let (status, value) = decode(encoded);
        assert_eq!(status, AdapterStatus::PanicContained as u32);
        assert_eq!(value, 0);
    }

    #[test]
    fn lifecycle_panic_is_contained_without_payload() {
        let status = guarded_jint(|| -> i32 { panic!("synthetic lifecycle panic") });
        assert_eq!(status, LifecycleStatus::PanicContained as i32);
    }

    #[test]
    fn invalid_and_stale_handles_stay_sanitized_across_slot_reuse() {
        let mut core = VaultCore::new(1);

        assert_eq!(
            lock_vault_on_core(&mut core, 0),
            LifecycleStatus::InvalidHandle as i32
        );
        assert_eq!(
            lock_vault_on_core(&mut core, -1),
            LifecycleStatus::InvalidHandle as i32
        );
        assert_eq!(is_handle_valid_on_core(&core, 0), 0);
        assert_eq!(is_handle_valid_on_core(&core, -1), 0);

        let first = open_vault_on_core(&mut core, FIXTURE, &credentials());
        assert!(first > 0);
        assert_eq!(is_handle_valid_on_core(&core, first), 1);
        assert_eq!(lock_vault_on_core(&mut core, first), 0);
        assert_eq!(is_handle_valid_on_core(&core, first), 0);

        let second = open_vault_on_core(&mut core, FIXTURE, &credentials());
        assert!(second > 0);
        assert_ne!(first, second);
        assert_eq!(is_handle_valid_on_core(&core, first), 0);
        assert_eq!(is_handle_valid_on_core(&core, second), 1);

        // Repeating a lock with the stale generation remains an idempotent no-op
        // and must never disturb the newly reused slot.
        assert_eq!(lock_vault_on_core(&mut core, first), 0);
        assert_eq!(is_handle_valid_on_core(&core, second), 1);
    }

    #[test]
    fn owner_operation_panic_locks_all_immediately_without_poisoning() {
        let owner = Mutex::new(VaultCore::new(1));
        let handle = with_core_mutex(&owner, |core| {
            open_vault_on_core(core, FIXTURE, &credentials())
        })
        .expect("healthy owner must accept fixture");
        assert!(handle > 0);

        let panic_status = with_core_mutex(&owner, |_| -> () {
            panic!("synthetic panic inside owner operation");
        });
        assert_eq!(panic_status, Err(LifecycleStatus::PanicContained));
        assert!(!owner.is_poisoned());

        let live = with_core_mutex(&owner, |core| is_handle_valid_on_core(core, handle))
            .expect("owner must remain usable after contained panic");
        assert_eq!(live, 0);
    }

    #[test]
    fn poisoned_owner_fails_closed_before_recovering() {
        let owner = Mutex::new(VaultCore::new(1));
        let handle = with_core_mutex(&owner, |core| {
            open_vault_on_core(core, FIXTURE, &credentials())
        })
        .expect("healthy owner must accept fixture");
        assert!(handle > 0);

        let poison = catch_unwind(AssertUnwindSafe(|| {
            let _guard = owner.lock().expect("owner must start unpoisoned");
            panic!("synthetic panic while vault owner is held");
        }));
        assert!(poison.is_err());
        assert!(owner.is_poisoned());

        let recovery = with_core_mutex(&owner, |_| 1);
        assert_eq!(recovery, Err(LifecycleStatus::Internal));
        assert!(!owner.is_poisoned());

        let live = with_core_mutex(&owner, |core| is_handle_valid_on_core(core, handle))
            .expect("cleared owner must be usable after fail-closed recovery");
        assert_eq!(live, 0);
    }

    #[test]
    fn lifecycle_error_mapping_is_sanitized() {
        assert_eq!(
            map_open_error(VaultCoreError::Open(KdbxOpenError::Preflight(
                KdbxPreflightError::UnsupportedKdf,
            ))),
            LifecycleStatus::UnsupportedFormat
        );
        assert_eq!(
            map_open_error(VaultCoreError::Open(KdbxOpenError::EngineRejected)),
            LifecycleStatus::OpenRejected
        );
        assert_eq!(
            map_open_error(VaultCoreError::CapacityExceeded),
            LifecycleStatus::CapacityExceeded
        );
    }

    #[test]
    fn status_codes_are_frozen_for_adapter_abi_three() {
        assert_eq!(ADAPTER_ABI_VERSION, 3);
        assert_eq!(AdapterStatus::Ok as u32, 0);
        assert_eq!(AdapterStatus::UnsupportedRequest as u32, 1);
        assert_eq!(AdapterStatus::PanicContained as u32, 2);
        assert_eq!(LifecycleStatus::InvalidArgument as i32, -1);
        assert_eq!(LifecycleStatus::JniError as i32, -2);
        assert_eq!(LifecycleStatus::InvalidCredentialMaterial as i32, -3);
        assert_eq!(LifecycleStatus::InvalidInput as i32, -4);
        assert_eq!(LifecycleStatus::UnsupportedFormat as i32, -5);
        assert_eq!(LifecycleStatus::ResourceLimit as i32, -6);
        assert_eq!(LifecycleStatus::OpenRejected as i32, -7);
        assert_eq!(LifecycleStatus::CapacityExceeded as i32, -8);
        assert_eq!(LifecycleStatus::InvalidHandle as i32, -9);
        assert_eq!(LifecycleStatus::Internal as i32, -10);
        assert_eq!(LifecycleStatus::PanicContained as i32, -11);
    }
}

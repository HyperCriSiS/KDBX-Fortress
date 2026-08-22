//! Opaque vault-handle representation and generation-checked session registry.
//!
//! The registry is intentionally staged before production `open_vault`
//! integration. Keeping it compiled in non-test builds lets the handle contract
//! stabilize without exposing decrypted KDBX state yet.

#![cfg_attr(not(test), allow(dead_code))]

use std::{error::Error, fmt};

const SLOT_TOKEN_MASK: u64 = 0xffff_ffff;
const GENERATION_SHIFT: u32 = 32;
const FIRST_GENERATION: u32 = 1;
const MAX_GENERATION: u32 = i32::MAX as u32;

/// Opaque process-local identifier for an unlocked vault session.
///
/// The numeric representation is intentionally not a pointer. It contains a
/// one-based slot token and a generation value so a handle copied before lock
/// cannot become valid again when the same registry slot is reused.
///
/// Handles are not authentication secrets, but callers must still treat them as
/// process-local capabilities: do not persist, log, export, or place them in
/// Android intents/bundles. Raw values are guaranteed to fit in a positive JNI
/// `jlong` / Kotlin `Long`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultHandle(u64);

impl VaultHandle {
    /// Returns the opaque positive integer representation for a future FFI
    /// adapter.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }

    /// Reconstructs a structurally valid handle received from an untrusted
    /// bridge caller.
    ///
    /// This validates only the representation. Liveness and generation are
    /// checked by the registry for every operation.
    pub fn from_raw(raw: u64) -> Result<Self, VaultHandleError> {
        let slot_token = raw & SLOT_TOKEN_MASK;
        let generation = raw >> GENERATION_SHIFT;

        if slot_token == 0 || generation == 0 || generation > u64::from(MAX_GENERATION) {
            return Err(VaultHandleError::InvalidHandle);
        }

        Ok(Self(raw))
    }

    fn encode(slot_index: u32, generation: u32) -> Result<Self, VaultHandleError> {
        if generation == 0 || generation > MAX_GENERATION {
            return Err(VaultHandleError::InvalidHandle);
        }

        let slot_token = slot_index
            .checked_add(1)
            .ok_or(VaultHandleError::CapacityExceeded)?;
        let raw = (u64::from(generation) << GENERATION_SHIFT) | u64::from(slot_token);
        Self::from_raw(raw)
    }

    fn parts(self) -> Result<(u32, u32), VaultHandleError> {
        let raw = self.0;
        let slot_token =
            u32::try_from(raw & SLOT_TOKEN_MASK).map_err(|_| VaultHandleError::InvalidHandle)?;
        let generation =
            u32::try_from(raw >> GENERATION_SHIFT).map_err(|_| VaultHandleError::InvalidHandle)?;
        let slot_index = slot_token
            .checked_sub(1)
            .ok_or(VaultHandleError::InvalidHandle)?;

        if generation == 0 || generation > MAX_GENERATION {
            return Err(VaultHandleError::InvalidHandle);
        }

        Ok((slot_index, generation))
    }
}

impl fmt::Debug for VaultHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultHandle(<opaque>)")
    }
}

impl TryFrom<u64> for VaultHandle {
    type Error = VaultHandleError;

    fn try_from(raw: u64) -> Result<Self, Self::Error> {
        Self::from_raw(raw)
    }
}

impl From<VaultHandle> for u64 {
    fn from(handle: VaultHandle) -> Self {
        handle.as_raw()
    }
}

/// Stable handle-registry failure categories suitable for later mapping to the
/// bridge-level `VaultError` contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHandleError {
    /// The raw handle is malformed, refers to no live slot, or has a stale
    /// generation.
    InvalidHandle,
    /// The explicitly bounded registry cannot accept another live vault.
    CapacityExceeded,
}

impl fmt::Display for VaultHandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => formatter.write_str("invalid or stale vault handle"),
            Self::CapacityExceeded => {
                formatter.write_str("vault handle registry capacity exceeded")
            }
        }
    }
}

impl Error for VaultHandleError {}

#[derive(Debug)]
struct Slot<T> {
    generation: u32,
    value: Option<T>,
    retired: bool,
}

/// Rust-owned registry for unlocked vault state.
///
/// `max_slots` is explicit so the eventual production owner cannot create an
/// unbounded number of unlocked sessions accidentally. A linear vacant-slot
/// scan is deliberate: the expected vault count is tiny, and avoiding a second
/// free-list allocation makes lock invalidation allocation-free and prevents
/// duplicate-free-list bookkeeping bugs.
#[derive(Debug)]
pub(crate) struct VaultHandleRegistry<T> {
    slots: Vec<Slot<T>>,
    max_slots: u32,
}

impl<T> VaultHandleRegistry<T> {
    pub(crate) const fn new(max_slots: u32) -> Self {
        Self {
            slots: Vec::new(),
            max_slots,
        }
    }

    pub(crate) fn insert(&mut self, value: T) -> Result<VaultHandle, VaultHandleError> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.retired && slot.value.is_none() {
                let slot_index =
                    u32::try_from(index).map_err(|_| VaultHandleError::CapacityExceeded)?;
                let handle = VaultHandle::encode(slot_index, slot.generation)?;
                slot.value = Some(value);
                return Ok(handle);
            }
        }

        let slot_index =
            u32::try_from(self.slots.len()).map_err(|_| VaultHandleError::CapacityExceeded)?;
        if slot_index >= self.max_slots {
            return Err(VaultHandleError::CapacityExceeded);
        }

        self.slots
            .try_reserve(1)
            .map_err(|_| VaultHandleError::CapacityExceeded)?;
        let handle = VaultHandle::encode(slot_index, FIRST_GENERATION)?;
        self.slots.push(Slot {
            generation: FIRST_GENERATION,
            value: Some(value),
            retired: false,
        });
        Ok(handle)
    }

    pub(crate) fn get(&self, handle: VaultHandle) -> Result<&T, VaultHandleError> {
        let (slot_index, generation) = handle.parts()?;
        let index = usize::try_from(slot_index).map_err(|_| VaultHandleError::InvalidHandle)?;
        let slot = self
            .slots
            .get(index)
            .ok_or(VaultHandleError::InvalidHandle)?;

        if slot.retired || slot.generation != generation {
            return Err(VaultHandleError::InvalidHandle);
        }

        slot.value.as_ref().ok_or(VaultHandleError::InvalidHandle)
    }

    pub(crate) fn get_mut(&mut self, handle: VaultHandle) -> Result<&mut T, VaultHandleError> {
        let (slot_index, generation) = handle.parts()?;
        let index = usize::try_from(slot_index).map_err(|_| VaultHandleError::InvalidHandle)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(VaultHandleError::InvalidHandle)?;

        if slot.retired || slot.generation != generation {
            return Err(VaultHandleError::InvalidHandle);
        }

        slot.value.as_mut().ok_or(VaultHandleError::InvalidHandle)
    }

    pub(crate) fn is_valid(&self, handle: VaultHandle) -> bool {
        self.get(handle).is_ok()
    }

    /// Idempotently locks one handle and drops its Rust-owned value immediately.
    ///
    /// Invalid, stale, already-locked, and structurally impossible handles are
    /// all no-ops. This matches the lifecycle contract that callers may repeat a
    /// lock request safely without learning additional state from an error.
    pub(crate) fn lock(&mut self, handle: VaultHandle) {
        let Ok((slot_index, generation)) = handle.parts() else {
            return;
        };
        let Ok(index) = usize::try_from(slot_index) else {
            return;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };

        if slot.retired || slot.generation != generation || slot.value.is_none() {
            return;
        }

        slot.value = None;
        Self::advance_or_retire(slot);
    }

    /// Idempotently drops every live Rust-owned vault value and invalidates all
    /// outstanding handles.
    pub(crate) fn lock_all(&mut self) {
        for slot in &mut self.slots {
            if slot.retired || slot.value.is_none() {
                continue;
            }

            slot.value = None;
            Self::advance_or_retire(slot);
        }
    }

    fn advance_or_retire(slot: &mut Slot<T>) {
        match slot.generation.checked_add(1) {
            Some(next) if next <= MAX_GENERATION => slot.generation = next,
            _ => slot.retired = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::{MAX_GENERATION, Slot, VaultHandle, VaultHandleError, VaultHandleRegistry};

    #[derive(Debug)]
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn raw_handle_validation_rejects_reserved_and_negative_jlong_encodings() {
        assert_eq!(
            VaultHandle::from_raw(0),
            Err(VaultHandleError::InvalidHandle)
        );
        assert_eq!(
            VaultHandle::from_raw(1),
            Err(VaultHandleError::InvalidHandle)
        );
        assert_eq!(
            VaultHandle::from_raw(1_u64 << 32),
            Err(VaultHandleError::InvalidHandle)
        );
        assert_eq!(
            VaultHandle::from_raw(u64::MAX),
            Err(VaultHandleError::InvalidHandle)
        );

        let valid = VaultHandle::from_raw((1_u64 << 32) | 1)
            .expect("well-formed first-slot handle must decode");
        assert_eq!(valid.as_raw(), (1_u64 << 32) | 1);
        assert!(valid.as_raw() <= i64::MAX as u64);
        assert_eq!(format!("{valid:?}"), "VaultHandle(<opaque>)");
    }

    #[test]
    fn lock_is_idempotent_and_drops_the_value_immediately() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut registry = VaultHandleRegistry::new(1);
        let handle = registry
            .insert(DropProbe(Arc::clone(&drops)))
            .expect("first slot must be available");

        assert!(registry.is_valid(handle));
        registry.lock(handle);
        assert!(!registry.is_valid(handle));
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        registry.lock(handle);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_handle_never_revives_when_a_slot_is_reused() {
        let mut registry = VaultHandleRegistry::new(1);
        let first = registry.insert("first").expect("first insert must succeed");
        registry.lock(first);

        let second = registry
            .insert("second")
            .expect("vacated slot must be reusable");
        assert_ne!(first, second);
        assert_eq!(registry.get(first), Err(VaultHandleError::InvalidHandle));
        assert_eq!(registry.get(second), Ok(&"second"));
    }

    #[test]
    fn mutable_access_requires_the_current_generation() {
        let mut registry = VaultHandleRegistry::new(1);
        let handle = registry.insert(String::from("before")).expect("insert");
        registry
            .get_mut(handle)
            .expect("live handle")
            .push_str("-after");
        assert_eq!(registry.get(handle).map(String::as_str), Ok("before-after"));
    }

    #[test]
    fn explicit_capacity_limit_fails_without_disturbing_live_state() {
        let mut registry = VaultHandleRegistry::new(1);
        let live = registry.insert("live").expect("first insert must succeed");

        assert_eq!(
            registry.insert("rejected"),
            Err(VaultHandleError::CapacityExceeded)
        );
        assert_eq!(registry.get(live), Ok(&"live"));
    }

    #[test]
    fn lock_all_invalidates_and_drops_every_live_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut registry = VaultHandleRegistry::new(2);
        let first = registry
            .insert(DropProbe(Arc::clone(&drops)))
            .expect("first insert");
        let second = registry
            .insert(DropProbe(Arc::clone(&drops)))
            .expect("second insert");

        registry.lock_all();
        assert!(!registry.is_valid(first));
        assert!(!registry.is_valid(second));
        assert_eq!(drops.load(Ordering::SeqCst), 2);

        registry.lock_all();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn deterministic_model_sequences_preserve_handle_invariants() {
        use std::collections::HashSet;

        const CAPACITY: usize = 4;
        const STEPS: usize = 20_000;

        let mut registry = VaultHandleRegistry::new(CAPACITY as u32);
        let mut live: Vec<(VaultHandle, u64)> = Vec::new();
        let mut stale: Vec<VaultHandle> = Vec::new();
        let mut seen = HashSet::new();
        let mut next_value = 1_u64;
        let mut state = 0x4d59_5df4_d0f3_3173_u64;

        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        for step in 0..STEPS {
            let selector = next(&mut state);

            match selector % 6 {
                0 => {
                    if live.len() < CAPACITY {
                        let value = next_value;
                        next_value = next_value.wrapping_add(1);
                        let handle = registry
                            .insert(value)
                            .expect("model insert within capacity");
                        assert!(seen.insert(handle), "a raw handle must never be reissued");
                        live.push((handle, value));
                    } else {
                        assert_eq!(
                            registry.insert(next_value),
                            Err(VaultHandleError::CapacityExceeded)
                        );
                    }
                }
                1 if !live.is_empty() => {
                    let index = (next(&mut state) as usize) % live.len();
                    let (handle, _) = live.swap_remove(index);
                    registry.lock(handle);
                    stale.push(handle);
                }
                2 if !stale.is_empty() => {
                    let handle = stale[(next(&mut state) as usize) % stale.len()];
                    registry.lock(handle);
                    assert_eq!(registry.get(handle), Err(VaultHandleError::InvalidHandle));
                }
                3 => {
                    for (handle, _) in live.drain(..) {
                        stale.push(handle);
                    }
                    registry.lock_all();
                }
                4 if !live.is_empty() => {
                    let index = (next(&mut state) as usize) % live.len();
                    let (handle, expected) = live[index];
                    let value = registry.get_mut(handle).expect("model live handle");
                    *value = value.wrapping_add(1);
                    live[index].1 = expected.wrapping_add(1);
                }
                _ => {}
            }

            assert!(live.len() <= CAPACITY);
            for (handle, expected) in &live {
                assert!(registry.is_valid(*handle));
                assert_eq!(registry.get(*handle), Ok(expected));
            }

            if !stale.is_empty() {
                let handle = stale[(next(&mut state) as usize) % stale.len()];
                assert!(!registry.is_valid(handle));
                assert_eq!(registry.get(handle), Err(VaultHandleError::InvalidHandle));
            }

            if step % 257 == 0 {
                for handle in &stale {
                    assert!(!registry.is_valid(*handle));
                }
            }
        }
    }

    #[test]
    fn deterministic_raw_handle_fuzz_never_accepts_reserved_or_negative_encodings() {
        let registry = VaultHandleRegistry::<u8>::new(4);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;

        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        for _ in 0..100_000 {
            let raw = next(&mut state);
            match VaultHandle::from_raw(raw) {
                Ok(handle) => {
                    assert_eq!(handle.as_raw(), raw);
                    assert!(raw <= i64::MAX as u64);
                    assert_eq!(registry.get(handle), Err(VaultHandleError::InvalidHandle));
                }
                Err(VaultHandleError::InvalidHandle) => {}
                Err(VaultHandleError::CapacityExceeded) => {
                    panic!("raw handle decoding must never report capacity")
                }
            }
        }

        for raw in [0, 1, 1_u64 << 32, u64::MAX, i64::MIN as u64] {
            assert_eq!(
                VaultHandle::from_raw(raw),
                Err(VaultHandleError::InvalidHandle)
            );
        }
    }

    #[test]
    fn generation_exhaustion_retires_the_slot_instead_of_wrapping() {
        let mut registry = VaultHandleRegistry::new(1);
        registry.slots.push(Slot {
            generation: MAX_GENERATION,
            value: Some("last-generation"),
            retired: false,
        });
        let handle = VaultHandle::encode(0, MAX_GENERATION).expect("max generation is valid");

        registry.lock(handle);
        assert!(!registry.is_valid(handle));
        assert!(registry.slots[0].retired);
        assert_eq!(
            registry.insert("must-not-reuse"),
            Err(VaultHandleError::CapacityExceeded)
        );
    }

    #[test]
    fn dropping_registry_drops_remaining_live_state() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut registry = VaultHandleRegistry::new(2);
            registry
                .insert(DropProbe(Arc::clone(&drops)))
                .expect("first insert");
            registry
                .insert(DropProbe(Arc::clone(&drops)))
                .expect("second insert");
        }

        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}

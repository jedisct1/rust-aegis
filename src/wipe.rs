//! Best-effort erasure of secrets.
//!
//! A plain memset can be optimized away once the value is dead, so use volatile writes.
//! This remains best-effort: Rust may leave stale copies behind when a value is moved.

use core::sync::atomic::{compiler_fence, Ordering};

pub(crate) fn wipe_slice(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Only meant for cipher states: plain data with no interior references and no `Drop` glue.
pub(crate) fn wipe_value<T>(value: &mut T) {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value as *mut T as *mut u8, core::mem::size_of::<T>())
    };
    wipe_slice(bytes);
}

use super::error::{self, Error};
use super::{ensure_init, ffi};

pub(crate) fn derive_key_into(
    out: &mut [u8],
    master_key: &[u8],
    context: &[u8],
) -> Result<(), Error> {
    ensure_init();

    debug_assert_eq!(out.len(), master_key.len());

    let max_context_len = match out.len() {
        16 => 120,
        32 => 72,
        _ => return Err(Error::InvalidArgument("key length must be 16 or 32 bytes")),
    };
    if context.len() > max_context_len {
        return Err(Error::InvalidArgument("context too long"));
    }

    let context_ptr = if context.is_empty() {
        core::ptr::null()
    } else {
        context.as_ptr()
    };

    let ret = unsafe {
        ffi::aegis_raf_derive_master_key(
            out.as_mut_ptr(),
            out.len(),
            master_key.as_ptr(),
            master_key.len(),
            context_ptr,
            context.len(),
        )
    };
    if ret != 0 {
        return Err(error::map_errno_derive());
    }

    Ok(())
}

/// Derives a context-bound key from an application master key.
///
/// This is the algorithm-independent form of
/// [`Raf::derive_master_key`](super::Raf::derive_master_key), parameterized by
/// the key length `KEY_LEN`, which must be either `16` (for the 128-bit family)
/// or `32` (for the 256-bit family). The master key and the derived key share
/// that length. `KEY_LEN` is normally inferred from the `master_key` argument,
/// so a call reads `derive_key(&master_key, context)`.
///
/// Different contexts with the same `master_key` produce independent keys, so
/// distinct files or file families can be isolated without managing separate
/// master keys. An empty `context` is valid and still derives a scoped key; it
/// is not a pass-through of `master_key`.
///
/// `context` must not exceed 120 bytes for 16-byte keys or 72 bytes for 32-byte
/// keys. The returned key is ordinary key material owned by the caller; clear or
/// zeroize it after use if your application requires that.
///
/// Returns [`Error::InvalidArgument`] if `KEY_LEN` is neither 16 nor 32, or if
/// `context` exceeds the per-length limit.
pub fn derive_key<const KEY_LEN: usize>(
    master_key: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<[u8; KEY_LEN], Error> {
    let mut out = [0u8; KEY_LEN];
    derive_key_into(&mut out, master_key, context)?;
    Ok(out)
}

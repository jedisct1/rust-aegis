use core::ffi::c_int;

use super::ffi;

use sealed::Sealed;

mod sealed {
    use core::ffi::c_int;

    use super::super::ffi;

    pub trait Sealed {
        unsafe fn ffi_scratch_size(chunk_size: u32) -> usize;
        unsafe fn ffi_create(
            ctx: *mut u8,
            io: *const ffi::aegis_raf_io,
            rng: *const ffi::aegis_raf_rng,
            cfg: *const ffi::aegis_raf_config,
            key: *const u8,
        ) -> c_int;
        unsafe fn ffi_open(
            ctx: *mut u8,
            io: *const ffi::aegis_raf_io,
            rng: *const ffi::aegis_raf_rng,
            cfg: *const ffi::aegis_raf_config,
            key: *const u8,
        ) -> c_int;
        unsafe fn ffi_read(
            ctx: *mut u8,
            out: *mut u8,
            bytes_read: *mut usize,
            len: usize,
            offset: u64,
        ) -> c_int;
        unsafe fn ffi_write(
            ctx: *mut u8,
            bytes_written: *mut usize,
            data: *const u8,
            len: usize,
            offset: u64,
        ) -> c_int;
        unsafe fn ffi_truncate(ctx: *mut u8, size: u64) -> c_int;
        unsafe fn ffi_get_size(ctx: *const u8, size: *mut u64) -> c_int;
        unsafe fn ffi_sync(ctx: *mut u8) -> c_int;
        unsafe fn ffi_close(ctx: *mut u8);
        unsafe fn ffi_merkle_rebuild(ctx: *mut u8) -> c_int;
        unsafe fn ffi_merkle_verify(ctx: *mut u8, corrupted: *mut u64) -> c_int;
        unsafe fn ffi_merkle_commitment(ctx: *const u8, out: *mut u8, len: usize) -> c_int;
    }
}

/// An AEGIS variant usable with the random-access file (RAF) API.
///
/// This trait is implemented for the marker types [`Aegis128L`], [`Aegis128X2`],
/// [`Aegis128X4`], [`Aegis256`], [`Aegis256X2`], and [`Aegis256X4`], and is used
/// as the type parameter of [`Raf`](super::Raf) and [`RafBuilder`](super::RafBuilder)
/// to select the cipher. It is sealed and cannot be implemented outside this crate;
/// the members of interest to callers are [`Key`](Algorithm::Key),
/// [`KEY_LEN`](Algorithm::KEY_LEN), and [`ALG_ID`](Algorithm::ALG_ID).
pub trait Algorithm: Sealed {
    /// The key type for this variant: `[u8; 16]` for the 128-bit family, `[u8; 32]` for the 256-bit family.
    type Key: AsRef<[u8]> + AsMut<[u8]> + Default;
    /// The length in bytes of keys for this variant.
    const KEY_LEN: usize;
    /// The numeric identifier stored in a RAF file header to record this variant.
    const ALG_ID: u8;
}

macro_rules! impl_algorithm {
    ($name:ident, $key_len:literal, $alg_id:literal, $prefix:ident, $ctx:ident) => {
        #[doc = concat!("Marker type selecting ", stringify!($name), " for the RAF API.")]
        pub struct $name;

        impl Algorithm for $name {
            type Key = [u8; $key_len];
            const KEY_LEN: usize = $key_len;
            const ALG_ID: u8 = $alg_id;
        }

        impl Sealed for $name {
            unsafe fn ffi_scratch_size(chunk_size: u32) -> usize {
                pastey::paste! { ffi::[<$prefix _raf_scratch_size>](chunk_size) }
            }

            unsafe fn ffi_create(
                ctx: *mut u8,
                io: *const ffi::aegis_raf_io,
                rng: *const ffi::aegis_raf_rng,
                cfg: *const ffi::aegis_raf_config,
                key: *const u8,
            ) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_create>](ctx as *mut ffi::$ctx, io, rng, cfg, key) }
            }

            unsafe fn ffi_open(
                ctx: *mut u8,
                io: *const ffi::aegis_raf_io,
                rng: *const ffi::aegis_raf_rng,
                cfg: *const ffi::aegis_raf_config,
                key: *const u8,
            ) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_open>](ctx as *mut ffi::$ctx, io, rng, cfg, key) }
            }

            unsafe fn ffi_read(
                ctx: *mut u8,
                out: *mut u8,
                bytes_read: *mut usize,
                len: usize,
                offset: u64,
            ) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_read>](ctx as *mut ffi::$ctx, out, bytes_read, len, offset) }
            }

            unsafe fn ffi_write(
                ctx: *mut u8,
                bytes_written: *mut usize,
                data: *const u8,
                len: usize,
                offset: u64,
            ) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_write>](ctx as *mut ffi::$ctx, bytes_written, data, len, offset) }
            }

            unsafe fn ffi_truncate(ctx: *mut u8, size: u64) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_truncate>](ctx as *mut ffi::$ctx, size) }
            }

            unsafe fn ffi_get_size(ctx: *const u8, size: *mut u64) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_get_size>](ctx as *const ffi::$ctx, size) }
            }

            unsafe fn ffi_sync(ctx: *mut u8) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_sync>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_close(ctx: *mut u8) {
                pastey::paste! { ffi::[<$prefix _raf_close>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_merkle_rebuild(ctx: *mut u8) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_merkle_rebuild>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_merkle_verify(ctx: *mut u8, corrupted: *mut u64) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_merkle_verify>](ctx as *mut ffi::$ctx, corrupted) }
            }

            unsafe fn ffi_merkle_commitment(ctx: *const u8, out: *mut u8, len: usize) -> c_int {
                pastey::paste! { ffi::[<$prefix _raf_merkle_commitment>](ctx as *const ffi::$ctx, out, len) }
            }
        }
    };
}

impl_algorithm!(Aegis128L, 16, 1, aegis128l, aegis128l_raf_ctx);
impl_algorithm!(Aegis128X2, 16, 2, aegis128x2, aegis128x2_raf_ctx);
impl_algorithm!(Aegis128X4, 16, 3, aegis128x4, aegis128x4_raf_ctx);
impl_algorithm!(Aegis256, 32, 4, aegis256, aegis256_raf_ctx);
impl_algorithm!(Aegis256X2, 32, 5, aegis256x2, aegis256x2_raf_ctx);
impl_algorithm!(Aegis256X4, 32, 6, aegis256x4, aegis256x4_raf_ctx);

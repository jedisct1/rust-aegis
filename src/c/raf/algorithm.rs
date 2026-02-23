use core::ffi::c_int;

use super::ffi;

mod sealed {
    pub trait Sealed {}
}

pub trait Algorithm: sealed::Sealed {
    type Key: AsRef<[u8]>;
    const ALG_ID: u8;

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

macro_rules! impl_algorithm {
    ($name:ident, $key_len:literal, $alg_id:literal, $prefix:ident, $ctx:ident) => {
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Algorithm for $name {
            type Key = [u8; $key_len];
            const ALG_ID: u8 = $alg_id;

            unsafe fn ffi_scratch_size(chunk_size: u32) -> usize {
                paste::paste! { ffi::[<$prefix _raf_scratch_size>](chunk_size) }
            }

            unsafe fn ffi_create(
                ctx: *mut u8,
                io: *const ffi::aegis_raf_io,
                rng: *const ffi::aegis_raf_rng,
                cfg: *const ffi::aegis_raf_config,
                key: *const u8,
            ) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_create>](ctx as *mut ffi::$ctx, io, rng, cfg, key) }
            }

            unsafe fn ffi_open(
                ctx: *mut u8,
                io: *const ffi::aegis_raf_io,
                rng: *const ffi::aegis_raf_rng,
                cfg: *const ffi::aegis_raf_config,
                key: *const u8,
            ) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_open>](ctx as *mut ffi::$ctx, io, rng, cfg, key) }
            }

            unsafe fn ffi_read(
                ctx: *mut u8,
                out: *mut u8,
                bytes_read: *mut usize,
                len: usize,
                offset: u64,
            ) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_read>](ctx as *mut ffi::$ctx, out, bytes_read, len, offset) }
            }

            unsafe fn ffi_write(
                ctx: *mut u8,
                bytes_written: *mut usize,
                data: *const u8,
                len: usize,
                offset: u64,
            ) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_write>](ctx as *mut ffi::$ctx, bytes_written, data, len, offset) }
            }

            unsafe fn ffi_truncate(ctx: *mut u8, size: u64) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_truncate>](ctx as *mut ffi::$ctx, size) }
            }

            unsafe fn ffi_get_size(ctx: *const u8, size: *mut u64) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_get_size>](ctx as *const ffi::$ctx, size) }
            }

            unsafe fn ffi_sync(ctx: *mut u8) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_sync>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_close(ctx: *mut u8) {
                paste::paste! { ffi::[<$prefix _raf_close>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_merkle_rebuild(ctx: *mut u8) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_merkle_rebuild>](ctx as *mut ffi::$ctx) }
            }

            unsafe fn ffi_merkle_verify(ctx: *mut u8, corrupted: *mut u64) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_merkle_verify>](ctx as *mut ffi::$ctx, corrupted) }
            }

            unsafe fn ffi_merkle_commitment(ctx: *const u8, out: *mut u8, len: usize) -> c_int {
                paste::paste! { ffi::[<$prefix _raf_merkle_commitment>](ctx as *const ffi::$ctx, out, len) }
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

use core::ffi::{c_int, c_void};

#[repr(C)]
pub struct aegis_raf_scratch {
    pub buf: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct aegis_raf_io {
    pub user: *mut c_void,
    pub read_at: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize, u64) -> c_int>,
    pub write_at: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, u64) -> c_int>,
    pub get_size: Option<unsafe extern "C" fn(*mut c_void, *mut u64) -> c_int>,
    pub set_size: Option<unsafe extern "C" fn(*mut c_void, u64) -> c_int>,
    pub sync: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

#[repr(C)]
pub struct aegis_raf_rng {
    pub user: *mut c_void,
    pub random: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int>,
}

#[repr(C)]
pub struct aegis_raf_merkle_config {
    pub hash_leaf:
        Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize, *const u8, usize, u64) -> c_int>,
    pub hash_parent: Option<
        unsafe extern "C" fn(*mut c_void, *mut u8, usize, *const u8, *const u8, u32, u64) -> c_int,
    >,
    pub hash_empty: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize, u32, u64) -> c_int>,
    pub hash_commitment: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *mut u8,
            usize,
            *const u8,
            *const u8,
            usize,
            u64,
        ) -> c_int,
    >,
    pub user: *mut c_void,
    pub buf: *mut u8,
    pub len: usize,
    pub max_chunks: u64,
    pub hash_len: u32,
}

#[repr(C)]
pub struct aegis_raf_config {
    pub scratch: *const aegis_raf_scratch,
    pub merkle: *const aegis_raf_merkle_config,
    pub chunk_size: u32,
    pub flags: u8,
}

#[repr(C)]
pub struct aegis_raf_info {
    pub file_size: u64,
    pub chunk_size: u32,
    pub alg_id: u8,
}

macro_rules! define_raf_ctx {
    ($name:ident, $align:literal) => {
        #[repr(C)]
        #[repr(align($align))]
        pub struct $name {
            pub opaque: [u8; 512],
        }
    };
}

define_raf_ctx!(aegis128l_raf_ctx, 32);
define_raf_ctx!(aegis128x2_raf_ctx, 32);
define_raf_ctx!(aegis128x4_raf_ctx, 64);
define_raf_ctx!(aegis256_raf_ctx, 16);
define_raf_ctx!(aegis256x2_raf_ctx, 32);
define_raf_ctx!(aegis256x4_raf_ctx, 64);

extern "C" {
    pub fn aegis_init() -> c_int;

    pub fn aegis_raf_probe(io: *const aegis_raf_io, info: *mut aegis_raf_info) -> c_int;
    pub fn aegis_raf_merkle_buffer_size(cfg: *const aegis_raf_merkle_config) -> usize;
}

macro_rules! declare_raf_ffi {
    ($prefix:ident, $ctx:ident) => {
        paste::paste! {
            extern "C" {
                pub fn [<$prefix _raf_scratch_size>](chunk_size: u32) -> usize;

                pub fn [<$prefix _raf_create>](
                    ctx: *mut $ctx,
                    io: *const aegis_raf_io,
                    rng: *const aegis_raf_rng,
                    cfg: *const aegis_raf_config,
                    master_key: *const u8,
                ) -> c_int;

                pub fn [<$prefix _raf_open>](
                    ctx: *mut $ctx,
                    io: *const aegis_raf_io,
                    rng: *const aegis_raf_rng,
                    cfg: *const aegis_raf_config,
                    master_key: *const u8,
                ) -> c_int;

                pub fn [<$prefix _raf_read>](
                    ctx: *mut $ctx,
                    out: *mut u8,
                    bytes_read: *mut usize,
                    len: usize,
                    offset: u64,
                ) -> c_int;

                pub fn [<$prefix _raf_write>](
                    ctx: *mut $ctx,
                    bytes_written: *mut usize,
                    data: *const u8,
                    len: usize,
                    offset: u64,
                ) -> c_int;

                pub fn [<$prefix _raf_truncate>](ctx: *mut $ctx, size: u64) -> c_int;

                pub fn [<$prefix _raf_get_size>](ctx: *const $ctx, size: *mut u64) -> c_int;

                pub fn [<$prefix _raf_sync>](ctx: *mut $ctx) -> c_int;

                pub fn [<$prefix _raf_close>](ctx: *mut $ctx);

                pub fn [<$prefix _raf_merkle_rebuild>](ctx: *mut $ctx) -> c_int;

                pub fn [<$prefix _raf_merkle_verify>](
                    ctx: *mut $ctx,
                    corrupted_chunk: *mut u64,
                ) -> c_int;

                pub fn [<$prefix _raf_merkle_commitment>](
                    ctx: *const $ctx,
                    out: *mut u8,
                    out_len: usize,
                ) -> c_int;
            }
        }
    };
}

declare_raf_ffi!(aegis128l, aegis128l_raf_ctx);
declare_raf_ffi!(aegis128x2, aegis128x2_raf_ctx);
declare_raf_ffi!(aegis128x4, aegis128x4_raf_ctx);
declare_raf_ffi!(aegis256, aegis256_raf_ctx);
declare_raf_ffi!(aegis256x2, aegis256x2_raf_ctx);
declare_raf_ffi!(aegis256x4, aegis256x4_raf_ctx);

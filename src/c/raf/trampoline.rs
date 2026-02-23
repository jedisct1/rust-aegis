use core::ffi::{c_int, c_void};
use std::pin::Pin;

use super::errno::{set_errno, EIO};
use super::ffi::{aegis_raf_io, aegis_raf_merkle_config, aegis_raf_rng};
use super::io::RafIo;
use super::merkle::MerkleHasher;
use super::rng::RafRng;

fn io_err_to_errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(EIO)
}

pub(crate) struct IoShim {
    inner: Box<dyn RafIo>,
}

impl IoShim {
    pub fn new(io: impl RafIo + 'static) -> Pin<Box<Self>> {
        Box::pin(IoShim {
            inner: Box::new(io),
        })
    }

    pub fn as_ffi(self: &mut Pin<Box<Self>>) -> aegis_raf_io {
        let ptr: *mut IoShim = &mut **self;
        aegis_raf_io {
            user: ptr as *mut c_void,
            read_at: Some(io_read_at),
            write_at: Some(io_write_at),
            get_size: Some(io_get_size),
            set_size: Some(io_set_size),
            sync: Some(io_sync),
        }
    }

    pub fn new_dyn(io: &mut dyn RafIo) -> IoShimRef<'_> {
        IoShimRef { inner: io }
    }
}

pub(crate) struct IoShimRef<'a> {
    inner: &'a mut dyn RafIo,
}

impl<'a> IoShimRef<'a> {
    pub fn as_ffi_ref(&mut self) -> aegis_raf_io {
        let ptr: *mut IoShimRef<'_> = self;
        aegis_raf_io {
            user: ptr as *mut c_void,
            read_at: Some(io_read_at_ref),
            write_at: Some(io_write_at_ref),
            get_size: Some(io_get_size_ref),
            set_size: Some(io_set_size_ref),
            sync: Some(io_sync_ref),
        }
    }
}

unsafe extern "C" fn io_read_at(user: *mut c_void, buf: *mut u8, len: usize, off: u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShim) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match shim.inner.read_at(slice, off) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_write_at(user: *mut c_void, buf: *const u8, len: usize, off: u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShim) };
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    match shim.inner.write_at(slice, off) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_get_size(user: *mut c_void, size: *mut u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShim) };
    match shim.inner.get_size() {
        Ok(s) => {
            unsafe { *size = s };
            0
        }
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_set_size(user: *mut c_void, size: u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShim) };
    match shim.inner.set_size(size) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_sync(user: *mut c_void) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShim) };
    match shim.inner.sync() {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_read_at_ref(
    user: *mut c_void,
    buf: *mut u8,
    len: usize,
    off: u64,
) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShimRef<'_>) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match shim.inner.read_at(slice, off) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_write_at_ref(
    user: *mut c_void,
    buf: *const u8,
    len: usize,
    off: u64,
) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShimRef<'_>) };
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    match shim.inner.write_at(slice, off) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_get_size_ref(user: *mut c_void, size: *mut u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShimRef<'_>) };
    match shim.inner.get_size() {
        Ok(s) => {
            unsafe { *size = s };
            0
        }
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_set_size_ref(user: *mut c_void, size: u64) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShimRef<'_>) };
    match shim.inner.set_size(size) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

unsafe extern "C" fn io_sync_ref(user: *mut c_void) -> c_int {
    let shim = unsafe { &mut *(user as *mut IoShimRef<'_>) };
    match shim.inner.sync() {
        Ok(()) => 0,
        Err(e) => {
            set_errno(io_err_to_errno(&e));
            -1
        }
    }
}

pub(crate) struct RngShim {
    inner: Box<dyn RafRng>,
}

impl RngShim {
    pub fn new_boxed(rng: Box<dyn RafRng>) -> Pin<Box<Self>> {
        Box::pin(RngShim { inner: rng })
    }

    pub fn as_ffi(self: &mut Pin<Box<Self>>) -> aegis_raf_rng {
        let ptr: *mut RngShim = &mut **self;
        aegis_raf_rng {
            user: ptr as *mut c_void,
            random: Some(rng_random),
        }
    }
}

unsafe extern "C" fn rng_random(user: *mut c_void, out: *mut u8, len: usize) -> c_int {
    let shim = unsafe { &mut *(user as *mut RngShim) };
    let slice = unsafe { std::slice::from_raw_parts_mut(out, len) };
    match shim.inner.fill(slice) {
        Ok(()) => 0,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

const MERKLE_HASH_MIN: usize = 8;
const MERKLE_HASH_MAX: usize = 64;
const MAX_MERKLE_BUF: usize = 1 << 30;

pub(crate) struct MerkleShim {
    hasher: Box<dyn MerkleHasher>,
    hash_len: usize,
    pub buf: Vec<u8>,
    pub max_chunks: u64,
}

impl MerkleShim {
    pub fn new(
        hasher: Box<dyn MerkleHasher>,
        buf_size: usize,
        max_chunks: u64,
    ) -> Result<Pin<Box<Self>>, super::Error> {
        let hash_len = hasher.hash_len();
        if !(MERKLE_HASH_MIN..=MERKLE_HASH_MAX).contains(&hash_len) {
            return Err(super::Error::InvalidArgument(
                "hash_len must be between 8 and 64",
            ));
        }
        if buf_size == usize::MAX || buf_size > MAX_MERKLE_BUF {
            return Err(super::Error::Overflow);
        }
        Ok(Box::pin(MerkleShim {
            hasher,
            hash_len,
            buf: vec![0u8; buf_size],
            max_chunks,
        }))
    }

    pub fn as_ffi(self: &mut Pin<Box<Self>>) -> aegis_raf_merkle_config {
        let ptr: *mut MerkleShim = &mut **self;
        let hash_len = self.hash_len as u32;
        let max_chunks = self.max_chunks;
        let buf_ptr = self.buf.as_mut_ptr();
        let buf_len = self.buf.len();
        aegis_raf_merkle_config {
            hash_leaf: Some(merkle_hash_leaf),
            hash_parent: Some(merkle_hash_parent),
            hash_empty: Some(merkle_hash_empty),
            hash_commitment: Some(merkle_hash_commitment),
            user: ptr as *mut c_void,
            buf: buf_ptr,
            len: buf_len,
            max_chunks,
            hash_len,
        }
    }
}

unsafe extern "C" fn merkle_hash_leaf(
    user: *mut c_void,
    out: *mut u8,
    out_len: usize,
    chunk: *const u8,
    chunk_len: usize,
    chunk_idx: u64,
) -> c_int {
    let shim = unsafe { &*(user as *const MerkleShim) };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    let chunk_slice = unsafe { std::slice::from_raw_parts(chunk, chunk_len) };
    match shim.hasher.hash_leaf(out_slice, chunk_slice, chunk_idx) {
        Ok(()) => 0,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

unsafe extern "C" fn merkle_hash_parent(
    user: *mut c_void,
    out: *mut u8,
    out_len: usize,
    left: *const u8,
    right: *const u8,
    level: u32,
    node_idx: u64,
) -> c_int {
    let shim = unsafe { &*(user as *const MerkleShim) };
    let hash_len = shim.hash_len;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    let left_slice = unsafe { std::slice::from_raw_parts(left, hash_len) };
    let right_slice = unsafe { std::slice::from_raw_parts(right, hash_len) };
    match shim
        .hasher
        .hash_parent(out_slice, left_slice, right_slice, level, node_idx)
    {
        Ok(()) => 0,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

unsafe extern "C" fn merkle_hash_empty(
    user: *mut c_void,
    out: *mut u8,
    out_len: usize,
    level: u32,
    node_idx: u64,
) -> c_int {
    let shim = unsafe { &*(user as *const MerkleShim) };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    match shim.hasher.hash_empty(out_slice, level, node_idx) {
        Ok(()) => 0,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

unsafe extern "C" fn merkle_hash_commitment(
    user: *mut c_void,
    out: *mut u8,
    out_len: usize,
    structural_root: *const u8,
    ctx: *const u8,
    ctx_len: usize,
    file_size: u64,
) -> c_int {
    let shim = unsafe { &*(user as *const MerkleShim) };
    let hash_len = shim.hash_len;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    let root_slice = unsafe { std::slice::from_raw_parts(structural_root, hash_len) };
    let ctx_slice = unsafe { std::slice::from_raw_parts(ctx, ctx_len) };
    match shim
        .hasher
        .hash_commitment(out_slice, root_slice, ctx_slice, file_size)
    {
        Ok(()) => 0,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

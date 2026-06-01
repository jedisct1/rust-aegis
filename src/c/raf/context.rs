use std::marker::PhantomData;
use std::pin::Pin;

use super::algorithm::Algorithm;
use super::ensure_init;
use super::error::{self, Error};
use super::ffi;
use super::io::RafIo;
use super::kdf;
use super::merkle::MerkleHasher;
#[cfg(feature = "getrandom")]
use super::rng::OsRng;
use super::rng::RafRng;
use super::scratch::ScratchBuf;
use super::trampoline::{IoShim, MerkleShim, RngShim};

pub(crate) const AEGIS_RAF_CREATE: u8 = 0x01;
pub(crate) const AEGIS_RAF_TRUNCATE: u8 = 0x02;

#[repr(C)]
#[repr(align(64))]
struct RafCtxStorage {
    opaque: [u8; 512],
}

/// An open encrypted random-access file.
///
/// A `Raf` wraps a [`RafIo`] backing store and exposes encrypted reads and
/// writes at arbitrary byte offsets. Each chunk is encrypted and authenticated
/// independently, so neither reads nor writes require touching the whole file.
/// Create one with [`RafBuilder`], or with the convenience constructors
/// [`Raf::create_file`] / [`Raf::open_file`] when the `getrandom` feature is enabled.
///
/// The type parameter `A` selects the AEGIS variant (see [`Algorithm`]).
pub struct Raf<A: Algorithm> {
    ctx: Box<RafCtxStorage>,
    _scratch: ScratchBuf,
    _scratch_ffi: ffi::aegis_raf_scratch,
    _io_shim: Pin<Box<IoShim>>,
    _rng_shim: Pin<Box<RngShim>>,
    _merkle_shim: Option<Pin<Box<MerkleShim>>>,
    _algo: PhantomData<A>,
}

impl<A: Algorithm> Raf<A> {
    fn ctx_ptr(&mut self) -> *mut u8 {
        self.ctx.opaque.as_mut_ptr()
    }

    fn ctx_ptr_const(&self) -> *const u8 {
        self.ctx.opaque.as_ptr()
    }

    /// Derives a context-bound RAF key from an application master key.
    ///
    /// Different contexts with the same `master_key` produce independent RAF
    /// keys, so distinct files or file families can be isolated without
    /// managing separate master keys. An empty `context` is valid and still
    /// derives a RAF-scoped key; it is not a pass-through of `master_key`.
    ///
    /// `context` must not exceed 120 bytes for the 128-bit variants or 72 bytes
    /// for the 256-bit variants. The returned key is ordinary key material owned
    /// by the caller; clear or zeroize it after use if your application requires
    /// that.
    ///
    /// See [`derive_key`](super::derive_key) for an algorithm-independent form
    /// parameterized by the key length.
    pub fn derive_master_key(master_key: &A::Key, context: &[u8]) -> Result<A::Key, Error> {
        let mut out = A::Key::default();
        debug_assert_eq!(master_key.as_ref().len(), A::KEY_LEN);
        debug_assert_eq!(out.as_mut().len(), A::KEY_LEN);
        kdf::derive_key_into(out.as_mut(), master_key.as_ref(), context)?;
        Ok(out)
    }

    /// Reads decrypted bytes into `buf` starting at plaintext `offset`.
    ///
    /// Returns the number of bytes read, which may be fewer than requested if
    /// the end of the file is reached. Each touched chunk is authenticated, so
    /// tampering is reported as [`Error::AuthenticationFailed`].
    pub fn read(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        let mut bytes_read: usize = 0;
        let ret = unsafe {
            A::ffi_read(
                self.ctx_ptr(),
                buf.as_mut_ptr(),
                &mut bytes_read,
                buf.len(),
                offset,
            )
        };
        if ret != 0 {
            return Err(error::map_errno_read());
        }
        Ok(bytes_read)
    }

    /// Encrypts `data` and writes it starting at plaintext `offset`.
    ///
    /// Writing past the current end of the file extends it. Returns the number
    /// of bytes written.
    pub fn write(&mut self, data: &[u8], offset: u64) -> Result<usize, Error> {
        let mut bytes_written: usize = 0;
        let ret = unsafe {
            A::ffi_write(
                self.ctx_ptr(),
                &mut bytes_written,
                data.as_ptr(),
                data.len(),
                offset,
            )
        };
        if ret != 0 {
            return Err(error::map_errno_write());
        }
        Ok(bytes_written)
    }

    /// Sets the logical (plaintext) length of the file to `size` bytes.
    ///
    /// Shrinking discards trailing data; growing zero-extends the plaintext.
    pub fn truncate(&mut self, size: u64) -> Result<(), Error> {
        let ret = unsafe { A::ffi_truncate(self.ctx_ptr(), size) };
        if ret != 0 {
            return Err(error::map_errno_truncate());
        }
        Ok(())
    }

    /// Returns the current logical (plaintext) size of the file in bytes.
    pub fn size(&self) -> u64 {
        let mut size: u64 = 0;
        unsafe { A::ffi_get_size(self.ctx_ptr_const(), &mut size) };
        size
    }

    /// Flushes pending writes and file metadata to the backing store.
    pub fn sync(&mut self) -> Result<(), Error> {
        let ret = unsafe { A::ffi_sync(self.ctx_ptr()) };
        if ret != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Recomputes the entire Merkle tree from the current file contents.
    ///
    /// Requires the file to have been opened with a Merkle hasher; otherwise
    /// returns [`Error::MerkleNotEnabled`].
    pub fn merkle_rebuild(&mut self) -> Result<(), Error> {
        let ret = unsafe { A::ffi_merkle_rebuild(self.ctx_ptr()) };
        if ret != 0 {
            return Err(error::map_errno_merkle());
        }
        Ok(())
    }

    /// Verifies the whole file against its Merkle tree.
    ///
    /// Returns `Ok(None)` when every chunk verifies, or `Ok(Some(index))` with
    /// the index of the first corrupted chunk. Requires the file to have been
    /// opened with a Merkle hasher; otherwise returns [`Error::MerkleNotEnabled`].
    pub fn merkle_verify(&mut self) -> Result<Option<u64>, Error> {
        let mut corrupted: u64 = 0;
        let ret = unsafe { A::ffi_merkle_verify(self.ctx_ptr(), &mut corrupted) };
        if ret != 0 {
            let err = error::map_errno_merkle();
            match err {
                Error::AuthenticationFailed => return Ok(Some(corrupted)),
                _ => return Err(err),
            }
        }
        Ok(None)
    }

    /// Writes the file's Merkle commitment into `out`.
    ///
    /// The commitment is a single hash that fixes the entire file contents; it
    /// can be stored elsewhere and later compared to detect tampering. `out`
    /// must be at least the hasher's output length. Requires a Merkle hasher;
    /// otherwise returns [`Error::MerkleNotEnabled`].
    pub fn merkle_commitment(&self, out: &mut [u8]) -> Result<(), Error> {
        let ret =
            unsafe { A::ffi_merkle_commitment(self.ctx_ptr_const(), out.as_mut_ptr(), out.len()) };
        if ret != 0 {
            return Err(error::map_errno_merkle());
        }
        Ok(())
    }
}

impl<A: Algorithm> Drop for Raf<A> {
    fn drop(&mut self) {
        unsafe { A::ffi_close(self.ctx_ptr()) }
    }
}

/// Builder for configuring and opening a [`Raf`].
///
/// Lets you choose the chunk size, supply a custom [`RafRng`], enable a Merkle
/// tree, and decide whether to truncate on creation, before calling
/// [`create`](RafBuilder::create) or [`open`](RafBuilder::open).
pub struct RafBuilder<A: Algorithm> {
    chunk_size: u32,
    flags: u8,
    rng: Box<dyn RafRng>,
    merkle: Option<(Box<dyn MerkleHasher>, u64)>,
    _algo: PhantomData<A>,
}

impl<A: Algorithm> RafBuilder<A> {
    /// Creates a builder that uses the operating system RNG ([`OsRng`]).
    #[cfg(feature = "getrandom")]
    pub fn new() -> Self {
        Self::with_rng(OsRng)
    }

    /// Creates a builder that draws randomness from the supplied [`RafRng`].
    ///
    /// Use this on platforms without OS randomness, where the `getrandom`
    /// feature is unavailable.
    pub fn with_rng(rng: impl RafRng + 'static) -> Self {
        RafBuilder {
            chunk_size: 65536,
            flags: 0,
            rng: Box::new(rng),
            merkle: None,
            _algo: PhantomData,
        }
    }

    /// Sets the size in bytes of each independently encrypted chunk.
    ///
    /// Only applies when creating a file; when opening, the chunk size is taken
    /// from the file header. Defaults to 65536 bytes.
    pub fn chunk_size(mut self, size: u32) -> Self {
        self.chunk_size = size;
        self
    }

    /// Controls whether an existing file is truncated when [`create`](RafBuilder::create) is called.
    pub fn truncate(mut self, yes: bool) -> Self {
        if yes {
            self.flags |= AEGIS_RAF_TRUNCATE;
        } else {
            self.flags &= !AEGIS_RAF_TRUNCATE;
        }
        self
    }

    /// Replaces the random number generator used by this builder.
    pub fn rng(mut self, rng: impl RafRng + 'static) -> Self {
        self.rng = Box::new(rng);
        self
    }

    /// Enables a Merkle tree over the file using `hasher`, sized for up to `max_chunks` chunks.
    ///
    /// With a Merkle tree, whole-file integrity can be checked via
    /// [`Raf::merkle_verify`] and [`Raf::merkle_commitment`].
    pub fn merkle(mut self, hasher: impl MerkleHasher + 'static, max_chunks: u64) -> Self {
        self.merkle = Some((Box::new(hasher), max_chunks));
        self
    }

    /// Creates a new encrypted file on `io` with the given `key` and returns an open [`Raf`].
    ///
    /// The header records the algorithm and chunk size. If [`truncate`](RafBuilder::truncate)
    /// was not set, creation fails with [`Error::AlreadyExists`] when the backing store is non-empty.
    pub fn create(self, io: impl RafIo + 'static, key: &A::Key) -> Result<Raf<A>, Error> {
        ensure_init();

        let chunk_size = self.chunk_size;
        let scratch_size = unsafe { A::ffi_scratch_size(chunk_size) };
        let scratch = ScratchBuf::new(scratch_size);
        let scratch_ffi = scratch.as_ffi();

        let mut io_shim = IoShim::new(io);
        let mut rng_shim = RngShim::new_boxed(self.rng);

        let io_ffi = io_shim.as_ffi();
        let rng_ffi = rng_shim.as_ffi();

        let mut merkle_shim = self
            .merkle
            .map(|(hasher, max_chunks)| build_merkle_shim(hasher, max_chunks))
            .transpose()?;
        let merkle_ffi = merkle_shim.as_mut().map(|s| s.as_ffi());

        let cfg = ffi::aegis_raf_config {
            scratch: &scratch_ffi,
            merkle: merkle_ffi
                .as_ref()
                .map(|m| m as *const _)
                .unwrap_or(std::ptr::null()),
            chunk_size,
            flags: self.flags | AEGIS_RAF_CREATE,
        };

        let mut ctx = Box::new(RafCtxStorage { opaque: [0u8; 512] });
        let ret = unsafe {
            A::ffi_create(
                ctx.opaque.as_mut_ptr(),
                &io_ffi,
                &rng_ffi,
                &cfg,
                key.as_ref().as_ptr(),
            )
        };
        if ret != 0 {
            return Err(error::map_errno_create());
        }

        Ok(Raf {
            ctx,
            _scratch: scratch,
            _scratch_ffi: scratch_ffi,
            _io_shim: io_shim,
            _rng_shim: rng_shim,
            _merkle_shim: merkle_shim,
            _algo: PhantomData,
        })
    }

    /// Opens an existing encrypted file on `io` with the given `key` and returns an open [`Raf`].
    ///
    /// The algorithm `A` must match the one stored in the header, otherwise an
    /// [`Error::InvalidArgument`] is returned. The chunk size is read from the header.
    pub fn open(self, io: impl RafIo + 'static, key: &A::Key) -> Result<Raf<A>, Error> {
        ensure_init();

        let mut io_shim = IoShim::new(io);
        let mut rng_shim = RngShim::new_boxed(self.rng);

        let probe_io_ffi = io_shim.as_ffi();
        let mut info = ffi::aegis_raf_info {
            file_size: 0,
            chunk_size: 0,
            alg_id: 0,
        };
        let ret = unsafe { ffi::aegis_raf_probe(&probe_io_ffi, &mut info) };
        if ret != 0 {
            return Err(error::map_errno_probe());
        }
        if info.alg_id != A::ALG_ID {
            return Err(Error::InvalidArgument("algorithm mismatch"));
        }

        let chunk_size = info.chunk_size;
        let scratch_size = unsafe { A::ffi_scratch_size(chunk_size) };
        let scratch = ScratchBuf::new(scratch_size);
        let scratch_ffi = scratch.as_ffi();

        let io_ffi = io_shim.as_ffi();
        let rng_ffi = rng_shim.as_ffi();

        let mut merkle_shim = self
            .merkle
            .map(|(hasher, max_chunks)| build_merkle_shim(hasher, max_chunks))
            .transpose()?;
        let merkle_ffi = merkle_shim.as_mut().map(|s| s.as_ffi());

        let cfg = ffi::aegis_raf_config {
            scratch: &scratch_ffi,
            merkle: merkle_ffi
                .as_ref()
                .map(|m| m as *const _)
                .unwrap_or(std::ptr::null()),
            chunk_size,
            flags: 0,
        };

        let mut ctx = Box::new(RafCtxStorage { opaque: [0u8; 512] });
        let ret = unsafe {
            A::ffi_open(
                ctx.opaque.as_mut_ptr(),
                &io_ffi,
                &rng_ffi,
                &cfg,
                key.as_ref().as_ptr(),
            )
        };
        if ret != 0 {
            return Err(error::map_errno_open());
        }

        Ok(Raf {
            ctx,
            _scratch: scratch,
            _scratch_ffi: scratch_ffi,
            _io_shim: io_shim,
            _rng_shim: rng_shim,
            _merkle_shim: merkle_shim,
            _algo: PhantomData,
        })
    }
}

#[cfg(feature = "getrandom")]
impl<A: Algorithm> Default for RafBuilder<A> {
    fn default() -> Self {
        Self::new()
    }
}

fn build_merkle_shim(
    hasher: Box<dyn MerkleHasher>,
    max_chunks: u64,
) -> Result<Pin<Box<MerkleShim>>, Error> {
    let hash_len = hasher.hash_len();
    let temp_cfg = ffi::aegis_raf_merkle_config {
        hash_leaf: None,
        hash_parent: None,
        hash_empty: None,
        hash_commitment: None,
        user: std::ptr::null_mut(),
        buf: std::ptr::null_mut(),
        len: 0,
        max_chunks,
        hash_len: hash_len as u32,
    };
    let buf_size = unsafe { ffi::aegis_raf_merkle_buffer_size(&temp_cfg) };
    MerkleShim::new(hasher, buf_size, max_chunks)
}

mod algorithm;
mod context;
mod errno;
mod error;
mod ffi;
mod io;
mod merkle;
mod rng;
mod scratch;
mod stream;
mod trampoline;

use std::sync::Once;

pub use algorithm::Algorithm;
pub use algorithm::{Aegis128L, Aegis128X2, Aegis128X4, Aegis256, Aegis256X2, Aegis256X4};
pub use context::{Raf, RafBuilder};
pub use error::Error;
pub use io::{FileIo, RafIo};
pub use merkle::MerkleHasher;
#[cfg(feature = "getrandom")]
pub use rng::OsRng;
pub use rng::RafRng;
pub use stream::RafCursor;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| assert_eq!(unsafe { ffi::aegis_init() }, 0));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmId {
    Aegis128L = 1,
    Aegis128X2 = 2,
    Aegis128X4 = 3,
    Aegis256 = 4,
    Aegis256X2 = 5,
    Aegis256X4 = 6,
}

impl AlgorithmId {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(AlgorithmId::Aegis128L),
            2 => Ok(AlgorithmId::Aegis128X2),
            3 => Ok(AlgorithmId::Aegis128X4),
            4 => Ok(AlgorithmId::Aegis256),
            5 => Ok(AlgorithmId::Aegis256X2),
            6 => Ok(AlgorithmId::Aegis256X4),
            _ => Err(Error::InvalidArgument("unknown algorithm id")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RafInfo {
    pub algorithm: AlgorithmId,
    pub chunk_size: u32,
    pub file_size: u64,
}

pub fn probe(io: &mut dyn RafIo) -> Result<RafInfo, Error> {
    ensure_init();
    let mut shim = trampoline::IoShim::new_dyn(io);
    let io_ffi = shim.as_ffi_ref();
    let mut info = ffi::aegis_raf_info {
        file_size: 0,
        chunk_size: 0,
        alg_id: 0,
    };
    let ret = unsafe { ffi::aegis_raf_probe(&io_ffi, &mut info) };
    if ret != 0 {
        return Err(error::map_errno_probe());
    }
    Ok(RafInfo {
        algorithm: AlgorithmId::from_u8(info.alg_id)?,
        chunk_size: info.chunk_size,
        file_size: info.file_size,
    })
}

#[cfg(feature = "getrandom")]
impl<A: Algorithm> Raf<A> {
    pub fn create_file(path: impl AsRef<std::path::Path>, key: &A::Key) -> Result<Self, Error> {
        let io = FileIo::create(path)?;
        RafBuilder::<A>::new().truncate(true).create(io, key)
    }

    pub fn open_file(path: impl AsRef<std::path::Path>, key: &A::Key) -> Result<Self, Error> {
        let io = FileIo::open(path)?;
        RafBuilder::<A>::new().open(io, key)
    }
}

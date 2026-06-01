/// Encrypted random-access file I/O built on top of the AEGIS ciphers.
#[cfg(feature = "raf-core")]
#[cfg_attr(docsrs, doc(cfg(feature = "raf")))]
pub mod raf;

/// AEGIS-128L.
pub mod aegis128l;
/// AEGIS-128X2, the 2-lane variant of AEGIS-128L.
pub mod aegis128x2;
/// AEGIS-128X4, the 4-lane variant of AEGIS-128L.
pub mod aegis128x4;
/// AEGIS-256.
pub mod aegis256;
/// AEGIS-256X2, the 2-lane variant of AEGIS-256.
pub mod aegis256x2;
/// AEGIS-256X4, the 4-lane variant of AEGIS-256.
pub mod aegis256x4;

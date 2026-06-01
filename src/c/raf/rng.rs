use super::Error;

/// Source of randomness used by the RAF layer to generate per-file salts and nonces.
///
/// With the `getrandom` feature, [`OsRng`] is supplied by default. On platforms
/// without OS randomness, implement this trait and pass it via
/// [`RafBuilder::with_rng`](super::RafBuilder::with_rng).
pub trait RafRng {
    /// Fills `buf` entirely with cryptographically secure random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// A [`RafRng`] backed by the operating system RNG via the `getrandom` crate.
#[cfg(feature = "getrandom")]
pub struct OsRng;

#[cfg(feature = "getrandom")]
impl RafRng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

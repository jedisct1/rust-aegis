use super::Error;

pub trait RafRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

#[cfg(feature = "getrandom")]
pub struct OsRng;

#[cfg(feature = "getrandom")]
impl RafRng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

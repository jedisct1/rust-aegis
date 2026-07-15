use crate::wipe::wipe_slice;
use crate::Error;

/// Cumulative message length, bounded by [`crate::MAX_AEAD_BYTES`].
pub(crate) struct MessageLength(u64);

impl MessageLength {
    pub(crate) fn new() -> Self {
        MessageLength(0)
    }

    #[cfg(feature = "pure-rust")]
    pub(crate) fn get(&self) -> u64 {
        self.0
    }

    /// Advances the counter, or fails without changing it.
    pub(crate) fn try_add(&mut self, n: usize) -> Result<(), Error> {
        match self.0.checked_add(n as u64) {
            Some(len) if len <= crate::MAX_AEAD_BYTES => {
                self.0 = len;
                Ok(())
            }
            _ => Err(Error::MessageTooLong),
        }
    }

    /// Advances the counter; on the encryption path, overflow is a caller bug.
    pub(crate) fn add(&mut self, n: usize) {
        assert!(
            self.try_add(n).is_ok(),
            "total message length exceeds 2^61 - 1 bytes"
        );
    }

    #[cfg(test)]
    pub(crate) fn set_for_tests(&mut self, len: u64) {
        self.0 = len;
    }
}

pub(crate) fn check_ad_length(ad: &[u8]) {
    assert!(
        ad.len() as u64 <= crate::MAX_AEAD_BYTES,
        "associated data length exceeds 2^61 - 1 bytes"
    );
}

/// Exclusively borrowed decryption destination.
///
/// Keeps unverified plaintext unreachable while a `Decryptor` is alive.
/// Unless released by a successful finalization, the written prefix is erased on drop.
pub(crate) struct Quarantine<'a> {
    dst: Option<&'a mut [u8]>,
    written: usize,
}

impl<'a> Quarantine<'a> {
    pub(crate) fn new(dst: &'a mut [u8]) -> Self {
        Quarantine {
            dst: Some(dst),
            written: 0,
        }
    }

    pub(crate) fn fits(&self, n: usize) -> Result<(), Error> {
        let dst = self
            .dst
            .as_ref()
            .expect("destination must be present until finalization");
        if n > dst.len() - self.written {
            return Err(Error::OutputBufferTooSmall);
        }
        Ok(())
    }

    /// Callers must have checked [`Quarantine::fits`] first.
    pub(crate) fn next_chunk(&mut self, n: usize) -> &mut [u8] {
        let dst = self
            .dst
            .as_mut()
            .expect("destination must be present until finalization");
        let chunk = &mut dst[self.written..][..n];
        self.written += n;
        chunk
    }

    /// Ends the quarantine and returns the written prefix.
    pub(crate) fn release(&mut self) -> &'a mut [u8] {
        let dst = self
            .dst
            .take()
            .expect("destination must be present until finalization");
        &mut dst[..self.written]
    }
}

impl Drop for Quarantine<'_> {
    fn drop(&mut self) {
        if let Some(dst) = self.dst.take() {
            wipe_slice(&mut dst[..self.written]);
        }
    }
}

/// Constant-time tag comparison.
#[cfg(feature = "pure-rust")]
pub(crate) fn tags_match(expected: &[u8], computed: &[u8]) -> bool {
    let mut acc = 0;
    for (a, b) in expected.iter().zip(computed.iter()) {
        acc |= a ^ b;
    }
    acc == 0
}

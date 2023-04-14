/// AEGIS-128L AEAD.
pub mod aegis128l {
    use core::ffi::c_int;

    pub use crate::Error;

    /// AEGIS-128L authentication tag
    pub type Tag = Vec<u8>;

    /// AEGIS-128L key
    pub type Key = [u8; 16];

    /// AEGIS-128L nonce
    pub type Nonce = [u8; 16];

    extern "C" {
        fn crypto_aead_aegis128l_encrypt_detached(
            tag_bits: u16,
            c: *mut u8,
            mac: *mut u8,
            m: *const u8,
            mlen: usize,
            ad: *const u8,
            adlen: usize,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;

        fn crypto_aead_aegis128l_decrypt_detached(
            tag_bits: u16,
            m: *mut u8,
            c: *const u8,
            clen: usize,
            mac: *const u8,
            ad: *const u8,
            adlen: usize,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
    }

    #[derive(Copy, Clone, Debug)]
    pub struct Aegis128L<const TAG_BITS: u16> {
        key: Key,
        nonce: Nonce,
    }

    impl<const TAG_BITS: u16> Aegis128L<TAG_BITS> {
        pub fn new(key: &Key, nonce: &Nonce) -> Self {
            assert!(
                TAG_BITS == 128 || TAG_BITS == 256,
                "Invalid tag length, must be 128 or 256"
            );
            Aegis128L {
                key: *key,
                nonce: *nonce,
            }
        }

        /// Encrypts a message using AEGIS-128L
        /// # Arguments
        /// * `m` - Message
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        #[cfg(feature = "std")]
        pub fn encrypt(self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag) {
            let mut c = vec![0u8; m.len()];
            let mut tag = vec![0u8; (TAG_BITS / 8) as _];
            unsafe {
                crypto_aead_aegis128l_encrypt_detached(
                    TAG_BITS,
                    c.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    m.as_ptr(),
                    m.len(),
                    ad.as_ptr(),
                    ad.len(),
                    self.nonce.as_ptr(),
                    self.key.as_ptr(),
                );
            }
            (c, tag)
        }

        /// Encrypts a message in-place using AEGIS-128L
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        pub fn encrypt_in_place(self, mc: &mut [u8], ad: &[u8]) -> Tag {
            let mut tag = vec![0u8; (TAG_BITS / 8) as _];
            unsafe {
                crypto_aead_aegis128l_encrypt_detached(
                    TAG_BITS,
                    mc.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    mc.as_ptr(),
                    mc.len(),
                    ad.as_ptr(),
                    ad.len(),
                    self.nonce.as_ptr(),
                    self.key.as_ptr(),
                );
            }
            tag
        }

        /// Decrypts a message using AEGIS-128L
        /// # Arguments
        /// * `c` - Ciphertext
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        /// # Returns
        /// Decrypted message.
        #[cfg(feature = "std")]
        pub fn decrypt(&self, c: &[u8], tag: &Tag, ad: &[u8]) -> Result<Vec<u8>, Error> {
            let mut m = vec![0u8; c.len()];
            let res = unsafe {
                crypto_aead_aegis128l_decrypt_detached(
                    TAG_BITS,
                    m.as_mut_ptr(),
                    c.as_ptr(),
                    c.len(),
                    tag.as_ptr(),
                    ad.as_ptr(),
                    ad.len(),
                    self.nonce.as_ptr(),
                    self.key.as_ptr(),
                )
            };
            if res != 0 {
                return Err(Error::InvalidTag);
            }
            Ok(m)
        }

        /// Decrypts a message in-place using AEGIS-128L
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        pub fn decrypt_in_place(&self, mc: &mut [u8], tag: &Tag, ad: &[u8]) -> Result<(), Error> {
            let ret = unsafe {
                crypto_aead_aegis128l_decrypt_detached(
                    TAG_BITS,
                    mc.as_mut_ptr(),
                    mc.as_ptr(),
                    mc.len(),
                    tag.as_ptr(),
                    ad.as_ptr(),
                    ad.len(),
                    self.nonce.as_ptr(),
                    self.key.as_ptr(),
                )
            };
            if ret != 0 {
                return Err(Error::InvalidTag);
            }
            Ok(())
        }
    }
}

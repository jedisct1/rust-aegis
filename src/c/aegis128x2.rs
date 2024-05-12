use core::{ffi::c_int, mem::MaybeUninit};

pub use crate::Error;

/// AEGIS-128X2 key
pub type Key = [u8; 16];

/// AEGIS-128X2 nonce
pub type Nonce = [u8; 16];

#[allow(non_camel_case_types)]
type aegis128x2_state = [u8; 448];

extern "C" {
    fn aegis_init() -> c_int;

    fn aegis128x2_encrypt_detached(
        c: *mut u8,
        mac: *mut u8,
        maclen: usize,
        m: *const u8,
        mlen: usize,
        ad: *const u8,
        adlen: usize,
        npub: *const u8,
        k: *const u8,
    ) -> c_int;

    fn aegis128x2_decrypt_detached(
        m: *mut u8,
        c: *const u8,
        clen: usize,
        mac: *const u8,
        maclen: usize,
        ad: *const u8,
        adlen: usize,
        npub: *const u8,
        k: *const u8,
    ) -> c_int;

    fn aegis128x2_mac_init(st_: *mut aegis128x2_state, k: *const u8);

    fn aegis128x2_mac_update(st_: *mut aegis128x2_state, m: *const u8, mlen: usize) -> c_int;

    fn aegis128x2_mac_final(st_: *mut aegis128x2_state, mac: *mut u8, maclen: usize) -> c_int;

    fn aegis128x2_mac_verify(st_: *mut aegis128x2_state, mac: *const u8, maclen: usize) -> c_int;

    fn aegis128x2_mac_state_clone(dst: *mut aegis128x2_state, src: *const aegis128x2_state);

}

#[cfg(feature = "std")]
static INIT: std::sync::Once = std::sync::Once::new();
#[cfg(not(feature = "std"))]
static INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
#[cfg(not(feature = "std"))]
static INITIALIZING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Tag length in bytes must be 16 (128 bits) or 32 (256 bits)
#[derive(Copy, Clone, Debug)]
pub struct Aegis128X2<const TAG_BYTES: usize> {
    key: Key,
    nonce: Nonce,
}

/// AEGIS-128X2 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

impl<const TAG_BYTES: usize> Aegis128X2<TAG_BYTES> {
    fn ensure_init() {
        #[cfg(feature = "std")]
        INIT.call_once(|| assert_eq!(unsafe { aegis_init() }, 0));

        #[cfg(not(feature = "std"))]
        {
            use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

            if INITIALIZED.load(Acquire) {
                return;
            }
            let initializing = match INITIALIZING.compare_exchange(false, true, Acquire, Relaxed) {
                Ok(initializing) => initializing,
                Err(initializing) => initializing,
            };
            if initializing {
                while !INITIALIZED.load(Acquire) {}
            } else {
                assert_eq!(unsafe { aegis_init() }, 0);
                INITIALIZED.store(true, Release);
                INITIALIZING.store(false, Release);
            }
        }
    }

    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Self::ensure_init();
        Aegis128X2 {
            key: *key,
            nonce: *nonce,
        }
    }

    /// Encrypts a message using AEGIS-128X2
    /// # Arguments
    /// * `m` - Message
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    #[cfg(feature = "std")]
    pub fn encrypt(self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag<TAG_BYTES>) {
        let mut c = vec![0u8; m.len()];
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis128x2_encrypt_detached(
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
                TAG_BYTES as _,
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

    /// Encrypts a message in-place using AEGIS-128X2
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    pub fn encrypt_in_place(self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis128x2_encrypt_detached(
                mc.as_mut_ptr(),
                tag.as_mut_ptr(),
                TAG_BYTES as _,
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

    /// Decrypts a message using AEGIS-128X2
    /// # Arguments
    /// * `c` - Ciphertext
    /// * `tag` - Authentication tag
    /// * `ad` - Associated data
    /// # Returns
    /// Decrypted message.
    #[cfg(feature = "std")]
    pub fn decrypt(&self, c: &[u8], tag: &Tag<TAG_BYTES>, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut m = vec![0u8; c.len()];
        let res = unsafe {
            aegis128x2_decrypt_detached(
                m.as_mut_ptr(),
                c.as_ptr(),
                c.len(),
                tag.as_ptr(),
                TAG_BYTES as _,
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

    /// Decrypts a message in-place using AEGIS-128X2
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `tag` - Authentication tag
    /// * `ad` - Associated data
    pub fn decrypt_in_place(
        &self,
        mc: &mut [u8],
        tag: &Tag<TAG_BYTES>,
        ad: &[u8],
    ) -> Result<(), Error> {
        let ret = unsafe {
            aegis128x2_decrypt_detached(
                mc.as_mut_ptr(),
                mc.as_ptr(),
                mc.len(),
                tag.as_ptr(),
                TAG_BYTES as _,
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

/// AEGIS, used as a MAC, with support for incremental updates.
///
/// The state can be cloned to authenticate multiple messages with the same key.
///
/// 256-bit output tags are recommended for security.
///
/// Note that AEGIS is not a hash function. It is a MAC that requires a secret key.
/// Inputs leading to a state collision can be efficiently computed if the key is known.
#[derive(Debug)]
pub struct Aegis128X2Mac<const TAG_BYTES: usize> {
    st: aegis128x2_state,
}

impl<const TAG_BYTES: usize> Clone for Aegis128X2Mac<TAG_BYTES> {
    fn clone(&self) -> Self {
        let mut st = MaybeUninit::<aegis128x2_state>::uninit();
        unsafe {
            aegis128x2_mac_state_clone(st.as_mut_ptr(), &self.st);
        }
        Aegis128X2Mac {
            st: unsafe { st.assume_init() },
        }
    }
}

impl<const TAG_BYTES: usize> Aegis128X2Mac<TAG_BYTES> {
    fn ensure_init() {
        #[cfg(feature = "std")]
        INIT.call_once(|| assert_eq!(unsafe { aegis_init() }, 0));

        #[cfg(not(feature = "std"))]
        {
            use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

            if INITIALIZED.load(Acquire) {
                return;
            }
            let initializing = match INITIALIZING.compare_exchange(false, true, Acquire, Relaxed) {
                Ok(initializing) => initializing,
                Err(initializing) => initializing,
            };
            if initializing {
                while !INITIALIZED.load(Acquire) {}
            } else {
                assert_eq!(unsafe { aegis_init() }, 0);
                INITIALIZED.store(true, Release);
                INITIALIZING.store(false, Release);
            }
        }
    }

    /// Initializes the MAC state with a key.
    ///
    /// The state can be cloned to authenticate multiple messages with the same key.
    pub fn new(key: &Key) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Self::ensure_init();
        let mut st = MaybeUninit::<aegis128x2_state>::uninit();
        unsafe {
            aegis128x2_mac_init(st.as_mut_ptr(), key.as_ptr());
        }
        Aegis128X2Mac {
            st: unsafe { st.assume_init() },
        }
    }

    /// Updates the MAC state with a message
    ///
    /// This function can be called multiple times to update the MAC state with additional data.
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            aegis128x2_mac_update(&mut self.st, m.as_ptr(), m.len());
        }
    }

    /// Finalizes the MAC and returns the authentication tag
    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis128x2_mac_final(&mut self.st, tag.as_mut_ptr(), TAG_BYTES);
        }
        tag
    }

    /// Verifies the authentication tag
    pub fn verify(mut self, tag: &Tag<TAG_BYTES>) -> Result<(), Error> {
        let res = unsafe { aegis128x2_mac_verify(&mut self.st, tag.as_ptr(), TAG_BYTES) };
        if res != 0 {
            return Err(Error::InvalidTag);
        }
        Ok(())
    }
}

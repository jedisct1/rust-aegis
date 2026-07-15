use core::{ffi::c_int, fmt, mem::MaybeUninit};

use crate::incremental::{check_ad_length, MessageLength, Quarantine};
use crate::wipe::wipe_value;
pub use crate::Error;

/// AEGIS-256X2 key
pub type Key = [u8; 32];

/// AEGIS-256X2 nonce
pub type Nonce = [u8; 32];

#[allow(non_camel_case_types)]
#[repr(C)]
#[repr(align(32))]
struct aegis256x2_state {
    opaque: [u8; 320],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[repr(align(32))]
struct aegis256x2_mac_state {
    opaque: [u8; 512],
}

// Must stay in sync with the bundled aegis256x2.h.
const _: () = {
    assert!(core::mem::size_of::<aegis256x2_state>() == 320);
    assert!(core::mem::align_of::<aegis256x2_state>() == 32);
    assert!(core::mem::size_of::<aegis256x2_mac_state>() == 512);
    assert!(core::mem::align_of::<aegis256x2_mac_state>() == 32);
};

extern "C" {
    fn aegis_init() -> c_int;

    fn aegis256x2_state_init(
        st_: *mut aegis256x2_state,
        ad: *const u8,
        adlen: usize,
        npub: *const u8,
        k: *const u8,
    );

    fn aegis256x2_state_encrypt_update(
        st_: *mut aegis256x2_state,
        c: *mut u8,
        m: *const u8,
        mlen: usize,
    ) -> c_int;

    fn aegis256x2_state_encrypt_final(
        st_: *mut aegis256x2_state,
        mac: *mut u8,
        maclen: usize,
    ) -> c_int;

    fn aegis256x2_state_decrypt_update(
        st_: *mut aegis256x2_state,
        m: *mut u8,
        c: *const u8,
        clen: usize,
    ) -> c_int;

    fn aegis256x2_state_decrypt_final(
        st_: *mut aegis256x2_state,
        mac: *const u8,
        maclen: usize,
    ) -> c_int;

    fn aegis256x2_encrypt_detached(
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

    fn aegis256x2_decrypt_detached(
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

    fn aegis256x2_mac_init(st_: *mut aegis256x2_mac_state, k: *const u8, npub: *const u8);

    fn aegis256x2_mac_update(st_: *mut aegis256x2_mac_state, m: *const u8, mlen: usize) -> c_int;

    fn aegis256x2_mac_final(st_: *mut aegis256x2_mac_state, mac: *mut u8, maclen: usize) -> c_int;

    fn aegis256x2_mac_verify(
        st_: *mut aegis256x2_mac_state,
        mac: *const u8,
        maclen: usize,
    ) -> c_int;

    fn aegis256x2_mac_reset(st_: *mut aegis256x2_mac_state);

    fn aegis256x2_mac_state_clone(dst: *mut aegis256x2_mac_state, src: *const aegis256x2_mac_state);
}

#[cfg(feature = "std")]
static INIT: std::sync::Once = std::sync::Once::new();
#[cfg(not(feature = "std"))]
static INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
#[cfg(not(feature = "std"))]
static INITIALIZING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Tag length in bytes must be 16 (128 bits) or 32 (256 bits)
#[derive(Copy, Clone)]
pub struct Aegis256X2<const TAG_BYTES: usize> {
    key: Key,
    nonce: Nonce,
}

impl<const TAG_BYTES: usize> fmt::Debug for Aegis256X2<TAG_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis256X2").finish_non_exhaustive()
    }
}

/// AEGIS-256X2 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

impl<const TAG_BYTES: usize> Aegis256X2<TAG_BYTES> {
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

    /// Creates a new AEGIS-256X2 instance from a key and a nonce.
    ///
    /// `key` and `nonce` must be 32 bytes long.
    ///
    /// # Panics
    /// Panics if `TAG_BYTES` is not 16 or 32.
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Self::ensure_init();
        Aegis256X2 {
            key: *key,
            nonce: *nonce,
        }
    }

    /// Encrypts a message using AEGIS-256X2
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
            aegis256x2_encrypt_detached(
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

    /// Encrypts a message in-place using AEGIS-256X2
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    pub fn encrypt_in_place(self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis256x2_encrypt_detached(
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

    /// Decrypts a message using AEGIS-256X2
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
            aegis256x2_decrypt_detached(
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

    /// Decrypts a message in-place using AEGIS-256X2
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
            aegis256x2_decrypt_detached(
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

    /// Starts an incremental encryption of a single message.
    ///
    /// The associated data must be complete up front.
    /// The message itself can then be fed to the returned [`Encryptor`] in chunks of any size.
    ///
    /// As with the one-shot functions, a key and nonce pair must never be reused.
    ///
    /// # Panics
    /// Panics if `associated_data` is longer than `2^61 - 1` bytes.
    pub fn encryptor(&self, associated_data: &[u8]) -> Encryptor<TAG_BYTES> {
        Encryptor {
            st: self.state_init(associated_data),
            mlen: MessageLength::new(),
        }
    }

    /// Starts an incremental decryption of a single message.
    ///
    /// `plaintext` must be large enough to receive the whole decrypted message.
    /// It stays exclusively borrowed by the returned [`Decryptor`],
    /// so the decrypted bytes stay out of reach until [`Decryptor::finalize`] verifies the tag.
    ///
    /// # Panics
    /// Panics if `associated_data` is longer than `2^61 - 1` bytes.
    pub fn decryptor<'a>(
        &self,
        associated_data: &[u8],
        plaintext: &'a mut [u8],
    ) -> Decryptor<'a, TAG_BYTES> {
        Decryptor {
            st: self.state_init(associated_data),
            plaintext: Quarantine::new(plaintext),
            mlen: MessageLength::new(),
        }
    }

    fn state_init(&self, ad: &[u8]) -> aegis256x2_state {
        check_ad_length(ad);
        let mut st = MaybeUninit::<aegis256x2_state>::uninit();
        unsafe {
            aegis256x2_state_init(
                st.as_mut_ptr(),
                ad.as_ptr(),
                ad.len(),
                self.nonce.as_ptr(),
                self.key.as_ptr(),
            );
            st.assume_init()
        }
    }
}

/// Incremental AEGIS-256X2 encryption of a single message.
///
/// Created with [`Aegis256X2::encryptor`].
/// Each update emits one ciphertext byte per plaintext byte, so chunks can have any size.
/// [`Encryptor::finalize`] returns the detached authentication tag.
///
/// The internal state is erased on drop.
pub struct Encryptor<const TAG_BYTES: usize> {
    st: aegis256x2_state,
    mlen: MessageLength,
}

impl<const TAG_BYTES: usize> Encryptor<TAG_BYTES> {
    /// Encrypts the next plaintext chunk into `ciphertext`.
    ///
    /// # Panics
    /// Panics if the two slices differ in length, or if the cumulative
    /// message length exceeds `2^61 - 1` bytes.
    pub fn update(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert_eq!(
            plaintext.len(),
            ciphertext.len(),
            "plaintext and ciphertext chunks must have the same length"
        );
        self.raw_update(ciphertext.as_mut_ptr(), plaintext.as_ptr(), plaintext.len());
    }

    /// Encrypts the next chunk in place.
    ///
    /// # Panics
    /// Panics if the cumulative message length exceeds `2^61 - 1` bytes.
    pub fn update_in_place(&mut self, buffer: &mut [u8]) {
        self.raw_update(buffer.as_mut_ptr(), buffer.as_ptr(), buffer.len());
    }

    /// Completes the encryption and returns the detached authentication tag.
    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        let rc =
            unsafe { aegis256x2_state_encrypt_final(&mut self.st, tag.as_mut_ptr(), TAG_BYTES) };
        assert_eq!(rc, 0, "unexpected libaegis encryption failure");
        tag
    }

    fn raw_update(&mut self, ciphertext: *mut u8, plaintext: *const u8, len: usize) {
        self.mlen.add(len);
        let rc =
            unsafe { aegis256x2_state_encrypt_update(&mut self.st, ciphertext, plaintext, len) };
        assert_eq!(rc, 0, "unexpected libaegis encryption failure");
    }

    #[cfg(test)]
    pub(crate) fn set_consumed_length_for_tests(&mut self, mlen: u64) {
        self.mlen.set_for_tests(mlen);
    }
}

impl<const TAG_BYTES: usize> fmt::Debug for Encryptor<TAG_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("aegis256x2::Encryptor")
            .finish_non_exhaustive()
    }
}

impl<const TAG_BYTES: usize> Drop for Encryptor<TAG_BYTES> {
    fn drop(&mut self) {
        wipe_value(&mut self.st);
    }
}

/// Incremental AEGIS-256X2 decryption of a single message.
///
/// Created with [`Aegis256X2::decryptor`].
/// Ciphertext chunks are decrypted into the borrowed destination buffer,
/// and the plaintext only becomes reachable once [`Decryptor::finalize`] has verified the tag.
///
/// If verification fails, or if the value is dropped before finalization,
/// the decrypted bytes and the internal state are erased.
pub struct Decryptor<'a, const TAG_BYTES: usize> {
    st: aegis256x2_state,
    plaintext: Quarantine<'a>,
    mlen: MessageLength,
}

impl<'a, const TAG_BYTES: usize> Decryptor<'a, TAG_BYTES> {
    /// Decrypts the next ciphertext chunk into the borrowed destination.
    ///
    /// On error, nothing is consumed and the decryptor remains usable.
    pub fn update(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        self.plaintext.fits(ciphertext.len())?;
        self.mlen.try_add(ciphertext.len())?;
        let plaintext = self.plaintext.next_chunk(ciphertext.len());
        let rc = unsafe {
            aegis256x2_state_decrypt_update(
                &mut self.st,
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        assert_eq!(rc, 0, "unexpected libaegis decryption failure");
        Ok(())
    }

    /// Verifies the authentication tag and releases the decrypted message.
    ///
    /// On success, returns the written prefix of the destination buffer.
    /// On failure, the decrypted bytes are erased and [`Error::InvalidTag`] is returned.
    pub fn finalize(mut self, tag: &Tag<TAG_BYTES>) -> Result<&'a mut [u8], Error> {
        let rc = unsafe { aegis256x2_state_decrypt_final(&mut self.st, tag.as_ptr(), TAG_BYTES) };
        if rc != 0 {
            return Err(Error::InvalidTag);
        }
        Ok(self.plaintext.release())
    }

    #[cfg(test)]
    pub(crate) fn set_consumed_length_for_tests(&mut self, mlen: u64) {
        self.mlen.set_for_tests(mlen);
    }
}

impl<const TAG_BYTES: usize> fmt::Debug for Decryptor<'_, TAG_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("aegis256x2::Decryptor")
            .finish_non_exhaustive()
    }
}

impl<const TAG_BYTES: usize> Drop for Decryptor<'_, TAG_BYTES> {
    fn drop(&mut self) {
        wipe_value(&mut self.st);
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
pub struct Aegis256X2Mac<const TAG_BYTES: usize> {
    st: aegis256x2_mac_state,
}

impl<const TAG_BYTES: usize> fmt::Debug for Aegis256X2Mac<TAG_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aegis256X2Mac").finish_non_exhaustive()
    }
}

impl<const TAG_BYTES: usize> Clone for Aegis256X2Mac<TAG_BYTES> {
    fn clone(&self) -> Self {
        let mut st = MaybeUninit::<aegis256x2_mac_state>::uninit();
        unsafe {
            aegis256x2_mac_state_clone(st.as_mut_ptr(), &self.st);
        }
        Aegis256X2Mac {
            st: unsafe { st.assume_init() },
        }
    }
}

impl<const TAG_BYTES: usize> Aegis256X2Mac<TAG_BYTES> {
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
        let mut st = MaybeUninit::<aegis256x2_mac_state>::uninit();
        unsafe {
            aegis256x2_mac_init(st.as_mut_ptr(), key.as_ptr(), [0u8; 32].as_ptr());
        }
        Aegis256X2Mac {
            st: unsafe { st.assume_init() },
        }
    }

    /// Initializes the MAC state with a key and a nonce.
    ///
    /// The state can be cloned to authenticate multiple messages with the same key.
    pub fn new_with_nonce(key: &Key, npub: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Self::ensure_init();
        let mut st = MaybeUninit::<aegis256x2_mac_state>::uninit();
        unsafe {
            aegis256x2_mac_init(st.as_mut_ptr(), key.as_ptr(), npub.as_ptr());
        }
        Aegis256X2Mac {
            st: unsafe { st.assume_init() },
        }
    }

    /// Updates the MAC state with a message
    ///
    /// This function can be called multiple times to update the MAC state with additional data.
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            aegis256x2_mac_update(&mut self.st, m.as_ptr(), m.len());
        }
    }

    /// Finalizes the MAC and returns the authentication tag
    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis256x2_mac_final(&mut self.st, tag.as_mut_ptr(), TAG_BYTES);
        }
        tag
    }

    /// Finalizes the MAC, resets the state for reuse, and returns the authentication tag
    pub fn finalize_and_reset(&mut self) -> Tag<TAG_BYTES> {
        let mut tag = [0u8; TAG_BYTES];
        unsafe {
            aegis256x2_mac_final(&mut self.st, tag.as_mut_ptr(), TAG_BYTES);
            aegis256x2_mac_reset(&mut self.st);
        }
        tag
    }

    /// Verifies the authentication tag
    pub fn verify(mut self, tag: &Tag<TAG_BYTES>) -> Result<(), Error> {
        let res = unsafe { aegis256x2_mac_verify(&mut self.st, tag.as_ptr(), TAG_BYTES) };
        if res != 0 {
            return Err(Error::InvalidTag);
        }
        Ok(())
    }

    /// Resets the MAC state
    pub fn reset(&mut self) {
        unsafe {
            aegis256x2_mac_reset(&mut self.st);
        }
    }
}

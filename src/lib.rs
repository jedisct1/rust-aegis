#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_crate;
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_crate::AesBlock;

#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_ni;
#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_ni::AesBlock;

use core::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidTag,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// AEGIS-128L AEAD.
pub mod aegis128l {
    use crate::AesBlock;
    pub use crate::Error;

    /// AEGIS-128L authentication tag
    pub type Tag = [u8; 16];

    /// AEGIS-128L key
    pub type Key = [u8; 16];

    /// AEGIS-128L nonce
    pub type Nonce = [u8; 16];

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy)]
    struct State {
        blocks: [AesBlock; 8],
    }

    impl State {
        fn update(&mut self, d1: AesBlock, d2: AesBlock) {
            let blocks = &mut self.blocks;
            let tmp = blocks[7];
            let mut i = 7;
            while i > 0 {
                blocks[i] = blocks[i - 1].round(blocks[i]);
                i -= 1;
            }
            blocks[0] = tmp.round(blocks[0]);
            blocks[0] = blocks[0].xor(d1);
            blocks[4] = blocks[4].xor(d2);
        }

        pub fn new(key: &Key, nonce: &Nonce) -> Self {
            let c1 = AesBlock::from_bytes(&[
                0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
                0x28, 0xdd,
            ]);
            let c2 = AesBlock::from_bytes(&[
                0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
                0x79, 0x62,
            ]);
            let key_block = AesBlock::from_bytes(key);
            let nonce_block = AesBlock::from_bytes(nonce);
            let blocks: [AesBlock; 8] = [
                key_block.xor(nonce_block),
                c1,
                c2,
                c1,
                key_block.xor(nonce_block),
                key_block.xor(c2),
                key_block.xor(c1),
                key_block.xor(c2),
            ];
            let mut state = State { blocks };
            for _ in 0..10 {
                state.update(nonce_block, key_block);
            }
            state
        }

        fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let z0 = blocks[6].xor(blocks[1]).xor(blocks[2].and(blocks[3]));
            let z1 = blocks[2].xor(blocks[5]).xor(blocks[6].and(blocks[7]));
            let msg0 = AesBlock::from_bytes(&src[..16]);
            let msg1 = AesBlock::from_bytes(&src[16..32]);
            let c0 = msg0.xor(z0);
            let c1 = msg1.xor(z1);
            dst[..16].copy_from_slice(&c0.as_bytes());
            dst[16..32].copy_from_slice(&c1.as_bytes());
            self.update(msg0, msg1);
        }

        fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let z0 = blocks[6].xor(blocks[1]).xor(blocks[2].and(blocks[3]));
            let z1 = blocks[2].xor(blocks[5]).xor(blocks[6].and(blocks[7]));
            let msg0 = AesBlock::from_bytes(&src[0..16]).xor(z0);
            let msg1 = AesBlock::from_bytes(&src[16..32]).xor(z1);
            dst[..16].copy_from_slice(&msg0.as_bytes());
            dst[16..32].copy_from_slice(&msg1.as_bytes());
            self.update(msg0, msg1);
        }

        fn dec_partial(&mut self, dst: &mut [u8; 32], src: &[u8]) {
            let len = src.len();
            let mut src_padded = [0u8; 32];
            src_padded[..len].copy_from_slice(src);

            let blocks = &self.blocks;
            let z0 = blocks[6].xor(blocks[1]).xor(blocks[2].and(blocks[3]));
            let z1 = blocks[2].xor(blocks[5]).xor(blocks[6].and(blocks[7]));
            let msg_padded0 = AesBlock::from_bytes(&src_padded[0..16]).xor(z0);
            let msg_padded1 = AesBlock::from_bytes(&src_padded[16..32]).xor(z1);

            dst[..16].copy_from_slice(&msg_padded0.as_bytes());
            dst[16..32].copy_from_slice(&msg_padded1.as_bytes());
            dst[len..].fill(0);

            let msg0 = AesBlock::from_bytes(&dst[0..16]);
            let msg1 = AesBlock::from_bytes(&dst[16..32]);
            self.update(msg0, msg1);
        }

        fn mac(&mut self, adlen: usize, mlen: usize) -> Tag {
            let tmp = {
                let blocks = &self.blocks;
                let mut sizes = [0u8; 16];
                sizes[..8].copy_from_slice(&(adlen as u64 * 8).to_le_bytes());
                sizes[8..16].copy_from_slice(&(mlen as u64 * 8).to_le_bytes());
                AesBlock::from_bytes(&sizes).xor(blocks[2])
            };
            for _ in 0..7 {
                let tmp2 = tmp;
                self.update(tmp, tmp2);
            }
            let blocks = &self.blocks;
            let mac = blocks[0]
                .xor(blocks[1])
                .xor(blocks[2])
                .xor(blocks[3])
                .xor(blocks[4])
                .xor(blocks[5])
                .xor(blocks[6]);
            mac.as_bytes()
        }
    }

    #[repr(transparent)]
    pub struct Aegis128L(State);

    impl Aegis128L {
        /// Create a new AEAD instance.
        /// `key` and `nonce` must be 16 bytes long.
        pub fn new(nonce: &Nonce, key: &Key) -> Self {
            Aegis128L(State::new(key, nonce))
        }

        /// Encrypts a message using AEGIS-128L
        /// # Arguments
        /// * `m` - Message
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        #[cfg(feature = "std")]
        pub fn encrypt(mut self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag) {
            let state = &mut self.0;
            let mlen = m.len();
            let adlen = ad.len();
            let mut c = Vec::with_capacity(mlen);
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mlen {
                src.copy_from_slice(&m[i..][..32]);
                state.enc(&mut dst, &src);
                c.extend_from_slice(&dst);
                i += 32;
            }
            if mlen % 32 != 0 {
                src.fill(0);
                src[..mlen % 32].copy_from_slice(&m[i..]);
                state.enc(&mut dst, &src);
                c.extend_from_slice(&dst[..mlen % 32]);
            }
            let tag = state.mac(adlen, mlen);
            (c, tag)
        }

        /// Encrypts a message in-place using AEGIS-128L
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag {
            let state = &mut self.0;
            let mclen = mc.len();
            let adlen = ad.len();
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mclen {
                src.copy_from_slice(&mc[i..][..32]);
                state.enc(&mut dst, &src);
                mc[i..][..32].copy_from_slice(&dst);
                i += 32;
            }
            if mclen % 32 != 0 {
                src.fill(0);
                src[..mclen % 32].copy_from_slice(&mc[i..]);
                state.enc(&mut dst, &src);
                mc[i..].copy_from_slice(&dst[..mclen % 32]);
            }

            state.mac(adlen, mclen)
        }

        /// Decrypts a message using AEGIS-128L
        /// # Arguments
        /// * `c` - Ciphertext
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        /// # Returns
        /// Decrypted message.
        #[cfg(feature = "std")]
        pub fn decrypt(mut self, c: &[u8], tag: &Tag, ad: &[u8]) -> Result<Vec<u8>, Error> {
            let state = &mut self.0;
            let clen = c.len();
            let adlen = ad.len();
            let mut m = Vec::with_capacity(clen);
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= clen {
                src.copy_from_slice(&c[i..][..32]);
                state.dec(&mut dst, &src);
                m.extend_from_slice(&dst);
                i += 32;
            }
            if clen % 32 != 0 {
                state.dec_partial(&mut dst, &c[i..]);
                m.extend_from_slice(&dst[0..clen % 32]);
            }
            let tag2 = state.mac(adlen, clen);
            let mut acc = 0;
            for (a, b) in tag.iter().zip(tag2.iter()) {
                acc |= a ^ b;
            }
            if acc != 0 {
                m.fill(0xaa);
                return Err(Error::InvalidTag);
            }
            Ok(m)
        }

        /// Decrypts a message in-place using AEGIS-128L
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        pub fn decrypt_in_place(
            mut self,
            mc: &mut [u8],
            tag: &Tag,
            ad: &[u8],
        ) -> Result<(), Error> {
            let state = &mut self.0;
            let mclen = mc.len();
            let adlen = ad.len();
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mclen {
                src.copy_from_slice(&mc[i..][..32]);
                state.dec(&mut dst, &src);
                mc[i..][..32].copy_from_slice(&dst);
                i += 32;
            }
            if mclen % 32 != 0 {
                state.dec_partial(&mut dst, &mc[i..]);
                mc[i..].copy_from_slice(&dst[0..mclen % 32]);
            }
            let tag2 = state.mac(adlen, mclen);
            let mut acc = 0;
            for (a, b) in tag.iter().zip(tag2.iter()) {
                acc |= a ^ b;
            }
            if acc != 0 {
                mc.fill(0xaa);
                return Err(Error::InvalidTag);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aegis128l::Aegis128L;

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Aegis128L::new(&nonce, key).encrypt(m, ad);
        let expected_c = [
            137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159,
            166, 71, 169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131,
            148, 166, 200, 180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196,
            143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206,
            238, 139, 2, 251, 194, 222, 185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127,
            160, 215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69, 205, 251, 65, 159,
            177, 3, 101,
        ];
        let expected_tag = [
            16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Aegis128L::new(&nonce, key).decrypt(&c, &tag, ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_aegis_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Aegis128L::new(&nonce, key).encrypt_in_place(&mut mc, ad);
        let expected_mc = [
            137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159,
            166, 71, 169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131,
            148, 166, 200, 180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196,
            143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206,
            238, 139, 2, 251, 194, 222, 185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127,
            160, 215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69, 205, 251, 65, 159,
            177, 3, 101,
        ];
        let expected_tag = [
            16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150,
        ];
        assert_eq!(mc, expected_mc);
        assert_eq!(tag, expected_tag);

        Aegis128L::new(&nonce, key)
            .decrypt_in_place(&mut mc, &tag, ad)
            .unwrap();
        assert_eq!(mc, m);
    }
}

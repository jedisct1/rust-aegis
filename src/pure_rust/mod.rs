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

/// AEGIS-128L AEAD.
pub mod aegis128l {
    use super::AesBlock;
    pub use crate::Error;

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

        #[inline(always)]
        fn absorb(&mut self, src: &[u8; 32]) {
            let msg0 = AesBlock::from_bytes(&src[..16]);
            let msg1 = AesBlock::from_bytes(&src[16..32]);
            self.update(msg0, msg1);
        }

        fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let z0 = blocks[6].xor(blocks[1]).xor(blocks[2].and(blocks[3]));
            let z1 = blocks[2].xor(blocks[5]).xor(blocks[6].and(blocks[7]));
            let msg0 = AesBlock::from_bytes(&src[..16]);
            let msg1 = AesBlock::from_bytes(&src[16..32]);
            let c0 = msg0.xor(z0);
            let c1 = msg1.xor(z1);
            dst[..16].copy_from_slice(&c0.to_bytes());
            dst[16..32].copy_from_slice(&c1.to_bytes());
            self.update(msg0, msg1);
        }

        fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let z0 = blocks[6].xor(blocks[1]).xor(blocks[2].and(blocks[3]));
            let z1 = blocks[2].xor(blocks[5]).xor(blocks[6].and(blocks[7]));
            let msg0 = AesBlock::from_bytes(&src[0..16]).xor(z0);
            let msg1 = AesBlock::from_bytes(&src[16..32]).xor(z1);
            dst[..16].copy_from_slice(&msg0.to_bytes());
            dst[16..32].copy_from_slice(&msg1.to_bytes());
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

            dst[..16].copy_from_slice(&msg_padded0.to_bytes());
            dst[16..32].copy_from_slice(&msg_padded1.to_bytes());
            dst[len..].fill(0);

            let msg0 = AesBlock::from_bytes(&dst[0..16]);
            let msg1 = AesBlock::from_bytes(&dst[16..32]);
            self.update(msg0, msg1);
        }

        fn mac<const TAG_BYTES: usize>(&mut self, adlen: usize, mlen: usize) -> Tag<TAG_BYTES> {
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
            let mut tag = [0u8; TAG_BYTES];
            match TAG_BYTES {
                16 => tag.copy_from_slice(
                    &blocks[0]
                        .xor(blocks[1])
                        .xor(blocks[2])
                        .xor(blocks[3])
                        .xor(blocks[4])
                        .xor(blocks[5])
                        .xor(blocks[6])
                        .to_bytes(),
                ),
                32 => {
                    tag[..16].copy_from_slice(
                        &blocks[0]
                            .xor(blocks[1])
                            .xor(blocks[2])
                            .xor(blocks[3])
                            .to_bytes(),
                    );
                    tag[16..].copy_from_slice(
                        &blocks[4]
                            .xor(blocks[5])
                            .xor(blocks[6])
                            .xor(blocks[7])
                            .to_bytes(),
                    );
                }
                _ => unreachable!(),
            }
            tag
        }
    }

    /// Tag length in bits must be 128 or 256
    #[repr(transparent)]
    pub struct Aegis128L<const TAG_BYTES: usize>(State);

    /// AEGIS-128L authentication tag
    pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

    impl<const TAG_BYTES: usize> Aegis128L<TAG_BYTES> {
        /// Create a new AEAD instance.
        /// `key` and `nonce` must be 16 bytes long.
        pub fn new(key: &Key, nonce: &Nonce) -> Self {
            assert!(
                TAG_BYTES == 16 || TAG_BYTES == 32,
                "Invalid tag length, must be 16 or 32"
            );
            Aegis128L(State::new(key, nonce))
        }

        /// Encrypts a message using AEGIS-128L
        /// # Arguments
        /// * `m` - Message
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        #[cfg(feature = "std")]
        pub fn encrypt(mut self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag<TAG_BYTES>) {
            let state = &mut self.0;
            let mlen = m.len();
            let adlen = ad.len();
            let mut c = Vec::with_capacity(mlen);
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.absorb(&src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.absorb(&src);
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
            let tag = state.mac::<TAG_BYTES>(adlen, mlen);
            (c, tag)
        }

        /// Encrypts a message in-place using AEGIS-128L
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
            let state = &mut self.0;
            let mclen = mc.len();
            let adlen = ad.len();
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.absorb(&src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.absorb(&src);
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

            state.mac::<TAG_BYTES>(adlen, mclen)
        }

        /// Decrypts a message using AEGIS-128L
        /// # Arguments
        /// * `c` - Ciphertext
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        /// # Returns
        /// Decrypted message.
        #[cfg(feature = "std")]
        pub fn decrypt(
            mut self,
            c: &[u8],
            tag: &Tag<TAG_BYTES>,
            ad: &[u8],
        ) -> Result<Vec<u8>, Error> {
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
            let tag2 = state.mac::<TAG_BYTES>(adlen, clen);
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
            tag: &Tag<TAG_BYTES>,
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
            let tag2 = state.mac::<TAG_BYTES>(adlen, mclen);
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

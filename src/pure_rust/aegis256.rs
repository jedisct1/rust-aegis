use super::AesBlock;
pub use crate::Error;

/// AEGIS-256 key
pub type Key = [u8; 32];

/// AEGIS-256 nonce
pub type Nonce = [u8; 32];

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct State {
    blocks: [AesBlock; 6],
}

impl State {
    #[inline(always)]
    fn update(&mut self, d: AesBlock) {
        let blocks = &mut self.blocks;
        let tmp = blocks[5];
        blocks[5] = blocks[4].round(blocks[5]);
        blocks[4] = blocks[3].round(blocks[4]);
        blocks[3] = blocks[2].round(blocks[3]);
        blocks[2] = blocks[1].round(blocks[2]);
        blocks[1] = blocks[0].round(blocks[1]);
        blocks[0] = tmp.round(blocks[0]).xor(d);
    }

    #[inline(always)]
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let c0 = AesBlock::from_bytes(&[
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62,
        ]);
        let c1 = AesBlock::from_bytes(&[
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
            0x28, 0xdd,
        ]);
        let key_blocks = (
            AesBlock::from_bytes(&key[0..16]),
            AesBlock::from_bytes(&key[16..32]),
        );
        let nonce_blocks = (
            AesBlock::from_bytes(&nonce[0..16]),
            AesBlock::from_bytes(&nonce[16..32]),
        );
        let kn_blocks = (
            key_blocks.0.xor(nonce_blocks.0),
            key_blocks.1.xor(nonce_blocks.1),
        );
        let blocks: [AesBlock; 6] = [
            kn_blocks.0,
            kn_blocks.1,
            c1,
            c0,
            key_blocks.0.xor(c0),
            key_blocks.1.xor(c1),
        ];
        let mut state = State { blocks };
        for _ in 0..4 {
            state.update(key_blocks.0);
            state.update(key_blocks.1);
            state.update(kn_blocks.0);
            state.update(kn_blocks.1);
        }
        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 16]) {
        let msg = AesBlock::from_bytes(src);
        self.update(msg);
    }

    #[inline(always)]
    fn enc(&mut self, dst: &mut [u8; 16], src: &[u8; 16]) {
        let blocks = &self.blocks;
        let z = blocks[5]
            .xor(blocks[4])
            .xor(blocks[1])
            .xor(blocks[2].and(blocks[3]));
        let msg = AesBlock::from_bytes(src);
        let c = msg.xor(z);
        dst.copy_from_slice(&c.to_bytes());
        self.update(msg);
    }

    #[inline(always)]
    fn dec(&mut self, dst: &mut [u8; 16], src: &[u8; 16]) {
        let blocks = &self.blocks;
        let z = blocks[5]
            .xor(blocks[4])
            .xor(blocks[1])
            .xor(blocks[2].and(blocks[3]));
        let msg = AesBlock::from_bytes(src).xor(z);
        dst.copy_from_slice(&msg.to_bytes());
        self.update(msg);
    }

    #[inline(always)]
    fn dec_partial(&mut self, dst: &mut [u8; 16], src: &[u8]) {
        let len = src.len();
        let mut src_padded = [0u8; 16];
        src_padded[..len].copy_from_slice(src);

        let blocks = &self.blocks;
        let z = blocks[5]
            .xor(blocks[4])
            .xor(blocks[1])
            .xor(blocks[2].and(blocks[3]));
        let msg_padded = AesBlock::from_bytes(&src_padded).xor(z);

        dst.copy_from_slice(&msg_padded.to_bytes());
        dst[len..].fill(0);

        let msg = AesBlock::from_bytes(dst);
        self.update(msg);
    }

    #[inline(always)]
    fn mac<const TAG_BYTES: usize>(&mut self, adlen: usize, mlen: usize) -> Tag<TAG_BYTES> {
        let tmp = {
            let blocks = &self.blocks;
            let mut sizes = [0u8; 16];
            sizes[..8].copy_from_slice(&(adlen as u64 * 8).to_le_bytes());
            sizes[8..16].copy_from_slice(&(mlen as u64 * 8).to_le_bytes());
            AesBlock::from_bytes(&sizes).xor(blocks[3])
        };
        for _ in 0..7 {
            self.update(tmp);
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
                    .to_bytes(),
            ),
            32 => {
                tag[..16].copy_from_slice(&blocks[0].xor(blocks[1]).xor(blocks[2]).to_bytes());
                tag[16..].copy_from_slice(&blocks[3].xor(blocks[4]).xor(blocks[5]).to_bytes());
            }
            _ => unreachable!(),
        }
        tag
    }

    #[inline(always)]
    fn mac_finalize<const TAG_BYTES: usize>(&mut self, data_len: usize) -> Tag<TAG_BYTES> {
        let tmp = {
            let blocks = &self.blocks;
            let mut sizes = [0u8; 16];
            sizes[..8].copy_from_slice(&(data_len as u64 * 8).to_le_bytes());
            sizes[8..16].copy_from_slice(&(TAG_BYTES as u64 * 8).to_le_bytes());
            AesBlock::from_bytes(&sizes).xor(blocks[3])
        };
        for _ in 0..7 {
            self.update(tmp);
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
                    .to_bytes(),
            ),
            32 => {
                tag[..16].copy_from_slice(&blocks[0].xor(blocks[1]).xor(blocks[2]).to_bytes());
                tag[16..].copy_from_slice(&blocks[3].xor(blocks[4]).xor(blocks[5]).to_bytes());
            }
            _ => unreachable!(),
        }
        tag
    }
}

/// Tag length in bits must be 128 or 256
#[repr(transparent)]
pub struct Aegis256<const TAG_BYTES: usize>(State);

/// AEGIS-256 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

impl<const TAG_BYTES: usize> Aegis256<TAG_BYTES> {
    /// Create a new AEAD instance.
    /// `key` and `nonce` must be 16 bytes long.
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Aegis256(State::new(key, nonce))
    }

    /// Encrypts a message using AEGIS-256
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
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        let mut i = 0;
        while i + 16 <= adlen {
            src.copy_from_slice(&ad[i..][..16]);
            state.absorb(&src);
            i += 16;
        }
        if adlen % 16 != 0 {
            src.fill(0);
            src[..adlen % 16].copy_from_slice(&ad[i..]);
            state.absorb(&src);
        }
        i = 0;
        while i + 16 <= mlen {
            src.copy_from_slice(&m[i..][..16]);
            state.enc(&mut dst, &src);
            c.extend_from_slice(&dst);
            i += 16;
        }
        if mlen % 16 != 0 {
            src.fill(0);
            src[..mlen % 16].copy_from_slice(&m[i..]);
            state.enc(&mut dst, &src);
            c.extend_from_slice(&dst[..mlen % 16]);
        }
        let tag = state.mac::<TAG_BYTES>(adlen, mlen);
        (c, tag)
    }

    /// Encrypts a message in-place using AEGIS-256
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let state = &mut self.0;
        let mclen = mc.len();
        let adlen = ad.len();
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        let mut i = 0;
        while i + 16 <= adlen {
            src.copy_from_slice(&ad[i..][..16]);
            state.absorb(&src);
            i += 16;
        }
        if adlen % 16 != 0 {
            src.fill(0);
            src[..adlen % 16].copy_from_slice(&ad[i..]);
            state.absorb(&src);
        }
        i = 0;
        while i + 16 <= mclen {
            src.copy_from_slice(&mc[i..][..16]);
            state.enc(&mut dst, &src);
            mc[i..][..16].copy_from_slice(&dst);
            i += 16;
        }
        if mclen % 16 != 0 {
            src.fill(0);
            src[..mclen % 16].copy_from_slice(&mc[i..]);
            state.enc(&mut dst, &src);
            mc[i..].copy_from_slice(&dst[..mclen % 16]);
        }

        state.mac::<TAG_BYTES>(adlen, mclen)
    }

    /// Decrypts a message using AEGIS-256
    /// # Arguments
    /// * `c` - Ciphertext
    /// * `tag` - Authentication tag
    /// * `ad` - Associated data
    /// # Returns
    /// Decrypted message.
    #[cfg(feature = "std")]
    pub fn decrypt(mut self, c: &[u8], tag: &Tag<TAG_BYTES>, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let state = &mut self.0;
        let clen = c.len();
        let adlen = ad.len();
        let mut m = Vec::with_capacity(clen);
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        let mut i = 0;
        while i + 16 <= adlen {
            src.copy_from_slice(&ad[i..][..16]);
            state.enc(&mut dst, &src);
            i += 16;
        }
        if adlen % 16 != 0 {
            src.fill(0);
            src[..adlen % 16].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 16 <= clen {
            src.copy_from_slice(&c[i..][..16]);
            state.dec(&mut dst, &src);
            m.extend_from_slice(&dst);
            i += 16;
        }
        if clen % 16 != 0 {
            state.dec_partial(&mut dst, &c[i..]);
            m.extend_from_slice(&dst[0..clen % 16]);
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

    /// Decrypts a message in-place using AEGIS-256
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
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        let mut i = 0;
        while i + 16 <= adlen {
            src.copy_from_slice(&ad[i..][..16]);
            state.enc(&mut dst, &src);
            i += 16;
        }
        if adlen % 16 != 0 {
            src.fill(0);
            src[..adlen % 16].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 16 <= mclen {
            src.copy_from_slice(&mc[i..][..16]);
            state.dec(&mut dst, &src);
            mc[i..][..16].copy_from_slice(&dst);
            i += 16;
        }
        if mclen % 16 != 0 {
            state.dec_partial(&mut dst, &mc[i..]);
            mc[i..].copy_from_slice(&dst[0..mclen % 16]);
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

/// AEGIS-256 MAC with incremental update support.
///
/// The state can be cloned to authenticate multiple messages with the same key.
///
/// 256-bit output tags are recommended for security.
///
/// Note that AEGIS is not a hash function. It is a MAC that requires a secret key.
/// Inputs leading to a state collision can be efficiently computed if the key is known.
#[derive(Clone)]
pub struct Aegis256Mac<const TAG_BYTES: usize> {
    state: State,
    buf: [u8; 16],
    buf_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis256Mac<TAG_BYTES> {
    /// Initializes the MAC state with a key.
    ///
    /// The state can be cloned to authenticate multiple messages with the same key.
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 32];
        Self::new_with_nonce(key, &nonce)
    }

    /// Initializes the MAC state with a key and a nonce.
    ///
    /// The state can be cloned to authenticate multiple messages with the same key.
    pub fn new_with_nonce(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Aegis256Mac {
            state: State::new(key, nonce),
            buf: [0u8; 16],
            buf_len: 0,
            msg_len: 0,
        }
    }

    /// Updates the MAC state with a message.
    ///
    /// This function can be called multiple times to update the MAC state with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.msg_len += data.len();
        let mut offset = 0;

        // Process buffered data first
        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() < needed {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..].copy_from_slice(&data[..needed]);
            self.state.absorb(&self.buf);
            self.buf_len = 0;
            offset = needed;
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.state.absorb(&block);
            offset += 16;
        }

        // Buffer remaining
        if offset < data.len() {
            self.buf_len = data.len() - offset;
            self.buf[..self.buf_len].copy_from_slice(&data[offset..]);
        }
    }

    /// Finalizes the MAC and returns the authentication tag.
    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        if self.buf_len > 0 || self.msg_len == 0 {
            self.buf[self.buf_len..].fill(0);
            self.state.absorb(&self.buf);
        }
        self.state.mac_finalize::<TAG_BYTES>(self.msg_len)
    }

    /// Verifies the authentication tag.
    pub fn verify(self, expected: &Tag<TAG_BYTES>) -> Result<(), Error> {
        let tag = self.finalize();
        let mut acc = 0u8;
        for (a, b) in tag.iter().zip(expected.iter()) {
            acc |= a ^ b;
        }
        if acc != 0 {
            return Err(Error::InvalidTag);
        }
        Ok(())
    }
}

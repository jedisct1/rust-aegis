use super::{AesBlock, AesBlock2};
pub use crate::Error;

/// AEGIS-128X2 key
pub type Key = [u8; 16];

/// AEGIS-128X2 nonce
pub type Nonce = [u8; 16];

/// AEGIS-128X2 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

/// State for AEGIS-128X2 with 8 rows of 2 parallel AES blocks
#[derive(Clone, Copy)]
struct State {
    s0: AesBlock2,
    s1: AesBlock2,
    s2: AesBlock2,
    s3: AesBlock2,
    s4: AesBlock2,
    s5: AesBlock2,
    s6: AesBlock2,
    s7: AesBlock2,
}

impl State {
    #[inline(always)]
    fn update(&mut self, m0: AesBlock2, m1: AesBlock2) {
        let tmp = self.s7;
        self.s7 = self.s6.round(self.s7);
        self.s6 = self.s5.round(self.s6);
        self.s5 = self.s4.round(self.s5);
        self.s4 = self.s3.round(self.s4).xor(m1);
        self.s3 = self.s2.round(self.s3);
        self.s2 = self.s1.round(self.s2);
        self.s1 = self.s0.round(self.s1);
        self.s0 = tmp.round(self.s0).xor(m0);
    }

    #[inline(always)]
    fn new(key: &Key, nonce: &Nonce) -> Self {
        let c0 = AesBlock::from_bytes(&[
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62,
        ]);
        let c1 = AesBlock::from_bytes(&[
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
            0x28, 0xdd,
        ]);

        let key_block = AesBlock::from_bytes(key);
        let nonce_block = AesBlock::from_bytes(nonce);
        let kn = key_block.xor(nonce_block);
        let kc0 = key_block.xor(c0);
        let kc1 = key_block.xor(c1);

        // Context blocks for each parallel state
        let ctx0 = AesBlock::from_bytes(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx1 = AesBlock::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let kn2 = AesBlock2::from_blocks(kn, kn);
        let c0_2 = AesBlock2::from_blocks(c0, c0);
        let c1_2 = AesBlock2::from_blocks(c1, c1);
        let kc0_2 = AesBlock2::from_blocks(kc0, kc0);
        let kc1_2 = AesBlock2::from_blocks(kc1, kc1);
        let ctx = AesBlock2::from_blocks(ctx0, ctx1);
        let nonce2 = AesBlock2::from_blocks(nonce_block, nonce_block);
        let key2 = AesBlock2::from_blocks(key_block, key_block);

        let mut state = State {
            s0: kn2,
            s1: c1_2,
            s2: c0_2,
            s3: c1_2,
            s4: kn2,
            s5: kc0_2,
            s6: kc1_2,
            s7: kc0_2,
        };

        for _ in 0..10 {
            state.s3 = state.s3.xor(ctx);
            state.s7 = state.s7.xor(ctx);
            state.update(nonce2, key2);
        }

        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 64]) {
        let m0 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
        );
        let m1 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );
        self.update(m0, m1);
    }

    #[inline(always)]
    fn enc(&mut self, dst: &mut [u8; 64], src: &[u8; 64]) {
        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let m0 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
        );
        let m1 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );

        let c0 = m0.xor(z0);
        let c1 = m1.xor(z1);

        let (c00, c01) = c0.as_blocks();
        let (c10, c11) = c1.as_blocks();
        dst[0..16].copy_from_slice(&c00.to_bytes());
        dst[16..32].copy_from_slice(&c01.to_bytes());
        dst[32..48].copy_from_slice(&c10.to_bytes());
        dst[48..64].copy_from_slice(&c11.to_bytes());

        self.update(m0, m1);
    }

    #[inline(always)]
    fn dec(&mut self, dst: &mut [u8; 64], src: &[u8; 64]) {
        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let c0 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
        );
        let c1 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );

        let m0 = c0.xor(z0);
        let m1 = c1.xor(z1);

        let (m00, m01) = m0.as_blocks();
        let (m10, m11) = m1.as_blocks();
        dst[0..16].copy_from_slice(&m00.to_bytes());
        dst[16..32].copy_from_slice(&m01.to_bytes());
        dst[32..48].copy_from_slice(&m10.to_bytes());
        dst[48..64].copy_from_slice(&m11.to_bytes());

        self.update(m0, m1);
    }

    #[inline(always)]
    fn dec_partial(&mut self, dst: &mut [u8], src: &[u8]) {
        let len = src.len();
        debug_assert!(len < 64);

        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let (z00, z01) = z0.as_blocks();
        let (z10, z11) = z1.as_blocks();

        let mut pad = [0u8; 64];
        pad[..len].copy_from_slice(src);

        // XOR with keystream
        let mut out = [0u8; 64];
        let p0 = AesBlock::from_bytes(&pad[0..16]).xor(z00);
        let p1 = AesBlock::from_bytes(&pad[16..32]).xor(z01);
        let p2 = AesBlock::from_bytes(&pad[32..48]).xor(z10);
        let p3 = AesBlock::from_bytes(&pad[48..64]).xor(z11);
        out[0..16].copy_from_slice(&p0.to_bytes());
        out[16..32].copy_from_slice(&p1.to_bytes());
        out[32..48].copy_from_slice(&p2.to_bytes());
        out[48..64].copy_from_slice(&p3.to_bytes());

        dst[..len].copy_from_slice(&out[..len]);

        // Zero pad for state update
        let mut msg_pad = [0u8; 64];
        msg_pad[..len].copy_from_slice(&out[..len]);
        let m0 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&msg_pad[0..16]),
            AesBlock::from_bytes(&msg_pad[16..32]),
        );
        let m1 = AesBlock2::from_blocks(
            AesBlock::from_bytes(&msg_pad[32..48]),
            AesBlock::from_bytes(&msg_pad[48..64]),
        );
        self.update(m0, m1);
    }

    #[inline(always)]
    fn mac<const TAG_BYTES: usize>(&mut self, adlen: usize, mlen: usize) -> Tag<TAG_BYTES> {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(adlen as u64 * 8).to_le_bytes());
        sizes[8..16].copy_from_slice(&(mlen as u64 * 8).to_le_bytes());
        let u = AesBlock::from_bytes(&sizes);

        let (s20, s21) = self.s2.as_blocks();
        let t0 = s20.xor(u);
        let t1 = s21.xor(u);
        let t = AesBlock2::from_blocks(t0, t1);

        for _ in 0..7 {
            self.update(t, t);
        }

        let (s00, s01) = self.s0.as_blocks();
        let (s10, s11) = self.s1.as_blocks();
        let (s20, s21) = self.s2.as_blocks();
        let (s30, s31) = self.s3.as_blocks();
        let (s40, s41) = self.s4.as_blocks();
        let (s50, s51) = self.s5.as_blocks();
        let (s60, s61) = self.s6.as_blocks();
        let (s70, s71) = self.s7.as_blocks();

        let mut tag = [0u8; TAG_BYTES];
        if TAG_BYTES == 16 {
            let t0 = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50).xor(s60);
            let t1 = s01.xor(s11).xor(s21).xor(s31).xor(s41).xor(s51).xor(s61);
            tag.copy_from_slice(&t0.xor(t1).to_bytes()[..TAG_BYTES]);
        } else {
            let t0_lo = s00.xor(s10).xor(s20).xor(s30);
            let t1_lo = s01.xor(s11).xor(s21).xor(s31);
            let t0_hi = s40.xor(s50).xor(s60).xor(s70);
            let t1_hi = s41.xor(s51).xor(s61).xor(s71);
            tag[..16].copy_from_slice(&t0_lo.xor(t1_lo).to_bytes());
            tag[16..].copy_from_slice(&t0_hi.xor(t1_hi).to_bytes());
        }
        tag
    }

    #[inline(always)]
    fn mac_finalize<const TAG_BYTES: usize>(&mut self, data_len: usize) -> Tag<TAG_BYTES> {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(data_len as u64 * 8).to_le_bytes());
        sizes[8..16].copy_from_slice(&(TAG_BYTES as u64 * 8).to_le_bytes());
        let u = AesBlock::from_bytes(&sizes);

        let (s20, s21) = self.s2.as_blocks();
        let t0 = s20.xor(u);
        let t1 = s21.xor(u);
        let t = AesBlock2::from_blocks(t0, t1);

        for _ in 0..7 {
            self.update(t, t);
        }

        let (s00, s01) = self.s0.as_blocks();
        let (s10, s11) = self.s1.as_blocks();
        let (s20, s21) = self.s2.as_blocks();
        let (s30, s31) = self.s3.as_blocks();
        let (s40, s41) = self.s4.as_blocks();
        let (s50, s51) = self.s5.as_blocks();
        let (s60, s61) = self.s6.as_blocks();
        let (_s70, s71) = self.s7.as_blocks();
        let zeros = AesBlock::from_bytes(&[0u8; 16]);

        if TAG_BYTES == 16 {
            let tag0 = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50).xor(s60);
            let tag1 = s01.xor(s11).xor(s21).xor(s31).xor(s41).xor(s51).xor(s61);
            let m0 = AesBlock2::from_blocks(tag0, zeros);
            let m1 = AesBlock2::from_blocks(tag1, zeros);
            self.update(m0, m1);
        } else {
            let tag1_lo = s01.xor(s11).xor(s21).xor(s31);
            let tag1_hi = s41.xor(s51).xor(s61).xor(s71);
            let m0 = AesBlock2::from_blocks(tag1_lo, zeros);
            let m1 = AesBlock2::from_blocks(tag1_hi, zeros);
            self.update(m0, m1);
        }

        let (s20, _) = self.s2.as_blocks();
        let mut extra_sizes = [0u8; 16];
        extra_sizes[..8].copy_from_slice(&2u64.to_le_bytes());
        extra_sizes[8..16].copy_from_slice(&(TAG_BYTES as u64 * 8).to_le_bytes());
        let extra_block = s20.xor(AesBlock::from_bytes(&extra_sizes));
        let extra = AesBlock2::from_blocks(extra_block, zeros);

        for _ in 0..7 {
            self.update(extra, extra);
        }

        let (s00, _) = self.s0.as_blocks();
        let (s10, _) = self.s1.as_blocks();
        let (s20, _) = self.s2.as_blocks();
        let (s30, _) = self.s3.as_blocks();
        let (s40, _) = self.s4.as_blocks();
        let (s50, _) = self.s5.as_blocks();
        let (s60, _) = self.s6.as_blocks();
        let (s70, _) = self.s7.as_blocks();

        let mut tag = [0u8; TAG_BYTES];
        if TAG_BYTES == 16 {
            let final_tag = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50).xor(s60);
            tag.copy_from_slice(&final_tag.to_bytes());
        } else {
            let final_lo = s00.xor(s10).xor(s20).xor(s30);
            let final_hi = s40.xor(s50).xor(s60).xor(s70);
            tag[..16].copy_from_slice(&final_lo.to_bytes());
            tag[16..].copy_from_slice(&final_hi.to_bytes());
        }
        tag
    }
}

/// AEGIS-128X2 authenticated encryption
#[derive(Clone, Copy)]
pub struct Aegis128X2<const TAG_BYTES: usize> {
    state: State,
}

impl<const TAG_BYTES: usize> Aegis128X2<TAG_BYTES> {
    /// Create a new AEGIS-128X2 instance
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        debug_assert!(TAG_BYTES == 16 || TAG_BYTES == 32);
        Aegis128X2 {
            state: State::new(key, nonce),
        }
    }

    /// Encrypt a message
    #[cfg(feature = "std")]
    pub fn encrypt(mut self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag<TAG_BYTES>) {
        let state = &mut self.state;
        let mlen = m.len();
        let adlen = ad.len();
        let mut c = vec![0u8; mlen];

        // Process AD
        let mut i = 0;
        while i + 64 <= adlen {
            let mut block = [0u8; 64];
            block.copy_from_slice(&ad[i..i + 64]);
            state.absorb(&block);
            i += 64;
        }
        if adlen % 64 != 0 {
            let mut block = [0u8; 64];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process message
        i = 0;
        while i + 64 <= mlen {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src.copy_from_slice(&m[i..i + 64]);
            state.enc(&mut dst, &src);
            c[i..i + 64].copy_from_slice(&dst);
            i += 64;
        }
        if mlen % 64 != 0 {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src[..mlen - i].copy_from_slice(&m[i..]);
            state.enc(&mut dst, &src);
            c[i..].copy_from_slice(&dst[..mlen - i]);
        }

        let tag = state.mac::<TAG_BYTES>(adlen, mlen);
        (c, tag)
    }

    /// Encrypt in place
    pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let state = &mut self.state;
        let mclen = mc.len();
        let adlen = ad.len();

        // Process AD
        let mut i = 0;
        while i + 64 <= adlen {
            let mut block = [0u8; 64];
            block.copy_from_slice(&ad[i..i + 64]);
            state.absorb(&block);
            i += 64;
        }
        if adlen % 64 != 0 {
            let mut block = [0u8; 64];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process message
        i = 0;
        while i + 64 <= mclen {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src.copy_from_slice(&mc[i..i + 64]);
            state.enc(&mut dst, &src);
            mc[i..i + 64].copy_from_slice(&dst);
            i += 64;
        }
        if mclen % 64 != 0 {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src[..mclen - i].copy_from_slice(&mc[i..]);
            state.enc(&mut dst, &src);
            mc[i..].copy_from_slice(&dst[..mclen - i]);
        }

        state.mac::<TAG_BYTES>(adlen, mclen)
    }

    /// Decrypt a message
    #[cfg(feature = "std")]
    pub fn decrypt(mut self, c: &[u8], tag: &Tag<TAG_BYTES>, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let state = &mut self.state;
        let clen = c.len();
        let adlen = ad.len();
        let mut m = vec![0u8; clen];

        // Process AD
        let mut i = 0;
        while i + 64 <= adlen {
            let mut block = [0u8; 64];
            block.copy_from_slice(&ad[i..i + 64]);
            state.absorb(&block);
            i += 64;
        }
        if adlen % 64 != 0 {
            let mut block = [0u8; 64];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process ciphertext
        i = 0;
        while i + 64 <= clen {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src.copy_from_slice(&c[i..i + 64]);
            state.dec(&mut dst, &src);
            m[i..i + 64].copy_from_slice(&dst);
            i += 64;
        }
        if clen % 64 != 0 {
            state.dec_partial(&mut m[i..], &c[i..]);
        }

        let tag2 = state.mac::<TAG_BYTES>(adlen, clen);
        let mut acc = 0u8;
        for (a, b) in tag.iter().zip(tag2.iter()) {
            acc |= a ^ b;
        }
        if acc != 0 {
            m.fill(0xaa);
            return Err(Error::InvalidTag);
        }
        Ok(m)
    }

    /// Decrypt in place
    pub fn decrypt_in_place(
        mut self,
        mc: &mut [u8],
        tag: &Tag<TAG_BYTES>,
        ad: &[u8],
    ) -> Result<(), Error> {
        let state = &mut self.state;
        let mclen = mc.len();
        let adlen = ad.len();

        // Process AD
        let mut i = 0;
        while i + 64 <= adlen {
            let mut block = [0u8; 64];
            block.copy_from_slice(&ad[i..i + 64]);
            state.absorb(&block);
            i += 64;
        }
        if adlen % 64 != 0 {
            let mut block = [0u8; 64];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process ciphertext
        i = 0;
        while i + 64 <= mclen {
            let mut src = [0u8; 64];
            let mut dst = [0u8; 64];
            src.copy_from_slice(&mc[i..i + 64]);
            state.dec(&mut dst, &src);
            mc[i..i + 64].copy_from_slice(&dst);
            i += 64;
        }
        if mclen % 64 != 0 {
            let remaining = mclen - i;
            let mut tmp = [0u8; 64];
            state.dec_partial(&mut tmp[..remaining], &mc[i..]);
            mc[i..].copy_from_slice(&tmp[..remaining]);
        }

        let tag2 = state.mac::<TAG_BYTES>(adlen, mclen);
        let mut acc = 0u8;
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

/// AEGIS-128X2 MAC
#[derive(Clone)]
pub struct Aegis128X2Mac<const TAG_BYTES: usize> {
    state: State,
    buf: [u8; 64],
    buf_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis128X2Mac<TAG_BYTES> {
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 16];
        Self::new_with_nonce(key, &nonce)
    }

    pub fn new_with_nonce(key: &Key, nonce: &Nonce) -> Self {
        Aegis128X2Mac {
            state: State::new(key, nonce),
            buf: [0u8; 64],
            buf_len: 0,
            msg_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.msg_len += data.len();
        let mut offset = 0;

        // Process buffered data first
        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
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
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.state.absorb(&block);
            offset += 64;
        }

        // Buffer remaining
        if offset < data.len() {
            self.buf_len = data.len() - offset;
            self.buf[..self.buf_len].copy_from_slice(&data[offset..]);
        }
    }

    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        // Pad and absorb final block
        if self.buf_len > 0 || self.msg_len == 0 {
            self.buf[self.buf_len..].fill(0);
            self.state.absorb(&self.buf);
        }
        self.state.mac_finalize::<TAG_BYTES>(self.msg_len)
    }

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

use super::{AesBlock, AesBlock4};
pub use crate::Error;

/// AEGIS-256X4 key
pub type Key = [u8; 32];

/// AEGIS-256X4 nonce
pub type Nonce = [u8; 32];

/// AEGIS-256X4 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

/// State for AEGIS-256X4 with 6 rows of 4 parallel AES blocks
#[derive(Clone, Copy)]
struct State {
    s0: AesBlock4,
    s1: AesBlock4,
    s2: AesBlock4,
    s3: AesBlock4,
    s4: AesBlock4,
    s5: AesBlock4,
}

impl State {
    #[inline(always)]
    fn update(&mut self, m: AesBlock4) {
        let tmp = self.s5;
        self.s5 = self.s4.round(self.s5);
        self.s4 = self.s3.round(self.s4);
        self.s3 = self.s2.round(self.s3);
        self.s2 = self.s1.round(self.s2);
        self.s1 = self.s0.round(self.s1);
        self.s0 = tmp.round(self.s0).xor(m);
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

        let k0 = AesBlock::from_bytes(&key[0..16]);
        let k1 = AesBlock::from_bytes(&key[16..32]);
        let n0 = AesBlock::from_bytes(&nonce[0..16]);
        let n1 = AesBlock::from_bytes(&nonce[16..32]);
        let k0n0 = k0.xor(n0);
        let k1n1 = k1.xor(n1);
        let k0c0 = k0.xor(c0);
        let k1c1 = k1.xor(c1);

        // Context blocks for each parallel state
        let ctx0 = AesBlock::from_bytes(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx1 = AesBlock::from_bytes(&[1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx2 = AesBlock::from_bytes(&[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx3 = AesBlock::from_bytes(&[3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let k0n0_4 = AesBlock4::from_blocks(k0n0, k0n0, k0n0, k0n0);
        let k1n1_4 = AesBlock4::from_blocks(k1n1, k1n1, k1n1, k1n1);
        let c0_4 = AesBlock4::from_blocks(c0, c0, c0, c0);
        let c1_4 = AesBlock4::from_blocks(c1, c1, c1, c1);
        let k0c0_4 = AesBlock4::from_blocks(k0c0, k0c0, k0c0, k0c0);
        let k1c1_4 = AesBlock4::from_blocks(k1c1, k1c1, k1c1, k1c1);
        let ctx = AesBlock4::from_blocks(ctx0, ctx1, ctx2, ctx3);
        let k0_4 = AesBlock4::from_blocks(k0, k0, k0, k0);
        let k1_4 = AesBlock4::from_blocks(k1, k1, k1, k1);

        let mut state = State {
            s0: k0n0_4,
            s1: k1n1_4,
            s2: c1_4,
            s3: c0_4,
            s4: k0c0_4,
            s5: k1c1_4,
        };

        for _ in 0..4 {
            state.s3 = state.s3.xor(ctx);
            state.s5 = state.s5.xor(ctx);
            state.update(k0_4);

            state.s3 = state.s3.xor(ctx);
            state.s5 = state.s5.xor(ctx);
            state.update(k1_4);

            state.s3 = state.s3.xor(ctx);
            state.s5 = state.s5.xor(ctx);
            state.update(k0n0_4);

            state.s3 = state.s3.xor(ctx);
            state.s5 = state.s5.xor(ctx);
            state.update(k1n1_4);
        }

        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 64]) {
        let m = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );
        self.update(m);
    }

    #[inline(always)]
    fn enc(&mut self, dst: &mut [u8; 64], src: &[u8; 64]) {
        let z = self.s1.xor(self.s4).xor(self.s5).xor(self.s2.and(self.s3));

        let m = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );

        let c = m.xor(z);
        let (c0, c1, c2, c3) = c.as_blocks();
        dst[0..16].copy_from_slice(&c0.to_bytes());
        dst[16..32].copy_from_slice(&c1.to_bytes());
        dst[32..48].copy_from_slice(&c2.to_bytes());
        dst[48..64].copy_from_slice(&c3.to_bytes());

        self.update(m);
    }

    #[inline(always)]
    fn dec(&mut self, dst: &mut [u8; 64], src: &[u8; 64]) {
        let z = self.s1.xor(self.s4).xor(self.s5).xor(self.s2.and(self.s3));

        let c = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );

        let m = c.xor(z);
        let (m0, m1, m2, m3) = m.as_blocks();
        dst[0..16].copy_from_slice(&m0.to_bytes());
        dst[16..32].copy_from_slice(&m1.to_bytes());
        dst[32..48].copy_from_slice(&m2.to_bytes());
        dst[48..64].copy_from_slice(&m3.to_bytes());

        self.update(m);
    }

    #[inline(always)]
    fn dec_partial(&mut self, dst: &mut [u8], src: &[u8]) {
        let len = src.len();
        debug_assert!(len < 64);

        let z = self.s1.xor(self.s4).xor(self.s5).xor(self.s2.and(self.s3));
        let (z0, z1, z2, z3) = z.as_blocks();

        let mut pad = [0u8; 64];
        pad[..len].copy_from_slice(src);

        // XOR with keystream
        let mut out = [0u8; 64];
        let p0 = AesBlock::from_bytes(&pad[0..16]).xor(z0);
        let p1 = AesBlock::from_bytes(&pad[16..32]).xor(z1);
        let p2 = AesBlock::from_bytes(&pad[32..48]).xor(z2);
        let p3 = AesBlock::from_bytes(&pad[48..64]).xor(z3);
        out[0..16].copy_from_slice(&p0.to_bytes());
        out[16..32].copy_from_slice(&p1.to_bytes());
        out[32..48].copy_from_slice(&p2.to_bytes());
        out[48..64].copy_from_slice(&p3.to_bytes());

        dst[..len].copy_from_slice(&out[..len]);

        // Zero pad for state update
        let mut msg_pad = [0u8; 64];
        msg_pad[..len].copy_from_slice(&out[..len]);
        let m = AesBlock4::from_blocks(
            AesBlock::from_bytes(&msg_pad[0..16]),
            AesBlock::from_bytes(&msg_pad[16..32]),
            AesBlock::from_bytes(&msg_pad[32..48]),
            AesBlock::from_bytes(&msg_pad[48..64]),
        );
        self.update(m);
    }

    #[inline(always)]
    fn mac<const TAG_BYTES: usize>(&mut self, adlen: usize, mlen: usize) -> Tag<TAG_BYTES> {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(adlen as u64 * 8).to_le_bytes());
        sizes[8..16].copy_from_slice(&(mlen as u64 * 8).to_le_bytes());
        let u = AesBlock::from_bytes(&sizes);

        let (s30, s31, s32, s33) = self.s3.as_blocks();
        let t0 = s30.xor(u);
        let t1 = s31.xor(u);
        let t2 = s32.xor(u);
        let t3 = s33.xor(u);
        let t = AesBlock4::from_blocks(t0, t1, t2, t3);

        for _ in 0..7 {
            self.update(t);
        }

        let (s00, s01, s02, s03) = self.s0.as_blocks();
        let (s10, s11, s12, s13) = self.s1.as_blocks();
        let (s20, s21, s22, s23) = self.s2.as_blocks();
        let (s30, s31, s32, s33) = self.s3.as_blocks();
        let (s40, s41, s42, s43) = self.s4.as_blocks();
        let (s50, s51, s52, s53) = self.s5.as_blocks();

        let mut tag = [0u8; TAG_BYTES];
        if TAG_BYTES == 16 {
            let t0 = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50);
            let t1 = s01.xor(s11).xor(s21).xor(s31).xor(s41).xor(s51);
            let t2 = s02.xor(s12).xor(s22).xor(s32).xor(s42).xor(s52);
            let t3 = s03.xor(s13).xor(s23).xor(s33).xor(s43).xor(s53);
            tag.copy_from_slice(&t0.xor(t1).xor(t2).xor(t3).to_bytes()[..TAG_BYTES]);
        } else {
            let t0_lo = s00.xor(s10).xor(s20);
            let t1_lo = s01.xor(s11).xor(s21);
            let t2_lo = s02.xor(s12).xor(s22);
            let t3_lo = s03.xor(s13).xor(s23);
            let t0_hi = s30.xor(s40).xor(s50);
            let t1_hi = s31.xor(s41).xor(s51);
            let t2_hi = s32.xor(s42).xor(s52);
            let t3_hi = s33.xor(s43).xor(s53);
            tag[..16].copy_from_slice(&t0_lo.xor(t1_lo).xor(t2_lo).xor(t3_lo).to_bytes());
            tag[16..].copy_from_slice(&t0_hi.xor(t1_hi).xor(t2_hi).xor(t3_hi).to_bytes());
        }
        tag
    }
}

/// AEGIS-256X4 authenticated encryption
#[derive(Clone, Copy)]
pub struct Aegis256X4<const TAG_BYTES: usize> {
    state: State,
}

impl<const TAG_BYTES: usize> Aegis256X4<TAG_BYTES> {
    /// Create a new AEGIS-256X4 instance
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        debug_assert!(TAG_BYTES == 16 || TAG_BYTES == 32);
        Aegis256X4 {
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

/// AEGIS-256X4 MAC
#[derive(Clone)]
pub struct Aegis256X4Mac<const TAG_BYTES: usize> {
    state: State,
    buf: [u8; 64],
    buf_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis256X4Mac<TAG_BYTES> {
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 32];
        Self::new_with_nonce(key, &nonce)
    }

    pub fn new_with_nonce(key: &Key, nonce: &Nonce) -> Self {
        Aegis256X4Mac {
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
        self.state.mac::<TAG_BYTES>(0, self.msg_len)
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

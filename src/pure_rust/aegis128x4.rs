use super::{AesBlock, AesBlock4};
pub use crate::Error;

/// AEGIS-128X4 key
pub type Key = [u8; 16];

/// AEGIS-128X4 nonce
pub type Nonce = [u8; 16];

/// AEGIS-128X4 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

/// State for AEGIS-128X4 with 8 rows of 4 parallel AES blocks
#[derive(Clone, Copy)]
struct State {
    s0: AesBlock4,
    s1: AesBlock4,
    s2: AesBlock4,
    s3: AesBlock4,
    s4: AesBlock4,
    s5: AesBlock4,
    s6: AesBlock4,
    s7: AesBlock4,
}

impl State {
    #[inline(always)]
    fn update(&mut self, m0: AesBlock4, m1: AesBlock4) {
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
        let ctx0 = AesBlock::from_bytes(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx1 = AesBlock::from_bytes(&[1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx2 = AesBlock::from_bytes(&[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ctx3 = AesBlock::from_bytes(&[3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let kn4 = AesBlock4::from_blocks(kn, kn, kn, kn);
        let c0_4 = AesBlock4::from_blocks(c0, c0, c0, c0);
        let c1_4 = AesBlock4::from_blocks(c1, c1, c1, c1);
        let kc0_4 = AesBlock4::from_blocks(kc0, kc0, kc0, kc0);
        let kc1_4 = AesBlock4::from_blocks(kc1, kc1, kc1, kc1);
        let ctx = AesBlock4::from_blocks(ctx0, ctx1, ctx2, ctx3);
        let nonce4 = AesBlock4::from_blocks(nonce_block, nonce_block, nonce_block, nonce_block);
        let key4 = AesBlock4::from_blocks(key_block, key_block, key_block, key_block);

        let mut state = State {
            s0: kn4,
            s1: c1_4,
            s2: c0_4,
            s3: c1_4,
            s4: kn4,
            s5: kc0_4,
            s6: kc1_4,
            s7: kc0_4,
        };

        for _ in 0..10 {
            state.s3 = state.s3.xor(ctx);
            state.s7 = state.s7.xor(ctx);
            state.update(nonce4, key4);
        }

        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 128]) {
        let m0 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );
        let m1 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[64..80]),
            AesBlock::from_bytes(&src[80..96]),
            AesBlock::from_bytes(&src[96..112]),
            AesBlock::from_bytes(&src[112..128]),
        );
        self.update(m0, m1);
    }

    #[inline(always)]
    fn enc(&mut self, dst: &mut [u8; 128], src: &[u8; 128]) {
        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let m0 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );
        let m1 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[64..80]),
            AesBlock::from_bytes(&src[80..96]),
            AesBlock::from_bytes(&src[96..112]),
            AesBlock::from_bytes(&src[112..128]),
        );

        let c0 = m0.xor(z0);
        let c1 = m1.xor(z1);

        let (c00, c01, c02, c03) = c0.as_blocks();
        let (c10, c11, c12, c13) = c1.as_blocks();
        dst[0..16].copy_from_slice(&c00.to_bytes());
        dst[16..32].copy_from_slice(&c01.to_bytes());
        dst[32..48].copy_from_slice(&c02.to_bytes());
        dst[48..64].copy_from_slice(&c03.to_bytes());
        dst[64..80].copy_from_slice(&c10.to_bytes());
        dst[80..96].copy_from_slice(&c11.to_bytes());
        dst[96..112].copy_from_slice(&c12.to_bytes());
        dst[112..128].copy_from_slice(&c13.to_bytes());

        self.update(m0, m1);
    }

    #[inline(always)]
    fn dec(&mut self, dst: &mut [u8; 128], src: &[u8; 128]) {
        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let c0 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[0..16]),
            AesBlock::from_bytes(&src[16..32]),
            AesBlock::from_bytes(&src[32..48]),
            AesBlock::from_bytes(&src[48..64]),
        );
        let c1 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&src[64..80]),
            AesBlock::from_bytes(&src[80..96]),
            AesBlock::from_bytes(&src[96..112]),
            AesBlock::from_bytes(&src[112..128]),
        );

        let m0 = c0.xor(z0);
        let m1 = c1.xor(z1);

        let (m00, m01, m02, m03) = m0.as_blocks();
        let (m10, m11, m12, m13) = m1.as_blocks();
        dst[0..16].copy_from_slice(&m00.to_bytes());
        dst[16..32].copy_from_slice(&m01.to_bytes());
        dst[32..48].copy_from_slice(&m02.to_bytes());
        dst[48..64].copy_from_slice(&m03.to_bytes());
        dst[64..80].copy_from_slice(&m10.to_bytes());
        dst[80..96].copy_from_slice(&m11.to_bytes());
        dst[96..112].copy_from_slice(&m12.to_bytes());
        dst[112..128].copy_from_slice(&m13.to_bytes());

        self.update(m0, m1);
    }

    #[inline(always)]
    fn dec_partial(&mut self, dst: &mut [u8], src: &[u8]) {
        let len = src.len();
        debug_assert!(len < 128);

        let z0 = self.s6.xor(self.s1).xor(self.s2.and(self.s3));
        let z1 = self.s2.xor(self.s5).xor(self.s6.and(self.s7));

        let (z00, z01, z02, z03) = z0.as_blocks();
        let (z10, z11, z12, z13) = z1.as_blocks();

        let mut pad = [0u8; 128];
        pad[..len].copy_from_slice(src);

        // XOR with keystream
        let mut out = [0u8; 128];
        let p0 = AesBlock::from_bytes(&pad[0..16]).xor(z00);
        let p1 = AesBlock::from_bytes(&pad[16..32]).xor(z01);
        let p2 = AesBlock::from_bytes(&pad[32..48]).xor(z02);
        let p3 = AesBlock::from_bytes(&pad[48..64]).xor(z03);
        let p4 = AesBlock::from_bytes(&pad[64..80]).xor(z10);
        let p5 = AesBlock::from_bytes(&pad[80..96]).xor(z11);
        let p6 = AesBlock::from_bytes(&pad[96..112]).xor(z12);
        let p7 = AesBlock::from_bytes(&pad[112..128]).xor(z13);
        out[0..16].copy_from_slice(&p0.to_bytes());
        out[16..32].copy_from_slice(&p1.to_bytes());
        out[32..48].copy_from_slice(&p2.to_bytes());
        out[48..64].copy_from_slice(&p3.to_bytes());
        out[64..80].copy_from_slice(&p4.to_bytes());
        out[80..96].copy_from_slice(&p5.to_bytes());
        out[96..112].copy_from_slice(&p6.to_bytes());
        out[112..128].copy_from_slice(&p7.to_bytes());

        dst[..len].copy_from_slice(&out[..len]);

        // Zero pad for state update
        let mut msg_pad = [0u8; 128];
        msg_pad[..len].copy_from_slice(&out[..len]);
        let m0 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&msg_pad[0..16]),
            AesBlock::from_bytes(&msg_pad[16..32]),
            AesBlock::from_bytes(&msg_pad[32..48]),
            AesBlock::from_bytes(&msg_pad[48..64]),
        );
        let m1 = AesBlock4::from_blocks(
            AesBlock::from_bytes(&msg_pad[64..80]),
            AesBlock::from_bytes(&msg_pad[80..96]),
            AesBlock::from_bytes(&msg_pad[96..112]),
            AesBlock::from_bytes(&msg_pad[112..128]),
        );
        self.update(m0, m1);
    }

    #[inline(always)]
    fn mac<const TAG_BYTES: usize>(&mut self, adlen: usize, mlen: usize) -> Tag<TAG_BYTES> {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(adlen as u64 * 8).to_le_bytes());
        sizes[8..16].copy_from_slice(&(mlen as u64 * 8).to_le_bytes());
        let u = AesBlock::from_bytes(&sizes);

        let (s20, s21, s22, s23) = self.s2.as_blocks();
        let t0 = s20.xor(u);
        let t1 = s21.xor(u);
        let t2 = s22.xor(u);
        let t3 = s23.xor(u);
        let t = AesBlock4::from_blocks(t0, t1, t2, t3);

        for _ in 0..7 {
            self.update(t, t);
        }

        let (s00, s01, s02, s03) = self.s0.as_blocks();
        let (s10, s11, s12, s13) = self.s1.as_blocks();
        let (s20, s21, s22, s23) = self.s2.as_blocks();
        let (s30, s31, s32, s33) = self.s3.as_blocks();
        let (s40, s41, s42, s43) = self.s4.as_blocks();
        let (s50, s51, s52, s53) = self.s5.as_blocks();
        let (s60, s61, s62, s63) = self.s6.as_blocks();
        let (s70, s71, s72, s73) = self.s7.as_blocks();

        let mut tag = [0u8; TAG_BYTES];
        if TAG_BYTES == 16 {
            let t0 = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50).xor(s60);
            let t1 = s01.xor(s11).xor(s21).xor(s31).xor(s41).xor(s51).xor(s61);
            let t2 = s02.xor(s12).xor(s22).xor(s32).xor(s42).xor(s52).xor(s62);
            let t3 = s03.xor(s13).xor(s23).xor(s33).xor(s43).xor(s53).xor(s63);
            tag.copy_from_slice(&t0.xor(t1).xor(t2).xor(t3).to_bytes()[..TAG_BYTES]);
        } else {
            let t0_lo = s00.xor(s10).xor(s20).xor(s30);
            let t1_lo = s01.xor(s11).xor(s21).xor(s31);
            let t2_lo = s02.xor(s12).xor(s22).xor(s32);
            let t3_lo = s03.xor(s13).xor(s23).xor(s33);
            let t0_hi = s40.xor(s50).xor(s60).xor(s70);
            let t1_hi = s41.xor(s51).xor(s61).xor(s71);
            let t2_hi = s42.xor(s52).xor(s62).xor(s72);
            let t3_hi = s43.xor(s53).xor(s63).xor(s73);
            tag[..16].copy_from_slice(&t0_lo.xor(t1_lo).xor(t2_lo).xor(t3_lo).to_bytes());
            tag[16..].copy_from_slice(&t0_hi.xor(t1_hi).xor(t2_hi).xor(t3_hi).to_bytes());
        }
        tag
    }

    #[inline(always)]
    fn mac_finalize<const TAG_BYTES: usize>(&mut self, data_len: usize) -> Tag<TAG_BYTES> {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(data_len as u64 * 8).to_le_bytes());
        sizes[8..16].copy_from_slice(&(TAG_BYTES as u64 * 8).to_le_bytes());
        let u = AesBlock::from_bytes(&sizes);

        let (s20, s21, s22, s23) = self.s2.as_blocks();
        let t0 = s20.xor(u);
        let t1 = s21.xor(u);
        let t2 = s22.xor(u);
        let t3 = s23.xor(u);
        let t = AesBlock4::from_blocks(t0, t1, t2, t3);

        for _ in 0..7 {
            self.update(t, t);
        }

        let (s00, s01, s02, s03) = self.s0.as_blocks();
        let (s10, s11, s12, s13) = self.s1.as_blocks();
        let (s20, s21, s22, s23) = self.s2.as_blocks();
        let (s30, s31, s32, s33) = self.s3.as_blocks();
        let (s40, s41, s42, s43) = self.s4.as_blocks();
        let (s50, s51, s52, s53) = self.s5.as_blocks();
        let (s60, s61, s62, s63) = self.s6.as_blocks();
        let (_s70, s71, s72, s73) = self.s7.as_blocks();

        let zeros = AesBlock::from_bytes(&[0u8; 16]);

        if TAG_BYTES == 16 {
            let tag0 = s00.xor(s10).xor(s20).xor(s30).xor(s40).xor(s50).xor(s60);
            let tag1 = s01.xor(s11).xor(s21).xor(s31).xor(s41).xor(s51).xor(s61);
            let tag2 = s02.xor(s12).xor(s22).xor(s32).xor(s42).xor(s52).xor(s62);
            let tag3 = s03.xor(s13).xor(s23).xor(s33).xor(s43).xor(s53).xor(s63);

            let m0 = AesBlock4::from_blocks(tag0, zeros, zeros, zeros);
            let m1 = AesBlock4::from_blocks(tag1, zeros, zeros, zeros);
            self.update(m0, m1);

            let m0 = AesBlock4::from_blocks(tag2, zeros, zeros, zeros);
            let m1 = AesBlock4::from_blocks(tag3, zeros, zeros, zeros);
            self.update(m0, m1);
        } else {
            let tag1_lo = s01.xor(s11).xor(s21).xor(s31);
            let tag1_hi = s41.xor(s51).xor(s61).xor(s71);
            let tag2_lo = s02.xor(s12).xor(s22).xor(s32);
            let tag2_hi = s42.xor(s52).xor(s62).xor(s72);
            let tag3_lo = s03.xor(s13).xor(s23).xor(s33);
            let tag3_hi = s43.xor(s53).xor(s63).xor(s73);

            let m0 = AesBlock4::from_blocks(tag1_lo, zeros, zeros, zeros);
            let m1 = AesBlock4::from_blocks(tag1_hi, zeros, zeros, zeros);
            self.update(m0, m1);

            let m0 = AesBlock4::from_blocks(tag2_lo, zeros, zeros, zeros);
            let m1 = AesBlock4::from_blocks(tag2_hi, zeros, zeros, zeros);
            self.update(m0, m1);

            let m0 = AesBlock4::from_blocks(tag3_lo, zeros, zeros, zeros);
            let m1 = AesBlock4::from_blocks(tag3_hi, zeros, zeros, zeros);
            self.update(m0, m1);
        }

        let (s20, _, _, _) = self.s2.as_blocks();
        let mut extra_sizes = [0u8; 16];
        extra_sizes[..8].copy_from_slice(&4u64.to_le_bytes());
        extra_sizes[8..16].copy_from_slice(&(TAG_BYTES as u64 * 8).to_le_bytes());
        let extra_block = s20.xor(AesBlock::from_bytes(&extra_sizes));
        let extra = AesBlock4::from_blocks(extra_block, zeros, zeros, zeros);

        for _ in 0..7 {
            self.update(extra, extra);
        }

        let (s00, _, _, _) = self.s0.as_blocks();
        let (s10, _, _, _) = self.s1.as_blocks();
        let (s20, _, _, _) = self.s2.as_blocks();
        let (s30, _, _, _) = self.s3.as_blocks();
        let (s40, _, _, _) = self.s4.as_blocks();
        let (s50, _, _, _) = self.s5.as_blocks();
        let (s60, _, _, _) = self.s6.as_blocks();
        let (s70, _, _, _) = self.s7.as_blocks();

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

/// AEGIS-128X4 authenticated encryption
#[derive(Clone, Copy)]
pub struct Aegis128X4<const TAG_BYTES: usize> {
    state: State,
}

impl<const TAG_BYTES: usize> Aegis128X4<TAG_BYTES> {
    /// Create a new AEGIS-128X4 instance
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        debug_assert!(TAG_BYTES == 16 || TAG_BYTES == 32);
        Aegis128X4 {
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
        while i + 128 <= adlen {
            let mut block = [0u8; 128];
            block.copy_from_slice(&ad[i..i + 128]);
            state.absorb(&block);
            i += 128;
        }
        if adlen % 128 != 0 {
            let mut block = [0u8; 128];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process message
        i = 0;
        while i + 128 <= mlen {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
            src.copy_from_slice(&m[i..i + 128]);
            state.enc(&mut dst, &src);
            c[i..i + 128].copy_from_slice(&dst);
            i += 128;
        }
        if mlen % 128 != 0 {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
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
        while i + 128 <= adlen {
            let mut block = [0u8; 128];
            block.copy_from_slice(&ad[i..i + 128]);
            state.absorb(&block);
            i += 128;
        }
        if adlen % 128 != 0 {
            let mut block = [0u8; 128];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process message
        i = 0;
        while i + 128 <= mclen {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
            src.copy_from_slice(&mc[i..i + 128]);
            state.enc(&mut dst, &src);
            mc[i..i + 128].copy_from_slice(&dst);
            i += 128;
        }
        if mclen % 128 != 0 {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
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
        while i + 128 <= adlen {
            let mut block = [0u8; 128];
            block.copy_from_slice(&ad[i..i + 128]);
            state.absorb(&block);
            i += 128;
        }
        if adlen % 128 != 0 {
            let mut block = [0u8; 128];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process ciphertext
        i = 0;
        while i + 128 <= clen {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
            src.copy_from_slice(&c[i..i + 128]);
            state.dec(&mut dst, &src);
            m[i..i + 128].copy_from_slice(&dst);
            i += 128;
        }
        if clen % 128 != 0 {
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
        while i + 128 <= adlen {
            let mut block = [0u8; 128];
            block.copy_from_slice(&ad[i..i + 128]);
            state.absorb(&block);
            i += 128;
        }
        if adlen % 128 != 0 {
            let mut block = [0u8; 128];
            block[..adlen - i].copy_from_slice(&ad[i..]);
            state.absorb(&block);
        }

        // Process ciphertext
        i = 0;
        while i + 128 <= mclen {
            let mut src = [0u8; 128];
            let mut dst = [0u8; 128];
            src.copy_from_slice(&mc[i..i + 128]);
            state.dec(&mut dst, &src);
            mc[i..i + 128].copy_from_slice(&dst);
            i += 128;
        }
        if mclen % 128 != 0 {
            let remaining = mclen - i;
            let mut tmp = [0u8; 128];
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

/// AEGIS-128X4 MAC
#[derive(Clone)]
pub struct Aegis128X4Mac<const TAG_BYTES: usize> {
    state: State,
    buf: [u8; 128],
    buf_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis128X4Mac<TAG_BYTES> {
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 16];
        Self::new_with_nonce(key, &nonce)
    }

    pub fn new_with_nonce(key: &Key, nonce: &Nonce) -> Self {
        Aegis128X4Mac {
            state: State::new(key, nonce),
            buf: [0u8; 128],
            buf_len: 0,
            msg_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.msg_len += data.len();
        let mut offset = 0;

        // Process buffered data first
        if self.buf_len > 0 {
            let needed = 128 - self.buf_len;
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
        while offset + 128 <= data.len() {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[offset..offset + 128]);
            self.state.absorb(&block);
            offset += 128;
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

use super::AesBlock;
pub use crate::Error;
use core::convert::TryInto;

/// AEGIS-256X4 key
pub type Key = [u8; 32];

/// AEGIS-256X4 nonce
pub type Nonce = [u8; 32];

const D: usize = 4; // Degree of parallelism for AEGIS-256X4

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct State {
    // We maintain D parallel AEGIS-256 states, each with 6 AES blocks
    blocks: [[AesBlock; 6]; D],
}

impl State {
    fn update(&mut self, d: [AesBlock; D]) {
        // Update all D states in parallel
        for i in 0..D {
            let blocks = &mut self.blocks[i];
            let tmp = blocks[5];

            blocks[5] = blocks[4].round(blocks[5]);
            blocks[4] = blocks[3].round(blocks[4]);
            blocks[3] = blocks[2].round(blocks[3]);
            blocks[2] = blocks[1].round(blocks[2]);
            blocks[1] = blocks[0].round(blocks[1]);
            blocks[0] = tmp.round(blocks[0]).xor(d[i]);
        }
    }

    pub fn new(key: &Key, nonce: &Nonce) -> Self {
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

        // Initialize D AEGIS-256 states
        let mut blocks = [[AesBlock::from_bytes(&[0u8; 16]); 6]; D];

        for i in 0..D {
            blocks[i] = [k0.xor(n0), k1.xor(n1), c1, c0, k0.xor(c0), k1.xor(c1)];
        }

        let mut state = State { blocks };

        // Create context for each state
        let mut ctx = [AesBlock::from_bytes(&[0u8; 16]); D];
        for i in 0..D {
            let mut ctx_bytes = [0u8; 16];
            ctx_bytes[0] = i as u8;
            ctx_bytes[1] = (D - 1) as u8;
            ctx[i] = AesBlock::from_bytes(&ctx_bytes);
        }

        // Initialization rounds
        for _ in 0..4 {
            // Add context to states and update
            for i in 0..D {
                state.blocks[i][3] = state.blocks[i][3].xor(ctx[i]);
                state.blocks[i][5] = state.blocks[i][5].xor(ctx[i]);
            }

            let mut k0_v = [AesBlock::from_bytes(&[0u8; 16]); D];
            for i in 0..D {
                k0_v[i] = k0;
            }
            state.update(k0_v);

            for i in 0..D {
                state.blocks[i][3] = state.blocks[i][3].xor(ctx[i]);
                state.blocks[i][5] = state.blocks[i][5].xor(ctx[i]);
            }

            let mut k1_v = [AesBlock::from_bytes(&[0u8; 16]); D];
            for i in 0..D {
                k1_v[i] = k1;
            }
            state.update(k1_v);

            for i in 0..D {
                state.blocks[i][3] = state.blocks[i][3].xor(ctx[i]);
                state.blocks[i][5] = state.blocks[i][5].xor(ctx[i]);
            }

            let mut k0n0_v = [AesBlock::from_bytes(&[0u8; 16]); D];
            for i in 0..D {
                k0n0_v[i] = k0.xor(n0);
            }
            state.update(k0n0_v);

            for i in 0..D {
                state.blocks[i][3] = state.blocks[i][3].xor(ctx[i]);
                state.blocks[i][5] = state.blocks[i][5].xor(ctx[i]);
            }

            let mut k1n1_v = [AesBlock::from_bytes(&[0u8; 16]); D];
            for i in 0..D {
                k1n1_v[i] = k1.xor(n1);
            }
            state.update(k1n1_v);
        }

        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 16 * D]) {
        let mut msg = [AesBlock::from_bytes(&[0u8; 16]); D];
        // Split across D states: 16 bytes each per state
        for i in 0..D {
            msg[i] = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]);
        }
        self.update(msg);
    }

    fn enc(&mut self, dst: &mut [u8; 16 * D], src: &[u8; 16 * D]) {
        for i in 0..D {
            let blocks = &self.blocks[i];
            let z = blocks[1]
                .xor(blocks[4])
                .xor(blocks[5])
                .xor(blocks[2].and(blocks[3]));

            let msg = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]);
            let c = msg.xor(z);

            dst[i * 16..i * 16 + 16].copy_from_slice(&c.to_bytes());
        }

        self.absorb(src);
    }

    fn dec(&mut self, dst: &mut [u8; 16 * D], src: &[u8; 16 * D]) {
        let mut msg = [AesBlock::from_bytes(&[0u8; 16]); D];

        for i in 0..D {
            let blocks = &self.blocks[i];
            let z = blocks[1]
                .xor(blocks[4])
                .xor(blocks[5])
                .xor(blocks[2].and(blocks[3]));

            msg[i] = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]).xor(z);
            dst[i * 16..i * 16 + 16].copy_from_slice(&msg[i].to_bytes());
        }

        self.update(msg);
    }

    fn dec_partial(&mut self, dst: &mut [u8; 16 * D], src: &[u8]) -> usize {
        let len = src.len();
        let _r_bytes = 16 * D; // R bits = 128 * D bits = 16 * D bytes

        // Build z vector according to spec
        let mut z_bytes = [0u8; 64]; // 128 * D bits = 64 bytes for D=4

        for i in 0..D {
            let blocks = &self.blocks[i];
            let z_i = blocks[1]
                .xor(blocks[4])
                .xor(blocks[5])
                .xor(blocks[2].and(blocks[3]));
            z_bytes[i * 16..i * 16 + 16].copy_from_slice(&z_i.to_bytes());
        }

        // ZeroPad(cn, R)
        let mut padded_input = [0u8; 64]; // R bytes
        padded_input[..len].copy_from_slice(src);

        // out = t ^ z
        let mut output = [0u8; 64];
        for i in 0..64 {
            output[i] = padded_input[i] ^ z_bytes[i];
        }

        // xn = Truncate(out, |cn|)
        dst[..len].copy_from_slice(&output[..len]);

        // v = ZeroPad(xn, R)
        let mut v_padded = [0u8; 64]; // R bytes
        v_padded[..len].copy_from_slice(&output[..len]);

        let mut update_data = [AesBlock::from_bytes(&[0u8; 16]); D];
        for i in 0..D {
            update_data[i] = AesBlock::from_bytes(&v_padded[i * 16..i * 16 + 16]);
        }

        self.update(update_data);
        len
    }

    fn finalize<const TAG_BYTES: usize>(
        &mut self,
        ad_len: usize,
        msg_len: usize,
    ) -> [u8; TAG_BYTES] {
        // Create t vector according to spec
        let u = {
            let mut u_bytes = [0u8; 16];
            u_bytes[..8].copy_from_slice(&(ad_len as u64 * 8).to_le_bytes());
            u_bytes[8..16].copy_from_slice(&(msg_len as u64 * 8).to_le_bytes());
            AesBlock::from_bytes(&u_bytes)
        };

        // Construct t vector: for i in 0..D: t = t || (V[3,i] ^ u)
        let mut t_data = [AesBlock::from_bytes(&[0u8; 16]); D];
        for i in 0..D {
            t_data[i] = self.blocks[i][3].xor(u); // V[3,i] ^ u
        }

        // Repeat(7, Update(t)) - Update all D states simultaneously
        for _ in 0..7 {
            self.update(t_data);
        }

        // Compute final tag by XORing tags from all D states
        if TAG_BYTES == 16 {
            let mut tag_block = AesBlock::from_bytes(&[0u8; 16]); // ZeroPad({}, 128)

            for i in 0..D {
                // ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i]
                let ti = self.blocks[i][0]
                    .xor(self.blocks[i][1])
                    .xor(self.blocks[i][2])
                    .xor(self.blocks[i][3])
                    .xor(self.blocks[i][4])
                    .xor(self.blocks[i][5]);
                tag_block = tag_block.xor(ti);
            }

            let mut tag = [0u8; TAG_BYTES];
            tag.copy_from_slice(&tag_block.to_bytes()[..TAG_BYTES]);
            tag
        } else {
            // TAG_BYTES == 32
            let mut ti0 = AesBlock::from_bytes(&[0u8; 16]); // ZeroPad({}, 128)
            let mut ti1 = AesBlock::from_bytes(&[0u8; 16]); // ZeroPad({}, 128)

            for i in 0..D {
                // ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i]
                ti0 = ti0
                    .xor(self.blocks[i][0])
                    .xor(self.blocks[i][1])
                    .xor(self.blocks[i][2]);

                // ti1 = ti1 ^ V[3,i] ^ V[4,i] ^ V[5,i]
                ti1 = ti1
                    .xor(self.blocks[i][3])
                    .xor(self.blocks[i][4])
                    .xor(self.blocks[i][5]);
            }

            let mut tag = [0u8; TAG_BYTES];
            tag[..16].copy_from_slice(&ti0.to_bytes());
            tag[16..32].copy_from_slice(&ti1.to_bytes());
            tag
        }
    }
}

/// Tag length in bytes must be 16 (128 bits) or 32 (256 bits)
#[derive(Copy, Clone, Debug)]
pub struct Aegis256X4<const TAG_BYTES: usize> {
    key: Key,
    nonce: Nonce,
}

/// AEGIS-256X4 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

impl<const TAG_BYTES: usize> Aegis256X4<TAG_BYTES> {
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Aegis256X4 {
            key: *key,
            nonce: *nonce,
        }
    }

    /// Encrypts a message using AEGIS-256X4
    #[cfg(feature = "std")]
    pub fn encrypt(self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag<TAG_BYTES>) {
        let mut state = State::new(&self.key, &self.nonce);
        let mut c = vec![0u8; m.len()];

        // Process associated data
        let ad_blocks = ad.len() / (16 * D);
        let ad_rem = ad.len() % (16 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 16 * D..(i + 1) * 16 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 16 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 16 * D..]);
            state.absorb(&buf);
        }

        // Process message
        let msg_blocks = m.len() / (16 * D);
        let msg_rem = m.len() % (16 * D);

        for i in 0..msg_blocks {
            let src_block = &m[i * 16 * D..(i + 1) * 16 * D];
            let dst_block = &mut c[i * 16 * D..(i + 1) * 16 * D];
            state.enc(dst_block.try_into().unwrap(), src_block.try_into().unwrap());
        }

        if msg_rem > 0 {
            let mut src_buf = [0u8; 16 * D];
            let mut dst_buf = [0u8; 16 * D];
            src_buf[..msg_rem].copy_from_slice(&m[msg_blocks * 16 * D..]);
            state.enc(&mut dst_buf, &src_buf);
            c[msg_blocks * 16 * D..].copy_from_slice(&dst_buf[..msg_rem]);
        }

        let tag = state.finalize::<TAG_BYTES>(ad.len(), m.len());
        (c, tag)
    }

    /// Encrypts a message in place
    pub fn encrypt_in_place(self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let mut state = State::new(&self.key, &self.nonce);

        // Process associated data
        let ad_blocks = ad.len() / (16 * D);
        let ad_rem = ad.len() % (16 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 16 * D..(i + 1) * 16 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 16 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 16 * D..]);
            state.absorb(&buf);
        }

        // Process message
        let msg_len = mc.len();
        let msg_blocks = msg_len / (16 * D);
        let msg_rem = msg_len % (16 * D);

        for i in 0..msg_blocks {
            let mut block = [0u8; 16 * D];
            block.copy_from_slice(&mc[i * 16 * D..(i + 1) * 16 * D]);
            let src = block.clone();
            state.enc(&mut block, &src);
            mc[i * 16 * D..(i + 1) * 16 * D].copy_from_slice(&block);
        }

        if msg_rem > 0 {
            let mut src_buf = [0u8; 16 * D];
            let mut dst_buf = [0u8; 16 * D];
            src_buf[..msg_rem].copy_from_slice(&mc[msg_blocks * 16 * D..]);
            state.enc(&mut dst_buf, &src_buf);
            mc[msg_blocks * 16 * D..].copy_from_slice(&dst_buf[..msg_rem]);
        }

        state.finalize::<TAG_BYTES>(ad.len(), msg_len)
    }

    /// Decrypts a message using AEGIS-256X4
    #[cfg(feature = "std")]
    pub fn decrypt(self, c: &[u8], tag: &Tag<TAG_BYTES>, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = State::new(&self.key, &self.nonce);
        let mut m = vec![0u8; c.len()];

        // Process associated data
        let ad_blocks = ad.len() / (16 * D);
        let ad_rem = ad.len() % (16 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 16 * D..(i + 1) * 16 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 16 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 16 * D..]);
            state.absorb(&buf);
        }

        // Process ciphertext
        let ct_blocks = c.len() / (16 * D);
        let ct_rem = c.len() % (16 * D);

        for i in 0..ct_blocks {
            let src_block = &c[i * 16 * D..(i + 1) * 16 * D];
            let dst_block = &mut m[i * 16 * D..(i + 1) * 16 * D];
            state.dec(dst_block.try_into().unwrap(), src_block.try_into().unwrap());
        }

        if ct_rem > 0 {
            let mut dst_buf = [0u8; 16 * D];
            let actual_len = state.dec_partial(&mut dst_buf, &c[ct_blocks * 16 * D..]);
            m[ct_blocks * 16 * D..].copy_from_slice(&dst_buf[..actual_len]);
        }

        let computed_tag = state.finalize::<TAG_BYTES>(ad.len(), c.len());

        // Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..TAG_BYTES {
            diff |= computed_tag[i] ^ tag[i];
        }

        if diff != 0 {
            return Err(Error::InvalidTag);
        }

        Ok(m)
    }

    /// Decrypts a message in place
    pub fn decrypt_in_place(
        self,
        mc: &mut [u8],
        tag: &Tag<TAG_BYTES>,
        ad: &[u8],
    ) -> Result<(), Error> {
        let mut state = State::new(&self.key, &self.nonce);

        // Process associated data
        let ad_blocks = ad.len() / (16 * D);
        let ad_rem = ad.len() % (16 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 16 * D..(i + 1) * 16 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 16 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 16 * D..]);
            state.absorb(&buf);
        }

        // Process ciphertext
        let ct_len = mc.len();
        let ct_blocks = ct_len / (16 * D);
        let ct_rem = ct_len % (16 * D);

        for i in 0..ct_blocks {
            let mut block = [0u8; 16 * D];
            block.copy_from_slice(&mc[i * 16 * D..(i + 1) * 16 * D]);
            let src = block.clone();
            state.dec(&mut block, &src);
            mc[i * 16 * D..(i + 1) * 16 * D].copy_from_slice(&block);
        }

        if ct_rem > 0 {
            let mut dst_buf = [0u8; 16 * D];
            let actual_len = state.dec_partial(&mut dst_buf, &mc[ct_blocks * 16 * D..]);
            mc[ct_blocks * 16 * D..].copy_from_slice(&dst_buf[..actual_len]);
        }

        let computed_tag = state.finalize::<TAG_BYTES>(ad.len(), ct_len);

        // Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..TAG_BYTES {
            diff |= computed_tag[i] ^ tag[i];
        }

        if diff != 0 {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}

// MAC functionality
pub struct Aegis256X4Mac<const TAG_BYTES: usize> {
    state: State,
    ad_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis256X4Mac<TAG_BYTES> {
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 32];
        Aegis256X4Mac {
            state: State::new(key, &nonce),
            ad_len: 0,
            msg_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let blocks = data.len() / (16 * D);
        let rem = data.len() % (16 * D);

        for i in 0..blocks {
            let block = &data[i * 16 * D..(i + 1) * 16 * D];
            self.state.absorb(block.try_into().unwrap());
        }

        if rem > 0 {
            let mut buf = [0u8; 16 * D];
            buf[..rem].copy_from_slice(&data[blocks * 16 * D..]);
            self.state.absorb(&buf);
        }

        self.msg_len += data.len();
    }

    pub fn finalize(mut self) -> Tag<TAG_BYTES> {
        self.state.finalize::<TAG_BYTES>(self.ad_len, self.msg_len)
    }

    pub fn verify(mut self, tag: &Tag<TAG_BYTES>) -> Result<(), Error> {
        let computed_tag = self.state.finalize::<TAG_BYTES>(self.ad_len, self.msg_len);

        let mut diff = 0u8;
        for i in 0..TAG_BYTES {
            diff |= computed_tag[i] ^ tag[i];
        }

        if diff != 0 {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}

impl<const TAG_BYTES: usize> Clone for Aegis256X4Mac<TAG_BYTES> {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            ad_len: self.ad_len,
            msg_len: self.msg_len,
        }
    }
}

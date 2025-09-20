use super::AesBlock;
pub use crate::Error;
use core::convert::TryInto;

/// AEGIS-128X4 key
pub type Key = [u8; 16];

/// AEGIS-128X4 nonce
pub type Nonce = [u8; 16];

const D: usize = 4; // Degree of parallelism for AEGIS-128X4

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct State {
    // We maintain 8 AES blocks, each with D parallel states
    blocks: [[AesBlock; D]; 8],
}

impl State {
    fn update(&mut self, d: [[AesBlock; 2]; D]) {
        // Update all D states in parallel
        let mut tmp = [AesBlock::from_bytes(&[0u8; 16]); D];
        for i in 0..D {
            tmp[i] = self.blocks[7][i];
        }

        for i in 0..D {
            self.blocks[7][i] = self.blocks[6][i].round(self.blocks[7][i]);
            self.blocks[6][i] = self.blocks[5][i].round(self.blocks[6][i]);
            self.blocks[5][i] = self.blocks[4][i].round(self.blocks[5][i]);
            self.blocks[4][i] = self.blocks[3][i].round(self.blocks[4][i]).xor(d[i][1]);
            self.blocks[3][i] = self.blocks[2][i].round(self.blocks[3][i]);
            self.blocks[2][i] = self.blocks[1][i].round(self.blocks[2][i]);
            self.blocks[1][i] = self.blocks[0][i].round(self.blocks[1][i]);
            self.blocks[0][i] = tmp[i].round(self.blocks[0][i]).xor(d[i][0]);
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

        let key_block = AesBlock::from_bytes(key);
        let nonce_block = AesBlock::from_bytes(nonce);

        // Initialize D AEGIS-128L states
        let mut blocks = [[AesBlock::from_bytes(&[0u8; 16]); D]; 8];

        for i in 0..D {
            blocks[0][i] = key_block.xor(nonce_block);
            blocks[1][i] = c1;
            blocks[2][i] = c0;
            blocks[3][i] = c1;
            blocks[4][i] = key_block.xor(nonce_block);
            blocks[5][i] = key_block.xor(c0);
            blocks[6][i] = key_block.xor(c1);
            blocks[7][i] = key_block.xor(c0);
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
        for _ in 0..10 {
            // Add context to states
            for i in 0..D {
                state.blocks[3][i] = state.blocks[3][i].xor(ctx[i]);
                state.blocks[7][i] = state.blocks[7][i].xor(ctx[i]);
            }

            // Update with nonce and key for each state
            let mut update_data = [[AesBlock::from_bytes(&[0u8; 16]); 2]; D];
            for i in 0..D {
                update_data[i][0] = nonce_block;
                update_data[i][1] = key_block;
            }
            state.update(update_data);
        }

        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 32 * D]) {
        let mut msg = [[AesBlock::from_bytes(&[0u8; 16]); 2]; D];
        // M0 = first 64 bytes, M1 = second 64 bytes
        // Split M0 and M1 across D states: 16 bytes each per state
        for i in 0..D {
            msg[i][0] = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]); // M0 split
            msg[i][1] = AesBlock::from_bytes(&src[64 + i * 16..64 + i * 16 + 16]);
            // M1 split
        }
        self.update(msg);
    }

    fn enc(&mut self, dst: &mut [u8; 32 * D], src: &[u8; 32 * D]) {
        for i in 0..D {
            let z0 = self.blocks[6][i]
                .xor(self.blocks[1][i])
                .xor(self.blocks[2][i].and(self.blocks[3][i]));
            let z1 = self.blocks[2][i]
                .xor(self.blocks[5][i])
                .xor(self.blocks[6][i].and(self.blocks[7][i]));

            // Read from correct positions: M0 split, then M1 split
            let msg0 = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]); // M0 split
            let msg1 = AesBlock::from_bytes(&src[64 + i * 16..64 + i * 16 + 16]); // M1 split

            let c0 = msg0.xor(z0);
            let c1 = msg1.xor(z1);

            // Write to same positions: M0 split, then M1 split
            dst[i * 16..i * 16 + 16].copy_from_slice(&c0.to_bytes());
            dst[64 + i * 16..64 + i * 16 + 16].copy_from_slice(&c1.to_bytes());
        }

        self.absorb(src);
    }

    fn dec(&mut self, dst: &mut [u8; 32 * D], src: &[u8; 32 * D]) {
        let mut msg = [[AesBlock::from_bytes(&[0u8; 16]); 2]; D];

        for i in 0..D {
            let z0 = self.blocks[6][i]
                .xor(self.blocks[1][i])
                .xor(self.blocks[2][i].and(self.blocks[3][i]));
            let z1 = self.blocks[2][i]
                .xor(self.blocks[5][i])
                .xor(self.blocks[6][i].and(self.blocks[7][i]));

            // Read from correct positions: M0 split, then M1 split
            msg[i][0] = AesBlock::from_bytes(&src[i * 16..i * 16 + 16]).xor(z0); // M0 split
            msg[i][1] = AesBlock::from_bytes(&src[64 + i * 16..64 + i * 16 + 16]).xor(z1); // M1 split

            // Write to same positions: M0 split, then M1 split
            dst[i * 16..i * 16 + 16].copy_from_slice(&msg[i][0].to_bytes());
            dst[64 + i * 16..64 + i * 16 + 16].copy_from_slice(&msg[i][1].to_bytes());
        }

        self.update(msg);
    }

    fn dec_partial(&mut self, dst: &mut [u8; 32 * D], src: &[u8]) -> usize {
        let len = src.len();
        let _r_bytes = 32 * D; // R bits = 256 * D bits = 32 * D bytes

        // Build z0 and z1 vectors according to spec
        let mut z0_bytes = [0u8; 64]; // 128 * D bits = 64 bytes for D=4
        let mut z1_bytes = [0u8; 64]; // 128 * D bits = 64 bytes for D=4

        for i in 0..D {
            let z0_i = self.blocks[6][i]
                .xor(self.blocks[1][i])
                .xor(self.blocks[2][i].and(self.blocks[3][i]));
            let z1_i = self.blocks[2][i]
                .xor(self.blocks[5][i])
                .xor(self.blocks[6][i].and(self.blocks[7][i]));

            z0_bytes[i * 16..i * 16 + 16].copy_from_slice(&z0_i.to_bytes());
            z1_bytes[i * 16..i * 16 + 16].copy_from_slice(&z1_i.to_bytes());
        }

        // ZeroPad(cn, R) and split into t0, t1
        let mut padded_input = [0u8; 128]; // R bytes
        padded_input[..len].copy_from_slice(src);

        let t0 = &padded_input[..64]; // First 128*D bits
        let t1 = &padded_input[64..]; // Second 128*D bits

        // out0 = t0 ^ z0, out1 = t1 ^ z1
        let mut out0 = [0u8; 64];
        let mut out1 = [0u8; 64];
        for i in 0..64 {
            out0[i] = t0[i] ^ z0_bytes[i];
            out1[i] = t1[i] ^ z1_bytes[i];
        }

        // xn = Truncate(out0 || out1, |cn|)
        let mut output = [0u8; 128];
        output[..64].copy_from_slice(&out0);
        output[64..].copy_from_slice(&out1);
        dst[..len].copy_from_slice(&output[..len]);

        // v0, v1 = Split(ZeroPad(xn, R), 128 * D)
        let mut v_padded = [0u8; 128]; // R bytes
        v_padded[..len].copy_from_slice(&output[..len]);

        let mut update_data = [[AesBlock::from_bytes(&[0u8; 16]); 2]; D];
        for i in 0..D {
            update_data[i][0] = AesBlock::from_bytes(&v_padded[i * 16..i * 16 + 16]); // v0 split
            update_data[i][1] = AesBlock::from_bytes(&v_padded[64 + i * 16..64 + i * 16 + 16]);
            // v1 split
        }

        self.update(update_data);
        len
    }

    fn finalize<const TAG_BYTES: usize>(
        &mut self,
        ad_len: usize,
        msg_len: usize,
    ) -> [u8; TAG_BYTES] {
        // Create t vector according to spec: t = {} and u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = {
            let mut u_bytes = [0u8; 16];
            u_bytes[..8].copy_from_slice(&(ad_len as u64 * 8).to_le_bytes());
            u_bytes[8..16].copy_from_slice(&(msg_len as u64 * 8).to_le_bytes());
            AesBlock::from_bytes(&u_bytes)
        };

        // Construct t vector: for i in 0..D: t = t || (V[2,i] ^ u)
        let mut t_data = [[AesBlock::from_bytes(&[0u8; 16]); 2]; D];
        for i in 0..D {
            t_data[i][0] = self.blocks[2][i].xor(u); // V[2,i] ^ u
            t_data[i][1] = self.blocks[2][i].xor(u); // V[2,i] ^ u for both M0 and M1
        }

        // Repeat(7, Update(t, t)) - Update all D states simultaneously
        for _ in 0..7 {
            self.update(t_data);
        }

        // Compute final tag by XORing tags from all D states
        if TAG_BYTES == 16 {
            let mut tag_block = AesBlock::from_bytes(&[0u8; 16]); // ZeroPad({}, 128)

            for i in 0..D {
                // ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
                let ti = self.blocks[0][i]
                    .xor(self.blocks[1][i])
                    .xor(self.blocks[2][i])
                    .xor(self.blocks[3][i])
                    .xor(self.blocks[4][i])
                    .xor(self.blocks[5][i])
                    .xor(self.blocks[6][i]);
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
                // ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
                ti0 = ti0
                    .xor(self.blocks[0][i])
                    .xor(self.blocks[1][i])
                    .xor(self.blocks[2][i])
                    .xor(self.blocks[3][i]);

                // ti1 = ti1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
                ti1 = ti1
                    .xor(self.blocks[4][i])
                    .xor(self.blocks[5][i])
                    .xor(self.blocks[6][i])
                    .xor(self.blocks[7][i]);
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
pub struct Aegis128X4<const TAG_BYTES: usize> {
    key: Key,
    nonce: Nonce,
}

/// AEGIS-128X4 authentication tag
pub type Tag<const TAG_BYTES: usize> = [u8; TAG_BYTES];

impl<const TAG_BYTES: usize> Aegis128X4<TAG_BYTES> {
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        assert!(
            TAG_BYTES == 16 || TAG_BYTES == 32,
            "Invalid tag length, must be 16 or 32"
        );
        Aegis128X4 {
            key: *key,
            nonce: *nonce,
        }
    }

    /// Encrypts a message using AEGIS-128X4
    #[cfg(feature = "std")]
    pub fn encrypt(self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag<TAG_BYTES>) {
        let mut state = State::new(&self.key, &self.nonce);
        let mut c = vec![0u8; m.len()];

        // Process associated data
        let ad_blocks = ad.len() / (32 * D);
        let ad_rem = ad.len() % (32 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 32 * D..(i + 1) * 32 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 32 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 32 * D..]);
            state.absorb(&buf);
        }

        // Process message
        let msg_blocks = m.len() / (32 * D);
        let msg_rem = m.len() % (32 * D);

        for i in 0..msg_blocks {
            let src_block = &m[i * 32 * D..(i + 1) * 32 * D];
            let dst_block = &mut c[i * 32 * D..(i + 1) * 32 * D];
            state.enc(dst_block.try_into().unwrap(), src_block.try_into().unwrap());
        }

        if msg_rem > 0 {
            let mut src_buf = [0u8; 32 * D];
            let mut dst_buf = [0u8; 32 * D];
            src_buf[..msg_rem].copy_from_slice(&m[msg_blocks * 32 * D..]);
            state.enc(&mut dst_buf, &src_buf);
            c[msg_blocks * 32 * D..].copy_from_slice(&dst_buf[..msg_rem]);
        }

        let tag = state.finalize::<TAG_BYTES>(ad.len(), m.len());
        (c, tag)
    }

    /// Encrypts a message in place
    pub fn encrypt_in_place(self, mc: &mut [u8], ad: &[u8]) -> Tag<TAG_BYTES> {
        let mut state = State::new(&self.key, &self.nonce);

        // Process associated data
        let ad_blocks = ad.len() / (32 * D);
        let ad_rem = ad.len() % (32 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 32 * D..(i + 1) * 32 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 32 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 32 * D..]);
            state.absorb(&buf);
        }

        // Process message
        let msg_len = mc.len();
        let msg_blocks = msg_len / (32 * D);
        let msg_rem = msg_len % (32 * D);

        for i in 0..msg_blocks {
            let mut block = [0u8; 32 * D];
            block.copy_from_slice(&mc[i * 32 * D..(i + 1) * 32 * D]);
            let src = block.clone();
            state.enc(&mut block, &src);
            mc[i * 32 * D..(i + 1) * 32 * D].copy_from_slice(&block);
        }

        if msg_rem > 0 {
            let mut src_buf = [0u8; 32 * D];
            let mut dst_buf = [0u8; 32 * D];
            src_buf[..msg_rem].copy_from_slice(&mc[msg_blocks * 32 * D..]);
            state.enc(&mut dst_buf, &src_buf);
            mc[msg_blocks * 32 * D..].copy_from_slice(&dst_buf[..msg_rem]);
        }

        state.finalize::<TAG_BYTES>(ad.len(), msg_len)
    }

    /// Decrypts a message using AEGIS-128X4
    #[cfg(feature = "std")]
    pub fn decrypt(self, c: &[u8], tag: &Tag<TAG_BYTES>, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = State::new(&self.key, &self.nonce);
        let mut m = vec![0u8; c.len()];

        // Process associated data
        let ad_blocks = ad.len() / (32 * D);
        let ad_rem = ad.len() % (32 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 32 * D..(i + 1) * 32 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 32 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 32 * D..]);
            state.absorb(&buf);
        }

        // Process ciphertext
        let ct_blocks = c.len() / (32 * D);
        let ct_rem = c.len() % (32 * D);

        for i in 0..ct_blocks {
            let src_block = &c[i * 32 * D..(i + 1) * 32 * D];
            let dst_block = &mut m[i * 32 * D..(i + 1) * 32 * D];
            state.dec(dst_block.try_into().unwrap(), src_block.try_into().unwrap());
        }

        if ct_rem > 0 {
            let mut dst_buf = [0u8; 32 * D];
            let actual_len = state.dec_partial(&mut dst_buf, &c[ct_blocks * 32 * D..]);
            m[ct_blocks * 32 * D..].copy_from_slice(&dst_buf[..actual_len]);
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
        let ad_blocks = ad.len() / (32 * D);
        let ad_rem = ad.len() % (32 * D);

        for i in 0..ad_blocks {
            let block = &ad[i * 32 * D..(i + 1) * 32 * D];
            state.absorb(block.try_into().unwrap());
        }

        if ad_rem > 0 {
            let mut buf = [0u8; 32 * D];
            buf[..ad_rem].copy_from_slice(&ad[ad_blocks * 32 * D..]);
            state.absorb(&buf);
        }

        // Process ciphertext
        let ct_len = mc.len();
        let ct_blocks = ct_len / (32 * D);
        let ct_rem = ct_len % (32 * D);

        for i in 0..ct_blocks {
            let mut block = [0u8; 32 * D];
            block.copy_from_slice(&mc[i * 32 * D..(i + 1) * 32 * D]);
            let src = block.clone();
            state.dec(&mut block, &src);
            mc[i * 32 * D..(i + 1) * 32 * D].copy_from_slice(&block);
        }

        if ct_rem > 0 {
            let mut dst_buf = [0u8; 32 * D];
            let actual_len = state.dec_partial(&mut dst_buf, &mc[ct_blocks * 32 * D..]);
            mc[ct_blocks * 32 * D..].copy_from_slice(&dst_buf[..actual_len]);
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
pub struct Aegis128X4Mac<const TAG_BYTES: usize> {
    state: State,
    ad_len: usize,
    msg_len: usize,
}

impl<const TAG_BYTES: usize> Aegis128X4Mac<TAG_BYTES> {
    pub fn new(key: &Key) -> Self {
        let nonce = [0u8; 16];
        Aegis128X4Mac {
            state: State::new(key, &nonce),
            ad_len: 0,
            msg_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let blocks = data.len() / (32 * D);
        let rem = data.len() % (32 * D);

        for i in 0..blocks {
            let block = &data[i * 32 * D..(i + 1) * 32 * D];
            self.state.absorb(block.try_into().unwrap());
        }

        if rem > 0 {
            let mut buf = [0u8; 32 * D];
            buf[..rem].copy_from_slice(&data[blocks * 32 * D..]);
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

impl<const TAG_BYTES: usize> Clone for Aegis128X4Mac<TAG_BYTES> {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            ad_len: self.ad_len,
            msg_len: self.msg_len,
        }
    }
}

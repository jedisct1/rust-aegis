mod aes {
    pub use softaes::Block;
    pub use softaes::SoftAesFast as Aes;
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AesBlock(aes::Block);

impl AesBlock {
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        AesBlock(aes::Block::from_slice(bytes))
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0.to_bytes()
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        AesBlock(self.0 ^ other.0)
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock) -> AesBlock {
        AesBlock(self.0 & other.0)
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        AesBlock(aes::Aes::block_encrypt(&self.0, &rk.0))
    }
}

/// A pair of AES blocks for parallel processing
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AesBlock2([AesBlock; 2]);

impl AesBlock2 {
    #[inline(always)]
    pub fn from_blocks(b0: AesBlock, b1: AesBlock) -> Self {
        AesBlock2([b0, b1])
    }

    #[inline(always)]
    pub fn as_blocks(&self) -> (AesBlock, AesBlock) {
        (self.0[0], self.0[1])
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock2) -> AesBlock2 {
        AesBlock2([self.0[0].xor(other.0[0]), self.0[1].xor(other.0[1])])
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock2) -> AesBlock2 {
        AesBlock2([self.0[0].and(other.0[0]), self.0[1].and(other.0[1])])
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock2) -> AesBlock2 {
        AesBlock2([self.0[0].round(rk.0[0]), self.0[1].round(rk.0[1])])
    }
}

/// Four AES blocks for parallel processing
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AesBlock4([AesBlock; 4]);

impl AesBlock4 {
    #[inline(always)]
    pub fn from_blocks(b0: AesBlock, b1: AesBlock, b2: AesBlock, b3: AesBlock) -> Self {
        AesBlock4([b0, b1, b2, b3])
    }

    #[inline(always)]
    pub fn as_blocks(&self) -> (AesBlock, AesBlock, AesBlock, AesBlock) {
        (self.0[0], self.0[1], self.0[2], self.0[3])
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock4) -> AesBlock4 {
        AesBlock4([
            self.0[0].xor(other.0[0]),
            self.0[1].xor(other.0[1]),
            self.0[2].xor(other.0[2]),
            self.0[3].xor(other.0[3]),
        ])
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock4) -> AesBlock4 {
        AesBlock4([
            self.0[0].and(other.0[0]),
            self.0[1].and(other.0[1]),
            self.0[2].and(other.0[2]),
            self.0[3].and(other.0[3]),
        ])
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock4) -> AesBlock4 {
        AesBlock4([
            self.0[0].round(rk.0[0]),
            self.0[1].round(rk.0[1]),
            self.0[2].round(rk.0[2]),
            self.0[3].round(rk.0[3]),
        ])
    }
}

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

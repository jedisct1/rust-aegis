#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AesBlock(aes::Block);

impl AesBlock {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        AesBlock(*aes::Block::from_slice(bytes))
    }

    #[inline]
    pub fn as_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(self.0.as_slice());
        bytes
    }

    #[inline]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        let s1 = self.0.as_slice();
        let s2 = other.0.as_slice();
        let mut res = AesBlock::default();
        let s3 = res.0.as_mut_slice();
        (0..16).for_each(|i| s3[i] = s1[i] ^ s2[i]);
        res
    }

    #[inline]
    pub fn and(&self, other: AesBlock) -> AesBlock {
        let s1 = self.0.as_slice();
        let s2 = other.0.as_slice();
        let mut res = AesBlock::default();
        let s3 = res.0.as_mut_slice();
        (0..16).for_each(|i| s3[i] = s1[i] & s2[i]);
        res
    }

    #[inline]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        let mut res = self.0;
        aes::hazmat::cipher_round(&mut res, &rk.0);
        AesBlock(res)
    }
}

use core::arch::aarch64;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock(aarch64::uint8x16_t);

impl AesBlock {
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        AesBlock(unsafe { aarch64::vld1q_u8(bytes.as_ptr() as *const _) })
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe { aarch64::vst1q_u8(bytes.as_mut_ptr() as *mut _, self.0) };
        bytes
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { aarch64::veorq_u8(self.0, other.0) })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { aarch64::vandq_u8(self.0, other.0) })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        // Use target_feature to ensure the AES instructions are inlined
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round(
            a: aarch64::uint8x16_t,
            rk: aarch64::uint8x16_t,
        ) -> aarch64::uint8x16_t {
            aarch64::veorq_u8(
                aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a, aarch64::vmovq_n_u8(0))),
                rk,
            )
        }
        AesBlock(unsafe { aes_round(self.0, rk.0) })
    }
}

/// A pair of AES blocks for parallel processing
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock2([aarch64::uint8x16_t; 2]);

impl AesBlock2 {
    #[inline(always)]
    pub fn from_blocks(b0: AesBlock, b1: AesBlock) -> Self {
        AesBlock2([b0.0, b1.0])
    }

    #[inline(always)]
    pub fn as_blocks(&self) -> (AesBlock, AesBlock) {
        (AesBlock(self.0[0]), AesBlock(self.0[1]))
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock2) -> AesBlock2 {
        AesBlock2(unsafe {
            [
                aarch64::veorq_u8(self.0[0], other.0[0]),
                aarch64::veorq_u8(self.0[1], other.0[1]),
            ]
        })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock2) -> AesBlock2 {
        AesBlock2(unsafe {
            [
                aarch64::vandq_u8(self.0[0], other.0[0]),
                aarch64::vandq_u8(self.0[1], other.0[1]),
            ]
        })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock2) -> AesBlock2 {
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round2(
            a: [aarch64::uint8x16_t; 2],
            rk: [aarch64::uint8x16_t; 2],
        ) -> [aarch64::uint8x16_t; 2] {
            let zero = aarch64::vmovq_n_u8(0);
            [
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[0], zero)), rk[0]),
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[1], zero)), rk[1]),
            ]
        }
        AesBlock2(unsafe { aes_round2(self.0, rk.0) })
    }
}

/// Four AES blocks for parallel processing
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock4([aarch64::uint8x16_t; 4]);

impl AesBlock4 {
    #[inline(always)]
    pub fn from_blocks(b0: AesBlock, b1: AesBlock, b2: AesBlock, b3: AesBlock) -> Self {
        AesBlock4([b0.0, b1.0, b2.0, b3.0])
    }

    #[inline(always)]
    pub fn as_blocks(&self) -> (AesBlock, AesBlock, AesBlock, AesBlock) {
        (
            AesBlock(self.0[0]),
            AesBlock(self.0[1]),
            AesBlock(self.0[2]),
            AesBlock(self.0[3]),
        )
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock4) -> AesBlock4 {
        AesBlock4(unsafe {
            [
                aarch64::veorq_u8(self.0[0], other.0[0]),
                aarch64::veorq_u8(self.0[1], other.0[1]),
                aarch64::veorq_u8(self.0[2], other.0[2]),
                aarch64::veorq_u8(self.0[3], other.0[3]),
            ]
        })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock4) -> AesBlock4 {
        AesBlock4(unsafe {
            [
                aarch64::vandq_u8(self.0[0], other.0[0]),
                aarch64::vandq_u8(self.0[1], other.0[1]),
                aarch64::vandq_u8(self.0[2], other.0[2]),
                aarch64::vandq_u8(self.0[3], other.0[3]),
            ]
        })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock4) -> AesBlock4 {
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round4(
            a: [aarch64::uint8x16_t; 4],
            rk: [aarch64::uint8x16_t; 4],
        ) -> [aarch64::uint8x16_t; 4] {
            let zero = aarch64::vmovq_n_u8(0);
            [
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[0], zero)), rk[0]),
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[1], zero)), rk[1]),
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[2], zero)), rk[2]),
                aarch64::veorq_u8(aarch64::vaesmcq_u8(aarch64::vaeseq_u8(a[3], zero)), rk[3]),
            ]
        }
        AesBlock4(unsafe { aes_round4(self.0, rk.0) })
    }
}

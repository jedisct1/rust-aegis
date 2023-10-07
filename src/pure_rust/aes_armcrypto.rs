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
        AesBlock(unsafe {
            aarch64::veorq_u8(
                aarch64::vaesmcq_u8(aarch64::vaeseq_u8(self.0, aarch64::vmovq_n_u8(0))),
                rk.0,
            )
        })
    }
}

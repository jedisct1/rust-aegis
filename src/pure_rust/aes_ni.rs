#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock(arch::__m128i);

impl AesBlock {
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        AesBlock(unsafe { arch::_mm_loadu_si128(bytes.as_ptr() as *const _) })
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe { arch::_mm_storeu_si128(bytes.as_mut_ptr() as *mut _, self.0) };
        bytes
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { arch::_mm_xor_si128(self.0, other.0) })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { arch::_mm_and_si128(self.0, other.0) })
    }

    /// Perform one AES encryption round
    #[inline(always)]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        // Use target_feature to ensure the AES instruction is inlined
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round(a: arch::__m128i, rk: arch::__m128i) -> arch::__m128i {
            arch::_mm_aesenc_si128(a, rk)
        }
        AesBlock(unsafe { aes_round(self.0, rk.0) })
    }
}

/// A pair of AES blocks for parallel processing
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock2([arch::__m128i; 2]);

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
                arch::_mm_xor_si128(self.0[0], other.0[0]),
                arch::_mm_xor_si128(self.0[1], other.0[1]),
            ]
        })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock2) -> AesBlock2 {
        AesBlock2(unsafe {
            [
                arch::_mm_and_si128(self.0[0], other.0[0]),
                arch::_mm_and_si128(self.0[1], other.0[1]),
            ]
        })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock2) -> AesBlock2 {
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round2(a: [arch::__m128i; 2], rk: [arch::__m128i; 2]) -> [arch::__m128i; 2] {
            [
                arch::_mm_aesenc_si128(a[0], rk[0]),
                arch::_mm_aesenc_si128(a[1], rk[1]),
            ]
        }
        AesBlock2(unsafe { aes_round2(self.0, rk.0) })
    }
}

/// Four AES blocks for parallel processing
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock4([arch::__m128i; 4]);

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
                arch::_mm_xor_si128(self.0[0], other.0[0]),
                arch::_mm_xor_si128(self.0[1], other.0[1]),
                arch::_mm_xor_si128(self.0[2], other.0[2]),
                arch::_mm_xor_si128(self.0[3], other.0[3]),
            ]
        })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock4) -> AesBlock4 {
        AesBlock4(unsafe {
            [
                arch::_mm_and_si128(self.0[0], other.0[0]),
                arch::_mm_and_si128(self.0[1], other.0[1]),
                arch::_mm_and_si128(self.0[2], other.0[2]),
                arch::_mm_and_si128(self.0[3], other.0[3]),
            ]
        })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock4) -> AesBlock4 {
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn aes_round4(a: [arch::__m128i; 4], rk: [arch::__m128i; 4]) -> [arch::__m128i; 4] {
            [
                arch::_mm_aesenc_si128(a[0], rk[0]),
                arch::_mm_aesenc_si128(a[1], rk[1]),
                arch::_mm_aesenc_si128(a[2], rk[2]),
                arch::_mm_aesenc_si128(a[3], rk[3]),
            ]
        }
        AesBlock4(unsafe { aes_round4(self.0, rk.0) })
    }
}

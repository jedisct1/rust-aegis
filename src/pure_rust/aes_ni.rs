use core::arch::x86_64;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct AesBlock(x86_64::__m128i);

impl AesBlock {
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        AesBlock(unsafe { x86_64::_mm_loadu_si128(bytes.as_ptr() as *const _) })
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe { x86_64::_mm_storeu_si128(bytes.as_mut_ptr() as *mut _, self.0) };
        bytes
    }

    #[inline(always)]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { x86_64::_mm_xor_si128(self.0, other.0) })
    }

    #[inline(always)]
    pub fn and(&self, other: AesBlock) -> AesBlock {
        AesBlock(unsafe { x86_64::_mm_and_si128(self.0, other.0) })
    }

    #[inline(always)]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        // Unfortunately, Rust is unable to inline this and emits a function call.
        AesBlock(unsafe { x86_64::_mm_aesenc_si128(self.0, rk.0) })
    }
}

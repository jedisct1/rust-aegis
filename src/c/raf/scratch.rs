use std::alloc::Layout;

use super::ffi::aegis_raf_scratch;

const SCRATCH_ALIGN: usize = 64;

pub(crate) struct ScratchBuf {
    ptr: *mut u8,
    layout: Layout,
}

impl ScratchBuf {
    pub fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, SCRATCH_ALIGN).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "scratch buffer allocation failed");
        ScratchBuf { ptr, layout }
    }

    pub fn as_ffi(&self) -> aegis_raf_scratch {
        aegis_raf_scratch {
            buf: self.ptr,
            len: self.layout.size(),
        }
    }
}

impl Drop for ScratchBuf {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) }
    }
}

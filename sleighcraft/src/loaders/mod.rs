pub mod plain;

use crate::ffi::ffi::AddressProxy;

/// Any loader must implement Loader trait, which enables sleigh to get raw bytes
pub trait Loader {
    /// load bytes at `addr` from image into buffer indicated by `ptr`
    fn load_fill(&mut self, ptr: &mut [u8], addr: &AddressProxy);
    fn adjust_vma(&mut self, _adjust: isize) {}
    /// return size of the loaded image
    fn buf_size(&mut self) -> usize;
}

/// Wrapper for any object which implements `Loader` trait, only for ffi usage.
/// We use dynamic dispatch here to better comminucate with the c++ side
pub struct RustLoaderWrapper<'a> {
    internal: &'a mut dyn Loader
}

impl<'a> RustLoaderWrapper<'a> {
    pub(crate) fn load_fill(&mut self, ptr: &mut [u8], addr: &AddressProxy) {
        self.internal.load_fill(ptr, addr)
    }

    pub(crate) fn adjust_vma(&mut self, adjust: isize) {
        self.internal.adjust_vma(adjust)
    }

    pub(crate) fn buf_size(&mut self) -> usize {
        self.internal.buf_size()
    }
}

impl<'a> RustLoaderWrapper<'a> {
    pub(crate) fn new(loader: &'a mut dyn Loader) -> Self {
        RustLoaderWrapper {
            internal: loader
        }
    }
}

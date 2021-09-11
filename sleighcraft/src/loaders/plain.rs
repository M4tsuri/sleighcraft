use std::str::pattern::Searcher;

use crate::ffi::ffi::AddressProxy;
use super::Loader;

/// A plain loader which loads specified bytes into the internal buffer without any 
/// modification.
#[derive(Debug, Default)]
pub struct PlainLoader {
    buf: Vec<u8>,
    start: u64,
}

impl Loader for PlainLoader {
    fn load_fill(&mut self, ptr: &mut [u8], addr: &AddressProxy) {
        let start_off = addr.get_offset() as u64;
        let size = ptr.len();
        let max = self.start + (self.buf.len() as u64 - 1);

        for i in 0..size {
            let cur_off = start_off + i as u64;
            if self.start <= cur_off && max >= cur_off {
                let offset = (cur_off - self.start) as usize;
                ptr[i] = self.buf[offset];
            } else {
                ptr[i] = 0;
            }
        }
    }
    fn buf_size(&mut self) -> usize {
        self.buf.len()
    }
}

impl PlainLoader {
    /// extend internal buffer with specified data
    pub fn extend(&mut self, buf: &[u8]) {
        self.buf.extend_from_slice(buf);
    }

    /// Construct a new loader with empty buffer and 0 offset
    pub fn new() -> Self {
        Self {
            buf: vec![],
            start: 0
        }
    } 

    pub fn from_buf(buf: &[u8], start: u64) -> Self {
        let mut v = vec![];
        v.extend_from_slice(buf);
        Self { buf: v, start }
    }
}

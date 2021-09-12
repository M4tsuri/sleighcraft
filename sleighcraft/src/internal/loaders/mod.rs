//
//  Copyright 2021 StarCrossTech
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// This file is changed.

//! This module defines everything about a loader.
//! Users can define there own loader by implementing the `Loader` trait.


pub mod plain;

use crate::internal::ffi::ffi::AddressProxy;

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
pub struct LoaderWrapper {
    internal: Box<dyn Loader>
}

impl LoaderWrapper {
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

impl LoaderWrapper {
    pub(crate) fn new(loader: Box<dyn Loader>) -> Self {
        LoaderWrapper {
            internal: loader
        }
    }
}

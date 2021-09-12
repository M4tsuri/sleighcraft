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
//
// This file is changed.


use crate::internal::collectors::asm_collector::{AsmCollector, AsmCollectorWrapper};
use crate::internal::collectors::pcode_collector::{PcodeCollector, PcodeCollectorWrapper};
use crate::internal::error::{Error, Result};
use crate::internal::loaders::{Loader, LoaderWrapper};
use cxx::UniquePtr;
use owning_ref::{BoxRefMut, OwningRef, OwningRefMut};

use crate::internal::ffi::ffi::*;
use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::pin::Pin;
use crate::config::Mode;

pub struct Sleigh {
    sleigh_proxy: UniquePtr<SleighProxy>,
    asm_emit: AsmCollectorWrapper,
    pcode_emit: PcodeCollectorWrapper,
    loader: Pin<Box<LoaderWrapper>>,
    spec: String,
    mode: Mode
}

impl Sleigh {
    pub fn decode(&mut self, start: u64) -> Result<()> {
        // self.load_image.set_buf(bytes);
        let assembly_emit = self.asm_emit.borrow_mut();
        let pcodes_emit = self.pcode_emit.borrow_mut();
        
        self.sleigh_proxy
            .as_mut().unwrap()
            .decode_with(assembly_emit, pcodes_emit, start)
            .map_err(|e| Error::CppException(e))
    }
}

pub struct SleighBuilder<L, A, P> 
where 
    L: Loader + 'static,
    A: AsmCollector + 'static,
    P: PcodeCollector + 'static
{
    asm_collector: Option<A>,
    pcode_collector: Option<P>,
    loader: Option<L>,
    spec: Option<String>,
    mode: Option<Mode>,
}

impl<L, A, P> SleighBuilder<L, A, P>
where 
    L: Loader + 'static,
    A: AsmCollector + 'static,
    P: PcodeCollector + 'static
{
    pub fn new() -> Self {
        Self {
            asm_collector: None,
            pcode_collector: None,
            loader: None,
            spec: None,
            mode: None
        }
    }

    // TODO: add from_arch(arch_name: &str) -> Self helper function.

    pub fn set_asm_collector(mut self, asm_collector: A) -> Self {
        self.asm_collector = Some(asm_collector);
        self
    }

    pub fn set_pcode_collector(mut self, pcode_collector: P) -> Self {
        self.pcode_collector = Some(pcode_collector);
        self
    }

    pub fn set_mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn set_spec(mut self, spec: String) -> Self {
        // self.load_image = unsafe{Some(Box::from_raw(loader))};
        self.spec = Some(spec);
        self
    }

    pub fn set_loader(mut self, loader: L) -> Self {
        self.loader = Some(loader);
        self
    }

    pub fn try_build(mut self) -> Result<Sleigh> {
        let wrapped_loader = LoaderWrapper::new(Box::new(self.loader.unwrap()));
        let mut pinned_loader = Box::pin(wrapped_loader);
        
        if self.mode.is_none() {
            // Set default address and Operand size
            self.mode = Some(Mode::MODE16);
        };

        Ok(Sleigh {
            sleigh_proxy: new_sleigh_proxy(&mut pinned_loader),
            asm_emit: AsmCollectorWrapper::new(Box::new(self.asm_collector.unwrap())),
            pcode_emit:  PcodeCollectorWrapper::new(Box::new(self.pcode_collector.unwrap())),
            spec: self.spec.unwrap(),
            mode: self.mode.unwrap(),
            loader: pinned_loader
        })
    }
}



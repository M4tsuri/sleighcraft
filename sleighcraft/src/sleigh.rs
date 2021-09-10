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


use crate::error::{Error, Result};
use cxx::{CxxString, UniquePtr};
use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::ffi::ffi::*;
use std::borrow::BorrowMut;
use std::pin::Pin;
use crate::Mode::MODE16;

#[derive(Copy, Clone)]
#[repr(i32)]
pub enum Mode {
    // Default Address size is 16-bit
    MODE16 = 0,
    // Address size is 32-bit
    MODE32 = 1,
    // Address size is 32-bit
    MODE64 = 2,
}

pub trait AssemblyEmit {
    fn dump(&mut self, addr: &AddressProxy, mnem: &str, body: &str);
}

pub struct RustAssemblyEmit<'a> {
    internal: &'a mut dyn AssemblyEmit,
}

impl<'a> RustAssemblyEmit<'a> {
    pub fn dump(&mut self, address: &AddressProxy, mnem: &CxxString, body: &CxxString) {
        let mnem = mnem.to_str().unwrap();
        let body = body.to_str().unwrap();

        self.internal.dump(address, mnem, body);
    }

    pub fn from_internal(internal: &'a mut dyn AssemblyEmit) -> Self {
        Self { internal }
    }
}

#[derive(Debug, Default)]
pub struct CollectingAssemblyEmit {
    pub asms: Vec<Instruction>,
}

impl AssemblyEmit for CollectingAssemblyEmit {
    fn dump(&mut self, addr: &AddressProxy, mnem: &str, body: &str) {
        let space = addr.get_space().get_name().to_str().unwrap().to_string();
        let offset = addr.get_offset() as u64;
        let asm = Instruction {
            addr: Address { space, offset },
            mnemonic: mnem.to_string(),
            body: body.to_string(),
        };
        self.asms.push(asm)
    }
}

#[derive(Debug)]
pub struct PcodeVarnodeData {
    pub space: String,
    pub offset: usize,
    pub size: u32,
}

impl PcodeVarnodeData {
    pub fn from_proxy(proxy: &VarnodeDataProxy) -> Self {
        let space = String::from(proxy.get_space().get_name().to_str().unwrap());
        let offset = proxy.get_offset();
        let size = proxy.get_size();

        Self {
            space,
            offset,
            size,
        }
    }
}

#[derive(Debug)]
pub struct PcodeInstruction {
    pub addr: Address,
    pub opcode: PcodeOpCode,
    pub vars: Vec<PcodeVarnodeData>,
    pub out_var: Option<PcodeVarnodeData>,
}

pub trait PcodeEmit {
    /// Callback that will be called when disassembling, emitting the pcode
    /// - address: the address of the machine instruction
    /// - opcode: the opcode of the particular pcode instruction
    /// - outvar: a data about the output varnode
    /// - vars: an array of VarnodeData for each input varnode
    fn dump(
        &mut self,
        address: &AddressProxy,
        opcode: PcodeOpCode,
        outvar: Option<&VarnodeDataProxy>,
        vars: &[&VarnodeDataProxy],
    );
}

#[derive(Debug, Default)]
pub struct CollectingPcodeEmit {
    pub pcode_asms: Vec<PcodeInstruction>,
}

impl PcodeEmit for CollectingPcodeEmit {
    fn dump(
        &mut self,
        addr: &AddressProxy,
        opcode: PcodeOpCode,
        outvar: Option<&VarnodeDataProxy>,
        vars: &[&VarnodeDataProxy],
    ) {
        //let space = String::from(outvar.get_space().get_name().to_str().unwrap());
        //let offset = outvar.get_offset() as u64;
        // let data = format!("{}{}{}{}{:x}{}{}{}{}", "(", space, ",", "0x", of, ",", size, ")", "=");

        let space = String::from(addr.get_space().get_name().to_str().unwrap());
        let offset = addr.get_offset() as u64;
        let mut pcode_vars = vec![];
        for v in vars.iter() {
            pcode_vars.push(PcodeVarnodeData::from_proxy(*v));
        }
        let out_var = if let Some(outvar) = outvar {
            Some(PcodeVarnodeData::from_proxy(outvar))
        } else {
            None
        };
        self.pcode_asms.push(PcodeInstruction {
            addr: Address { space, offset },
            opcode: opcode,
            vars: pcode_vars,
            out_var,
        });
    }
}

pub struct RustPcodeEmit<'a> {
    pub internal: &'a mut dyn PcodeEmit,
}

impl<'a> RustPcodeEmit<'a> {
    pub fn from_internal(internal: &'a mut dyn PcodeEmit) -> Self {
        Self { internal }
    }

    pub fn dump(
        &mut self,
        address: &AddressProxy,
        opcode: PcodeOpCode,
        outvar: Pin<&mut VarnodeDataProxy>,
        vars: &cxx::CxxVector<VarnodeDataProxy>,
    ) {
        let outvar = if outvar.not_null() {
            Some(&*outvar)
        } else {
            None
        };

        let mut vars_vec = vec![];
        for i in 0..vars.len() {
            vars_vec.push(vars.get(i).unwrap());
        }
        self.internal
            .dump(address, opcode, outvar, vars_vec.as_slice());
    }
}

pub trait LoadImage {
    fn load_fill(&mut self, ptr: &mut [u8], addr: &AddressProxy);
    fn adjust_vma(&mut self, _adjust: isize) {}
    fn buf_size(&mut self) -> usize;
}

pub struct RustLoadImage<'a> {
    internal: &'a mut dyn LoadImage,
}

impl<'a> RustLoadImage<'a> {
    pub fn from_internal(internal: &'a mut dyn LoadImage) -> Self {
        Self { internal }
    }

    pub fn load_fill(&mut self, ptr: &mut [u8], addr: &AddressProxy) {
        self.internal.load_fill(ptr, addr)
    }

    pub fn adjust_vma(&mut self, adjust: isize) {
        self.internal.adjust_vma(adjust)
    }
    pub fn buf_size(&mut self) -> usize {
        self.internal.buf_size()
    }
}

#[derive(Debug, Default)]
pub struct PlainLoadImage {
    buf: Vec<u8>,
    start: u64,
}

impl LoadImage for PlainLoadImage {
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

impl PlainLoadImage {
    pub fn from_buf(buf: &[u8], start: u64) -> Self {
        let mut v = vec![];
        v.extend_from_slice(buf);
        Self { buf: v, start }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub space: String,
    pub offset: u64,
}

#[derive(Debug)]
pub struct Instruction {
    pub addr: Address,
    pub mnemonic: String,
    pub body: String,
}

impl Instruction {
    pub fn set_addr(&mut self, sp: String, of: u64) {
        self.addr = Address {
            space: sp,
            offset: of,
        }
    }
    pub fn set_mnemonic(&mut self, mnem: String) {
        self.mnemonic = mnem
    }
    pub fn set_body(&mut self, body: String) {
        self.body = body
    }
}

fn load_preset() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    macro_rules! def_arch {
        ($name: expr) => {
            // presets are used across the whole lifetime, it's safe to ignore
            // the lifetime by leaking its names' memory
            let name: &'static str = Box::leak($name.to_lowercase().into_boxed_str());
            map.insert(name, include_str!(concat!("sla/", $name, ".sla")));
        };
    }
    def_arch!("6502");
    def_arch!("6805");
    def_arch!("6809");
    def_arch!("8048");
    def_arch!("8051");
    def_arch!("8085");
    def_arch!("68020");
    def_arch!("68030");
    def_arch!("68040");
    def_arch!("80251");
    def_arch!("80390");
    def_arch!("AARCH64");
    def_arch!("AARCH64BE");
    def_arch!("ARM4_be");
    def_arch!("ARM4_le");
    def_arch!("ARM4t_be");
    def_arch!("ARM4t_le");
    def_arch!("ARM5_be");
    def_arch!("ARM5_le");
    def_arch!("ARM5t_be");
    def_arch!("ARM5t_le");
    def_arch!("ARM6_be");
    def_arch!("ARM6_le");
    def_arch!("ARM7_be");
    def_arch!("ARM7_le");
    def_arch!("ARM8_be");
    def_arch!("ARM8_le");
    def_arch!("avr8");
    def_arch!("avr8e");
    def_arch!("avr8eind");
    def_arch!("avr8xmega");
    def_arch!("avr32a");
    def_arch!("coldfire");
    def_arch!("CP1600");
    def_arch!("CR16B");
    def_arch!("CR16C");
    def_arch!("Dalvik");
    def_arch!("data-be-64");
    def_arch!("data-le-64");
    def_arch!("dsPIC30F");
    def_arch!("dsPIC33C");
    def_arch!("dsPIC33E");
    def_arch!("dsPIC33F");
    def_arch!("HC05");
    def_arch!("HC08");
    def_arch!("HCS08");
    def_arch!("HCS12");
    def_arch!("JVM");
    def_arch!("m8c");
    def_arch!("MCS96");
    def_arch!("mips32be");
    def_arch!("mips32le");
    def_arch!("mips32R6be");
    def_arch!("mips32R6le");
    def_arch!("mips64be");
    def_arch!("mips64le");
    def_arch!("mx51");
    def_arch!("pa-risc32be");
    def_arch!("pic12c5xx");
    def_arch!("pic16");
    def_arch!("pic16c5x");
    def_arch!("pic16f");
    def_arch!("pic17c7xx");
    def_arch!("pic18");
    def_arch!("PIC24E");
    def_arch!("PIC24F");
    def_arch!("PIC24H");
    def_arch!("ppc_32_4xx_be");
    def_arch!("ppc_32_4xx_le");
    def_arch!("ppc_32_be");
    def_arch!("ppc_32_le");
    def_arch!("ppc_32_quicciii_be");
    def_arch!("ppc_32_quicciii_le");
    def_arch!("ppc_64_be");
    def_arch!("ppc_64_isa_altivec_be");
    def_arch!("ppc_64_isa_altivec_le");
    def_arch!("ppc_64_isa_altivec_vle_be");
    def_arch!("ppc_64_isa_be");
    def_arch!("ppc_64_isa_le");
    def_arch!("ppc_64_isa_vle_be");
    def_arch!("ppc_64_le");
    def_arch!("riscv");
    def_arch!("sh-1");
    def_arch!("sh-2");
    def_arch!("sh-2a");
    def_arch!("SparcV9_32");
    def_arch!("SparcV9_64");
    def_arch!("SuperH4_be");
    def_arch!("SuperH4_le");
    def_arch!("TI_MSP430");
    def_arch!("TI_MSP430X");
    def_arch!("toy_be_posStack");
    def_arch!("toy_be");
    def_arch!("toy_builder_be_align2");
    def_arch!("toy_builder_be");
    def_arch!("toy_builder_le_align2");
    def_arch!("toy_builder_le");
    def_arch!("toy_le");
    def_arch!("toy_wsz_be");
    def_arch!("toy_wsz_le");
    def_arch!("toy64_be_harvard");
    def_arch!("toy64_be");
    def_arch!("toy64_le");
    def_arch!("tricore");
    def_arch!("V850");
    def_arch!("x86-64");
    def_arch!("x86");
    def_arch!("z80");
    def_arch!("z180");

    map
}

const PRESET: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| load_preset());

pub struct Sleigh<'a> {
    sleigh_proxy: UniquePtr<SleighProxy>,
    asm_emit: RustAssemblyEmit<'a>,
    pcode_emit: RustPcodeEmit<'a>,
    _load_image: Pin<Box<RustLoadImage<'a>>>,
}

impl<'a> Sleigh<'a> {
    pub fn decode(&mut self, start: u64) -> Result<()> {
        // self.load_image.set_buf(bytes);
        let assembly_emit = self.asm_emit.borrow_mut();
        let pcodes_emit = self.pcode_emit.borrow_mut();
        self.sleigh_proxy
            .as_mut()
            .unwrap()
            .decode_with(assembly_emit, pcodes_emit, start)
            .map_err(|e| Error::CppException(e))
    }
}

#[derive(Default)]
pub struct SleighBuilder<'a> {
    asm_emit: Option<RustAssemblyEmit<'a>>,
    pcode_emit: Option<RustPcodeEmit<'a>>,
    load_image: Option<RustLoadImage<'a>>,
    spec: Option<String>,
    mode: Option<Mode>,
}
impl<'a> SleighBuilder<'a> {
    // TODO: add from_arch(arch_name: &str) -> Self helper function.

    pub fn asm_emit(&mut self, asm_emit: &'a mut dyn AssemblyEmit) -> &mut Self {
        self.asm_emit = Some(RustAssemblyEmit::from_internal(asm_emit));
        self
    }

    pub fn pcode_emit(&mut self, pcode_emit: &'a mut dyn PcodeEmit) -> &mut Self {
        self.pcode_emit = Some(RustPcodeEmit::from_internal(pcode_emit));
        self
    }

    pub fn mode(&mut self, mode: Mode) -> &mut Self {
        self.mode = Some(mode);
        self
    }

    pub fn spec(&mut self, spec: &str) -> &mut Self {
        // self.load_image = unsafe{Some(Box::from_raw(loader))};
        self.spec = Some(spec.to_string());
        self
    }

    pub fn loader(&mut self, loader: &'a mut dyn LoadImage) -> &mut Self {
        self.load_image = Some(RustLoadImage::from_internal(loader));
        self
    }

    pub fn try_build(mut self) -> Result<Sleigh<'a>> {
        let load_image = self
            .load_image
            .ok_or(Error::MissingArg("load_image".to_string()))?;
        let mut load_image = Box::pin(load_image);
        let mut sleigh_proxy = new_sleigh_proxy(&mut load_image);

        let spec = self.spec.ok_or(Error::MissingArg("spec".to_string()))?;
        if self.mode.is_none() {
            // Set default address and Operand size
            self.mode = Some(MODE16);
        };
        sleigh_proxy
            .as_mut()
            .unwrap()
            .set_spec(spec.as_str(), self.mode.unwrap() as i32);

        let asm_emit = self
            .asm_emit
            .ok_or(Error::MissingArg("asm_emit".to_string()))?;
        let pcode_emit = self
            .pcode_emit
            .ok_or(Error::MissingArg("pcode_emit".to_string()))?;

        Ok(Sleigh {
            sleigh_proxy,
            asm_emit,
            pcode_emit,
            _load_image: load_image,
        })
    }
}
pub fn arch(name: &str) -> Result<&str> {
    let content = *PRESET
        .get(&name.to_lowercase().as_str())
        .ok_or(Error::ArchNotFound(name.to_string()))?;
    Ok(content)
}

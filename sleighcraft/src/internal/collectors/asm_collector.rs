use std::any::Any;

use cxx::CxxString;
use crate::internal::ffi::ffi::AddressProxy;
use crate::pcode::{Instruction, Address};

pub trait AsmCollector {
    /// this function is invoked at the C++ side
    fn dump(&mut self, addr: &AddressProxy, mnem: &str, body: &str);

    /// reset current collector
    fn reset(&mut self) {}

    fn as_any(&self) -> &dyn Any;
}

pub struct AsmCollectorWrapper {
    internal: Box<dyn AsmCollector>,
}

impl AsmCollectorWrapper {
    pub fn dump(&mut self, address: &AddressProxy, mnem: &CxxString, body: &CxxString) {
        let mnem = mnem.to_str().unwrap();
        let body = body.to_str().unwrap();

        self.internal.dump(address, mnem, body);
    }

    pub fn new(internal: Box<dyn AsmCollector>) -> Self {
        Self { internal }
    }

    pub fn reset(&mut self) {
        self.internal.reset();
    }

    pub fn cast<T: AsmCollector + 'static>(&self) -> &T {
        self.internal.as_any().downcast_ref::<T>().unwrap()
    }
}

#[derive(Debug)]
pub struct DefaultAsmCollector {
    asms: Vec<Instruction>,
}

impl DefaultAsmCollector {
    pub fn new() -> Self {
        Self {
            asms: vec![]
        }
    }

    pub fn get_content(&self) -> &Vec<Instruction> {
        &self.asms
    }
}

impl AsmCollector for DefaultAsmCollector {
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

    fn reset(&mut self) {
        self.asms.clear();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
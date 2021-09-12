use cxx::CxxString;
use crate::internal::ffi::ffi::AddressProxy;
use crate::pcode::{Instruction, Address};

pub trait AsmCollector {
    fn dump(&mut self, addr: &AddressProxy, mnem: &str, body: &str);
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
}

#[derive(Debug)]
pub struct DefaultAsmCollector {
    pub asms: Vec<Instruction>,
}

impl DefaultAsmCollector {
    pub fn new() -> Self {
        Self {
            asms: vec![]
        }
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
}
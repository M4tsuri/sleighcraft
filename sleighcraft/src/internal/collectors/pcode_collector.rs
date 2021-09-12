use crate::internal::ffi::ffi::VarnodeDataProxy;
use crate::internal::ffi::ffi::AddressProxy;
use crate::internal::ffi::pcode::ffi::PcodeOpCode;
use crate::pcode::Address;
use std::pin::Pin;
use std::any::Any;

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

pub trait PcodeCollector {
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

    fn reset(&mut self) {}

    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug)]
pub struct DefaultPcodeCollector {
    pcode_asms: Vec<PcodeInstruction>,
}

impl DefaultPcodeCollector {
    pub fn new() -> Self {
        Self {
            pcode_asms: vec![]
        }
    }

    pub fn get_content(&self) -> &Vec<PcodeInstruction> {
        &self.pcode_asms
    }
}

impl PcodeCollector for DefaultPcodeCollector {
    fn as_any(&self) -> &dyn Any {
        self
    }

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

    fn reset(&mut self) {
        self.pcode_asms.clear();
    }
}

pub struct PcodeCollectorWrapper {
    pub internal: Box<dyn PcodeCollector>,
}

impl PcodeCollectorWrapper {
    pub fn new(internal: Box<dyn PcodeCollector>) -> Self {
        Self { internal }
    }

    pub fn reset(&mut self) {
        self.internal.reset();
    }

    pub fn cast<T: PcodeCollector + 'static>(&self) -> &T {
        self.internal.as_any().downcast_ref::<T>().unwrap()
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
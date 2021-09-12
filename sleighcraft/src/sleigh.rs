use crate::{config::Mode, internal::{collectors::{asm_collector::AsmCollector, pcode_collector::{PcodeCollector, PcodeInstruction}}, loaders::Loader, sleigh::{Sleigh, SleighBuilder}}, pcode::Instruction};
use crate::internal::loaders::plain::PlainLoader;
use crate::internal::collectors::{asm_collector::DefaultAsmCollector, pcode_collector::DefaultPcodeCollector};
use crate::config::PRESET;
use crate::internal::error::{Error, Result};

#[allow(dead_code)]
pub struct Rs {
    sleigh: Sleigh,
}

#[allow(dead_code)]
impl Rs {
    pub fn new(arch_str: &str, mode: Mode) -> Self {
        let spec = Self::arch(arch_str).unwrap();
        let loader = PlainLoader::new();
        let asm_collector = DefaultAsmCollector::new();
        let pcode_collector = DefaultPcodeCollector::new();
        let sleigh_builder = SleighBuilder::new();

        Self {
            sleigh: sleigh_builder
                .set_spec(spec)
                .set_mode(mode)
                .set_loader(loader)
                .set_pcode_collector(pcode_collector)
                .set_asm_collector(asm_collector)
                .try_build().unwrap()
        }
    } 

    fn get_loader<T: Loader + 'static>(&mut self) -> &mut T {
        let loader_wrapper = self.sleigh.get_loader();
        loader_wrapper.cast::<T>()
    }
    
    fn get_pcode_collector<T: PcodeCollector + 'static>(&self) -> &T {
        let collector = self.sleigh.get_pcode_collector();
        collector.cast::<T>()
    }

    fn get_asm_collector<T: AsmCollector + 'static>(&self) -> &T {
        let collector = self.sleigh.get_asm_collector();
        collector.cast::<T>()
    }

    pub fn disasm(&mut self, buf: &[u8]) -> Result<(&Vec<Instruction>, &Vec<PcodeInstruction>)> {
        // load given buf to internal loader
        let loader = self.get_loader::<PlainLoader>();
        loader.load(buf);

        // reset the assembly collectors
        self.sleigh.reset_collectors();

        // decode all mechine code in the buffer
        self.sleigh.decode(0)?;

        let pcode_collector = self.get_pcode_collector::<DefaultPcodeCollector>();
        let asm_collector = self.get_asm_collector::<DefaultAsmCollector>();

        Ok((asm_collector.get_content(), pcode_collector.get_content()))  
    }

    fn arch(name: &str) -> Result<String> {
        let content = *PRESET
            .get(&name.to_lowercase().as_str())
            .ok_or(Error::ArchNotFound(name.to_string()))?;
        Ok(content.into())
    }
}

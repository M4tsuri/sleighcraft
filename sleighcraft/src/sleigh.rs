use std::sync::{Arc, Mutex};

use crate::{config::Mode, internal::{collectors::{asm_collector::AsmCollector, pcode_collector::PcodeCollector}, loaders::Loader, sleigh::{Sleigh, SleighBuilder}}};
use crate::internal::loaders::plain::PlainLoader;
use crate::internal::collectors::{asm_collector::DefaultAsmCollector, pcode_collector::DefaultPcodeCollector};
use crate::config::PRESET;
use crate::internal::error::{Error, Result};
use lazy_static::lazy_static;

lazy_static! {
    static ref DEFAULT_BUILDER: Mutex<SleighBuilder<PlainLoader, DefaultAsmCollector, DefaultPcodeCollector>> = Mutex::new(SleighBuilder::new());
}

struct Rs {
    sleigh: Sleigh,
}

impl Rs {
    fn new(arch_str: &str, mode: Mode) -> Self {
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

    fn arch(name: &str) -> Result<String> {
        let content = *PRESET
            .get(&name.to_lowercase().as_str())
            .ok_or(Error::ArchNotFound(name.to_string()))?;
        Ok(content.into())
    }
}

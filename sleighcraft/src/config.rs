use once_cell::sync::Lazy;
use std::collections::HashMap;

pub(crate) const PRESET: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| load_preset());

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



fn load_preset() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    macro_rules! def_arch {
        ($name: expr) => {
            // presets are used across the whole lifetime, it's safe to ignore
            // the lifetime by leaking its names' memory
            let name: &'static str = Box::leak($name.to_lowercase().into_boxed_str());
            map.insert(name, include_str!(concat!("resources/sla/", $name, ".sla")));
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
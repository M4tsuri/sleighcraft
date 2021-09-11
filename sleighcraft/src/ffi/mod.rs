
pub mod pcode;
use crate::sleigh::{RustAssemblyEmit, RustPcodeEmit, Instruction};
use crate::loaders::{RustLoaderWrapper};

type RustLoadImage<'a> = RustLoaderWrapper<'a>;
#[allow(dead_code)]
#[cxx::bridge]
pub(crate) mod ffi {
    extern "Rust" {
        type RustAssemblyEmit<'a>;
        fn dump(
            self: &mut RustAssemblyEmit,
            address: &AddressProxy,
            mnem: &CxxString,
            body: &CxxString,
        );
        type RustPcodeEmit<'a>;
        fn dump(
            self: &mut RustPcodeEmit,
            address: &AddressProxy,
            opcode: PcodeOpCode,
            outvar: Pin<&mut VarnodeDataProxy>,
            vars: &CxxVector<VarnodeDataProxy>,
        );
        type RustLoadImage<'a>;
        fn load_fill(self: &mut RustLoadImage, ptr: &mut [u8], addr: &AddressProxy);
        //fn get_arch_type(self: &RustLoadImage) -> String;
        fn adjust_vma(self: &mut RustLoadImage, adjust: isize);
        fn buf_size(self: &mut RustLoadImage) -> usize;

        type Instruction;
        fn set_addr(self: &mut Instruction, space: String, offset: u64);
        fn set_mnemonic(self: &mut Instruction, mnem: String);
        fn set_body(self: &mut Instruction, body: String);

    }

    unsafe extern "C++" {
        type PcodeOpCode = crate::ffi::pcode::ffi::PcodeOpCode;
        type SpaceType = crate::ffi::pcode::ffi::SpaceType;

        include!("bridge/disasm.h");
        include!("bridge/proxies.h");

        type OpBehaviorProxy;
        type CoverProxy;
        type TypeOpProxy;
        fn get_name(self: &TypeOpProxy) -> &CxxString;
        fn get_opcode(self: &TypeOpProxy) -> PcodeOpCode;
        fn get_flags(self: &TypeOpProxy) -> u32;
        fn get_behavior(self: &TypeOpProxy) -> UniquePtr<OpBehaviorProxy>;
        fn evaluate_unary(self: &TypeOpProxy, sizeout: i32, sizein: i32, in1: usize) -> usize;
        fn evaluate_binary(
            self: &TypeOpProxy,
            sizeout: i32,
            sizein: i32,
            in1: usize,
            in2: usize,
        ) -> usize;
        fn recover_input_binary(
            self: &TypeOpProxy,
            slot: i32,
            sizeout: i32,
            sout: usize,
            sizein: i32,
            sin: usize,
        ) -> usize;
        fn recover_input_unary(self: &TypeOpProxy, sizeout: i32, out: usize, sizein: i32) -> usize;
        fn is_commutative(self: &TypeOpProxy) -> bool;
        fn inherits_sign(self: &TypeOpProxy) -> bool;

        type OpCodeProxy;

        fn count(self: &OpCodeProxy) -> i32;
        fn get_out(self: &OpCodeProxy) -> UniquePtr<VarnodeProxy>;
        fn get_in(self: &OpCodeProxy, slot: i32) -> UniquePtr<VarnodeProxy>;
        fn get_time(self: &OpCodeProxy) -> u32;
        fn get_eval_type(self: &OpCodeProxy) -> u32;
        fn get_halt_type(self: &OpCodeProxy) -> u32;
        fn is_dead(self: &OpCodeProxy) -> bool;
        fn is_assignment(self: &OpCodeProxy) -> bool;
        fn is_call(self: &OpCodeProxy) -> bool;
        fn is_call_without_spec(self: &OpCodeProxy) -> bool;
        fn is_marker(self: &OpCodeProxy) -> bool;
        fn is_indirect_creation(self: &OpCodeProxy) -> bool;
        fn is_indirect_store(self: &OpCodeProxy) -> bool;
        fn not_printed(self: &OpCodeProxy) -> bool;
        fn is_bool_output(self: &OpCodeProxy) -> bool;
        fn is_branch(self: &OpCodeProxy) -> bool;
        fn is_call_or_branch(self: &OpCodeProxy) -> bool;
        fn is_flow_break(self: &OpCodeProxy) -> bool;
        fn is_boolean_flip(self: &OpCodeProxy) -> bool;
        fn is_fallthru_true(self: &OpCodeProxy) -> bool;
        fn is_code_ref(self: &OpCodeProxy) -> bool;
        fn is_instruction_start(self: &OpCodeProxy) -> bool;
        fn is_block_start(self: &OpCodeProxy) -> bool;
        fn is_modified(self: &OpCodeProxy) -> bool;
        fn is_mark(self: &OpCodeProxy) -> bool;
        fn set_mark(self: &OpCodeProxy);
        fn is_warning(self: &OpCodeProxy) -> bool;
        fn clear_mark(self: &OpCodeProxy);
        fn is_indirect_source(self: &OpCodeProxy) -> bool;
        fn set_indirect_source(self: &OpCodeProxy);
        fn clear_indirect_source(self: &OpCodeProxy);
        fn is_ptr_flow(self: &OpCodeProxy) -> bool;
        fn set_ptr_flow(self: &OpCodeProxy);
        fn is_splitting(self: &OpCodeProxy) -> bool;
        fn does_special_propagation(self: &OpCodeProxy) -> bool;
        fn does_special_printing(self: &OpCodeProxy) -> bool;
        fn is_incidental_copy(self: &OpCodeProxy) -> bool;
        fn is_calculated_bool(self: &OpCodeProxy) -> bool;
        fn is_cpool_transformed(self: &OpCodeProxy) -> bool;
        fn uses_spacebase_ptr(self: &OpCodeProxy) -> bool;
        fn get_cse_hash(self: &OpCodeProxy) -> u32;
        fn get_opcode(self: &OpCodeProxy) -> UniquePtr<TypeOpProxy>;
        fn get_code(self: &OpCodeProxy) -> PcodeOpCode;
        fn is_commutative(self: &OpCodeProxy) -> bool;
        fn next_op(self: &OpCodeProxy) -> UniquePtr<CoverProxy>;
        fn previous_op(self: &OpCodeProxy) -> UniquePtr<CoverProxy>;
        fn get_start_op(self: &OpCodeProxy) -> UniquePtr<CoverProxy>;

        type VariableProxy;
        type VarnodeProxy;
        fn set_high(self: &VarnodeProxy, tv: &VariableProxy, mg: i16);
        fn get_addr(self: &VarnodeProxy) -> UniquePtr<AddressProxy>;
        fn get_space(self: &VarnodeProxy) -> UniquePtr<AddrSpaceProxy>;
        fn get_offset(self: &VarnodeProxy) -> usize;
        fn get_size(self: &VarnodeProxy) -> i32;
        fn get_merge_group(self: &VarnodeProxy) -> i16;
        fn get_def(self: &VarnodeProxy) -> UniquePtr<CoverProxy>;
        fn get_high(self: &VarnodeProxy) -> UniquePtr<VariableProxy>;
        fn equals(self: &VarnodeProxy, op2: &VarnodeProxy) -> bool;
        fn not_equal(self: &VarnodeProxy, op2: &VarnodeProxy) -> bool;
        fn less_than(self: &VarnodeProxy, op2: &VarnodeProxy) -> bool;

        type VarnodeDataProxy;

        fn get_addr(self: &VarnodeDataProxy) -> UniquePtr<AddressProxy>;
        fn is_contains(self: &VarnodeDataProxy, op2: &VarnodeDataProxy) -> bool;
        fn get_offset(self: &VarnodeDataProxy) -> usize;
        fn get_size(self: &VarnodeDataProxy) -> u32;
        fn get_space(self: &VarnodeDataProxy) -> UniquePtr<AddrSpaceProxy>;
        fn not_null(self: &VarnodeDataProxy) -> bool;

        type AddrSpaceProxy;
        fn get_name(self: &AddrSpaceProxy) -> &CxxString;
        fn get_type(self: &AddrSpaceProxy) -> SpaceType;
        fn get_delay(self: &AddrSpaceProxy) -> i32;
        fn get_deadcode_delay(self: &AddrSpaceProxy) -> i32;
        fn get_index(self: &AddrSpaceProxy) -> i32;
        fn get_wordsize(self: &AddrSpaceProxy) -> u32;
        fn get_addrsize(self: &AddrSpaceProxy) -> u32;
        fn get_highest(self: &AddrSpaceProxy) -> usize;
        fn get_pointer_lower_bound(self: &AddrSpaceProxy) -> usize;
        fn get_pointer_upper_bound(self: &AddrSpaceProxy) -> usize;
        fn get_minimum_ptr_size(self: &AddrSpaceProxy) -> i32;
        fn wrap_offset(self: &AddrSpaceProxy, off: usize) -> usize;
        fn get_shortcut(self: &AddrSpaceProxy) -> i8;
        fn is_heritaged(self: &AddrSpaceProxy) -> bool;
        fn does_deadcode(self: &AddrSpaceProxy) -> bool;
        fn has_physical(self: &AddrSpaceProxy) -> bool;
        fn is_big_endian(self: &AddrSpaceProxy) -> bool;
        fn is_reverse_justified(self: &AddrSpaceProxy) -> bool;
        fn is_overlay(self: &AddrSpaceProxy) -> bool;
        fn is_overlay_base(self: &AddrSpaceProxy) -> bool;
        fn is_other_space(self: &AddrSpaceProxy) -> bool;
        fn is_truncated(self: &AddrSpaceProxy) -> bool;
        fn has_near_pointers(self: &AddrSpaceProxy) -> bool;
        // fn print_offset(self: &AddrSpaceProxy ,s: buffer, offset: usize);
        fn num_spacebase(self: &AddrSpaceProxy) -> i32;
        // fn get_spacebase(self: &AddrSpaceProxy, i: i32) -> UniquePtr<VarnodeDataProxy>;
        // fn get_spacebase_full(self: &AddrSpaceProxy, i: i32) -> UniquePtr<VarnodeDataProxy>;

        type AddressProxy;
        fn is_invalid(self: &AddressProxy) -> bool;
        fn get_addr_size(self: &AddressProxy) -> i32;
        fn is_big_endian(self: &AddressProxy) -> bool;
        fn get_space(self: &AddressProxy) -> UniquePtr<AddrSpaceProxy>;
        fn get_offset(self: &AddressProxy) -> usize;
        fn to_physical(self: Pin<&mut AddressProxy>);
        fn get_shortcut(self: &AddressProxy) -> i8;
        fn equals(self: &AddressProxy, op2: &AddressProxy) -> bool;
        fn not_equal(self: &AddressProxy, op2: &AddressProxy) -> bool;
        fn less_than(self: &AddressProxy, op2: &AddressProxy) -> bool;
        fn less_equal(self: &AddressProxy, op2: &AddressProxy) -> bool;
        fn add(self: &AddressProxy, off: i32) -> UniquePtr<AddressProxy>;
        fn sub(self: &AddressProxy, off: i32) -> UniquePtr<AddressProxy>;
        fn contained_by(self: &AddressProxy, size: i32, op2: &AddressProxy, size2: i32) -> bool;
        fn justified_contain(
            self: &AddressProxy,
            size: i32,
            op2: &AddressProxy,
            size2: i32,
            forceleft: bool,
        ) -> i32;
        fn overlap(self: &AddressProxy, skip: i32, op: &AddressProxy, size: i32) -> i32;
        fn is_contiguous(self: &AddressProxy, size: i32, loaddr: &AddressProxy, losz: i32) -> bool;
        fn is_constant(self: &AddressProxy) -> bool;
        fn renormalize(self: Pin<&mut AddressProxy>, size: i32);
        fn is_join(self: &AddressProxy) -> bool;
        fn addr_get_space_from_const(addr: &AddressProxy) -> UniquePtr<AddrSpaceProxy>;

        type RustLoadImageProxy;

        fn from_rust(load_iamge: &mut RustLoadImage) -> UniquePtr<RustLoadImageProxy>;

        // type InstructionProxy;
        //
        // fn get_space(self: &InstructionProxy) -> &CxxString;
        // fn get_offset(self: &InstructionProxy) -> u64;
        // fn get_mnemonic(self: &InstructionProxy) -> &CxxString;
        // fn get_body(self: &InstructionProxy) -> &CxxString;

        pub(crate) type SleighProxy;
        fn set_spec(self: Pin<&mut SleighProxy>, spec_content: &str, mode: i32);
        fn new_sleigh_proxy(ld: &mut RustLoadImage) -> UniquePtr<SleighProxy>;
        fn decode_with(
            self: Pin<&mut SleighProxy>,
            asm_emit: &mut RustAssemblyEmit,
            pcode_emit: &mut RustPcodeEmit,
            start: u64,
        ) -> Result<()>;
    }
}
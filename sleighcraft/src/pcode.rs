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

/// a pcode op, same with which in ghidra
pub type PcodeOp = crate::internal::ffi::pcode::ffi::PcodeOpCode;

impl AsRef<str> for PcodeOp {
    fn as_ref(&self) -> &str {
        match *self {
            PcodeOp::COPY => "COPY",
            PcodeOp::LOAD => "LOAD",
            PcodeOp::STORE => "STORE",
            PcodeOp::BRANCH => "BRANCH",
            PcodeOp::CBRANCH => "CBRANCH",
            PcodeOp::BRANCHIND => "BRANCHIND",
            PcodeOp::CALL => "CALL",
            PcodeOp::CALLIND => "CALLIND",
            PcodeOp::CALLOTHER => "CALLOTHER",
            PcodeOp::RETURN => "RETURN",
            PcodeOp::INT_EQUAL => "INT_EQUAL",
            PcodeOp::INT_NOTEQUAL => "INT_NOTEQUAL",
            PcodeOp::INT_SLESS => "INT_SLESS",
            PcodeOp::INT_SLESSEQUAL => "INT_SLESSEQUAL",
            PcodeOp::INT_LESS => "INT_LESS",
            PcodeOp::INT_LESSEQUAL => "INT_LESSEQUAL",
            PcodeOp::INT_ZEXT => "INT_ZEXT",
            PcodeOp::INT_SEXT => "INT_SEXT",
            PcodeOp::INT_ADD => "INT_ADD",
            PcodeOp::INT_SUB => "INT_SUB",
            PcodeOp::INT_CARRY => "INT_CARRY",
            PcodeOp::INT_SCARRY => "INT_SCARRY",
            PcodeOp::INT_SBORROW => "INT_SBORROW",
            PcodeOp::INT_2COMP => "INT_2COMP",
            PcodeOp::INT_NEGATE => "INT_NEGATE",
            PcodeOp::INT_XOR => "INT_XOR",
            PcodeOp::INT_AND => "INT_AND",
            PcodeOp::INT_OR => "INT_OR",
            PcodeOp::INT_LEFT => "INT_LEFT",
            PcodeOp::INT_RIGHT => "INT_RIGHT",
            PcodeOp::INT_SRIGHT => "INT_SRIGHT",
            PcodeOp::INT_MULT => "INT_MULT",
            PcodeOp::INT_DIV => "INT_DIV",
            PcodeOp::INT_SDIV => "INT_SDIV",
            PcodeOp::INT_REM => "INT_REM",
            PcodeOp::INT_SREM => "INT_SREM",
            PcodeOp::BOOL_NEGATE => "BOOL_NEGATE",
            PcodeOp::BOOL_XOR => "BOOL_XOR",
            PcodeOp::BOOL_AND => "BOOL_AND",
            PcodeOp::BOOL_OR => "BOOL_OR",
            PcodeOp::FLOAT_EQUAL => "FLOAT_EQUAL",
            PcodeOp::FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            PcodeOp::FLOAT_LESS => "FLOAT_LESS",
            PcodeOp::FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            PcodeOp::FLOAT_NAN => "FLOAT_NAN",
            PcodeOp::FLOAT_ADD => "FLOAT_ADD",
            PcodeOp::FLOAT_DIV => "FLOAT_DIV",
            PcodeOp::FLOAT_MULT => "FLOAT_MULT",
            PcodeOp::FLOAT_SUB => "FLOAT_SUB",
            PcodeOp::FLOAT_NEG => "FLOAT_NEG",
            PcodeOp::FLOAT_ABS => "FLOAT_ABS",
            PcodeOp::FLOAT_SQRT => "FLOAT_SQRT",
            PcodeOp::FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
            PcodeOp::FLOAT_FLOAT2FLOAT => "FLOAT_FLOAT2FLOAT",
            PcodeOp::FLOAT_TRUNC => "FLOAT_TRUNC",
            PcodeOp::FLOAT_CEIL => "FLOAT_CEIL",
            PcodeOp::FLOAT_FLOOR => "FLOAT_FLOOR",
            PcodeOp::FLOAT_ROUND => "FLOAT_ROUND",
            PcodeOp::MULTIEQUAL => "MULTIEQUAL",
            PcodeOp::INDIRECT => "INDIRECT",
            PcodeOp::PIECE => "PIECE",
            PcodeOp::SUBPIECE => "SUBPIECE",
            PcodeOp::CAST => "CAST",
            PcodeOp::PTRADD => "PTRADD",
            PcodeOp::PTRSUB => "PTRSUB",
            PcodeOp::SEGMENTOP => "SEGMENTOP",
            PcodeOp::CPOOLREF => "CPOOLREF",
            PcodeOp::NEW => "NEW",
            PcodeOp::INSERT => "INSERT",
            PcodeOp::EXTRACT => "EXTRACT",
            PcodeOp::POPCOUNT => "POPCOUNT",
            PcodeOp::MAX => "MAX",
            _ => unreachable!(),
        }
    }   
}
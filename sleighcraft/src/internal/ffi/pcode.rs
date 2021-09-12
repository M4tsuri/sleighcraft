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

//! Definition of pcode.
//! You can find documentation of ghidra pcode [here](https://ghidra.re/courses/languages/html/pcoderef.html)
//! There are three important concepts when describing a pcode: PcodeOp, Varnode, AddressSpace.
//! All of them are defined in this file.

use cxx;

#[cxx::bridge]
pub(crate) mod ffi {
    pub enum SpaceType {
        Constant = 0,
        Processor = 1,
        SpaceBase = 2,
        Internal = 3,
        Fspec = 4,
        Iop = 5,
        Join = 6,
    }

    #[derive(Debug)]
    pub enum PcodeOpCode {
        COPY = 1,
        ///< Copy one operand to another
        LOAD = 2,
        ///< Load from a pointer into a specified address space
        STORE = 3,
        ///< Store at a pointer into a specified address space
        BRANCH = 4,
        ///< Always branch
        CBRANCH = 5,
        ///< Conditional branch
        BRANCHIND = 6,
        ///< Indirect branch (jumptable)
        CALL = 7,
        ///< Call to an absolute address
        CALLIND = 8,
        ///< Call through an indirect address
        CALLOTHER = 9,
        ///< User-defined operation
        RETURN = 10,
        ///< Return from subroutine
        // Integer/bit operations
        INT_EQUAL = 11,
        ///< Integer comparison, equality (==)
        INT_NOTEQUAL = 12,
        ///< Integer comparison, in-equality (!=)
        INT_SLESS = 13,
        ///< Integer comparison, signed less-than (<)
        INT_SLESSEQUAL = 14,
        ///< Integer comparison, signed less-than-or-equal (<=)
        INT_LESS = 15,
        ///< Integer comparison, unsigned less-than (<)
        // This also indicates a borrow on unsigned substraction
        INT_LESSEQUAL = 16,
        ///< Integer comparison, unsigned less-than-or-equal (<=)
        INT_ZEXT = 17,
        ///< Zero extension
        INT_SEXT = 18,
        ///< Sign extension
        INT_ADD = 19,
        ///< Addition, signed or unsigned (+)
        INT_SUB = 20,
        ///< Subtraction, signed or unsigned (-)
        INT_CARRY = 21,
        ///< Test for unsigned carry
        INT_SCARRY = 22,
        ///< Test for signed carry
        INT_SBORROW = 23,
        ///< Test for signed borrow
        INT_2COMP = 24,
        ///< Twos complement
        INT_NEGATE = 25,
        ///< Logical/bitwise negation (~)
        INT_XOR = 26,
        ///< Logical/bitwise exclusive-or (^)
        INT_AND = 27,
        ///< Logical/bitwise and (&)
        INT_OR = 28,
        ///< Logical/bitwise or (|)
        INT_LEFT = 29,
        ///< Left shift (<<)
        INT_RIGHT = 30,
        ///< Right shift, logical (>>)
        INT_SRIGHT = 31,
        ///< Right shift, arithmetic (>>)
        INT_MULT = 32,
        ///< Integer multiplication, signed and unsigned (*)
        INT_DIV = 33,
        ///< Integer division, unsigned (/)
        INT_SDIV = 34,
        ///< Integer division, signed (/)
        INT_REM = 35,
        ///< Remainder/modulo, unsigned (%)
        INT_SREM = 36,
        ///< Remainder/modulo, signed (%)
        BOOL_NEGATE = 37,
        ///< Boolean negate (!)
        BOOL_XOR = 38,
        ///< Boolean exclusive-or (^^)
        BOOL_AND = 39,
        ///< Boolean and (&&)
        BOOL_OR = 40,
        ///< Boolean or (||)
        // Floating point operations
        FLOAT_EQUAL = 41,
        ///< Floating-point comparison, equality (==)
        FLOAT_NOTEQUAL = 42,
        ///< Floating-point comparison, in-equality (!=)
        FLOAT_LESS = 43,
        ///< Floating-point comparison, less-than (<)
        FLOAT_LESSEQUAL = 44,
        ///< Floating-point comparison, less-than-or-equal (<=)
        // Slot 45 is currently unused
        FLOAT_NAN = 46,
        ///< Not-a-number test (NaN)
        FLOAT_ADD = 47,
        ///< Floating-point addition (+)
        FLOAT_DIV = 48,
        ///< Floating-point division (/)
        FLOAT_MULT = 49,
        ///< Floating-point multiplication (*)
        FLOAT_SUB = 50,
        ///< Floating-point subtraction (-)
        FLOAT_NEG = 51,
        ///< Floating-point negation (-)
        FLOAT_ABS = 52,
        ///< Floating-point absolute value (abs)
        FLOAT_SQRT = 53,
        ///< Floating-point square root (sqrt)
        FLOAT_INT2FLOAT = 54,
        ///< Convert an integer to a floating-point
        FLOAT_FLOAT2FLOAT = 55,
        ///< Convert between different floating-point sizes
        FLOAT_TRUNC = 56,
        ///< Round towards zero
        FLOAT_CEIL = 57,
        ///< Round towards +infinity
        FLOAT_FLOOR = 58,
        ///< Round towards -infinity
        FLOAT_ROUND = 59,
        ///< Round towards nearest
        // Internal opcodes for simplification. Not
        // typically generated in a direct translation.
        // Data-flow operations
        MULTIEQUAL = 60,
        ///< Phi-node operator
        INDIRECT = 61,
        ///< Copy with an indirect effect
        PIECE = 62,
        ///< Concatenate
        SUBPIECE = 63,
        ///< Truncate
        CAST = 64,
        ///< Cast from one data-type to another
        PTRADD = 65,
        ///< Index into an array ([])
        PTRSUB = 66,
        ///< Drill down to a sub-field  (->)
        SEGMENTOP = 67,
        ///< Look-up a \e segmented address
        CPOOLREF = 68,
        ///< Recover a value from the \e constant \e pool
        NEW = 69,
        ///< Allocate a new object (new)
        INSERT = 70,
        ///< Insert a bit-range
        EXTRACT = 71,
        ///< Extract a bit-range
        POPCOUNT = 72,
        ///< Count the 1-bits
        MAX = 73,
    }
}
// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::common::*;
use crate::tpi::data::TypeData;

// References for primitive types:
//
// cvinfo.h provides an enumeration:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L328-L750
//
// pdbparse.cpp describes them as strings:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/pdbdump/pdbdump.cpp#L1896-L1974
//
// The most obscure: MSDN Library October 2001 Disk 2 contains a \MSDN\specs.chm file which contains
// html\S66CD.HTM which actually documents the *format* of the primitive type descriptors rather
// than just listing them. TypeData::Primitive is designed to model the orthogonal information
// encoded into the bits of the TypeIndex rather than exploding the matrix like the reference
// implementations.

/// Represents a primitive type like `void` or `char *`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrimitiveType {
    /// The kind of the primitive type.
    pub kind: PrimitiveKind,

    /// Pointer indirection applied to the primitive type.
    pub indirection: Option<Indirection>,
}

/// A simple type.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrimitiveKind {
    /// Uncharacterized type (no type)
    NoType,

    /// Void type
    Void,

    /// Character (byte)
    Char,

    /// Unsigned character
    UChar,

    /// "Really a char"
    RChar,

    /// Wide characters, i.e. 16 bits
    WChar,

    /// "Really a 16-bit char"
    RChar16,

    /// "Really a 32-bit char"
    RChar32,

    /// Signed 8-bit integer
    I8,

    /// Unsigned 8-bit integer
    U8,

    /// Signed 16-bit integer
    Short,

    /// Unsigned 16-bit integer
    UShort,

    /// Signed 16-bit integer
    I16,

    /// Unsigned 16-bit integer
    U16,

    /// Signed 32-bit integer
    Long,

    /// Unsigned 32-bit inteer
    ULong,

    /// Signed 32-bit integer
    I32,

    /// Unsigned 32-bit inteer
    U32,

    /// Signed 64-bit integer
    Quad,

    /// Unsigned 64-bit integer
    UQuad,

    /// Signed 64-bit integer
    I64,

    /// Unsigned 64-bit integer
    U64,

    /// Signed 128-bit integer
    Octa,

    /// Unsigned 128-bit integer
    UOcta,

    /// Signed 128-bit integer
    I128,

    /// Unsigned 128-bit integer
    U128,

    /// 16-bit floating point
    F16,

    /// 32-bit floating point
    F32,

    /// 32-bit partial precision floating point
    F32PP,

    /// 48-bit floating point
    F48,

    /// 64-bit floating point
    F64,

    /// 80-bit floating point
    F80,

    /// 128-bit floating point
    F128,

    /// 32-bit complex number
    Complex32,

    /// 64-bit complex number
    Complex64,

    /// 80-bit complex number
    Complex80,

    /// 128-bit complex number
    Complex128,

    /// 8-bit boolean value
    Bool8,

    /// 16-bit boolean value
    Bool16,

    /// 32-bit boolean value
    Bool32,

    /// 16-bit boolean value
    Bool64,

    /// Windows `HRESULT` error code.
    ///
    /// See: <https://docs.microsoft.com/en-us/windows/desktop/seccrypto/common-hresult-values>
    HRESULT,
}

/// Pointer mode of primitive types.
///
/// This is partially overlapping with [`PointerKind`](crate::PointerKind) for regular pointer type
/// definitions. While `PointerKind` can specify many more pointer types, including relative
/// pointers, `Indirection` also contains a 128-bit variant.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Indirection {
    /// 16-bit ("near") pointer.
    Near16,
    /// 16:16 far pointer.
    Far16,
    /// 16:16 huge pointer.
    Huge16,
    /// 32-bit pointer.
    Near32,
    /// 48-bit 16:32 pointer.
    Far32,
    /// 64-bit near pointer.
    Near64,
    /// 128-bit near pointer.
    Near128,
}

pub fn type_data_for_primitive(index: TypeIndex) -> Result<TypeData<'static>> {
    // https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L326-L750

    // primitives live under 0x1000, and we should never reach here for non-primitive indexes
    assert!(index < TypeIndex(0x1000));

    // indirection is stored in these bits
    let indirection = match index.0 & 0xf00 {
        0x000 => None,
        0x100 => Some(Indirection::Near16),
        0x200 => Some(Indirection::Far16),
        0x300 => Some(Indirection::Huge16),
        0x400 => Some(Indirection::Near32),
        0x500 => Some(Indirection::Far32),
        0x600 => Some(Indirection::Near64),
        0x700 => Some(Indirection::Near128),
        _ => {
            return Err(Error::TypeNotFound(index.0));
        }
    };

    // primitive types are stored in the lowest octet
    let kind = match index.0 & 0xff {
        0x00 => PrimitiveKind::NoType,

        0x03 => PrimitiveKind::Void,
        0x08 => PrimitiveKind::HRESULT,

        0x10 => PrimitiveKind::Char,
        0x20 => PrimitiveKind::UChar,
        0x68 => PrimitiveKind::I8,
        0x69 => PrimitiveKind::U8,

        0x70 => PrimitiveKind::RChar,
        0x71 => PrimitiveKind::WChar,
        0x7a => PrimitiveKind::RChar16,
        0x7b => PrimitiveKind::RChar32,

        0x11 => PrimitiveKind::Short,
        0x21 => PrimitiveKind::UShort,
        0x72 => PrimitiveKind::I16,
        0x73 => PrimitiveKind::U16,

        0x12 => PrimitiveKind::Long,
        0x22 => PrimitiveKind::ULong,
        0x74 => PrimitiveKind::I32,
        0x75 => PrimitiveKind::U32,

        0x13 => PrimitiveKind::Quad,
        0x23 => PrimitiveKind::UQuad,
        0x76 => PrimitiveKind::I64,
        0x77 => PrimitiveKind::U64,

        0x14 => PrimitiveKind::Octa,
        0x24 => PrimitiveKind::UOcta,
        0x78 => PrimitiveKind::I128,
        0x79 => PrimitiveKind::U128,

        0x46 => PrimitiveKind::F16,
        0x40 => PrimitiveKind::F32,
        0x45 => PrimitiveKind::F32PP,
        0x44 => PrimitiveKind::F48,
        0x41 => PrimitiveKind::F64,
        0x42 => PrimitiveKind::F80,
        0x43 => PrimitiveKind::F128,

        0x50 => PrimitiveKind::Complex32,
        0x51 => PrimitiveKind::Complex64,
        0x52 => PrimitiveKind::Complex80,
        0x53 => PrimitiveKind::Complex128,

        0x30 => PrimitiveKind::Bool8,
        0x31 => PrimitiveKind::Bool16,
        0x32 => PrimitiveKind::Bool32,
        0x33 => PrimitiveKind::Bool64,

        _ => {
            return Err(Error::TypeNotFound(index.0));
        }
    };

    Ok(TypeData::Primitive(PrimitiveType { kind, indirection }))
}

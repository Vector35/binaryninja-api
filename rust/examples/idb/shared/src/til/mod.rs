/// The u8 values used to describes the type information records in IDA.
///
/// The recommended way of using type info is to use the [tinfo_t] class.
/// The type information is internally kept as an array of bytes terminated by 0.
///
/// Items in brackets [] are optional and sometimes are omitted.
/// ::type_t... means a sequence of ::type_t bytes which defines a type.
///
/// NOTE: to work with the types of instructions or data in the database,
/// use `get_tinfo()`/`set_tinfo()` and similar functions.
#[allow(unused)]
mod flag;

use std::io::{BufRead, BufReader, Read};
use std::num::NonZeroU8;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{read_c_string, read_c_string_vec, read_string_len_u8, IDBSectionCompression};

// TODO migrate this to flags
const TIL_SECTION_MAGIC: &[u8; 6] = b"IDATIL";

#[derive(Debug, Clone)]
pub struct TILSection {
    pub format: u32,
    pub flags: TILSectionFlag,
    pub title: String,
    pub base: String,
    pub id: u8,
    pub cm: u8,
    pub def_align: u8,
    pub symbols: Vec<TILTypeInfo>,
    pub type_ordinal_numbers: Option<u32>,
    pub types: Vec<TILTypeInfo>,
}

#[derive(Debug, Clone)]
pub(crate) struct TILSectionHeader {
    format: u32,
    flags: TILSectionFlag,
    title: String,
    base: String,
    id: u8,
    cm: u8,
    _size_i: u8,
    _size_b: u8,
    size_e: u8,
    def_align: u8,
    _size_s_l_ll: Option<(u8, u8, u8)>,
    _size_ldbl: Option<u8>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
struct TILSectionHeader1 {
    signature: [u8; 6],
    format: u32,
    flags: TILSectionFlag,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
struct TILSectionHeader2 {
    id: u8,
    cm: u8,
    size_i: u8,
    size_b: u8,
    size_e: u8,
    def_align: u8,
}

impl TILSection {
    pub fn parse<I: BufRead>(mut input: I) -> Result<Self> {
        Self::read_inner(&mut input)
    }

    pub(crate) fn read<I: BufRead>(input: &mut I, compress: IDBSectionCompression) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input),
            IDBSectionCompression::Zlib => {
                let mut input = BufReader::new(flate2::read::ZlibDecoder::new(input));
                Self::read_inner(&mut input)
            }
        }
    }

    fn read_inner<I: BufRead>(input: &mut I) -> Result<Self> {
        let header = Self::read_header(&mut *input)?;
        let symbols = if header.flags.is_zip() {
            Self::read_bucket_zip(&mut *input, &header)?
        } else {
            Self::read_bucket_normal(&mut *input, &header)?
        };
        let type_ordinal_numbers = header
            .flags
            .is_ord()
            .then(|| bincode::deserialize_from(&mut *input))
            .transpose()?;
        let types = if header.flags.is_zip() {
            Self::read_bucket_zip(&mut *input, &header)?
        } else {
            Self::read_bucket_normal(&mut *input, &header)?
        };

        Ok(TILSection {
            format: header.format,
            flags: header.flags,
            title: header.title,
            base: header.base,
            id: header.id,
            cm: header.cm,
            def_align: header.def_align,
            symbols,
            type_ordinal_numbers,
            types,
        })
    }

    fn read_header<I: BufRead>(input: &mut I) -> Result<TILSectionHeader> {
        let header1: TILSectionHeader1 = bincode::deserialize_from(&mut *input)?;
        ensure!(
            header1.signature == *TIL_SECTION_MAGIC,
            "Invalid TIL Signature"
        );

        let title = read_string_len_u8(&mut *input)?;
        let base = read_string_len_u8(&mut *input)?;

        let header2: TILSectionHeader2 = bincode::deserialize_from(&mut *input)?;
        let size_s_l_ll: Option<(u8, u8, u8)> = header1
            .flags
            .is_esi()
            .then(|| bincode::deserialize_from(&mut *input))
            .transpose()?;
        let size_ldbl: Option<u8> = header1
            .flags
            .size_long_double()
            .then(|| bincode::deserialize_from(&mut *input))
            .transpose()?;
        Ok(TILSectionHeader {
            format: header1.format,
            flags: header1.flags,
            title,
            base,
            id: header2.id,
            _size_i: header2.size_i,
            _size_b: header2.size_b,
            size_e: header2.size_e,
            cm: header2.cm,
            def_align: header2.def_align,
            _size_s_l_ll: size_s_l_ll,
            _size_ldbl: size_ldbl,
        })
    }

    #[cfg(test)]
    pub(crate) fn decompress<I: BufRead, O: std::io::Write>(
        input: &mut I,
        output: &mut O,
        compress: IDBSectionCompression,
    ) -> Result<()> {
        match compress {
            IDBSectionCompression::Zlib => {
                let mut input = BufReader::new(flate2::read::ZlibDecoder::new(input));
                Self::decompress_inner(&mut input, output)
            }
            IDBSectionCompression::None => Self::decompress_inner(input, output),
        }
    }

    #[cfg(test)]
    pub(crate) fn decompress_inner<I: BufRead, O: std::io::Write>(
        input: &mut I,
        output: &mut O,
    ) -> Result<()> {
        let mut header = Self::read_header(&mut *input)?;
        let og_flags = header.flags;
        // disable the zip flag
        header.flags.set_zip(false);
        let header1 = TILSectionHeader1 {
            signature: *TIL_SECTION_MAGIC,
            format: header.format,
            flags: header.flags,
        };
        let header2 = TILSectionHeader2 {
            id: header.id,
            cm: header.cm,
            size_i: header._size_i,
            size_b: header._size_b,
            size_e: header.size_e,
            def_align: header.def_align,
        };
        bincode::serialize_into(&mut *output, &header1)?;
        crate::write_string_len_u8(&mut *output, &header.title)?;
        crate::write_string_len_u8(&mut *output, &header.base)?;
        bincode::serialize_into(&mut *output, &header2)?;
        header
            ._size_s_l_ll
            .map(|value| bincode::serialize_into(&mut *output, &value))
            .transpose()?;
        header
            ._size_ldbl
            .map(|value| bincode::serialize_into(&mut *output, &value))
            .transpose()?;

        // if not zipped, just copy the rest of the data, there is no posible zip
        // block inside a bucket
        if !og_flags.is_zip() {
            std::io::copy(&mut *input, output)?;
            return Ok(());
        }

        // symbols
        Self::decompress_bucket(&mut *input, &mut *output)?;
        let _type_ordinal_numbers: Option<u32> = header
            .flags
            .is_ord()
            .then(|| -> Result<u32> {
                let result: u32 = bincode::deserialize_from(&mut *input)?;
                bincode::serialize_into(&mut *output, &result)?;
                Ok(result)
            })
            .transpose()?;
        // types
        Self::decompress_bucket(&mut *input, &mut *output)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct TILSectionFlag(u32);
impl TILSectionFlag {
    pub fn is_zip(&self) -> bool {
        self.0 & flag::TIL_ZIP != 0
    }
    pub fn set_zip(&mut self, value: bool) {
        if value {
            self.0 |= flag::TIL_ZIP
        } else {
            self.0 &= !flag::TIL_ZIP
        }
    }
    pub fn has_macro_table(&self) -> bool {
        self.0 & flag::TIL_MAC != 0
    }
    /// extended sizeof info (short, long, longlong)
    pub fn is_esi(&self) -> bool {
        self.0 & flag::TIL_ESI != 0
    }
    /// universal til for any compiler
    pub fn is_uni(&self) -> bool {
        self.0 & flag::TIL_UNI != 0
    }
    /// type ordinal numbers are present
    pub fn is_ord(&self) -> bool {
        self.0 & flag::TIL_ORD != 0
    }
    /// type aliases are present
    pub fn is_ali(&self) -> bool {
        self.0 & flag::TIL_ALI != 0
    }
    /// til has been modified, should be saved
    pub fn is_mod(&self) -> bool {
        self.0 & flag::TIL_MOD != 0
    }
    /// til has extra streams
    pub fn is_stm(&self) -> bool {
        self.0 & flag::TIL_STM != 0
    }
    /// sizeof(long double)
    pub fn size_long_double(&self) -> bool {
        self.0 & flag::TIL_SLD != 0
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TILBucketRaw {
    ndefs: u32,
    len: u32,
}

impl TILSection {
    fn read_bucket_header<I: BufRead>(input: &mut I) -> Result<(u32, u32)> {
        let ndefs = bincode::deserialize_from(&mut *input)?;
        let len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len))
    }

    fn read_bucket_zip_header<I: BufRead>(input: &mut I) -> Result<(u32, u32, u32)> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let compressed_len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len, compressed_len))
    }

    fn read_bucket_normal<I: BufRead>(
        input: &mut I,
        header: &TILSectionHeader,
    ) -> Result<Vec<TILTypeInfo>> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let mut input = input.take(len.into());
        let type_info = (0..ndefs)
            .map(|_| TILTypeInfo::read(&mut input, header))
            .collect::<Result<_, _>>()?;
        ensure!(
            input.limit() == 0,
            "TypeBucket total data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_bucket_zip<I: BufRead>(
        input: &mut I,
        header: &TILSectionHeader,
    ) -> Result<Vec<TILTypeInfo>> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        // make sure the decompressor don't read out-of-bounds
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = BufReader::new(flate2::read::ZlibDecoder::new(&mut compressed_input));
        // make sure only the defined size is decompressed
        let mut decompressed_input = inflate.take(len.into());
        let type_info = (0..ndefs.try_into().unwrap())
            .map(|_| TILTypeInfo::read(&mut decompressed_input, header))
            .collect::<Result<Vec<_>, _>>()?;
        // make sure the input was fully consumed
        ensure!(
            decompressed_input.limit() == 0,
            "TypeBucket data is smaller then expected"
        );
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket compressed data is smaller then expected"
        );
        Ok(type_info)
    }

    #[cfg(test)]
    fn decompress_bucket<I: BufRead, O: std::io::Write>(
        input: &mut I,
        output: &mut O,
    ) -> Result<()> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        bincode::serialize_into(&mut *output, &TILBucketRaw { len, ndefs })?;
        // write the decompressed data
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = flate2::read::ZlibDecoder::new(&mut compressed_input);
        let mut decompressed_input = inflate.take(len.into());
        std::io::copy(&mut decompressed_input, output)?;
        ensure!(
            decompressed_input.limit() == 0,
            "TypeBucket data is smaller then expected"
        );
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket compressed data is smaller then expected"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TILTypeInfo {
    _flags: u32,
    pub name: String,
    pub ordinal: u64,
    pub tinfo: Type,
    _cmt: String,
    _fieldcmts: String,
    _sclass: u8,
}

impl TILTypeInfo {
    pub(crate) fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let flags: u32 = bincode::deserialize_from(&mut *input)?;
        let name = read_c_string(&mut *input)?;
        let is_u64 = (flags >> 31) != 0;
        let ordinal = match (header.format, is_u64) {
            // formats below 0x12 doesn't have 64 bits ord
            (0..=0x11, _) | (_, false) => bincode::deserialize_from::<_, u32>(&mut *input)?.into(),
            (_, true) => bincode::deserialize_from(&mut *input)?,
        };
        let tinfo_raw =
            TypeRaw::read(&mut *input, header).context("parsing `TILTypeInfo::tiinfo`")?;
        let _info = read_c_string(&mut *input)?;
        let cmt = read_c_string(&mut *input)?;
        let fields = read_c_string_vec(&mut *input)?;
        let fieldcmts = read_c_string(&mut *input)?;
        let sclass: u8 = bincode::deserialize_from(&mut *input)?;

        let tinfo = Type::new(tinfo_raw, Some(fields))?;

        Ok(Self {
            _flags: flags,
            name,
            ordinal,
            tinfo,
            _cmt: cmt,
            _fieldcmts: fieldcmts,
            _sclass: sclass,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Type {
    Basic(Basic),
    Pointer(Pointer),
    Function(Function),
    Array(Array),
    Typedef(Typedef),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Bitfield(Bitfield),
}
impl Type {
    fn new(tinfo_raw: TypeRaw, fields: Option<Vec<String>>) -> Result<Self> {
        match tinfo_raw {
            TypeRaw::Basic(x) => Basic::new(x, fields).map(Type::Basic),
            TypeRaw::Bitfield(x) => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Bitfield"));
                }
                Ok(Type::Bitfield(x))
            }
            TypeRaw::Typedef(x) => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Typedef"));
                }
                Ok(Type::Typedef(x))
            }
            TypeRaw::Pointer(x) => Pointer::new(x, fields).map(Type::Pointer),
            TypeRaw::Function(x) => Function::new(x, fields).map(Type::Function),
            TypeRaw::Array(x) => Array::new(x, fields).map(Type::Array),
            TypeRaw::Struct(x) => Struct::new(x, fields).map(Type::Struct),
            TypeRaw::Union(x) => Union::new(x, fields).map(Type::Union),
            TypeRaw::Enum(x) => Enum::new(x, fields).map(Type::Enum),
        }
    }
}

#[derive(Debug, Clone)]
enum TypeRaw {
    Basic(TypeMetadata),
    Pointer(PointerRaw),
    Function(FunctionRaw),
    Array(ArrayRaw),
    Typedef(Typedef),
    Struct(StructRaw),
    Union(UnionRaw),
    Enum(EnumRaw),
    Bitfield(Bitfield),
}

impl TypeRaw {
    pub fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let metadata = TypeMetadata::read(&mut *input)?;
        if metadata.get_base_type_flag().is_typeid_last()
            || metadata.get_base_type_flag().is_reserved()
        {
            return Ok(TypeRaw::Basic(metadata));
        } else if metadata.get_base_type_flag().is_pointer() {
            Ok(TypeRaw::Pointer(
                PointerRaw::read(input, metadata, header).context("Type::Pointer")?,
            ))
        } else if metadata.get_base_type_flag().is_function() {
            Ok(TypeRaw::Function(
                FunctionRaw::read(input, &metadata, header).context("Type::Function")?,
            ))
        } else if metadata.get_base_type_flag().is_array() {
            Ok(TypeRaw::Array(
                ArrayRaw::read(input, metadata, header).context("Type::Array")?,
            ))
        } else if metadata.get_full_type_flag().is_typedef() {
            Ok(TypeRaw::Typedef(
                Typedef::read(input).context("Type::Typedef")?,
            ))
        } else if metadata.get_full_type_flag().is_union() {
            Ok(TypeRaw::Union(
                UnionRaw::read(input, header).context("Type::Union")?,
            ))
        } else if metadata.get_full_type_flag().is_struct() {
            Ok(TypeRaw::Struct(
                StructRaw::read(input, header).context("Type::Struct")?,
            ))
        } else if metadata.get_full_type_flag().is_enum() {
            Ok(TypeRaw::Enum(
                EnumRaw::read(input, header).context("Type::Enum")?,
            ))
        } else if metadata.get_base_type_flag().is_bitfield() {
            Ok(TypeRaw::Bitfield(
                Bitfield::read(input, metadata).context("Type::Bitfield")?,
            ))
        } else {
            todo!();
            //Ok(Type::Unknown(read_c_string_raw(input)?))
        }
    }

    pub fn read_ref<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let mut bytes = read_dt_bytes(&mut *input)?;

        if !bytes.starts_with(b"=") {
            let dt = serialize_dt(bytes.len().try_into().unwrap())?;
            bytes = [b'='].into_iter().chain(dt).chain(bytes).collect();
        }

        let mut bytes = &bytes[..];
        let result = TypeRaw::read(&mut bytes, header)?;
        if !bytes.is_empty() {
            return Err(anyhow!("Unable to fully parser Type ref"));
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Basic {
    Void,
    // NOTE Unknown with None bytes is NOT the same as Void
    Unknown {
        bytes: Option<NonZeroU8>,
    },

    Bool {
        bytes: Option<NonZeroU8>,
    },
    Char,
    SegReg,
    Int {
        bytes: Option<NonZeroU8>,
        is_signed: Option<bool>,
    },
    Float {
        bytes: Option<NonZeroU8>,
    },
}

impl Basic {
    fn new(mdata: TypeMetadata, fields: Option<Vec<String>>) -> Result<Self> {
        const fn bytes(bytes: u8) -> NonZeroU8 {
            if bytes == 0 {
                unreachable!()
            }
            unsafe { NonZeroU8::new_unchecked(bytes) }
        }
        if let Some(fields) = fields {
            ensure!(fields.is_empty(), "Unset with fields");
        }
        let bt = mdata.get_base_type_flag().0;
        let btmt = mdata.get_type_flag().0;
        use flag::{tf_bool::*, tf_float::*, tf_int::*, tf_unk::*};
        match bt {
            BT_VOID => {
                let bytes = match btmt {
                    // special case, void
                    BTMT_SIZE0 => return Ok(Self::Void),
                    BTMT_SIZE12 => Some(bytes(1)),
                    BTMT_SIZE48 => Some(bytes(4)),
                    BTMT_SIZE128 => Some(bytes(16)),
                    _ => unreachable!(),
                };
                Ok(Self::Unknown { bytes })
            }
            BT_UNK => {
                let bytes = match btmt {
                    BTMT_SIZE0 => return Err(anyhow!("forbidden use of BT_UNK")),
                    BTMT_SIZE12 => Some(bytes(2)),
                    BTMT_SIZE48 => Some(bytes(8)),
                    BTMT_SIZE128 => None,
                    _ => unreachable!(),
                };
                Ok(Self::Unknown { bytes })
            }

            bt_int @ BT_INT8..=BT_INT => {
                let is_signed = match btmt {
                    BTMT_UNKSIGN => None,
                    BTMT_SIGNED => Some(true),
                    BTMT_UNSIGNED => Some(false),
                    // special case for char
                    BTMT_CHAR => match bt_int {
                        BT_INT8 => return Ok(Self::Char),
                        BT_INT => return Ok(Self::SegReg),
                        _ => {
                            return Err(anyhow!("Reserved use of tf_int::BTMT_CHAR {:x}", mdata.0))
                        }
                    },
                    _ => unreachable!(),
                };
                let bytes = match bt_int {
                    BT_INT8 => Some(bytes(1)),
                    BT_INT16 => Some(bytes(2)),
                    BT_INT32 => Some(bytes(4)),
                    BT_INT64 => Some(bytes(8)),
                    BT_INT128 => Some(bytes(16)),
                    BT_INT => None,
                    _ => unreachable!(),
                };
                Ok(Self::Int { bytes, is_signed })
            }

            BT_BOOL => {
                let bytes = match btmt {
                    BTMT_DEFBOOL => None,
                    BTMT_BOOL1 => Some(bytes(1)),
                    BTMT_BOOL4 => Some(bytes(4)),
                    // TODO get the inf_is_64bit  field
                    //BTMT_BOOL2 if !inf_is_64bit => Some(bytes(2)),
                    //BTMT_BOOL8 if inf_is_64bit => Some(bytes(8)),
                    BTMT_BOOL8 => Some(bytes(2)), // delete this
                    _ => unreachable!(),
                };
                Ok(Self::Bool { bytes })
            }

            BT_FLOAT => {
                let bytes = match btmt {
                    BTMT_FLOAT => Some(bytes(4)),
                    BTMT_DOUBLE => Some(bytes(8)),
                    BTMT_LNGDBL => None,
                    // TODO find the tbyte_size field
                    //(BTMT_SPECFLT, Some(bytes)) => Some(bytes),
                    //(BTMT_SPECFLT, None) => Some(bytes(2)),
                    BTMT_SPECFLT => Some(bytes(8)), // delete this
                    _ => unreachable!(),
                };
                Ok(Self::Float { bytes })
            }
            _ => Err(anyhow!("Unkown Unset Type {}", mdata.0)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: Option<Closure>,
    pub tah: TAH,
    pub typ: Box<Type>,
}

impl Pointer {
    fn new(raw: PointerRaw, fields: Option<Vec<String>>) -> Result<Self> {
        Ok(Self {
            closure: raw.closure.map(Closure::new).transpose()?,
            tah: raw.tah,
            typ: Type::new(*raw.typ, fields).map(Box::new)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Closure {
    Closure(Box<Type>),
    PointerBased(u8),
}

impl Closure {
    fn new(raw: ClosureRaw) -> Result<Self> {
        match raw {
            ClosureRaw::Closure(c) => Type::new(*c, None).map(Box::new).map(Self::Closure),
            ClosureRaw::PointerBased(p) => Ok(Self::PointerBased(p)),
        }
    }
}

#[derive(Debug, Clone)]
struct PointerRaw {
    pub closure: Option<ClosureRaw>,
    pub tah: TAH,
    pub typ: Box<TypeRaw>,
}

#[derive(Debug, Clone)]
enum ClosureRaw {
    Closure(Box<TypeRaw>),
    PointerBased(u8),
}

impl PointerRaw {
    fn read<I: BufRead>(
        input: &mut I,
        metadata: TypeMetadata,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        let closure = metadata
            .get_type_flag()
            .is_type_closure()
            .then(|| ClosureRaw::read(&mut *input, header))
            .transpose()?;
        let tah = TAH::read(&mut *input)?;
        let typ = TypeRaw::read(&mut *input, header)?;
        Ok(Self {
            closure,
            tah,
            typ: Box::new(typ),
        })
    }
}

impl ClosureRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let closure_type: u8 = bincode::deserialize_from(&mut *input)?;
        if closure_type == 0xFF {
            let closure = TypeRaw::read(&mut *input, header)?;
            Ok(Self::Closure(Box::new(closure)))
        } else {
            let closure_ptr = bincode::deserialize_from(&mut *input)?;
            Ok(Self::PointerBased(closure_ptr))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub ret: Box<Type>,
    pub args: Vec<(Option<String>, Type, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
}
impl Function {
    fn new(value: FunctionRaw, fields: Option<Vec<String>>) -> Result<Self> {
        let args = associate_field_name_and_member(fields, value.args)
            .context("Function")?
            .map(|(n, (t, a))| Type::new(t, None).map(|t| (n, t, a)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            ret: Type::new(*value.ret, None).map(Box::new)?,
            args,
            retloc: value.retloc,
        })
    }
}

#[derive(Debug, Clone)]
struct FunctionRaw {
    pub ret: Box<TypeRaw>,
    pub args: Vec<(TypeRaw, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
}

#[derive(Debug, Clone)]
pub enum ArgLoc {
    // TODO add those to flags
    // ::ALOC_STACK
    // ::ALOC_STATIC
    // ::ALOC_REG1
    // ::ALOC_REG2
    // ::ALOC_RREL
    // ::ALOC_DIST
    // ::ALOC_CUSTOM
    /// 0 - None
    None,
    /// 1 - stack offset
    Stack(u32),
    /// 2 - distributed (scattered)
    Dist(Vec<ArgLocDist>),
    /// 3 - one register (and offset within it)
    Reg1(u32),
    /// 4 - register pair
    Reg2(u32),
    /// 5 - register relative
    RRel { reg: u16, off: u32 },
    /// 6 - global address
    Static(u32),
    // 7..=0xf custom
    // TODO is possible to know the custom impl len?
}

#[derive(Debug, Clone)]
pub struct ArgLocDist {
    pub info: u16,
    pub off: u16,
    pub size: u16,
}

impl FunctionRaw {
    fn read<I: BufRead>(
        input: &mut I,
        metadata: &TypeMetadata,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        // TODO what is that?
        let mut flags = metadata.get_type_flag().0 << 2;

        let cc = Self::read_cc(&mut *input, &mut flags)?;

        let _tah = TAH::read(&mut *input)?;
        let ret = TypeRaw::read(&mut *input, header)?;
        let have_retloc = cc.get_calling_convention().is_special_pe()
            && !matches!(&ret, TypeRaw::Basic(mdata) if mdata.get_full_type_flag().is_void());
        let retloc = have_retloc.then(|| ArgLoc::read(&mut *input)).transpose()?;
        if cc.get_calling_convention().is_void_arg() {
            return Ok(Self {
                ret: Box::new(ret),
                args: vec![],
                retloc,
            });
        }

        let n = read_dt(&mut *input)?;
        let is_special_pe = cc.get_calling_convention().is_special_pe();
        let args = (0..n)
            .map(|_| -> Result<_> {
                let tmp = input.fill_buf()?.get(0).copied();
                if tmp == Some(0xFF) {
                    // TODO what is this?
                    let _tmp: u8 = bincode::deserialize_from(&mut *input)?;
                    let _flags = read_de(&mut *input)?;
                }
                let tinfo = TypeRaw::read(&mut *input, header)?;
                let argloc = is_special_pe
                    .then(|| ArgLoc::read(&mut *input))
                    .transpose()?;

                Ok((tinfo, argloc))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            ret: Box::new(ret),
            args,
            retloc,
        })
    }

    fn read_cc<I: BufRead>(input: &mut I, flags: &mut u8) -> Result<TypeMetadata> {
        let mut cm = TypeMetadata::read(&mut *input)?;
        if !cm.get_calling_convention().is_spoiled() {
            return Ok(cm);
        }
        // TODO find what to do with this spoiled and flags stuff
        let mut _spoiled = vec![];
        loop {
            // TODO create flags::CM_CC_MASK
            let nspoiled = cm.0 & !0xf0;
            if nspoiled == 0xF {
                let b: u8 = bincode::deserialize_from(&mut *input)?;
                *flags |= (b & 0x1F) << 1;
            } else {
                for _ in 0..nspoiled {
                    let b: u8 = bincode::deserialize_from(&mut *input)?;
                    let (size, reg) = if b & 0x80 != 0 {
                        let size: u8 = bincode::deserialize_from(&mut *input)?;
                        let reg = b & 0x7F;
                        (size, reg)
                    } else {
                        ensure!(b > 1, "Unable to solve register from a spoiled function");
                        let size = (b >> 4) + 1;
                        let reg = (b & 0xF) - 1;
                        (size, reg)
                    };
                    _spoiled.push((size, reg));
                }
                *flags |= 1;
            }

            cm = TypeMetadata::read(&mut *input)?;
            if !cm.get_calling_convention().is_spoiled() {
                return Ok(cm);
            }
        }
    }
}

impl ArgLoc {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let t: u8 = bincode::deserialize_from(&mut *input)?;
        if t != 0xFF {
            let b = t & 0x7F;
            match (t, b) {
                (0..=0x80, 1..) => Ok(Self::Reg1((b - 1).into())),
                (0..=0x80, 0) => Ok(Self::Stack(0)),
                _ => {
                    let c: u8 = bincode::deserialize_from(&mut *input)?;
                    if c == 0 {
                        Ok(Self::None)
                    } else {
                        Ok(Self::Reg2(u32::from(b) | u32::from(c - 1) << 16))
                    }
                }
            }
        } else {
            let typ = read_dt(&mut *input)?;
            match typ & 0xF {
                0 => Ok(Self::None),
                1 => {
                    let sval = read_de(&mut *input)?;
                    Ok(Self::Stack(sval))
                }
                2 => {
                    let n = (typ >> 5) & 0x7;
                    let dist: Vec<_> = (0..n)
                        .map(|_| {
                            let info = read_dt(&mut *input)?;
                            let off = read_dt(&mut *input)?;
                            let size = read_dt(&mut *input)?;
                            Ok(ArgLocDist { info, off, size })
                        })
                        .collect::<Result<_, std::io::Error>>()?;
                    Ok(Self::Dist(dist))
                }
                3 => {
                    let reg_info = read_dt(&mut *input)?;
                    // TODO read other dt?
                    Ok(Self::Reg1(reg_info.into()))
                }
                4 => {
                    let reg_info = read_dt(&mut *input)?;
                    // TODO read other dt?
                    Ok(Self::Reg2(reg_info.into()))
                }
                5 => {
                    let reg = read_dt(&mut *input)?;
                    let off = read_de(&mut *input)?;
                    Ok(Self::RRel { reg, off })
                }
                6 => {
                    let sval = read_de(&mut *input)?;
                    Ok(Self::Static(sval))
                }
                0x7..=0xF => todo!("Custom implementation for ArgLoc"),
                _ => unreachable!(),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Array {
    pub base: u8,
    pub nelem: u16,
    pub tah: TAH,
    pub elem_type: Box<Type>,
}
impl Array {
    fn new(value: ArrayRaw, fields: Option<Vec<String>>) -> Result<Self> {
        if matches!(&fields, Some(f) if !f.is_empty()) {
            return Err(anyhow!("fields in a Array"));
        }
        Ok(Self {
            base: value.base,
            nelem: value.nelem,
            tah: value.tah,
            elem_type: Type::new(*value.elem_type, None).map(Box::new)?,
        })
    }
}

#[derive(Clone, Debug)]
struct ArrayRaw {
    pub base: u8,
    pub nelem: u16,
    pub tah: TAH,
    pub elem_type: Box<TypeRaw>,
}

impl ArrayRaw {
    fn read<I: BufRead>(
        input: &mut I,
        metadata: TypeMetadata,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        let (base, nelem) = if metadata.get_type_flag().is_non_based() {
            let nelem = read_dt(&mut *input)?;
            (0, nelem)
        } else {
            let (base, nelem) = read_da(&mut *input)?;
            (base, nelem.into())
        };
        let tah = TAH::read(&mut *input)?;
        let elem_type = TypeRaw::read(&mut *input, header)?;
        Ok(ArrayRaw {
            base,
            nelem,
            tah,
            elem_type: Box::new(elem_type),
        })
    }
}

#[derive(Clone, Debug)]
pub enum Typedef {
    Ordinal(u32),
    Name(String),
}

impl Typedef {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let buf = read_dt_bytes(&mut *input)?;
        match &buf[..] {
            [b'#', data @ ..] => {
                let mut tmp = &data[..];
                let de = read_de(&mut tmp)?;
                if !tmp.is_empty() {
                    return Err(anyhow!("Typedef Ordinal with more data then expected"));
                }
                Ok(Typedef::Ordinal(de))
            }
            _ => Ok(Typedef::Name(String::from_utf8(buf)?)),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Struct {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        taudt_bits: SDACL,
        members: Vec<StructMember>,
    },
}
impl Struct {
    fn new(value: StructRaw, fields: Option<Vec<String>>) -> Result<Self> {
        match value {
            StructRaw::Ref {
                ref_type,
                taudt_bits,
            } => {
                if matches!(&fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Struct"));
                }
                Ok(Struct::Ref {
                    ref_type: Type::new(*ref_type, None).map(Box::new)?,
                    taudt_bits,
                })
            }
            StructRaw::NonRef {
                effective_alignment,
                taudt_bits,
                members,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Struct")?
                    .map(|(n, m)| StructMember::new(n, m))
                    .collect::<Result<_, _>>()?;
                Ok(Struct::NonRef {
                    effective_alignment,
                    taudt_bits,
                    members,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
enum StructRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        taudt_bits: SDACL,
        members: Vec<StructMemberRaw>,
    },
}

impl StructRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // simple reference
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taudt_bits = SDACL::read(&mut *input)?;
            return Ok(Self::Ref {
                ref_type: Box::new(ref_type),
                taudt_bits,
            });
        };

        let alpow = n & 7;
        let mem_cnt = n >> 3;
        let effective_alignment = if alpow == 0 { 0 } else { 1 << (alpow - 1) };
        let taudt_bits = SDACL::read(&mut *input)?;
        let members = (0..mem_cnt)
            .map(|_| StructMemberRaw::read(&mut *input, header))
            .collect::<Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            taudt_bits,
            members,
        })
    }
}

#[derive(Clone, Debug)]
pub enum Union {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        taudt_bits: SDACL,
        effective_alignment: u16,
        members: Vec<(Option<String>, Type)>,
    },
}
impl Union {
    fn new(value: UnionRaw, fields: Option<Vec<String>>) -> Result<Self> {
        match value {
            UnionRaw::Ref {
                ref_type,
                taudt_bits,
            } => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Union"));
                }
                Ok(Union::Ref {
                    ref_type: Type::new(*ref_type, None).map(Box::new)?,
                    taudt_bits,
                })
            }
            UnionRaw::NonRef {
                taudt_bits,
                effective_alignment,
                members,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Union")?
                    .map(|(n, m)| Type::new(m, None).map(|m| (n, m)))
                    .collect::<Result<_, _>>()?;
                Ok(Union::NonRef {
                    taudt_bits,
                    effective_alignment,
                    members,
                })
            }
        }
    }
}

// TODO struct and union are basically identical, the diff is that member in union don't have SDACL,
// merge both
#[derive(Clone, Debug)]
enum UnionRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taudt_bits: SDACL,
    },
    NonRef {
        taudt_bits: SDACL,
        effective_alignment: u16,
        members: Vec<TypeRaw>,
    },
}

impl UnionRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // is ref
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taudt_bits = SDACL::read(&mut *input)?;
            return Ok(Self::Ref {
                ref_type: Box::new(ref_type),
                taudt_bits,
            });
        };
        let alpow = n & 7;
        let mem_cnt = n >> 3;
        let effective_alignment = if alpow == 0 { 0 } else { 1 << (alpow - 1) };
        let taudt_bits = SDACL::read(&mut *input)?;
        let members = (0..mem_cnt)
            .map(|_| TypeRaw::read(&mut *input, header))
            .collect::<Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            taudt_bits,
            members,
        })
    }
}

#[derive(Clone, Debug)]
pub enum Enum {
    Ref {
        ref_type: Box<Type>,
        taenum_bits: TypeAttribute,
    },
    NonRef {
        group_sizes: Vec<u16>,
        taenum_bits: TypeAttribute,
        bte: u8,
        members: Vec<(Option<String>, u64)>,
        bytesize: u64,
    },
}
impl Enum {
    fn new(value: EnumRaw, fields: Option<Vec<String>>) -> Result<Self> {
        match value {
            EnumRaw::Ref {
                ref_type,
                taenum_bits,
            } => {
                if matches!(&fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Enum"));
                }
                Ok(Enum::Ref {
                    ref_type: Type::new(*ref_type, None).map(Box::new)?,
                    taenum_bits,
                })
            }
            EnumRaw::NonRef {
                group_sizes,
                taenum_bits,
                bte,
                members,
                bytesize,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Enum")?
                    .map(|(n, f)| (n, f))
                    .collect();
                Ok(Enum::NonRef {
                    group_sizes,
                    taenum_bits,
                    bte,
                    members,
                    bytesize,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
enum EnumRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taenum_bits: TypeAttribute,
    },
    NonRef {
        group_sizes: Vec<u16>,
        taenum_bits: TypeAttribute,
        bte: u8,
        members: Vec<u64>,
        bytesize: u64,
    },
}

impl EnumRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // is ref
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taenum_bits = SDACL::read(&mut *input)?.0;
            return Ok(EnumRaw::Ref {
                ref_type: Box::new(ref_type),
                taenum_bits,
            });
        };

        let taenum_bits = TAH::read(&mut *input)?.0;
        let bte = bincode::deserialize_from(&mut *input)?;
        let mut cur: u64 = 0;
        let emsize = bte & flag::tf_enum::BTE_SIZE_MASK;
        let bytesize: u32 = match emsize {
            0 if header.size_e != 0 => header.size_e.into(),
            0 => return Err(anyhow!("BTE emsize is 0 without header")),
            5 | 6 | 7 => return Err(anyhow!("BTE emsize with reserved values")),
            _ => 1u32 << (emsize - 1),
        };

        let mask: u64 = if bytesize >= 16 {
            // is saturating valid?
            //u64::MAX
            return Err(anyhow!("Bytes size is too big"));
        } else {
            u64::MAX >> (u64::BITS - (bytesize * 8))
        };

        let mut group_sizes = vec![];
        let mut members = vec![];
        for _ in 0..n {
            let lo: u64 = read_de(&mut *input)?.into();
            let is_64 = (taenum_bits.0 & 0x0020) != 0;
            let step = if is_64 {
                let hi: u64 = read_de(&mut *input)?.into();
                (lo | (hi << 32)) & mask
            } else {
                lo & mask
            };
            // TODO: subarrays
            // https://www.hex-rays.com/products/ida/support/sdkdoc/group__tf__enum.html#ga9ae7aa54dbc597ec17cbb17555306a02
            if (bte & flag::tf_enum::BTE_BITFIELD) != 0 {
                let group_size = read_dt(&mut *input)?;
                group_sizes.push(group_size);
            }
            // TODO check is this is wrapping by default
            let next_step = cur.wrapping_add(step);
            cur = next_step;
            members.push(cur);
        }
        return Ok(EnumRaw::NonRef {
            group_sizes,
            taenum_bits,
            bte,
            members,
            bytesize: bytesize.into(),
        });
    }
}

#[derive(Debug, Clone)]
pub struct Bitfield {
    pub unsigned: bool,
    pub width: u16,
    pub nbytes: i32,
}

impl Bitfield {
    fn read<I: BufRead>(input: &mut I, metadata: TypeMetadata) -> Result<Self> {
        let nbytes = 1 << (metadata.get_type_flag().0 >> 4);
        let dt = read_dt(&mut *input)?;
        let width = dt >> 1;
        let unsigned = (dt & 1) > 0;
        let _tag = TAH::read(&mut *input)?;
        Ok(Self {
            unsigned,
            width,
            nbytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name: Option<String>,
    pub member_type: Type,
    pub sdacl: SDACL,
}

impl StructMember {
    fn new(name: Option<String>, m: StructMemberRaw) -> Result<Self> {
        Ok(Self {
            name,
            member_type: Type::new(m.0, None)?,
            sdacl: m.1,
        })
    }
}
#[derive(Clone, Debug)]
struct StructMemberRaw(pub TypeRaw, pub SDACL);
impl StructMemberRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let member_type = TypeRaw::read(&mut *input, header)?;
        let sdacl = SDACL::read(&mut *input)?;
        Ok(Self(member_type, sdacl))
    }
}

#[derive(Clone, Default, Debug)]
pub struct TypeMetadata(pub u8);
impl TypeMetadata {
    fn new(value: u8) -> Self {
        // TODO check for invalid values
        Self(value)
    }
    fn read<I: Read>(input: I) -> Result<Self> {
        Ok(Self::new(bincode::deserialize_from(input)?))
    }
}

// TODO make those inner fields into enums or private
#[derive(Clone, Copy, Debug)]
pub struct BaseTypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct FullTypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct TypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct CallingConventionFlag(pub u8);

#[derive(Clone, Copy, Debug)]
pub struct TypeAttribute(pub u16);
impl TypeAttribute {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let mut val: u16 = 0;
        let tah: u8 = bincode::deserialize_from(&mut *input)?;
        let tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1;
        if tah == 0xFE || tmp == 8 {
            if tmp == 8 {
                val = tmp as u16;
            }
            let mut shift = 0;
            loop {
                let next_byte: u8 = bincode::deserialize_from(&mut *input)?;
                if next_byte == 0 {
                    return Err(anyhow!("Failed to parse TypeAttribute"));
                }
                val |= ((next_byte & 0x7F) as u16) << shift;
                if next_byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        if (val & 0x0010) > 0 {
            val = read_dt(&mut *input)?;
            for _ in 0..val {
                let _string = read_dt_string(&mut *input)?;
                let another_de = read_dt(&mut *input)?;
                let mut other_string = vec![0; another_de.into()];
                input.read_exact(&mut other_string)?;
            }
        }
        Ok(TypeAttribute(val))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TAH(pub TypeAttribute);
impl TAH {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let Some(tah) = input.fill_buf()?.get(0).copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on DA"
            )));
        };
        if tah == 0xFE {
            Ok(Self(TypeAttribute::read(input)?))
        } else {
            Ok(Self(TypeAttribute(0)))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SDACL(pub TypeAttribute);
impl SDACL {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let Some(sdacl) = input.fill_buf()?.get(0).copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on SDACL"
            )));
        };
        if ((sdacl & !0x30) ^ 0xC0) <= 0x01 {
            Ok(Self(TypeAttribute::read(input)?))
        } else {
            Ok(Self(TypeAttribute(0)))
        }
    }
}

impl CallingConventionFlag {
    fn is_spoiled(&self) -> bool {
        self.0 == 0xA0
    }

    fn is_void_arg(&self) -> bool {
        self.0 == 0x20
    }

    fn is_special_pe(&self) -> bool {
        self.0 == 0xD0 || self.0 == 0xE0 || self.0 == 0xF0
    }
}

impl TypeMetadata {
    pub fn get_base_type_flag(&self) -> BaseTypeFlag {
        BaseTypeFlag(self.0 & flag::tf_mask::TYPE_BASE_MASK)
    }

    pub fn get_full_type_flag(&self) -> FullTypeFlag {
        FullTypeFlag(self.0 & flag::tf_mask::TYPE_FULL_MASK)
    }

    pub fn get_type_flag(&self) -> TypeFlag {
        TypeFlag(self.0 & flag::tf_mask::TYPE_FLAGS_MASK)
    }

    pub fn get_calling_convention(&self) -> CallingConventionFlag {
        CallingConventionFlag(self.0 & 0xF0)
    }
}

impl TypeFlag {
    fn is_non_based(&self) -> bool {
        self.0 == 0x10
    }

    pub fn is_unsigned(&self) -> bool {
        self.0 == 0x20
    }

    pub fn is_signed(&self) -> bool {
        !self.is_unsigned()
    }

    fn is_type_closure(&self) -> bool {
        self.0 == flag::tf_ptr::BTMT_CLOSURE
    }
}

impl FullTypeFlag {
    fn is_enum(&self) -> bool {
        self.0 == flag::tf_shortcuts::BTF_ENUM
    }

    fn is_void(&self) -> bool {
        self.0 == flag::tf_shortcuts::BTF_VOID
    }

    fn is_struct(&self) -> bool {
        self.0 == flag::tf_shortcuts::BTF_STRUCT
    }

    fn is_union(&self) -> bool {
        self.0 == flag::tf_shortcuts::BTF_UNION
    }

    fn is_typedef(&self) -> bool {
        self.0 == flag::tf_shortcuts::BTF_TYPEDEF
    }
}

impl BaseTypeFlag {
    fn is_pointer(&self) -> bool {
        self.0 == flag::tf_ptr::BT_PTR
    }

    fn is_function(&self) -> bool {
        self.0 == flag::tf_func::BT_FUNC
    }

    fn is_array(&self) -> bool {
        self.0 == flag::tf_array::BT_ARRAY
    }

    fn is_bitfield(&self) -> bool {
        self.0 == flag::tf_complex::BT_BITFIELD
    }

    fn is_typeid_last(&self) -> bool {
        self.0 <= flag::tf_last_basic::BT_LAST_BASIC
    }

    fn is_reserved(&self) -> bool {
        self.0 == flag::BT_RESERVED
    }
}

fn read_dt_bytes<I: BufRead>(input: &mut I) -> Result<Vec<u8>> {
    let buf_len = read_dt(&mut *input)?;
    let mut buf = vec![0; buf_len.into()];
    input.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_dt_string<I: BufRead>(input: &mut I) -> Result<String> {
    let buf = read_dt_bytes(input)?;
    Ok(String::from_utf8(buf)?)
}

/// Reads 1 to 5 bytes
/// Value Range: 0-0xFFFFFFFF
/// Usage: Enum Deltas
fn read_de<I: Read>(input: &mut I) -> std::io::Result<u32> {
    let mut val: u32 = 0;
    for _ in 0..5 {
        let mut hi = val << 6;
        let mut b = [0; 1];
        input.read_exact(&mut b)?;
        let b: u32 = b[0].into();
        let sign = b & 0x80;
        if sign == 0 {
            let lo = b & 0x3F;
            val = lo | hi;
            return Ok(val);
        } else {
            let lo = 2 * hi;
            hi = b & 0x7F;
            val = lo | hi;
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Can't find the end of DE",
    ))
}

/// Reads 1 or 2 bytes.
/// Value Range: 0-0xFFFE
/// Usage: 16bit numbers
fn read_dt<I: Read>(input: &mut I) -> std::io::Result<u16> {
    let mut value = [0u8; 1];
    input.read_exact(&mut value)?;
    let value = value[0].into();

    let value = match value {
        0 => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DT can't have 0 value",
            ))
        }
        //SEG = 2
        value if value & 0x80 != 0 => {
            let mut iter = [0u8; 1];
            input.read_exact(&mut iter)?;
            let inter: u16 = iter[0].into();
            value & 0x7F | inter << 7
        }
        //SEG = 1
        _ => value,
    };
    Ok(value - 1)
}

fn serialize_dt(value: u16) -> Result<Vec<u8>> {
    if value > 0x7FFE {
        return Err(anyhow!("Invalid value for DT"));
    }
    let lo = value + 1;
    let mut hi = value + 1;
    let mut result: Vec<u8> = Vec::with_capacity(2);
    if lo > 127 {
        result.push((lo & 0x7F | 0x80) as u8);
        hi = (lo >> 7) & 0xFF;
    }
    result.push(hi as u8);
    Ok(result)
}

/// Reads 1 to 9 bytes.
/// ValueRange: 0-0x7FFFFFFF, 0-0xFFFFFFFF
/// Usage: Arrays
fn read_da<I: BufRead>(input: &mut I) -> Result<(u8, u8)> {
    let mut a = 0;
    let mut b = 0;
    let mut da = 0;
    let mut base = 0;
    let mut nelem = 0;
    // TODO check no more then 9 bytes are read
    loop {
        let Some(typ) = input.fill_buf()?.get(0).copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on DA"
            )));
        };
        if typ & 0x80 == 0 {
            break;
        }
        input.consume(1);

        da = (da << 7) | typ & 0x7F;
        b += 1;
        if b >= 4 {
            let z: u8 = bincode::deserialize_from(&mut *input)?;
            if z != 0 {
                base = 0x10 * da | z & 0xF
            }
            nelem = (z >> 4) & 7;
            loop {
                let Some(y) = input.fill_buf()?.get(0).copied() else {
                    return Err(anyhow!(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Unexpected EoF on DA"
                    )));
                };
                if (y & 0x80) == 0 {
                    break;
                }
                input.consume(1);
                nelem = (nelem << 7) | y & 0x7F;
                a += 1;
                if a >= 4 {
                    return Ok((nelem, base));
                }
            }
        }
    }
    return Ok((nelem, base));
}

/// Reads 2 to 7 bytes.
/// Value Range: Nothing or 0-0xFFFF_FFFF
/// Usage: some kind of size
fn read_dt_de<I: Read>(input: &mut I) -> std::io::Result<Option<u32>> {
    match read_dt(&mut *input)? {
        0 => Ok(None),
        0x7FFE => read_de(&mut *input).map(Some),
        n => Ok(Some(n.into())),
    }
}

fn associate_field_name_and_member<T>(
    fields: Option<Vec<String>>,
    members: Vec<T>,
) -> Result<impl Iterator<Item = (Option<String>, T)>> {
    let fields_len: usize = fields.iter().filter(|t| !t.is_empty()).count();
    ensure!(fields_len <= members.len(), "More fields then members");
    // allow to have less fields then members, first fields will have names, others not
    Ok(fields
        .into_iter()
        .flat_map(Vec::into_iter)
        .map(Option::Some)
        .chain(std::iter::repeat(None))
        .into_iter()
        .zip(members))
}

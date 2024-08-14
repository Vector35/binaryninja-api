/// byte sequence used to describe a type in IDA
type TypeT = u8;
/// Enum type flags
type BteT = u8;

/// multi-use
pub const RESERVED_BYTE: TypeT = 0xFF;

/// Masks
pub mod tf_mask {
    use super::TypeT;
    /// the low 4 bits define the basic type
    pub const TYPE_BASE_MASK: TypeT = 0x0F;
    /// type flags - they have different meaning depending on the basic type
    pub const TYPE_FLAGS_MASK: TypeT = 0x30;
    /// modifiers.
    /// for [super::tf_array::BT_ARRAY] see [super::tf_array]
    /// ::BT_VOID can have them ONLY in 'void *'
    pub const TYPE_MODIF_MASK: TypeT = 0xC0;
    /// basic type with type flags
    pub const TYPE_FULL_MASK: TypeT = TYPE_BASE_MASK | TYPE_FLAGS_MASK;
}

/// Basic type: unknown & void
///  [BT_UNK] and [BT_VOID] with non-zero type flags can be used in function
///  (and struct) declarations to describe the function arguments or structure
///  fields if only their size is known. They may be used in ida to describe
///  the user input.
///
///  In general BT_... bits should not be used alone to describe types.
///  Use BTF_... constants instead.
///
///  For struct used also as 'single-field-alignment-suffix'
///  [__declspec(align(x))] with [tf_mask::TYPE_MODIF_MASK] == [tf_mask::TYPE_FULL_MASK]
pub mod tf_unk {
    use super::TypeT;
    /// unknown
    pub const BT_UNK: TypeT = 0x00;
    /// void
    pub const BT_VOID: TypeT = 0x01;
    /// [BT_VOID] - normal void; [BT_UNK] - don't use
    pub const BTMT_SIZE0: TypeT = 0x00;
    /// size = 1 byte  if [BT_VOID]; 2 if [BT_UNK]
    pub const BTMT_SIZE12: TypeT = 0x10;
    /// size = 4 bytes if [BT_VOID]; 8 if [BT_UNK]
    pub const BTMT_SIZE48: TypeT = 0x20;
    /// size = 16 bytes if [BT_VOID]; unknown if [BT_UNK] (IN struct alignment - see below)
    pub const BTMT_SIZE128: TypeT = 0x30;
}

/// Basic type: integer
pub mod tf_int {
    use super::TypeT;
    /// __int8
    pub const BT_INT8: TypeT = 0x02;
    /// __int16
    pub const BT_INT16: TypeT = 0x03;
    /// __int32
    pub const BT_INT32: TypeT = 0x04;
    /// __int64
    pub const BT_INT64: TypeT = 0x05;
    /// __int128 (for alpha & future use)
    pub const BT_INT128: TypeT = 0x06;
    /// natural int. (size provided by idp module)
    pub const BT_INT: TypeT = 0x07;
    /// unknown signedness
    pub const BTMT_UNKSIGN: TypeT = 0x00;
    /// signed
    pub const BTMT_SIGNED: TypeT = 0x10;
    /// unsigned
    pub const BTMT_UNSIGNED: TypeT = 0x20;
    /// specify char or segment register
    /// - [BT_INT8]         - char
    /// - [BT_INT]          - segment register
    /// - other [BT_INT]...   - don't use
    pub const BTMT_CHAR: TypeT = 0x30;
}

/// Basic type: bool
pub mod tf_bool {
    use super::TypeT;
    /// bool
    pub const BT_BOOL: TypeT = 0x08;
    /// bool size is model specific or unknown(?)
    pub const BTMT_DEFBOOL: TypeT = 0x00;
    /// bool sized 1byte
    pub const BTMT_BOOL1: TypeT = 0x10;
    /// bool sized 2bytes - !inf_is_64bit()
    pub const BTMT_BOOL2: TypeT = 0x20;
    /// bool sized 8bytes - inf_is_64bit()
    pub const BTMT_BOOL8: TypeT = 0x20;
    /// bool sized 4bytes
    pub const BTMT_BOOL4: TypeT = 0x30;
}

/// Basic type: float
pub mod tf_float {
    use super::TypeT;
    /// float
    pub const BT_FLOAT: TypeT = 0x09;
    /// float (4 bytes)
    pub const BTMT_FLOAT: TypeT = 0x00;
    /// double (8 bytes)
    pub const BTMT_DOUBLE: TypeT = 0x10;
    /// long double (compiler specific)
    pub const BTMT_LNGDBL: TypeT = 0x20;
    /// float (variable size). `if { use_tbyte } then { tbyte_size } else { 2 }`,
    pub const BTMT_SPECFLT: TypeT = 0x30;
}

/// Basic type: last
pub mod tf_last_basic {
    /// the last basic type, all basic types may be followed by `tah-typeattrs`
    pub const BT_LAST_BASIC: super::TypeT = super::tf_float::BT_FLOAT;
}

/// Derived type: pointer
/// Pointers to undeclared yet [tf_complex::BT_COMPLEX] types are prohibited
pub mod tf_ptr {
    use super::TypeT;
    /// pointer
    /// has the following format:
    /// `[db sizeof(ptr)]; [tah-typeattrs]; type_t...`
    pub const BT_PTR: TypeT = 0x0A;
    /// default for model
    pub const BTMT_DEFPTR: TypeT = 0x00;
    /// near
    pub const BTMT_NEAR: TypeT = 0x10;
    /// far
    pub const BTMT_FAR: TypeT = 0x20;
    /// closure
    /// - if ptr to [super::tf_func::BT_FUNC] - __closure.
    ///   in this case next byte MUST be
    ///   [super::RESERVED_BYTE], and after it [super::tf_func::BT_FUNC]
    /// - else the next byte contains size_of::<ptr>()
    ///   allowed values are 1 - `\varmem{ph,processor_t,max_ptr_size}`
    /// - if value is bigger than `\varmem{ph,processor_t,max_ptr_size}`,
    ///   based_ptr_name_and_size() is called to
    ///   find out the typeinfo
    pub const BTMT_CLOSURE: TypeT = 0x30;
}

/// Derived type: array
/// For [tf_array::BT_ARRAY], the BTMT_... flags must be equivalent to the BTMT_... flags of its elements
pub mod tf_array {
    use super::TypeT;
    /// array
    pub const BT_ARRAY: TypeT = 0x0B;

    /// code
    /// ```custom,{class=text}
    /// if set
    ///    array base==0
    ///    format: dt num_elem; [tah-typeattrs]; type_t...
    ///    if num_elem==0 then the array size is unknown
    /// else
    ///    format: da num_elem, base; [tah-typeattrs]; type_t... \endcode
    /// ```
    /// used only for serialization
    pub const BTMT_NONBASED: TypeT = 0x10;
    /// reserved bit
    pub const BTMT_ARRESERV: TypeT = 0x20;
}

/// \defgroup tf_func Derived type: function
///  Ellipsis is not taken into account in the number of parameters//
///  The return type cannot be ::BT_ARRAY or ::BT_FUNC.
///
pub mod tf_func {
    use super::TypeT;
    /// function.
    /// format: <pre>
    ///  optional:
    /// ```custom,{class=text}
    ///   ::CM_CC_SPOILED | num_of_spoiled_regs
    ///   if num_of_spoiled_reg == BFA_FUNC_MARKER:
    ///     ::bfa_byte
    ///     if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0
    ///      ::fti_bits (only low bits: FTI_SPOILED,...,FTI_VIRTUAL)
    ///      num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
    ///     else
    ///       bfa_byte is function attribute byte (see \ref BFA_...)
    ///   else:
    ///     num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
    /// ```
    ///  ::cm_t ... calling convention and memory model
    ///  [tah-typeattrs];
    ///  ::type_t ... return type;
    ///  [serialized argloc_t of returned value (if ::CM_CC_SPECIAL{PE} && !return void);
    /// ```custom,{class=text}
    ///  if !::CM_CC_VOIDARG:
    ///    dt N (N=number of parameters)
    ///    if ( N == 0 )
    ///    if ::CM_CC_ELLIPSIS or ::CM_CC_SPECIALE
    ///        func(...)
    ///      else
    ///        parameters are unknown
    ///    else
    ///      N records:
    ///        ::type_t ... (i.e. type of each parameter)
    ///        [serialized argloc_t (if ::CM_CC_SPECIAL{PE})] (i.e. place of each parameter)
    ///        [#FAH_BYTE + de( \ref funcarg_t::flags )] </pre>
    /// ```
    pub const BT_FUNC: TypeT = 0x0C;

    ///< call method - default for model or unknown
    pub const BTMT_DEFCALL: TypeT = 0x00;
    ///< function returns by retn
    pub const BTMT_NEARCALL: TypeT = 0x10;
    ///< function returns by retf
    pub const BTMT_FARCALL: TypeT = 0x20;
    ///< function returns by iret
    ///< in this case cc MUST be 'unknown'
    pub const BTMT_INTCALL: TypeT = 0x30;
}

/// Derived type: complex
pub mod tf_complex {
    use super::TypeT;
    /// struct/union/enum/typedef.
    /// format: <pre>:
    /// ```custom,{class=text}
    ///   [dt N (N=field count) if !::BTMT_TYPEDEF]
    ///   if N == 0:
    ///     p_string name (unnamed types have names "anon_...")
    ///     [sdacl-typeattrs];
    ///   else, for struct & union:
    ///     if N == 0x7FFE   // Support for high (i.e., > 4095) members count
    ///       N = deserialize_de()
    ///     ALPOW = N & 0x7
    ///     MCNT = N >> 3
    ///     if MCNT == 0
    ///       empty struct
    ///     if ALPOW == 0
    ///       ALIGN = get_default_align()
    ///     else
    ///       ALIGN = (1 << (ALPOW - 1))
    ///     [sdacl-typeattrs];
    ///   else, for enums:
    ///     if N == 0x7FFE   // Support for high enum entries count.
    ///       N = deserialize_de()
    ///     [tah-typeattrs]; </pre>
    /// ```
    pub const BT_COMPLEX: TypeT = 0x0D;
    /// struct
    /// `MCNT records: type_t; [sdacl-typeattrs];`
    pub const BTMT_STRUCT: TypeT = 0x00;
    /// union
    /// `MCNT records: type_t...`
    pub const BTMT_UNION: TypeT = 0x10;
    /// enum
    /// ```custom,{class=text}
    ///   next byte bte_t (see below)
    ///   N records: de delta(s)
    ///              OR
    ///              blocks (see below)
    /// ```
    pub const BTMT_ENUM: TypeT = 0x20;
    /// named reference
    /// `always p_string name`
    pub const BTMT_TYPEDEF: TypeT = 0x30;
    /// bitfield (only in struct)
    /// ```custom,{class=text}
    /// ['bitmasked' enum see below]
    /// next byte is dt
    ///  ((size in bits << 1) | (unsigned ? 1 : 0))
    /// ```
    pub const BT_BITFIELD: TypeT = 0x0E;
    /// __int8
    pub const BTMT_BFLDI8: TypeT = 0x00;
    /// __int16
    pub const BTMT_BFLDI16: TypeT = 0x10;
    /// __int32
    pub const BTMT_BFLDI32: TypeT = 0x20;
    /// __int64
    pub const BTMT_BFLDI64: TypeT = 0x30;
}

/// RESERVED
pub const BT_RESERVED: TypeT = 0x0F;

/// Type modifiers
/// "pub const volatile" types are forbidden
pub mod tf_modifiers {
    use super::TypeT;
    /// const
    pub const BTM_CONST: TypeT = 0x40;
    /// volatile
    pub const BTM_VOLATILE: TypeT = 0x80;
}

/// Special enum definitions
pub mod tf_enum {
    use super::BteT;
    /// storage size.
    ///   - if == 0 then inf_get_cc_size_e()
    ///   - else 1 << (n -1) = 1,2,4...64
    pub const BTE_SIZE_MASK: BteT = 0x07;
    /// must be 0, in order to distinguish from a tah-byte
    pub const BTE_RESERVED: BteT = 0x08;
    /// 'subarrays'. In this case ANY record
    /// has the following format:
    ///   - 'de' mask (has name)
    ///   - 'dt' cnt
    ///   - cnt records of 'de' values
    ///      (cnt CAN be 0)
    /// NOTE: delta for ALL subsegment is ONE
    pub const BTE_BITFIELD: BteT = 0x10;
    /// output style mask
    pub const BTE_OUT_MASK: BteT = 0x60;
    /// hex
    pub const BTE_HEX: BteT = 0x00;
    /// char or hex
    pub const BTE_CHAR: BteT = 0x20;
    /// signed decimal
    pub const BTE_SDEC: BteT = 0x40;
    /// unsigned decimal
    pub const BTE_UDEC: BteT = 0x60;
    /// this bit MUST be present
    pub const BTE_ALWAYS: BteT = 0x80;
}

/// Convenience definitions: segment register
pub mod tf_conv_segreg {
    use super::{tf_int, TypeT};
    /// segment register
    pub const BT_SEGREG: TypeT = tf_int::BT_INT | tf_int::BTMT_CHAR;
}

/// Convenience definitions: unknown types
pub mod tf_conv_unk {
    use super::{tf_unk, TypeT};
    /// 1 byte
    pub const BT_UNK_BYTE: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE12;
    /// 2 bytes
    pub const BT_UNK_WORD: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE12;
    /// 4 bytes
    pub const BT_UNK_DWORD: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE48;
    /// 8 bytes
    pub const BT_UNK_QWORD: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE48;
    /// 16 bytes
    pub const BT_UNK_OWORD: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE128;
    /// unknown size - for parameters
    pub const BT_UNKNOWN: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE128;
}

/// Convenience definitions: shortcuts
pub mod tf_shortcuts {
    use super::{tf_bool, tf_complex, tf_conv_unk, tf_float, tf_int, tf_unk, TypeT};
    /// byte
    pub const BTF_BYTE: TypeT = tf_conv_unk::BT_UNK_BYTE;
    /// unknown
    pub const BTF_UNK: TypeT = tf_conv_unk::BT_UNKNOWN;
    /// void
    pub const BTF_VOID: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE0;

    /// signed byte
    pub const BTF_INT8: TypeT = tf_int::BT_INT8 | tf_int::BTMT_SIGNED;
    /// signed char
    pub const BTF_CHAR: TypeT = tf_int::BT_INT8 | tf_int::BTMT_CHAR;
    /// unsigned char
    pub const BTF_UCHAR: TypeT = tf_int::BT_INT8 | tf_int::BTMT_UNSIGNED;
    /// unsigned byte
    pub const BTF_UINT8: TypeT = tf_int::BT_INT8 | tf_int::BTMT_UNSIGNED;

    /// signed short
    pub const BTF_INT16: TypeT = tf_int::BT_INT16 | tf_int::BTMT_SIGNED;
    /// unsigned short
    pub const BTF_UINT16: TypeT = tf_int::BT_INT16 | tf_int::BTMT_UNSIGNED;

    /// signed int
    pub const BTF_INT32: TypeT = tf_int::BT_INT32 | tf_int::BTMT_SIGNED;
    /// unsigned int
    pub const BTF_UINT32: TypeT = tf_int::BT_INT32 | tf_int::BTMT_UNSIGNED;

    /// signed long
    pub const BTF_INT64: TypeT = tf_int::BT_INT64 | tf_int::BTMT_SIGNED;
    /// unsigned long
    pub const BTF_UINT64: TypeT = tf_int::BT_INT64 | tf_int::BTMT_UNSIGNED;

    /// signed 128-bit value
    pub const BTF_INT128: TypeT = tf_int::BT_INT128 | tf_int::BTMT_SIGNED;
    /// unsigned 128-bit value
    pub const BTF_UINT128: TypeT = tf_int::BT_INT128 | tf_int::BTMT_UNSIGNED;

    /// int, unknown signedness
    pub const BTF_INT: TypeT = tf_int::BT_INT | tf_int::BTMT_UNKSIGN;
    /// unsigned int
    pub const BTF_UINT: TypeT = tf_int::BT_INT | tf_int::BTMT_UNSIGNED;
    /// singed int
    pub const BTF_SINT: TypeT = tf_int::BT_INT | tf_int::BTMT_SIGNED;

    /// boolean
    pub const BTF_BOOL: TypeT = tf_bool::BT_BOOL;

    /// float
    pub const BTF_FLOAT: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_FLOAT;
    /// double
    pub const BTF_DOUBLE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_DOUBLE;
    /// long double
    pub const BTF_LDOUBLE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_LNGDBL;
    /// see [tf_float::BTMT_SPECFLT]
    pub const BTF_TBYTE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_SPECFLT;

    /// struct
    pub const BTF_STRUCT: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_STRUCT;
    /// union
    pub const BTF_UNION: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_UNION;
    /// enum
    pub const BTF_ENUM: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_ENUM;
    /// typedef
    pub const BTF_TYPEDEF: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_TYPEDEF;
}

/// pack buckets using zip
pub const TIL_ZIP: u32 = 0x0001;
/// til has macro table
pub const TIL_MAC: u32 = 0x0002;
/// extended sizeof info (short, long, longlong)
pub const TIL_ESI: u32 = 0x0004;
/// universal til for any compiler
pub const TIL_UNI: u32 = 0x0008;
/// type ordinal numbers are present
pub const TIL_ORD: u32 = 0x0010;
/// type aliases are present (this bit is used only on the disk)
pub const TIL_ALI: u32 = 0x0020;
/// til has been modified, should be saved
pub const TIL_MOD: u32 = 0x0040;
/// til has extra streams
pub const TIL_STM: u32 = 0x0080;
/// sizeof(long double)
pub const TIL_SLD: u32 = 0x0100;

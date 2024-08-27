use std::collections::HashMap;

use binaryninja::architecture::{Architecture, CoreArchitecture};
use binaryninja::binaryninjacore_sys::{BNMemberAccess, BNMemberScope};
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser};
use binaryninja::logger;
use binaryninja::rc::Ref;
use binaryninja::types::{
    Conf, EnumerationBuilder, FunctionParameter, NamedTypeReferenceClass, StructureBuilder,
    StructureType, Type,
};

use idb_rs::{TILSection, TILTypeInfo};

use log::{error, trace, warn, LevelFilter};

use anyhow::Result;

#[derive(Debug, Clone)]
enum BnTypeError {
    // TODO delete this and make this verification during the TIL/IDB parsing, translating the ordinal
    // into a kind of type_idx
    OrdinalNotFound(u32),
    NameNotFound(String),

    //TypedefNameNotFound(String),
    FunctionReturn(Box<BnTypeError>),
    FunctionArg(Box<BnTypeError>, usize),
    Array(Box<BnTypeError>),
    StructMember(Box<BnTypeError>, usize),
    UnionMember(Box<BnTypeError>, usize),
}

impl std::fmt::Display for BnTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BnTypeError::OrdinalNotFound(i) => write!(f, "Reference to non existing Ordinal {i}"),
            BnTypeError::NameNotFound(name) => write!(f, "Reference to non existing name {name}"),
            BnTypeError::FunctionReturn(error) => {
                write!(f, "Function return: {error}")
            }
            BnTypeError::FunctionArg(error, i) => {
                write!(f, "Function argument {i}: {error}")
            }
            BnTypeError::Array(error) => write!(f, "Array: {error}"),
            BnTypeError::StructMember(error, i) => {
                write!(f, "StructMember {i}: {error}")
            }
            BnTypeError::UnionMember(error, i) => {
                write!(f, "Union member {i}: {error}")
            }
        }
    }
}

struct IDBDebugInfoParser;
impl CustomDebugInfoParser for IDBDebugInfoParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        view.file().filename().as_str().ends_with(".i64")
            || view.file().filename().as_str().ends_with(".idb")
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        _bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match parse_idb_info(debug_info, debug_file, progress) {
            Ok(()) => true,
            Err(error) => {
                error!("Unable to parse IDB file: {error}");
                false
            }
        }
    }
}

struct TILDebugInfoParser;
impl CustomDebugInfoParser for TILDebugInfoParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        view.file().filename().as_str().ends_with(".til")
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        _bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match parse_til_info(debug_info, debug_file, progress) {
            Ok(()) => true,
            Err(error) => {
                error!("Unable to parse TIL file: {error}");
                false
            }
        }
    }
}

struct BinaryViewReader<'a> {
    bv: &'a BinaryView,
    offset: u64,
}
impl std::io::Read for BinaryViewReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.bv.offset_valid(self.offset) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
        }
        let len = self.bv.read(buf, self.offset);
        self.offset += u64::try_from(len).unwrap();
        Ok(len)
    }
}

impl std::io::Seek for BinaryViewReader<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_offset = match pos {
            std::io::SeekFrom::Start(offset) => Some(offset),
            std::io::SeekFrom::End(end) => u64::try_from(self.bv.len())
                .unwrap()
                .checked_add_signed(end),
            std::io::SeekFrom::Current(next) => self.offset.checked_add_signed(next),
        };
        let new_offset =
            new_offset.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""))?;
        if !self.bv.offset_valid(new_offset) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
        }
        self.offset = new_offset;
        Ok(new_offset)
    }
}

fn parse_idb_info(
    debug_info: &mut DebugInfo,
    debug_file: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    trace!("Opening a IDB file");
    let file = BinaryViewReader {
        bv: debug_file,
        offset: 0,
    };
    trace!("Parsing a IDB file");
    let file = std::io::BufReader::new(file);
    let mut parser = idb_rs::IDBParser::new(file)?;
    let Some(til_section) = parser.til_section() else {
        return Ok(());
    };
    trace!("Parsing the TIL section");
    let til = parser.read_til_section(til_section)?;
    parse_til_section_info(debug_info, debug_file, &til, progress)
}

fn translate_enum(members: &[(Option<String>, u64)], bytesize: u64) -> Ref<Type> {
    let eb = EnumerationBuilder::new();
    for (i, (name, bytesize)) in members.iter().enumerate() {
        let name = name.to_owned().unwrap_or_else(|| format!("member_{i}"));
        eb.insert(name, *bytesize);
    }
    Type::enumeration(
        &eb.finalize(),
        usize::try_from(bytesize).unwrap(),
        Conf::new(false, 0),
    )
}

fn translate_basic(mdata: &idb_rs::til::Basic, arch: CoreArchitecture) -> Ref<Type> {
    match mdata {
        idb_rs::til::Basic::Void => Type::void(),
        idb_rs::til::Basic::Unknown { bytes } => {
            if let Some(bytes) = bytes {
                Type::array(&Type::char(), bytes.get().into())
            } else {
                Type::void()
            }
        }
        idb_rs::til::Basic::Bool { bytes } => {
            if let Some(bytes) = bytes {
                // NOTE Binja don't have any representation for bool other then the default
                Type::int(bytes.get().into(), false)
            } else {
                Type::bool()
            }
        }
        idb_rs::til::Basic::Char => Type::char(),
        // TODO what exacly is Segment Register?
        idb_rs::til::Basic::SegReg => Type::char(),
        idb_rs::til::Basic::Int { bytes, is_signed } => {
            // default into signed
            let is_signed = is_signed.as_ref().copied().unwrap_or(true);
            let bytes = bytes
                .map(|x| x.get().into())
                .unwrap_or_else(|| arch.default_integer_size());
            Type::int(bytes, is_signed)
        }
        idb_rs::til::Basic::Float { bytes } => {
            // TODO find a beter way to define the default float size
            let bytes = bytes
                .map(|x| x.get().into())
                .unwrap_or_else(|| arch.default_integer_size());
            Type::float(bytes)
        }
    }
}

fn parse_til_info(
    debug_info: &mut DebugInfo,
    debug_file: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    trace!("Opening a TIL file");
    let file = BinaryViewReader {
        bv: debug_file,
        offset: 0,
    };
    let file = std::io::BufReader::new(file);
    trace!("Parsing the TIL section");
    let til = idb_rs::TILSection::parse(file)?;
    parse_til_section_info(debug_info, debug_file, &til, progress)
}

#[derive(Default)]
enum TranslateTypeResult {
    #[default]
    NotYet,
    Error(BnTypeError),
    // a type that is not final, but equivalent to the final type
    PartiallyTranslated(Ref<Type>),
    Translated(Ref<Type>),
}

impl From<Result<Ref<Type>, BnTypeError>> for TranslateTypeResult {
    fn from(value: Result<Ref<Type>, BnTypeError>) -> Self {
        match value {
            Ok(ty) => Self::Translated(ty),
            Err(error) => Self::Error(error),
        }
    }
}

struct TranslatesIDBType<'a> {
    // sanitized name form IDB
    name: String,
    // class, just to make easy to create named_type
    _class: NamedTypeReferenceClass,
    // the result, if converted
    ty: TranslateTypeResult,
    og_ty: &'a TILTypeInfo,
    is_symbol: bool,
}

struct TranslateIDBTypes<'a> {
    debug_info: &'a mut DebugInfo,
    _debug_file: &'a BinaryView,
    arch: CoreArchitecture,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    _til: &'a TILSection,
    // note it's mapped 1:1 with the same index from til types.chain(symbols)
    types: Vec<TranslatesIDBType<'a>>,
    // ordinals with index to types
    types_by_ord: HashMap<u64, usize>,
    // original names with index to types
    types_by_name: HashMap<String, usize>,
}

impl TranslateIDBTypes<'_> {
    fn find_typedef_by_ordinal(&self, ord: u64) -> Option<TranslateTypeResult> {
        self.types_by_ord
            .get(&ord)
            .map(|idx| self.find_typedef(&self.types[*idx]))
    }

    fn find_typedef_by_name(&self, name: &str) -> Option<TranslateTypeResult> {
        if name.is_empty() {
            // TODO this is my assumption, maybe an empty names Typedef means something else.
            return Some(TranslateTypeResult::Translated(Type::void()));
        }

        if let Some(other_ty) = self
            .types_by_name
            .get(name)
            .map(|idx| self.find_typedef(&self.types[*idx]))
        {
            return Some(other_ty);
        }

        // check for types that ar usually not defined directly
        match name {
            "Unkown" | "uint8_t" => Some(TranslateTypeResult::Translated(Type::int(1, false))),
            "IUnkown" | "int8_t" => Some(TranslateTypeResult::Translated(Type::int(1, true))),
            // TODO SHORT changes with ARCH?
            "SHORT" | "int16_t" => Some(TranslateTypeResult::Translated(Type::int(2, true))),
            "USHORT" | "uint16_t" => Some(TranslateTypeResult::Translated(Type::int(2, false))),
            "int32_t" => Some(TranslateTypeResult::Translated(Type::int(4, true))),
            "uint32_t" => Some(TranslateTypeResult::Translated(Type::int(4, false))),
            "int64_t" => Some(TranslateTypeResult::Translated(Type::int(8, true))),
            "uint64_t" => Some(TranslateTypeResult::Translated(Type::int(8, false))),
            "int128_t" => Some(TranslateTypeResult::Translated(Type::int(16, true))),
            "uint128_t" => Some(TranslateTypeResult::Translated(Type::int(16, false))),
            _ => None,
        }
    }

    fn find_typedef(&self, ty: &TranslatesIDBType) -> TranslateTypeResult {
        // only return a typedef, if it's solved, at least partially
        match &ty.ty {
            TranslateTypeResult::NotYet => TranslateTypeResult::NotYet,
            TranslateTypeResult::Error(error) => TranslateTypeResult::Error(error.to_owned()),
            TranslateTypeResult::PartiallyTranslated(og_ty)
            | TranslateTypeResult::Translated(og_ty) => TranslateTypeResult::Translated(
                Type::named_type_from_type(ty.name.as_str(), &og_ty),
            ),
        }
    }

    fn translate_pointer(&self, ty: &idb_rs::til::Type) -> TranslateTypeResult {
        match self.translate_type(ty) {
            TranslateTypeResult::Translated(trans) => {
                TranslateTypeResult::Translated(Type::pointer(&self.arch, &trans))
            }
            TranslateTypeResult::PartiallyTranslated(trans) => {
                TranslateTypeResult::PartiallyTranslated(Type::pointer(&self.arch, &trans))
            }
            // NOTE don't propagate the error, just return an partial representation of the
            // type, AKA void*
            TranslateTypeResult::Error(_) | TranslateTypeResult::NotYet => {
                TranslateTypeResult::PartiallyTranslated(Type::pointer(&self.arch, &Type::void()))
            }
        }
    }

    fn translate_function(&self, fun: &idb_rs::til::Function) -> TranslateTypeResult {
        let mut is_partial = false;
        // funtions are always 0 len, so it's translated or partial(void)
        let return_ty = match self.translate_type(&fun.ret) {
            TranslateTypeResult::Translated(trans) => trans,
            TranslateTypeResult::PartiallyTranslated(trans) => {
                is_partial = true;
                trans
            }
            TranslateTypeResult::Error(error) => {
                return TranslateTypeResult::Error(BnTypeError::FunctionReturn(Box::new(error)))
            }
            TranslateTypeResult::NotYet => {
                return TranslateTypeResult::PartiallyTranslated(Type::void())
            }
        };
        let mut bn_args = Vec::with_capacity(fun.args.len());
        for (i, (arg_name, arg_type, _arg_loc)) in fun.args.iter().enumerate() {
            let arg = match self.translate_type(arg_type) {
                TranslateTypeResult::Translated(trans) => trans,
                TranslateTypeResult::PartiallyTranslated(trans) => {
                    is_partial = true;
                    trans
                }
                TranslateTypeResult::NotYet => {
                    return TranslateTypeResult::PartiallyTranslated(Type::void())
                }
                TranslateTypeResult::Error(error) => {
                    return TranslateTypeResult::Error(BnTypeError::FunctionArg(Box::new(error), i))
                }
            };
            // TODO create location from `arg_loc`?
            let loc = None;
            let name = arg_name.to_owned().unwrap_or_else(|| format!("arg_{i}"));
            bn_args.push(FunctionParameter::new(arg, name, loc));
        }

        let ty = Type::function(&return_ty, &bn_args, false);
        if is_partial {
            TranslateTypeResult::PartiallyTranslated(ty)
        } else {
            TranslateTypeResult::Translated(ty)
        }
    }

    fn translate_array(&self, array: &idb_rs::til::Array) -> TranslateTypeResult {
        match self.translate_type(&*array.elem_type) {
            TranslateTypeResult::NotYet => TranslateTypeResult::NotYet,
            TranslateTypeResult::Translated(ty) => {
                TranslateTypeResult::Translated(Type::array(&ty, array.nelem.into()))
            }
            TranslateTypeResult::PartiallyTranslated(ty) => {
                TranslateTypeResult::PartiallyTranslated(Type::array(&ty, array.nelem.into()))
            }
            TranslateTypeResult::Error(error) => {
                TranslateTypeResult::Error(BnTypeError::Array(Box::new(error)))
            }
        }
    }

    fn translate_bitfields_into_struct(
        &self,
        offset: usize,
        members_slice: &[idb_rs::til::StructMember],
        struct_builder: &StructureBuilder,
    ) {
        if members_slice.is_empty() {
            unreachable!()
        }
        let mut members = members_slice
            .iter()
            .map(|ty| match &ty.member_type {
                idb_rs::til::Type::Bitfield(b) => b,
                _ => unreachable!(),
            })
            .enumerate();
        let (_, first_field) = members.next().unwrap();
        let mut current_field_bytes = first_field.nbytes;
        let mut current_field_bits: u32 = first_field.width.into();
        let mut start_idx = 0;

        let create_field = |start_idx, i, bytes| {
            let name = if start_idx == i - 1 {
                let member: &idb_rs::til::StructMember = &members_slice[i - 1];
                let name: &Option<String> = &member.name;
                name.to_owned()
                    .unwrap_or_else(|| format!("bitfield_{}", offset + start_idx))
            } else {
                format!("bitfield_{}_{}", offset + start_idx, offset + (i - 1))
            };
            let field = field_from_bytes(bytes);
            struct_builder.append(
                &field,
                name,
                BNMemberAccess::NoAccess,
                BNMemberScope::NoScope,
            );
        };

        for (i, member) in members {
            // starting a new field
            let max_bits = u32::try_from(current_field_bytes).unwrap() * 8;
            // this bitfield start a a new field, or can't contain other bitfields
            // finish the previous and start a new
            if current_field_bytes != member.nbytes
                || max_bits < current_field_bits + u32::from(member.width)
            {
                create_field(start_idx, i, current_field_bytes);
                current_field_bytes = member.nbytes;
                current_field_bits = 0;
                start_idx = i;
            }

            // just add the current bitfield into the field
            current_field_bits += u32::from(member.width);
        }

        if current_field_bits != 0 {
            create_field(start_idx, members_slice.len(), current_field_bytes);
        }
    }

    fn translate_struct(
        &self,
        members: &[idb_rs::til::StructMember],
        effective_alignment: u16,
    ) -> TranslateTypeResult {
        if members.is_empty() {
            // binary ninja crashes if you create an empty struct, because it divide by 0
            return TranslateTypeResult::Translated(Type::void());
        }
        let mut is_partial = false;
        let structure = StructureBuilder::new();
        structure.set_alignment(effective_alignment.into());

        let mut first_bitfield_seq = None;
        for (i, member) in members.iter().enumerate() {
            match (&member.member_type, first_bitfield_seq) {
                // accumulate the bitfield to be condensated
                (idb_rs::til::Type::Bitfield(_bit), None) => {
                    first_bitfield_seq = Some(i);
                    continue;
                }
                (idb_rs::til::Type::Bitfield(_bit), Some(_)) => continue,

                // condensate the bitfields into byte-wide fields
                (_, Some(start_idx)) => {
                    first_bitfield_seq = None;
                    let members_bitrange = &members[start_idx..i];
                    self.translate_bitfields_into_struct(start_idx, members_bitrange, &structure);
                }

                (_, None) => {}
            }

            let mem = match self.translate_type(&member.member_type) {
                TranslateTypeResult::Translated(ty) => ty,
                TranslateTypeResult::PartiallyTranslated(partial_ty) => {
                    is_partial = true;
                    partial_ty
                }
                TranslateTypeResult::NotYet => return TranslateTypeResult::NotYet,
                TranslateTypeResult::Error(error) => {
                    return TranslateTypeResult::Error(BnTypeError::StructMember(
                        Box::new(error),
                        i,
                    ))
                }
            };
            let name = member
                .name
                .to_owned()
                .unwrap_or_else(|| format!("member_{i}"));
            structure.append(&mem, name, BNMemberAccess::NoAccess, BNMemberScope::NoScope);
        }
        if let Some(start_idx) = first_bitfield_seq {
            let members_bitrange = &members[start_idx..];
            self.translate_bitfields_into_struct(start_idx, members_bitrange, &structure);
        }
        let bn_ty = Type::structure(&structure.finalize());
        if is_partial {
            TranslateTypeResult::PartiallyTranslated(bn_ty)
        } else {
            TranslateTypeResult::Translated(bn_ty)
        }
    }

    fn translate_union(
        &self,
        members: &[(Option<String>, idb_rs::til::Type)],
        _effective_alignment: u16,
    ) -> TranslateTypeResult {
        let mut is_partial = false;
        let structure = StructureBuilder::new();
        structure.set_structure_type(StructureType::UnionStructureType);
        for (i, (member_name, member_type)) in members.iter().enumerate() {
            // bitfields can be translated into complete fields
            let mem = match member_type {
                idb_rs::til::Type::Bitfield(field) => field_from_bytes(field.nbytes),
                member_type => match self.translate_type(member_type) {
                    TranslateTypeResult::Translated(ty) => ty,
                    TranslateTypeResult::Error(error) => {
                        return TranslateTypeResult::Error(BnTypeError::UnionMember(
                            Box::new(error),
                            i,
                        ))
                    }
                    TranslateTypeResult::NotYet => return TranslateTypeResult::NotYet,
                    TranslateTypeResult::PartiallyTranslated(partial) => {
                        is_partial = true;
                        partial
                    }
                },
            };

            let name = member_name
                .to_owned()
                .unwrap_or_else(|| format!("member_{i}"));
            structure.append(&mem, name, BNMemberAccess::NoAccess, BNMemberScope::NoScope);
        }
        let str_ref = structure.finalize();

        let bn_ty = Type::structure(&str_ref);
        if is_partial {
            TranslateTypeResult::PartiallyTranslated(bn_ty)
        } else {
            TranslateTypeResult::Translated(bn_ty)
        }
    }

    fn translate_type(&self, ty: &idb_rs::til::Type) -> TranslateTypeResult {
        match &ty {
            // types that are always translatable
            idb_rs::til::Type::Basic(meta) => {
                TranslateTypeResult::Translated(translate_basic(meta, self.arch))
            }
            idb_rs::til::Type::Bitfield(bit) => {
                TranslateTypeResult::Translated(field_from_bytes(bit.nbytes))
            }
            idb_rs::til::Type::Enum(idb_rs::til::Enum::NonRef {
                members, bytesize, ..
            }) => TranslateTypeResult::Translated(translate_enum(members, *bytesize)),
            idb_rs::til::Type::Typedef(idb_rs::til::Typedef::Ordinal(ord)) => self
                .find_typedef_by_ordinal((*ord).into())
                .unwrap_or_else(|| TranslateTypeResult::Error(BnTypeError::OrdinalNotFound(*ord))),
            idb_rs::til::Type::Typedef(idb_rs::til::Typedef::Name(name)) => {
                self.find_typedef_by_name(name).unwrap_or_else(|| {
                    TranslateTypeResult::Error(BnTypeError::NameNotFound(name.to_owned()))
                })
            }

            // may not be translatable imediatly, but the size is known and can be
            // updated after alBasicers are finished
            idb_rs::til::Type::Union(idb_rs::til::Union::Ref { ref_type, .. })
            | idb_rs::til::Type::Struct(idb_rs::til::Struct::Ref { ref_type, .. })
            | idb_rs::til::Type::Enum(idb_rs::til::Enum::Ref { ref_type, .. }) => {
                self.translate_pointer(&**ref_type)
            }
            idb_rs::til::Type::Pointer(ty) => self.translate_pointer(&ty.typ),
            idb_rs::til::Type::Function(fun) => self.translate_function(fun),

            // can only be partially solved if all fields are solved or partially solved
            idb_rs::til::Type::Array(array) => self.translate_array(array),
            idb_rs::til::Type::Struct(idb_rs::til::Struct::NonRef {
                members,
                effective_alignment,
                ..
            }) => self.translate_struct(members, *effective_alignment),
            idb_rs::til::Type::Union(idb_rs::til::Union::NonRef {
                members,
                effective_alignment,
                ..
            }) => self.translate_union(members, *effective_alignment),
        }
    }
}

fn find_typedef_named_type_class(ty: &idb_rs::til::Type) -> NamedTypeReferenceClass {
    match ty {
        idb_rs::til::Type::Typedef(_) => NamedTypeReferenceClass::TypedefNamedTypeClass,
        idb_rs::til::Type::Struct(_) => NamedTypeReferenceClass::StructNamedTypeClass,
        idb_rs::til::Type::Union(_) => NamedTypeReferenceClass::UnionNamedTypeClass,
        idb_rs::til::Type::Enum(_) => NamedTypeReferenceClass::EnumNamedTypeClass,
        _ => NamedTypeReferenceClass::UnknownNamedTypeClass,
    }
}

fn field_from_bytes(bytes: i32) -> Ref<Type> {
    match bytes {
        0 => unreachable!(),
        num @ (1 | 2 | 4 | 8 | 16) => Type::int(num.try_into().unwrap(), false),
        nelem => Type::array(&Type::char(), nelem.try_into().unwrap()),
    }
}

fn parse_til_section_info(
    debug_info: &mut DebugInfo,
    debug_file: &BinaryView,
    til: &TILSection,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    let total = til.symbols.len() + til.types.len();
    let mut types = Vec::with_capacity(total);
    let mut types_by_ord = HashMap::with_capacity(total);
    let mut types_by_name = HashMap::with_capacity(total);
    let all_types = til.types.iter().zip(core::iter::repeat(false));
    // TODO: it's unclear how the demangle symbols and types names/ord, for now only parse types
    //let all_types = all_types.chain(til.symbols.iter().zip(core::iter::repeat(true)));
    for (i, (ty, is_symbol)) in all_types.enumerate() {
        // TODO sanitized the input
        // TODO find out how the namespaces used by TIL works
        let name = ty.name.to_owned();
        types.push(TranslatesIDBType {
            name,
            is_symbol,
            og_ty: ty,
            _class: find_typedef_named_type_class(&ty.tinfo),
            ty: TranslateTypeResult::NotYet,
        });
        if ty.ordinal != 0 && !is_symbol {
            let dup1 = types_by_ord.insert(ty.ordinal, i);
            if let Some(old) = dup1 {
                let old_type = &types[old];
                let new_type = types.last().unwrap();
                // TODO error?
                panic!(
                    "dup ord {}:{} {}:\n{:?}\n{:?}",
                    old_type.is_symbol,
                    new_type.is_symbol,
                    ty.ordinal,
                    &old_type.og_ty,
                    &new_type.og_ty,
                )
            }
        }
        if ty.name != "" {
            let dup2 = types_by_name.insert(ty.name.to_owned(), i);
            if let Some(old) = dup2 {
                let old_type = &types[old];
                let new_type = types.last().unwrap();
                // TODO error?
                panic!(
                    "dup name {}:{}: {}:\n{:?}\n{:?}",
                    old_type.is_symbol,
                    new_type.is_symbol,
                    &ty.name,
                    &old_type.og_ty,
                    &new_type.og_ty,
                )
            }
        }
    }

    let mut translator = TranslateIDBTypes {
        debug_info,
        _debug_file: debug_file,
        arch: debug_file.default_arch().unwrap(/* TODO */),
        progress,
        _til: til,
        types,
        types_by_ord,
        types_by_name,
    };
    if (translator.progress)(0, total).is_err() {
        warn!("IDB import aborted");
        return Ok(());
    }

    // solve types until there is nothing else being solved
    loop {
        // is something was solved, mark this variable as true
        let mut did_something = false;
        let mut num_translated = 0usize;
        for i in 0..translator.types.len() {
            match &translator.types[i].ty {
                TranslateTypeResult::NotYet => {
                    let result = translator.translate_type(&translator.types[i].og_ty.tinfo);
                    did_something |= !matches!(&result, TranslateTypeResult::NotYet);
                    translator.types[i].ty = result;
                    // if originaly NotKnow and now translated, update the result on bn
                    match &translator.types[i].ty {
                        TranslateTypeResult::PartiallyTranslated(bn_ty)
                        | TranslateTypeResult::Translated(bn_ty) => {
                            let name = &translator.types[i].name;
                            let success =
                                translator.debug_info.add_type(name, &bn_ty, &[/* TODO */]);
                            if !success {
                                error!("Unable to add type `{}`", name)
                            }
                        }
                        _ => {}
                    }
                }
                TranslateTypeResult::PartiallyTranslated(_) => {
                    let result = translator.translate_type(&translator.types[i].og_ty.tinfo);
                    did_something |=
                        !matches!(&result, TranslateTypeResult::PartiallyTranslated(_));
                    translator.types[i].ty = result;
                }
                // NOTE for now we are just accumulating errors, just try to translate the max number
                // of types as possible
                TranslateTypeResult::Error(_) => {}
                // already translated, nothing do to here
                TranslateTypeResult::Translated(_) => {}
            }

            // count the number of finished types
            match &translator.types[i].ty {
                TranslateTypeResult::Translated(_) => num_translated += 1,
                _ => {}
            }
        }

        if !did_something {
            // means we acomplilshed nothing during this loop, there is no point in trying again
            break;
        }
        if (translator.progress)(num_translated, total).is_err() {
            // error means the user aborted the progress
            break;
        }
    }

    // print any errors
    for ty in &translator.types {
        match &ty.ty {
            TranslateTypeResult::Error(error) => {
                error!("Unable to parse type `{}`: {error}", &ty.name);
            }
            TranslateTypeResult::NotYet => {
                error!("Unable to parse type `{}`", &ty.name);
            }
            TranslateTypeResult::PartiallyTranslated(_) => {
                error!("Unable to parse type `{}` correctly", &ty.name);
            }
            TranslateTypeResult::Translated(_) => {}
        };
    }

    // add a second time to fix the references LOL
    for ty in &translator.types {
        match &ty.ty {
            TranslateTypeResult::Translated(bn_ty)
            | TranslateTypeResult::PartiallyTranslated(bn_ty) => {
                let success = translator
                    .debug_info
                    .add_type(&ty.name, &bn_ty, &[/* TODO */]);
                if !success {
                    error!("Unable to fix type `{}`", &ty.name)
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    let _logger = logger::init(LevelFilter::Error);
    DebugInfoParser::register("IDB Parser", IDBDebugInfoParser);
    DebugInfoParser::register("TIL Parser", TILDebugInfoParser);
    true
}

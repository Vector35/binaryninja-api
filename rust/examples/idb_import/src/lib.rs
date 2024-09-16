use std::collections::HashMap;

use binaryninja::architecture::CoreArchitecture;
use binaryninja::binaryninjacore_sys::{BNMemberAccess, BNMemberScope};
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{
    CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser,
};
use binaryninja::logger;
use binaryninja::rc::Ref;
use binaryninja::types::{
    Conf, EnumerationBuilder, FunctionParameter, NamedTypeReferenceClass, StructureBuilder,
    StructureType, Type,
};

use idb_rs::id0::ID0Section;
use idb_rs::til::{
    array::Array as TILArray, function::Function as TILFunction, r#enum::Enum as TILEnum,
    r#struct::Struct as TILStruct, r#struct::StructMember as TILStructMember, section::TILSection,
    union::Union as TILUnion, TILTypeInfo, Type as TILType, Typedef as TILTypedef,
};

use log::{error, trace, warn, LevelFilter};

use anyhow::Result;

#[derive(Debug, Clone)]
enum BnTypeError {
    // TODO delete this and make this verification during the TIL/IDB parsing, translating the ordinal
    // into a kind of type_idx
    OrdinalNotFound(u32),
    NameNotFound(String),

    Typedef(Box<BnTypeError>),
    Function(FunctionError),
    Array(Box<BnTypeError>),
    Pointer(Box<BnTypeError>),
    /// Error for members
    Struct(Vec<(usize, BnTypeError)>),
    Union(Vec<(usize, BnTypeError)>),
}

#[derive(Default, Debug, Clone)]
struct FunctionError {
    ret: Option<Box<BnTypeError>>,
    args: Vec<(usize, BnTypeError)>,
}

impl std::fmt::Display for BnTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BnTypeError::OrdinalNotFound(i) => write!(f, "Reference to non existing Ordinal {i}"),
            BnTypeError::NameNotFound(name) => write!(f, "Reference to non existing name {name}"),
            BnTypeError::Typedef(error) => write!(f, "Typedef: {error}"),
            BnTypeError::Function(FunctionError { ret, args }) => {
                if let Some(error) = ret {
                    write!(f, "Function return: {error} ")?;
                }
                for (i, error) in args {
                    write!(f, "Function argument {i}: {error} ")?;
                }
                Ok(())
            }
            BnTypeError::Array(error) => write!(f, "Array: {error}"),
            BnTypeError::Struct(errors) => {
                for (i, error) in errors {
                    write!(f, "Struct Member {i}: {error} ")?;
                }
                Ok(())
            }
            BnTypeError::Union(errors) => {
                for (i, error) in errors {
                    write!(f, "Union Member {i}: {error} ")?;
                }
                Ok(())
            }
            BnTypeError::Pointer(error) => write!(f, "Pointer: {error}"),
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
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match parse_idb_info(debug_info, bv, debug_file, progress) {
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
    bv: &BinaryView,
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
    if let Some(til_section) = parser.til_section_offset() {
        trace!("Parsing the TIL section");
        let til = parser.read_til_section(til_section)?;
        // progress 0%-50%
        parse_til_section_info(debug_info, debug_file, til, |value, total| {
            progress(value, total.wrapping_mul(2))
        })?;
    }

    if let Some(id0_section) = parser.id0_section_offset() {
        trace!("Parsing the ID0 section");
        let id0 = parser.read_id0_section(id0_section)?;
        // progress 50%-100%
        parse_id0_section_info(debug_info, bv, debug_file, id0, |value, old_total| {
            let new_total = old_total.wrapping_mul(2);
            progress(value + old_total, new_total)
        })?;
    }

    Ok(())
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

fn translate_basic(mdata: &idb_rs::til::Basic) -> Ref<Type> {
    match *mdata {
        idb_rs::til::Basic::Void => Type::void(),
        idb_rs::til::Basic::Unknown { bytes: 0 } => Type::void(),
        idb_rs::til::Basic::Unknown { bytes } => Type::array(&Type::char(), bytes.into()),
        idb_rs::til::Basic::Bool { bytes } if bytes.get() == 1 => Type::bool(),
        // NOTE Binja don't have any representation for bool other then the default
        idb_rs::til::Basic::Bool { bytes } => Type::int(bytes.get().into(), false),
        idb_rs::til::Basic::Char => Type::char(),
        // TODO what exacly is Segment Register?
        idb_rs::til::Basic::SegReg => Type::char(),
        idb_rs::til::Basic::Int { bytes, is_signed } => {
            // default into signed
            let is_signed = is_signed.as_ref().copied().unwrap_or(true);
            Type::int(bytes.get().into(), is_signed)
        }
        idb_rs::til::Basic::Float { bytes } => Type::float(bytes.get().into()),
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
    let til = TILSection::parse(file)?;
    parse_til_section_info(debug_info, debug_file, til, progress)
}

#[derive(Default)]
enum TranslateTypeResult {
    #[default]
    NotYet,
    /// Unable to solve type, there is no point in trying again
    Error(BnTypeError),
    /// a type that is not final, but equivalent to the final type, if error, there is no
    /// point in trying again
    PartiallyTranslated(Ref<Type>, Option<BnTypeError>),
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

struct TranslateIDBTypes<'a, F: Fn(usize, usize) -> Result<(), ()>> {
    arch: CoreArchitecture,
    debug_info: &'a mut DebugInfo,
    _debug_file: &'a BinaryView,
    progress: F,
    til: &'a TILSection,
    // note it's mapped 1:1 with the same index from til types.chain(symbols)
    types: Vec<TranslatesIDBType<'a>>,
    // ordinals with index to types
    types_by_ord: HashMap<u64, usize>,
    // original names with index to types
    types_by_name: HashMap<String, usize>,
}

impl<F: Fn(usize, usize) -> Result<(), ()>> TranslateIDBTypes<'_, F> {
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
            "SHORT" | "USHORT" => Some(TranslateTypeResult::Translated(Type::int(
                self.til
                    .sizes
                    .map(|x| x.size_short.get())
                    .unwrap_or(2)
                    .into(),
                name == "SHORT",
            ))),
            "int16_t" => Some(TranslateTypeResult::Translated(Type::int(2, true))),
            "uint16_t" => Some(TranslateTypeResult::Translated(Type::int(2, false))),
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
            TranslateTypeResult::Error(error) => {
                TranslateTypeResult::Error(BnTypeError::Typedef(Box::new(error.to_owned())))
            }
            TranslateTypeResult::PartiallyTranslated(og_ty, error) => {
                TranslateTypeResult::PartiallyTranslated(
                    Type::named_type_from_type(ty.name.as_str(), &og_ty),
                    error
                        .as_ref()
                        .map(|x| BnTypeError::Typedef(Box::new(x.clone())))
                        .clone(),
                )
            }
            TranslateTypeResult::Translated(og_ty) => TranslateTypeResult::Translated(
                Type::named_type_from_type(ty.name.as_str(), &og_ty),
            ),
        }
    }

    fn translate_pointer(&self, ty: &TILType) -> TranslateTypeResult {
        match self.translate_type(ty) {
            TranslateTypeResult::Translated(trans) => {
                TranslateTypeResult::Translated(Type::pointer(&self.arch, &trans))
            }
            TranslateTypeResult::PartiallyTranslated(trans, error) => {
                TranslateTypeResult::PartiallyTranslated(
                    Type::pointer(&self.arch, &trans),
                    error.map(|e| BnTypeError::Pointer(Box::new(e))),
                )
            }
            TranslateTypeResult::Error(error) => TranslateTypeResult::PartiallyTranslated(
                Type::pointer(&self.arch, &Type::void()),
                Some(error),
            ),
            TranslateTypeResult::NotYet => TranslateTypeResult::PartiallyTranslated(
                Type::pointer(&self.arch, &Type::void()),
                None,
            ),
        }
    }

    fn translate_function(&self, fun: &TILFunction) -> TranslateTypeResult {
        let mut is_partial = false;
        let mut errors: FunctionError = Default::default();
        // funtions are always 0 len, so it's translated or partial(void)
        let return_ty = match self.translate_type(&fun.ret) {
            TranslateTypeResult::Translated(trans) => trans,
            TranslateTypeResult::PartiallyTranslated(trans, error) => {
                is_partial |= true;
                errors.ret = error.map(Box::new);
                trans
            }
            TranslateTypeResult::Error(error) => {
                errors.ret = Some(Box::new(error));
                return TranslateTypeResult::PartiallyTranslated(
                    Type::void(),
                    Some(BnTypeError::Function(errors)),
                );
            }
            TranslateTypeResult::NotYet => {
                return TranslateTypeResult::PartiallyTranslated(Type::void(), None)
            }
        };
        let mut partial_error_args = vec![];
        let mut bn_args = Vec::with_capacity(fun.args.len());
        for (i, (arg_name, arg_type, _arg_loc)) in fun.args.iter().enumerate() {
            let arg = match self.translate_type(arg_type) {
                TranslateTypeResult::Translated(trans) => trans,
                TranslateTypeResult::PartiallyTranslated(trans, error) => {
                    is_partial = true;
                    if let Some(error) = error {
                        errors.args.push((i, error));
                    }
                    trans
                }
                TranslateTypeResult::NotYet => {
                    return TranslateTypeResult::PartiallyTranslated(Type::void(), None)
                }
                TranslateTypeResult::Error(error) => {
                    partial_error_args.push((i, error));
                    return TranslateTypeResult::PartiallyTranslated(
                        Type::void(),
                        Some(BnTypeError::Function(errors)),
                    );
                }
            };
            // TODO create location from `arg_loc`?
            let loc = None;
            let name = arg_name.to_owned().unwrap_or_else(|| format!("arg_{i}"));
            bn_args.push(FunctionParameter::new(arg, name, loc));
        }

        let ty = Type::function(&return_ty, &bn_args, false);
        if is_partial {
            let error = (errors.ret.is_some() || !errors.args.is_empty())
                .then(|| BnTypeError::Function(errors));
            TranslateTypeResult::PartiallyTranslated(ty, error)
        } else {
            assert!(errors.ret.is_none() && errors.args.is_empty());
            TranslateTypeResult::Translated(ty)
        }
    }

    fn translate_array(&self, array: &TILArray) -> TranslateTypeResult {
        match self.translate_type(&*array.elem_type) {
            TranslateTypeResult::NotYet => TranslateTypeResult::NotYet,
            TranslateTypeResult::Translated(ty) => {
                TranslateTypeResult::Translated(Type::array(&ty, array.nelem.into()))
            }
            TranslateTypeResult::PartiallyTranslated(ty, error) => {
                TranslateTypeResult::PartiallyTranslated(
                    Type::array(&ty, array.nelem.into()),
                    error.map(Box::new).map(BnTypeError::Array),
                )
            }
            TranslateTypeResult::Error(error) => {
                TranslateTypeResult::Error(BnTypeError::Array(Box::new(error)))
            }
        }
    }

    fn translate_bitfields_into_struct(
        &self,
        offset: usize,
        members_slice: &[TILStructMember],
        struct_builder: &StructureBuilder,
    ) {
        if members_slice.is_empty() {
            unreachable!()
        }
        let mut members = members_slice
            .iter()
            .map(|ty| match &ty.member_type {
                TILType::Bitfield(b) => b,
                _ => unreachable!(),
            })
            .enumerate();
        let (_, first_field) = members.next().unwrap();
        let mut current_field_bytes = first_field.nbytes;
        let mut current_field_bits: u32 = first_field.width.into();
        let mut start_idx = 0;

        let create_field = |start_idx, i, bytes| {
            let name = if start_idx == i - 1 {
                let member: &TILStructMember = &members_slice[i - 1];
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
        members: &[TILStructMember],
        effective_alignment: u16,
    ) -> TranslateTypeResult {
        if members.is_empty() {
            // binary ninja crashes if you create an empty struct, because it divide by 0
            return TranslateTypeResult::Translated(Type::void());
        }
        let mut is_partial = false;
        let structure = StructureBuilder::new();
        structure.set_alignment(effective_alignment.into());

        let mut errors = vec![];
        let mut first_bitfield_seq = None;
        for (i, member) in members.iter().enumerate() {
            match (&member.member_type, first_bitfield_seq) {
                // accumulate the bitfield to be condensated
                (TILType::Bitfield(_bit), None) => {
                    first_bitfield_seq = Some(i);
                    continue;
                }
                (TILType::Bitfield(_bit), Some(_)) => continue,

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
                TranslateTypeResult::PartiallyTranslated(partial_ty, error) => {
                    is_partial |= true;
                    if let Some(error) = error {
                        errors.push((i, error));
                    }
                    partial_ty
                }
                TranslateTypeResult::NotYet => return TranslateTypeResult::NotYet,
                TranslateTypeResult::Error(error) => {
                    errors.push((i, error));
                    return TranslateTypeResult::Error(BnTypeError::Struct(errors));
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
            let partial_error = (!errors.is_empty()).then_some(BnTypeError::Struct(errors));
            TranslateTypeResult::PartiallyTranslated(bn_ty, partial_error)
        } else {
            assert!(errors.is_empty());
            TranslateTypeResult::Translated(bn_ty)
        }
    }

    fn translate_union(
        &self,
        members: &[(Option<String>, TILType)],
        _effective_alignment: u16,
    ) -> TranslateTypeResult {
        let mut is_partial = false;
        let structure = StructureBuilder::new();
        structure.set_structure_type(StructureType::UnionStructureType);
        let mut errors = vec![];
        for (i, (member_name, member_type)) in members.iter().enumerate() {
            // bitfields can be translated into complete fields
            let mem = match member_type {
                TILType::Bitfield(field) => field_from_bytes(field.nbytes),
                member_type => match self.translate_type(member_type) {
                    TranslateTypeResult::Translated(ty) => ty,
                    TranslateTypeResult::Error(error) => {
                        errors.push((i, error));
                        return TranslateTypeResult::Error(BnTypeError::Union(errors));
                    }
                    TranslateTypeResult::NotYet => return TranslateTypeResult::NotYet,
                    TranslateTypeResult::PartiallyTranslated(partial, error) => {
                        is_partial |= true;
                        if let Some(error) = error {
                            errors.push((i, error));
                        }
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
            let partial_error = (!errors.is_empty()).then_some(BnTypeError::Struct(errors));
            TranslateTypeResult::PartiallyTranslated(bn_ty, partial_error)
        } else {
            assert!(errors.is_empty());
            TranslateTypeResult::Translated(bn_ty)
        }
    }

    fn translate_type(&self, ty: &TILType) -> TranslateTypeResult {
        match &ty {
            // types that are always translatable
            TILType::Basic(meta) => TranslateTypeResult::Translated(translate_basic(meta)),
            TILType::Bitfield(bit) => TranslateTypeResult::Translated(field_from_bytes(bit.nbytes)),
            TILType::Enum(TILEnum::NonRef {
                members, bytesize, ..
            }) => TranslateTypeResult::Translated(translate_enum(members, *bytesize)),
            TILType::Typedef(TILTypedef::Ordinal(ord)) => self
                .find_typedef_by_ordinal((*ord).into())
                .unwrap_or_else(|| TranslateTypeResult::Error(BnTypeError::OrdinalNotFound(*ord))),
            TILType::Typedef(TILTypedef::Name(name)) => {
                self.find_typedef_by_name(name).unwrap_or_else(|| {
                    TranslateTypeResult::Error(BnTypeError::NameNotFound(name.to_owned()))
                })
            }

            // may not be translatable imediatly, but the size is known and can be
            // updated after alBasicers are finished
            TILType::Union(TILUnion::Ref { ref_type, .. })
            | TILType::Struct(TILStruct::Ref { ref_type, .. })
            | TILType::Enum(TILEnum::Ref { ref_type, .. }) => self.translate_pointer(&**ref_type),
            TILType::Pointer(ty) => self.translate_pointer(&ty.typ),
            TILType::Function(fun) => self.translate_function(fun),

            // can only be partially solved if all fields are solved or partially solved
            TILType::Array(array) => self.translate_array(array),
            TILType::Struct(TILStruct::NonRef {
                members,
                effective_alignment,
                ..
            }) => self.translate_struct(members, *effective_alignment),
            TILType::Union(TILUnion::NonRef {
                members,
                effective_alignment,
                ..
            }) => self.translate_union(members, *effective_alignment),
        }
    }
}

fn find_typedef_named_type_class(ty: &TILType) -> NamedTypeReferenceClass {
    match ty {
        TILType::Typedef(_) => NamedTypeReferenceClass::TypedefNamedTypeClass,
        TILType::Struct(_) => NamedTypeReferenceClass::StructNamedTypeClass,
        TILType::Union(_) => NamedTypeReferenceClass::UnionNamedTypeClass,
        TILType::Enum(_) => NamedTypeReferenceClass::EnumNamedTypeClass,
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
    til: TILSection,
    progress: impl Fn(usize, usize) -> Result<(), ()>,
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
        til: &til,
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
                        // ignore partial errors here, they will be printed below
                        TranslateTypeResult::PartiallyTranslated(bn_ty, _)
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
                TranslateTypeResult::PartiallyTranslated(_, None) => {
                    let result = translator.translate_type(&translator.types[i].og_ty.tinfo);
                    assert!(!matches!(&result, TranslateTypeResult::NotYet));
                    did_something |=
                        !matches!(&result, TranslateTypeResult::PartiallyTranslated(_, None));
                    translator.types[i].ty = result;
                    // don't need to add again they will be fixed on the loop below
                }
                // if an error was produced, there is no point in try again
                TranslateTypeResult::PartiallyTranslated(_, Some(_)) => {}
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
            TranslateTypeResult::NotYet => {
                panic!(
                    "type could not be processed `{}`: {:#?}",
                    &ty.name, &ty.og_ty
                );
            }
            TranslateTypeResult::Error(error) => {
                error!("Unable to parse type `{}`: {error}", &ty.name);
            }
            TranslateTypeResult::PartiallyTranslated(_, error) => {
                if let Some(error) = error {
                    error!("Unable to parse type `{}` correctly: {error}", &ty.name);
                } else {
                    warn!("Type `{}` maybe not be fully translated", &ty.name);
                }
            }
            TranslateTypeResult::Translated(_) => {}
        };
    }

    // add a second time to fix the references LOL
    for ty in &translator.types {
        match &ty.ty {
            TranslateTypeResult::Translated(bn_ty)
            | TranslateTypeResult::PartiallyTranslated(bn_ty, _) => {
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

fn parse_id0_section_info(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    _debug_file: &BinaryView,
    id0: ID0Section,
    progress: impl Fn(usize, usize) -> Result<(), ()>,
) -> Result<()> {
    // TODO verify the best way to add comments, try to use the debug_info instead
    for fc in id0.functions_and_comments()? {
        match fc? {
            idb_rs::id0::FunctionsAndComments::Name => {}
            // function will be create bellow using the entry points
            idb_rs::id0::FunctionsAndComments::Function(_) => {}
            idb_rs::id0::FunctionsAndComments::RepeatableComment { address, value }
            | idb_rs::id0::FunctionsAndComments::Comment { address, value } => {
                for function in &bv.functions_at(address) {
                    function.set_comment(value);
                }
            }
            idb_rs::id0::FunctionsAndComments::Unknown { .. } => {}
        }
    }

    #[derive(Debug, Default)]
    struct ID0Function {
        address: Option<u64>,
        name: Option<String>,
        symbol: Option<String>,
    }
    let mut functions: HashMap<u64, ID0Function> = HashMap::new();
    for entry_point in id0.entry_points()? {
        // TODO check for duplication
        match entry_point? {
            idb_rs::id0::EntryPoint::Name => {}
            idb_rs::id0::EntryPoint::Unknown { .. } => {}
            // TODO take ordinal in consideration if the order of the functions is important
            idb_rs::id0::EntryPoint::Ordinal { .. } => {}
            idb_rs::id0::EntryPoint::Function { key, address } => {
                let fun = functions.entry(key).or_default();
                let _ = fun.address.insert(address);
            }
            idb_rs::id0::EntryPoint::ForwardedSymbol { key, symbol } => {
                let fun = functions.entry(key).or_default();
                let _ = fun.symbol.insert(symbol.to_string());
            }
            idb_rs::id0::EntryPoint::FunctionName { key, name } => {
                let fun = functions.entry(key).or_default();
                let _ = fun.name.insert(name.to_string());
            }
        }
    }
    let total = functions.len();
    for (i, function) in functions.into_values().enumerate() {
        if progress(i, total).is_err() {
            warn!("Aborted while adding the functions");
            break;
        }
        let name = function.name.clone();
        if !debug_info.add_function(DebugFunctionInfo::new(
            None,
            None,
            function.name.clone(),
            None,
            function.address,
            None,
            vec![],
            vec![],
        )) {
            error!("Unable to add the function {name:?}")
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

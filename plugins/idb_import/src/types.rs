use std::collections::HashMap;
use std::num::{NonZeroU16, NonZeroU8};

use anyhow::{anyhow, Result};
use binaryninja::architecture::{Architecture, ArchitectureExt, CoreArchitecture};
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::calling_convention::CoreCallingConvention;
use binaryninja::confidence::Conf;
use binaryninja::rc::Ref;
use binaryninja::types::{
    EnumerationBuilder, FunctionParameter, MemberAccess, MemberScope, StructureBuilder,
    StructureType, Type,
};
use idb_rs::til::function::CallingConvention as TILCallingConvention;
use idb_rs::til::pointer::Pointer as TILPointer;
use idb_rs::til::{
    array::Array as TILArray, function::Function as TILFunction, r#enum::Enum as TILEnum,
    r#struct::Struct as TILStruct, r#struct::StructMember as TILStructMember,
    r#union::Union as TILUnion, section::TILSection, TILTypeInfo, Type as TILType,
    TypeVariant as TILTypeVariant,
};
use idb_rs::IDBString;

#[derive(Debug, Clone)]
pub enum BnTypeError {
    // TODO delete this and make this verification during the TIL/IDB parsing, translating the ordinal
    // into a kind of type_idx
    OrdinalNotFound(u32),
    NameNotFound(String),

    Typedef(Box<BnTypeError>),
    Function(BnTypeFunctionError),
    Array(Box<BnTypeError>),
    Pointer(Box<BnTypeError>),
    /// Error for members
    Struct(Vec<(usize, BnTypeError)>),
    Union(Vec<(usize, BnTypeError)>),

    // can't create function due to missing CallingConvention
    MissingArchCC,
}

#[derive(Default, Debug, Clone)]
pub struct BnTypeFunctionError {
    pub ret: Option<Box<BnTypeError>>,
    pub args: Vec<(usize, BnTypeError)>,
}

impl std::fmt::Display for BnTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BnTypeError::OrdinalNotFound(i) => write!(f, "Reference to non existing Ordinal {i}"),
            BnTypeError::NameNotFound(name) => write!(f, "Reference to non existing name {name}"),
            BnTypeError::Typedef(error) => write!(f, "Typedef: {error}"),
            BnTypeError::Function(BnTypeFunctionError { ret, args }) => {
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
            BnTypeError::MissingArchCC => write!(f, "Arch is missing a default CallingConvention"),
        }
    }
}

#[derive(Default)]
pub enum TranslateTypeResult {
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

pub struct TranslatesIDBType<'a> {
    // sanitized name from IDB
    pub name: IDBString,
    // the result, if converted
    pub ty: TranslateTypeResult,
    pub og_ty: &'a TILTypeInfo,
    pub is_symbol: bool,
}

pub struct TranslateIDBTypes<'a, F: Fn(usize, usize) -> Result<(), ()>> {
    pub arch: CoreArchitecture,
    pub progress: F,
    pub til: &'a TILSection,
    // note it's mapped 1:1 with the same index from til types.chain(symbols)
    pub types: Vec<TranslatesIDBType<'a>>,
}

impl<F: Fn(usize, usize) -> Result<(), ()>> TranslateIDBTypes<'_, F> {
    fn find_typedef_by_name(&self, name: &[u8]) -> Option<TranslateTypeResult> {
        if name.is_empty() {
            // TODO this is my assumption, maybe an empty names Typedef means something else.
            return Some(TranslateTypeResult::Translated(Type::void()));
        }

        // check for types that ar usually not defined directly
        match name {
            b"Unkown" | b"uint8_t" => Some(TranslateTypeResult::Translated(Type::int(1, false))),
            b"IUnkown" | b"int8_t" => Some(TranslateTypeResult::Translated(Type::int(1, true))),
            b"SHORT" | b"USHORT" => Some(TranslateTypeResult::Translated(Type::int(
                self.til.sizeof_short().get().into(),
                name == b"SHORT",
            ))),
            b"int16_t" => Some(TranslateTypeResult::Translated(Type::int(2, true))),
            b"uint16_t" => Some(TranslateTypeResult::Translated(Type::int(2, false))),
            b"int32_t" => Some(TranslateTypeResult::Translated(Type::int(4, true))),
            b"uint32_t" => Some(TranslateTypeResult::Translated(Type::int(4, false))),
            b"int64_t" => Some(TranslateTypeResult::Translated(Type::int(8, true))),
            b"uint64_t" => Some(TranslateTypeResult::Translated(Type::int(8, false))),
            b"int128_t" => Some(TranslateTypeResult::Translated(Type::int(16, true))),
            b"uint128_t" => Some(TranslateTypeResult::Translated(Type::int(16, false))),
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
                    Type::named_type_from_type(ty.name.as_utf8_lossy(), og_ty),
                    error
                        .as_ref()
                        .map(|x| BnTypeError::Typedef(Box::new(x.clone())))
                        .clone(),
                )
            }
            TranslateTypeResult::Translated(og_ty) => TranslateTypeResult::Translated(
                Type::named_type_from_type(ty.name.as_utf8_lossy(), og_ty),
            ),
        }
    }

    fn translate_pointer(&self, ty: &TILPointer) -> TranslateTypeResult {
        match self.translate_type(&ty.typ) {
            TranslateTypeResult::Translated(trans) => {
                TranslateTypeResult::Translated(self.inner_translate_pointer(ty, &trans))
            }
            TranslateTypeResult::PartiallyTranslated(trans, error) => {
                TranslateTypeResult::PartiallyTranslated(
                    self.inner_translate_pointer(ty, &trans),
                    error.map(|e| BnTypeError::Pointer(Box::new(e))),
                )
            }
            TranslateTypeResult::Error(error) => TranslateTypeResult::PartiallyTranslated(
                self.inner_translate_pointer(ty, &Type::void()),
                Some(error),
            ),
            TranslateTypeResult::NotYet => TranslateTypeResult::PartiallyTranslated(
                self.inner_translate_pointer(ty, &Type::void()),
                None,
            ),
        }
    }

    fn inner_translate_pointer(&self, ty: &TILPointer, trans: &Type) -> Ref<Type> {
        // TODO handle ty.shifted
        // TODO handle ty.modifier
        Type::pointer_with_options(&self.arch, trans, ty.typ.is_const, ty.typ.is_volatile, None)
    }

    fn translate_function(&self, fun: &TILFunction) -> TranslateTypeResult {
        let mut is_partial = false;
        let mut errors: BnTypeFunctionError = Default::default();
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
        for (i, fun_arg) in fun.args.iter().enumerate() {
            let arg = match self.translate_type(&fun_arg.ty) {
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
            let name = fun_arg
                .name
                .as_ref()
                .map(|name| name.as_utf8_lossy().to_string())
                .unwrap_or_else(|| format!("arg_{i}"));
            bn_args.push(FunctionParameter::new(arg, name, loc));
        }

        let var_args = matches!(fun.calling_convention, Some(TILCallingConvention::Ellipsis));
        let cc = fun
            .calling_convention
            .and_then(|cc| convert_cc(&self.arch, cc))
            .or_else(|| self.arch.get_default_calling_convention())
            .or_else(|| {
                self.arch
                    .calling_conventions()
                    .iter()
                    .next()
                    .map(|x| x.clone())
            });
        let Some(cc) = cc else {
            return TranslateTypeResult::Error(BnTypeError::MissingArchCC);
        };
        let ty = Type::function_with_opts(
            &return_ty,
            &bn_args,
            var_args,
            cc,
            Conf::new(0, binaryninja::confidence::MIN_CONFIDENCE),
        );
        if is_partial {
            let error = (errors.ret.is_some() || !errors.args.is_empty())
                .then_some(BnTypeError::Function(errors));
            TranslateTypeResult::PartiallyTranslated(ty, error)
        } else {
            assert!(errors.ret.is_none() && errors.args.is_empty());
            TranslateTypeResult::Translated(ty)
        }
    }

    // TODO can binja handle 0 sized array? There is a better translation?
    fn translate_array(&self, array: &TILArray) -> TranslateTypeResult {
        match self.translate_type(&array.elem_type) {
            TranslateTypeResult::NotYet => TranslateTypeResult::NotYet,
            TranslateTypeResult::Translated(ty) => TranslateTypeResult::Translated(Type::array(
                &ty,
                array.nelem.map(NonZeroU16::get).unwrap_or(0).into(),
            )),
            TranslateTypeResult::PartiallyTranslated(ty, error) => {
                TranslateTypeResult::PartiallyTranslated(
                    Type::array(&ty, array.nelem.map(NonZeroU16::get).unwrap_or(0).into()),
                    error.map(Box::new).map(BnTypeError::Array),
                )
            }
            TranslateTypeResult::Error(error) => {
                TranslateTypeResult::Error(BnTypeError::Array(Box::new(error)))
            }
        }
    }

    fn condensate_bitfields_from_struct(
        &self,
        offset: usize,
        members_slice: &[TILStructMember],
        struct_builder: &mut StructureBuilder,
    ) {
        if members_slice.is_empty() {
            unreachable!()
        }
        let mut members = members_slice
            .iter()
            .map(|ty| match &ty.member_type.type_variant {
                TILTypeVariant::Bitfield(b) => b,
                _ => unreachable!(),
            })
            .enumerate();
        let (_, first_field) = members.next().unwrap();
        let mut current_field_bytes = first_field.nbytes;
        let mut current_field_bits: u32 = first_field.width.into();
        let mut start_idx = 0;

        let mut create_field = |start_idx, i, bytes| {
            let name = if start_idx == i - 1 {
                let member: &TILStructMember = &members_slice[i - 1];
                member
                    .name
                    .as_ref()
                    .map(|name| name.as_utf8_lossy().to_string())
                    .unwrap_or_else(|| format!("bitfield_{}", offset + start_idx))
            } else {
                format!("bitfield_{}_{}", offset + start_idx, offset + (i - 1))
            };
            let field = field_from_bytes(bytes);
            struct_builder.append(&field, name, MemberAccess::NoAccess, MemberScope::NoScope);
        };

        for (i, member) in members {
            // starting a new field
            let max_bits = u32::from(current_field_bytes.get()) * 8;
            // this bitfield start a a new field, or can't contain other bitfields
            // finish the previous and start a new
            if current_field_bytes != member.nbytes
                || max_bits < current_field_bits + u32::from(member.width)
            {
                create_field(start_idx, i, current_field_bytes.get().into());
                current_field_bytes = member.nbytes;
                current_field_bits = 0;
                start_idx = i;
            }

            // just add the current bitfield into the field
            current_field_bits += u32::from(member.width);
        }

        if current_field_bits != 0 {
            create_field(
                start_idx,
                members_slice.len(),
                current_field_bytes.get().into(),
            );
        }
    }

    fn translate_struct(&self, ty_struct: &TILStruct) -> TranslateTypeResult {
        if ty_struct.members.is_empty() {
            // binary ninja crashes if you create an empty struct, because it divide by 0
            return TranslateTypeResult::Translated(Type::void());
        }
        let mut is_partial = false;
        let mut structure = StructureBuilder::new();
        if let Some(align) = ty_struct.alignment {
            structure.alignment(align.get().into());
        }
        structure.packed(ty_struct.is_unaligned && ty_struct.is_uknown_8);

        let mut errors = vec![];
        let mut first_bitfield_seq = None;
        for (i, member) in ty_struct.members.iter().enumerate() {
            match (&member.member_type.type_variant, first_bitfield_seq) {
                // accumulate the bitfield to be condensated
                (TILTypeVariant::Bitfield(_bit), None) => {
                    first_bitfield_seq = Some(i);
                    continue;
                }
                (TILTypeVariant::Bitfield(_bit), Some(_)) => continue,

                // condensate the bitfields into byte-wide fields
                (_, Some(start_idx)) => {
                    first_bitfield_seq = None;
                    let members_bitrange = &ty_struct.members[start_idx..i];
                    self.condensate_bitfields_from_struct(
                        start_idx,
                        members_bitrange,
                        &mut structure,
                    );
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
            //TODO handle member.alignment
            let name = member
                .name
                .as_ref()
                .map(|name| name.as_utf8_lossy().to_string())
                .unwrap_or_else(|| format!("member_{i}"));
            structure.append(&mem, name, MemberAccess::NoAccess, MemberScope::NoScope);
        }
        if let Some(start_idx) = first_bitfield_seq {
            let members_bitrange = &ty_struct.members[start_idx..];
            self.condensate_bitfields_from_struct(start_idx, members_bitrange, &mut structure);
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

    fn translate_union(&self, ty_union: &TILUnion) -> TranslateTypeResult {
        let mut is_partial = false;
        let mut structure = StructureBuilder::new();
        structure.structure_type(StructureType::UnionStructureType);
        let mut errors = vec![];
        for (i, member) in ty_union.members.iter().enumerate() {
            // bitfields can be translated into complete fields
            let mem = match &member.ty.type_variant {
                TILTypeVariant::Bitfield(field) => field_from_bytes(field.nbytes.get().into()),
                _ => match self.translate_type(&member.ty) {
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

            let name = member
                .name
                .as_ref()
                .map(|name| name.as_utf8_lossy().to_string())
                .unwrap_or_else(|| format!("member_{i}"));
            structure.append(&mem, name, MemberAccess::NoAccess, MemberScope::NoScope);
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

    fn translate_enum(&self, ty_enum: &TILEnum) -> Ref<Type> {
        let mut eb = EnumerationBuilder::new();
        for (i, member) in ty_enum.members.iter().enumerate() {
            let name = member
                .name
                .as_ref()
                .map(|name| name.as_utf8_lossy().to_string())
                .unwrap_or_else(|| format!("member_{i}"));
            eb.insert(name, member.value);
        }
        Type::enumeration(
            &eb.finalize(),
            // TODO: This looks bad, look at the comment in [`Type::width`].
            // TODO check the default size of enum
            ty_enum
                .storage_size
                .map(|x| x.into())
                .or(self.til.header.size_enum.map(|x| x.into()))
                .unwrap_or(4.try_into().unwrap()),
            ty_enum.is_signed,
        )
    }

    fn translate_basic(&self, mdata: &idb_rs::til::Basic) -> Ref<Type> {
        match *mdata {
            idb_rs::til::Basic::Void => Type::void(),
            idb_rs::til::Basic::Unknown { bytes: 0 } => Type::void(),
            idb_rs::til::Basic::Unknown { bytes } => Type::array(&Type::char(), bytes.into()),
            idb_rs::til::Basic::Bool if self.til.header.size_bool.get() == 1 => Type::bool(),
            idb_rs::til::Basic::BoolSized { bytes } if bytes.get() == 1 => Type::bool(),
            // NOTE Binja don't have any representation for bool other then the default
            idb_rs::til::Basic::BoolSized { bytes } => Type::int(bytes.get().into(), false),
            idb_rs::til::Basic::Bool /*if self.til.header.size_bool.get() != 1*/ => Type::int(self.til.header.size_bool.get().into(), false),
            idb_rs::til::Basic::Char => Type::char(),
            // TODO what exacly is Segment Register?
            idb_rs::til::Basic::SegReg => Type::char(),
            idb_rs::til::Basic::IntSized { bytes, is_signed } => {
                // default into signed
                let is_signed = is_signed.as_ref().copied().unwrap_or(true);
                Type::int(bytes.get().into(), is_signed)
            }
            idb_rs::til::Basic::Int { is_signed } => {
                let is_signed = is_signed.as_ref().copied().unwrap_or(true);
                Type::int(self.til.header.size_int.get().into(), is_signed)
            },
            idb_rs::til::Basic::Short { is_signed } => {
                let is_signed = is_signed.as_ref().copied().unwrap_or(true);
                Type::int(self.til.sizeof_short().get().into(), is_signed)
            },
            idb_rs::til::Basic::Long { is_signed } => {
                let is_signed = is_signed.as_ref().copied().unwrap_or(true);
                Type::int(self.til.sizeof_long().get().into(), is_signed)
            },
            idb_rs::til::Basic::LongLong { is_signed } => {
                let is_signed = is_signed.as_ref().copied().unwrap_or(true);
                Type::int(self.til.sizeof_long_long().get().into(), is_signed)
            },
            idb_rs::til::Basic::LongDouble => {
                // TODO is size_long_double architecture dependent?
                Type::float(self.til.header.size_long_double.map(NonZeroU8::get).unwrap_or(8).into())
            },
            idb_rs::til::Basic::Float { bytes } => Type::float(bytes.get().into()),
        }
    }

    pub fn translate_type(&self, ty: &TILType) -> TranslateTypeResult {
        match &ty.type_variant {
            // types that are always translatable
            TILTypeVariant::Basic(meta) => {
                TranslateTypeResult::Translated(self.translate_basic(meta))
            }
            TILTypeVariant::Bitfield(bit) => {
                TranslateTypeResult::Translated(field_from_bytes(bit.nbytes.get().into()))
            }
            TILTypeVariant::Enum(ty_enum) => {
                TranslateTypeResult::Translated(self.translate_enum(ty_enum))
            }
            TILTypeVariant::Typeref(typeref) => match &typeref.typeref_value {
                idb_rs::til::TyperefValue::Ref(idx) => self.find_typedef(&self.types[*idx]),
                idb_rs::til::TyperefValue::UnsolvedName(name) => self
                    .find_typedef_by_name(name.as_ref().map(|x| x.as_bytes()).unwrap_or(&[]))
                    .unwrap_or_else(|| {
                        TranslateTypeResult::Error(BnTypeError::NameNotFound(
                            name.as_ref()
                                .map(|x| x.as_utf8_lossy().to_string())
                                .unwrap_or(String::new()),
                        ))
                    }),
                idb_rs::til::TyperefValue::UnsolvedOrd(ord) => {
                    TranslateTypeResult::Error(BnTypeError::OrdinalNotFound(*ord))
                }
            },

            TILTypeVariant::Pointer(ty) => self.translate_pointer(ty),
            TILTypeVariant::Function(fun) => self.translate_function(fun),

            // can only be partially solved if all fields are solved or partially solved
            TILTypeVariant::Array(array) => self.translate_array(array),
            TILTypeVariant::Struct(ty_struct) => self.translate_struct(ty_struct),
            TILTypeVariant::Union(ty_union) => self.translate_union(ty_union),
        }
    }
}

pub fn translate_ephemeral_type(debug_file: &BinaryView, ty: &TILType) -> TranslateTypeResult {
    // in case we need to translate types
    let header = idb_rs::til::ephemeral_til_header();
    let translator = TranslateIDBTypes {
        arch: debug_file.default_arch().unwrap(/* TODO */),
        progress: |_, _| Ok(()),
        // TODO it's unclear what to do here
        til: &TILSection {
            header,
            symbols: vec![],
            types: vec![],
            macros: None,
        },
        types: vec![],
    };

    translator.translate_type(ty)
}

pub fn translate_til_types(
    arch: CoreArchitecture,
    til: &TILSection,
    progress: impl Fn(usize, usize) -> Result<(), ()>,
) -> Result<Vec<TranslatesIDBType>> {
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
        types.push(TranslatesIDBType {
            name: ty.name.clone(),
            is_symbol,
            og_ty: ty,
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
        if !ty.name.as_bytes().is_empty() {
            let dup2 = types_by_name.insert(ty.name.as_bytes().to_owned(), i);
            if let Some(old) = dup2 {
                let old_type = &types[old];
                let new_type = types.last().unwrap();
                // TODO error?
                panic!(
                    "dup name {}:{}: {}:\n{:?}\n{:?}",
                    old_type.is_symbol,
                    new_type.is_symbol,
                    &ty.name.as_utf8_lossy(),
                    &old_type.og_ty,
                    &new_type.og_ty,
                )
            }
        }
    }

    let mut translator = TranslateIDBTypes {
        arch,
        progress,
        til,
        types,
    };
    if (translator.progress)(0, total).is_err() {
        return Err(anyhow!("IDB import aborted"));
    }

    // solve types until there is nothing else that can be solved
    loop {
        // if something was solved, mark this variable as true
        let mut did_something = false;
        let mut num_translated = 0usize;
        for i in 0..translator.types.len() {
            match &translator.types[i].ty {
                TranslateTypeResult::NotYet => {
                    let result = translator.translate_type(&translator.types[i].og_ty.tinfo);
                    did_something |= !matches!(&result, TranslateTypeResult::NotYet);
                    translator.types[i].ty = result;
                }
                TranslateTypeResult::PartiallyTranslated(_, None) => {
                    let result = translator.translate_type(&translator.types[i].og_ty.tinfo);
                    // don't allow regress, it can goes from PartiallyTranslated to any state other then NotYet
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
            if let TranslateTypeResult::Translated(_) = &translator.types[i].ty {
                num_translated += 1
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

    Ok(translator.types)
}

fn field_from_bytes(bytes: i32) -> Ref<Type> {
    match bytes {
        0 => unreachable!(),
        num @ (1 | 2 | 4 | 8 | 16) => Type::int(num.try_into().unwrap(), false),
        nelem => Type::array(&Type::char(), nelem.try_into().unwrap()),
    }
}

fn convert_cc<A: Architecture + ArchitectureExt>(
    arch: &A,
    in_cc: TILCallingConvention,
) -> Option<Ref<CoreCallingConvention>> {
    match in_cc {
        TILCallingConvention::Cdecl => arch.get_cdecl_calling_convention(),
        TILCallingConvention::Ellipsis => arch.get_cdecl_calling_convention(),
        TILCallingConvention::Stdcall => arch.get_stdcall_calling_convention(),
        TILCallingConvention::Fastcall => arch.get_fastcall_calling_convention(),
        TILCallingConvention::Voidarg
        | TILCallingConvention::Pascal
        | TILCallingConvention::Thiscall
        | TILCallingConvention::Swift
        | TILCallingConvention::Golang
        | TILCallingConvention::Reserved3
        | TILCallingConvention::Uservars
        | TILCallingConvention::Userpurge
        | TILCallingConvention::Usercall => None,
    }
}

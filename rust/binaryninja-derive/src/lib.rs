use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, FieldsNamed, Ident, Path, Variant,
};

type Result<T> = std::result::Result<T, Diagnostic>;

struct Repr {
    c: bool,
    primitive: Option<(Path, bool)>,
}

impl Repr {
    fn from_attrs(attrs: Vec<Attribute>) -> Result<Self> {
        let mut c = false;
        let mut primitive = None;
        for attr in attrs {
            if attr.path().is_ident("repr") {
                attr.parse_nested_meta(|meta| {
                    if let Some(ident) = meta.path.get_ident() {
                        if ident == "C" {
                            c = true;
                        } else if ident_in_list(ident, ["u8", "u16", "u32", "u64"]) {
                            primitive = Some((meta.path.clone(), false));
                        } else if ident_in_list(ident, ["i8", "i16", "i32", "i64"]) {
                            primitive = Some((meta.path.clone(), true));
                        } else if ident_in_list(ident, ["usize", "isize", "u128", "i128"]) {
                            return Err(ident
                                .span()
                                .error(format!("`repr({ident})` types are not supported"))
                                .into());
                        }
                    }
                    Ok(())
                })?;
            }
        }

        Ok(Self { c, primitive })
    }
}

fn ident_in_list<const N: usize>(ident: &Ident, list: [&'static str; N]) -> bool {
    list.iter().any(|id| ident == id)
}

#[proc_macro_derive(AbstractType)]
pub fn abstract_type_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match impl_abstract_type(input) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

fn impl_abstract_type(ast: DeriveInput) -> Result<TokenStream> {
    let repr = Repr::from_attrs(ast.attrs)?;

    if !ast.generics.params.is_empty() {
        return Err(ast.generics.span().error("type must not be generic"));
    }

    let ident = ast.ident;
    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => impl_abstract_struct_type(ident, fields, repr),
            Fields::Unnamed(_) => Err(s
                .fields
                .span()
                .error("tuple structs are unsupported; struct must have named fields")),
            Fields::Unit => Err(ident
                .span()
                .error("unit structs are unsupported; provide at least one named field")),
        },
        Data::Enum(e) => impl_abstract_enum_type(ident, e.variants, repr),
        Data::Union(u) => impl_abstract_union_type(ident, u.fields, repr),
    }
}

fn field_arguments(name: &Ident, fields: FieldsNamed) -> Vec<TokenStream> {
    fields
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.as_ref().unwrap();
            let ty = &field.ty;
            quote! {
                &<#ty as ::binaryninja::types::AbstractType>::resolve_type(),
                stringify!(#ident),
                ::std::mem::offset_of!(#name, #ident) as u64,
                false,
                ::binaryninja::types::MemberAccess::NoAccess,
                ::binaryninja::types::MemberScope::NoScope,
            }
        })
        .collect()
}

fn impl_abstract_struct_type(name: Ident, fields: FieldsNamed, repr: Repr) -> Result<TokenStream> {
    if !repr.c {
        return Err(name.span().error("struct must be `repr(C)`"));
    }

    let args = field_arguments(&name, fields);
    Ok(quote! {
        impl ::binaryninja::types::AbstractType for #name {
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(.insert(#args))*
                        .finalize()
                )
            }
        }
    })
}

fn impl_abstract_union_type(name: Ident, fields: FieldsNamed, repr: Repr) -> Result<TokenStream> {
    if !repr.c {
        return Err(name.span().error("union must be `repr(C)`"));
    }

    let args = field_arguments(&name, fields);
    Ok(quote! {
        impl ::binaryninja::types::AbstractType for #name {
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(.insert(#args))*
                        .set_structure_type(
                            ::binaryninja::types::StructureType::UnionStructureType
                        )
                        .finalize()
                )
            }
        }
    })
}

fn impl_abstract_enum_type(
    name: Ident,
    variants: impl IntoIterator<Item = Variant>,
    repr: Repr,
) -> Result<TokenStream> {
    if repr.c {
        return Err(name.span().error("`repr(C)` enums are not supported"));
    }

    let Some((primitive, signed)) = repr.primitive else {
        return Err(name
            .span()
            .error("must provide a primitive `repr` type, e.g. `u32`"));
    };
    let variants = variants
        .into_iter()
        .map(|variant| {
            if !variant.fields.is_empty() {
                return Err(variant.span().error("variant must not have any fields"));
            }
            let Some((_, discriminant)) = variant.discriminant else {
                return Err(variant
                    .span()
                    .error("variant must have an explicit discriminant"));
            };
            let ident = variant.ident;
            Ok(quote! { stringify!(#ident), #discriminant as u64 })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        impl ::binaryninja::types::AbstractType for #name {
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::enumeration(
                    &::binaryninja::types::Enumeration::builder()
                        #(.insert(#variants))*
                        .finalize(),
                    ::std::mem::size_of::<#primitive>(),
                    #signed
                )
            }
        }
    })
}

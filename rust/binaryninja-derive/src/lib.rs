use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::meta::ParseNestedMeta;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, FieldsNamed, Ident, Path, Variant,
};

#[proc_macro_error]
#[proc_macro_derive(BinaryNinjaType)]
pub fn binja_type_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    impl_binja_type(input)
}

#[derive(Default)]
struct Repr {
    c: bool,
    primitive: Option<(Path, bool)>,
}

impl Repr {
    fn from_attrs(attrs: Vec<Attribute>) -> Self {
        let mut c = false;
        let mut primitive = None;
        // Look for a `repr(...)` attribute on the type
        for attr in attrs {
            if attr.path().is_ident("repr") {
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("C") {
                        c = true;
                    }
                    if meta_path_in_list(&meta, ["u8", "u16", "u32", "u64"]) {
                        primitive = Some((meta.path.clone(), false));
                    } else if meta_path_in_list(&meta, ["i8", "i16", "i32", "i64"]) {
                        primitive = Some((meta.path.clone(), true));
                    } else if meta_path_in_list(&meta, ["u128", "i128", "usize", "isize"]) {
                        abort!(
                            meta.path,
                            "`repr({})` types are not supported",
                            meta.path.get_ident().unwrap()
                        )
                    }
                    Ok(())
                });
            }
        }
        Self { c, primitive }
    }
}

fn meta_path_in_list<const N: usize>(meta: &ParseNestedMeta, list: [&'static str; N]) -> bool {
    list.iter().any(|&p| meta.path.is_ident(p))
}

fn impl_binja_type(ast: DeriveInput) -> TokenStream {
    let repr = Repr::from_attrs(ast.attrs);

    if !ast.generics.params.is_empty() {
        abort!(ast.generics, "type must not be generic");
    }

    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => impl_binja_struct_type(ast.ident, fields, repr),
            Fields::Unnamed(_) => abort!(s.fields, "struct must have named fields"),
            Fields::Unit => abort!(s.fields, "unit structs are unsupported"),
        },
        Data::Enum(e) => impl_binja_enum_type(ast.ident, e.variants.into_iter().collect(), repr),
        Data::Union(u) => impl_binja_union_type(ast.ident, u.fields, repr),
    }
}

// The `quote` macro produces TokenStreams from proc_macro2 instead of proc_macro
fn named_fields_to_structure_args(fields: FieldsNamed) -> Vec<proc_macro2::TokenStream> {
    fields
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.as_ref().unwrap();
            let ty = &field.ty;
            quote!(&<#ty>::binja_type(), stringify!(#ident))
        })
        .collect::<Vec<_>>()
}

fn impl_binja_struct_type(name: Ident, fields: FieldsNamed, repr: Repr) -> TokenStream {
    if !repr.c {
        abort!(name, "struct must be `repr(C)`");
    }
    let args = named_fields_to_structure_args(fields);
    quote!(
        impl BinaryNinjaType for #name {
            fn binja_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        .with_members([#((#args)),*]) // Note the extra parens
                        .finalize(),
                )
            }
        }
    )
    .into()
}

fn impl_binja_union_type(name: Ident, fields: FieldsNamed, repr: Repr) -> TokenStream {
    if !repr.c {
        abort!(name, "union must be `repr(C)`");
    }
    let args = named_fields_to_structure_args(fields);
    quote!(
        impl BinaryNinjaType for #name {
            fn binja_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(
                            .insert(
                                #args,
                                0,
                                false,
                                ::binaryninja::types::MemberAccess::NoAccess,
                                ::binaryninja::types::MemberScope::NoScope
                            )
                        )*
                        .set_structure_type(::binaryninja::types::StructureType::UnionStructureType)
                        .finalize(),
                )
            }
        }
    )
    .into()
}

fn impl_binja_enum_type(name: Ident, variants: Vec<Variant>, repr: Repr) -> TokenStream {
    if repr.c {
        abort!(name, "`repr(C)` enums are not supported")
    }
    let Some((primitive, sign)) = repr.primitive else {
        abort!(name, "must provide a primitive `repr` type, e.g. `u32`")
    };
    let variants = variants
        .iter()
        .map(|variant| {
            if !variant.fields.is_empty() {
                abort!(variant, "variant must not have any fields")
            }
            if let Some((_, discriminant)) = &variant.discriminant {
                let ident = &variant.ident;
                quote!(stringify!(#ident), #discriminant)
            } else {
                abort!(variant, "variant must have an explicit discriminant")
            }
        })
        .collect::<Vec<_>>();
    quote!(
        impl BinaryNinjaType for #name {
            fn binja_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::enumeration(
                    &::binaryninja::types::Enumeration::builder()
                        #(
                            .insert(#variants)
                        )*
                        .finalize(),
                    std::mem::size_of::<#primitive>(),
                    #sign,
                )
            }
        }
    )
    .into()
}

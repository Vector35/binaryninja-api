use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, FieldsNamed, Ident};

#[proc_macro_error]
#[proc_macro_derive(BinaryNinjaType)]
pub fn binja_type_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    impl_binja_type(input)
}

fn impl_binja_type(ast: DeriveInput) -> TokenStream {
    let mut repr_c = false;
    for attr in ast.attrs {
        if attr.path().is_ident("repr") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("C") {
                    repr_c = true;
                }
                Ok(())
            });
        }
    }

    if !repr_c {
        abort!(ast.ident, "type must be `repr(C)`");
    }

    if !ast.generics.params.is_empty() {
        abort!(ast.generics, "type must not be generic");
    }

    let ident = ast.ident;
    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => impl_binja_struct_type(ident, fields),
            Fields::Unnamed(_) => abort!(s.fields, "struct must have named fields"),
            Fields::Unit => abort!(s.fields, "unit structs are unsupported"),
        },
        Data::Enum(_) => todo!(),
        Data::Union(s) => impl_binja_union_type(ident, s.fields),
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
            quote! { &<#ty>::binja_type(), stringify!(#ident) }
        })
        .collect::<Vec<_>>()
}

fn impl_binja_struct_type(name: Ident, fields: FieldsNamed) -> TokenStream {
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

fn impl_binja_union_type(name: Ident, fields: FieldsNamed) -> TokenStream {
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

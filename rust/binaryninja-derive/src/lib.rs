use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DeriveInput, Fields, FieldsNamed, Ident};

type Result<T> = std::result::Result<T, Diagnostic>;

#[proc_macro_derive(AbstractType)]
pub fn abstract_type_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match impl_abstract_type(input) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

fn impl_abstract_type(ast: DeriveInput) -> Result<TokenStream> {
    let mut repr_c = false;
    for attr in ast.attrs {
        if attr.path().is_ident("repr") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("c") {
                    repr_c = true;
                }
                Ok(())
            });
        }
    }

    if !repr_c {
        return Err(ast.ident.span().error("type must be `repr(C)`"));
    }

    if !ast.generics.params.is_empty() {
        return Err(ast.generics.span().error("type must not be generic"));
    }

    let ident = ast.ident;
    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => Ok(impl_abstract_struct_type(ident, fields)),
            Fields::Unnamed(_) => Err(s
                .fields
                .span()
                .error("tuple structs are unsupported; struct must have named fields")),
            Fields::Unit => Err(ident
                .span()
                .error("unit structs are unsupported; provide at least one named field")),
        },
        Data::Enum(_) => todo!(),
        Data::Union(u) => Ok(impl_abstract_union_type(ident, u.fields)),
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

fn impl_abstract_struct_type(name: Ident, fields: FieldsNamed) -> TokenStream {
    let args = field_arguments(&name, fields);
    quote! {
        impl ::binaryninja::types::AbstractType for #name {
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(.insert(#args))*
                        .finalize()
                )
            }
        }
    }
}

fn impl_abstract_union_type(name: Ident, fields: FieldsNamed) -> TokenStream {
    let args = field_arguments(&name, fields);
    quote! {
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
    }
}

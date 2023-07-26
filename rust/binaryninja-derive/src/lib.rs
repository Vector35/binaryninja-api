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
    let repr_c = ast.attrs.iter().find(|attr| {
        let ident = attr.path().get_ident();
        match ident {
            Some(ident) if ident == "repr" => {}
            _ => return false,
        }
        match attr.parse_args::<Ident>() {
            Ok(ident) if ident == "C" => true,
            _ => false,
        }
    });

    if repr_c.is_none() {
        abort!(ast, "type must be `repr(C)`");
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
        _ => todo!(),
    }
}

fn impl_binja_struct_type(name: Ident, fields: FieldsNamed) -> TokenStream {
    let args = fields
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.as_ref().unwrap();
            let ty = &field.ty;
            quote! { (&<#ty>::binja_type(), stringify!(#ident)) }
        })
        .collect::<Vec<_>>();
    quote!(
        impl BinaryNinjaType for #name {
            fn binja_type() -> Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        .with_members([#(#args),*])
                        .finalize(),
                )
            }
        }
    )
    .into()
}

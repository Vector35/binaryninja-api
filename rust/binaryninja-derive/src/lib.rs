use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    parenthesized, parse_macro_input, token, Attribute, Data, DeriveInput, Expr, Field, Fields,
    FieldsNamed, Ident, Lit, LitInt, Path, Type, Variant,
};

type Result<T> = std::result::Result<T, Diagnostic>;

struct AbstractField {
    ty: Type,
    width: Option<Type>,
    ident: Ident,
    named: bool,
}

impl AbstractField {
    fn from_field(field: Field) -> Result<Self> {
        let Some(ident) = field.ident else {
            return Err(field.span().error("field must be named"));
        };
        let named = field.attrs.iter().any(|attr| attr.path().is_ident("named"));
        let width = field
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("width"));
        if let Type::Ptr(ty) = field.ty {
            if let Some(attr) = width {
                if let Expr::Lit(expr) = &attr.meta.require_name_value()?.value {
                    if let Lit::Str(lit_str) = &expr.lit {
                        return Ok(Self {
                            ty: *ty.elem,
                            width: Some(lit_str.parse()?),
                            ident,
                            named,
                        });
                    }
                }
            }
            Err(ident.span()
                .error("pointer field must have explicit `#[width = \"<type>\"]` attribute, for example: `u64`"))
        } else {
            match width {
                Some(attr) => Err(attr
                    .span()
                    .error("`#[width]` attribute can only be applied to pointer fields")),
                None => Ok(Self {
                    ty: field.ty,
                    width: None,
                    ident,
                    named,
                }),
            }
        }
    }

    fn resolved_ty(&self) -> TokenStream {
        let ty = &self.ty;
        let mut resolved = quote! { <#ty as ::binaryninja::types::AbstractType>::resolve_type() };
        if self.named {
            resolved = quote! {
                ::binaryninja::types::Type::named_type_from_type(
                    stringify!(#ty),
                    &#resolved
                )
            };
        }
        if let Some(width) = &self.width {
            resolved = quote! {
                ::binaryninja::types::Type::pointer_of_width(
                    &#resolved,
                    ::std::mem::size_of::<#width>(),
                    false,
                    false,
                    None
                )
            }
        }
        resolved
    }
}

struct Repr {
    c: bool,
    packed: Option<Option<LitInt>>,
    align: Option<LitInt>,
    primitive: Option<(Path, bool)>,
}

impl Repr {
    fn from_attrs(attrs: Vec<Attribute>) -> Result<Self> {
        let mut c = false;
        let mut packed = None;
        let mut align = None;
        let mut primitive = None;
        for attr in attrs {
            let Some(ident) = attr.path().get_ident() else {
                continue;
            };
            if ident == "named" {
                return Err(attr
                    .span()
                    .error("`#[named]` attribute can only be applied to fields"));
            } else if ident == "width" {
                return Err(attr
                    .span()
                    .error("`#[width]` attribute can only be applied to pointer fields"));
            } else if ident == "repr" {
                attr.parse_nested_meta(|meta| {
                    if let Some(ident) = meta.path.get_ident() {
                        if ident == "C" {
                            c = true;
                        } else if ident == "packed" {
                            if meta.input.peek(token::Paren) {
                                let content;
                                parenthesized!(content in meta.input);
                                packed = Some(Some(content.parse()?));
                            } else {
                                packed = Some(None);
                            }
                        } else if ident == "align" {
                            let content;
                            parenthesized!(content in meta.input);
                            align = Some(content.parse()?);
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

        Ok(Self {
            c,
            packed,
            align,
            primitive,
        })
    }
}

fn ident_in_list<const N: usize>(ident: &Ident, list: [&'static str; N]) -> bool {
    list.iter().any(|id| ident == id)
}

#[proc_macro_derive(AbstractType, attributes(named, width))]
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
            Fields::Named(fields) => {
                impl_abstract_structure_type(ident, fields, repr, StructureKind::Struct)
            }
            Fields::Unnamed(_) => Err(s
                .fields
                .span()
                .error("tuple structs are unsupported; struct must have named fields")),
            Fields::Unit => Err(ident
                .span()
                .error("unit structs are unsupported; provide at least one named field")),
        },
        Data::Enum(e) => impl_abstract_enum_type(ident, e.variants, repr),
        Data::Union(u) => impl_abstract_structure_type(ident, u.fields, repr, StructureKind::Union),
    }
}

enum StructureKind {
    Struct,
    Union,
}

fn impl_abstract_structure_type(
    name: Ident,
    fields: FieldsNamed,
    repr: Repr,
    kind: StructureKind,
) -> Result<TokenStream> {
    if !repr.c {
        let msg = match kind {
            StructureKind::Struct => "struct must be `repr(C)`",
            StructureKind::Union => "union must be `repr(C)`",
        };
        return Err(name.span().error(msg));
    }

    let abstract_fields = fields
        .named
        .into_iter()
        .map(AbstractField::from_field)
        .collect::<Result<Vec<_>>>()?;
    let layout_name = format_ident!("__{name}_layout");
    let field_wrapper = format_ident!("__{name}_field_wrapper");
    let layout_fields = abstract_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let layout_ty = field.width.as_ref().unwrap_or(&field.ty);
            quote! {
                #ident: #field_wrapper<
                    [u8; <#layout_ty as ::binaryninja::types::AbstractType>::SIZE],
                    { <#layout_ty as ::binaryninja::types::AbstractType>::ALIGN },
                >
            }
        })
        .collect::<Vec<_>>();
    let args = abstract_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let resolved_ty = field.resolved_ty();
            quote! {
                &#resolved_ty,
                stringify!(#ident),
                ::std::mem::offset_of!(#layout_name, #ident) as u64,
                false,
                ::binaryninja::types::MemberAccess::NoAccess,
                ::binaryninja::types::MemberScope::NoScope,
            }
        })
        .collect::<Vec<_>>();
    let is_packed = repr.packed.is_some();
    let packed = repr.packed.map(|size| match size {
        Some(n) => quote! { #[repr(packed(#n))] },
        None => quote! { #[repr(packed)] },
    });
    let (align, set_alignment) = repr
        .align
        .map(|n| {
            (
                quote! { #[repr(align(#n))] },
                quote! { .set_alignment(Self::ALIGN) },
            )
        })
        .unzip();
    let (kind, set_union) = match kind {
        StructureKind::Struct => (quote! { struct }, None),
        StructureKind::Union => (
            quote! { union },
            Some(quote! {
                .set_structure_type(
                    ::binaryninja::types::StructureType::UnionStructureType
                )
            }),
        ),
    };
    Ok(quote! {
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct #field_wrapper<T, const N: usize>
        where
            ::binaryninja::elain::Align<N>: ::binaryninja::elain::Alignment
        {
            t: T,
            _align: ::binaryninja::elain::Align<N>,
        }

        #[repr(C)]
        #packed
        #align
        #kind #layout_name {
            #(#layout_fields),*
        }

        impl ::binaryninja::types::AbstractType for #name {
            const SIZE: usize = ::std::mem::size_of::<#layout_name>();
            const ALIGN: usize = ::std::mem::align_of::<#layout_name>();
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(.insert(#args))*
                        .set_width(Self::SIZE as u64)
                        .set_packed(#is_packed)
                        #set_alignment
                        #set_union
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
    if repr.align.is_some() {
        // No way to set custom alignment for enums in Binja
        return Err(name
            .span()
            .error("`repr(align(...))` on enums is not supported"));
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

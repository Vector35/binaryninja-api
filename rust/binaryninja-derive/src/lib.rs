use proc_macro2::{Span, TokenStream};
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{format_ident, quote};
use std::cell::OnceCell;
use syn::spanned::Spanned;
use syn::{
    parenthesized, parse_macro_input, token, Attribute, Data, DeriveInput, Expr, Field, Fields,
    FieldsNamed, Ident, Lit, LitInt, Meta, Path, Type, Variant,
};

type Result<T> = std::result::Result<T, Diagnostic>;

enum FieldKind {
    Ptr(Type, usize),
    Ty(Type),
}

impl FieldKind {
    fn ty(&self) -> &Type {
        match self {
            FieldKind::Ptr(ty, _) | FieldKind::Ty(ty) => &ty,
        }
    }
}

struct AbstractField {
    kind: FieldKind,
    ident: Ident,
    name: Option<String>,
}

impl AbstractField {
    fn from_field(field: Field, parent_name: &Ident, pointer_width: Option<usize>) -> Result<Self> {
        let Some(ident) = field.ident else {
            return Err(field.span().error("field must be named"));
        };
        let kind = match field.ty {
            Type::Ptr(ty) => {
                let Some(width) = pointer_width else {
                    return Err(parent_name.span().error(
                        // broken up to make rustfmt happy
                        "types containing pointer fields must be \
                         decorated with `#[binja(pointer_width = <int>)]`",
                    ));
                };
                FieldKind::Ptr(*ty.elem, width)
            }
            _ => FieldKind::Ty(field.ty),
        };
        let name = find_binja_attr(&field.attrs)?
            .map(|attr| match attr.kind {
                BinjaAttrKind::PointerWidth(_) => Err(attr.span.error(
                    // broken up to make rustfmt happy
                    "invalid attribute, expected either \
                    `#[binja(named)]` or `#[binja(name = \"...\")]`",
                )),
                BinjaAttrKind::Named(Some(name)) => Ok(name),
                BinjaAttrKind::Named(None) => {
                    let ty = kind.ty();
                    Ok(quote!(#ty).to_string())
                }
            })
            .transpose()?;
        Ok(Self { kind, ident, name })
    }

    fn resolved_ty(&self) -> TokenStream {
        let ty = self.kind.ty();
        let mut resolved = quote! { <#ty as ::binaryninja::types::AbstractType>::resolve_type() };
        if let Some(name) = &self.name {
            resolved = quote! {
                ::binaryninja::types::Type::named_type_from_type(#name, &#resolved)
            }
        }
        if let FieldKind::Ptr(_, width) = self.kind {
            resolved = quote! {
                ::binaryninja::types::Type::pointer_of_width(&#resolved, #width, false, false, None)
            }
        }
        resolved
    }
}

#[derive(Debug)]
struct BinjaAttr {
    kind: BinjaAttrKind,
    span: Span,
}

#[derive(Debug)]
enum BinjaAttrKind {
    PointerWidth(usize),
    Named(Option<String>),
}

fn find_binja_attr(attrs: &[Attribute]) -> Result<Option<BinjaAttr>> {
    let binja_attr = OnceCell::new();

    let set_attr = |attr: BinjaAttr| {
        let span = attr.span;
        binja_attr
            .set(attr)
            .map_err(|_| span.error("conflicting `#[binja(...)]` attributes"))
    };

    for attr in attrs {
        let Some(ident) = attr.path().get_ident() else {
            continue;
        };
        if ident == "binja" {
            let meta = attr.parse_args::<Meta>()?;
            let meta_ident = meta.path().require_ident()?;
            if meta_ident == "pointer_width" {
                let value = &meta.require_name_value()?.value;
                if let Expr::Lit(expr) = &value {
                    if let Lit::Int(val) = &expr.lit {
                        set_attr(BinjaAttr {
                            kind: BinjaAttrKind::PointerWidth(val.base10_parse()?),
                            span: attr.span(),
                        })?;
                        continue;
                    }
                }
                return Err(value.span().error("expected integer literal"));
            } else if meta_ident == "name" {
                let value = &meta.require_name_value()?.value;
                if let Expr::Lit(expr) = &value {
                    if let Lit::Str(lit) = &expr.lit {
                        set_attr(BinjaAttr {
                            kind: BinjaAttrKind::Named(Some(lit.value())),
                            span: attr.span(),
                        })?;
                        continue;
                    }
                }
                return Err(value.span().error(r#"expected string literal"#));
            } else if meta_ident == "named" {
                meta.require_path_only()?;
                set_attr(BinjaAttr {
                    kind: BinjaAttrKind::Named(None),
                    span: attr.span(),
                })?;
            } else {
                return Err(meta
                    .span()
                    .error(format!("unrecognized property `{meta_ident}`")));
            }
        }
    }
    Ok(binja_attr.into_inner())
}

struct Repr {
    c: bool,
    packed: Option<Option<LitInt>>,
    align: Option<LitInt>,
    primitive: Option<(Path, bool)>,
}

impl Repr {
    fn from_attrs(attrs: &[Attribute]) -> Result<Self> {
        let mut c = false;
        let mut packed = None;
        let mut align = None;
        let mut primitive = None;
        for attr in attrs {
            let Some(ident) = attr.path().get_ident() else {
                continue;
            };
            if ident == "repr" {
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
                        } else if ident_in_list(ident, ["u8", "u16", "u32", "u64", "u128"]) {
                            primitive = Some((meta.path.clone(), false));
                        } else if ident_in_list(ident, ["i8", "i16", "i32", "i64", "i128"]) {
                            primitive = Some((meta.path.clone(), true));
                        } else if ident_in_list(ident, ["usize", "isize"]) {
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

#[proc_macro_derive(AbstractType, attributes(binja))]
pub fn abstract_type_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match impl_abstract_type(input) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

fn impl_abstract_type(ast: DeriveInput) -> Result<TokenStream> {
    let repr = Repr::from_attrs(&ast.attrs)?;
    let width = find_binja_attr(&ast.attrs)?
        .map(|attr| match attr.kind {
            BinjaAttrKind::PointerWidth(width) => Ok(width),
            BinjaAttrKind::Named(Some(_)) => Err(attr
                .span
                .error(r#"`#[binja(name = "...")] is only supported on fields"#)),
            BinjaAttrKind::Named(None) => Err(attr
                .span
                .error("`#[binja(named)]` is only supported on fields")),
        })
        .transpose()?;

    if !ast.generics.params.is_empty() {
        return Err(ast.generics.span().error("type must not be generic"));
    }

    let ident = ast.ident;
    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => {
                impl_abstract_structure_type(ident, fields, repr, width, StructureKind::Struct)
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
        Data::Union(u) => {
            impl_abstract_structure_type(ident, u.fields, repr, width, StructureKind::Union)
        }
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
    pointer_width: Option<usize>,
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
        .map(|field| AbstractField::from_field(field, &name, pointer_width))
        .collect::<Result<Vec<_>>>()?;
    let layout_name = format_ident!("__{name}_layout");
    let field_wrapper = format_ident!("__{name}_field_wrapper");
    let layout_fields = abstract_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let (size, align) = match &field.kind {
                FieldKind::Ptr(_, width) => {
                    let align = width.next_power_of_two();
                    (quote! { #width }, quote! { #align })
                }
                FieldKind::Ty(ty) => (
                    quote! { { <#ty as ::binaryninja::types::AbstractType>::LAYOUT.size() } },
                    quote! { { <#ty as ::binaryninja::types::AbstractType>::LAYOUT.align() } },
                ),
            };
            quote! { #ident: #field_wrapper<#size, #align> }
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
                quote! { .set_alignment(Self::LAYOUT.align()) },
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
        struct #field_wrapper<const SIZE: usize, const ALIGN: usize>
        where
            ::binaryninja::elain::Align<ALIGN>: ::binaryninja::elain::Alignment
        {
            t: [u8; SIZE],
            _align: ::binaryninja::elain::Align<ALIGN>,
        }

        #[repr(C)]
        #packed
        #align
        #kind #layout_name {
            #(#layout_fields),*
        }

        impl ::binaryninja::types::AbstractType for #name {
            const LAYOUT: ::std::alloc::Layout = ::std::alloc::Layout::new::<#layout_name>();
            fn resolve_type() -> ::binaryninja::rc::Ref<::binaryninja::types::Type> {
                ::binaryninja::types::Type::structure(
                    &::binaryninja::types::Structure::builder()
                        #(.insert(#args))*
                        .set_width(Self::LAYOUT.size() as u64)
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

use binaryninja::architecture::{Architecture, CoreArchitecture};
use binaryninja::rc::Ref;
use binaryninja::types::{
    NamedTypeReference, NamedTypeReferenceClass, QualifiedName, Type, ValueLocationSource,
};
use swift_demangler::{TypeKind, TypeRef};

pub(crate) trait TypeRefExt {
    fn to_bn_type(&self, arch: &CoreArchitecture) -> Option<Ref<Type>>;
    fn to_bn_type_with_depth(&self, arch: &CoreArchitecture, depth: usize) -> Option<Ref<Type>>;
}

// Bound recursive conversion even when a mangled name has many nested wrappers.
const MAX_SWIFT_TYPE_DEPTH: usize = 16;

impl TypeRefExt for TypeRef<'_> {
    fn to_bn_type(&self, arch: &CoreArchitecture) -> Option<Ref<Type>> {
        self.to_bn_type_with_depth(arch, 0)
    }

    fn to_bn_type_with_depth(&self, arch: &CoreArchitecture, depth: usize) -> Option<Ref<Type>> {
        if depth >= MAX_SWIFT_TYPE_DEPTH {
            return None;
        }
        let next_depth = depth + 1;

        match self.kind() {
            TypeKind::Named(named) => {
                let name = named.name()?;
                let module = named.module();

                // __C is Swift's internal module for C/Objective-C imports; drop it.
                let module = match module {
                    Some("__C") => None,
                    other => other,
                };

                // Map Swift standard library primitive types to BN primitives.
                // Bound generic types (e.g., Optional<T>) are never primitives.
                if module == Some("Swift") && !named.is_generic() {
                    if let Some(ty) = swift_primitive(name, arch) {
                        return Some(ty);
                    }
                }

                let ntr = if named.is_generic() {
                    // Include generic arguments in the type name.
                    let args: Vec<String> =
                        named.generic_args().iter().map(|a| a.display()).collect();
                    let full_name = format!("{}<{}>", name, args.join(", "));
                    make_named_type_ref(module, &full_name)
                } else {
                    make_named_type_ref(module, name)
                };

                // Class types (including ObjC classes) are reference types —
                // always a pointer at the ABI level.
                if named.is_class() {
                    Some(Type::pointer(arch, &ntr))
                } else {
                    Some(ntr)
                }
            }

            TypeKind::Function(func_type) => {
                let params: Vec<_> = func_type
                    .parameters()
                    .iter()
                    .map(|p| {
                        let ty = p.type_ref.to_bn_type_with_depth(arch, next_depth)?;
                        let name = p.label.unwrap_or("").to_string();
                        Some(binaryninja::types::FunctionParameter {
                            ty: ty.into(),
                            name,
                            location: ValueLocationSource::Default,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;

                let ret_type = match func_type.return_type() {
                    Some(rt) => rt.to_bn_type_with_depth(arch, next_depth)?,
                    None => Type::void(),
                };

                Some(Type::function(&ret_type, params, false))
            }

            TypeKind::Tuple(elements) => {
                if elements.is_empty() {
                    // () is Swift.Void
                    Some(Type::void())
                } else {
                    let display = self.display();
                    Some(make_named_type_ref(Some("Swift"), &display))
                }
            }

            TypeKind::Optional(inner) => {
                let display = inner.display();
                Some(make_named_type_ref(Some("Swift"), &display))
            }

            TypeKind::Array(inner) => {
                let display = inner.display();
                let label = format!("[{display}]");
                Some(make_named_type_ref(Some("Swift"), &label))
            }

            TypeKind::Dictionary { key, value } => {
                let key_display = key.display();
                let value_display = value.display();
                let label = format!("[{key_display} : {value_display}]");
                Some(make_named_type_ref(Some("Swift"), &label))
            }

            TypeKind::InOut(inner) => {
                let inner_ty = inner.to_bn_type_with_depth(arch, next_depth)?;
                Some(Type::pointer(arch, &inner_ty))
            }

            TypeKind::Metatype(_) => {
                // Metatype is an opaque pointer-sized value at runtime.
                Some(Type::pointer_of_width(
                    &Type::void(),
                    arch.address_size(),
                    false,
                    false,
                    None,
                ))
            }

            TypeKind::GenericParam { .. } => {
                // Generic parameters are opaque pointer-sized values at runtime.
                Some(Type::pointer_of_width(
                    &Type::int(1, false),
                    arch.address_size(),
                    false,
                    false,
                    None,
                ))
            }

            // Ownership wrappers: unwrap and recurse.
            TypeKind::Shared(inner)
            | TypeKind::Owned(inner)
            | TypeKind::Sending(inner)
            | TypeKind::Isolated(inner)
            | TypeKind::NoDerivative(inner) => inner.to_bn_type_with_depth(arch, next_depth),

            TypeKind::Weak(inner) | TypeKind::Unowned(inner) => {
                inner.to_bn_type_with_depth(arch, next_depth)
            }

            TypeKind::DynamicSelf(inner) => inner.to_bn_type_with_depth(arch, next_depth),

            TypeKind::ConstrainedExistential(inner) => {
                inner.to_bn_type_with_depth(arch, next_depth)
            }

            TypeKind::Any => {
                // Swift.Any is an existential container (pointer-sized at the ABI level).
                Some(make_named_type_ref(Some("Swift"), "Any"))
            }

            TypeKind::Existential(protocols) => {
                if protocols.len() == 1 {
                    protocols[0].to_bn_type_with_depth(arch, next_depth)
                } else {
                    None
                }
            }

            TypeKind::Generic { inner, .. } => inner.to_bn_type_with_depth(arch, next_depth),

            // Types we can't meaningfully represent.
            TypeKind::Error
            | TypeKind::Builtin(_)
            | TypeKind::BuiltinFixedArray { .. }
            | TypeKind::ImplFunction(_)
            | TypeKind::Pack(_)
            | TypeKind::ValueGeneric(_)
            | TypeKind::CompileTimeLiteral(_)
            | TypeKind::AssociatedType { .. }
            | TypeKind::Opaque { .. }
            | TypeKind::SILBox { .. }
            | TypeKind::Other(_) => None,
        }
    }
}

/// Map a Swift standard library type name to a primitive type.
fn swift_primitive(name: &str, arch: &CoreArchitecture) -> Option<Ref<Type>> {
    match name {
        "Int" => Some(Type::int(arch.address_size(), true)),
        "UInt" => Some(Type::int(arch.address_size(), false)),
        "Int8" => Some(Type::int(1, true)),
        "Int16" => Some(Type::int(2, true)),
        "Int32" => Some(Type::int(4, true)),
        "Int64" => Some(Type::int(8, true)),
        "UInt8" => Some(Type::int(1, false)),
        "UInt16" => Some(Type::int(2, false)),
        "UInt32" => Some(Type::int(4, false)),
        "UInt64" => Some(Type::int(8, false)),
        "Float" => Some(Type::float(4)),
        "Double" => Some(Type::float(8)),
        "Float80" => Some(Type::float(10)),
        "Bool" => Some(Type::bool()),
        _ => None,
    }
}

/// Create a named type reference from an optional module and a type name.
///
/// `__C` (Swift's internal module for C/Objective-C imports) is dropped since
/// it is not meaningful to users.
pub(crate) fn make_named_type_ref(module: Option<&str>, name: &str) -> Ref<Type> {
    let qname = match module {
        Some("__C") | None => QualifiedName::from(name),
        Some(module) => QualifiedName::from(format!("{module}.{name}")),
    };
    let ntr = NamedTypeReference::new(NamedTypeReferenceClass::UnknownNamedTypeClass, qname);
    Type::named_type(&ntr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binaryninja::architecture::ArchitectureExt;
    use binaryninja::demangle::{CustomDemangler, DemanglerConfig};
    use swift_demangler::{Context, HasFunctionSignature, Symbol};

    use crate::demangler::SwiftDemangler;

    #[test]
    fn deeply_nested_inout_type_is_rejected() {
        let _session = crate::test_session();
        let arch = CoreArchitecture::by_name("aarch64").expect("aarch64 architecture");

        for (depth, expected) in [(2, true), (MAX_SWIFT_TYPE_DEPTH, false), (1_000, false)] {
            let mangled = format!("$s4main1fyySi{}F", "z".repeat(depth));
            let ctx = Context::new();
            let Symbol::Function(function) = Symbol::parse(&ctx, &mangled).expect("Swift symbol")
            else {
                panic!("expected a function symbol");
            };
            let signature = function.signature().expect("function signature");
            let parameters = signature.parameters();
            assert_eq!(parameters.len(), 1);
            assert_eq!(parameters[0].type_ref.to_bn_type(&arch).is_some(), expected);
        }
    }

    #[test]
    fn deep_parameter_does_not_produce_a_partial_function_type() {
        let _session = crate::test_session();
        let arch = CoreArchitecture::by_name("aarch64").expect("aarch64 architecture");
        let platform = arch.standalone_platform().expect("aarch64 platform");
        let config = DemanglerConfig::for_platform(&platform, false);
        let demangler = SwiftDemangler;

        let shallow = "$s4main1fyySizF";
        let deep = format!("$s4main1fyySi{}F", "z".repeat(MAX_SWIFT_TYPE_DEPTH));
        assert!(demangler
            .demangle(shallow, &config)
            .expect("shallow symbol")
            .ty
            .is_some());
        assert!(demangler
            .demangle(&deep, &config)
            .expect("deep symbol")
            .ty
            .is_none());
    }

    #[test]
    fn deep_nested_function_parameter_does_not_disappear() {
        let _session = crate::test_session();
        let arch = CoreArchitecture::by_name("aarch64").expect("aarch64 architecture");
        let ctx = Context::new();
        let shallow = Symbol::parse(&ctx, "$s4main1fyyySizXEF").expect("function symbol");
        let Symbol::Function(function) = shallow else {
            panic!("expected a function symbol");
        };
        let params = function.signature().expect("signature").parameters();
        assert!(matches!(params[0].type_ref.kind(), TypeKind::Function(_)));
        assert!(params[0].type_ref.to_bn_type(&arch).is_some());

        let mangled = format!("$s4main1fyyySi{}XEF", "z".repeat(MAX_SWIFT_TYPE_DEPTH));
        let deep_ctx = Context::new();
        let Symbol::Function(function) = Symbol::parse(&deep_ctx, &mangled).expect("deep symbol")
        else {
            panic!("expected a function symbol");
        };
        let params = function.signature().expect("signature").parameters();
        assert!(matches!(params[0].type_ref.kind(), TypeKind::Function(_)));
        assert!(params[0].type_ref.to_bn_type(&arch).is_none());
    }
}

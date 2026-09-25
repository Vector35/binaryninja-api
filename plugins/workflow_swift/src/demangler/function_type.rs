use binaryninja::architecture::{ArchitectureExt, CoreArchitecture};
use binaryninja::confidence::Conf;
use binaryninja::rc::Ref;
use binaryninja::types::{FunctionParameter, Type, ValueLocation, ValueLocationSource};
use swift_demangler::{
    Accessor, AccessorKind, ConstructorKind, HasFunctionSignature, HasModule, Metadata,
    MetadataKind, Symbol,
};

use super::type_reconstruction::{make_named_type_ref, TypeRefExt};

/// Architecture-specific register assignments for Swift implicit parameters.
struct PlatformAbi {
    arch: CoreArchitecture,
    error_reg: &'static str,
    async_context_reg: &'static str,
}

impl PlatformAbi {
    fn for_arch(arch: &CoreArchitecture) -> Option<Self> {
        match arch.name().as_ref() {
            "aarch64" => Some(Self {
                arch: *arch,
                error_reg: "x21",
                async_context_reg: "x22",
            }),
            _ => None,
        }
    }

    fn error_location(&self) -> Option<ValueLocation> {
        self.register_location(self.error_reg)
    }

    fn async_context_location(&self) -> Option<ValueLocation> {
        self.register_location(self.async_context_reg)
    }

    fn register_location(&self, name: &str) -> Option<ValueLocation> {
        let reg = self.arch.register_by_name(name)?;
        Some(ValueLocation::from_register(reg))
    }
}

/// Swift calling convention builder.
///
/// Tracks which implicit parameters (self, error, async context) are present,
/// constructs the corresponding `FunctionParameter`s, and resolves the correct
/// architecture-specific calling convention when building the final function type.
struct CallingConvention {
    arch: CoreArchitecture,
    abi: Option<PlatformAbi>,
    flags: u8,
    leading_params: Vec<FunctionParameter>,
    trailing_params: Vec<FunctionParameter>,
}

impl CallingConvention {
    const SELF: u8 = 1;
    const THROWS: u8 = 2;
    const ASYNC: u8 = 4;

    fn for_arch(arch: &CoreArchitecture) -> Self {
        Self {
            arch: *arch,
            abi: PlatformAbi::for_arch(arch),
            flags: 0,
            leading_params: Vec::new(),
            trailing_params: Vec::new(),
        }
    }

    /// Mark this as a concrete instance method with self in x20.
    fn set_self(&mut self, module: Option<&str>, containing_type: &str) {
        self.flags |= Self::SELF;
        let named_ty = make_named_type_ref(module, containing_type);
        let self_ty = Type::pointer(&self.arch, &named_ty);
        self.leading_params.push(FunctionParameter {
            ty: self_ty.into(),
            name: "self".to_string(),
            location: ValueLocationSource::Default,
        });
    }

    /// Optionally mark as a concrete instance method if `containing_type` is `Some`.
    fn set_self_if(&mut self, module: Option<&str>, containing_type: Option<&str>) {
        if let Some(ct) = containing_type {
            self.set_self(module, ct);
        }
    }

    /// Mark this as a protocol witness method. Self is in x20 (swift-self)
    /// like concrete methods. The self type metadata and witness table are
    /// appended as trailing arguments after the explicit params.
    fn set_protocol_self(&mut self, module: Option<&str>, containing_type: &str) {
        self.set_self(module, containing_type);
        let void_ptr = Type::pointer(&self.arch, &Type::void());
        self.trailing_params.push(FunctionParameter {
            ty: void_ptr.clone().into(),
            name: "selfMetadata".to_string(),
            location: ValueLocationSource::Default,
        });
        self.trailing_params.push(FunctionParameter {
            ty: void_ptr.into(),
            name: "selfWitnessTable".to_string(),
            location: ValueLocationSource::Default,
        });
    }

    fn set_protocol_self_if(&mut self, module: Option<&str>, containing_type: Option<&str>) {
        if let Some(ct) = containing_type {
            self.set_protocol_self(module, ct);
        }
    }

    /// Mark this as a throwing function.
    fn set_throws(&mut self) {
        self.flags |= Self::THROWS;
    }

    /// Mark this as an async function.
    fn set_async(&mut self) {
        self.flags |= Self::ASYNC;
    }

    /// Build the final function type.
    ///
    /// Prepends `self` before `params` and appends error/async context after,
    /// then looks up the appropriate calling convention by name on the architecture.
    fn build_type(self, ret_type: &Type, params: Vec<FunctionParameter>) -> Ref<Type> {
        let cc_name = self.cc_name();

        let mut all_params = self.leading_params;
        all_params.extend(params);
        all_params.extend(self.trailing_params);

        if self.flags & Self::THROWS != 0 {
            let error_ty = Type::pointer(&self.arch, &make_named_type_ref(Some("Swift"), "Error"));
            all_params.push(FunctionParameter {
                ty: error_ty.into(),
                name: "error".to_string(),
                location: self.abi.as_ref().and_then(|a| a.error_location()).into(),
            });
        }

        if self.flags & Self::ASYNC != 0 {
            let ptr_ty = Type::pointer(&self.arch, &Type::void());
            all_params.push(FunctionParameter {
                ty: ptr_ty.into(),
                name: "asyncContext".to_string(),
                location: self
                    .abi
                    .as_ref()
                    .and_then(|a| a.async_context_location())
                    .into(),
            });
        }

        if let Some(cc) = self.arch.calling_convention_by_name(&cc_name) {
            Type::function_with_opts(ret_type, &all_params, false, cc, Conf::new(0, 0))
        } else {
            Type::function(ret_type, all_params, false)
        }
    }

    fn cc_name(&self) -> String {
        let mut name = String::from("swift");
        if self.flags & Self::SELF != 0 {
            name.push_str("-self");
        }
        if self.flags & Self::THROWS != 0 {
            name.push_str("-throws");
        }
        if self.flags & Self::ASYNC != 0 {
            name.push_str("-async");
        }
        name
    }
}

/// Build a Binary Ninja function type from a parsed Swift symbol.
///
/// Returns `None` if the symbol does not have a function signature (e.g. metadata, variables).
/// Thunks are intentionally excluded for now.
pub fn build_function_type(symbol: &Symbol, arch: &CoreArchitecture) -> Option<Ref<Type>> {
    let mut symbol = symbol;
    loop {
        symbol = match symbol {
            Symbol::Attributed(a) => &a.inner,
            Symbol::Specialization(s) => &s.inner,
            Symbol::Suffixed(s) => &s.inner,
            _ => break,
        };
    }

    match symbol {
        Symbol::Accessor(a) => return build_accessor_type(a, arch),
        Symbol::Metadata(m) => return build_metadata_function_type(m, arch),
        _ => {}
    }

    let mut cc = CallingConvention::for_arch(arch);

    // Determine implicit `self` parameter for instance methods/constructors.
    match symbol {
        Symbol::Function(f) if f.is_method() && !f.is_static() => {
            if f.containing_type_is_protocol() {
                cc.set_protocol_self_if(f.module(), f.containing_type());
            } else {
                cc.set_self_if(f.module(), f.containing_type());
            }
        }
        Symbol::Constructor(c) if c.kind() != ConstructorKind::Allocating => {
            cc.set_self_if(c.module(), c.containing_type());
        }
        Symbol::Destructor(d) => {
            cc.set_self_if(d.module(), d.containing_type());
            return Some(cc.build_type(&Type::void(), vec![]));
        }
        _ => {}
    };

    let (sig, labels) = match symbol {
        Symbol::Function(f) => (f.signature(), f.labels()),
        Symbol::Constructor(c) => (c.signature(), c.labels()),
        Symbol::Closure(c) => (c.signature(), vec![]),
        _ => (None, vec![]),
    };
    let sig = sig?;

    if sig.is_throwing() {
        cc.set_throws();
    }
    if sig.is_async() {
        cc.set_async();
    }

    let params: Vec<FunctionParameter> = sig
        .parameters()
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let ty = p.type_ref.to_bn_type(arch)?;
            let name = labels
                .get(i)
                .copied()
                .flatten()
                .or(p.label)
                .unwrap_or("")
                .to_string();
            Some(FunctionParameter {
                ty: ty.into(),
                name,
                location: ValueLocationSource::Default,
            })
        })
        .collect::<Option<Vec<_>>>()?;

    let ret_type = match sig.return_type() {
        Some(rt) => rt.to_bn_type(arch)?,
        None => Type::void(),
    };

    Some(cc.build_type(&ret_type, params))
}

/// Build a function type for a property accessor from its property type.
fn build_accessor_type(accessor: &Accessor, arch: &CoreArchitecture) -> Option<Ref<Type>> {
    let prop_ty = accessor
        .property_type()
        .and_then(|pt| pt.to_bn_type(arch))?;

    let mut cc = CallingConvention::for_arch(arch);

    // Non-static instance accessors take `self` as a parameter.
    if !accessor.is_static() {
        if let Some(ct) = accessor.containing_type() {
            cc.set_self(accessor.module(), &ct);
        }
    }

    match accessor.kind() {
        // Getter-like: (self) -> PropertyType
        AccessorKind::Getter | AccessorKind::GlobalGetter | AccessorKind::Read => {
            Some(cc.build_type(&prop_ty, vec![]))
        }

        // Setter-like: (self, newValue: PropertyType) -> Void
        AccessorKind::Setter
        | AccessorKind::WillSet
        | AccessorKind::DidSet
        | AccessorKind::Modify
        | AccessorKind::Init => {
            let params = vec![FunctionParameter {
                ty: prop_ty.into(),
                name: "newValue".to_string(),
                location: ValueLocationSource::Default,
            }];
            Some(cc.build_type(&Type::void(), params))
        }

        _ => None,
    }
}

/// Build a function type for Swift runtime metadata functions.
fn build_metadata_function_type(metadata: &Metadata, arch: &CoreArchitecture) -> Option<Ref<Type>> {
    let void_ptr = Type::pointer(arch, &Type::void());

    match metadata.kind() {
        // Type metadata accessor: void* fn()
        // Returns a pointer to the type metadata singleton.
        MetadataKind::AccessFunction | MetadataKind::CanonicalSpecializedGenericAccessFunction => {
            Some(Type::function(&void_ptr, vec![], false))
        }

        // Method lookup function: void* fn(void* metadata, void* method)
        MetadataKind::MethodLookupFunction => {
            let params = vec![
                FunctionParameter {
                    ty: void_ptr.clone().into(),
                    name: "metadata".to_string(),
                    location: ValueLocationSource::Default,
                },
                FunctionParameter {
                    ty: void_ptr.clone().into(),
                    name: "method".to_string(),
                    location: ValueLocationSource::Default,
                },
            ];
            Some(Type::function(&void_ptr, params, false))
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_demangler::Context;

    #[test]
    fn deeply_nested_specializations_keep_the_function_type() {
        let _session = crate::test_session();
        let arch = CoreArchitecture::by_name("aarch64").expect("aarch64 architecture");
        let mangled = format!("$s4main5helloSSyYaKF{}", "yTg5".repeat(5_000));
        let ctx = Context::new();
        let symbol = Symbol::parse(&ctx, &mangled).expect("Swift symbol");

        assert!(build_function_type(&symbol, &arch).is_some());
    }
}

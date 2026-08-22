mod function_type;
mod name;
mod type_reconstruction;

use binaryninja::binary_view::BinaryView;
use binaryninja::demangle::{CustomDemangler, DemanglerConfig, DemanglerResult};
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::types::QualifiedName;

fn should_extract_types(view: Option<&BinaryView>) -> bool {
    let mut opts = match view {
        Some(v) => QueryOptions::new_with_view(v),
        None => QueryOptions::new(),
    };
    Settings::global().get_bool_with_opts(crate::SETTING_EXTRACT_TYPES, &mut opts)
}

pub struct SwiftDemangler;

impl CustomDemangler for SwiftDemangler {
    fn is_mangled_string(&self, name: &str) -> bool {
        name.starts_with("$s")
            || name.starts_with("_$s")
            || name.starts_with("$S")
            || name.starts_with("_$S")
            || name.starts_with("$e")
            || name.starts_with("_$e")
            || name.starts_with("_T")
    }

    fn demangle(&self, name: &str, config: &DemanglerConfig) -> Option<DemanglerResult> {
        let ctx = swift_demangler::Context::new();
        let symbol = swift_demangler::Symbol::parse(&ctx, name)?;

        if should_extract_types(config.view.as_deref()) {
            let ty = config
                .platform
                .as_ref()
                .and_then(|platform| function_type::build_function_type(&symbol, &platform.arch()));
            let qname = if ty.is_some() {
                name::build_short_name(&symbol)
            } else {
                None
            }
            .unwrap_or_else(|| QualifiedName::from(symbol.display()));
            Some(DemanglerResult::new(qname, ty))
        } else {
            let qname = QualifiedName::from(symbol.display());
            Some(DemanglerResult::new(qname, None))
        }
    }
}

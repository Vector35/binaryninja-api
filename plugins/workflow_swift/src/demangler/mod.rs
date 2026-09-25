mod function_type;
mod name;
mod type_reconstruction;

use binaryninja::binary_view::BinaryView;
use binaryninja::demangle::{CustomDemangler, DemanglerConfig, DemanglerResult};
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::types::QualifiedName;
use swift_demangler::raw::Node;

fn should_extract_types(view: Option<&BinaryView>) -> bool {
    let mut opts = match view {
        Some(v) => QueryOptions::new_with_view(v),
        None => QueryOptions::new(),
    };
    Settings::global().get_bool_with_opts(crate::SETTING_EXTRACT_TYPES, &mut opts)
}

// Symbol::from_node recursively builds specialization and marker chains, and
// the resulting Box<Symbol> chain also drops recursively. Keep both bounded.
const MAX_SWIFT_SYMBOL_CHILDREN: usize = 256;
const MAX_SWIFT_NODE_DEPTH: usize = 32;

fn has_excessive_node_depth(root: Node<'_>) -> bool {
    let mut pending = vec![(root, 0_usize)];
    while let Some((node, depth)) = pending.pop() {
        if depth >= MAX_SWIFT_NODE_DEPTH {
            return true;
        }
        pending.extend(node.children().map(|child| (child, depth + 1)));
    }
    false
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
        let root = Node::parse(&ctx, name)?;
        if root.num_children() > MAX_SWIFT_SYMBOL_CHILDREN || has_excessive_node_depth(root) {
            return None;
        }
        let symbol = swift_demangler::Symbol::from_node(root)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_specializations_do_not_overflow_a_worker_stack() {
        let _session = crate::test_session();
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let demangler = SwiftDemangler;
                let config = DemanglerConfig::default();
                let shallow = format!("$s4main5helloSSyYaKF{}", "yTg5".repeat(255));
                assert!(demangler.demangle(&shallow, &config).is_some());
                let mangled = format!("$s4main5helloSSyYaKF{}", "yTg5".repeat(30_000));
                assert!(demangler.demangle(&mangled, &config).is_none());
                let bounded_type = format!("$s4main1fyySi{}F", "z".repeat(24));
                assert!(demangler.demangle(&bounded_type, &config).is_some());
                let rejected_type = format!("$s4main1fyySi{}F", "z".repeat(32));
                assert!(demangler.demangle(&rejected_type, &config).is_none());
                let deep_type = format!("$s4main1fyySi{}F", "z".repeat(1_000));
                assert!(demangler.demangle(&deep_type, &config).is_none());
            })
            .expect("worker thread")
            .join()
            .expect("worker thread completed");
    }
}

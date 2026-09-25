mod function_type;
mod name;
mod type_reconstruction;

use binaryninja::binary_view::BinaryView;
use binaryninja::demangle::{CustomDemangler, DemanglerConfig, DemanglerResult};
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::types::QualifiedName;
use swift_demangler::raw::{Node, NodeKind};

fn should_extract_types(view: Option<&BinaryView>) -> bool {
    let mut opts = match view {
        Some(v) => QueryOptions::new_with_view(v),
        None => QueryOptions::new(),
    };
    Settings::global().get_bool_with_opts(crate::SETTING_EXTRACT_TYPES, &mut opts)
}

// The pinned Swift parser accumulates decimal values in a signed int and some
// operators increment the result. A long decimal run is safe inside a Swift
// length-prefixed identifier. Locate candidate identifier payloads, then probe
// a copy with suspect payload digits replaced by letters. Only parse the
// original when every replacement appears as identifier text in the node tree.
fn has_oversized_decimal_run(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut oversized = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if !bytes[pos].is_ascii_digit() {
            pos += 1;
            continue;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if decimal_below_int_max(&bytes[start..pos]).is_none() {
            oversized.push(start..pos);
        }
    }
    if oversized.is_empty() {
        return false;
    }

    // A length prefix can be adjacent to digits in a preceding identifier.
    // Mark payloads using bounded lengths so a run spanning two identifiers
    // can be checked without treating the combined digits as one number.
    let mut candidate_payload = vec![false; bytes.len()];
    let mut pos = 0;
    while pos < bytes.len() {
        if !bytes[pos].is_ascii_digit() {
            pos += 1;
            continue;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let Some(length) = decimal_below_int_max(&bytes[start..pos]) else {
            continue;
        };
        if length > 0 && length <= bytes.len() - pos {
            candidate_payload[pos..pos + length].fill(true);
            pos += length;
        }
    }

    let mut probe = bytes.to_vec();
    let mut markers = Vec::new();
    for run in oversized {
        let mut pos = run.start;
        while pos < run.end {
            let start = pos;
            let is_payload = candidate_payload[pos];
            while pos < run.end && candidate_payload[pos] == is_payload {
                pos += 1;
            }
            if !is_payload {
                if decimal_below_int_max(&bytes[start..pos]).is_none() {
                    return true;
                }
                continue;
            }
            let len = pos - start;
            let Some(marker) = make_probe_marker(len, name, &markers) else {
                return true;
            };
            probe[start..pos].copy_from_slice(marker.as_bytes());
            markers.push(marker);
        }
    }

    if markers.is_empty() {
        return true;
    }
    let Ok(probe) = String::from_utf8(probe) else {
        return true;
    };
    let ctx = swift_demangler::Context::new();
    let Some(root) = Node::parse(&ctx, &probe) else {
        return true;
    };
    if root.num_children() > MAX_SWIFT_SYMBOL_CHILDREN || has_excessive_node_depth(root) {
        return true;
    }
    let mut found = vec![false; markers.len()];
    for node in std::iter::once(root).chain(root.descendants()) {
        if matches!(node.kind(), NodeKind::Identifier | NodeKind::Module) {
            if let Some(text) = node.text() {
                for (marker, found) in markers.iter().zip(&mut found) {
                    *found |= text.contains(marker);
                }
            }
        }
    }
    !found.into_iter().all(|found| found)
}

fn make_probe_marker(len: usize, original: &str, used: &[String]) -> Option<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut code = used.len();
    loop {
        let mut marker = vec![b'A'; len];
        let mut remaining = code;
        for byte in &mut marker {
            *byte = ALPHABET[remaining % ALPHABET.len()];
            remaining /= ALPHABET.len();
        }
        if remaining != 0 {
            return None;
        }
        let marker = String::from_utf8(marker).ok()?;
        if !original.contains(&marker) && !used.contains(&marker) {
            return Some(marker);
        }
        code = code.checked_add(1)?;
    }
}

fn decimal_below_int_max(digits: &[u8]) -> Option<usize> {
    let value = digits.iter().try_fold(0_u32, |value, digit| {
        value.checked_mul(10)?.checked_add(u32::from(*digit - b'0'))
    })?;
    (value < i32::MAX as u32).then_some(value as usize)
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
        if has_oversized_decimal_run(name) {
            return None;
        }
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
    fn rejects_decimal_values_that_overflow_the_native_parser() {
        assert!(!has_oversized_decimal_run("$sSiTQ2147483646_"));
        assert!(has_oversized_decimal_run("$sSiTQ2147483647_"));
        assert!(has_oversized_decimal_run("$sSiTQ3_2147483647_"));
        assert!(has_oversized_decimal_run("$s999999999999999999999999"));
        assert!(has_oversized_decimal_run(
            "$s4main5helloSSyYaKFTQ2147483647_"
        ));
        assert!(!has_oversized_decimal_run("$s4main1fyySiF"));
        assert!(!has_oversized_decimal_run("$s4main11f2147483647yyF"));
        assert!(!has_oversized_decimal_run(
            "$s11a214748364711b2147483647yyF"
        ));
        let many_digits = format!("f{}", "2147483647x".repeat(17));
        let many_digit_name = format!("$s4main{}{many_digits}yyF", many_digits.len());
        assert!(!has_oversized_decimal_run(&many_digit_name));

        let _session = crate::test_session();
        let config = DemanglerConfig::default();
        let demangler = SwiftDemangler;
        assert!(demangler.demangle("$sSiTQ2147483647_", &config).is_none());
        assert!(demangler
            .demangle("$s999999999999999999999999", &config)
            .is_none());
        assert!(demangler
            .demangle("$s4main5helloSSyYaKFTQ2147483647_", &config)
            .is_none());
        assert!(demangler.demangle("$s4main1fyySiF", &config).is_some());
        assert!(demangler
            .demangle("$s4main11f2147483647yyF", &config)
            .is_some());
        assert!(demangler
            .demangle("$s11a214748364711b2147483647yyF", &config)
            .is_some());
        assert!(demangler.demangle(&many_digit_name, &config).is_some());
    }

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

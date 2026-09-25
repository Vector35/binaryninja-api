use binaryninja::types::QualifiedName;
use swift_demangler::{ConstructorKind, DestructorKind, HasModule, Symbol};

/// Push a module name into the name parts, skipping `__C` (Swift's internal
/// module for C/Objective-C imports).
fn push_module(parts: &mut Vec<String>, module: Option<&str>) {
    if let Some(m) = module {
        if m != "__C" {
            parts.push(m.to_string());
        }
    }
}

/// Build a qualified name from a symbol's components, omitting parameter types
/// and return type since those are represented directly in the function's type
///
/// Returns `None` for symbol kinds that don't benefit from shortening (e.g.
/// variables, thunks), in which case the caller should fall back to `symbol.display()`.
pub fn build_short_name(symbol: &swift_demangler::Symbol) -> Option<QualifiedName> {
    let mut prefixes = Vec::new();
    let mut suffixes = Vec::new();
    let mut inner = symbol;
    loop {
        inner = match inner {
            Symbol::Attributed(a) => {
                prefixes.push(inner);
                &a.inner
            }
            Symbol::Specialization(s) => {
                prefixes.push(inner);
                &s.inner
            }
            Symbol::Suffixed(s) => {
                suffixes.push(s.suffix);
                &s.inner
            }
            _ => break,
        };
    }

    let mut parts: Vec<String> = Vec::new();

    match inner {
        Symbol::Function(f) => {
            push_module(&mut parts, f.module());
            if let Some(ct) = f.containing_type() {
                parts.push(ct.to_string());
            }
            parts.push(f.full_name());
        }
        Symbol::Constructor(c) => {
            push_module(&mut parts, c.module());
            if let Some(ct) = c.containing_type() {
                parts.push(ct.to_string());
            }
            let init_name = match c.kind() {
                ConstructorKind::Allocating => "__allocating_init",
                ConstructorKind::Regular => "init",
            };
            let labels: Vec<String> = c
                .labels()
                .iter()
                .map(|l| {
                    l.map(|s| format!("{s}:"))
                        .unwrap_or_else(|| "_:".to_string())
                })
                .collect();
            parts.push(format!("{init_name}({})", labels.join("")));
        }
        Symbol::Destructor(d) => {
            push_module(&mut parts, d.module());
            if let Some(ct) = d.containing_type() {
                parts.push(ct.to_string());
            }
            let deinit_name = match d.kind() {
                DestructorKind::Deallocating => "__deallocating_deinit",
                DestructorKind::IsolatedDeallocating => "__isolated_deallocating_deinit",
                DestructorKind::Regular => "deinit",
            };
            parts.push(deinit_name.to_string());
        }
        _ => return None,
    }

    if parts.is_empty() {
        return None;
    }

    let short_name = parts.join(".");
    if prefixes.is_empty() && suffixes.is_empty() {
        return Some(QualifiedName::from(short_name));
    }

    // Prefixes are ordered outermost first; suffixes are ordered innermost
    // first. Build the result once rather than copying a growing name at each
    // wrapper level.
    let mut combined = String::new();
    for prefix in prefixes {
        combined.push_str(&prefix.display());
    }
    combined.push_str(&short_name);
    for suffix in suffixes.into_iter().rev() {
        combined.push(' ');
        combined.push_str(suffix);
    }
    Some(QualifiedName::from(combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_demangler::Context;

    #[test]
    fn deeply_nested_specializations_keep_the_function_name() {
        let mangled = format!("$s4main5helloSSyYaKF{}", "yTg5".repeat(5_000));
        let ctx = Context::new();
        let symbol = Symbol::parse(&ctx, &mangled).expect("Swift symbol");
        let short = build_short_name(&symbol)
            .expect("function name")
            .to_string();

        assert!(short.starts_with("generic specialization <> of "));
        assert!(short.ends_with("main.hello()"));
    }
}

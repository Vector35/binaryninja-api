use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::rc::Ref as BNRef;
use binaryninja::symbol::Symbol as BNSymbol;
use binaryninja::symbol::SymbolType as BNSymbolType;
use warp::symbol::{Symbol, SymbolClass, SymbolModifiers};

pub fn from_bn_symbol(raw_symbol: &BNSymbol) -> Symbol {
    // TODO: Use this?
    let _is_export = raw_symbol.external();
    let raw_symbol_name = raw_symbol.raw_name();
    let symbol_name = raw_symbol_name.to_string_lossy();
    match raw_symbol.sym_type() {
        BNSymbolType::ImportAddress => {
            Symbol::new(
                symbol_name,
                SymbolClass::Function,
                // TODO: External = symbolic i guess
                SymbolModifiers::External,
            )
        }
        BNSymbolType::Data => {
            Symbol::new(
                symbol_name,
                // TODO: Data?
                SymbolClass::Data,
                SymbolModifiers::default(),
            )
        }
        BNSymbolType::Symbolic => {
            Symbol::new(
                symbol_name,
                SymbolClass::Function,
                // TODO: External = symbolic i guess
                SymbolModifiers::External,
            )
        }
        BNSymbolType::LocalLabel => {
            // TODO: This is a placeholder for another symbol.
            Symbol::new(symbol_name, SymbolClass::Data, SymbolModifiers::External)
        }
        BNSymbolType::External => Symbol::new(
            symbol_name,
            // TODO: External data?
            SymbolClass::Function,
            SymbolModifiers::External,
        ),
        BNSymbolType::ImportedData => {
            Symbol::new(symbol_name, SymbolClass::Data, SymbolModifiers::External)
        }
        BNSymbolType::LibraryFunction | BNSymbolType::Function => Symbol::new(
            symbol_name,
            SymbolClass::Function,
            SymbolModifiers::default(),
        ),
        BNSymbolType::ImportedFunction => Symbol::new(
            symbol_name,
            SymbolClass::Function,
            // TODO: Exported?
            SymbolModifiers::External,
        ),
    }
}

pub fn to_bn_symbol_at_address(view: &BinaryView, symbol: &Symbol, addr: u64) -> BNRef<BNSymbol> {
    let is_external = symbol.modifiers.contains(SymbolModifiers::External);
    let _is_exported = symbol.modifiers.contains(SymbolModifiers::Exported);
    let symbol_type = match symbol.class {
        SymbolClass::Function if is_external => BNSymbolType::ImportedFunction,
        // TODO: We should instead make it a Function, however due to the nature of the imports we are setting them to library for now.
        SymbolClass::Function => BNSymbolType::LibraryFunction,
        SymbolClass::Data if is_external => BNSymbolType::ImportedData,
        SymbolClass::Data => BNSymbolType::Data,
        _ => BNSymbolType::Data,
    };
    let raw_name = symbol.name.as_str();
    let mut symbol_builder = BNSymbol::builder(symbol_type, &symbol.name, addr);
    // Demangle symbol name (short is with simplifications).
    if let Some(arch) = view.default_arch() {
        if let Some((full_name, _)) =
            binaryninja::demangle::demangle_generic(&arch, raw_name, Some(view), false)
        {
            symbol_builder = symbol_builder.full_name(full_name);
        }
        if let Some((short_name, _)) =
            binaryninja::demangle::demangle_generic(&arch, raw_name, Some(view), false)
        {
            symbol_builder = symbol_builder.short_name(short_name);
        }
    }
    symbol_builder.create()
}

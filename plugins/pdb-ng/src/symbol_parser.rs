// Copyright 2022-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use binaryninja::confidence::ConfMergeable;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::mem;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use itertools::Itertools;
use pdb::register::Register::{AMD64, X86};
use pdb::register::{AMD64Register, X86Register};
use pdb::Error::UnimplementedSymbolKind;
use pdb::{
    AnnotationReferenceSymbol, BasePointerRelativeSymbol, BlockSymbol, BuildInfoSymbol,
    CallSiteInfoSymbol, CompileFlagsSymbol, ConstantSymbol, DataReferenceSymbol, DataSymbol,
    DefRangeFramePointerRelativeFullScopeSymbol, DefRangeFramePointerRelativeSymbol,
    DefRangeRegisterRelativeSymbol, DefRangeRegisterSymbol, DefRangeSubFieldRegisterSymbol,
    DefRangeSubFieldSymbol, DefRangeSymbol, ExportSymbol, FallibleIterator, FrameProcedureSymbol,
    InlineSiteSymbol, LabelSymbol, LocalSymbol, MultiRegisterVariableSymbol, ObjNameSymbol,
    ProcedureReferenceSymbol, ProcedureSymbol, PublicSymbol, RegisterRelativeSymbol,
    RegisterVariableSymbol, Rva, SeparatedCodeSymbol, Source, Symbol, SymbolData, SymbolIndex,
    SymbolIter, ThreadStorageSymbol, ThunkSymbol, TrampolineSymbol, TypeIndex,
    UserDefinedTypeSymbol, UsingNamespaceSymbol,
};

use crate::PDBParserInstance;
use binaryninja::architecture::{Architecture, ArchitectureExt, Register, RegisterId};
use binaryninja::binary_view::BinaryViewBase;
use binaryninja::confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE};
use binaryninja::demangle::demangle_ms;
use binaryninja::rc::Ref;
use binaryninja::types::{FunctionParameter, QualifiedName, StructureBuilder, Type, TypeClass};
use binaryninja::variable::{Variable, VariableSourceType};

const DEMANGLE_CONFIDENCE: u8 = 32;

/// Parsed Data Symbol like globals, etc
#[derive(Debug, Clone)]
pub struct SymbolNames {
    pub raw_name: String,
    pub short_name: Option<String>,
    pub full_name: Option<String>,
}

/// Parsed Data Symbol like globals, etc
#[derive(Debug, Clone)]
pub struct ParsedDataSymbol {
    /// If the symbol comes from the public symbol list (lower quality)
    pub is_public: bool,
    /// Absolute address in bv
    pub address: u64,
    /// Symbol name
    pub name: SymbolNames,
    /// Type if known
    pub type_: Option<Conf<Ref<Type>>>,
}

/// Parsed functions and function-y symbols
#[derive(Debug, Clone)]
pub struct ParsedProcedure {
    /// If the symbol comes from the public symbol list (lower quality)
    pub is_public: bool,
    /// Absolute address in bv
    pub address: u64,
    /// Symbol name
    pub name: SymbolNames,
    /// Function type if known
    pub type_: Option<Conf<Ref<Type>>>,
    /// List of local variables (TODO: use these)
    pub locals: Vec<ParsedVariable>,
}

/// Structure with some information about a procedure
#[derive(Debug, Clone)]
pub struct ParsedProcedureInfo {
    /// Known parameters for the procedure
    pub params: Vec<ParsedVariable>,
    /// Known local variables for the procedure
    pub locals: Vec<ParsedVariable>,
}

/// One parsed variable / parameter
#[derive(Debug, Clone)]
pub struct ParsedVariable {
    /// Variable name
    pub name: String,
    /// Variable type if known
    pub type_: Option<Conf<Ref<Type>>>,
    /// Location(s) where the variable is stored. PDB lets you store a variable in multiple locations
    /// despite binja not really understanding that. Length is probably never zero
    pub storage: Vec<ParsedLocation>,
    /// Do we think this is a parameter
    pub is_param: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct ParsedLocation {
    /// Location information
    pub location: Variable,
    /// Is the storage location relative to the base pointer? See [ParsedProcedureInfo.frame_offset]
    pub base_relative: bool,
    /// Is the storage location relative to the stack pointer?
    pub stack_relative: bool,
}

/// Big enum of all the types of symbols we know how to parse
#[derive(Debug, Clone)]
pub enum ParsedSymbol {
    /// Parsed Data Symbol like globals, etc
    Data(ParsedDataSymbol),
    /// Parsed functions and function-y symbols
    Procedure(ParsedProcedure),
    /// Structure with some information about a procedure
    ProcedureInfo(ParsedProcedureInfo),
    /// One parsed variable / parameter
    LocalVariable(ParsedVariable),
    /// Location of a local variable
    Location(ParsedLocation),
}

/// This is all done in the parser instance namespace because the lifetimes are impossible to
/// wrangle otherwise.
impl<'a, S: Source<'a> + 'a> PDBParserInstance<'a, S> {
    pub fn parse_symbols(
        &mut self,
        progress: Box<dyn Fn(usize, usize) -> Result<()> + '_>,
    ) -> Result<(Vec<ParsedSymbol>, Vec<ParsedSymbol>)> {
        let mut module_count = 0usize;
        let dbg = self.pdb.debug_information()?;
        let mut modules = dbg.modules()?;
        while let Some(_module) = modules.next()? {
            module_count += 1;
        }

        let global_symbols = self.pdb.global_symbols()?;
        let symbols = global_symbols.iter();
        let parsed = self.parse_mod_symbols(symbols)?;
        for sym in parsed {
            match &sym {
                ParsedSymbol::Data(ParsedDataSymbol {
                    name: SymbolNames { raw_name, .. },
                    ..
                })
                | ParsedSymbol::Procedure(ParsedProcedure {
                    name: SymbolNames { raw_name, .. },
                    ..
                }) => {
                    self.parsed_symbols_by_name
                        .insert(raw_name.clone(), self.parsed_symbols.len());
                }
                _ => {}
            }
            self.parsed_symbols.push(sym);
        }

        (progress)(1, module_count + 1)?;

        let dbg = self.pdb.debug_information()?;
        let mut modules = dbg.modules()?;
        let mut i = 0;
        while let Some(module) = modules.next()? {
            i += 1;
            (progress)(i + 1, module_count + 1)?;

            self.log(|| {
                format!(
                    "Module {} {}",
                    module.module_name(),
                    module.object_file_name()
                )
            });
            if let Some(module_info) = self.pdb.module_info(&module)? {
                let symbols = module_info.symbols()?;
                let parsed = self.parse_mod_symbols(symbols)?;
                for sym in parsed {
                    match &sym {
                        ParsedSymbol::Data(ParsedDataSymbol {
                            name: SymbolNames { raw_name, .. },
                            ..
                        })
                        | ParsedSymbol::Procedure(ParsedProcedure {
                            name: SymbolNames { raw_name, .. },
                            ..
                        }) => {
                            self.parsed_symbols_by_name
                                .insert(raw_name.clone(), self.parsed_symbols.len());
                        }
                        _ => {}
                    }
                    self.parsed_symbols.push(sym);
                }
            }
        }

        let use_public = self.settings.get_bool_with_opts(
            "pdb.features.loadGlobalSymbols",
            &mut self.settings_query_opts,
        );

        let mut best_symbols = HashMap::<String, &ParsedSymbol>::new();
        for sym in &self.parsed_symbols {
            match sym {
                ParsedSymbol::Data(ParsedDataSymbol {
                    is_public,
                    address,
                    name:
                        SymbolNames {
                            raw_name,
                            full_name,
                            ..
                        },
                    type_,
                    ..
                }) => {
                    if *is_public && !use_public {
                        continue;
                    }

                    let this_confidence = match type_ {
                        Some(Conf { confidence, .. }) => *confidence,
                        _ => MIN_CONFIDENCE,
                    };
                    let (new_better, old_exists) = match best_symbols.get(raw_name) {
                        Some(ParsedSymbol::Data(ParsedDataSymbol {
                            type_:
                                Some(Conf {
                                    confidence: old_conf,
                                    ..
                                }),
                            ..
                        })) => (this_confidence > *old_conf, true),
                        Some(ParsedSymbol::Data(ParsedDataSymbol { type_: None, .. })) => {
                            (true, true)
                        }
                        Some(..) => (false, true),
                        _ => (true, false),
                    };
                    if new_better {
                        self.log(|| {
                            format!(
                                "New best symbol (at 0x{:x}) for `{}` / `{}`: {:?}",
                                *address,
                                raw_name,
                                full_name.as_ref().unwrap_or(raw_name),
                                sym
                            )
                        });
                        if old_exists {
                            self.log(|| "Clobbering old definition");
                        }
                        best_symbols.insert(raw_name.clone(), sym);
                    }
                }
                _ => {}
            }
        }

        let mut best_functions = HashMap::<String, &ParsedSymbol>::new();
        for sym in &self.parsed_symbols {
            match sym {
                ParsedSymbol::Procedure(ParsedProcedure {
                    is_public,
                    address,
                    name:
                        SymbolNames {
                            raw_name,
                            full_name,
                            ..
                        },
                    type_,
                    ..
                }) => {
                    if *is_public && !use_public {
                        continue;
                    }

                    let this_confidence = match type_ {
                        Some(Conf { confidence, .. }) => *confidence,
                        _ => MIN_CONFIDENCE,
                    };
                    let (new_better, old_exists) = match best_functions.get(raw_name) {
                        Some(ParsedSymbol::Procedure(ParsedProcedure {
                            type_:
                                Some(Conf {
                                    confidence: old_conf,
                                    ..
                                }),
                            ..
                        })) => (this_confidence > *old_conf, true),
                        Some(ParsedSymbol::Procedure(ParsedProcedure { type_: None, .. })) => {
                            (true, true)
                        }
                        Some(..) => (false, true),
                        _ => (true, false),
                    };
                    if new_better {
                        self.log(|| {
                            format!(
                                "New best function (at 0x{:x}) for `{}` / `{}`: {:?}",
                                *address,
                                raw_name,
                                full_name.as_ref().unwrap_or(raw_name),
                                sym
                            )
                        });
                        if old_exists {
                            self.log(|| "Clobbering old definition");
                        }
                        best_functions.insert(raw_name.clone(), sym);
                    }
                }
                _ => {}
            }
        }

        Ok((
            best_symbols
                .into_iter()
                .map(|(_, sym)| sym.clone())
                .sorted_by_key(|sym| match sym {
                    ParsedSymbol::Data(ParsedDataSymbol {
                        type_, is_public, ..
                    }) => type_
                        .as_ref()
                        .map(|ty| {
                            if *is_public {
                                ty.confidence / 2
                            } else {
                                ty.confidence
                            }
                        })
                        .unwrap_or(0),
                    ParsedSymbol::Procedure(ParsedProcedure {
                        type_, is_public, ..
                    }) => type_
                        .as_ref()
                        .map(|ty| {
                            if *is_public {
                                ty.confidence / 2
                            } else {
                                ty.confidence
                            }
                        })
                        .unwrap_or(0),
                    _ => 0,
                })
                .collect::<Vec<_>>(),
            best_functions
                .into_iter()
                .map(|(_, func)| func.clone())
                .sorted_by_key(|sym| match sym {
                    ParsedSymbol::Data(ParsedDataSymbol {
                        type_, is_public, ..
                    }) => type_
                        .as_ref()
                        .map(|ty| {
                            if *is_public {
                                ty.confidence / 2
                            } else {
                                ty.confidence
                            }
                        })
                        .unwrap_or(0),
                    ParsedSymbol::Procedure(ParsedProcedure {
                        type_, is_public, ..
                    }) => type_
                        .as_ref()
                        .map(|ty| {
                            if *is_public {
                                ty.confidence / 2
                            } else {
                                ty.confidence
                            }
                        })
                        .unwrap_or(0),
                    _ => 0,
                })
                .collect::<Vec<_>>(),
        ))
    }

    /// Parse all the symbols in a module, via the given SymbolIter
    pub fn parse_mod_symbols(&mut self, mut symbols: SymbolIter) -> Result<Vec<ParsedSymbol>> {
        // Collect tree structure first
        let mut first = None;
        let mut last_local = None;
        let mut top_level_syms = vec![];
        let mut thunk_syms = vec![];
        let mut unparsed_syms = BTreeMap::new();
        while let Some(sym) = symbols.next()? {
            if first.is_none() {
                first = Some(sym.index());
            }
            unparsed_syms.insert(sym.index(), sym);

            let p = sym.parse();
            self.log(|| format!("Parsed: {:x?}", p));

            // It's some sort of weird tree structure where SOME symbols have "end" indices
            // and anything between them and that index is a child symbol
            // Sometimes there are "end scope" symbols at those end indices but like, sometimes
            // there aren't? Which makes that entire system seem pointless (or I'm just missing
            // something and it makes sense to _someone_)
            if let Some(&(start, _end)) = self.symbol_stack.last() {
                self.add_symbol_child(start, sym.index());
            } else {
                // Place thunk symbols in their own list at the end, so they can reference
                // other symbols parsed in the module
                match &p {
                    Ok(SymbolData::Thunk(_)) => {
                        thunk_syms.push(sym.index());
                    }
                    _ => {
                        top_level_syms.push(sym.index());
                    }
                }
            }
            let mut popped = false;
            while let Some(&(_start, end)) = self.symbol_stack.last() {
                if sym.index().0 >= end.0 {
                    let _ = self.symbol_stack.pop();
                    popped = true;
                } else {
                    break;
                }
            }

            // These aren't actually used for parsing (I don't trust them) but we can include a little
            // debug error check here and see if it's ever actually wrong
            match p {
                Ok(SymbolData::ScopeEnd) | Ok(SymbolData::InlineSiteEnd) if popped => {}
                Ok(SymbolData::ScopeEnd) | Ok(SymbolData::InlineSiteEnd) if !popped => {
                    self.log(|| "Did not pop at a scope end??? WTF??");
                }
                _ if popped => {
                    self.log(|| "Popped but not at a scope end??? WTF??");
                }
                _ => {}
            }

            // Push new scopes on the stack to build the tree
            match p {
                Ok(SymbolData::Procedure(data)) => {
                    self.symbol_stack.push((sym.index(), data.end));
                }
                Ok(SymbolData::InlineSite(data)) => {
                    self.symbol_stack.push((sym.index(), data.end));
                }
                Ok(SymbolData::Block(data)) => {
                    self.symbol_stack.push((sym.index(), data.end));
                }
                Ok(SymbolData::Thunk(data)) => {
                    self.symbol_stack.push((sym.index(), data.end));
                }
                Ok(SymbolData::SeparatedCode(data)) => {
                    self.symbol_stack.push((sym.index(), data.end));
                }
                Ok(SymbolData::FrameProcedure(..)) => {
                    if let Some(&(_, proc_end)) = self.symbol_stack.last() {
                        self.symbol_stack.push((sym.index(), proc_end));
                    }
                }
                Ok(SymbolData::Local(..)) => {
                    last_local = Some(sym.index());
                }
                Ok(SymbolData::DefRange(..))
                | Ok(SymbolData::DefRangeSubField(..))
                | Ok(SymbolData::DefRangeRegister(..))
                | Ok(SymbolData::DefRangeFramePointerRelative(..))
                | Ok(SymbolData::DefRangeFramePointerRelativeFullScope(..))
                | Ok(SymbolData::DefRangeSubFieldRegister(..))
                | Ok(SymbolData::DefRangeRegisterRelative(..)) => {
                    // I'd like to retract my previous statement that someone could possibly
                    // understand this:
                    // These symbol types impact the previous symbol, if it was a local
                    // BUT ALSO!! PART III REVENGE OF THE SYM-TH: You can have more than one of
                    // these and they all (?? it's undocumented) apply to the last local, PROBABLY
                    if let Some(last) = last_local {
                        self.add_symbol_child(last, sym.index());
                    } else {
                        self.log(|| format!("Found def range with no last local: {:?}", p));
                    }
                }
                _ => {}
            }
        }
        assert!(self.symbol_stack.is_empty());
        // Add thunks at the end as per above
        top_level_syms.extend(thunk_syms);

        // Restart and do the processing for real this time
        if let Some(first) = first {
            symbols.seek(first);
        }

        let mut final_symbols = HashSet::new();

        for root_idx in top_level_syms {
            for child_idx in self.walk_children(root_idx).into_iter() {
                let &sym = unparsed_syms
                    .get(&child_idx)
                    .expect("should have parsed this");

                self.log(|| format!("Symbol {:?} ", sym.index()));
                let (name, address) =
                    if let Some(parsed) = self.handle_symbol_index(sym.index(), &sym)? {
                        final_symbols.insert(sym.index());
                        match parsed {
                            ParsedSymbol::Data(ParsedDataSymbol { name, address, .. }) => {
                                (Some(name.clone()), Some(*address))
                            }
                            ParsedSymbol::Procedure(ParsedProcedure { name, address, .. }) => {
                                (Some(name.clone()), Some(*address))
                            }
                            _ => (None, None),
                        }
                    } else {
                        (None, None)
                    };

                if let Some(name) = name {
                    self.named_symbols.insert(name.raw_name, sym.index());
                }
                if let Some(address) = address {
                    if !self.addressed_symbols.contains_key(&address) {
                        self.addressed_symbols.insert(address, vec![]);
                    }
                    self.addressed_symbols
                        .get_mut(&address)
                        .expect("just created this")
                        .push(
                            self.indexed_symbols
                                .get(&sym.index())
                                .ok_or_else(|| anyhow!("Can't find sym {} ?", sym.index()))?
                                .clone(),
                        );
                }
            }
        }

        let filtered_symbols = mem::replace(&mut self.indexed_symbols, BTreeMap::new())
            .into_iter()
            .filter_map(|(idx, sym)| {
                if final_symbols.contains(&idx) {
                    Some(sym)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // The symbols overlap between modules or something, so we can't keep this info around
        self.symbol_tree.clear();
        self.module_cpu_type = None;

        Ok(filtered_symbols)
    }

    /// Set a symbol to be the parent of another, building the symbol tree
    fn add_symbol_child(&mut self, parent: SymbolIndex, child: SymbolIndex) {
        if let Some(tree) = self.symbol_tree.get_mut(&parent) {
            tree.push(child);
        } else {
            self.symbol_tree.insert(parent, Vec::from([child]));
        }

        self.symbol_parents.insert(child, parent);
    }

    /// Postorder traversal of children of symbol index (only during this module parse)
    fn walk_children(&self, sym: SymbolIndex) -> Vec<SymbolIndex> {
        let mut children = vec![];

        if let Some(tree) = self.symbol_tree.get(&sym) {
            for &child in tree {
                children.extend(self.walk_children(child).into_iter());
            }
        }

        children.push(sym);
        children
    }

    /// Direct children of symbol index (only during this module parse)
    fn symbol_children(&self, sym: SymbolIndex) -> Vec<SymbolIndex> {
        if let Some(tree) = self.symbol_tree.get(&sym) {
            tree.clone()
        } else {
            vec![]
        }
    }

    /// Direct parent of symbol index (only during this module parse)
    #[allow(dead_code)]
    fn symbol_parent(&self, sym: SymbolIndex) -> Option<SymbolIndex> {
        self.symbol_parents.get(&sym).copied()
    }

    /// Find symbol by index (only during this module parse)
    fn lookup_symbol(&self, sym: &SymbolIndex) -> Option<&ParsedSymbol> {
        self.indexed_symbols.get(sym)
    }

    /// Parse a new symbol by its index
    fn handle_symbol_index(
        &mut self,
        idx: SymbolIndex,
        sym: &Symbol,
    ) -> Result<Option<&ParsedSymbol>> {
        if let None = self.indexed_symbols.get(&idx) {
            match sym.parse() {
                Ok(data) => match self.handle_symbol(idx, &data) {
                    Ok(Some(parsed)) => {
                        self.log(|| format!("Symbol {} parsed into: {:?}", idx, parsed));
                        self.indexed_symbols.insert(idx, parsed);
                    }
                    Ok(None) => {}
                    e => {
                        self.log(|| format!("Error parsing symbol {}: {:?}", idx, e));
                    }
                },
                Err(UnimplementedSymbolKind(k)) => {
                    self.log(|| format!("Not parsing unimplemented symbol {}: kind {:x?}", idx, k));
                }
                Err(e) => {
                    self.log(|| format!("Could not parse symbol: {}: {}", idx, e));
                }
            };
        }

        Ok(self.indexed_symbols.get(&idx))
    }

    /// Parse a new symbol's data
    fn handle_symbol(
        &mut self,
        index: SymbolIndex,
        data: &SymbolData,
    ) -> Result<Option<ParsedSymbol>> {
        match data {
            SymbolData::ScopeEnd => self.handle_scope_end_symbol(index),
            SymbolData::ObjName(data) => self.handle_obj_name_symbol(index, data),
            SymbolData::RegisterVariable(data) => self.handle_register_variable_symbol(index, data),
            SymbolData::Constant(data) => self.handle_constant_symbol(index, data),
            SymbolData::UserDefinedType(data) => self.handle_user_defined_type_symbol(index, data),
            SymbolData::MultiRegisterVariable(data) => {
                self.handle_multi_register_variable_symbol(index, data)
            }
            SymbolData::Data(data) => self.handle_data_symbol(index, data),
            SymbolData::Public(data) => self.handle_public_symbol(index, data),
            SymbolData::Procedure(data) => self.handle_procedure_symbol(index, data),
            SymbolData::ThreadStorage(data) => self.handle_thread_storage_symbol(index, data),
            SymbolData::CompileFlags(data) => self.handle_compile_flags_symbol(index, data),
            SymbolData::UsingNamespace(data) => self.handle_using_namespace_symbol(index, data),
            SymbolData::ProcedureReference(data) => {
                self.handle_procedure_reference_symbol(index, &data)
            }
            SymbolData::DataReference(data) => self.handle_data_reference_symbol(index, data),
            SymbolData::AnnotationReference(data) => {
                self.handle_annotation_reference_symbol(index, data)
            }
            SymbolData::Trampoline(data) => self.handle_trampoline_symbol(index, data),
            SymbolData::Export(data) => self.handle_export_symbol(index, data),
            SymbolData::Local(data) => self.handle_local_symbol(index, data),
            SymbolData::BuildInfo(data) => self.handle_build_info_symbol(index, data),
            SymbolData::InlineSite(data) => self.handle_inline_site_symbol(index, data),
            SymbolData::InlineSiteEnd => self.handle_inline_site_end_symbol(index),
            SymbolData::ProcedureEnd => self.handle_procedure_end_symbol(index),
            SymbolData::Label(data) => self.handle_label_symbol(index, data),
            SymbolData::Block(data) => self.handle_block_symbol(index, data),
            SymbolData::RegisterRelative(data) => self.handle_register_relative_symbol(index, data),
            SymbolData::Thunk(data) => self.handle_thunk_symbol(index, data),
            SymbolData::SeparatedCode(data) => self.handle_separated_code_symbol(index, data),
            SymbolData::DefRange(data) => self.handle_def_range(index, &data),
            SymbolData::DefRangeSubField(data) => self.handle_def_range_sub_field(index, data),
            SymbolData::DefRangeRegister(data) => self.handle_def_range_register(index, data),
            SymbolData::DefRangeFramePointerRelative(data) => {
                self.handle_def_range_frame_pointer_relative_symbol(index, data)
            }
            SymbolData::DefRangeFramePointerRelativeFullScope(data) => {
                self.handle_def_range_frame_pointer_relative_full_scope_symbol(index, data)
            }
            SymbolData::DefRangeSubFieldRegister(data) => {
                self.handle_def_range_sub_field_register_symbol(index, data)
            }
            SymbolData::DefRangeRegisterRelative(data) => {
                self.handle_def_range_register_relative_symbol(index, data)
            }
            SymbolData::BasePointerRelative(data) => {
                self.handle_base_pointer_relative_symbol(index, data)
            }
            SymbolData::FrameProcedure(data) => self.handle_frame_procedure_symbol(index, data),
            SymbolData::CallSiteInfo(data) => self.handle_call_site_info(index, data),
            e => Err(anyhow!("Unhandled symbol type {:?}", e)),
        }
    }

    fn handle_scope_end_symbol(&mut self, _index: SymbolIndex) -> Result<Option<ParsedSymbol>> {
        self.log(|| "Got ScopeEnd symbol");
        Ok(None)
    }

    fn handle_obj_name_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ObjNameSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got ObjName symbol: {:?}", data));
        Ok(None)
    }

    fn handle_register_variable_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &RegisterVariableSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got RegisterVariable symbol: {:?}", data));

        let storage = if let Some(reg) = self.convert_register(data.register) {
            vec![ParsedLocation {
                location: Variable {
                    ty: VariableSourceType::RegisterVariableSourceType,
                    index: 0,
                    storage: reg.0 as i64,
                },
                base_relative: false,
                stack_relative: false,
            }]
        } else {
            // TODO: What do we do here?
            vec![]
        };

        Ok(Some(ParsedSymbol::LocalVariable(ParsedVariable {
            name: data.name.to_string().to_string(),
            type_: self.lookup_type_conf(&data.type_index, false)?,
            storage,
            is_param: data.slot.map_or(true, |slot| slot > 0),
        })))
    }

    fn handle_constant_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ConstantSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Constant symbol: {:?}", data));
        Ok(None)
    }

    fn handle_user_defined_type_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &UserDefinedTypeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got UserDefinedType symbol: {:?}", data));
        Ok(None)
    }

    fn handle_multi_register_variable_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &MultiRegisterVariableSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got MultiRegisterVariable symbol: {:?}", data));
        Ok(None)
    }

    fn handle_data_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DataSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Data symbol: {:?}", data));

        let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
        let raw_name = data.name.to_string().to_string();
        let (t, name) = self.demangle_to_type(&raw_name, rva)?;
        let name = name.map(|n| n.to_string());

        // Sometimes the demangler REALLY knows what type this is supposed to be, and the
        // data symbol is actually wrong. So in those cases, let the demangler take precedence
        // Otherwise-- the demangler is usually wrong and clueless
        let data_type = t.merge(self.lookup_type_conf(&data.type_index, false)?);

        // Ignore symbols with no name and no type
        if !self.settings.get_bool_with_opts(
            "pdb.features.allowUnnamedVoidSymbols",
            &mut self.settings_query_opts,
        ) && name.is_none()
        {
            if let Some(ty) = &data_type {
                if ty.contents.type_class() == TypeClass::VoidTypeClass {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

        let name = SymbolNames {
            raw_name,
            short_name: name.clone(),
            full_name: name,
        };

        self.log(|| {
            format!(
                "DATA: 0x{:x}: {:?} {:?}",
                self.bv.start() + rva.0 as u64,
                &name,
                &data_type
            )
        });

        Ok(Some(ParsedSymbol::Data(ParsedDataSymbol {
            is_public: false,
            address: self.bv.start() + rva.0 as u64,
            name,
            type_: data_type,
        })))
    }

    fn handle_public_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &PublicSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Public symbol: {:?}", data));
        let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
        let raw_name = data.name.to_string().to_string();
        let (t, name) = self.demangle_to_type(&raw_name, rva)?;
        let name = name.map(|n| n.to_string());

        let name = SymbolNames {
            raw_name,
            short_name: name.clone(),
            full_name: name,
        };

        // These are generally low confidence because we only have the demangler to inform us of type

        if data.function {
            self.log(|| {
                format!(
                    "PUBLIC FUNCTION: 0x{:x}: {:?} {:?}",
                    self.bv.start() + rva.0 as u64,
                    &name,
                    t
                )
            });

            Ok(Some(ParsedSymbol::Procedure(ParsedProcedure {
                is_public: true,
                address: self.bv.start() + rva.0 as u64,
                name,
                type_: t,
                locals: vec![],
            })))
        } else {
            self.log(|| {
                format!(
                    "PUBLIC DATA: 0x{:x}: {:?} {:?}",
                    self.bv.start() + rva.0 as u64,
                    &name,
                    t
                )
            });

            Ok(Some(ParsedSymbol::Data(ParsedDataSymbol {
                is_public: true,
                address: self.bv.start() + rva.0 as u64,
                name,
                type_: t,
            })))
        }
    }

    /// Given a proc symbol index and guessed type (from demangler or tpi), find all the local variables
    /// and parameters related to that symbol.
    /// Returns Ok(Some((resolved params, locals))))
    fn lookup_locals(
        &self,
        index: SymbolIndex,
        type_index: TypeIndex,
        demangled_type: Option<Conf<Ref<Type>>>,
    ) -> Result<(Option<Conf<Ref<Type>>>, Vec<ParsedVariable>)> {
        // So generally speaking, here's the information we have:
        // - The function type is usually accurate wrt the parameter locations
        // - The parameter symbols have the names we want for the params
        // - The parameter symbols are a big ugly mess
        // We basically want to take the function type from the type, and just fill in the
        // names of all the parameters. Non-param locals don't really matter since binja
        // can't handle them anyway.

        // Type parameters order needs to be like this:
        // 1. `this` pointer (if exists)
        // 2. Various stack params
        // 3. Various register params
        // We assume that if a parameter is found in a register, that is where it is passed.
        // Otherwise they are in the default order as per the CC

        // Get child objects and search for local variable names
        let mut locals = vec![];
        let mut params = vec![];
        let mut known_frame = false;
        for child in self.symbol_children(index) {
            match self.lookup_symbol(&child) {
                Some(ParsedSymbol::ProcedureInfo(info)) => {
                    params = info.params.clone();
                    locals = info.locals.clone();
                    known_frame = true;
                }
                _ => {}
            }
        }

        let raw_type = self.lookup_type_conf(&type_index, false)?;
        let fancy_type = self.lookup_type_conf(&type_index, true)?;

        // Best guess so far in case of error handling
        let fancier_type = fancy_type
            .clone()
            .merge(raw_type.clone())
            .merge(demangled_type.clone());

        if !known_frame {
            return Ok((fancier_type, vec![]));
        }

        // We need both of these to exist (not sure why they wouldn't)
        let (raw_type, fancy_type) = match (raw_type, fancy_type) {
            (Some(raw), Some(fancy)) => (raw, fancy),
            _ => return Ok((fancier_type, vec![])),
        };

        let raw_params = raw_type.contents.parameters().ok_or(anyhow!("no params"))?;
        let mut fancy_params = fancy_type
            .contents
            .parameters()
            .ok_or(anyhow!("no params"))?;

        // Collect all the parameters we are expecting from the symbols
        let mut parsed_params = vec![];
        for p in &params {
            let param = FunctionParameter::new(
                p.type_.clone().merge(Conf::new(
                    Type::int(self.arch.address_size(), false),
                    MIN_CONFIDENCE,
                )),
                p.name.clone(),
                p.storage.first().map(|loc| loc.location),
            );
            // Ignore thisptr because it's not technically part of the raw type signature
            if p.name != "this" {
                parsed_params.push(param);
            }
        }
        let mut parsed_locals = vec![];
        for p in &locals {
            let param = FunctionParameter::new(
                p.type_.clone().merge(Conf::new(
                    Type::int(self.arch.address_size(), false),
                    MIN_CONFIDENCE,
                )),
                p.name.clone(),
                p.storage.first().map(|loc| loc.location),
            );
            // Ignore thisptr because it's not technically part of the raw type signature
            if p.name != "this" {
                parsed_locals.push(param);
            }
        }

        self.log(|| format!("Raw params:    {:#x?}", raw_params));
        self.log(|| format!("Fancy params:  {:#x?}", fancy_params));
        self.log(|| format!("Parsed params: {:#x?}", parsed_params));

        // We expect one parameter for each unnamed parameter in the marked up type
        let expected_param_count = fancy_params.iter().filter(|p| p.name.is_empty()).count();
        // Sanity
        if expected_param_count != raw_params.len() {
            return Err(anyhow!(
                "Mismatched number of formal parameters and interpreted parameters"
            ));
        }

        // If we don't have enough parameters to fill the slots, there's a problem here
        // So just fallback to the unnamed params
        if expected_param_count > parsed_params.len() {
            // As per reversing of msdia140.dll (and nowhere else): if a function doesn't have
            // enough parameter variables declared as parameters, the remaining parameters are
            // the first however many locals. If you don't have enough of those, idk??
            if expected_param_count > (parsed_params.len() + parsed_locals.len()) {
                return Ok((fancier_type, vec![]));
            }
            parsed_params.extend(parsed_locals);
        }
        let expected_parsed_params = parsed_params
            .drain(0..expected_param_count)
            .collect::<Vec<_>>();

        // For all formal parameters, apply names to them in fancy_params
        // These should be all types in fancy_params that are unnamed (named ones we inserted)

        let mut i = 0;
        for p in fancy_params.iter_mut() {
            if p.name.is_empty() {
                if p.ty.contents != expected_parsed_params[i].ty.contents {
                    self.log(|| {
                        format!(
                            "Suspicious parameter {}: {:?} vs {:?}",
                            i, p, expected_parsed_params[i]
                        )
                    });
                }
                if expected_parsed_params[i].name.as_str() == "__formal" {
                    p.name = format!("__formal{}", i);
                } else {
                    p.name = expected_parsed_params[i].name.clone();
                }
                i += 1;
            }
        }

        // Now apply the default location for the params from the cc
        let cc = fancy_type
            .contents
            .calling_convention()
            .map_or_else(|| Conf::new(self.default_cc.clone(), 0), |cc| cc);

        self.log(|| {
            format!(
                "Type calling convention: {:?}",
                fancy_type.contents.calling_convention()
            )
        });
        self.log(|| format!("Default calling convention: {:?}", self.default_cc));
        self.log(|| format!("Result calling convention: {:?}", cc));

        let locations = cc.contents.variables_for_parameters(&fancy_params, None);
        for (p, new_location) in fancy_params.iter_mut().zip(locations.into_iter()) {
            p.location = Some(new_location);
        }

        self.log(|| format!("Final params: {:#x?}", fancy_params));

        // Use the new locals we've parsed to make the Real Definitely True function type
        let fancy_type = Conf::new(
            Type::function_with_opts(
                &fancy_type
                    .contents
                    .return_value()
                    .ok_or(anyhow!("no ret"))?,
                fancy_params.as_slice(),
                fancy_type.contents.has_variable_arguments().contents,
                cc,
                fancy_type.contents.stack_adjustment(),
            ),
            MAX_CONFIDENCE,
        );

        let fancier_type = fancy_type
            .clone()
            .merge(raw_type.clone())
            .merge(demangled_type.clone());

        self.log(|| format!("Raw type:       {:#x?}", raw_type));
        self.log(|| format!("Demangled type: {:#x?}", demangled_type));
        self.log(|| format!("Fancy type:     {:#x?}", fancy_type));
        self.log(|| format!("Result type:    {:#x?}", fancier_type));

        Ok((Some(fancier_type), vec![]))
    }

    fn handle_procedure_symbol(
        &mut self,
        index: SymbolIndex,
        data: &ProcedureSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Procedure symbol: {:?}", data));

        let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
        let address = self.bv.start() + rva.0 as u64;

        let mut raw_name = data.name.to_string().to_string();

        // Generally proc symbols have real types, but use the demangler just in case the microsoft
        // public pdbs have the function type as `void`
        let (t, name) = self.demangle_to_type(&raw_name, rva)?;
        let mut name = name.map(|n| n.to_string());

        // Some proc symbols don't have a mangled name, so try and look up their name
        if name.is_none() || name.as_ref().expect("just failed none") == &raw_name {
            // Lookup public symbol with the same name
            if let Some(others) = self.addressed_symbols.get(&address) {
                for o in others {
                    match o {
                        ParsedSymbol::Procedure(ParsedProcedure {
                            name: proc_name, ..
                        }) => {
                            if proc_name.full_name.as_ref().unwrap_or(&proc_name.raw_name)
                                == &raw_name
                            {
                                name = Some(raw_name);
                                raw_name = proc_name.raw_name.clone();
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let (fn_type, locals) = self.lookup_locals(index, data.type_index, t)?;

        let name = SymbolNames {
            raw_name,
            short_name: name.clone(),
            full_name: name,
        };

        self.log(|| format!("PROC: 0x{:x}: {:?} {:?}", address, &name, &fn_type));

        Ok(Some(ParsedSymbol::Procedure(ParsedProcedure {
            is_public: false,
            address,
            name,
            type_: fn_type,
            locals,
        })))
    }

    fn handle_thread_storage_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ThreadStorageSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got ThreadStorage symbol: {:?}", data));
        Ok(None)
    }

    fn handle_compile_flags_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &CompileFlagsSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got CompileFlags symbol: {:?}", data));
        self.module_cpu_type = Some(data.cpu_type);
        Ok(None)
    }

    fn handle_using_namespace_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &UsingNamespaceSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got UsingNamespace symbol: {:?}", data));
        Ok(None)
    }

    fn handle_procedure_reference_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ProcedureReferenceSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got ProcedureReference symbol: {:?}", data));
        Ok(None)
    }

    fn handle_data_reference_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DataReferenceSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DataReference symbol: {:?}", data));
        Ok(None)
    }

    fn handle_annotation_reference_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &AnnotationReferenceSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got AnnotationReference symbol: {:?}", data));
        Ok(None)
    }

    fn handle_trampoline_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &TrampolineSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Trampoline symbol: {:?}", data));
        let rva = data.thunk.to_rva(&self.address_map).unwrap_or_default();
        let target_rva = data.target.to_rva(&self.address_map).unwrap_or_default();

        let address = self.bv.start() + rva.0 as u64;
        let target_address = self.bv.start() + target_rva.0 as u64;

        let mut target_name = None;
        let mut thunk_name = None;

        let mut fn_type: Option<Conf<Ref<Type>>> = None;

        // These have the same name as their target, so look that up
        if let Some(syms) = self.addressed_symbols.get(&target_address) {
            // Take name from the public symbol
            for sym in syms {
                match sym {
                    ParsedSymbol::Procedure(proc) if proc.is_public => {
                        fn_type = proc.type_.clone().merge(fn_type);
                        target_name = Some(proc.name.clone());
                    }
                    _ => {}
                }
            }
            // Take type from the non-public symbol if we have one
            for sym in syms {
                match sym {
                    ParsedSymbol::Procedure(proc) if !proc.is_public => {
                        fn_type = proc.type_.clone().merge(fn_type);
                        if target_name.is_none() {
                            target_name = Some(proc.name.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        // And handle the fact that pdb public symbols for trampolines have the name of their target
        // ugh
        if let Some(syms) = self.addressed_symbols.get_mut(&address) {
            if let [ParsedSymbol::Procedure(proc)] = syms.as_mut_slice() {
                if let Some(tn) = &target_name {
                    if proc.name.raw_name == tn.raw_name
                        || proc.name.full_name.as_ref().unwrap_or(&proc.name.raw_name)
                            == tn.full_name.as_ref().unwrap_or(&tn.raw_name)
                    {
                        // Yeah it's one of these symbols
                        let old_name = proc.name.clone();
                        let new_name = SymbolNames {
                            raw_name: "j_".to_string() + &old_name.raw_name,
                            short_name: old_name.short_name.as_ref().map(|n| "j_".to_string() + n),
                            full_name: old_name.full_name.as_ref().map(|n| "j_".to_string() + n),
                        };

                        // I'm so sorry about this
                        // XXX: Update the parsed public symbol's name to use j_ syntax
                        if let Some(idx) = self.named_symbols.remove(&old_name.raw_name) {
                            self.named_symbols.insert(new_name.raw_name.clone(), idx);
                        }
                        if let Some(idx) = self.parsed_symbols_by_name.remove(&old_name.raw_name) {
                            self.parsed_symbols_by_name
                                .insert(new_name.raw_name.clone(), idx);
                            match &mut self.parsed_symbols[idx] {
                                ParsedSymbol::Data(ParsedDataSymbol {
                                    name: parsed_name, ..
                                })
                                | ParsedSymbol::Procedure(ParsedProcedure {
                                    name: parsed_name,
                                    ..
                                }) => {
                                    parsed_name.raw_name = new_name.raw_name.clone();
                                    parsed_name.short_name = new_name.short_name.clone();
                                    parsed_name.full_name = new_name.full_name.clone();
                                }
                                _ => {}
                            }
                        }
                        proc.name = new_name.clone();
                        thunk_name = Some(new_name);
                    }
                }
            }
        }

        if thunk_name.is_none() {
            if let Some(tn) = target_name {
                thunk_name = Some(SymbolNames {
                    raw_name: "j_".to_string() + &tn.raw_name,
                    short_name: tn.short_name.as_ref().map(|n| "j_".to_string() + n),
                    full_name: tn.full_name.as_ref().map(|n| "j_".to_string() + n),
                });
            }
        }

        let name = thunk_name.unwrap_or(SymbolNames {
            raw_name: format!("j_sub_{:x}", target_address),
            short_name: None,
            full_name: None,
        });

        self.log(|| format!("TRAMPOLINE: 0x{:x}: {:?} {:?}", address, &name, &fn_type));

        Ok(Some(ParsedSymbol::Procedure(ParsedProcedure {
            is_public: false,
            address,
            name,
            type_: fn_type,
            locals: vec![],
        })))
    }

    fn handle_export_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ExportSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Export symbol: {:?}", data));
        Ok(None)
    }

    fn handle_local_symbol(
        &mut self,
        index: SymbolIndex,
        data: &LocalSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Local symbol: {:?}", data));
        // Look for definition ranges for this symbol
        let mut locations: Vec<ParsedLocation> = vec![];
        for child in self.symbol_children(index) {
            match self.lookup_symbol(&child) {
                Some(ParsedSymbol::Location(loc)) => {
                    locations.push(*loc);
                }
                _ => {}
            }
        }

        Ok(Some(ParsedSymbol::LocalVariable(ParsedVariable {
            name: data.name.to_string().to_string(),
            type_: self.lookup_type_conf(&data.type_index, false)?,
            storage: locations,
            is_param: data.flags.isparam,
        })))
    }

    fn handle_build_info_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &BuildInfoSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got BuildInfo symbol: {:?}", data));
        Ok(None)
    }

    fn handle_inline_site_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &InlineSiteSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got InlineSite symbol: {:?}", data));
        Ok(None)
    }

    fn handle_inline_site_end_symbol(
        &mut self,
        _index: SymbolIndex,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| "Got InlineSiteEnd symbol");
        Ok(None)
    }

    fn handle_procedure_end_symbol(&mut self, _index: SymbolIndex) -> Result<Option<ParsedSymbol>> {
        self.log(|| "Got ProcedureEnd symbol");
        Ok(None)
    }

    fn handle_label_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &LabelSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Label symbol: {:?}", data));
        Ok(None)
    }

    fn handle_block_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &BlockSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Block symbol: {:?}", data));
        Ok(None)
    }

    fn handle_register_relative_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &RegisterRelativeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got RegisterRelative symbol: {:?}", data));
        match self.lookup_register(data.register) {
            Some(X86(X86Register::EBP)) | Some(AMD64(AMD64Register::RBP)) => {
                // Local is relative to base pointer
                // This is just another way of writing BasePointerRelativeSymbol
                Ok(Some(ParsedSymbol::LocalVariable(ParsedVariable {
                    name: data.name.to_string().to_string(),
                    type_: self.lookup_type_conf(&data.type_index, false)?,
                    storage: vec![ParsedLocation {
                        location: Variable {
                            ty: VariableSourceType::StackVariableSourceType,
                            index: 0,
                            storage: data.offset as i64,
                        },
                        base_relative: true,   // !!
                        stack_relative: false, // !!
                    }],
                    is_param: data.slot.map_or(false, |slot| slot > 0),
                })))
            }
            Some(X86(X86Register::ESP)) | Some(AMD64(AMD64Register::RSP)) => {
                // Local is relative to stack pointer
                // This is the same as base pointer case except not base relative (ofc)
                Ok(Some(ParsedSymbol::LocalVariable(ParsedVariable {
                    name: data.name.to_string().to_string(),
                    type_: self.lookup_type_conf(&data.type_index, false)?,
                    storage: vec![ParsedLocation {
                        location: Variable {
                            ty: VariableSourceType::StackVariableSourceType,
                            index: 0,
                            storage: data.offset as i64,
                        },
                        base_relative: false, // !!
                        stack_relative: true, // !!
                    }],
                    is_param: data.slot.map_or(false, |slot| slot > 0),
                })))
            }
            _ => {
                // Local is relative to some non-bp register.
                // This is, of course, totally possible and normal
                // Binja just can't handle it in the slightest.
                // Soooooooo ????
                // TODO
                Ok(None)
            }
        }
    }

    fn handle_thunk_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &ThunkSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got Thunk symbol: {:?}", data));
        let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
        let raw_name = data.name.to_string().to_string();
        let address = self.bv.start() + rva.0 as u64;

        let (t, name) = self.demangle_to_type(&raw_name, rva)?;
        let name = name.map(|n| n.to_string());
        let mut fn_type = t;

        // These have the same name as their target, so look that up
        if let Some(&idx) = self.named_symbols.get(&raw_name) {
            if let Some(ParsedSymbol::Procedure(proc)) = self.indexed_symbols.get(&idx) {
                fn_type = proc.type_.clone().merge(fn_type);
            }
        }

        let mut thunk_name = None;

        // And handle the fact that pdb public symbols for thunks have the name of their target
        // ugh
        if let Some(syms) = self.addressed_symbols.get_mut(&address) {
            if let [ParsedSymbol::Procedure(proc)] = syms.as_mut_slice() {
                // Yeah it's one of these symbols
                // Make sure we don't do this twice (does that even happen?)
                if !proc.name.raw_name.starts_with("j_") {
                    let old_name = proc.name.clone();
                    let new_name = SymbolNames {
                        raw_name: "j_".to_string() + &old_name.raw_name,
                        short_name: Some(
                            "j_".to_string() + old_name.short_name.as_ref().unwrap_or(&raw_name),
                        ),
                        full_name: Some(
                            "j_".to_string() + old_name.full_name.as_ref().unwrap_or(&raw_name),
                        ),
                    };

                    // I'm so sorry about this
                    // XXX: Update the parsed public symbol's name to use j_ syntax
                    if let Some(idx) = self.named_symbols.remove(&old_name.raw_name) {
                        self.named_symbols.insert(new_name.raw_name.clone(), idx);
                    }
                    if let Some(idx) = self.parsed_symbols_by_name.remove(&old_name.raw_name) {
                        self.parsed_symbols_by_name
                            .insert(new_name.raw_name.clone(), idx);
                        match &mut self.parsed_symbols[idx] {
                            ParsedSymbol::Data(ParsedDataSymbol {
                                name: parsed_name, ..
                            })
                            | ParsedSymbol::Procedure(ParsedProcedure {
                                name: parsed_name, ..
                            }) => {
                                parsed_name.raw_name = new_name.raw_name.clone();
                                parsed_name.short_name = new_name.short_name.clone();
                                parsed_name.full_name = new_name.full_name.clone();
                            }
                            _ => {}
                        }
                    }
                    proc.name = new_name.clone();
                    thunk_name = Some(new_name);
                }
            }
        }

        let locals = vec![];
        let name = thunk_name.unwrap_or(SymbolNames {
            raw_name,
            short_name: name.clone(),
            full_name: name,
        });

        self.log(|| format!("THUNK: 0x{:x}: {:?} {:?}", address, &name, &fn_type));

        Ok(Some(ParsedSymbol::Procedure(ParsedProcedure {
            is_public: false,
            address,
            name,
            type_: fn_type,
            locals,
        })))
    }

    fn handle_separated_code_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &SeparatedCodeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got SeparatedCode symbol: {:?}", data));
        Ok(None)
    }

    fn handle_def_range(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRange symbol: {:?}", data));
        Ok(None)
    }

    fn handle_def_range_sub_field(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeSubFieldSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRangeSubField symbol: {:?}", data));
        Ok(None)
    }

    fn handle_def_range_register(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeRegisterSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRangeRegister symbol: {:?}", data));
        if let Some(reg) = self.convert_register(data.register) {
            Ok(Some(ParsedSymbol::Location(ParsedLocation {
                location: Variable {
                    ty: VariableSourceType::RegisterVariableSourceType,
                    index: 0,
                    storage: reg.0 as i64,
                },
                base_relative: false,
                stack_relative: false,
            })))
        } else {
            Ok(None)
        }
    }

    fn handle_def_range_frame_pointer_relative_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeFramePointerRelativeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRangeFramePointerRelative symbol: {:?}", data));
        Ok(None)
    }

    fn handle_def_range_frame_pointer_relative_full_scope_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeFramePointerRelativeFullScopeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| {
            format!(
                "Got DefRangeFramePointerRelativeFullScope symbol: {:?}",
                data
            )
        });
        Ok(None)
    }

    fn handle_def_range_sub_field_register_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeSubFieldRegisterSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRangeSubFieldRegister symbol: {:?}", data));
        Ok(None)
    }

    fn handle_def_range_register_relative_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &DefRangeRegisterRelativeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got DefRangeRegisterRelative symbol: {:?}", data));
        Ok(None)
    }

    fn handle_base_pointer_relative_symbol(
        &mut self,
        _index: SymbolIndex,
        data: &BasePointerRelativeSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got BasePointerRelative symbol: {:?}", data));

        // These are usually parameters if offset > 0

        Ok(Some(ParsedSymbol::LocalVariable(ParsedVariable {
            name: data.name.to_string().to_string(),
            type_: self.lookup_type_conf(&data.type_index, false)?,
            storage: vec![ParsedLocation {
                location: Variable {
                    ty: VariableSourceType::StackVariableSourceType,
                    index: 0,
                    storage: data.offset as i64,
                },
                base_relative: true,
                stack_relative: false,
            }],
            is_param: data.offset as i64 > 0 || data.slot.map_or(false, |slot| slot > 0),
        })))
    }

    fn handle_frame_procedure_symbol(
        &mut self,
        index: SymbolIndex,
        data: &FrameProcedureSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got FrameProcedure symbol: {:?}", data));

        // This symbol generally comes before a proc and all various parameters
        // It has a lot of information we don't care about, and some information we maybe do?
        // This function also tries to find all the locals and parameters of the procedure

        let mut params = vec![];
        let mut locals = vec![];
        let mut seen_offsets = HashSet::new();

        for child in self.symbol_children(index) {
            match self.lookup_symbol(&child) {
                Some(ParsedSymbol::LocalVariable(ParsedVariable {
                    name,
                    type_,
                    storage,
                    is_param,
                    ..
                })) => {
                    let new_storage = storage.iter().map(|&var| var.location).collect::<Vec<_>>();

                    // See if the parameter really is a parameter. Sometimes they don't say they are
                    let mut really_is_param = *is_param;
                    for loc in &new_storage {
                        match loc {
                            Variable {
                                ty: VariableSourceType::RegisterVariableSourceType,
                                ..
                            } => {
                                // Assume register vars are always parameters
                                really_is_param = true;
                            }
                            Variable {
                                ty: VariableSourceType::StackVariableSourceType,
                                storage,
                                ..
                            } if *storage >= 0 => {
                                // Sometimes you can get two locals at the same offset, both rbp+(x > 0)
                                // I'm guessing from looking at dumps from dia2dump that only the first
                                // one is considered a parameter, although there are times that I see
                                // two params at the same offset and both are considered parameters...
                                // This doesn't seem possible (or correct) because they would overlap
                                // and only one would be useful anyway.
                                // Regardless of the mess, Binja can only handle one parameter per slot
                                // so we're just going to use the first one.
                                really_is_param = seen_offsets.insert(*storage);
                            }
                            _ => {}
                        }
                    }

                    if really_is_param {
                        params.push(ParsedVariable {
                            name: name.clone(),
                            type_: type_.clone(),
                            storage: new_storage
                                .into_iter()
                                .map(|loc| ParsedLocation {
                                    location: loc,
                                    // This has been handled now
                                    base_relative: false,
                                    stack_relative: false,
                                })
                                .collect(),
                            is_param: really_is_param,
                        });
                    } else {
                        locals.push(ParsedVariable {
                            name: name.clone(),
                            type_: type_.clone(),
                            storage: new_storage
                                .into_iter()
                                .map(|loc| ParsedLocation {
                                    location: loc,
                                    // This has been handled now
                                    base_relative: false,
                                    stack_relative: false,
                                })
                                .collect(),
                            is_param: really_is_param,
                        });
                    }
                }
                Some(ParsedSymbol::Data(_)) => {
                    // Apparently you can have static data symbols as parameters
                    // Because of course you can
                }
                None => {}
                e => self.log(|| format!("Unexpected symbol type in frame: {:?}", e)),
            }
        }

        Ok(Some(ParsedSymbol::ProcedureInfo(ParsedProcedureInfo {
            params,
            locals,
        })))
    }

    fn handle_call_site_info(
        &mut self,
        _index: SymbolIndex,
        data: &CallSiteInfoSymbol,
    ) -> Result<Option<ParsedSymbol>> {
        self.log(|| format!("Got CallSiteInfo symbol: {:?}", data));
        Ok(None)
    }

    /// Demangle a name and get a type out
    /// Also fixes void(void) and __s_RTTI_Nonsense
    fn demangle_to_type(
        &self,
        raw_name: &String,
        rva: Rva,
    ) -> Result<(Option<Conf<Ref<Type>>>, Option<QualifiedName>)> {
        let (mut t, mut name) = match demangle_ms(&self.arch, raw_name, true) {
            Some((name, Some(t))) => (Some(Conf::new(t, DEMANGLE_CONFIDENCE)), name),
            Some((name, _)) => (None, name),
            _ => (None, QualifiedName::new(vec![raw_name.clone()])),
        };

        if let Some(ty) = t.as_ref() {
            if ty.contents.type_class() == TypeClass::FunctionTypeClass {
                // demangler makes (void) into (void arg1) which is wrong
                let parameters = ty.contents.parameters().ok_or(anyhow!("no parameters"))?;
                if let [p] = parameters.as_slice() {
                    if p.ty.contents.type_class() == TypeClass::VoidTypeClass {
                        t = Some(Conf::new(
                            Type::function(
                                &ty.contents
                                    .return_value()
                                    .ok_or(anyhow!("no return value"))?,
                                vec![],
                                ty.contents.has_variable_arguments().contents,
                            ),
                            ty.confidence,
                        ))
                    }
                }
            }
        }

        // These have types but they aren't actually set anywhere. So it's the demangler's
        // job to take care of them, apparently?
        static MEM: OnceLock<Vec<(String, Vec<String>)>> = OnceLock::new();
        let name_to_type = MEM.get_or_init(|| {
            vec![
                (
                    "`RTTI Complete Object Locator'".to_string(),
                    vec![
                        "_s_RTTICompleteObjectLocator".to_string(),
                        "_s__RTTICompleteObjectLocator".to_string(),
                        "_s__RTTICompleteObjectLocator2".to_string(),
                    ],
                ),
                (
                    "`RTTI Class Hierarchy Descriptor'".to_string(),
                    vec![
                        "_s_RTTIClassHierarchyDescriptor".to_string(),
                        "_s__RTTIClassHierarchyDescriptor".to_string(),
                        "_s__RTTIClassHierarchyDescriptor2".to_string(),
                    ],
                ),
                (
                    // TODO: This type is dynamic
                    "`RTTI Base Class Array'".to_string(),
                    vec![
                        "_s_RTTIBaseClassArray".to_string(),
                        "_s__RTTIBaseClassArray".to_string(),
                        "_s__RTTIBaseClassArray2".to_string(),
                    ],
                ),
                (
                    "`RTTI Base Class Descriptor at (".to_string(),
                    vec![
                        "_s_RTTIBaseClassDescriptor".to_string(),
                        "_s__RTTIBaseClassDescriptor".to_string(),
                        "_s__RTTICBaseClassDescriptor2".to_string(),
                    ],
                ),
                (
                    "`RTTI Type Descriptor'".to_string(),
                    vec!["_TypeDescriptor".to_string()],
                ),
            ]
        });

        if let Some(last_name) = name.last() {
            for (search_name, search_types) in name_to_type.iter() {
                if last_name.contains(search_name) {
                    for search_type in search_types {
                        let qualified_search_type = QualifiedName::from(search_type);
                        if let Some(ty) = self.named_types.get(&qualified_search_type) {
                            // Fallback in case we don't find a specific one
                            t = Some(Conf::new(
                                Type::named_type_from_type(search_type, ty.as_ref()),
                                DEMANGLE_CONFIDENCE,
                            ));

                            if self.settings.get_bool_with_opts(
                                "pdb.features.expandRTTIStructures",
                                &mut self.settings_query_opts.clone(),
                            ) {
                                if let Some((lengthy_type, length)) =
                                    self.make_lengthy_type(ty, self.bv.start() + rva.0 as u64)?
                                {
                                    // See if we have a type with this length
                                    let lengthy_name: QualifiedName =
                                        format!("${}$_extraBytes_{}", search_type, length).into();

                                    if let Some(ty) = self.named_types.get(&lengthy_name) {
                                        // Wow!
                                        t = Some(Conf::new(
                                            Type::named_type_from_type(lengthy_name, ty.as_ref()),
                                            DEMANGLE_CONFIDENCE,
                                        ));
                                    } else {
                                        t = Some(Conf::new(lengthy_type, DEMANGLE_CONFIDENCE));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // VTables have types on their data symbols,
        if let Some((last, class_name)) = name.split_last() {
            if last.contains("`vftable'") {
                let mut vt_name = class_name.with_item("VTable");
                if last.contains("{for") {
                    // DerivedClass::`vftable'{for `BaseClass'}
                    let mut base_name = last.to_owned();
                    base_name.drain(0..("`vftable'{for `".len()));
                    base_name.drain((base_name.len() - "'}".len())..(base_name.len()));
                    // Multiply inherited classes have multiple vtable types
                    // TODO: Do that
                    vt_name = QualifiedName::new(vec![base_name, "VTable".to_string()]);
                }

                vt_name = vt_name
                    .replace("class ", "")
                    .replace("struct ", "")
                    .replace("enum ", "");

                if let Some(ty) = self.named_types.get(&vt_name) {
                    t = Some(Conf::new(
                        Type::named_type_from_type(vt_name, ty.as_ref()),
                        DEMANGLE_CONFIDENCE,
                    ));
                } else {
                    // Sometimes the demangler has trouble with `class Foo` in templates
                    vt_name = vt_name
                        .replace("class ", "")
                        .replace("struct ", "")
                        .replace("enum ", "");

                    if let Some(ty) = self.named_types.get(&vt_name) {
                        t = Some(Conf::new(
                            Type::named_type_from_type(vt_name, ty.as_ref()),
                            DEMANGLE_CONFIDENCE,
                        ));
                    } else {
                        t = Some(Conf::new(
                            Type::named_type_from_type(
                                vt_name,
                                Type::structure(StructureBuilder::new().finalize().as_ref())
                                    .as_ref(),
                            ),
                            DEMANGLE_CONFIDENCE,
                        ));
                    }
                }
            }
        }

        if let Some(last_name) = name.last_mut() {
            if last_name.starts_with("__imp_") {
                last_name.drain(0..("__imp_".len()));
            }
        }

        let name = if name.len() == 1 && &name[0] == raw_name && raw_name.starts_with('?') {
            None
        } else if name.len() == 1 && name[0].is_empty() {
            None
        } else if name.len() > 0 && name[0].starts_with("\x7f") {
            // Not sure why these exist but they do Weird Stuff
            name[0].drain(0..1);
            Some(name)
        } else {
            Some(name)
        };

        Ok((t, name))
    }

    fn make_lengthy_type(
        &self,
        base_type: &Ref<Type>,
        base_address: u64,
    ) -> Result<Option<(Ref<Type>, usize)>> {
        if base_type.type_class() != TypeClass::StructureTypeClass {
            return Ok(None);
        }
        let structure = base_type
            .get_structure()
            .ok_or(anyhow!("Expected structure"))?;
        let mut members = structure.members();
        let last_member = members.last_mut().ok_or(anyhow!("Not enough members"))?;

        if last_member.ty.contents.type_class() != TypeClass::ArrayTypeClass {
            return Ok(None);
        }
        if last_member.ty.contents.count() != 0 {
            return Ok(None);
        }

        let member_element = last_member
            .ty
            .contents
            .element_type()
            .ok_or(anyhow!("Last member has no type"))?
            .contents;
        let member_width = member_element.width();

        // Read member_width bytes from bv starting at that member, until we read all zeroes
        let member_address = base_address + last_member.offset;

        let mut bytes = vec![0; member_width as usize];

        let mut element_count = 0;
        while self.bv.read(
            bytes.as_mut_slice(),
            member_address + member_width * element_count,
        ) == member_width as usize
        {
            if bytes.iter().all(|&b| b == 0) {
                break;
            }
            element_count += 1;
        }

        // Make a new copy of the type with the correct element count
        last_member.ty.contents = Type::array(&member_element, element_count);

        Ok(Some((
            Type::structure(StructureBuilder::from(members).finalize().as_ref()),
            element_count as usize,
        )))
    }

    /// Sorry about the type names
    /// Given a pdb::Register (u32), get a pdb::register::Register (big enum with names)
    fn lookup_register(&self, reg: pdb::Register) -> Option<pdb::register::Register> {
        if let Some(cpu) = self.module_cpu_type {
            pdb::register::Register::new(reg, cpu).ok()
        } else {
            None
        }
    }

    /// Convert a pdb::Register (u32) to a binja register index for the current arch
    fn convert_register(&self, reg: pdb::Register) -> Option<RegisterId> {
        match self.lookup_register(reg) {
            Some(X86(xreg)) => {
                self.log(|| format!("Register {:?} ==> {:?}", reg, xreg));
                self.arch
                    .register_by_name(xreg.to_string().to_lowercase())
                    .map(|reg| reg.id())
            }
            Some(AMD64(areg)) => {
                self.log(|| format!("Register {:?} ==> {:?}", reg, areg));
                self.arch
                    .register_by_name(areg.to_string().to_lowercase())
                    .map(|reg| reg.id())
            }
            // TODO: Other arches
            _ => None,
        }
    }
}

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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Display;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use log::{debug, info};
use pdb::*;

use crate::symbol_parser::{ParsedDataSymbol, ParsedProcedure, ParsedSymbol};
use crate::type_parser::ParsedType;
use binaryninja::architecture::{Architecture, CoreArchitecture};
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::calling_convention::CoreCallingConvention;
use binaryninja::confidence::{Conf, MIN_CONFIDENCE};
use binaryninja::debuginfo::{DebugFunctionInfo, DebugInfo};
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::types::{
    EnumerationBuilder, NamedTypeReference, NamedTypeReferenceClass, QualifiedName,
    StructureBuilder, StructureType, Type, TypeClass,
};
use binaryninja::variable::NamedDataVariableWithType;

/// Megastruct for all the parsing
/// Certain fields are only used by specific files, as marked below.
/// Why not make new structs for them? Because vvvv this garbage
pub struct PDBParserInstance<'a, S: Source<'a> + 'a> {
    /// DebugInfo where types/functions will be stored eventually
    pub(crate) debug_info: &'a mut DebugInfo,
    /// Parent binary view (usually during BinaryView::Finalize)
    pub(crate) bv: &'a BinaryView,
    /// Default arch of self.bv
    pub(crate) arch: CoreArchitecture,
    /// Default calling convention for self.arch
    pub(crate) default_cc: Ref<CoreCallingConvention>,
    /// Thiscall calling convention for self.bv, or default_cc if we can't find one
    pub(crate) thiscall_cc: Ref<CoreCallingConvention>,
    /// Cdecl calling convention for self.bv, or default_cc if we can't find one
    pub(crate) cdecl_cc: Ref<CoreCallingConvention>,
    /// Default platform of self.bv
    pub(crate) platform: Ref<Platform>,
    /// pdb-rs structure for making lifetime hell a real place
    pub(crate) pdb: PDB<'a, S>,
    /// pdb-rs Mapping of modules to addresses for resolving RVAs
    pub(crate) address_map: AddressMap<'a>,
    /// Binja Settings instance (for optimization)
    pub(crate) settings: Ref<Settings>,
    /// Binja Settings query instance (for optimization)
    pub(crate) settings_query_opts: QueryOptions<'a>,

    /// type_parser.rs

    /// TypeIndex -> ParsedType enum used during parsing
    pub(crate) indexed_types: BTreeMap<TypeIndex, ParsedType>,
    /// QName -> Binja Type for finished types
    pub(crate) named_types: BTreeMap<QualifiedName, Ref<Type>>,
    /// Raw (mangled) name -> TypeIndex for resolving forward references
    pub(crate) full_type_indices: BTreeMap<String, TypeIndex>,
    /// Stack of types we're currently parsing
    pub(crate) type_stack: Vec<TypeIndex>,
    /// Stack of parent types we're parsing nested types inside of
    pub(crate) namespace_stack: QualifiedName,
    /// Type Index -> Does it return on the stack
    pub(crate) type_default_returnable: BTreeMap<TypeIndex, bool>,

    /// symbol_parser.rs

    /// List of fully parsed symbols from all modules
    pub(crate) parsed_symbols: Vec<ParsedSymbol>,
    /// Raw name -> index in parsed_symbols
    pub(crate) parsed_symbols_by_name: BTreeMap<String, usize>,
    /// Raw name -> Symbol index for looking up symbols for the currently parsing module (mostly for thunks)
    pub(crate) named_symbols: BTreeMap<String, SymbolIndex>,
    /// Parent -> Children symbol index tree for the currently parsing module
    pub(crate) symbol_tree: BTreeMap<SymbolIndex, Vec<SymbolIndex>>,
    /// Child -> Parent symbol index mapping, inverse of symbol_tree
    pub(crate) symbol_parents: BTreeMap<SymbolIndex, SymbolIndex>,
    /// Stack of (start, end) indices for the current symbols being parsed while constructing the tree
    pub(crate) symbol_stack: Vec<(SymbolIndex, SymbolIndex)>,
    /// Index -> parsed symbol for the currently parsing module
    pub(crate) indexed_symbols: BTreeMap<SymbolIndex, ParsedSymbol>,
    /// Symbol address -> Symbol for looking up by address
    pub(crate) addressed_symbols: BTreeMap<u64, Vec<ParsedSymbol>>,
    /// CPU type of the currently parsing module
    pub(crate) module_cpu_type: Option<CPUType>,
}

impl<'a, S: Source<'a> + 'a> PDBParserInstance<'a, S> {
    /// Try to create a new parser instance from a given bv/pdb
    pub fn new(
        debug_info: &'a mut DebugInfo,
        bv: &'a BinaryView,
        mut pdb: PDB<'a, S>,
    ) -> Result<Self> {
        let arch = if let Some(arch) = bv.default_arch() {
            arch
        } else {
            return Err(anyhow!("Cannot parse to view with no architecture"));
        };

        let platform = bv
            .default_platform()
            .expect("Expected bv to have a platform");

        let address_map = pdb.address_map()?;

        let default_cc = platform
            .get_default_calling_convention()
            .expect("Expected default calling convention");

        let thiscall_cc = Self::find_calling_convention(platform.as_ref(), "thiscall")
            .unwrap_or(default_cc.clone());

        let cdecl_cc = platform
            .get_cdecl_calling_convention()
            .unwrap_or(default_cc.clone());

        Ok(Self {
            debug_info,
            bv,
            arch,
            default_cc,
            thiscall_cc,
            cdecl_cc,
            platform,
            pdb,
            address_map,
            settings: Settings::new(),
            settings_query_opts: QueryOptions::new_with_view(bv),
            indexed_types: Default::default(),
            named_types: Default::default(),
            full_type_indices: Default::default(),
            type_stack: Default::default(),
            namespace_stack: Default::default(),
            type_default_returnable: Default::default(),
            parsed_symbols: Default::default(),
            parsed_symbols_by_name: Default::default(),
            named_symbols: Default::default(),
            symbol_tree: Default::default(),
            symbol_parents: Default::default(),
            symbol_stack: Default::default(),
            indexed_symbols: Default::default(),
            addressed_symbols: Default::default(),
            module_cpu_type: None,
        })
    }

    /// Try to parse the pdb into the DebugInfo
    pub fn try_parse_info(
        &mut self,
        progress: Box<dyn Fn(usize, usize) -> Result<()> + 'a>,
    ) -> Result<()> {
        self.parse_types(Self::split_progress(&progress, 0, &[1.0, 3.0, 0.5, 0.5]))?;
        for (name, ty) in self.named_types.iter() {
            self.debug_info.add_type(name, ty.as_ref(), &[]); // TODO : Components
        }

        info!(
            "PDB found {} types (before resolving NTRs)",
            self.named_types.len()
        );

        if self
            .settings
            .get_bool_with_opts("pdb.features.parseSymbols", &mut self.settings_query_opts)
        {
            let (symbols, functions) =
                self.parse_symbols(Self::split_progress(&progress, 1, &[1.0, 3.0, 0.5, 0.5]))?;

            if self.settings.get_bool_with_opts(
                "pdb.features.createMissingNamedTypes",
                &mut self.settings_query_opts,
            ) {
                self.resolve_missing_ntrs(
                    &symbols,
                    Self::split_progress(&progress, 2, &[1.0, 3.0, 0.5, 0.5]),
                )?;
                self.resolve_missing_ntrs(
                    &functions,
                    Self::split_progress(&progress, 3, &[1.0, 3.0, 0.5, 0.5]),
                )?;
            }

            info!("PDB found {} types", self.named_types.len());
            info!("PDB found {} data variables", symbols.len());
            info!("PDB found {} functions", functions.len());

            let allow_void = self.settings.get_bool_with_opts(
                "pdb.features.allowVoidGlobals",
                &mut self.settings_query_opts,
            );

            let min_confidence_type = Conf::new(Type::void(), MIN_CONFIDENCE);
            for sym in symbols {
                match sym {
                    ParsedSymbol::Data(ParsedDataSymbol {
                        address,
                        name,
                        type_,
                        ..
                    }) => {
                        let real_type = type_.as_ref().unwrap_or(&min_confidence_type);

                        if real_type.contents.type_class() == TypeClass::VoidTypeClass {
                            if !allow_void {
                                self.log(|| {
                                    format!("Not adding void-typed symbol {:?}@{:x}", name, address)
                                });
                                continue;
                            }
                        }

                        self.log(|| {
                            format!(
                                "Adding data variable: 0x{:x}: {} {:?}",
                                address, &name.raw_name, real_type
                            )
                        });
                        self.debug_info
                            .add_data_variable_info(NamedDataVariableWithType::new(
                                address,
                                real_type.clone(),
                                name.full_name.unwrap_or(name.raw_name),
                                true,
                            ));
                    }
                    s => {
                        self.log(|| format!("Not adding non-data symbol {:?}", s));
                    }
                }
            }

            for sym in functions {
                match sym {
                    ParsedSymbol::Procedure(ParsedProcedure {
                        address,
                        name,
                        type_,
                        locals: _,
                        ..
                    }) => {
                        self.log(|| {
                            format!(
                                "Adding function: 0x{:x}: {} {:?}",
                                address, &name.raw_name, type_
                            )
                        });
                        self.debug_info.add_function(DebugFunctionInfo::new(
                            Some(name.short_name.unwrap_or(name.raw_name.clone())),
                            Some(name.full_name.unwrap_or(name.raw_name.clone())),
                            Some(name.raw_name),
                            type_.clone().and_then(|conf| {
                                // TODO: When DebugInfo support confidence on function types, remove this
                                if conf.confidence == 0 {
                                    None
                                } else {
                                    Some(conf.contents)
                                }
                            }),
                            Some(address),
                            Some(self.platform.clone()),
                            vec![], // TODO : Components
                            vec![], //TODO: local variables
                        ));
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn collect_name(
        &self,
        name: &NamedTypeReference,
        unknown_names: &mut HashMap<QualifiedName, NamedTypeReferenceClass>,
    ) {
        let used_name = name.name();
        if let Some(&found) = unknown_names.get(&used_name) {
            if found != name.class() {
                // Interesting case, not sure we care
                self.log(|| {
                    format!(
                        "Mismatch unknown NTR class for {}: {} ?",
                        &used_name,
                        name.class() as u32
                    )
                });
            }
        } else {
            self.log(|| format!("Found new unused name: {}", &used_name));
            unknown_names.insert(used_name, name.class());
        }
    }

    fn collect_names(
        &self,
        ty: &Type,
        unknown_names: &mut HashMap<QualifiedName, NamedTypeReferenceClass>,
    ) {
        match ty.type_class() {
            TypeClass::StructureTypeClass => {
                if let Some(structure) = ty.get_structure() {
                    for member in structure.members() {
                        self.collect_names(member.ty.contents.as_ref(), unknown_names);
                    }
                    for base in structure.base_structures() {
                        self.collect_name(base.ty.as_ref(), unknown_names);
                    }
                }
            }
            TypeClass::PointerTypeClass => {
                if let Some(target) = ty.target() {
                    self.collect_names(target.contents.as_ref(), unknown_names);
                }
            }
            TypeClass::ArrayTypeClass => {
                if let Some(element_type) = ty.element_type() {
                    self.collect_names(element_type.contents.as_ref(), unknown_names);
                }
            }
            TypeClass::FunctionTypeClass => {
                if let Some(return_value) = ty.return_value() {
                    self.collect_names(return_value.contents.as_ref(), unknown_names);
                }
                if let Some(params) = ty.parameters() {
                    for param in params {
                        self.collect_names(param.ty.contents.as_ref(), unknown_names);
                    }
                }
            }
            TypeClass::NamedTypeReferenceClass => {
                if let Some(ntr) = ty.get_named_type_reference() {
                    self.collect_name(ntr.as_ref(), unknown_names);
                }
            }
            _ => {}
        }
    }

    fn resolve_missing_ntrs(
        &mut self,
        symbols: &Vec<ParsedSymbol>,
        progress: Box<dyn Fn(usize, usize) -> Result<()> + '_>,
    ) -> Result<()> {
        let mut unknown_names = HashMap::new();
        let mut known_names = self
            .bv
            .types()
            .iter()
            .map(|qnat| qnat.name)
            .collect::<HashSet<_>>();

        for ty in &self.named_types {
            known_names.insert(ty.0.clone());
        }

        let count = symbols.len();
        for (i, sym) in symbols.iter().enumerate() {
            match sym {
                ParsedSymbol::Data(ParsedDataSymbol {
                    type_: Some(type_), ..
                }) => {
                    self.collect_names(type_.contents.as_ref(), &mut unknown_names);
                }
                ParsedSymbol::Procedure(ParsedProcedure {
                    type_: Some(type_),
                    locals,
                    ..
                }) => {
                    self.collect_names(type_.contents.as_ref(), &mut unknown_names);
                    for l in locals {
                        if let Some(ltype) = &l.type_ {
                            self.collect_names(ltype.contents.as_ref(), &mut unknown_names);
                        }
                    }
                }
                _ => {}
            }
            progress(i, count)?;
        }

        for (name, class) in unknown_names.into_iter() {
            if known_names.contains(&name) {
                self.log(|| format!("Found referenced name and ignoring: {}", &name));
                continue;
            }
            self.log(|| format!("Adding referenced but unknown type {} (likely due to demangled name and stripped type)", &name));
            match class {
                NamedTypeReferenceClass::UnknownNamedTypeClass
                | NamedTypeReferenceClass::TypedefNamedTypeClass => {
                    self.debug_info.add_type(&name, Type::void().as_ref(), &[]);
                    // TODO : Components
                }
                NamedTypeReferenceClass::ClassNamedTypeClass
                | NamedTypeReferenceClass::StructNamedTypeClass
                | NamedTypeReferenceClass::UnionNamedTypeClass => {
                    let mut structure = StructureBuilder::new();
                    match class {
                        NamedTypeReferenceClass::ClassNamedTypeClass => {
                            structure.structure_type(StructureType::ClassStructureType);
                        }
                        NamedTypeReferenceClass::StructNamedTypeClass => {
                            structure.structure_type(StructureType::StructStructureType);
                        }
                        NamedTypeReferenceClass::UnionNamedTypeClass => {
                            structure.structure_type(StructureType::UnionStructureType);
                        }
                        _ => {}
                    }
                    structure.width(1);
                    structure.alignment(1);

                    self.debug_info.add_type(
                        &name,
                        Type::structure(structure.finalize().as_ref()).as_ref(),
                        &[], // TODO : Components
                    );
                }
                NamedTypeReferenceClass::EnumNamedTypeClass => {
                    let enumeration = EnumerationBuilder::new();
                    self.debug_info.add_type(
                        &name,
                        Type::enumeration(
                            enumeration.finalize().as_ref(),
                            self.arch.default_integer_size().try_into()?,
                            false,
                        )
                        .as_ref(),
                        &[], // TODO : Components
                    );
                }
            }
        }

        Ok(())
    }

    /// Lazy logging function that prints like 20MB of messages
    pub(crate) fn log<F: FnOnce() -> D, D: Display>(&self, msg: F) {
        static MEM: OnceLock<bool> = OnceLock::new();
        let debug_pdb = MEM.get_or_init(|| env::var("BN_DEBUG_PDB").is_ok());
        if *debug_pdb {
            let space = "\t".repeat(self.type_stack.len()) + &"\t".repeat(self.symbol_stack.len());
            let msg = format!("{}", msg());
            debug!(
                "{}{}",
                space,
                msg.replace("\n", &("\n".to_string() + &space))
            );
        }
    }

    pub(crate) fn split_progress<'b, F: Fn(usize, usize) -> Result<()> + 'b>(
        original_fn: F,
        subpart: usize,
        subpart_weights: &[f64],
    ) -> Box<dyn Fn(usize, usize) -> Result<()> + 'b> {
        // Normalize weights
        let weight_sum: f64 = subpart_weights.iter().sum();
        if weight_sum < 0.0001 {
            return Box::new(|_, _| Ok(()));
        }

        // Keep a running count of weights for the start
        let mut subpart_starts = vec![];
        let mut start = 0f64;
        for w in subpart_weights {
            subpart_starts.push(start);
            start += *w;
        }

        let subpart_start = subpart_starts[subpart] / weight_sum;
        let weight = subpart_weights[subpart] / weight_sum;

        Box::new(move |cur: usize, max: usize| {
            // Just use a large number for easy divisibility
            let steps = 1000000f64;
            let subpart_size = steps * weight;
            let subpart_progress = ((cur as f64) / (max as f64)) * subpart_size;

            original_fn(
                (subpart_start * steps + subpart_progress) as usize,
                steps as usize,
            )
        })
    }
}

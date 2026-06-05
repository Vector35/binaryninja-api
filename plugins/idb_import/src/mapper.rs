//! Map the IDB data we parsed into the [`BinaryView`].

use crate::parse::{
    BaseAddressInfo, CommentInfo, ExportInfo, FunctionInfo, IDBInfo, LabelInfo, NameInfo,
    SegmentInfo,
};
use crate::translate::TILTranslator;
use binaryninja::architecture::Architecture;
use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::qualified_name::QualifiedName;
use binaryninja::rc::Ref;
use binaryninja::section::{SectionBuilder, Semantics};
use binaryninja::symbol::{Binding, Symbol, SymbolType};
use binaryninja::types::Type;
use idb_rs::id0::SegmentType;
use idb_rs::til::TypeVariant;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Maps IDB data into a [`BinaryView`].
///
/// The mapper can be re-used if mapping into multiple views.
pub struct IDBMapper {
    info: IDBInfo,
}

impl IDBMapper {
    pub fn new(info: IDBInfo) -> Self {
        Self { info }
    }

    pub fn map_to_view(&self, view: &BinaryView) {
        let Some(id0) = &self.info.id0 else {
            tracing::warn!("No ID0 data found, skipping mapping.");
            return;
        };

        // Verify the IDB was built from the binary we are about to map into. The IDB records the
        // SHA256 of its original input file; the root of the view's parent chain is the raw view,
        // whose bytes are that same on-disk file, so we can hash it and compare.
        if let Some(expected_sha256) = &self.info.sha256 {
            match sha256_of_raw_view(view) {
                Some(actual_sha256) if actual_sha256 == *expected_sha256 => {
                    tracing::debug!("Verified IDB matches loaded binary (SHA256 {expected_sha256})");
                }
                Some(actual_sha256) => {
                    tracing::warn!(
                        "IDB input file SHA256 ({expected_sha256}) does not match the loaded \
                         binary ({actual_sha256}); imported data may not correspond to this binary."
                    );
                }
                None => {
                    tracing::debug!(
                        "Could not hash the loaded binary to verify against IDB SHA256 {expected_sha256}"
                    );
                }
            }
        }

        // Rebase the address from ida -> binja without this rebased views will fail to map.
        let bn_base_address = view.start();
        let base_address_delta = match id0.base_address {
            // There is no base address in the IDA file, so we assume everything is relative and rebase.
            BaseAddressInfo::None => bn_base_address,
            BaseAddressInfo::BaseSegment(start_addr) => bn_base_address.wrapping_sub(start_addr),
            BaseAddressInfo::BaseSection(section_addr) => {
                // Align against the lowest mapped *segment*, not the lowest section.
                // IDA's `min_ea` is the image base (it maps the file header too), but a
                // Mach-O's first section (`__text`) starts after the header + load
                // commands. Using the lowest section here over-shifts every imported
                // address by the header size; segments include the header region.
                let bn_segment_addr = view
                    .segments()
                    .iter()
                    .map(|s| s.address_range().start)
                    .min();
                match bn_segment_addr {
                    Some(bn_segment) => bn_segment.wrapping_sub(section_addr),
                    None => bn_base_address,
                }
            }
        };

        tracing::debug!(
            "Rebasing for {:0x} with delta {:0x}",
            bn_base_address,
            base_address_delta
        );
        let rebase = |addr: u64| -> u64 { addr.wrapping_add(base_address_delta) };

        for segment in &id0.segments {
            let mut rebased_segment = segment.clone();
            rebased_segment.region.start = rebase(segment.region.start);
            rebased_segment.region.end = rebase(segment.region.end);
            self.map_segment_to_view(view, &rebased_segment);
        }

        // Create the type translator, adding all referencable types from both the TIL and the binary view.
        let platform = view.default_platform().unwrap();
        // Provide a fallback `size_t` only when the view does not already define one. Many IDA
        // types reference `size_t`, so we keep this safety net, but defining it conditionally
        // avoids clobbering a real platform/view definition with our generic integer.
        if view.type_by_name("size_t").is_none() {
            view.define_auto_type(
                "size_t",
                "IDA",
                &Type::int(platform.arch().default_integer_size(), false),
            );
        }
        let til_translator =
            TILTranslator::new_from_platform(&platform).with_type_container(&view.type_container());
        let til_translator = match &self.info.til {
            Some(til) => til_translator.with_til_info(&til),
            None => til_translator,
        };

        self.map_types_to_view(view, &til_translator, &self.info.merged_types());

        for func in &self.info.merged_functions() {
            let mut rebased_func = func.clone();
            rebased_func.address = rebase(func.address);
            self.map_func_to_view(view, &til_translator, &rebased_func);
        }

        for export in &id0.exports {
            let mut rebased_export = export.clone();
            rebased_export.address = rebase(export.address);
            self.map_export_to_view(view, &til_translator, &rebased_export);
        }

        // NOTE: The undo bracketing below is not thread safe, so the mapper must be the only
        // writer mutating the view while it runs. This invariant holds because mapping is
        // registered as a single run-once analysis activity (see `plugin_init`) rather than being
        // invoked concurrently.
        let undo = view.file().begin_undo_actions(true);
        for comment in &self.info.merged_comments() {
            let mut rebased_comment = comment.clone();
            rebased_comment.address = rebase(comment.address);
            self.map_comment_to_view(view, &rebased_comment);
        }
        view.file().forget_undo_actions(&undo);

        for name in &self.info.merged_names() {
            let mut rebased_name = name.clone();
            rebased_name.address = rebase(name.address);
            self.map_name_to_view(view, &til_translator, &rebased_name);
        }

        // self.map_used_types_to_view(view, &til_translator);
    }

    pub fn map_types_to_view(
        &self,
        view: &BinaryView,
        til_translator: &TILTranslator,
        types: &[idb_rs::til::TILTypeInfo],
    ) {
        for ty in types {
            let ty_name = ty.name.to_string();
            if view.type_by_name(&ty_name).is_some() {
                tracing::debug!("Type already exists in view: {}", ty_name);
                continue;
            }
            match til_translator.translate_type_info(&ty.tinfo) {
                Ok(bn_ty) => {
                    tracing::debug!("Mapping type: {}", ty.name);
                    view.define_auto_type(&ty_name, "IDA", &bn_ty);
                }
                Err(err) => {
                    tracing::warn!("Failed to map type {}: {}", ty.name, err)
                }
            }
        }
    }

    pub fn map_used_types_to_view(&self, view: &BinaryView, til_translator: &TILTranslator) {
        let type_archives: Vec<_> = view
            .attached_type_archives()
            .iter()
            .filter_map(|id| view.type_archive_by_id(&id))
            .collect();

        let mut til_type_map = std::collections::HashMap::new();
        if let Some(til) = &self.info.til {
            til_type_map = til
                .types
                .iter()
                .map(|ty| (ty.name.to_string(), ty))
                .collect();
        }
        if let Some(dir_tree) = &self.info.dir_tree {
            til_type_map = dir_tree
                .types
                .iter()
                .map(|ty| (ty.name.to_string(), ty))
                .collect();
        }

        let mut used_types = HashSet::new();
        if let Ok(_used_types) = til_translator.used_types.lock() {
            used_types = _used_types.clone();
        }
        // NOTE: Types are resolved here after they have already been applied to functions, so any
        // named type references that get defined in this pass will read as stale until analysis
        // re-runs and re-resolves them. Acceptable for this best-effort backfill, but a reason to
        // resolve referenced types before applying function types if this path is wired in.
        'found: for used_ty in &used_types {
            // 0. Make sure the type doesn't already exist in the view
            if view.type_by_name(&used_ty.name).is_some() {
                tracing::debug!("Type already exists in view: {:?}", used_ty.name);
                continue 'found;
            }

            // 1. Check in BN type libraries.
            if let Some(found_ty) = view.import_type_library_type(&used_ty.name, None) {
                tracing::debug!("Found type in type library: {:?}", found_ty);
                continue 'found;
            }

            // 2. Check in type archives
            for type_archive in &type_archives {
                if let Some(found_ty) =
                    type_archive.get_type_by_name(QualifiedName::from(&used_ty.name))
                {
                    tracing::debug!("Found type in type archive: {:?}", found_ty);
                    view.define_auto_type(&used_ty.name, "IDA", &found_ty);
                    continue 'found;
                }
            }

            // // 3. Check in the TIL of the IDB info.
            if let Some(ty) = til_type_map.get(&used_ty.name) {
                if let Ok(bn_ty) = til_translator.translate_type_info(&ty.tinfo) {
                    tracing::debug!("Found type in TIL: {:?}", ty);
                    view.define_auto_type(&used_ty.name, "IDA", &bn_ty);
                    continue 'found;
                }
            }

            // NOTE: A further lookup source would be the TILs attached to the IDB (e.g. imported
            // library TILs) before giving up; not yet wired in.
            tracing::warn!("Failed to find type: {:?}", used_ty);
        }
    }

    pub fn map_segment_to_view(&self, view: &BinaryView, segment: &SegmentInfo) {
        let semantics = match segment.ty {
            SegmentType::Norm => Semantics::DefaultSection,
            // One issue is that an IDA section named 'extern' is _actually_ a synthetic section, so we
            // should not map it.
            SegmentType::Xtrn if segment.name == "extern" => {
                return;
            }
            SegmentType::Xtrn => {
                // IDA definition of extern is an actual section like '.idata' whereas extern in BN
                // is a synthetic section, do NOT use [`Semantics::External`].
                Semantics::ReadWriteData
            }
            SegmentType::Code => Semantics::ReadOnlyCode,
            SegmentType::Data => Semantics::ReadWriteData,
            SegmentType::Imp => Semantics::DefaultSection,
            SegmentType::Grp => Semantics::DefaultSection,
            SegmentType::Null => Semantics::DefaultSection,
            SegmentType::Undf => {
                // Don't map undefined segment i guess?
                return;
            }
            SegmentType::Bss => Semantics::ReadWriteData,
            SegmentType::Abssym => Semantics::DefaultSection,
            SegmentType::Comm => Semantics::DefaultSection,
            SegmentType::Imem => Semantics::DefaultSection,
        };

        // NOTE: We dedup on section name rather than address range on purpose. The BN loader has
        // usually already mapped the whole address space, so an IDA segment would always overlap
        // an existing section and a range-based check would suppress every segment. Name-based
        // dedup only skips re-adding a section we (or the loader) already named identically.
        if view.section_by_name(&segment.name).is_some() {
            tracing::debug!(
                "Section with name '{}' already exists, skipping...",
                segment.name
            );
            return;
        }

        tracing::info!(
            "Mapping segment '{}': {:0x} - {:0x} ({:?})",
            segment.name,
            segment.region.start,
            segment.region.end,
            segment.ty
        );

        let section = SectionBuilder::new(segment.name.clone(), segment.region.clone())
            .semantics(semantics)
            .is_auto(true);
        view.add_section(section);
    }

    pub fn map_export_to_view(
        &self,
        view: &BinaryView,
        til_translator: &TILTranslator,
        export: &ExportInfo,
    ) {
        let within_code_section = view
            .sections_at(export.address)
            .iter()
            .find(|s| s.semantics() == Semantics::ReadOnlyCode)
            .is_some();
        let is_func_ty = export
            .ty
            .as_ref()
            .is_some_and(|ty| matches!(ty.type_variant, TypeVariant::Function(_)));

        if within_code_section && is_func_ty {
            tracing::debug!("Mapping function export: {:0x}", export.address);
            let func_info = FunctionInfo {
                name: Some(export.name.clone()),
                ty: export.ty.clone(),
                address: export.address,
                is_library: false,
                is_no_return: false,
            };
            self.map_func_to_view(view, til_translator, &func_info);
        } else {
            tracing::debug!("Mapping data export: {:0x}", export.address);
            let name_info = NameInfo {
                label: Some(export.name.clone()),
                ty: export.ty.clone(),
                address: export.address,
                exported: true,
            };
            self.map_name_to_view(view, til_translator, &name_info);
        }
    }

    pub fn map_func_to_view(
        &self,
        view: &BinaryView,
        til_translator: &TILTranslator,
        func: &FunctionInfo,
    ) {
        // We need to skip things that hit the extern section, since they do not have a bearing in the
        // actual context of the binary, and can be derived differently between IDA and Binja.
        let within_extern_section = view
            .sections_at(func.address)
            .iter()
            .find(|s| s.semantics() == Semantics::External)
            .is_some();
        if within_extern_section {
            tracing::debug!("Skipping function in extern section: {:0x}", func.address);
            return;
        }

        let Some(bn_func) = view.add_auto_function(func.address) else {
            tracing::warn!("Failed to add function for {:0x}", func.address);
            return;
        };

        if let Some(func_ty) = &func.ty {
            match til_translator.translate_type_info(&func_ty) {
                Ok(bn_func_ty) => {
                    tracing::debug!("Mapping function with type: {:0x}", func.address);
                    bn_func.apply_auto_discovered_type(&bn_func_ty);
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to translate type {:?} for function {:0x}: {}",
                        func_ty,
                        func.address,
                        err
                    );
                }
            }
        }

        // NOTE: We let the function inherit the view's default platform. Carrying an explicit
        // platform on FunctionInfo would let mixed-architecture databases (e.g. ARM/Thumb
        // interworking) map each function with its own platform; that is a future enhancement.
        if let Some(func_sym) = symbol_from_func(func) {
            tracing::debug!(
                "Mapping function symbol: {:0x} => {}",
                func.address,
                func_sym
            );
            view.define_auto_symbol(&func_sym);
        }
    }

    pub fn map_label_to_view(&self, view: &BinaryView, label: &LabelInfo) {
        let symbol = Symbol::builder(SymbolType::LocalLabel, &label.label, label.address).create();
        tracing::debug!("Mapping label: {:0x} => {}", label.address, symbol);
        view.define_auto_symbol(&symbol);
    }

    pub fn map_name_to_view(
        &self,
        view: &BinaryView,
        til_translator: &TILTranslator,
        name: &NameInfo,
    ) {
        // We need to skip things that hit the extern section, since they do not have a bearing in the
        // actual context of the binary, and can be derived differently between IDA and Binja.
        let within_extern_section = view
            .sections_at(name.address)
            .iter()
            .find(|s| s.semantics() == Semantics::External)
            .is_some();
        if within_extern_section {
            tracing::debug!("Skipping name in extern section: {:0x}", name.address);
            return;
        }

        // Currently, we only want to use name info to map data variables, so skip anything in code.
        let within_code_section = view
            .sections_at(name.address)
            .iter()
            .find(|s| s.semantics() == Semantics::ReadOnlyCode)
            .is_some();
        if within_code_section || !view.functions_containing(name.address).is_empty() {
            tracing::debug!("Skipping name contained in code: {:0x}", name.address);
            return;
        }

        if let Some(label) = &name.label {
            let binding = name
                .exported
                .then_some(Binding::Global)
                .unwrap_or(Binding::None);
            let symbol = Symbol::builder(SymbolType::Data, &label, name.address)
                .binding(binding)
                .create();
            tracing::debug!("Mapping name label: {:0x} => {}", name.address, symbol);
            view.define_auto_symbol(&symbol);
        }

        if let Some(data_ty) = &name.ty {
            match til_translator.translate_type_info(&data_ty) {
                Ok(data_ty) => {
                    tracing::debug!("Mapping name with type: {:0x}", name.address);
                    view.define_auto_data_var(name.address, &data_ty);
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to translate type {:?} for name {:0x}: {}",
                        data_ty,
                        name.address,
                        err
                    );
                }
            }
        }
    }

    pub fn map_comment_to_view(&self, view: &BinaryView, comment: &CommentInfo) {
        // NOTE: This (`set_comment`) will generate an undo action.
        // First try and attach the comment to the containing functions, if that fails, then
        // attach the comment to the view. Attaching to the containing function can help with
        // the comments' placement.
        let functions = view.functions_containing(comment.address);
        for func in &functions {
            if func.start() == comment.address {
                func.set_comment(&comment.comment);
            } else {
                func.set_comment_at(comment.address, &comment.comment);
            }
        }

        // We did not find any functions containing the comment, so attach it to the view.
        if functions.is_empty() {
            view.set_comment_at(comment.address, &comment.comment);
        }
    }
}

/// Compute the SHA256 of the raw (on-disk) bytes backing `view`.
///
/// Walks to the root of the parent-view chain, which is the raw view whose contents are the
/// original input file, then hashes its full contents. Returns `None` if the view is empty.
fn sha256_of_raw_view(view: &BinaryView) -> Option<String> {
    let mut raw_view = view.to_owned();
    while let Some(parent) = raw_view.parent_view() {
        raw_view = parent;
    }

    let length = raw_view.len();
    if length == 0 {
        return None;
    }

    // Hash in chunks so we never hold the whole binary in memory at once.
    const CHUNK_SIZE: usize = 1 << 20;
    let mut hasher = Sha256::new();
    let mut offset = raw_view.start();
    let end = offset + length;
    while offset < end {
        let want = CHUNK_SIZE.min((end - offset) as usize);
        let chunk = raw_view.read_vec(offset, want);
        if chunk.is_empty() {
            // The view reported a length we cannot fully read; treat as unverifiable.
            return None;
        }
        hasher.update(&chunk);
        offset += chunk.len() as u64;
    }

    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

fn symbol_from_func(func: &FunctionInfo) -> Option<Ref<Symbol>> {
    let Some(func_name) = &func.name else {
        return None;
    };
    let short_func_name = binaryninja::demangle::demangle_llvm(&func_name, true)
        .map(|qn| qn.to_string())
        .unwrap_or(func_name.clone());
    let sym_type = match func.is_library {
        true => SymbolType::LibraryFunction,
        false => SymbolType::Function,
    };
    let symbol_builder =
        Symbol::builder(sym_type, func_name, func.address).short_name(short_func_name);
    Some(symbol_builder.create())
}

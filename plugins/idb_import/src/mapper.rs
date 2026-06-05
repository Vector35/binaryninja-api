//! Map the IDB data we parsed into the [`BinaryView`].

use crate::parse::{
    BaseAddressInfo, CommentInfo, DataInfo, DataKind, ExportInfo, FunctionFolderEntry,
    FunctionInfo, IDBInfo, LabelInfo, NameInfo, OperandFormat, OperandFormatInfo, SegmentInfo,
};
use crate::translate::TILTranslator;
use binaryninja::architecture::{Architecture, ArchitectureExt, Register, RegisterInfo};
use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::component::{Component, ComponentBuilder};
use binaryninja::disassembly::InstructionTextTokenKind;
use binaryninja::function::Function;
use binaryninja::types::IntegerDisplayType;
use binaryninja::qualified_name::QualifiedName;
use binaryninja::rc::Ref;
use binaryninja::section::{SectionBuilder, Semantics};
use binaryninja::symbol::{Binding, Symbol, SymbolType};
use binaryninja::types::Type;
use binaryninja::variable::Variable;
use idb_rs::id0::SegmentType;
use idb_rs::til::TypeVariant;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Maps IDB data into a [`BinaryView`].
///
/// The mapper can be re-used if mapping into multiple views.
pub struct IDBMapper {
    info: IDBInfo,
    apply_operand_formats: bool,
}

impl IDBMapper {
    pub fn new(info: IDBInfo) -> Self {
        Self {
            info,
            apply_operand_formats: false,
        }
    }

    /// Enable applying the IDB's per-operand number formats to the disassembly.
    pub fn with_operand_formats(mut self, enabled: bool) -> Self {
        self.apply_operand_formats = enabled;
        self
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
                // IDA's `min_ea` is the image base, and it maps the file header region too.
                // Across executable formats the first *section* generally begins after the
                // format's headers/metadata (e.g. the Mach-O header + load commands, the PE
                // headers, the ELF header + program headers), so aligning to the lowest section
                // over-shifts every imported address by the header size. Segments include the
                // header region, so the lowest segment matches IDA's image base regardless of
                // format.
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
        let til_translator = TILTranslator::new_from_platform(&platform)
            .with_type_container(&view.type_container())
            .with_register_names(id0.register_names.clone());
        let til_translator = match &self.info.til {
            Some(til) => til_translator.with_til_info(&til),
            None => til_translator,
        };

        self.map_types_to_view(view, &til_translator, &self.info.merged_types());

        // Keep the created functions keyed by their (rebased) address so we can place them into
        // folders later without depending on the analysis having indexed them yet.
        let mut functions_by_address: HashMap<u64, Ref<Function>> = HashMap::new();
        for func in &self.info.merged_functions() {
            let mut rebased_func = func.clone();
            rebased_func.address = rebase(func.address);
            if let Some(bn_func) = self.map_func_to_view(view, &til_translator, &rebased_func) {
                functions_by_address.insert(rebased_func.address, bn_func);
            }
        }

        for export in &id0.exports {
            let mut rebased_export = export.clone();
            rebased_export.address = rebase(export.address);
            if let Some(bn_func) =
                self.map_export_to_view(view, &til_translator, &rebased_export)
            {
                functions_by_address.insert(rebased_export.address, bn_func);
            }
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

        // Apply typed data items before names so that a more precise type from the name/TIL path
        // takes precedence over the byte-flag-derived type on the same address.
        if !self.info.data_items.is_empty() {
            tracing::info!("Mapping {} typed data items", self.info.data_items.len());
        }
        for data in &self.info.data_items {
            let mut rebased_data = data.clone();
            rebased_data.address = rebase(data.address);
            self.map_data_item_to_view(view, &rebased_data);
        }

        for name in &self.info.merged_names() {
            let mut rebased_name = name.clone();
            rebased_name.address = rebase(name.address);
            self.map_name_to_view(view, &til_translator, &rebased_name);
        }

        // IDA's local labels are named locations inside functions (e.g. loop targets). They live
        // in code, so `map_name_to_view` skips them; apply them as local-label symbols instead.
        for label in &id0.labels {
            let mut rebased_label = label.clone();
            rebased_label.address = rebase(label.address);
            self.map_label_to_view(view, &rebased_label);
        }

        // Recreate IDA's "Functions" window folder hierarchy. Binary Ninja's component API backs
        // what the UI shows as function folders.
        if let Some(dir_tree) = &self.info.dir_tree {
            if !dir_tree.function_folders.is_empty() {
                let mut stats = FolderStats::default();
                self.map_function_folders_to_view(
                    view,
                    &dir_tree.function_folders,
                    None,
                    &rebase,
                    &functions_by_address,
                    &mut stats,
                );
                tracing::info!(
                    "Mapped function folders: {} folders created, {} functions placed, {} not found",
                    stats.folders_created,
                    stats.functions_placed,
                    stats.functions_missing
                );
            }
        }

        // Apply per-operand number formats to the disassembly, if the user opted in. This is
        // gated because it disassembles each formatted instruction.
        if self.apply_operand_formats && !self.info.operand_formats.is_empty() {
            tracing::info!(
                "Applying {} operand formats",
                self.info.operand_formats.len()
            );
            for operand_format in &self.info.operand_formats {
                let mut rebased = operand_format.clone();
                rebased.address = rebase(operand_format.address);
                self.map_operand_format_to_view(view, &rebased);
            }
        }

        // self.map_used_types_to_view(view, &til_translator);
    }

    /// Apply IDA's per-operand number formats to the instruction at an address.
    ///
    /// `set_int_display_type` only takes effect when Binary Ninja renders a token with the exact
    /// (value, operand) we set, so disassembling the instruction to recover its immediate values
    /// and setting each value under every formatted operand index is safe: combinations that do
    /// not occur are simply never matched.
    fn map_operand_format_to_view(&self, view: &BinaryView, operand_format: &OperandFormatInfo) {
        let functions = view.functions_containing(operand_format.address);
        let Some(func) = functions.iter().next() else {
            return;
        };
        let arch = func.arch();

        // The longest instruction we may encounter; reading a few extra bytes is harmless.
        let bytes = view.read_vec(operand_format.address, 16);
        if bytes.is_empty() {
            return;
        }
        let Some((_consumed, tokens)) = arch.instruction_text(&bytes, operand_format.address) else {
            return;
        };

        let values: Vec<u64> = tokens
            .iter()
            .filter_map(|token| integer_token_value(&token.kind))
            .collect();
        if values.is_empty() {
            return;
        }

        for (operand_index, format) in &operand_format.formats {
            let display_type = integer_display_type(*format);
            for value in &values {
                func.set_int_display_type(
                    operand_format.address,
                    *value,
                    *operand_index as usize,
                    display_type,
                    Some(arch),
                    None,
                );
            }
        }
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

        // Skip a segment we have already mapped. We check both the name and the exact address
        // range: an overlap-based check would be wrong because the loader normally maps the whole
        // address space (so every IDA segment overlaps something), but an IDA segment that covers
        // the exact same range as an existing section — even under a different name — is the same
        // region and should not be added twice.
        if view.section_by_name(&segment.name).is_some() {
            tracing::debug!(
                "Section with name '{}' already exists, skipping...",
                segment.name
            );
            return;
        }
        if view
            .sections()
            .iter()
            .any(|existing| existing.address_range() == segment.region)
        {
            tracing::debug!(
                "Section covering {:0x}-{:0x} already exists, skipping '{}'...",
                segment.region.start,
                segment.region.end,
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
    ) -> Option<Ref<Function>> {
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
                register_vars: Vec::new(),
                stack_frame: None,
            };
            return self.map_func_to_view(view, til_translator, &func_info);
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
        None
    }

    pub fn map_func_to_view(
        &self,
        view: &BinaryView,
        til_translator: &TILTranslator,
        func: &FunctionInfo,
    ) -> Option<Ref<Function>> {
        // We need to skip things that hit the extern section, since they do not have a bearing in the
        // actual context of the binary, and can be derived differently between IDA and Binja.
        let within_extern_section = view
            .sections_at(func.address)
            .iter()
            .find(|s| s.semantics() == Semantics::External)
            .is_some();
        if within_extern_section {
            tracing::debug!("Skipping function in extern section: {:0x}", func.address);
            return None;
        }

        let Some(bn_func) = view.add_auto_function(func.address) else {
            tracing::warn!("Failed to add function for {:0x}", func.address);
            return None;
        };

        // IDA marks functions that never return (e.g. `abort`, `exit`); carry that over so BN's
        // analysis does not fall through past calls to them.
        if func.is_no_return {
            tracing::debug!("Marking function as no-return: {:0x}", func.address);
            bn_func.set_auto_can_return(false);
        }

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

        self.map_register_vars_to_func(&bn_func, func);
        self.map_stack_frame_to_func(&bn_func, til_translator, func);

        Some(bn_func)
    }

    /// Apply a function's IDA stack frame as Binary Ninja stack variables.
    ///
    /// IDA stores the frame as a structure whose members run from the bottom of the local
    /// variable area upward through the saved registers, return address and stack arguments.
    /// Binary Ninja measures stack offsets from the return address (locals negative, arguments
    /// positive), so an IDA frame offset is shifted down by `local_size + saved_regs_size`. The
    /// frame members do not carry explicit offsets, so each member's offset is the running sum of
    /// the preceding member widths; the synthetic saved-register and return-address members are
    /// skipped (but still advance the offset) since they are not user variables.
    fn map_stack_frame_to_func(
        &self,
        bn_func: &binaryninja::function::Function,
        til_translator: &TILTranslator,
        func: &FunctionInfo,
    ) {
        let Some(stack_frame) = &func.stack_frame else {
            return;
        };
        let base = (stack_frame.local_size + stack_frame.saved_regs_size) as i64;
        let mut frame_offset: u64 = 0;
        for (i, member) in stack_frame.frame.members.iter().enumerate() {
            let member_width = til_translator
                .width_of_type(&member.member_type)
                .unwrap_or(0);

            // Skip the saved-register / return-address regions, but keep advancing the offset so
            // the members after them still land at the right place.
            if member.is_frame_r || member.is_frame_s {
                frame_offset += member_width as u64;
                continue;
            }

            let name = member
                .name
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("var_{i}"));
            let bn_offset = frame_offset as i64 - base;
            match til_translator.translate_type_info(&member.member_type) {
                Ok(ty) => {
                    tracing::debug!(
                        "Mapping stack variable '{}' at frame offset {} (bn {}) for {:0x}",
                        name,
                        frame_offset,
                        bn_offset,
                        func.address
                    );
                    bn_func.create_auto_stack_var(bn_offset, &ty, &name);
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to translate stack variable '{}' type for {:0x}: {}",
                        name,
                        func.address,
                        err
                    );
                }
            }

            frame_offset += member_width as u64;
        }
    }

    /// Apply IDA register variables ("regvars") to a function.
    ///
    /// IDA records that a register holds a user-named value over an address range. Binary Ninja
    /// variables are function-scoped, so the range is not modeled; we name the architecture
    /// register over the whole function, typed as an unsigned int of the register's width.
    fn map_register_vars_to_func(
        &self,
        bn_func: &binaryninja::function::Function,
        func: &FunctionInfo,
    ) {
        if func.register_vars.is_empty() {
            return;
        }
        let arch = bn_func.arch();
        for reg_var in &func.register_vars {
            let Some(register) = arch.register_by_name(&reg_var.register) else {
                tracing::warn!(
                    "Skipping register variable '{}': unknown register '{}' at {:0x}",
                    reg_var.name,
                    reg_var.register,
                    func.address
                );
                continue;
            };
            let reg_width = register.info().size().max(1);
            let var = Variable::from_register(register);
            tracing::debug!(
                "Mapping register variable {} => {} at {:0x}",
                reg_var.register,
                reg_var.name,
                func.address
            );
            bn_func.create_user_var(&var, &Type::int(reg_width, false), &reg_var.name, false);
        }
    }

    /// Define a typed data variable for a data item IDA recorded in its byte flags.
    pub fn map_data_item_to_view(&self, view: &BinaryView, data: &DataInfo) {
        // Skip the synthetic extern section, and anything that lives inside code/functions.
        let within_extern_section = view
            .sections_at(data.address)
            .iter()
            .any(|s| s.semantics() == Semantics::External);
        if within_extern_section {
            return;
        }
        let within_code_section = view
            .sections_at(data.address)
            .iter()
            .any(|s| s.semantics() == Semantics::ReadOnlyCode);
        if within_code_section || !view.functions_containing(data.address).is_empty() {
            return;
        }

        let data_ty = match data.kind {
            DataKind::Int(bytes) => Type::int(bytes as usize, false),
            DataKind::Float(bytes) => Type::float(bytes as usize),
            DataKind::String(len) => Type::array(&Type::char(), len),
        };
        tracing::debug!("Mapping data item: {:0x} ({:?})", data.address, data.kind);
        view.define_auto_data_var(data.address, &data_ty);
    }

    /// Recreate an IDA function folder tree in the view.
    ///
    /// Binary Ninja models function folders with the component API (`Component`), which the UI
    /// presents as folders. Each IDA folder becomes a component nested under its parent (the root
    /// view component for top-level folders), and each function leaf is added to the folder it
    /// belongs to. Functions sitting directly at the dirtree root are left in no folder, matching
    /// their state in IDA.
    fn map_function_folders_to_view(
        &self,
        view: &BinaryView,
        entries: &[FunctionFolderEntry],
        parent: Option<&Component>,
        rebase: &impl Fn(u64) -> u64,
        functions_by_address: &HashMap<u64, Ref<Function>>,
        stats: &mut FolderStats,
    ) {
        for entry in entries {
            match entry {
                FunctionFolderEntry::Function(address) => {
                    let Some(parent) = parent else {
                        continue;
                    };
                    let rebased = rebase(*address);
                    // Prefer the function we created during mapping; fall back to a view lookup in
                    // case it came from another source.
                    let func = functions_by_address.get(&rebased).cloned().or_else(|| {
                        view.functions_at(rebased)
                            .iter()
                            .find(|func| func.start() == rebased)
                            .map(|func| func.to_owned())
                    });
                    match func {
                        Some(func) if parent.add_function(&func) => {
                            stats.functions_placed += 1;
                        }
                        Some(_) => {
                            tracing::debug!(
                                "Component rejected function at {:0x}",
                                rebased
                            );
                            stats.functions_missing += 1;
                        }
                        None => {
                            tracing::debug!(
                                "No function at {:0x} to place in folder, skipping",
                                rebased
                            );
                            stats.functions_missing += 1;
                        }
                    }
                }
                FunctionFolderEntry::Folder { name, entries } => {
                    let mut builder = ComponentBuilder::new(view.to_owned()).name(name.clone());
                    if let Some(parent) = parent {
                        builder = builder.parent(parent.guid());
                    }
                    let component = builder.finalize();
                    stats.folders_created += 1;
                    tracing::debug!("Created folder '{}'", name);
                    self.map_function_folders_to_view(
                        view,
                        entries,
                        Some(&component),
                        rebase,
                        functions_by_address,
                        stats,
                    );
                }
            }
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

/// Running totals for the folder mapping, used for a single summary log line.
#[derive(Default)]
struct FolderStats {
    folders_created: usize,
    functions_placed: usize,
    functions_missing: usize,
}

/// Extract the integer value carried by a disassembly token, if any.
fn integer_token_value(kind: &InstructionTextTokenKind) -> Option<u64> {
    match kind {
        InstructionTextTokenKind::Integer { value, .. } => Some(*value),
        InstructionTextTokenKind::PossibleAddress { value, .. } => Some(*value),
        InstructionTextTokenKind::CodeRelativeAddress { value, .. } => Some(*value),
        _ => None,
    }
}

/// Map an IDA operand number format to the Binary Ninja integer display type.
fn integer_display_type(format: OperandFormat) -> IntegerDisplayType {
    match format {
        OperandFormat::Hex => IntegerDisplayType::UnsignedHexadecimalDisplayType,
        OperandFormat::Dec => IntegerDisplayType::SignedDecimalDisplayType,
        OperandFormat::Char => IntegerDisplayType::CharacterConstantDisplayType,
        OperandFormat::Oct => IntegerDisplayType::UnsignedOctalDisplayType,
        OperandFormat::Bin => IntegerDisplayType::BinaryDisplayType,
        OperandFormat::Offset => IntegerDisplayType::PointerDisplayType,
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

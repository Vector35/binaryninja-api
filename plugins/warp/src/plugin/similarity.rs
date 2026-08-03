use crate::cache::container::for_cached_containers;
use crate::cache::try_cached_function_guid;
use crate::container::disk::{DiskContainer, DiskContainerSource};
use crate::container::{Container, SourceId, SourcePath};
use crate::convert::platform_to_target;
use crate::convert::to_bn_symbol_at_address;
use crate::processor::WarpFileProcessor;
use crate::{basic_block_guid, function_guid, relocatable_regions, sorted_basic_blocks};
use binaryninja::function::Function;
use binaryninja::rc::Ref;
use binaryninja::settings::Settings;
use binaryninja::similarity::{
    DiffRenderer, SimilarityAnnotationType, SimilarityApplyStatus, SimilarityEntityId,
    SimilarityEntityInfo, SimilarityEntityRef, SimilarityEntityType, SimilarityProvider,
    SimilarityProviderResults, SimilarityProviderType, SimilarityRangeAnnotation,
    SimilarityRenderContext, SimilarityResultId, SimilaritySessionCompletion,
    SimilaritySessionNode, SimilaritySessionNodeId,
};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use warp::signature::basic_block::BasicBlockGUID;
use warp::signature::function::{Function as WarpFunction, FunctionGUID};

type CatalogTargetKey = (
    SimilaritySessionNodeId,
    String,
    SourceId,
    FunctionGUID,
    String,
);
type AnalysisEntityIndex = HashMap<FunctionGUID, Vec<(String, SimilarityEntityRef)>>;

pub struct WarpSimilarityProviderType;

impl SimilarityProviderType for WarpSimilarityProviderType {
    type SimilarityProvider = WarpSimilarityProvider;
    const NAME: &'static str = "WARP";
    const DESCRIPTION: &'static str = "Uses WARP to find functions which are exact matches";

    fn create_provider(&self, _settings: &Settings) -> Self::SimilarityProvider {
        WarpSimilarityProvider::new()
    }

    fn default_settings(&self) -> Option<Ref<Settings>> {
        None
    }
}

pub struct WarpSimilarityProvider {
    container: RwLock<DiskContainer>,
    mapped_targets: RwLock<HashMap<CatalogTargetKey, SimilarityEntityId>>,
    target_data: RwLock<HashMap<SimilarityEntityRef, TargetData>>,
}

enum TargetData {
    Analysis(String),
    Catalog(WarpFunction),
}

impl TargetData {
    fn name(&self) -> &str {
        match self {
            Self::Analysis(name) => name,
            Self::Catalog(function) => &function.symbol.name,
        }
    }
}

impl WarpSimilarityProvider {
    pub fn new() -> Self {
        Self {
            container: RwLock::new(DiskContainer::new(
                "Similarity Container".to_string(),
                HashMap::new(),
            )),
            mapped_targets: RwLock::new(HashMap::new()),
            target_data: RwLock::new(HashMap::new()),
        }
    }

    fn find_prepared_functions_with_matching_guid(
        &self,
        source: SourceId,
        func: &Function,
    ) -> Option<Vec<WarpFunction>> {
        let func_lifted_il = func.lifted_il().ok()?;
        let func_target = platform_to_target(&func.platform());
        let func_guid = function_guid(&func, &func_lifted_il);
        let container = self.container.read().ok()?;
        container
            .functions_with_guid(&func_target, &source, &func_guid)
            .ok()
    }

    fn find_global_functions_with_matching_guid(
        func: &Function,
    ) -> Option<Vec<(String, SourceId, WarpFunction)>> {
        let func_lifted_il = func.lifted_il().ok()?;
        let func_target = platform_to_target(&func.platform());
        let func_guid = function_guid(func, &func_lifted_il);
        let mut matches = Vec::new();
        for_cached_containers(|container| {
            let container_name = container.to_string();
            let Ok(sources) = container.sources_with_function_guid(&func_target, &func_guid) else {
                return;
            };
            for source in sources {
                let Ok(functions) =
                    container.functions_with_guid(&func_target, &source, &func_guid)
                else {
                    continue;
                };
                matches.extend(
                    functions
                        .into_iter()
                        .map(|function| (container_name.clone(), source, function)),
                );
            }
        });

        matches.sort_by(|left, right| {
            (
                left.0.as_str(),
                left.1.to_string(),
                left.2.symbol.name.as_str(),
            )
                .cmp(&(
                    right.0.as_str(),
                    right.1.to_string(),
                    right.2.symbol.name.as_str(),
                ))
        });
        matches.dedup_by(|left, right| {
            left.0 == right.0
                && left.1 == right.1
                && left.2.guid == right.2.guid
                && left.2.symbol.name == right.2.symbol.name
        });
        Some(matches)
    }

    fn analysis_function_guid(function: &Function) -> Option<FunctionGUID> {
        try_cached_function_guid(function).or_else(|| {
            function
                .lifted_il()
                .ok()
                .map(|lifted_il| function_guid(function, &lifted_il))
        })
    }

    fn available_mapped_address(guid: FunctionGUID, occupied_addresses: &HashSet<u64>) -> u64 {
        let mut guid_prefix = [0u8; 8];
        guid_prefix.copy_from_slice(&guid.as_bytes()[..8]);
        let mut address = u64::from_be_bytes(guid_prefix);
        while occupied_addresses.contains(&address) {
            address = address.wrapping_add(1);
        }
        address
    }

    fn index_analysis_entities(node: &SimilaritySessionNode) -> AnalysisEntityIndex {
        let mut entities: AnalysisEntityIndex = HashMap::new();
        for entity in &node.entities() {
            let Some(function) = node.entity_function(entity) else {
                continue;
            };
            let Some(guid) = Self::analysis_function_guid(&function) else {
                continue;
            };
            entities.entry(guid).or_default().push((
                function.symbol().raw_name().to_string_lossy().into_owned(),
                SimilarityEntityRef {
                    node_id: node.id(),
                    entity_id: entity,
                },
            ));
        }
        entities
    }

    fn find_analysis_entity(
        entities: &AnalysisEntityIndex,
        matched_function: &WarpFunction,
    ) -> Option<SimilarityEntityRef> {
        let matches = entities.get(&matched_function.guid)?;
        matches
            .iter()
            .find(|(name, _)| *name == matched_function.symbol.name)
            .or_else(|| matches.first())
            .map(|(_, entity)| *entity)
    }

    fn create_mapped_target(
        &self,
        node: &SimilaritySessionNode,
        container: String,
        source: SourceId,
        matched_function: &WarpFunction,
    ) -> Option<SimilarityEntityRef> {
        let key = (
            node.id(),
            container,
            source,
            matched_function.guid,
            matched_function.symbol.name.clone(),
        );
        let mut mapped_targets = self.mapped_targets.write().ok()?;
        if let Some(entity_id) = mapped_targets.get(&key) {
            if node.entity(*entity_id).is_some() {
                return Some(SimilarityEntityRef {
                    node_id: node.id(),
                    entity_id: *entity_id,
                });
            }
            mapped_targets.remove(&key);
        }

        // TODO: At some point I may want to raise the barrier to entry for providers, this behavior
        // TODO: may get in the way or progressing towards more core enabled functionality (e.g. porting types).
        // Mapped entities let WARP name and apply matches which do not have a loaded
        // analysis function. Their opaque address is identity storage and is never navigated.
        let occupied_addresses = node
            .entities()
            .iter()
            .filter_map(|entity| node.entity(entity).map(|info| info.address))
            .collect::<HashSet<_>>();
        let address = Self::available_mapped_address(matched_function.guid, &occupied_addresses);

        let entity_id = node.create_entity(SimilarityEntityInfo {
            entity_type: SimilarityEntityType::SimilarityEntityFunction,
            address,
            name: matched_function.symbol.name.clone(),
        });
        mapped_targets.insert(key, entity_id);
        Some(SimilarityEntityRef {
            node_id: node.id(),
            entity_id,
        })
    }

    fn related_entity_function(
        node: &SimilaritySessionNode,
        entity: SimilarityEntityRef,
    ) -> Option<Ref<Function>> {
        if entity.node_id == node.id() {
            return node.entity_function(entity.entity_id);
        }
        for candidate in node.incoming_nodes().iter() {
            if candidate.id() == entity.node_id {
                return candidate.entity_function(entity.entity_id);
            }
        }
        for candidate in node.outgoing_nodes().iter() {
            if candidate.id() == entity.node_id {
                return candidate.entity_function(entity.entity_id);
            }
        }
        None
    }

    fn render_blocks(function: &Function) -> Option<Vec<(BasicBlockGUID, u64, u64)>> {
        let lifted_il = function.lifted_il().ok()?;
        let relocatable_regions = relocatable_regions(&function.view());
        Some(
            sorted_basic_blocks(function)
                .into_iter()
                .map(|block| {
                    (
                        basic_block_guid(&relocatable_regions, &block, &lifted_il),
                        block.start(),
                        block.end(),
                    )
                })
                .collect(),
        )
    }

    fn unique_block_annotations(
        blocks: &[(BasicBlockGUID, u64, u64)],
        other_guids: &HashSet<BasicBlockGUID>,
        annotation_type: SimilarityAnnotationType,
    ) -> Vec<SimilarityRangeAnnotation> {
        blocks
            .iter()
            .filter(|(guid, _, _)| !other_guids.contains(guid))
            .map(|(_, start, end)| SimilarityRangeAnnotation {
                start: *start,
                end: *end,
                annotation_type,
            })
            .collect()
    }

    fn add_global_entity_results(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        results: &mut SimilarityProviderResults<'_>,
    ) {
        let Some(func) = node.entity_function(entity) else {
            return;
        };

        // Function GUID lookup is an exact-match constraint, so every returned function has
        // maximum similarity and confidence.
        let matched_functions =
            Self::find_global_functions_with_matching_guid(&func).unwrap_or_default();
        let mut target_data = Vec::with_capacity(matched_functions.len());
        let mut seen_targets = HashSet::with_capacity(matched_functions.len());
        let source = SimilarityEntityRef {
            node_id: node.id(),
            entity_id: entity,
        };

        for (container, catalog_source, matched_function) in matched_functions {
            let target =
                self.create_mapped_target(node, container, catalog_source, &matched_function);
            let Some(target) = target else { continue };
            if !seen_targets.insert(target) {
                continue;
            }
            let id = results.add_result(source, target, u8::MAX, u8::MAX);
            if id != 0.into() {
                target_data.push((target, TargetData::Catalog(matched_function)));
            }
        }

        if let Ok(mut stored_data) = self.target_data.write() {
            stored_data.extend(target_data);
        }
    }

    fn add_edge_entity_results(
        &self,
        to: &SimilaritySessionNode,
        source_id: SourceId,
        source_entities: &AnalysisEntityIndex,
        entity: SimilarityEntityId,
        results: &mut SimilarityProviderResults<'_>,
    ) {
        let Some(func) = to.entity_function(entity) else {
            return;
        };
        let matched_functions = self
            .find_prepared_functions_with_matching_guid(source_id, &func)
            .unwrap_or_default();
        let mut target_data = Vec::with_capacity(matched_functions.len());
        let mut seen_targets = HashSet::with_capacity(matched_functions.len());
        let source = SimilarityEntityRef {
            node_id: to.id(),
            entity_id: entity,
        };

        for matched_function in matched_functions {
            let Some(target) = Self::find_analysis_entity(source_entities, &matched_function)
            else {
                continue;
            };
            if !seen_targets.insert(target) {
                continue;
            }
            let id = results.add_result(source, target, u8::MAX, u8::MAX);
            if id != 0.into() {
                target_data.push((target, TargetData::Analysis(matched_function.symbol.name)));
            }
        }
        if let Ok(mut stored_data) = self.target_data.write() {
            stored_data.extend(target_data);
        }
    }

    fn render_functions(
        context: &SimilarityRenderContext,
        function: &Function,
        entity: SimilarityEntityRef,
        matched_function: &Function,
        matched_entity: SimilarityEntityRef,
    ) {
        let function_blocks = Self::render_blocks(function);
        let matched_blocks = Self::render_blocks(matched_function);
        let function_renderer = DiffRenderer::new();
        let matched_renderer = DiffRenderer::new();

        if let (Some(function_blocks), Some(matched_blocks)) = (function_blocks, matched_blocks) {
            let function_guids = function_blocks
                .iter()
                .map(|(guid, _, _)| *guid)
                .collect::<HashSet<_>>();
            let matched_guids = matched_blocks
                .iter()
                .map(|(guid, _, _)| *guid)
                .collect::<HashSet<_>>();
            for annotation in Self::unique_block_annotations(
                &function_blocks,
                &matched_guids,
                SimilarityAnnotationType::SimilarityAnnotationRemoved,
            ) {
                function_renderer.add_range_annotation(annotation);
            }
            for annotation in Self::unique_block_annotations(
                &matched_blocks,
                &function_guids,
                SimilarityAnnotationType::SimilarityAnnotationAdded,
            ) {
                matched_renderer.add_range_annotation(annotation);
            }
        }

        function_renderer.render_function_for_entity(context, function, entity);
        matched_renderer.render_function_for_entity(context, matched_function, matched_entity);
    }
}

impl SimilarityProvider for WarpSimilarityProvider {
    fn visit_node(
        &self,
        node: &SimilaritySessionNode,
        results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        let scheduled_entities = node.scheduled_entities().to_vec();
        // The session opens a node before invoking providers and retains it through its
        // last dependent edge visit.
        let view = node
            .view()
            .expect("similarity provider visited an inactive node");
        let processor = WarpFileProcessor::new();
        let source_path = SourcePath::new(view.file().file_path());
        let source_id = source_path.to_source_id();
        // Prepared node state is a complete snapshot. Rebuilding it avoids retaining stale
        // function GUIDs when a sparse visit updates an existing function.
        let functions = node
            .entities()
            .iter()
            .filter_map(|entity| node.entity_function(entity))
            .collect::<Vec<_>>();
        let result = match processor.process_view_with_functions_and_progress(
            view.file().file_path(),
            &view,
            &functions,
            |_| {
                if completion.is_stop_requested() {
                    processor.state().cancel();
                }
            },
        ) {
            Ok(result) => result,
            Err(error) => {
                tracing::error!("Failed to prepare WARP similarity node: {:?}", error);
                return false;
            }
        };
        if completion.is_stop_requested() {
            return false;
        }

        let Ok(mut container) = self.container.write() else {
            return false;
        };
        container
            .sources
            .insert(source_id, DiskContainerSource::new(source_path, result));
        drop(container);

        for entity in scheduled_entities {
            if completion.is_stop_requested() {
                return false;
            }
            self.add_global_entity_results(node, entity, results);
        }
        true
    }

    fn visit_node_edge(
        &self,
        from: &SimilaritySessionNode,
        to: &SimilaritySessionNode,
        results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        let source = SourcePath::new(from.file().file_path()).to_source_id();
        let source_entities = Self::index_analysis_entities(from);

        for entity in &to.scheduled_entities() {
            if completion.is_stop_requested() {
                return false;
            }
            self.add_edge_entity_results(to, source, &source_entities, entity, results);
        }
        true
    }

    fn result_name(
        &self,
        node: &SimilaritySessionNode,
        _entity: SimilarityEntityId,
        id: SimilarityResultId,
    ) -> Option<String> {
        let result = node.result(id)?;
        self.target_data
            .read()
            .ok()?
            .get(&result.target)
            .map(|data| data.name().to_string())
    }

    fn apply_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        id: SimilarityResultId,
    ) -> SimilarityApplyStatus {
        let Some(result) = node.result(id) else {
            return SimilarityApplyStatus::SimilarityApplyFailed;
        };
        let default_status = node.apply_target(entity, result.target);
        if default_status == SimilarityApplyStatus::SimilarityApplySuccess {
            return default_status;
        }
        let Some(function) = node.entity_function(entity) else {
            return default_status;
        };
        let matched_function = {
            let target_data = match self.target_data.read() {
                Ok(data) => data,
                Err(_) => return default_status,
            };
            match target_data.get(&result.target) {
                Some(TargetData::Catalog(function)) => function.clone(),
                _ => return default_status,
            }
        };

        let view = function.view();
        let new_sym = to_bn_symbol_at_address(&view, &matched_function.symbol, function.start());
        view.define_auto_symbol(&new_sym);
        SimilarityApplyStatus::SimilarityApplySuccess
    }

    fn render_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        context: &SimilarityRenderContext,
        result_id: SimilarityResultId,
    ) {
        let Some(result) = node.result(result_id) else {
            return;
        };
        let Some(function) = node.entity_function(entity) else {
            return;
        };
        let source = SimilarityEntityRef {
            node_id: node.id(),
            entity_id: entity,
        };
        if let Some(matched_function) = Self::related_entity_function(node, result.target) {
            Self::render_functions(context, &function, source, &matched_function, result.target);
        } else {
            DiffRenderer::new().render_function_for_entity(context, &function, source);
        }
    }
}

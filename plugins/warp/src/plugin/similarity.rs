use crate::cache::{cached_constraints, cached_function_guid, try_cached_function_guid};
use crate::convert::platform_to_target;
use binaryninja::function::Function;
use binaryninja::rc::Ref;
use binaryninja::settings::Settings;
use binaryninja::similarity::{
    SimilarityEntityId, SimilarityEntityRef, SimilarityProvider, SimilarityProviderResults,
    SimilarityProviderType, SimilarityResultId, SimilaritySessionCompletion, SimilaritySessionNode,
    SimilaritySessionNodeId,
};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use warp::signature::constraint::Constraint;
use warp::signature::function::FunctionGUID;
use warp::target::Target;

type AnalysisEntityKey = (Target, FunctionGUID);
type AnalysisEntityIndex = HashMap<AnalysisEntityKey, Vec<SimilarityEntityId>>;

#[derive(Clone)]
struct AnalysisEntity {
    key: AnalysisEntityKey,
    name: String,
    entity: SimilarityEntityRef,
    constraints: HashSet<Constraint>,
}

#[derive(Clone)]
struct MatchedAnalysisEntity {
    entity: AnalysisEntity,
    confidence: u8,
}

#[derive(Default)]
struct PreparedNode {
    entities: HashMap<SimilarityEntityId, AnalysisEntity>,
    by_guid: AnalysisEntityIndex,
}

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
    prepared_nodes: RwLock<HashMap<SimilaritySessionNodeId, PreparedNode>>,
}

impl WarpSimilarityProvider {
    pub fn new() -> Self {
        Self {
            prepared_nodes: RwLock::new(HashMap::new()),
        }
    }

    fn analysis_function_guid(function: &Function) -> Option<FunctionGUID> {
        try_cached_function_guid(function)
            .or_else(|| cached_function_guid(function, || function.lifted_il().ok()))
    }

    fn prepare_node(
        node: &SimilaritySessionNode,
        completion: &SimilaritySessionCompletion,
    ) -> Option<PreparedNode> {
        let mut prepared = PreparedNode::default();
        for entity in &node.entities() {
            if completion.is_stop_requested() {
                return None;
            }
            let Some(function) = node.entity_function(entity) else {
                continue;
            };
            let Some(guid) = Self::analysis_function_guid(&function) else {
                continue;
            };
            let key = (platform_to_target(&function.platform()), guid);
            let analysis_entity = AnalysisEntity {
                key: key.clone(),
                name: function.symbol().raw_name().to_string_lossy().into_owned(),
                entity: SimilarityEntityRef {
                    node_id: node.id(),
                    entity_id: entity,
                },
                constraints: cached_constraints(&function, |_| true),
            };
            prepared.by_guid.entry(key).or_default().push(entity);
            prepared.entities.insert(entity, analysis_entity);
        }
        Some(prepared)
    }

    fn matching_constraint_count(source: &AnalysisEntity, target: &AnalysisEntity) -> usize {
        source.constraints.intersection(&target.constraints).count()
    }

    fn constraint_confidence(
        source: &AnalysisEntity,
        target: &AnalysisEntity,
        matching_constraints: usize,
    ) -> u8 {
        let total_constraints = source.constraints.len().max(target.constraints.len());
        if total_constraints == 0 {
            return 0;
        }
        (matching_constraints.saturating_mul(u8::MAX as usize) / total_constraints) as u8
    }

    fn unique_analysis_entities(entities: &[MatchedAnalysisEntity]) -> Vec<&MatchedAnalysisEntity> {
        let mut seen_names = HashSet::with_capacity(entities.len());
        entities
            .iter()
            .filter(|matched| seen_names.insert(matched.entity.name.as_str()))
            .collect()
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

    fn add_edge_entity_results(
        to: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        matched_entities: &[MatchedAnalysisEntity],
        results: &mut SimilarityProviderResults<'_>,
    ) {
        let source = SimilarityEntityRef {
            node_id: to.id(),
            entity_id: entity,
        };

        // Duplicate names resolve to the first analysis entity with the matching GUID.
        for matched_entity in Self::unique_analysis_entities(matched_entities) {
            results.add_result(
                source,
                matched_entity.entity.entity,
                u8::MAX,
                matched_entity.confidence,
            );
        }
    }
}

impl SimilarityProvider for WarpSimilarityProvider {
    fn visit_node(
        &self,
        node: &SimilaritySessionNode,
        _results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        // Prepared node state is a complete, lightweight snapshot. Rebuilding it avoids
        // retaining stale GUIDs when a sparse visit updates an existing function.
        let Some(prepared) = Self::prepare_node(node, completion) else {
            return false;
        };

        let Ok(mut prepared_nodes) = self.prepared_nodes.write() else {
            return false;
        };
        prepared_nodes.insert(node.id(), prepared);
        true
    }

    fn visit_node_edge(
        &self,
        from: &SimilaritySessionNode,
        to: &SimilaritySessionNode,
        results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        let pending_matches = {
            let Ok(prepared_nodes) = self.prepared_nodes.read() else {
                return false;
            };
            let Some(source) = prepared_nodes.get(&from.id()) else {
                return true;
            };
            let Some(target) = prepared_nodes.get(&to.id()) else {
                return true;
            };

            to.scheduled_entities()
                .iter()
                .map(|entity| {
                    let matches = target
                        .entities
                        .get(&entity)
                        .map_or_else(Vec::new, |target| {
                            source
                                .by_guid
                                .get(&target.key)
                                .into_iter()
                                .flatten()
                                .filter_map(|entity| source.entities.get(entity))
                                .map(|source| {
                                    let matching_constraints =
                                        Self::matching_constraint_count(source, target);
                                    MatchedAnalysisEntity {
                                        confidence: Self::constraint_confidence(
                                            source,
                                            target,
                                            matching_constraints,
                                        ),
                                        entity: source.clone(),
                                    }
                                })
                                .collect()
                        });
                    (entity, matches)
                })
                .collect::<Vec<_>>()
        };

        for (entity, matches) in pending_matches {
            if completion.is_stop_requested() {
                return false;
            }
            Self::add_edge_entity_results(to, entity, &matches, results);
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
        Self::related_entity_function(node, result.target)
            .map(|function| function.symbol().raw_name().to_string_lossy().into_owned())
    }
}

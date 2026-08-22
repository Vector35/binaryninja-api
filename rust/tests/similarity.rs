use binaryninja::function::FunctionViewType;
use binaryninja::headless::Session as HeadlessSession;
use binaryninja::rc::Ref;
use binaryninja::settings::Settings;
use binaryninja::similarity::{
    register_similarity_provider, register_similarity_session_resolver, CoreSimilarityProvider,
    CoreSimilarityProviderType, CoreSimilaritySessionGraphReceiver, CoreSimilaritySessionReceiver,
    SimilarityApplyStatus, SimilarityEntityId, SimilarityEntityInfo, SimilarityEntityRef,
    SimilarityEntityType, SimilarityProvider, SimilarityProviderType, SimilarityRenderContext,
    SimilarityResultId, SimilaritySession, SimilaritySessionCompletion,
    SimilaritySessionCompletionQuery, SimilaritySessionGraphReceiver, SimilaritySessionNode,
    SimilaritySessionNodeId, SimilaritySessionReceiver, SimilaritySessionResolver,
    SimilaritySessionResolverId, SimilaritySessionResolverType,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct WorkflowState {
    visited_nodes: Mutex<HashSet<SimilaritySessionNodeId>>,
    visited_edges: Mutex<HashSet<(SimilaritySessionNodeId, SimilaritySessionNodeId)>>,
    visited_entities: Mutex<HashSet<SimilarityEntityRef>>,
    resolved_entities: Mutex<HashSet<SimilarityEntityRef>>,
    update_counts: Mutex<HashMap<SimilarityEntityRef, usize>>,
    starts: AtomicUsize,
    graph_changes: AtomicUsize,
    provider_settings_updates: AtomicUsize,
    resolver_settings_updates: AtomicUsize,
}

struct TestProviderType {
    state: Arc<WorkflowState>,
}

impl SimilarityProviderType for TestProviderType {
    type SimilarityProvider = TestProvider;

    const NAME: &'static str = "Rust Similarity Test";
    const DESCRIPTION: &'static str = "Matches each function to itself";

    fn create_provider(&self, _settings: &Settings) -> Self::SimilarityProvider {
        TestProvider {
            state: self.state.clone(),
        }
    }

    fn default_settings(&self) -> Option<Ref<Settings>> {
        Some(Settings::new_with_id("rust.similarity.test.provider"))
    }
}

struct TestProvider {
    state: Arc<WorkflowState>,
}

impl SimilarityProvider for TestProvider {
    fn update_settings(&self, _settings: &Settings) -> bool {
        self.state
            .provider_settings_updates
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn visit_node(
        &self,
        node: &SimilaritySessionNode,
        results: &mut binaryninja::similarity::SimilarityProviderResults<'_>,
        _completion: &SimilaritySessionCompletion,
    ) -> bool {
        let entities = node.scheduled_entities().to_vec();
        self.state.visited_nodes.lock().unwrap().insert(node.id());
        self.state
            .visited_entities
            .lock()
            .unwrap()
            .extend(
                entities
                    .iter()
                    .copied()
                    .map(|entity_id| SimilarityEntityRef {
                        node_id: node.id(),
                        entity_id,
                    }),
            );
        for entity in entities {
            let entity_ref = SimilarityEntityRef {
                node_id: node.id(),
                entity_id: entity,
            };
            let result_id = results.add_result(entity_ref, entity_ref, 255, 255);
            assert_ne!(result_id, 0.into());
        }
        true
    }

    fn visit_node_edge(
        &self,
        from: &SimilaritySessionNode,
        to: &SimilaritySessionNode,
        _results: &mut binaryninja::similarity::SimilarityProviderResults<'_>,
        _completion: &SimilaritySessionCompletion,
    ) -> bool {
        self.state
            .visited_edges
            .lock()
            .unwrap()
            .insert((from.id(), to.id()));
        true
    }

    fn result_name(
        &self,
        _node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        _result: SimilarityResultId,
    ) -> Option<String> {
        Some(format!("match_{entity}"))
    }

    fn render_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        context: &SimilarityRenderContext,
        _result: SimilarityResultId,
    ) {
        if let Some(function) = node.entity_function(entity) {
            binaryninja::similarity::DiffRenderer::new().render_function_for_entity(
                context,
                &function,
                SimilarityEntityRef {
                    node_id: node.id(),
                    entity_id: entity,
                },
            );
        }
    }
}

struct TestResolverType {
    provider: Ref<CoreSimilarityProvider>,
    state: Arc<WorkflowState>,
}

impl SimilaritySessionResolverType for TestResolverType {
    type SimilaritySessionResolver = TestResolver;

    const NAME: &'static str = "Rust Similarity Test Resolver";
    const DESCRIPTION: &'static str = "Selects the first provider result";

    fn create_resolver(
        &self,
        _session: &SimilaritySession,
        _settings: &Settings,
    ) -> Self::SimilaritySessionResolver {
        TestResolver {
            provider: self.provider.to_owned(),
            state: self.state.clone(),
        }
    }

    fn default_settings(&self) -> Option<Ref<Settings>> {
        Some(Settings::new_with_id("rust.similarity.test.resolver"))
    }
}

struct TestResolver {
    provider: Ref<CoreSimilarityProvider>,
    state: Arc<WorkflowState>,
}

impl SimilaritySessionResolver for TestResolver {
    fn update_settings(&self, _settings: &Settings) -> bool {
        self.state
            .resolver_settings_updates
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn resolve_for_node(
        &self,
        _session: &SimilaritySession,
        node: &SimilaritySessionNode,
        entities: &[SimilarityEntityId],
        _completion: &SimilaritySessionCompletion,
        _resolver_id: SimilaritySessionResolverId,
    ) {
        for entity in entities {
            let Some(result) = node.results(*entity).into_iter().find(|result| {
                node.result(*result)
                    .is_some_and(|result| result.provider_id == self.provider.id())
            }) else {
                continue;
            };
            if node.set_resolved_result(*entity, result) {
                self.state
                    .resolved_entities
                    .lock()
                    .unwrap()
                    .insert(SimilarityEntityRef {
                        node_id: node.id(),
                        entity_id: *entity,
                    });
            }
        }
    }
}

struct TestReceiver {
    state: Arc<WorkflowState>,
}

struct TestGraphReceiver {
    state: Arc<WorkflowState>,
}

impl SimilaritySessionGraphReceiver for TestGraphReceiver {
    fn on_graph_changed(&self) {
        self.state.graph_changes.fetch_add(1, Ordering::Relaxed);
    }
}

impl SimilaritySessionReceiver for TestReceiver {
    fn on_started(&self, _completion: &SimilaritySessionCompletion) {
        self.state.starts.fetch_add(1, Ordering::Relaxed);
    }

    fn on_updated(
        &self,
        node: &SimilaritySessionNode,
        _provider: &CoreSimilarityProvider,
        entities: &[SimilarityEntityId],
    ) {
        let mut update_counts = self.state.update_counts.lock().unwrap();
        for &entity_id in entities {
            let entity = SimilarityEntityRef {
                node_id: node.id(),
                entity_id,
            };
            *update_counts.entry(entity).or_default() += 1;
        }
    }
}

#[test]
fn similarity_session_workflow() {
    let _headless_session = HeadlessSession::new().expect("Failed to initialize session");
    let is_ultimate = matches!(
        binaryninja::product().as_str(),
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate"
    );
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let fixture = out_dir.join("atox.obj");
    let root_view = binaryninja::load(&fixture).expect("Failed to create root view");
    let left_view = binaryninja::load(&fixture).expect("Failed to create left view");
    let right_view = binaryninja::load(&fixture).expect("Failed to create right view");
    let state = Arc::new(WorkflowState::default());

    let (_, provider_type) = register_similarity_provider(TestProviderType {
        state: state.clone(),
    });
    assert!(CoreSimilarityProviderType::by_name(TestProviderType::NAME).is_some());
    assert_eq!(provider_type.name(), TestProviderType::NAME);
    assert_eq!(provider_type.description(), TestProviderType::DESCRIPTION);
    let provider_settings = provider_type
        .default_settings()
        .expect("test provider has default settings");
    let provider = provider_type.create_provider(&provider_settings);
    if !is_ultimate {
        assert!(provider.is_none());
        return;
    }
    let provider = provider.expect("test provider can be created in Ultimate");
    assert_eq!(provider.provider_type().name(), TestProviderType::NAME);

    let session = SimilaritySession::new();
    session.add_provider(&provider);
    assert_eq!(session.providers().len(), 1);
    assert_eq!(session.provider(provider.id()).unwrap().id(), provider.id());

    let (_, resolver_type) = register_similarity_session_resolver(TestResolverType {
        provider: provider.to_owned(),
        state: state.clone(),
    });
    assert!(
        binaryninja::similarity::CoreSimilaritySessionResolverType::by_name(TestResolverType::NAME)
            .is_some()
    );
    assert_eq!(resolver_type.name(), TestResolverType::NAME);
    assert_eq!(resolver_type.description(), TestResolverType::DESCRIPTION);
    let resolver_settings = resolver_type
        .default_settings()
        .expect("test resolver has default settings");
    let resolver = resolver_type
        .create_resolver(&session, &resolver_settings)
        .expect("test resolver can be created");
    assert_eq!(resolver.resolver_type().name(), TestResolverType::NAME);
    assert!(session.add_resolver(&resolver));
    assert!(!session.add_resolver(&resolver));

    let receiver = CoreSimilaritySessionReceiver::create(TestReceiver {
        state: state.clone(),
    });
    session.add_receiver(&receiver);

    let root_file = root_view.file();
    let root = SimilaritySessionNode::new_from_file(&root_file);
    root.load_options().set_string("analysis.mode", "basic");
    assert_eq!(root.load_options().get_string("analysis.mode"), "basic");
    let left = SimilaritySessionNode::new(&left_view);
    let right = SimilaritySessionNode::new(&right_view);
    let catalog_only = root.create_entity(SimilarityEntityInfo {
        entity_type: SimilarityEntityType::SimilarityEntityFunction,
        address: u64::MAX,
        name: "catalog-only".to_string(),
    });
    assert_eq!(root.entity(catalog_only).unwrap().name, "catalog-only");
    assert!(!root
        .scheduled_entities()
        .iter()
        .any(|entity| entity == catalog_only));

    let graph = session.graph();
    let graph_receiver = CoreSimilaritySessionGraphReceiver::create(TestGraphReceiver {
        state: state.clone(),
    });
    graph.add_receiver(&graph_receiver);
    for node in [&root, &left, &right] {
        graph.add_node(node);
    }
    assert!(graph.add_edge(&root, &left));
    assert!(graph.add_edge(&root, &right));
    assert!(!graph.is_valid_edge(&left, &root));

    let schedule = graph.schedule();
    assert_eq!(schedule.len(), 2);
    assert_eq!(schedule[0][0].id(), root.id());
    assert_eq!(
        schedule[1]
            .iter()
            .map(|node| node.id())
            .collect::<HashSet<_>>(),
        HashSet::from([left.id(), right.id()])
    );

    let left_entity = left.scheduled_entities().get(0);
    let completion = session.run();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !completion.is_finished() {
        assert!(Instant::now() < deadline, "similarity session timed out");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        completion.progress(SimilaritySessionCompletionQuery::for_session()),
        1.0
    );
    for node in [&root, &left, &right] {
        assert_eq!(
            completion.progress(
                SimilaritySessionCompletionQuery::for_node(node.id()).with_provider(provider.id())
            ),
            1.0
        );
        assert_eq!(
            completion.progress(
                SimilaritySessionCompletionQuery::for_node(node.id()).with_resolver(resolver.id())
            ),
            1.0
        );
    }

    let catalog_only_ref = SimilarityEntityRef {
        node_id: root.id(),
        entity_id: catalog_only,
    };
    let expected_entities = [&root, &left, &right]
        .into_iter()
        .flat_map(|node| {
            node.entities()
                .into_iter()
                .map(|entity_id| SimilarityEntityRef {
                    node_id: node.id(),
                    entity_id,
                })
                .collect::<Vec<_>>()
        })
        .filter(|entity| *entity != catalog_only_ref)
        .collect::<HashSet<_>>();
    assert_eq!(state.starts.load(Ordering::Relaxed), 1);
    assert_eq!(state.graph_changes.load(Ordering::Relaxed), 5);
    assert_eq!(
        *state.visited_nodes.lock().unwrap(),
        HashSet::from([root.id(), left.id(), right.id()])
    );
    assert_eq!(
        *state.visited_edges.lock().unwrap(),
        HashSet::from([(root.id(), left.id()), (root.id(), right.id())])
    );
    assert_eq!(*state.visited_entities.lock().unwrap(), expected_entities);
    assert_eq!(*state.resolved_entities.lock().unwrap(), expected_entities);
    let expected_update_counts = expected_entities
        .iter()
        .copied()
        .map(|entity| (entity, 2))
        .collect::<HashMap<_, _>>();
    assert_eq!(*state.update_counts.lock().unwrap(), expected_update_counts);
    assert!(root.resolved_result(catalog_only).is_none());
    assert!(root.view().is_none());
    for node in [&root, &left, &right] {
        assert!(node.scheduled_entities().is_empty());
    }

    let result_id = left.results(left_entity)[0];
    let result = left.result(result_id).unwrap();
    assert_eq!(result.target.node_id, left.id());
    assert_eq!(left.result(result_id), Some(result));
    assert_eq!(left.result(999.into()), None);
    assert_eq!(
        provider.apply_result(&left, left_entity, result_id),
        SimilarityApplyStatus::SimilarityApplySuccess
    );

    let render_context = SimilarityRenderContext::new();
    render_context.set_preferred_view_type(FunctionViewType::MediumLevelIL);
    assert_eq!(
        render_context.preferred_view_type(),
        FunctionViewType::MediumLevelIL
    );
    provider.render_result(&left, left_entity, &render_context, result_id);
    let views = render_context.views();
    assert_eq!(views.len(), 2);
    assert!(views.iter().all(|view| view.entity
        == Some(SimilarityEntityRef {
            node_id: left.id(),
            entity_id: left_entity,
        })));

    assert!(left.clear_resolved_result(left_entity));
    assert!(left.resolved_result(left_entity).is_none());
    assert!(root.remove_entity(catalog_only));

    assert_eq!(session.resolver(resolver.id()).unwrap().id(), resolver.id());
    assert!(session.update_resolver_settings(&resolver, &resolver_settings));
    assert_eq!(state.resolver_settings_updates.load(Ordering::Relaxed), 1);
    assert!(session.update_provider_settings(&provider, &provider_settings));
    assert_eq!(state.provider_settings_updates.load(Ordering::Relaxed), 1);
    assert!(session.remove_resolver(&resolver));
    assert!(!session.remove_resolver(&resolver));
    assert!(session.resolver(resolver.id()).is_none());
    session.remove_receiver(&receiver);
    graph.remove_receiver(&graph_receiver);
    assert!(graph.receivers().is_empty());
    session.remove_provider(&provider);
    assert!(session.receivers().is_empty());
    assert!(session.providers().is_empty());
}

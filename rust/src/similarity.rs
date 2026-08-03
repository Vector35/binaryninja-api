//! Function similarity providers, sessions, and result rendering.

use binaryninjacore_sys::{
    BNSimilarityAnnotationType, BNSimilarityApplyStatus, BNSimilarityEntityId,
    BNSimilarityEntityRef, BNSimilarityEntityType, BNSimilarityProviderId, BNSimilarityResultId,
    BNSimilaritySessionCompletionQuery, BNSimilaritySessionId, BNSimilaritySessionNodeId,
    BNSimilaritySessionResolverId, BNSimilarityViewType,
};

pub mod graph;
pub mod node;
pub mod provider;
pub mod render;
pub mod session;

pub use graph::*;
pub use node::*;
pub use provider::*;
pub use render::*;
pub use session::*;

/// The kind of object represented by a similarity entity.
pub type SimilarityEntityType = BNSimilarityEntityType;

/// The result of applying a similarity match.
pub type SimilarityApplyStatus = BNSimilarityApplyStatus;

/// The kind of view produced when rendering a result.
pub type SimilarityViewType = BNSimilarityViewType;

/// The change represented by a rendered address range.
pub type SimilarityAnnotationType = BNSimilarityAnnotationType;

new_id_type!(
    /// Identifies an entity within a similarity session node.
    SimilarityEntityId,
    u32,
    BNSimilarityEntityId,
    value
);

new_id_type!(
    /// Identifies a result within a similarity session node.
    SimilarityResultId,
    u64,
    BNSimilarityResultId,
    value
);

new_id_type!(
    /// Identifies a similarity session node.
    SimilaritySessionNodeId,
    u32,
    BNSimilaritySessionNodeId,
    value
);

new_id_type!(
    /// Identifies a similarity session.
    SimilaritySessionId,
    u32,
    BNSimilaritySessionId,
    value
);

new_id_type!(
    /// Identifies a similarity provider instance.
    SimilarityProviderId,
    u32,
    BNSimilarityProviderId,
    value
);

new_id_type!(
    /// Identifies a similarity resolver instance.
    SimilaritySessionResolverId,
    u32,
    BNSimilaritySessionResolverId,
    value
);

/// Chooses which similarity session completion data to read or update.
///
/// A query cannot select both a provider and a resolver. An empty query selects the whole session.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct SimilaritySessionCompletionQuery {
    node_id: Option<SimilaritySessionNodeId>,
    provider_id: Option<SimilarityProviderId>,
    resolver_id: Option<SimilaritySessionResolverId>,
}

impl SimilaritySessionCompletionQuery {
    /// Selects the whole session.
    pub fn for_session() -> Self {
        Self::default()
    }
    /// Selects a node.
    pub fn for_node(node_id: SimilaritySessionNodeId) -> Self {
        Self {
            node_id: Some(node_id),
            ..Self::default()
        }
    }
    /// Selects a provider across the session.
    pub fn for_provider(provider_id: SimilarityProviderId) -> Self {
        Self {
            provider_id: Some(provider_id),
            ..Self::default()
        }
    }
    /// Selects a resolver across the session.
    pub fn for_resolver(resolver_id: SimilaritySessionResolverId) -> Self {
        Self {
            resolver_id: Some(resolver_id),
            ..Self::default()
        }
    }
    /// Selects a provider within the current selection.
    pub fn with_provider(mut self, provider_id: SimilarityProviderId) -> Self {
        self.provider_id = Some(provider_id);
        self.resolver_id = None;
        self
    }
    /// Selects a resolver within the current selection.
    pub fn with_resolver(mut self, resolver_id: SimilaritySessionResolverId) -> Self {
        self.provider_id = None;
        self.resolver_id = Some(resolver_id);
        self
    }

    /// Returns the selected node, if any.
    pub fn node_id(&self) -> Option<SimilaritySessionNodeId> {
        self.node_id
    }

    /// Returns the selected provider, if any.
    pub fn provider_id(&self) -> Option<SimilarityProviderId> {
        self.provider_id
    }

    /// Returns the selected resolver, if any.
    pub fn resolver_id(&self) -> Option<SimilaritySessionResolverId> {
        self.resolver_id
    }
}

impl From<SimilaritySessionCompletionQuery> for BNSimilaritySessionCompletionQuery {
    fn from(value: SimilaritySessionCompletionQuery) -> Self {
        Self {
            hasNodeId: value.node_id.is_some(),
            nodeId: value.node_id.unwrap_or(SimilaritySessionNodeId(0)).into(),
            hasProviderId: value.provider_id.is_some(),
            providerId: value.provider_id.unwrap_or(SimilarityProviderId(0)).into(),
            hasResolverId: value.resolver_id.is_some(),
            resolverId: value
                .resolver_id
                .unwrap_or(SimilaritySessionResolverId(0))
                .into(),
        }
    }
}

/// Identifies an entity within a session node.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SimilarityEntityRef {
    pub node_id: SimilaritySessionNodeId,
    pub entity_id: SimilarityEntityId,
}

/// Information about an entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SimilarityEntityInfo {
    pub entity_type: SimilarityEntityType,
    /// The address of the entity within its [`crate::binary_view::BinaryView`].
    pub address: u64,
    /// The display name of the entity.
    pub name: String,
}

impl From<BNSimilarityEntityRef> for SimilarityEntityRef {
    fn from(value: BNSimilarityEntityRef) -> Self {
        Self {
            node_id: value.nodeId.into(),
            entity_id: value.entityId.into(),
        }
    }
}

impl From<SimilarityEntityRef> for BNSimilarityEntityRef {
    fn from(value: SimilarityEntityRef) -> Self {
        Self {
            nodeId: value.node_id.into(),
            entityId: value.entity_id.into(),
        }
    }
}

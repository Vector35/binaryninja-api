use super::graph::SimilaritySessionGraph;
use super::provider::CoreSimilarityProvider;
use super::{
    SimilarityProviderId, SimilaritySessionCompletionQuery, SimilaritySessionId,
    SimilaritySessionResolverId,
};
use crate::rc::{Array, Ref, RefCountable};
use crate::settings::Settings;
use binaryninjacore_sys::*;
use std::time::Duration;

pub mod receiver;
pub mod resolver;

pub use receiver::*;
pub use resolver::*;

/// Coordinates providers and resolvers across a graph of binaries.
pub struct SimilaritySession {
    pub(crate) handle: *mut BNSimilaritySession,
}

impl SimilaritySession {
    /// Creates an empty session.
    pub fn new() -> Ref<Self> {
        let handle = unsafe { BNCreateSimilaritySession() };
        unsafe { Ref::new(Self { handle }) }
    }

    pub unsafe fn from_raw(handle: *mut BNSimilaritySession) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySession) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Returns the session's unique ID.
    pub fn id(&self) -> SimilaritySessionId {
        unsafe { BNSimilaritySessionGetId(self.handle) }.into()
    }

    /// Adds a provider and schedules entities processed by earlier runs for the next run.
    ///
    /// NOTE: Ignored while a run is active.
    pub fn add_provider(&self, provider: &CoreSimilarityProvider) {
        unsafe { BNSimilaritySessionAddProvider(self.handle, provider.handle) }
    }

    /// Removes a provider, clears its results, and marks affected entities for resolution.
    ///
    /// NOTE: Ignored while a run is active.
    pub fn remove_provider(&self, provider: &CoreSimilarityProvider) {
        unsafe { BNSimilaritySessionRemoveProvider(self.handle, provider.handle) }
    }

    /// Updates a provider already in the session and schedules previously processed entities again.
    ///
    /// Returns `false` during a run, when the provider is absent, or when it rejects the settings.
    pub fn update_provider_settings(
        &self,
        provider: &CoreSimilarityProvider,
        settings: &Settings,
    ) -> bool {
        unsafe {
            BNSimilaritySessionUpdateProviderSettings(self.handle, provider.handle, settings.handle)
        }
    }

    /// Returns a provider by ID.
    pub fn provider(&self, id: SimilarityProviderId) -> Option<Ref<CoreSimilarityProvider>> {
        let handle = unsafe { BNSimilaritySessionGetProvider(self.handle, id.into()) };
        match handle.is_null() {
            true => None,
            false => unsafe { Some(CoreSimilarityProvider::ref_from_raw(handle)) },
        }
    }

    /// Returns the session's providers.
    pub fn providers(&self) -> Array<CoreSimilarityProvider> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionGetProviders(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds a resolver created for this session and marks entities processed by earlier runs for resolution.
    ///
    /// NOTE: Returns `false` during a run, for a duplicate, or for a resolver created for another session.
    pub fn add_resolver(&self, resolver: &CoreSimilaritySessionResolver) -> bool {
        unsafe { BNSimilaritySessionAddResolver(self.handle, resolver.handle) }
    }

    /// Removes a resolver from the session.
    ///
    /// NOTE: Returns `false` during a run, or if it is absent or belongs to another session.
    pub fn remove_resolver(&self, resolver: &CoreSimilaritySessionResolver) -> bool {
        unsafe { BNSimilaritySessionRemoveResolver(self.handle, resolver.handle) }
    }

    /// Updates a resolver already in the session and marks previously processed entities for resolution.
    ///
    /// Returns `false` during a run, when the resolver is absent or belongs to another session, or when it rejects the
    /// settings.
    pub fn update_resolver_settings(
        &self,
        resolver: &CoreSimilaritySessionResolver,
        settings: &Settings,
    ) -> bool {
        unsafe {
            BNSimilaritySessionUpdateResolverSettings(self.handle, resolver.handle, settings.handle)
        }
    }

    /// Returns a resolver by ID.
    pub fn resolver(
        &self,
        id: SimilaritySessionResolverId,
    ) -> Option<Ref<CoreSimilaritySessionResolver>> {
        let handle = unsafe { BNSimilaritySessionGetResolver(self.handle, id.into()) };
        match handle.is_null() {
            true => None,
            false => unsafe { Some(CoreSimilaritySessionResolver::ref_from_raw(handle)) },
        }
    }

    /// Returns the session's resolvers.
    pub fn resolvers(&self) -> Array<CoreSimilaritySessionResolver> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionGetResolvers(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds an update receiver.
    ///
    /// A running session keeps using the receiver list it started with.
    pub fn add_receiver(&self, receiver: &CoreSimilaritySessionReceiver) {
        unsafe { BNSimilaritySessionAddReceiver(self.handle, receiver.handle) }
    }

    /// Removes an update receiver.
    ///
    /// A running session keeps using the receiver list it started with.
    pub fn remove_receiver(&self, receiver: &CoreSimilaritySessionReceiver) {
        unsafe { BNSimilaritySessionRemoveReceiver(self.handle, receiver.handle) }
    }

    /// Returns the session's update receivers.
    pub fn receivers(&self) -> Array<CoreSimilaritySessionReceiver> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionGetReceivers(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns the session graph.
    pub fn graph(&self) -> Ref<SimilaritySessionGraph> {
        let handle = unsafe { BNSimilaritySessionGetGraph(self.handle) };
        unsafe { SimilaritySessionGraph::ref_from_raw(handle) }
    }

    /// Starts a background run with the current graph, providers, and resolvers.
    ///
    /// Changes to them are ignored until the run finishes.
    ///
    /// NOTE: Returns the completion state of the active run when already running.
    pub fn run(&self) -> Ref<SimilaritySessionCompletion> {
        unsafe { SimilaritySessionCompletion::ref_from_raw(BNSimilaritySessionRun(self.handle)) }
    }
}

impl ToOwned for SimilaritySession {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for SimilaritySession {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionReference(handle.handle),
        })
    }
    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySession(handle.handle);
    }
}

/// Stop requests, progress, and timing for a session run.
pub struct SimilaritySessionCompletion {
    pub(crate) handle: *mut BNSimilaritySessionCompletion,
}

impl SimilaritySessionCompletion {
    /// Creates a new completion state, typically only done when calling into providers and resolvers
    /// directly instead of from a session.
    pub fn new() -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateSimilaritySessionCompletion()) }
    }

    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionCompletion) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionCompletion) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Returns whether the session run has finished.
    pub fn is_finished(&self) -> bool {
        unsafe { BNSimilaritySessionCompletionIsFinished(self.handle) }
    }

    /// Returns progress for the selected part of the run from `0.0` through `1.0`.
    pub fn progress(&self, query: SimilaritySessionCompletionQuery) -> f64 {
        let raw_query = query.into();
        unsafe { BNSimilaritySessionCompletionGetProgress(self.handle, &raw_query) }
    }

    /// Asks the run to stop.
    pub fn request_stop(&self) {
        unsafe { BNSimilaritySessionCompletionRequestStop(self.handle) }
    }

    /// Returns whether a stop has been requested.
    pub fn is_stop_requested(&self) -> bool {
        unsafe { BNSimilaritySessionCompletionIsStopRequested(self.handle) }
    }

    /// Increases progress for a node and one provider or resolver. Progress cannot decrease.
    ///
    /// NOTE: Only call this from the provider or resolver selected by the query.
    pub fn set_progress(&self, query: SimilaritySessionCompletionQuery, progress: f64) {
        let raw_query = query.into();
        unsafe { BNSimilaritySessionCompletionSetProgress(self.handle, &raw_query, progress) }
    }

    /// Returns timing for the selected part of the run.
    pub fn timing(&self, query: SimilaritySessionCompletionQuery) -> Duration {
        let raw_query = query.into();
        Duration::from_millis(unsafe {
            BNSimilaritySessionCompletionGetTiming(self.handle, &raw_query)
        })
    }
}

unsafe impl Send for SimilaritySessionCompletion {}
unsafe impl Sync for SimilaritySessionCompletion {}

impl ToOwned for SimilaritySessionCompletion {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for SimilaritySessionCompletion {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionCompletionReference(handle.handle),
        })
    }
    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionCompletion(handle.handle);
    }
}

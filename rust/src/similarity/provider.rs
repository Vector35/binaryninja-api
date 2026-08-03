use super::node::SimilaritySessionNode;
use super::render::SimilarityRenderContext;
use super::{
    SimilarityApplyStatus, SimilarityEntityId, SimilarityEntityRef, SimilarityProviderId,
    SimilarityResultId, SimilaritySessionCompletion,
};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::settings::Settings;
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::marker::PhantomData;
use std::rc::Rc;

/// Registers a similarity provider type.
pub fn register_similarity_provider<C>(provider_ty: C) -> (&'static C, CoreSimilarityProviderType)
where
    C: SimilarityProviderType,
{
    let name = C::NAME.to_cstr();
    let description = C::DESCRIPTION.to_cstr();
    // Provider types remain registered for the lifetime of the process.
    let leaked_provider: &'static C = Box::leak(Box::new(provider_ty));
    let result = unsafe {
        BNRegisterSimilarityProviderType(
            name.as_ptr(),
            description.as_ptr(),
            &mut BNCustomSimilarityProviderType {
                context: leaked_provider as *const C as *mut c_void,
                create: Some(cb_create_provider::<C>),
                getDefaultSettings: Some(cb_default_settings::<C>),
            },
        )
    };
    let core_provider_ty = unsafe { CoreSimilarityProviderType::from_raw(result) };
    (leaked_provider, core_provider_ty)
}

/// Creates similarity providers with the given settings.
pub trait SimilarityProviderType: Sync + 'static {
    type SimilarityProvider: SimilarityProvider;

    /// The provider name shown to users.
    const NAME: &'static str;

    /// A short description of the provider.
    const DESCRIPTION: &'static str;

    /// Creates a provider with the given settings.
    fn create_provider(&self, settings: &Settings) -> Self::SimilarityProvider;

    /// Returns the settings used to configure new providers, if any.
    fn default_settings(&self) -> Option<Ref<Settings>>;
}

/// Produces and applies similarity results for session entities.
///
/// Visits made by a session keep the visited node and both edge endpoints active. Direct calls must provide active
/// views.
pub trait SimilarityProvider: Send + Sync + 'static {
    /// Replaces this provider's settings only if they are valid.
    ///
    /// Return `false` without changing the current settings when the new settings are invalid or updates are not
    /// supported. Use
    /// [`SimilaritySession::update_provider_settings`](super::SimilaritySession::update_provider_settings) so affected
    /// entities are scheduled again.
    fn update_settings(&self, _settings: &Settings) -> bool {
        false
    }

    /// Visits the node's scheduled entities and writes results for the node.
    ///
    /// A successful visit replaces earlier results from this provider for scheduled entities. Results for unscheduled
    /// entities remain unchanged. Return `false` to discard the visit.
    fn visit_node(
        &self,
        _node: &SimilaritySessionNode,
        _results: &mut SimilarityProviderResults<'_>,
        _completion: &SimilaritySessionCompletion,
    ) -> bool {
        true
    }

    /// Visits an edge after both endpoint nodes have been visited and writes results for the edge.
    ///
    /// Return `false` to discard the visit.
    fn visit_node_edge(
        &self,
        _from: &SimilaritySessionNode,
        _to: &SimilaritySessionNode,
        _results: &mut SimilarityProviderResults<'_>,
        _completion: &SimilaritySessionCompletion,
    ) -> bool {
        true
    }

    /// Returns the display name for a result.
    fn result_name(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> Option<String>;

    /// Applies a result.
    ///
    /// The default implementation performs the standard metadata transfer from the result target.
    fn apply_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> SimilarityApplyStatus {
        let Some(result) = node.result(result) else {
            return SimilarityApplyStatus::SimilarityApplyFailed;
        };
        node.apply_target(entity, result.target)
    }

    /// Adds views for a result to a render context.
    fn render_result(
        &self,
        _node: &SimilaritySessionNode,
        _entity: SimilarityEntityId,
        _context: &SimilarityRenderContext,
        _result: SimilarityResultId,
    ) {
    }
}

/// Writes results for one provider node or edge visit.
///
/// Only use this writer during the provider callback that received it.
pub struct SimilarityProviderResults<'a> {
    handle: *mut BNSimilarityProviderResults,
    _lifetime: PhantomData<&'a mut BNSimilarityProviderResults>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl<'a> SimilarityProviderResults<'a> {
    unsafe fn from_raw(handle: *mut BNSimilarityProviderResults) -> Self {
        Self {
            handle,
            _lifetime: PhantomData,
            _not_send_or_sync: PhantomData,
        }
    }

    /// Adds a result for a scheduled entity and returns its ID, or zero on failure. The ID is unique
    /// within the node. A later visit replaces the result and gives it a new ID.
    pub fn add_result(
        &mut self,
        source: SimilarityEntityRef,
        target: SimilarityEntityRef,
        similarity: u8,
        confidence: u8,
    ) -> SimilarityResultId {
        let source = BNSimilarityEntityRef::from(source);
        let target = BNSimilarityEntityRef::from(target);
        unsafe {
            BNSimilarityProviderResultsAddResult(
                self.handle,
                &source,
                &target,
                similarity,
                confidence,
            )
            .into()
        }
    }
}

/// A registered similarity provider type.
pub struct CoreSimilarityProviderType {
    pub(crate) handle: *mut BNSimilarityProviderType,
}

impl CoreSimilarityProviderType {
    pub unsafe fn from_raw(handle: *mut BNSimilarityProviderType) -> Self {
        Self { handle }
    }

    /// Returns a registered provider type by name.
    pub fn by_name(name: &str) -> Option<CoreSimilarityProviderType> {
        let name = name.to_cstr();
        let raw_type = unsafe { BNGetSimilarityProviderTypeByName(name.as_ptr()) };
        match raw_type.is_null() {
            true => None,
            false => Some(unsafe { Self::from_raw(raw_type) }),
        }
    }

    /// Returns all registered provider types.
    pub fn all() -> Array<CoreSimilarityProviderType> {
        let mut count = 0;
        let result = unsafe { BNGetSimilarityProviderTypeList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns the registered name.
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNSimilarityProviderTypeGetName(self.handle)) }
    }

    /// Returns the provider description.
    pub fn description(&self) -> String {
        unsafe { BnString::into_string(BNSimilarityProviderTypeGetDescription(self.handle)) }
    }

    /// Creates a provider with the given settings, if supported. Returns `None` outside Ultimate.
    pub fn create_provider(&self, settings: &Settings) -> Option<Ref<CoreSimilarityProvider>> {
        let provider_raw =
            unsafe { BNSimilarityProviderTypeCreateProvider(self.handle, settings.handle) };
        (!provider_raw.is_null())
            .then(|| unsafe { CoreSimilarityProvider::ref_from_raw(provider_raw) })
    }

    /// Returns the default provider settings, if available.
    pub fn default_settings(&self) -> Option<Ref<Settings>> {
        let settings_raw = unsafe { BNSimilarityProviderTypeGetDefaultSettings(self.handle) };
        (!settings_raw.is_null()).then(|| unsafe { Settings::ref_from_raw(settings_raw) })
    }
}

impl CoreArrayProvider for CoreSimilarityProviderType {
    type Raw = *mut BNSimilarityProviderType;
    type Context = ();
    type Wrapped<'a> = CoreSimilarityProviderType;
}

unsafe impl CoreArrayProviderInner for CoreSimilarityProviderType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeSimilarityProviderTypeList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CoreSimilarityProviderType::from_raw(*raw)
    }
}

/// A core-backed similarity provider.
pub struct CoreSimilarityProvider {
    pub(crate) handle: *mut BNSimilarityProvider,
}

impl CoreSimilarityProvider {
    pub unsafe fn from_raw(handle: *mut BNSimilarityProvider) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilarityProvider) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Returns the provider's ID.
    pub fn id(&self) -> SimilarityProviderId {
        unsafe { BNSimilarityProviderGetId(self.handle) }.into()
    }

    /// Wraps a custom provider in a core provider.
    pub fn create<C: SimilarityProvider>(
        ty: &CoreSimilarityProviderType,
        provider: C,
    ) -> Ref<CoreSimilarityProvider> {
        let provider = Box::into_raw(Box::new(provider));
        let mut callbacks = BNCustomSimilarityProvider {
            context: provider.cast(),
            externalRefTaken: None,
            externalRefReleased: None,
            updateSettings: Some(cb_update_provider_settings::<C>),
            visitNode: Some(cb_visit_node::<C>),
            visitNodeEdge: Some(cb_visit_node_edge::<C>),
            getName: Some(cb_provider_get_name::<C>),
            apply: Some(cb_provider_apply::<C>),
            render: Some(cb_provider_render::<C>),
            free: Some(cb_provider_free::<C>),
        };

        let raw_provider = unsafe { BNCreateCustomSimilarityProvider(ty.handle, &mut callbacks) };
        unsafe { CoreSimilarityProvider::ref_from_raw(raw_provider) }
    }

    /// Returns the registered type that created this provider.
    pub fn provider_type(&self) -> CoreSimilarityProviderType {
        let handle = unsafe { BNSimilarityProviderGetType(self.handle) };
        unsafe { CoreSimilarityProviderType::from_raw(handle) }
    }

    /// Performs a complete node visit with the core managing result updates.
    pub fn visit_node(
        &self,
        node: &SimilaritySessionNode,
        completion: &SimilaritySessionCompletion,
    ) {
        unsafe { BNSimilarityProviderVisitNode(self.handle, node.handle, completion.handle) }
    }

    /// Performs a complete edge visit with the core managing result updates.
    pub fn visit_node_edge(
        &self,
        from: &SimilaritySessionNode,
        to: &SimilaritySessionNode,
        completion: &SimilaritySessionCompletion,
    ) {
        unsafe {
            BNSimilarityProviderVisitNodeEdge(
                self.handle,
                from.handle,
                to.handle,
                completion.handle,
            )
        }
    }

    /// Calls this provider's node visit with an existing result writer.
    pub fn perform_visit_node(
        &self,
        node: &SimilaritySessionNode,
        results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        unsafe {
            BNSimilarityProviderPerformVisitNode(
                self.handle,
                node.handle,
                results.handle,
                completion.handle,
            )
        }
    }

    /// Calls this provider's edge visit with an existing result writer.
    pub fn perform_visit_node_edge(
        &self,
        from: &SimilaritySessionNode,
        to: &SimilaritySessionNode,
        results: &mut SimilarityProviderResults<'_>,
        completion: &SimilaritySessionCompletion,
    ) -> bool {
        unsafe {
            BNSimilarityProviderPerformVisitNodeEdge(
                self.handle,
                from.handle,
                to.handle,
                results.handle,
                completion.handle,
            )
        }
    }

    /// Returns the display name for a result.
    pub fn result_name(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> Option<String> {
        let name_raw = unsafe {
            BNSimilarityProviderGetName(self.handle, node.handle, entity.into(), result.into())
        };
        if name_raw.is_null() {
            return None;
        }
        Some(unsafe { BnString::into_string(name_raw) })
    }

    /// Applies a result.
    pub fn apply_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> SimilarityApplyStatus {
        unsafe { BNSimilarityProviderApply(self.handle, node.handle, entity.into(), result.into()) }
    }

    /// Adds views for a result to a render context.
    pub fn render_result(
        &self,
        node: &SimilaritySessionNode,
        entity: SimilarityEntityId,
        context: &SimilarityRenderContext,
        result: SimilarityResultId,
    ) {
        unsafe {
            BNSimilarityProviderRender(
                self.handle,
                node.handle,
                entity.into(),
                context.handle,
                result.into(),
            )
        }
    }
}

unsafe impl Send for CoreSimilarityProvider {}
unsafe impl Sync for CoreSimilarityProvider {}

impl ToOwned for CoreSimilarityProvider {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreSimilarityProvider {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilarityProviderReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilarityProvider(handle.handle);
    }
}

impl CoreArrayProvider for CoreSimilarityProvider {
    type Raw = *mut BNSimilarityProvider;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for CoreSimilarityProvider {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSimilarityProviderList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

/// A match produced by a similarity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SimilarityResult {
    /// The provider which produced the match.
    pub provider_id: SimilarityProviderId,
    /// The similarity of the two entities.
    pub similarity: u8,
    /// The provider's confidence in the match.
    pub confidence: u8,
    /// The entity matched by this result.
    ///
    /// This can be used to transfer metadata from the target to the source entity.
    pub target: SimilarityEntityRef,
}

impl From<BNSimilarityResult> for SimilarityResult {
    fn from(value: BNSimilarityResult) -> Self {
        Self {
            provider_id: value.providerId.into(),
            similarity: value.similarity,
            confidence: value.confidence,
            target: value.target.into(),
        }
    }
}

impl From<SimilarityResult> for BNSimilarityResult {
    fn from(value: SimilarityResult) -> Self {
        Self {
            providerId: value.provider_id.into(),
            similarity: value.similarity,
            confidence: value.confidence,
            target: value.target.into(),
        }
    }
}

unsafe extern "C" fn cb_create_provider<C: SimilarityProviderType>(
    ctxt: *mut c_void,
    settings: *mut BNSettings,
) -> *mut BNSimilarityProvider {
    ffi_wrap!("SimilarityProviderType::create_provider", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let settings = Settings::from_raw(settings);
        let provider = ctxt.create_provider(&settings);
        let core_type = CoreSimilarityProviderType::by_name(C::NAME).unwrap();
        let core_provider = CoreSimilarityProvider::create(&core_type, provider);
        Ref::into_raw(core_provider).handle
    })
}

unsafe extern "C" fn cb_default_settings<C: SimilarityProviderType>(
    ctxt: *mut c_void,
) -> *mut BNSettings {
    ffi_wrap!("SimilarityProviderType::default_settings", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        ctxt.default_settings()
            .map(|settings| Ref::into_raw(settings).handle)
            .unwrap_or(std::ptr::null_mut())
    })
}

unsafe extern "C" fn cb_update_provider_settings<C: SimilarityProvider>(
    ctxt: *mut c_void,
    settings: *mut BNSettings,
) -> bool {
    ffi_wrap!("SimilarityProvider::update_settings", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let settings = Settings::from_raw(settings);
        ctxt.update_settings(&settings)
    })
}

unsafe extern "C" fn cb_visit_node<C: SimilarityProvider>(
    ctxt: *mut c_void,
    node: *mut BNSimilaritySessionNode,
    results: *mut BNSimilarityProviderResults,
    completion: *mut BNSimilaritySessionCompletion,
) -> bool {
    ffi_wrap!("SimilarityProvider::visit_node", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let node = SimilaritySessionNode::from_raw(node);
        let mut results = SimilarityProviderResults::from_raw(results);
        let completion = SimilaritySessionCompletion::from_raw(completion);
        ctxt.visit_node(&node, &mut results, &completion)
    })
}

unsafe extern "C" fn cb_visit_node_edge<C: SimilarityProvider>(
    ctxt: *mut c_void,
    from: *mut BNSimilaritySessionNode,
    to: *mut BNSimilaritySessionNode,
    results: *mut BNSimilarityProviderResults,
    completion: *mut BNSimilaritySessionCompletion,
) -> bool {
    ffi_wrap!("SimilarityProvider::visit_node_edge", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let from = SimilaritySessionNode::from_raw(from);
        let to = SimilaritySessionNode::from_raw(to);
        let mut results = SimilarityProviderResults::from_raw(results);
        let completion = SimilaritySessionCompletion::from_raw(completion);
        ctxt.visit_node_edge(&from, &to, &mut results, &completion)
    })
}

unsafe extern "C" fn cb_provider_get_name<C: SimilarityProvider>(
    ctxt: *mut c_void,
    node: *mut BNSimilaritySessionNode,
    entity: BNSimilarityEntityId,
    result: BNSimilarityResultId,
) -> *mut c_char {
    ffi_wrap!("SimilarityProvider::result_name", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let node = SimilaritySessionNode::from_raw(node);
        let Some(name) = ctxt.result_name(&node, entity.into(), result.into()) else {
            return std::ptr::null_mut();
        };
        BnString::into_raw(BnString::new(name))
    })
}

unsafe extern "C" fn cb_provider_apply<C: SimilarityProvider>(
    ctxt: *mut c_void,
    node: *mut BNSimilaritySessionNode,
    entity: BNSimilarityEntityId,
    result: BNSimilarityResultId,
) -> BNSimilarityApplyStatus {
    ffi_wrap!("SimilarityProvider::apply_result", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let node = SimilaritySessionNode::from_raw(node);
        ctxt.apply_result(&node, entity.into(), result.into())
    })
}

unsafe extern "C" fn cb_provider_render<C: SimilarityProvider>(
    ctxt: *mut c_void,
    node: *mut BNSimilaritySessionNode,
    entity: BNSimilarityEntityId,
    context: *mut BNSimilarityRenderContext,
    result: BNSimilarityResultId,
) {
    ffi_wrap!("SimilarityProvider::render_result", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let node = SimilaritySessionNode::from_raw(node);
        let context = SimilarityRenderContext::from_raw(context);
        ctxt.render_result(&node, entity.into(), &context, result.into());
    })
}

unsafe extern "C" fn cb_provider_free<C: SimilarityProvider>(ctxt: *mut c_void) {
    ffi_wrap!("SimilarityProvider::free", unsafe {
        let _ = Box::from_raw(ctxt as *mut C);
    })
}

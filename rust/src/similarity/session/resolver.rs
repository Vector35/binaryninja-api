use super::{SimilaritySession, SimilaritySessionCompletion};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::settings::Settings;
use crate::similarity::node::SimilaritySessionNode;
use crate::similarity::{SimilarityEntityId, SimilaritySessionResolverId};
use crate::string::IntoCStr;
use binaryninjacore_sys::*;
use std::ffi::c_void;

/// Creates similarity result resolvers with the given settings.
pub trait SimilaritySessionResolverType: Sync + 'static {
    type SimilaritySessionResolver: SimilaritySessionResolver;

    /// The resolver name shown to users.
    const NAME: &'static str;
    /// A short description of the resolver.
    const DESCRIPTION: &'static str;

    /// Creates a resolver for a session.
    fn create_resolver(
        &self,
        session: &SimilaritySession,
        settings: &Settings,
    ) -> Self::SimilaritySessionResolver;

    /// Returns the settings used to configure new resolvers, if any.
    fn default_settings(&self) -> Option<Ref<Settings>>;
}

/// Selects provider results for session entities.
///
/// Calls for nodes in the same processing group may run at the same time. Do not keep the session after a callback
/// returns.
pub trait SimilaritySessionResolver: Send + Sync + 'static {
    /// Replaces this resolver's settings only if they are valid.
    ///
    /// Return `false` without changing the current settings when the new settings are invalid or updates are not
    /// supported. Use
    /// [`SimilaritySession::update_resolver_settings`] so affected entities are resolved again.
    fn update_settings(&self, _settings: &Settings) -> bool {
        false
    }

    /// Prepares a node after its entities are created and before providers run.
    ///
    /// This is useful for large graphs where not all views are available, but the resolver needs to
    /// change the scheduled entities or add new entities.
    fn prepare_for_node(
        &self,
        _session: &SimilaritySession,
        _node: &SimilaritySessionNode,
        _completion: &SimilaritySessionCompletion,
        _resolver_id: SimilaritySessionResolverId,
    ) {
    }

    /// Selects results after a node's providers have run.
    ///
    /// To select a result, call [`SimilaritySessionNode::set_resolved_result`] for the given entity.
    /// To request another provider and resolver round, call [`SimilaritySessionNode::add_scheduled_entity`].
    fn resolve_for_node(
        &self,
        session: &SimilaritySession,
        node: &SimilaritySessionNode,
        entities: &[SimilarityEntityId],
        completion: &SimilaritySessionCompletion,
        resolver_id: SimilaritySessionResolverId,
    );
}

/// Registers a similarity session resolver type.
pub fn register_similarity_session_resolver<C>(
    resolver_ty: C,
) -> (&'static C, CoreSimilaritySessionResolverType)
where
    C: SimilaritySessionResolverType,
{
    let name = C::NAME.to_cstr();
    let description = C::DESCRIPTION.to_cstr();
    // Resolver types remain registered for the lifetime of the process.
    let leaked_resolver: &'static C = Box::leak(Box::new(resolver_ty));
    let result = unsafe {
        BNRegisterSimilaritySessionResolverType(
            name.as_ptr(),
            description.as_ptr(),
            &mut BNCustomSimilaritySessionResolverType {
                context: leaked_resolver as *const C as *mut c_void,
                create: Some(cb_create_resolver::<C>),
                getDefaultSettings: Some(cb_resolver_default_settings::<C>),
            },
        )
    };
    let core_resolver_ty = unsafe { CoreSimilaritySessionResolverType::from_raw(result) };
    (leaked_resolver, core_resolver_ty)
}

/// A registered similarity session resolver type.
pub struct CoreSimilaritySessionResolverType {
    pub(crate) handle: *mut BNSimilaritySessionResolverType,
}

impl CoreSimilaritySessionResolverType {
    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionResolverType) -> Self {
        Self { handle }
    }

    /// Returns a registered resolver type by name.
    pub fn by_name(name: &str) -> Option<Self> {
        let name = name.to_cstr();
        let raw_type = unsafe { BNGetSimilaritySessionResolverTypeByName(name.as_ptr()) };
        match raw_type.is_null() {
            true => None,
            false => Some(unsafe { Self::from_raw(raw_type) }),
        }
    }

    /// Returns all registered resolver types.
    pub fn all() -> Array<CoreSimilaritySessionResolverType> {
        let mut count = 0;
        let result = unsafe { BNGetSimilaritySessionResolverTypeList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns the registered name.
    pub fn name(&self) -> String {
        unsafe {
            crate::string::BnString::into_string(BNSimilaritySessionResolverTypeGetName(
                self.handle,
            ))
        }
    }

    /// Returns the resolver description.
    pub fn description(&self) -> String {
        unsafe {
            crate::string::BnString::into_string(BNSimilaritySessionResolverTypeGetDescription(
                self.handle,
            ))
        }
    }

    /// Creates a resolver for a session, if supported.
    pub fn create_resolver(
        &self,
        session: &SimilaritySession,
        settings: &Settings,
    ) -> Option<Ref<CoreSimilaritySessionResolver>> {
        let handle = unsafe {
            BNSimilaritySessionResolverTypeCreateResolver(
                self.handle,
                session.handle,
                settings.handle,
            )
        };
        (!handle.is_null()).then(|| unsafe { CoreSimilaritySessionResolver::ref_from_raw(handle) })
    }

    /// Returns the default resolver settings, if available.
    pub fn default_settings(&self) -> Option<Ref<Settings>> {
        let handle = unsafe { BNSimilaritySessionResolverTypeGetDefaultSettings(self.handle) };
        (!handle.is_null()).then(|| unsafe { Settings::ref_from_raw(handle) })
    }
}

impl CoreArrayProvider for CoreSimilaritySessionResolverType {
    type Raw = *mut BNSimilaritySessionResolverType;
    type Context = ();
    type Wrapped<'a> = CoreSimilaritySessionResolverType;
}

unsafe impl CoreArrayProviderInner for CoreSimilaritySessionResolverType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeSimilaritySessionResolverTypeList(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CoreSimilaritySessionResolverType::from_raw(*raw)
    }
}

/// A core-backed similarity session resolver.
pub struct CoreSimilaritySessionResolver {
    pub(crate) handle: *mut BNSimilaritySessionResolver,
}

impl CoreSimilaritySessionResolver {
    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionResolver) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionResolver) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Wraps a custom resolver for `session`.
    pub fn create<C: SimilaritySessionResolver>(
        ty: &CoreSimilaritySessionResolverType,
        session: &SimilaritySession,
        resolver: C,
    ) -> Ref<CoreSimilaritySessionResolver> {
        let resolver = Box::into_raw(Box::new(resolver));
        let mut callbacks = BNCustomSimilaritySessionResolver {
            context: resolver.cast(),
            externalRefTaken: None,
            externalRefReleased: None,
            updateSettings: Some(cb_update_resolver_settings::<C>),
            prepareForNode: Some(cb_prepare_for_node::<C>),
            resolveForNode: Some(cb_resolve_for_node::<C>),
            free: Some(cb_resolver_free::<C>),
        };
        let raw_resolver = unsafe {
            BNCreateCustomSimilaritySessionResolver(ty.handle, session.handle, &mut callbacks)
        };
        unsafe { CoreSimilaritySessionResolver::ref_from_raw(raw_resolver) }
    }

    /// Returns the resolver's ID.
    pub fn id(&self) -> SimilaritySessionResolverId {
        unsafe { BNSimilaritySessionResolverGetId(self.handle) }.into()
    }

    /// Returns the registered type that created this resolver.
    pub fn resolver_type(&self) -> CoreSimilaritySessionResolverType {
        let handle = unsafe { BNSimilaritySessionResolverGetType(self.handle) };
        unsafe { CoreSimilaritySessionResolverType::from_raw(handle) }
    }
}

impl SimilaritySessionResolver for CoreSimilaritySessionResolver {
    fn prepare_for_node(
        &self,
        session: &SimilaritySession,
        node: &SimilaritySessionNode,
        completion: &SimilaritySessionCompletion,
        _resolver_id: SimilaritySessionResolverId,
    ) {
        unsafe {
            BNSimilaritySessionResolverPrepareForNode(
                self.handle,
                session.handle,
                node.handle,
                completion.handle,
            )
        }
    }

    fn resolve_for_node(
        &self,
        session: &SimilaritySession,
        node: &SimilaritySessionNode,
        entities: &[SimilarityEntityId],
        completion: &SimilaritySessionCompletion,
        _resolver_id: SimilaritySessionResolverId,
    ) {
        let raw_entities: Vec<BNSimilarityEntityId> =
            entities.iter().copied().map(Into::into).collect();
        unsafe {
            BNSimilaritySessionResolverResolveForNode(
                self.handle,
                session.handle,
                node.handle,
                raw_entities.as_ptr(),
                raw_entities.len(),
                completion.handle,
            )
        }
    }
}

unsafe impl Send for CoreSimilaritySessionResolver {}
unsafe impl Sync for CoreSimilaritySessionResolver {}

impl ToOwned for CoreSimilaritySessionResolver {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreSimilaritySessionResolver {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionResolverReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionResolver(handle.handle);
    }
}

impl CoreArrayProvider for CoreSimilaritySessionResolver {
    type Raw = *mut BNSimilaritySessionResolver;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for CoreSimilaritySessionResolver {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSimilaritySessionResolverList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

unsafe extern "C" fn cb_create_resolver<C: SimilaritySessionResolverType>(
    ctxt: *mut c_void,
    session: *mut BNSimilaritySession,
    settings: *mut BNSettings,
) -> *mut BNSimilaritySessionResolver {
    ffi_wrap!("SimilaritySessionResolverType::create_resolver", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let session = SimilaritySession::from_raw(session);
        let settings = Settings::from_raw(settings);
        let resolver = ctxt.create_resolver(&session, &settings);
        let core_type = CoreSimilaritySessionResolverType::by_name(C::NAME).unwrap();
        let core_resolver = CoreSimilaritySessionResolver::create(&core_type, &session, resolver);
        Ref::into_raw(core_resolver).handle
    })
}

unsafe extern "C" fn cb_resolver_default_settings<C: SimilaritySessionResolverType>(
    ctxt: *mut c_void,
) -> *mut BNSettings {
    ffi_wrap!("SimilaritySessionResolverType::default_settings", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        ctxt.default_settings()
            .map(|settings| Ref::into_raw(settings).handle)
            .unwrap_or(std::ptr::null_mut())
    })
}

unsafe extern "C" fn cb_update_resolver_settings<C: SimilaritySessionResolver>(
    ctxt: *mut c_void,
    settings: *mut BNSettings,
) -> bool {
    ffi_wrap!("SimilaritySessionResolver::update_settings", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let settings = Settings::from_raw(settings);
        ctxt.update_settings(&settings)
    })
}

unsafe extern "C" fn cb_resolve_for_node<C: SimilaritySessionResolver>(
    ctxt: *mut c_void,
    session: *mut BNSimilaritySession,
    node: *mut BNSimilaritySessionNode,
    entities: *const BNSimilarityEntityId,
    entity_count: usize,
    completion: *mut BNSimilaritySessionCompletion,
    resolver_id: BNSimilaritySessionResolverId,
) {
    ffi_wrap!("SimilaritySessionResolver::resolve_for_node", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let session = SimilaritySession::from_raw(session);
        let node = SimilaritySessionNode::from_raw(node);
        let entity_slice = crate::ffi::slice_from_raw_parts(entities, entity_count);
        let mapped_entities: Vec<SimilarityEntityId> =
            entity_slice.iter().copied().map(Into::into).collect();
        let completion = SimilaritySessionCompletion::from_raw(completion);
        ctxt.resolve_for_node(
            &session,
            &node,
            &mapped_entities,
            &completion,
            resolver_id.into(),
        );
    })
}

unsafe extern "C" fn cb_prepare_for_node<C: SimilaritySessionResolver>(
    ctxt: *mut c_void,
    session: *mut BNSimilaritySession,
    node: *mut BNSimilaritySessionNode,
    completion: *mut BNSimilaritySessionCompletion,
    resolver_id: BNSimilaritySessionResolverId,
) {
    ffi_wrap!("SimilaritySessionResolver::prepare_for_node", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let session = SimilaritySession::from_raw(session);
        let node = SimilaritySessionNode::from_raw(node);
        let completion = SimilaritySessionCompletion::from_raw(completion);
        ctxt.prepare_for_node(&session, &node, &completion, resolver_id.into());
    })
}

unsafe extern "C" fn cb_resolver_free<C: SimilaritySessionResolver>(ctxt: *mut c_void) {
    ffi_wrap!("SimilaritySessionResolver::free", unsafe {
        let _ = Box::from_raw(ctxt as *mut C);
    })
}

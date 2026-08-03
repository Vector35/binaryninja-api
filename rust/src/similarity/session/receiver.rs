use super::SimilaritySessionCompletion;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::similarity::node::SimilaritySessionNode;
use crate::similarity::provider::CoreSimilarityProvider;
use crate::similarity::SimilarityEntityId;
use binaryninjacore_sys::*;
use std::ffi::c_void;

/// Receives start and update notifications from a similarity session.
pub trait SimilaritySessionReceiver: Send + Sync + 'static {
    /// Called when a session run starts.
    ///
    /// This is mainly used to get the completion state for the run.
    fn on_started(&self, _completion: &SimilaritySessionCompletion) {}

    /// Called when a provider's results, resolution state, or applied metadata changes.
    fn on_updated(
        &self,
        node: &SimilaritySessionNode,
        provider: &CoreSimilarityProvider,
        entities: &[SimilarityEntityId],
    );
}

/// A core-backed similarity session receiver.
pub struct CoreSimilaritySessionReceiver {
    pub(crate) handle: *mut BNSimilaritySessionReceiver,
}

impl CoreSimilaritySessionReceiver {
    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionReceiver) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionReceiver) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Wraps a custom session receiver in a core receiver.
    pub fn create<C: SimilaritySessionReceiver>(receiver: C) -> Ref<CoreSimilaritySessionReceiver> {
        let receiver = Box::into_raw(Box::new(receiver));
        let mut callbacks = BNCustomSimilaritySessionReceiver {
            context: receiver.cast(),
            externalRefTaken: None,
            externalRefReleased: None,
            onStarted: Some(cb_on_started::<C>),
            onUpdated: Some(cb_on_updated::<C>),
            free: Some(cb_receiver_free::<C>),
        };
        let raw_receiver = unsafe { BNCreateCustomSimilaritySessionReceiver(&mut callbacks) };
        unsafe { CoreSimilaritySessionReceiver::ref_from_raw(raw_receiver) }
    }
}

impl SimilaritySessionReceiver for CoreSimilaritySessionReceiver {
    fn on_started(&self, completion: &SimilaritySessionCompletion) {
        unsafe { BNSimilaritySessionReceiverNotifyStart(self.handle, completion.handle) }
    }

    fn on_updated(
        &self,
        node: &SimilaritySessionNode,
        provider: &CoreSimilarityProvider,
        entities: &[SimilarityEntityId],
    ) {
        let raw_entities: Vec<BNSimilarityEntityId> =
            entities.iter().copied().map(Into::into).collect();
        unsafe {
            BNSimilaritySessionReceiverNotifyBatch(
                self.handle,
                node.handle,
                provider.handle,
                raw_entities.as_ptr(),
                raw_entities.len(),
            )
        }
    }
}

unsafe impl Send for CoreSimilaritySessionReceiver {}
unsafe impl Sync for CoreSimilaritySessionReceiver {}

impl ToOwned for CoreSimilaritySessionReceiver {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreSimilaritySessionReceiver {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionReceiverReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionReceiver(handle.handle);
    }
}

impl CoreArrayProvider for CoreSimilaritySessionReceiver {
    type Raw = *mut BNSimilaritySessionReceiver;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for CoreSimilaritySessionReceiver {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSimilaritySessionReceiverList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

unsafe extern "C" fn cb_on_updated<C: SimilaritySessionReceiver>(
    ctxt: *mut c_void,
    node: *mut BNSimilaritySessionNode,
    provider: *mut BNSimilarityProvider,
    entities: *const BNSimilarityEntityId,
    count: usize,
) {
    ffi_wrap!("SimilaritySessionReceiver::on_updated", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let node = SimilaritySessionNode::from_raw(node);
        let provider = CoreSimilarityProvider { handle: provider };
        let entity_slice = crate::ffi::slice_from_raw_parts(entities, count);
        let mapped_entities: Vec<SimilarityEntityId> =
            entity_slice.iter().copied().map(Into::into).collect();
        ctxt.on_updated(&node, &provider, &mapped_entities);
    })
}

unsafe extern "C" fn cb_on_started<C: SimilaritySessionReceiver>(
    ctxt: *mut c_void,
    completion: *mut BNSimilaritySessionCompletion,
) {
    ffi_wrap!("SimilaritySessionReceiver::on_started", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        let completion = SimilaritySessionCompletion::from_raw(completion);
        ctxt.on_started(&completion);
    })
}

unsafe extern "C" fn cb_receiver_free<C: SimilaritySessionReceiver>(ctxt: *mut c_void) {
    ffi_wrap!("SimilaritySessionReceiver::free", unsafe {
        let _ = Box::from_raw(ctxt as *mut C);
    })
}

use crate::disassembly::InstructionTextToken;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::BnString;
use binaryninjacore_sys::{
    BNFreeUndoAction, BNFreeUndoActionList, BNFreeUndoEntry, BNFreeUndoEntryList,
    BNNewUndoActionReference, BNNewUndoEntryReference, BNUndoAction, BNUndoActionGetSummary,
    BNUndoActionGetSummaryText, BNUndoEntry, BNUndoEntryGetActions, BNUndoEntryGetId,
    BNUndoEntryGetTimestamp,
};
use std::fmt::Debug;
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[repr(transparent)]
pub struct UndoEntry {
    handle: NonNull<BNUndoEntry>,
}

impl UndoEntry {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNUndoEntry>) -> Self {
        Self { handle }
    }

    #[allow(dead_code)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNUndoEntry>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn id(&self) -> BnString {
        let result = unsafe { BNUndoEntryGetId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn actions(&self) -> Array<UndoAction> {
        let mut count = 0;
        let result = unsafe { BNUndoEntryGetActions(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn time(&self) -> SystemTime {
        let m = Duration::from_secs(unsafe { BNUndoEntryGetTimestamp(self.handle.as_ptr()) });
        UNIX_EPOCH + m
    }
}

impl Debug for UndoEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndoEntry")
            .field("id", &self.id())
            .field("time", &self.time())
            .field("actions", &self.actions().to_vec())
            .finish()
    }
}

impl ToOwned for UndoEntry {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for UndoEntry {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewUndoEntryReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeUndoEntry(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for UndoEntry {
    type Raw = *mut BNUndoEntry;
    type Context = ();
    type Wrapped<'a> = Guard<'a, UndoEntry>;
}

unsafe impl CoreArrayProviderInner for UndoEntry {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUndoEntryList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

#[repr(transparent)]
pub struct UndoAction {
    handle: NonNull<BNUndoAction>,
}

impl UndoAction {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNUndoAction>) -> Self {
        Self { handle }
    }

    #[allow(dead_code)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNUndoAction>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn summary(&self) -> Array<InstructionTextToken> {
        let mut count = 0;
        let result = unsafe { BNUndoActionGetSummary(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Gets the [`UndoAction`] summary as text rather than [`InstructionTextToken`]'s.
    pub fn summary_as_string(&self) -> BnString {
        let result = unsafe { BNUndoActionGetSummaryText(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }
}

impl Debug for UndoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndoAction")
            .field("summary", &self.summary_as_string())
            .finish()
    }
}

impl ToOwned for UndoAction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for UndoAction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewUndoActionReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeUndoAction(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for UndoAction {
    type Raw = *mut BNUndoAction;
    type Context = ();
    type Wrapped<'a> = Guard<'a, UndoAction>;
}

unsafe impl CoreArrayProviderInner for UndoAction {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUndoActionList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

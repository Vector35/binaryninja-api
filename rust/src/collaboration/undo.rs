use crate::collaboration::{Remote, RemoteFile, RemoteProject, RemoteSnapshot};
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::BnString;
use binaryninjacore_sys::{
    BNCollaborationFreeIdList, BNCollaborationUndoEntry, BNCollaborationUndoEntryGetData,
    BNCollaborationUndoEntryGetFile, BNCollaborationUndoEntryGetId,
    BNCollaborationUndoEntryGetParent, BNCollaborationUndoEntryGetParentId,
    BNCollaborationUndoEntryGetProject, BNCollaborationUndoEntryGetRemote,
    BNCollaborationUndoEntryGetSnapshot, BNCollaborationUndoEntryGetUrl,
    BNFreeCollaborationUndoEntry, BNFreeCollaborationUndoEntryList,
    BNNewCollaborationUndoEntryReference,
};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ptr::NonNull;

#[repr(transparent)]
pub struct RemoteUndoEntry {
    handle: NonNull<BNCollaborationUndoEntry>,
}

impl RemoteUndoEntry {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationUndoEntry>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationUndoEntry>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Owning Snapshot
    pub fn snapshot(&self) -> Result<Ref<RemoteSnapshot>, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetSnapshot(self.handle.as_ptr()) };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteSnapshot::ref_from_raw(handle) })
    }

    /// Owning File
    pub fn file(&self) -> Result<Ref<RemoteFile>, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetFile(self.handle.as_ptr()) };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteFile::ref_from_raw(handle) })
    }

    /// Owning Project
    pub fn project(&self) -> Result<Ref<RemoteProject>, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetProject(self.handle.as_ptr()) };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteProject::ref_from_raw(handle) })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetRemote(self.handle.as_ptr()) };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { Remote::ref_from_raw(handle) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationUndoEntryGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> RemoteUndoEntryId {
        RemoteUndoEntryId(unsafe { BNCollaborationUndoEntryGetId(self.handle.as_ptr()) })
    }

    /// Id of parent undo entry
    pub fn parent_id(&self) -> Option<RemoteUndoEntryId> {
        let mut value = 0;
        let success =
            unsafe { BNCollaborationUndoEntryGetParentId(self.handle.as_ptr(), &mut value) };
        success.then_some(RemoteUndoEntryId(value))
    }

    /// Undo entry contents data
    pub fn data(&self) -> Result<BnString, ()> {
        let mut value = std::ptr::null_mut();
        let success = unsafe { BNCollaborationUndoEntryGetData(self.handle.as_ptr(), &mut value) };
        if !success {
            return Err(());
        }
        assert!(!value.is_null());
        Ok(unsafe { BnString::from_raw(value) })
    }

    /// Parent Undo Entry object
    pub fn parent(&self) -> Option<Ref<RemoteUndoEntry>> {
        let value = unsafe { BNCollaborationUndoEntryGetParent(self.handle.as_ptr()) };
        NonNull::new(value).map(|handle| unsafe { RemoteUndoEntry::ref_from_raw(handle) })
    }
}

impl PartialEq for RemoteUndoEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteUndoEntry {}

impl ToOwned for RemoteUndoEntry {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteUndoEntry {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationUndoEntryReference(handle.handle.as_ptr()))
                .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationUndoEntry(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteUndoEntry {
    type Raw = *mut BNCollaborationUndoEntry;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteUndoEntry {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationUndoEntryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteUndoEntryId(pub u64);

impl Display for RemoteUndoEntryId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl CoreArrayProvider for RemoteUndoEntryId {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = RemoteUndoEntryId;
}

unsafe impl CoreArrayProviderInner for RemoteUndoEntryId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNCollaborationFreeIdList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        RemoteUndoEntryId(*raw)
    }
}

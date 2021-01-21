use binaryninjacore_sys::{BNFileMetadata,
                          BNCreateFileMetadata,
                          BNNewFileReference,
                          BNFreeFileMetadata,
                          BNCloseFile,
                          //BNSetFileMetadataNavigationHandler,
                          BNIsFileModified,
                          BNIsAnalysisChanged,
                          BNMarkFileModified,
                          BNMarkFileSaved,
                          BNIsBackedByDatabase,
                          BNGetFilename,
                          BNSetFilename,
                          BNBeginUndoActions,
                          BNCommitUndoActions,
                          BNUndo,
                          BNRedo,
                          BNGetCurrentView,
                          BNGetCurrentOffset,
                          BNNavigate,
                          BNGetFileViewOfType};

use crate::binaryview::BinaryView;

use crate::rc::*;
use crate::string::*;

#[derive(PartialEq, Eq, Hash)]
pub struct FileMetadata {
    pub(crate) handle: *mut BNFileMetadata,
}

unsafe impl Send for FileMetadata {}
unsafe impl Sync for FileMetadata {}

impl FileMetadata {
    pub(crate) fn from_raw(handle: *mut BNFileMetadata) -> Self {
        Self { handle }
    }

    pub fn new() -> Ref<Self> {
        unsafe { 
            Ref::new(
                Self {
                    handle: BNCreateFileMetadata(),
                }
            )
        }
    }

    pub fn with_filename<S: BnStrCompatible>(name: S) -> Ref<Self> {
        let ret = FileMetadata::new();
        ret.set_filename(name);
        ret
    }

    pub fn close(&self) {
        unsafe { BNCloseFile(self.handle); }
    }

    pub fn filename(&self) -> BnString {
        unsafe {
            let raw = BNGetFilename(self.handle);
            BnString::from_raw(raw)
        }
    }

    pub fn set_filename<S: BnStrCompatible>(&self, name: S) {
        let name = name.as_bytes_with_nul();

        unsafe { BNSetFilename(self.handle, name.as_ref().as_ptr() as *mut _); }
    }

    pub fn is_modified(&self) -> bool {
        unsafe { BNIsFileModified(self.handle) }
    }

    pub fn mark_modified(&self) {
        unsafe { BNMarkFileModified(self.handle); }
    }

    pub fn is_analysis_changed(&self) -> bool {
        unsafe { BNIsAnalysisChanged(self.handle) }
    }

    pub fn mark_saved(&self) {
        unsafe { BNMarkFileSaved(self.handle); }
    }

    pub fn is_database_backed(&self) -> bool {
        unsafe { BNIsBackedByDatabase(self.handle) }
    }

    pub fn begin_undo_actions(&self) {
        unsafe { BNBeginUndoActions(self.handle); }
    }

    pub fn commit_undo_actions(&self) {
        unsafe { BNCommitUndoActions(self.handle); }
    }

    pub fn undo(&self) {
        unsafe { BNUndo(self.handle); }
    }

    pub fn redo(&self) {
        unsafe { BNRedo(self.handle); }
    }

    pub fn current_view(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetCurrentView(self.handle))
        }
    }

    pub fn current_offset(&self) -> u64 {
        unsafe { BNGetCurrentOffset(self.handle) }
    }

    pub fn navigate_to<S: BnStrCompatible>(&self, view: S, offset: u64) -> Result<(), ()> {
        let view = view.as_bytes_with_nul();

        unsafe {
            if BNNavigate(self.handle, view.as_ref().as_ptr() as *const _, offset) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    pub fn get_view_of_type<S: BnStrCompatible>(&self, view: S) -> Result<Ref<BinaryView>, ()> {
        let view = view.as_bytes_with_nul();

        unsafe {
            let res = BNGetFileViewOfType(self.handle, view.as_ref().as_ptr() as *const _);

            if res.is_null() {
                Err(())
            } else {
                Ok(Ref::new(BinaryView::from_raw(res)))
            }
        }
    }
}

impl ToOwned for FileMetadata {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for FileMetadata {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFileReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFileMetadata(handle.handle);
    }
}


/*
BNCreateDatabase,
BNCreateDatabaseWithProgress,
BNOpenExistingDatabase,
BNOpenExistingDatabaseWithProgress,
*/


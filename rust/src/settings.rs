use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNSettingsScope as SettingsScope;

use crate::rc::*;

#[derive(PartialEq, Eq, Hash)]
pub struct Settings {
    pub(crate) handle: *mut BNSettings,
}

unsafe impl Send for Settings {}
unsafe impl Sync for Settings {}

impl Settings {
    pub(crate) unsafe fn from_raw(handle: *mut BNSettings) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }
}

impl AsRef<Settings> for Settings {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for Settings {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Settings {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSettingsReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSettings(handle.handle);
    }
}



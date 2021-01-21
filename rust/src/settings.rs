// Copyright 2021 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

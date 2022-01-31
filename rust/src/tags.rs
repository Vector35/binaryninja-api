use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;

use crate::rc::*;
use crate::string::*;

pub struct Tag {
    pub(crate) handle: *mut BNTag,
}

impl Tag {
    pub(crate) unsafe fn from_raw(handle: *mut BNTag) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn new<S: BnStrCompatible>(t: &TagType, data: S) -> Ref<Self> {
        let data = data.as_bytes_with_nul();
        unsafe { Self::from_raw(BNCreateTag(t.handle, data.as_ref().as_ptr() as *mut _)) }
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetId(self.handle)) }
    }

    pub fn data(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetData(self.handle)) }
    }

    pub fn t(&self) -> Ref<TagType> {
        unsafe { TagType::from_raw(BNTagGetType(self.handle)) }
    }

    pub fn set_data<S: BnStrCompatible>(&self, data: S) {
        let data = data.as_bytes_with_nul();
        unsafe {
            BNTagSetData(self.handle, data.as_ref().as_ptr() as *mut _);
        }
    }
}

unsafe impl RefCountable for Tag {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTagReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTag(handle.handle);
    }
}

impl AsRef<Tag> for Tag {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for Tag {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for Tag {}
unsafe impl Sync for Tag {}

pub type TagTypeType = BNTagTypeType;

pub struct TagType {
    pub(crate) handle: *mut BNTagType,
}

impl TagType {
    pub(crate) unsafe fn from_raw(handle: *mut BNTagType) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub(crate) fn create(view: &BinaryView) -> Ref<Self> {
        unsafe { Self::from_raw(BNCreateTagType(view.handle)) }
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetId(self.handle)) }
    }

    pub fn icon(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetIcon(self.handle)) }
    }

    pub fn set_icon<S: BnStrCompatible>(&self, icon: S) {
        let icon = icon.as_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, icon.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetName(self.handle)) }
    }

    pub fn set_name<S: BnStrCompatible>(&self, name: S) {
        let name = name.as_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, name.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn visible(&self) -> bool {
        unsafe { BNTagTypeGetVisible(self.handle) }
    }

    pub fn set_visible(&self, visible: bool) {
        unsafe { BNTagTypeSetVisible(self.handle, visible) }
    }

    pub fn t(&self) -> TagTypeType {
        unsafe { BNTagTypeGetType(self.handle) }
    }

    pub fn set_type<S: BnStrCompatible>(&self, t: S) {
        let t = t.as_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, t.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn view(&self) -> Ref<BinaryView> {
        unsafe { BinaryView::from_raw(BNTagTypeGetView(self.handle)) }
    }
}

unsafe impl RefCountable for TagType {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTagTypeReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTagType(handle.handle);
    }
}

impl AsRef<TagType> for TagType {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for TagType {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for TagType {}
unsafe impl Sync for TagType {}

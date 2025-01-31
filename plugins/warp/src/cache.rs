pub mod container;
pub mod function;
pub mod guid;
pub mod type_reference;

pub use function::*;
pub use guid::*;
pub use type_reference::*;

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::rc::Guard;
use binaryninja::rc::Ref as BNRef;
use binaryninja::ObjectDestructor;
use std::hash::{DefaultHasher, Hash, Hasher};

pub fn register_cache_destructor() {
    pub static mut CACHE_DESTRUCTOR: CacheDestructor = CacheDestructor;
    #[allow(static_mut_refs)]
    // SAFETY: This can be done as the backing data is an opaque ZST.
    unsafe {
        CACHE_DESTRUCTOR.register()
    };
}

/// A unique view ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewID(u64);

impl From<&BinaryView> for ViewID {
    fn from(value: &BinaryView) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write_u64(value.original_image_base());
        hasher.write_usize(value.file().session_id());
        Self(hasher.finish())
    }
}

impl From<BNRef<BinaryView>> for ViewID {
    fn from(value: BNRef<BinaryView>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, BinaryView>> for ViewID {
    fn from(value: Guard<'_, BinaryView>) -> Self {
        Self::from(value.as_ref())
    }
}

/// A unique function ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionID(u64);

impl From<&BNFunction> for FunctionID {
    fn from(value: &BNFunction) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write_u64(value.start());
        hasher.write_u64(value.lowest_address());
        hasher.write_u64(value.highest_address());
        Self(hasher.finish())
    }
}

impl From<BNRef<BNFunction>> for FunctionID {
    fn from(value: BNRef<BNFunction>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, BNFunction>> for FunctionID {
    fn from(value: Guard<'_, BNFunction>) -> Self {
        Self::from(value.as_ref())
    }
}

pub struct CacheDestructor;

impl ObjectDestructor for CacheDestructor {
    fn destruct_view(&self, view: &BinaryView) {
        clear_type_ref_cache(view);
        log::debug!("Removed WARP caches for {:?}", view.file().filename());
    }
}

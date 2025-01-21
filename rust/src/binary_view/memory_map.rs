use crate::binary_view::BinaryView;
use crate::data_buffer::DataBuffer;
use crate::file_accessor::FileAccessor;
use crate::rc::Ref;
use crate::segment::SegmentFlags;
use crate::string::{AsCStr, BnString};
use binaryninjacore_sys::*;

#[derive(PartialEq, Eq, Hash)]
pub struct MemoryMap {
    view: Ref<BinaryView>,
}

impl MemoryMap {
    pub fn new(view: Ref<BinaryView>) -> Self {
        Self { view }
    }

    // TODO: There does not seem to be a way to enumerate memory regions.

    /// JSON string representation of the base [`MemoryMap`], consisting of unresolved auto and user segments.
    pub fn base_description(&self) -> String {
        let desc_raw = unsafe { BNGetBaseMemoryMapDescription(self.view.handle) };
        unsafe { BnString::from_raw(desc_raw) }.to_string()
    }

    /// JSON string representation of the [`MemoryMap`].
    pub fn description(&self) -> String {
        let desc_raw = unsafe { BNGetMemoryMapDescription(self.view.handle) };
        unsafe { BnString::from_raw(desc_raw) }.to_string()
    }

    // When enabled, the memory map will present a simplified, logical view that merges and abstracts virtual memory
    // regions based on criteria such as contiguity and flag consistency. This view is designed to provide a higher-level
    // representation for user analysis, hiding underlying mapping details.
    //
    // When disabled, the memory map will revert to displaying the virtual view, which corresponds directly to the individual
    // segments mapped from the raw file without any merging or abstraction.
    pub fn set_logical_enabled(&mut self, enabled: bool) {
        unsafe { BNSetLogicalMemoryMapEnabled(self.view.handle, enabled) };
    }

    pub fn add_binary_memory_region(
        &mut self,
        name: impl AsCStr,
        start: u64,
        view: &BinaryView,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        unsafe {
            BNAddBinaryMemoryRegion(
                self.view.handle,
                name.as_cstr().as_ptr(),
                start,
                view.handle,
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    pub fn add_data_memory_region(
        &mut self,
        name: impl AsCStr,
        start: u64,
        data: &DataBuffer,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        unsafe {
            BNAddDataMemoryRegion(
                self.view.handle,
                name.as_cstr().as_ptr(),
                start,
                data.as_raw(),
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    pub fn add_remote_memory_region(
        &mut self,
        name: impl AsCStr,
        start: u64,
        accessor: &mut FileAccessor,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        unsafe {
            BNAddRemoteMemoryRegion(
                self.view.handle,
                name.as_cstr().as_ptr(),
                start,
                &mut accessor.api_object,
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    pub fn remove_memory_region(&mut self, name: impl AsCStr) -> bool {
        unsafe { BNRemoveMemoryRegion(self.view.handle, name.as_cstr().as_ptr()) }
    }

    pub fn active_memory_region_at(&self, addr: u64) -> BnString {
        unsafe {
            let name_raw = BNGetActiveMemoryRegionAt(self.view.handle, addr);
            BnString::from_raw(name_raw)
        }
    }

    pub fn memory_region_flags(&self, name: impl AsCStr) -> SegmentFlags {
        let flags_raw =
            unsafe { BNGetMemoryRegionFlags(self.view.handle, name.as_cstr().as_ptr()) };
        SegmentFlags::from_raw(flags_raw)
    }

    pub fn set_memory_region_flags(&mut self, name: impl AsCStr, flags: SegmentFlags) -> bool {
        unsafe {
            BNSetMemoryRegionFlags(self.view.handle, name.as_cstr().as_ptr(), flags.into_raw())
        }
    }

    pub fn is_memory_region_enabled(&self, name: impl AsCStr) -> bool {
        unsafe { BNIsMemoryRegionEnabled(self.view.handle, name.as_cstr().as_ptr()) }
    }

    pub fn set_memory_region_enabled(&mut self, name: impl AsCStr, enabled: bool) -> bool {
        unsafe { BNSetMemoryRegionEnabled(self.view.handle, name.as_cstr().as_ptr(), enabled) }
    }

    // TODO: Should we just call this is_memory_region_relocatable?
    pub fn is_memory_region_rebaseable(&self, name: impl AsCStr) -> bool {
        unsafe { BNIsMemoryRegionRebaseable(self.view.handle, name.as_cstr().as_ptr()) }
    }

    pub fn set_memory_region_rebaseable(&mut self, name: impl AsCStr, enabled: bool) -> bool {
        unsafe { BNSetMemoryRegionRebaseable(self.view.handle, name.as_cstr().as_ptr(), enabled) }
    }

    pub fn memory_region_fill(&self, name: impl AsCStr) -> u8 {
        unsafe { BNGetMemoryRegionFill(self.view.handle, name.as_cstr().as_ptr()) }
    }

    pub fn set_memory_region_fill(&mut self, name: impl AsCStr, fill: u8) -> bool {
        unsafe { BNSetMemoryRegionFill(self.view.handle, name.as_cstr().as_ptr(), fill) }
    }

    pub fn reset(&mut self) {
        unsafe { BNResetMemoryMap(self.view.handle) }
    }
}

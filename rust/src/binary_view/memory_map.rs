use crate::binary_view::BinaryView;
use crate::data_buffer::DataBuffer;
use crate::file_accessor::{Accessor, FileAccessor};
use crate::rc::Ref;
use crate::segment::SegmentFlags;
use crate::string::{BnString, IntoCStr};
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
        unsafe { BnString::into_string(desc_raw) }
    }

    /// JSON string representation of the [`MemoryMap`].
    pub fn description(&self) -> String {
        let desc_raw = unsafe { BNGetMemoryMapDescription(self.view.handle) };
        unsafe { BnString::into_string(desc_raw) }
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

    /// Whether the memory map is activated for the associated view.
    pub fn is_activated(&self) -> bool {
        unsafe { BNIsMemoryMapActivated(self.view.handle) }
    }

    pub fn add_binary_memory_region(
        &mut self,
        name: &str,
        start: u64,
        view: &BinaryView,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        let name_raw = name.to_cstr();
        unsafe {
            BNAddBinaryMemoryRegion(
                self.view.handle,
                name_raw.as_ptr(),
                start,
                view.handle,
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    /// Adds the memory region using a [`DataBuffer`].
    ///
    /// This will add the contents of the [`DataBuffer`] to the database.
    pub fn add_data_memory_region(
        &mut self,
        name: &str,
        start: u64,
        data: &DataBuffer,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        let name_raw = name.to_cstr();
        unsafe {
            BNAddDataMemoryRegion(
                self.view.handle,
                name_raw.as_ptr(),
                start,
                data.as_raw(),
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    // TODO: This really cant be safe until BNFileAccessor is ARC'd and can be freed. Probably need another thing
    // TODO: Ontop of a file accessor in the core that would manage it. (I.e. BNFileAccessorHandle) or something.
    /// Adds the memory region using a [`FileAccessor`].
    ///
    /// This does not add the region contents to the database, instead accesses to the contents
    /// are done "remotely" to a [`FileAccessor`].
    ///
    /// NOTE: The [`FileAccessor`] MUST live as long as the region is available, currently there is no gurentee by
    /// the type checker that the file accessor is tied to that of the memory region.
    pub fn add_remote_memory_region<A: Accessor>(
        &mut self,
        name: &str,
        start: u64,
        accessor: &mut FileAccessor<A>,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        let name_raw = name.to_cstr();
        unsafe {
            BNAddRemoteMemoryRegion(
                self.view.handle,
                name_raw.as_ptr(),
                start,
                &mut accessor.raw,
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    pub fn remove_memory_region(&mut self, name: &str) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNRemoveMemoryRegion(self.view.handle, name_raw.as_ptr()) }
    }

    pub fn active_memory_region_at(&self, addr: u64) -> String {
        unsafe {
            let name_raw = BNGetActiveMemoryRegionAt(self.view.handle, addr);
            BnString::into_string(name_raw)
        }
    }

    pub fn memory_region_flags(&self, name: &str) -> SegmentFlags {
        let name_raw = name.to_cstr();
        let flags_raw = unsafe { BNGetMemoryRegionFlags(self.view.handle, name_raw.as_ptr()) };
        SegmentFlags::from_raw(flags_raw)
    }

    pub fn set_memory_region_flags(&mut self, name: &str, flags: SegmentFlags) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNSetMemoryRegionFlags(self.view.handle, name_raw.as_ptr(), flags.into_raw()) }
    }

    pub fn is_memory_region_enabled(&self, name: &str) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNIsMemoryRegionEnabled(self.view.handle, name_raw.as_ptr()) }
    }

    pub fn set_memory_region_enabled(&mut self, name: &str, enabled: bool) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNSetMemoryRegionEnabled(self.view.handle, name_raw.as_ptr(), enabled) }
    }

    // TODO: Should we just call this is_memory_region_relocatable?
    pub fn is_memory_region_rebaseable(&self, name: &str) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNIsMemoryRegionRebaseable(self.view.handle, name_raw.as_ptr()) }
    }

    pub fn set_memory_region_rebaseable(&mut self, name: &str, enabled: bool) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNSetMemoryRegionRebaseable(self.view.handle, name_raw.as_ptr(), enabled) }
    }

    pub fn memory_region_fill(&self, name: &str) -> u8 {
        let name_raw = name.to_cstr();
        unsafe { BNGetMemoryRegionFill(self.view.handle, name_raw.as_ptr()) }
    }

    pub fn set_memory_region_fill(&mut self, name: &str, fill: u8) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNSetMemoryRegionFill(self.view.handle, name_raw.as_ptr(), fill) }
    }

    pub fn reset(&mut self) {
        unsafe { BNResetMemoryMap(self.view.handle) }
    }
}

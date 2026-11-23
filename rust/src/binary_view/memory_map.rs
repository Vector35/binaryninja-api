use crate::binary_view::BinaryView;
use crate::data_buffer::DataBuffer;
use crate::file_accessor::{Accessor, FileAccessor};
use crate::rc::Ref;
use crate::segment::SegmentFlags;
use crate::string::{raw_to_string, BnString, IntoCStr};
use binaryninjacore_sys::*;

/// Classification of a memory region by its backing (display/diagnostic only).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MemoryRegionKind {
    /// Projection of an auto/user segment (the loaded image).
    LoadSegment,
    /// Maps a range of the parent file.
    Mapped,
    /// Backed by an in-memory data buffer.
    Data,
    /// No backing; reads return the fill byte.
    Unbacked,
    /// Backed by an external FileAccessor or foreign BinaryView (ephemeral).
    Remote,
    /// Backed by another MemoryMap (logical view).
    Logical,
}

impl From<BNMemoryRegionKind> for MemoryRegionKind {
    fn from(kind: BNMemoryRegionKind) -> Self {
        use BNMemoryRegionKind::*;
        match kind {
            LoadSegmentMemoryRegion => Self::LoadSegment,
            MappedMemoryRegion => Self::Mapped,
            DataMemoryRegion => Self::Data,
            UnbackedMemoryRegion => Self::Unbacked,
            RemoteMemoryRegion => Self::Remote,
            LogicalMemoryRegion => Self::Logical,
        }
    }
}

/// Snapshot of a memory region's properties at the time of query.
///
/// This is a value type — modifying the memory map will not update existing
/// `MemoryRegionInfo` instances. To mutate a region, use the corresponding
/// [`MemoryMap`] methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryRegionInfo {
    pub name: String,
    pub display_name: String,
    pub start: u64,
    pub length: u64,
    pub flags: SegmentFlags,
    pub enabled: bool,
    pub rebaseable: bool,
    pub fill: u8,
    pub has_target: bool,
    pub absolute_address_mode: bool,
    pub local: bool,
    pub data_offset: u64,
    pub kind: MemoryRegionKind,
}

impl MemoryRegionInfo {
    pub fn end(&self) -> u64 {
        self.start + self.length
    }

    fn from_raw(region: &BNMemoryRegionInfo) -> Self {
        Self {
            name: raw_to_string(region.name).unwrap_or_default(),
            display_name: raw_to_string(region.displayName).unwrap_or_default(),
            start: region.start,
            length: region.length,
            flags: SegmentFlags::from_raw(region.flags),
            enabled: region.enabled,
            rebaseable: region.rebaseable,
            fill: region.fill,
            has_target: region.hasTarget,
            absolute_address_mode: region.absoluteAddressMode,
            local: region.local,
            data_offset: region.dataOffset,
            kind: region.kind.into(),
        }
    }
}

/// A resolved, non-overlapping address range in the memory map.
///
/// Each range contains an ordered list of memory regions that overlap at this
/// interval. The first region is the active (highest priority) one.
///
/// This is a snapshot value — it is not updated by later mutations to the
/// memory map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedRange {
    pub start: u64,
    pub length: u64,
    pub regions: Vec<MemoryRegionInfo>,
}

impl ResolvedRange {
    pub fn end(&self) -> u64 {
        self.start + self.length
    }

    /// The highest-priority region at this range.
    pub fn active_region(&self) -> Option<&MemoryRegionInfo> {
        self.regions.first()
    }

    /// Name of the active region, or `None` if empty.
    pub fn name(&self) -> Option<&str> {
        self.active_region().map(|r| r.name.as_str())
    }

    /// Flags of the active (highest-priority) region.
    pub fn flags(&self) -> SegmentFlags {
        self.active_region()
            .map(|r| r.flags)
            .unwrap_or(SegmentFlags::from_raw(0))
    }
}

/// Live proxy to the memory map of a [`BinaryView`].
///
/// A `MemoryMap` describes how a [`BinaryView`] is loaded into memory. It
/// contains *regions* — raw, possibly overlapping memory definitions — and
/// exposes *resolved ranges* — a computed, disjoint view of the address space
/// produced by splitting overlapping regions. The most recently added region
/// takes precedence when regions overlap. Mutation is always by region name.
///
/// - [`regions()`](Self::regions) returns configured memory regions, including
///   disabled ones.
/// - [`ranges()`](Self::ranges) returns resolved, non-overlapping address
///   ranges — the computed active view.
/// - Both return snapshot values that are not updated after later mutations.
///
/// # Architecture Note
///
/// This Rust `MemoryMap` struct is a proxy that accesses the BinaryView's current MemoryMap state through
/// the FFI boundary. The proxy provides a simple mutable interface: when you call modification operations
/// (add_memory_region, remove_memory_region, etc.), the proxy automatically accesses the updated MemoryMap.
/// Internally, the core uses immutable copy-on-write data structures, but the proxy abstracts this away.
///
/// When you access a BinaryView's MemoryMap, you always see the current state. For lock-free access during
/// analysis, AnalysisContext provides memory layout query methods (is_valid_offset, is_offset_readable, get_start,
/// get_length, etc.) that operate on an immutable snapshot of the MemoryMap cached when the analysis was initiated.
///
/// A MemoryMap can contain multiple, arbitrarily overlapping memory regions. When modified, address space
/// segmentation is automatically managed. If multiple regions overlap, the most recently added region takes
/// precedence by default.
///
/// All MemoryMap APIs support undo and redo operations. During BinaryView::Init, these APIs should be used
/// conditionally:
///
/// * Initial load: Use the MemoryMap APIs to define the memory regions that compose the system.
/// * Database load: Do not use the MemoryMap APIs, as the regions are already persisted and will be restored
///   automatically.
#[derive(PartialEq, Eq, Hash)]
pub struct MemoryMap {
    view: Ref<BinaryView>,
}

impl MemoryMap {
    pub fn new(view: Ref<BinaryView>) -> Self {
        Self { view }
    }

    /// Returns a snapshot of all configured memory regions, including disabled ones.
    pub fn regions(&self) -> Vec<MemoryRegionInfo> {
        let mut count: usize = 0;
        let regions_raw = unsafe { BNGetMemoryRegions(self.view.handle, &mut count) };
        if regions_raw.is_null() {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let region = unsafe { &*regions_raw.add(i) };
            result.push(MemoryRegionInfo::from_raw(region));
        }
        unsafe { BNFreeMemoryRegions(regions_raw, count) };
        result
    }

    /// Returns a snapshot of the resolved, non-overlapping address ranges.
    ///
    /// Each range contains an ordered list of memory regions, with the first
    /// being the active (highest priority) region at that interval.
    pub fn ranges(&self) -> Vec<ResolvedRange> {
        let mut count: usize = 0;
        let ranges_raw = unsafe { BNGetResolvedMemoryRanges(self.view.handle, &mut count) };
        if ranges_raw.is_null() {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let range = unsafe { &*ranges_raw.add(i) };
            let mut regions = Vec::with_capacity(range.regionCount);
            for j in 0..range.regionCount {
                let region = unsafe { &*range.regions.add(j) };
                regions.push(MemoryRegionInfo::from_raw(region));
            }
            result.push(ResolvedRange {
                start: range.start,
                length: range.length,
                regions,
            });
        }
        unsafe { BNFreeResolvedMemoryRanges(ranges_raw, count) };
        result
    }

    /// Look up a configured memory region by name.
    ///
    /// Returns a snapshot of the region's properties, or `None` if no region
    /// with the given name exists.
    pub fn get_region(&self, name: &str) -> Option<MemoryRegionInfo> {
        let name_raw = name.to_cstr();
        let mut result: BNMemoryRegionInfo = unsafe { std::mem::zeroed() };
        let found =
            unsafe { BNGetMemoryRegionInfo(self.view.handle, name_raw.as_ptr(), &mut result) };
        if !found {
            return None;
        }
        let info = MemoryRegionInfo::from_raw(&result);
        unsafe { BNFreeMemoryRegionInfo(&mut result) };
        Some(info)
    }

    /// Return the active region snapshot covering `addr`, or `None` if no
    /// enabled region covers the address.
    pub fn get_active_region_at(&self, addr: u64) -> Option<MemoryRegionInfo> {
        let mut result: BNMemoryRegionInfo = unsafe { std::mem::zeroed() };
        let found = unsafe { BNGetActiveMemoryRegionInfoAt(self.view.handle, addr, &mut result) };
        if !found {
            return None;
        }
        let info = MemoryRegionInfo::from_raw(&result);
        unsafe { BNFreeMemoryRegionInfo(&mut result) };
        Some(info)
    }

    /// Return the resolved range snapshot covering `addr`, or `None` if no
    /// range covers the address.
    pub fn get_resolved_range_at(&self, addr: u64) -> Option<ResolvedRange> {
        let mut result: BNResolvedMemoryRange = unsafe { std::mem::zeroed() };
        let found = unsafe { BNGetResolvedMemoryRangeAt(self.view.handle, addr, &mut result) };
        if !found {
            return None;
        }
        let mut regions = Vec::with_capacity(result.regionCount);
        for j in 0..result.regionCount {
            let region = unsafe { &*result.regions.add(j) };
            regions.push(MemoryRegionInfo::from_raw(region));
        }
        let resolved = ResolvedRange {
            start: result.start,
            length: result.length,
            regions,
        };
        unsafe { BNFreeResolvedMemoryRange(&mut result) };
        Some(resolved)
    }

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
    ///
    /// Returns `true` if this MemoryMap represents a parsed BinaryView with real segments
    /// (ELF, PE, Mach-O, etc.). Returns `false` for Raw BinaryViews or views that failed
    /// to parse segments.
    ///
    /// This is determined by whether the BinaryView has a parent view - parsed views have a
    /// parent Raw view, while Raw views have no parent.
    ///
    /// Use this to gate features that require parsed binary structure (sections, imports,
    /// relocations, etc.). For basic analysis queries (start, length, is_offset_readable, etc.),
    /// use the MemoryMap directly regardless of activation state - all BinaryViews have a
    /// usable MemoryMap.
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

    /// Adds an unbacked memory region with a given length and fill byte.
    pub fn add_unbacked_memory_region(
        &mut self,
        name: &str,
        start: u64,
        length: u64,
        segment_flags: Option<SegmentFlags>,
        fill: Option<u8>,
    ) -> bool {
        let name_raw = name.to_cstr();
        unsafe {
            BNAddUnbackedMemoryRegion(
                self.view.handle,
                name_raw.as_ptr(),
                start,
                length,
                segment_flags.unwrap_or_default().into_raw(),
                fill.unwrap_or_default(),
            )
        }
    }

    /// Adds a persistent memory region mapping `[start, start + length)` to the current file,
    /// fully backed by `length` bytes at `file_offset`. Fails if the mapping runs past the end of
    /// the parent file; add a separate unbacked region for any additional virtual span.
    ///
    /// This is the memory-region replacement for user segments: the region is identified by its
    /// stable `name`.
    pub fn add_mapped_memory_region(
        &mut self,
        name: &str,
        start: u64,
        length: u64,
        file_offset: u64,
        segment_flags: Option<SegmentFlags>,
    ) -> bool {
        let name_raw = name.to_cstr();
        unsafe {
            BNAddMappedMemoryRegion(
                self.view.handle,
                name_raw.as_ptr(),
                start,
                length,
                file_offset,
                segment_flags.unwrap_or_default().into_raw(),
            )
        }
    }

    pub fn remove_memory_region(&mut self, name: &str) -> bool {
        let name_raw = name.to_cstr();
        unsafe { BNRemoveMemoryRegion(self.view.handle, name_raw.as_ptr()) }
    }

    /// Return the name of the active region at `addr`, or an empty string if
    /// no region covers the address.
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

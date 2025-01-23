use std::collections::HashMap;
use std::ops::Range;

use binaryninja::section::Section;
use binaryninja::segment::Segment;
use log::{debug, error, info, warn};
use minidump::format::MemoryProtection;
use minidump::{
    Minidump, MinidumpMemory64List, MinidumpMemoryInfoList, MinidumpMemoryList, MinidumpModuleList,
    MinidumpStream, MinidumpSystemInfo, Module,
};

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::custom_binary_view::{
    BinaryViewType, BinaryViewTypeBase, CustomBinaryView, CustomBinaryViewType, CustomView,
    CustomViewBuilder,
};
use binaryninja::platform::Platform;
use binaryninja::Endianness;

type BinaryViewResult<R> = binaryninja::binary_view::Result<R>;

/// The _Minidump_ binary view type, which the Rust plugin registers with the Binary Ninja core
/// (via `binaryninja::custombinaryview::register_view_type`) as a possible binary view
/// that can be applied to opened binaries.
///
/// If this view type is valid for an opened binary (determined by `is_valid_for`),
/// the Binary Ninja core then uses this view type to create an actual instance of the _Minidump_
/// binary view (via `create_custom_view`).
pub struct MinidumpBinaryViewType {
    view_type: BinaryViewType,
}

impl MinidumpBinaryViewType {
    pub fn new(view_type: BinaryViewType) -> Self {
        MinidumpBinaryViewType { view_type }
    }
}

impl AsRef<BinaryViewType> for MinidumpBinaryViewType {
    fn as_ref(&self) -> &BinaryViewType {
        &self.view_type
    }
}

impl BinaryViewTypeBase for MinidumpBinaryViewType {
    fn is_deprecated(&self) -> bool {
        false
    }

    fn is_force_loadable(&self) -> bool {
        false
    }

    fn is_valid_for(&self, data: &BinaryView) -> bool {
        let mut magic_number = Vec::<u8>::new();
        data.read_into_vec(&mut magic_number, 0, 4);

        magic_number == b"MDMP"
    }
}

impl CustomBinaryViewType for MinidumpBinaryViewType {
    fn create_custom_view<'builder>(
        &self,
        data: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> BinaryViewResult<CustomView<'builder>> {
        debug!("Creating MinidumpBinaryView from registered MinidumpBinaryViewType");

        let binary_view = builder.create::<MinidumpBinaryView>(data, ());
        binary_view
    }
}

#[derive(Debug)]
struct SegmentData {
    rva_range: Range<u64>,
    mapped_addr_range: Range<u64>,
}

impl SegmentData {
    fn from_addresses_and_size(rva: u64, mapped_addr: u64, size: u64) -> Self {
        SegmentData {
            rva_range: Range {
                start: rva,
                end: rva + size,
            },
            mapped_addr_range: Range {
                start: mapped_addr,
                end: mapped_addr + size,
            },
        }
    }
}

#[derive(Debug)]
struct SegmentMemoryProtection {
    readable: bool,
    writable: bool,
    executable: bool,
}

/// An instance of the actual _Minidump_ custom binary view.
/// This contains the main logic to load the memory segments inside a minidump file into the binary view.
pub struct MinidumpBinaryView {
    /// The handle to the "real" BinaryView object, in the Binary Ninja core.
    inner: binaryninja::rc::Ref<BinaryView>,
}

impl MinidumpBinaryView {
    fn new(view: &BinaryView) -> Self {
        MinidumpBinaryView {
            inner: view.to_owned(),
        }
    }

    fn init(&self) -> BinaryViewResult<()> {
        let parent_view = self.parent_view().ok_or(())?;
        let read_buffer = parent_view.read_buffer(0, parent_view.len() as usize)?;

        if let Ok(minidump_obj) = Minidump::read(read_buffer.get_data()) {
            // Architecture, platform information
            if let Ok(minidump_system_info) = minidump_obj.get_stream::<MinidumpSystemInfo>() {
                if let Some(platform) = MinidumpBinaryView::translate_minidump_platform(
                    minidump_system_info.cpu,
                    minidump_obj.endian,
                    minidump_system_info.os,
                ) {
                    self.set_default_platform(&platform);
                } else {
                    error!(
                        "Could not parse valid system information from minidump: could not map system information in MinidumpSystemInfo stream (arch {:?}, endian {:?}, os {:?}) to a known architecture",
                        minidump_system_info.cpu,
                        minidump_obj.endian,
                        minidump_system_info.os,
                    );
                    return Err(());
                }
            } else {
                error!("Could not parse system information from minidump: could not find a valid MinidumpSystemInfo stream");
                return Err(());
            }

            // Memory segments
            let mut segment_data = Vec::<SegmentData>::new();

            // Memory segments in a full memory dump (MinidumpMemory64List)
            // Grab the shared base RVA for all entries in the MinidumpMemory64List,
            // since the minidump crate doesn't expose this to us
            if let Ok(raw_stream) = minidump_obj.get_raw_stream(MinidumpMemory64List::STREAM_TYPE) {
                if let Ok(base_rva_array) = raw_stream[8..16].try_into() {
                    let base_rva = u64::from_le_bytes(base_rva_array);
                    debug!("Found BaseRVA value {:#x}", base_rva);

                    if let Ok(minidump_memory_list) =
                        minidump_obj.get_stream::<MinidumpMemory64List>()
                    {
                        let mut current_rva = base_rva;
                        for memory_segment in minidump_memory_list.iter() {
                            debug!(
                            "Found memory segment at RVA {:#x} with virtual address {:#x} and size {:#x}",
                            current_rva,
                            memory_segment.base_address,
                            memory_segment.size,
                        );
                            segment_data.push(SegmentData::from_addresses_and_size(
                                current_rva,
                                memory_segment.base_address,
                                memory_segment.size,
                            ));
                            current_rva += memory_segment.size;
                        }
                    }
                } else {
                    error!("Could not parse BaseRVA value shared by all entries in the MinidumpMemory64List stream")
                }
            } else {
                warn!("Could not read memory from minidump: could not find a valid MinidumpMemory64List stream. This minidump may not be a full memory dump. Trying to find partial dump memory from a MinidumpMemoryList now...");
                // Memory segments in a regular memory dump (MinidumpMemoryList),
                // i.e. one that does not include the full process memory data.
                if let Ok(minidump_memory_list) = minidump_obj.get_stream::<MinidumpMemoryList>() {
                    for memory_segment in minidump_memory_list.by_addr() {
                        debug!(
                            "Found memory segment at RVA {:#x} with virtual address {:#x} and size {:#x}",
                            memory_segment.desc.memory.rva,
                            memory_segment.base_address,
                            memory_segment.size
                        );
                        segment_data.push(SegmentData::from_addresses_and_size(
                            memory_segment.desc.memory.rva as u64,
                            memory_segment.base_address,
                            memory_segment.size,
                        ));
                    }
                } else {
                    error!("Could not read any memory from minidump: could not find a valid MinidumpMemory64List stream or a valid MinidumpMemoryList stream.");
                }
            }

            // Memory protection information
            let mut segment_protection_data = HashMap::new();

            if let Ok(minidump_memory_info_list) =
                minidump_obj.get_stream::<MinidumpMemoryInfoList>()
            {
                for memory_info in minidump_memory_info_list.iter() {
                    if let Some(memory_range) = memory_info.memory_range() {
                        debug!(
                            "Found memory protection info for memory segment ranging from virtual address {:#x} to {:#x}: {:#?}",
                            memory_range.start,
                            memory_range.end,
                            memory_info.protection
                        );
                        segment_protection_data.insert(
                            // The range returned to us by MinidumpMemoryInfoList is an
                            // end-inclusive range_map::Range; we need to add 1 to
                            // the end index to make it into an end-exclusive std::ops::Range.
                            Range {
                                start: memory_range.start,
                                end: memory_range.end + 1,
                            },
                            memory_info.protection,
                        );
                    }
                }
            }

            for segment in segment_data.iter() {
                if let Some(segment_protection) =
                    segment_protection_data.get(&segment.mapped_addr_range)
                {
                    let segment_memory_protection =
                        MinidumpBinaryView::translate_memory_protection(*segment_protection);

                    info!(
                        "Adding memory segment at virtual address {:#x} to {:#x}, from data range {:#x} to {:#x}, with protections readable {}, writable {}, executable {}",
                         segment.mapped_addr_range.start,
                         segment.mapped_addr_range.end,
                         segment.rva_range.start,
                         segment.rva_range.end,
                         segment_memory_protection.readable,
                         segment_memory_protection.writable,
                         segment_memory_protection.executable,
                    );

                    self.add_segment(
                        Segment::builder(segment.mapped_addr_range.clone())
                            .parent_backing(segment.rva_range.clone())
                            .is_auto(true)
                            .readable(segment_memory_protection.readable)
                            .writable(segment_memory_protection.writable)
                            .executable(segment_memory_protection.executable),
                    );
                } else {
                    error!(
                        "Could not find memory protection information for memory segment from {:#x} to {:#x}", segment.mapped_addr_range.start,
                        segment.mapped_addr_range.end,
                    );
                }
            }

            // Module information
            // This stretches the concept a bit, but we can add each module as a
            // separate "section" of the binary.
            // Sections can be named, and can span multiple segments.
            if let Ok(minidump_module_list) = minidump_obj.get_stream::<MinidumpModuleList>() {
                for module_info in minidump_module_list.by_addr() {
                    info!(
                        "Found module with name {} at virtual address {:#x} with size {:#x}",
                        module_info.name,
                        module_info.base_address(),
                        module_info.size(),
                    );
                    let module_address_range = Range {
                        start: module_info.base_address(),
                        end: module_info.base_address() + module_info.size(),
                    };
                    self.add_section(
                        Section::builder(module_info.name.clone(), module_address_range)
                            .is_auto(true),
                    );
                }
            } else {
                warn!("Could not find valid module information in minidump: could not find a valid MinidumpModuleList stream");
            }
        } else {
            error!("Could not parse data as minidump");
            return Err(());
        }
        Ok(())
    }

    fn translate_minidump_platform(
        minidump_cpu_arch: minidump::system_info::Cpu,
        minidump_endian: minidump::Endian,
        minidump_os: minidump::system_info::Os,
    ) -> Option<binaryninja::rc::Ref<Platform>> {
        match minidump_os {
            minidump::system_info::Os::Windows => match minidump_cpu_arch {
                minidump::system_info::Cpu::Arm64 => Platform::by_name("windows-aarch64"),
                minidump::system_info::Cpu::Arm => Platform::by_name("windows-armv7"),
                minidump::system_info::Cpu::X86 => Platform::by_name("windows-x86"),
                minidump::system_info::Cpu::X86_64 => Platform::by_name("windows-x86_64"),
                _ => None,
            },
            minidump::system_info::Os::MacOs => match minidump_cpu_arch {
                minidump::system_info::Cpu::Arm64 => Platform::by_name("mac-aarch64"),
                minidump::system_info::Cpu::Arm => Platform::by_name("mac-armv7"),
                minidump::system_info::Cpu::X86 => Platform::by_name("mac-x86"),
                minidump::system_info::Cpu::X86_64 => Platform::by_name("mac-x86_64"),
                _ => None,
            },
            minidump::system_info::Os::Linux => match minidump_cpu_arch {
                minidump::system_info::Cpu::Arm64 => Platform::by_name("linux-aarch64"),
                minidump::system_info::Cpu::Arm => Platform::by_name("linux-armv7"),
                minidump::system_info::Cpu::X86 => Platform::by_name("linux-x86"),
                minidump::system_info::Cpu::X86_64 => Platform::by_name("linux-x86_64"),
                minidump::system_info::Cpu::Ppc => match minidump_endian {
                    minidump::Endian::Little => Platform::by_name("linux-ppc32_le"),
                    minidump::Endian::Big => Platform::by_name("linux-ppc32"),
                },
                minidump::system_info::Cpu::Ppc64 => match minidump_endian {
                    minidump::Endian::Little => Platform::by_name("linux-ppc64_le"),
                    minidump::Endian::Big => Platform::by_name("linux-ppc64"),
                },
                _ => None,
            },
            minidump::system_info::Os::NaCl => None,
            minidump::system_info::Os::Android => None,
            minidump::system_info::Os::Ios => None,
            minidump::system_info::Os::Ps3 => None,
            minidump::system_info::Os::Solaris => None,
            _ => None,
        }
    }

    fn translate_memory_protection(
        minidump_memory_protection: MemoryProtection,
    ) -> SegmentMemoryProtection {
        let (readable, writable, executable) = match minidump_memory_protection {
            MemoryProtection::PAGE_NOACCESS => (false, false, false),
            MemoryProtection::PAGE_READONLY => (true, false, false),
            MemoryProtection::PAGE_READWRITE => (true, true, false),
            MemoryProtection::PAGE_WRITECOPY => (true, true, false),
            MemoryProtection::PAGE_EXECUTE => (false, false, true),
            MemoryProtection::PAGE_EXECUTE_READ => (true, false, true),
            MemoryProtection::PAGE_EXECUTE_READWRITE => (true, true, true),
            MemoryProtection::PAGE_EXECUTE_WRITECOPY => (true, true, true),
            MemoryProtection::ACCESS_MASK => (false, false, false),
            MemoryProtection::PAGE_GUARD => (false, false, false),
            MemoryProtection::PAGE_NOCACHE => (false, false, false),
            MemoryProtection::PAGE_WRITECOMBINE => (false, false, false),
            _ => (false, false, false),
        };
        SegmentMemoryProtection {
            readable,
            writable,
            executable,
        }
    }
}

impl AsRef<BinaryView> for MinidumpBinaryView {
    fn as_ref(&self) -> &BinaryView {
        &self.inner
    }
}

impl BinaryViewBase for MinidumpBinaryView {
    // TODO: This should be filled out with the actual address size
    // from the platform information in the minidump.
    fn address_size(&self) -> usize {
        0
    }

    fn default_endianness(&self) -> Endianness {
        // TODO: This should be filled out with the actual endianness
        // from the platform information in the minidump.
        Endianness::LittleEndian
    }

    fn entry_point(&self) -> u64 {
        // TODO: We should fill this out with a real entry point.
        // This can be done by getting the main module of the minidump
        // with MinidumpModuleList::main_module,
        // then parsing the PE metadata of the main module to find its entry point(s).
        0
    }
}

unsafe impl CustomBinaryView for MinidumpBinaryView {
    type Args = ();

    fn new(handle: &BinaryView, _args: &Self::Args) -> BinaryViewResult<Self> {
        Ok(MinidumpBinaryView::new(handle))
    }

    fn init(&mut self, _args: Self::Args) -> BinaryViewResult<()> {
        MinidumpBinaryView::init(self)
    }
}

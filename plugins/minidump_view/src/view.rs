use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::binary_view::{CustomBinaryView, CustomBinaryViewType};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::section::{SectionBuilder, Semantics};
use binaryninja::segment::SegmentFlags;
use binaryninja::symbol::{SymbolBuilder, SymbolType};
use binaryninja::Endianness;
use minidump::format::MemoryProtection;
use minidump::system_info::{Cpu, Os, PointerWidth};
use minidump::{Minidump, MinidumpMemoryInfoList, MinidumpModuleList};
use minidump::{MinidumpSystemInfo, Module};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

pub struct MinidumpBinaryViewType;

impl CustomBinaryViewType for MinidumpBinaryViewType {
    type CustomBinaryView = MinidumpBinaryView;
    const NAME: &'static str = "Minidump";

    fn create_binary_view(&self, data: &BinaryView) -> Result<Self::CustomBinaryView, ()> {
        match MinidumpBinaryView::new(data) {
            Ok(minidump_binary_view) => Ok(minidump_binary_view),
            Err(e) => {
                tracing::error!("Failed to create minidump binary view: {}", e);
                Err(())
            }
        }
    }

    fn is_valid_for(&self, data: &BinaryView) -> bool {
        // Check for the MDMP magic bytes
        let magic = [0x4d, 0x44, 0x4d, 0x50];
        let mut buffer = [0u8; 4];
        data.read(&mut buffer, 0);
        buffer == magic
    }
}

/// An instance of the actual custom Minidump binary view.
///
/// This contains the main logic to load the memory segments inside a minidump file into the binary view.
pub struct MinidumpBinaryView {
    minidump: Minidump<'static, Vec<u8>>,
    endianness: Endianness,
    address_size: usize,
    /// The entry point of the main module.
    ///
    /// This will be set inside [`MinidumpBinaryView::initialize`], so won't be immediately available.
    main_entry_point: Option<u64>,
}

impl MinidumpBinaryView {
    pub fn new(data: &BinaryView) -> Result<Self, String> {
        let read_buffer = data
            .read_buffer(0, data.len() as usize)
            .ok_or("Failed to read data from binary view".to_string())?;
        let minidump = Minidump::read(read_buffer.get_data().to_vec())
            .map_err(|e| format!("Failed to parse minidump: {}", e))?;
        let system_info = minidump
            .get_stream::<MinidumpSystemInfo>()
            .map_err(|e| format!("Failed to get system info stream: {}", e))?;
        let endianness = match minidump.endian {
            minidump::Endian::Little => Endianness::LittleEndian,
            minidump::Endian::Big => Endianness::BigEndian,
        };
        let address_size = match system_info.cpu.pointer_width() {
            PointerWidth::Bits32 => 4,
            PointerWidth::Bits64 => 8,
            PointerWidth::Unknown => {
                tracing::warn!("Unknown pointer width, defaulting to 32-bit");
                4
            }
        };

        Ok(MinidumpBinaryView {
            minidump,
            endianness,
            address_size,
            main_entry_point: None,
        })
    }

    pub fn translate_platform(
        &self,
        system_info: &MinidumpSystemInfo,
    ) -> Result<Ref<Platform>, String> {
        let platform_name = self.translate_platform_name(system_info.os, system_info.cpu)?;
        Platform::by_name(platform_name)
            .ok_or_else(|| format!("Could not find platform {}", platform_name))
    }

    pub fn translate_platform_name(&self, os: Os, cpu: Cpu) -> Result<&'static str, String> {
        match os {
            Os::Windows => match cpu {
                Cpu::Arm64 => Ok("windows-aarch64"),
                Cpu::Arm => Ok("windows-armv7"),
                Cpu::X86 => Ok("windows-x86"),
                Cpu::X86_64 => Ok("windows-x86_64"),
                _ => Err("Unsupported CPU architecture".to_string()),
            },
            Os::MacOs => match cpu {
                Cpu::Arm64 => Ok("mac-aarch64"),
                Cpu::Arm => Ok("mac-armv7"),
                Cpu::X86 => Ok("mac-x86"),
                Cpu::X86_64 => Ok("mac-x86_64"),
                _ => Err("Unsupported CPU architecture".to_string()),
            },
            Os::Linux => match cpu {
                Cpu::Arm64 => Ok("linux-aarch64"),
                Cpu::Arm => Ok("linux-armv7"),
                Cpu::X86 => Ok("linux-x86"),
                Cpu::X86_64 => Ok("linux-x86_64"),
                Cpu::Ppc => match self.endianness {
                    Endianness::LittleEndian => Ok("linux-ppc32_le"),
                    Endianness::BigEndian => Ok("linux-ppc32"),
                },
                Cpu::Ppc64 => match self.endianness {
                    Endianness::LittleEndian => Ok("linux-ppc64_le"),
                    Endianness::BigEndian => Ok("linux-ppc64"),
                },
                _ => Err("Unsupported CPU architecture".to_string()),
            },
            // TODO: Support iOS
            Os::Ios => Err("Unsupported operating system".to_string()),
            _ => Err("Unsupported operating system".to_string()),
        }
    }

    pub fn translate_memory_protection(
        &self,
        minidump_memory_protection: MemoryProtection,
    ) -> SegmentFlags {
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
        SegmentFlags::new()
            .readable(readable)
            .writable(writable)
            .executable(executable)
    }
}

impl BinaryViewBase for MinidumpBinaryView {
    fn entry_point(&self) -> u64 {
        self.main_entry_point.unwrap_or(0)
    }

    fn default_endianness(&self) -> Endianness {
        self.endianness
    }

    fn address_size(&self) -> usize {
        self.address_size
    }
}

impl CustomBinaryView for MinidumpBinaryView {
    fn initialize(&mut self, view: &BinaryView) -> bool {
        let Ok(system_info) = self.minidump.get_stream::<MinidumpSystemInfo>() else {
            tracing::error!("Could not find a valid MinidumpSystemInfo stream");
            return false;
        };

        let platform = match self.translate_platform(&system_info) {
            Ok(platform) => platform,
            Err(err) => {
                tracing::error!("Could not determine platform: {}", err);
                return false;
            }
        };
        view.set_default_platform(&platform);

        let Some(unified_memory_list) = self.minidump.get_memory() else {
            tracing::error!("Could not find a valid memory list stream");
            return false;
        };

        // Some full memory dumps don't have memory info, so we will fall back to default segment flags in that case.
        let memory_info_list = self
            .minidump
            .get_stream::<MinidumpMemoryInfoList>()
            .inspect_err(|e| tracing::warn!("Could not find a valid memory info list stream: '{}' no segment flags will be set", e))
            .ok();

        for memory in unified_memory_list.iter() {
            let Some(memory_range) = memory.memory_range() else {
                tracing::error!(
                    "Could not find a valid memory range for memory segment: {:?}",
                    memory
                );
                continue;
            };

            // If we are opening the view again, this will already be filled from the first load, so skip it.
            if view
                .memory_map()
                .get_active_region_at(memory_range.start)
                .is_some()
            {
                tracing::debug!("Skipping memory segment {:0x} because it overlaps with an existing memory region", memory_range.start);
                continue;
            }

            let segment_flags = memory_info_list
                .as_ref()
                .and_then(|list| list.memory_info_at_address(memory.base_address()))
                .map(|info| self.translate_memory_protection(info.protection));

            // TODO: The parent backing _is_ the memory range itself, we currently add that memory range
            // TODO: after the fact instead of deriving it from the contents of the file itself.
            let buffer = DataBuffer::new(memory.bytes());
            view.memory_map().add_data_memory_region(
                &format!("{:0x}", memory_range.start),
                memory_range.start,
                &buffer,
                segment_flags,
            );
        }

        let Ok(module_list) = self.minidump.get_stream::<MinidumpModuleList>() else {
            tracing::warn!(
                "Could not find a valid module list stream, no module sections will be added!"
            );
            return true;
        };

        let main_module_addr = module_list
            .main_module()
            .map(|module| module.base_address());

        for module in module_list.iter() {
            tracing::info!(
                "Loading module '{}' at {:0x}",
                module.name,
                module.base_address()
            );
            let mut buffer: Vec<u8> = vec![0; module.size() as usize];
            let read_length = view.read(&mut buffer, module.base_address());
            if read_length != module.size() as usize {
                tracing::error!("Could not read module: {:?}", module);
                continue;
            }
            let file = match object::File::parse(&*buffer) {
                Ok(file) => file,
                Err(e) => {
                    tracing::error!("Could not parse module: {:?}: {}", module.name, e);
                    continue;
                }
            };
            for section in file.sections() {
                let section_name =
                    format!("{}:{}", module.name, section.name().unwrap_or("<unknown>"));
                let section_range = section.address()..section.address() + section.size();
                let section_semantics = match section.kind() {
                    SectionKind::Unknown => Semantics::DefaultSection,
                    SectionKind::Text => Semantics::ReadOnlyCode,
                    SectionKind::Data => Semantics::ReadWriteData,
                    SectionKind::ReadOnlyData => Semantics::ReadOnlyData,
                    SectionKind::ReadOnlyDataWithRel => Semantics::ReadOnlyData,
                    SectionKind::ReadOnlyString => Semantics::ReadOnlyData,
                    SectionKind::UninitializedData => Semantics::ReadOnlyData,
                    _ => Semantics::DefaultSection,
                };
                let section_builder = SectionBuilder::new(section_name, section_range)
                    .align(section.align())
                    .semantics(section_semantics)
                    .is_auto(true);
                view.add_section(section_builder);
            }
            for symbol in file.symbols() {
                let symbol_name = symbol.name().unwrap_or("<unknown>");
                let symbol_type = match symbol.kind() {
                    SymbolKind::Unknown => SymbolType::Symbolic,
                    SymbolKind::Text => SymbolType::Function,
                    SymbolKind::Data => SymbolType::Data,
                    SymbolKind::Section => SymbolType::Symbolic,
                    SymbolKind::File => SymbolType::Symbolic,
                    SymbolKind::Label => SymbolType::LocalLabel,
                    SymbolKind::Tls => SymbolType::Symbolic,
                    _ => SymbolType::Symbolic,
                };
                let symbol =
                    SymbolBuilder::new(symbol_type, symbol_name, symbol.address()).create();
                view.define_auto_symbol(&symbol);
            }
            view.add_entry_point(file.entry());
            // Set this so [`BinaryView::entry_point`] knows which is the main entry point.
            if main_module_addr.is_some_and(|addr| addr == module.base_address()) {
                self.main_entry_point = Some(file.entry());
            }
        }

        true
    }
}

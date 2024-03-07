#pragma once

#include "binaryninjaapi.h"
#include <exception>

#ifdef WIN32
#pragma warning(disable: 4005)
#endif

#define PE_ATTR_CODE        0x20
#define PE_ATTR_INIT_DATA   0x40
#define PE_ATTR_UNINIT_DATA 0x80
#define PE_ATTR_EXEC        0x20000000

// The dalay load table uses RVA, rather than VA
#define PE_DLATTR_RVA		0x1

// Relocation information was stripped from the file. The file must be loaded at its preferred base address.
//  If the base address is not available, the loader reports an error.
#define IMAGE_FILE_RELOCS_STRIPPED         0x0001
// The file is executable (there are no unresolved external references).
#define IMAGE_FILE_EXECUTABLE_IMAGE        0x0002
// COFF line numbers were stripped from the file.
#define IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004
// COFF symbol table entries were stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
// Aggressively trim the working set. This value is obsolete.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM       0x0010
// The application can handle addresses larger than 2 GB.
#define IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020
// The bytes of the word are reversed. This flag is obsolete.
#define IMAGE_FILE_BYTES_REVERSED_LO       0x0080
// The computer supports 32-bit words.
#define IMAGE_FILE_32BIT_MACHINE           0x0100
// Debugging information was removed and stored separately in another file.
#define IMAGE_FILE_DEBUG_STRIPPED          0x0200
// If the image is on removable media, copy it to and run it from the swap file.
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
// If the image is on the network, copy it to and run it from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800
// The image is a system file.
#define IMAGE_FILE_SYSTEM                  0x1000
// The image is a DLL file. While it is an executable file, it cannot be run directly.
#define IMAGE_FILE_DLL                     0x2000
// The file should be run only on a uniprocessor computer.
#define IMAGE_FILE_UP_SYSTEM_ONLY          0x4000
// The bytes of the word are reversed. This flag is obsolete.
#define IMAGE_FILE_BYTES_REVERSED_HI       0x8000

#define IMAGE_FILE_MACHINE_UNKNOWN 0x0
#define IMAGE_FILE_MACHINE_AM33 0x1d3
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM 0x1c0
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_ARMNT 0x1c4
#define IMAGE_FILE_MACHINE_EBC 0xebc
#define IMAGE_FILE_MACHINE_I386 0x14c
#define IMAGE_FILE_MACHINE_IA64 0x200
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_MIPS16 0x266
#define IMAGE_FILE_MACHINE_MIPSFPU 0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x466
#define IMAGE_FILE_MACHINE_POWERPC 0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x1f1
#define IMAGE_FILE_MACHINE_R4000 0x166
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define IMAGE_FILE_MACHINE_RISCV128 0x5128
#define IMAGE_FILE_MACHINE_SH3 0x1a2
#define IMAGE_FILE_MACHINE_SH3DSP 0x1a3
#define IMAGE_FILE_MACHINE_SH4 0x1a6
#define IMAGE_FILE_MACHINE_SH5 0x1a8
#define IMAGE_FILE_MACHINE_THUMB 0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x169

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11
#define IMAGE_DEBUG_TYPE_VC_FEATURE       12
#define IMAGE_DEBUG_TYPE_POGO             13
#define IMAGE_DEBUG_TYPE_ILTCG            14
#define IMAGE_DEBUG_TYPE_MPX              15
#define IMAGE_DEBUG_TYPE_REPRO            16
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20

#define UNW_FLAG_NHANDLER   0x0    // The function has no handler.
#define UNW_FLAG_EHANDLER   0x1    // The function has an exception handler that should be called.
#define UNW_FLAG_UHANDLER   0x2    // The function has a termination handler that should be called when unwinding an exception.
#define UNW_FLAG_CHAININFO  0x4    // The FunctionEntry member is the contents of a previous function table entry.

#define IMAGE_SUBSYSTEM_UNKNOWN 0
#define IMAGE_SUBSYSTEM_NATIVE 1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define IMAGE_SUBSYSTEM_OS2_CUI 5
#define IMAGE_SUBSYSTEM_POSIX_CUI 7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#define IMAGE_SUBSYSTEM_EFI_ROM 13
#define IMAGE_SUBSYSTEM_XBOX 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

#define IMAGE_DLLCHARACTERISTICS_0001                   0x0001	//Reserved.
#define IMAGE_DLLCHARACTERISTICS_0002                   0x0002	//Reserved.
#define IMAGE_DLLCHARACTERISTICS_0004                   0x0004	//Reserved.
#define IMAGE_DLLCHARACTERISTICS_0008                   0x0008	//Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA        0x0020	// Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           0x0040	// The DLL can be relocated at load time.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        0x0080	// Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified.
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT              0x0100	// Image is NX compatible.
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           0x0200	// Isolation aware, but do not isolate the image.
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                 0x0400	// The image does not use structured exception handling (SEH). No handlers can be called in this image.
#define IMAGE_DLLCHARACTERISTICS_NO_BIND                0x0800	// Do not bind the image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER           0x1000	// Image must execute in an AppContainer.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             0x2000	// A WDM driver.
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF               0x4000	// Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  0x8000	// Terminal Server aware.

#define IMAGE_SCN_RESERVED_0001 0x00000001
#define IMAGE_SCN_RESERVED_0002 0x00000002
#define IMAGE_SCN_RESERVED_0004 0x00000004
#define IMAGE_SCN_TYPE_NO_PAD 0x00000008 // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
#define IMAGE_SCN_RESERVED_0010 0x00000010
#define IMAGE_SCN_CNT_CODE 0x00000020 // The section contains executable code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 // The section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 // The section contains uninitialized data.
#define IMAGE_SCN_LNK_OTHER 0x00000100 // Reserved for future use.
#define IMAGE_SCN_LNK_INFO 0x00000200 // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
#define IMAGE_SCN_RESERVED_0400 0x00000400
#define IMAGE_SCN_LNK_REMOVE 0x00000800 // The section will not become part of the image. This is valid only for object files.
#define IMAGE_SCN_LNK_COMDAT 0x00001000 // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
#define IMAGE_SCN_GPREL 0x00008000 // The section contains data referenced through the global pointer (GP).
#define IMAGE_SCN_MEM_PURGEABLE 0x00010000 // Reserved for future use.
#define IMAGE_SCN_MEM_16BIT 0x00020000 // Reserved for future use.
#define IMAGE_SCN_MEM_LOCKED 0x00040000 // Reserved for future use.
#define IMAGE_SCN_MEM_PRELOAD 0x00080000 // Reserved for future use.
#define IMAGE_SCN_ALIGN_1BYTES 0x00100000 // Align data on a 1-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_2BYTES 0x00200000 // Align data on a 2-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_4BYTES 0x00300000 // Align data on a 4-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_8BYTES 0x00400000 // Align data on an 8-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000 // Align data on a 16-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_32BYTES 0x00600000 // Align data on a 32-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_64BYTES 0x00700000 // Align data on a 64-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_128BYTES 0x00800000 // Align data on a 128-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_256BYTES 0x00900000 // Align data on a 256-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000 // Align data on a 512-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000 // Align data on a 1024-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000 // Align data on a 2048-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000 // Align data on a 4096-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000 // Align data on an 8192-byte boundary. Valid only for object files.
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000 // The section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000 // The section can be discarded as needed.
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000 // The section cannot be cached.
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000 // The section is not pageable.
#define IMAGE_SCN_MEM_SHARED 0x10000000 // The section can be shared in memory.
#define IMAGE_SCN_MEM_EXECUTE 0x20000000 // The section can be executed as code.
#define IMAGE_SCN_MEM_READ 0x40000000 // The section can be read.
#define IMAGE_SCN_MEM_WRITE 0x80000000 // The section can be written to.

#define IMAGE_GUARD_CF_INSTRUMENTED                    0x00000100 // Module performs control flow integrity checks using system-supplied support
#define IMAGE_GUARD_CFW_INSTRUMENTED                   0x00000200 // Module performs control flow and write integrity checks
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          0x00000400 // Module contains valid control flow target metadata
#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED             0x00000800 // Module does not make use of the /GS security cookie
#define IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              0x00001000 // Module supports read only delay load IAT
#define IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   0x00002000 // Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000 // Module contains suppressed export information. This also infers that the address taken
// taken IAT table is also present in the load config.

#define IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       0x00008000 // Module enables suppression of exports
#define IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          0x00010000 // Module contains longjmp target information
#define IMAGE_GUARD_RF_INSTRUMENTED                    0x00020000 // Module contains return flow instrumentation and metadata
#define IMAGE_GUARD_RF_ENABLE                          0x00040000 // Module requests that the OS enable return flow protection
#define IMAGE_GUARD_RF_STRICT                          0x00080000 // Module requests that the OS enable return flow protection in strict mode
#define IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000 // Module was built with retpoline support

#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        0xF0000000 // Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       28         // Shift to right-justify Guard CF function table stride


#define IMAGE_GUARD_FLAG_FID_SUPPRESSED       1 // Call target is explicitly suppressed (do not treat it as valid for purposes of CFG)
#define IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED    2 // Call target is export suppressed. See https://docs.microsoft.com/en-us/windows/win32/secbp/pe-metadata#export-suppression for more details
#define IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER 4
#define IMAGE_GUARD_FLAG_FID_XFG              8 // Call target supports XFG


// COFF symbol support
#define IMAGE_SYM_DTYPE_NULL 0x0
#define IMAGE_SYM_DTYPE_POINTER 0x1
#define IMAGE_SYM_DTYPE_FUNCTION 0x2
#define IMAGE_SYM_DTYPE_ARRAY 0x3

#define IMAGE_SYM_UNDEFINED   0
#define IMAGE_SYM_ABSOLUTE    -1
#define IMAGE_SYM_DEBUG  -2

#define IMAGE_SYM_CLASS_NULL                0
#define IMAGE_SYM_CLASS_AUTOMATIC           1
#define IMAGE_SYM_CLASS_EXTERNAL            2
#define IMAGE_SYM_CLASS_STATIC              3
#define IMAGE_SYM_CLASS_REGISTER            4
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        5
#define IMAGE_SYM_CLASS_LABEL               6
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     7
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    8
#define IMAGE_SYM_CLASS_ARGUMENT            9
#define IMAGE_SYM_CLASS_STRUCT_TAG         10
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION    11
#define IMAGE_SYM_CLASS_UNION_TAG          12
#define IMAGE_SYM_CLASS_TYPE_DEFINITION    13
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC   14
#define IMAGE_SYM_CLASS_ENUM_TAG           15
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM     16
#define IMAGE_SYM_CLASS_REGISTER_PARAM     17
#define IMAGE_SYM_CLASS_BIT_FIELD          18
#define IMAGE_SYM_CLASS_AUTOARG            19
#define IMAGE_SYM_CLASS_LASTENT            20
#define IMAGE_SYM_CLASS_BLOCK             100
#define IMAGE_SYM_CLASS_FUNCTION          101
#define IMAGE_SYM_CLASS_END_OF_STRUCT     102
#define IMAGE_SYM_CLASS_FILE              103
#define IMAGE_SYM_CLASS_SECTION           104
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL     105
#define IMAGE_SYM_CLASS_HIDDEN            106
#define IMAGE_SYM_CLASS_CLR_TOKEN         107
#define IMAGE_SYM_CLASS_END_OF_FUNCTION   255

namespace BinaryNinja
{
	class PEFormatException: public std::exception
	{
		std::string m_message;

	public:
		PEFormatException(const std::string& msg = "invalid format"): m_message(msg) {}
		virtual const char* what() const NOEXCEPT { return m_message.c_str(); }
	};

	struct PEHeader
	{
		uint32_t magic;
		uint16_t machine;
		uint16_t sectionCount;
		uint32_t timestamp;
		uint32_t coffSymbolTable;
		uint32_t coffSymbolCount;
		uint16_t optionalHeaderSize;
		uint16_t characteristics;
	};

	struct PEOptionalHeader
	{
		uint16_t magic;
		uint8_t majorLinkerVersion;
		uint8_t minorLinkerVersion;
		uint32_t sizeOfCode;
		uint32_t sizeOfInitData;
		uint32_t sizeOfUninitData;
		uint32_t addressOfEntry;
		uint32_t baseOfCode;
		uint32_t baseOfData;
		uint64_t imageBase;
		uint32_t sectionAlign;
		uint32_t fileAlign;
		uint16_t majorOSVersion;
		uint16_t minorOSVersion;
		uint16_t majorImageVersion;
		uint16_t minorImageVersion;
		uint16_t majorSubsystemVersion;
		uint16_t minorSubsystemVersion;
		uint32_t win32Version;
		uint32_t sizeOfImage;
		uint32_t sizeOfHeaders;
		uint32_t checksum;
		uint16_t subsystem;
		uint16_t dllCharacteristics;
		uint64_t sizeOfStackReserve;
		uint64_t sizeOfStackCommit;
		uint64_t sizeOfHeapReserve;
		uint64_t sizeOfHeapCommit;
		uint32_t loaderFlags;
		uint32_t dataDirCount;
	};

	struct PEDataDirectory
	{
		uint32_t virtualAddress;
		uint32_t size;
	};

	struct PESection
	{
		std::string name;
		uint32_t virtualSize;
		uint32_t virtualAddress;
		uint32_t sizeOfRawData;
		uint32_t pointerToRawData;
		uint32_t pointerToRelocs;
		uint32_t pointerToLineNumbers;
		uint16_t relocCount;
		uint16_t lineNumberCount;
		uint32_t characteristics;
	};

	struct PEImportDirectoryEntry
	{
		uint32_t lookup;
		uint32_t timestamp;
		uint32_t forwardChain;
		uint32_t nameAddress;
		uint32_t iat;
		std::string name;
	};

	struct PEExportDirectory
	{
		uint32_t characteristics;
		uint32_t timestamp;
		uint16_t majorVersion;
		uint16_t minorVersion;
		uint32_t dllNameAddress;
		uint32_t base;
		uint32_t functionCount;
		uint32_t nameCount;
		uint32_t addressOfFunctions;
		uint32_t addressOfNames;
		uint32_t addressOfNameOrdinals;
	};

	struct DebugDirectory
	{
		uint32_t characteristics;
		uint32_t timeDateStamp;
		uint16_t majorVersion;
		uint16_t minorVersion;
		uint32_t type;
		uint32_t sizeOfData;
		uint32_t addressOfRawData;
		uint32_t pointerToRawData;
	};

	struct ImageTLSDirectory
	{
		uint64_t startAddressOfRawData;
		uint64_t endAddressOfRawData;
		uint64_t addressOfIndex;
		uint64_t addressOfCallBacks;
		uint32_t sizeOfZeroFill;
		uint32_t characteristics;
	};

	struct DelayImportDescriptorEntry
	{
		uint32_t attributes;
		uint32_t name;
		uint32_t moduleHandle;
		uint32_t delayImportAddressTable;
		uint32_t delayImportNameTable;
		uint32_t boundDelayImportTable;
		uint32_t unloadDelayImportTable;
		uint32_t timestamp;
	};

	struct ImageBaseRelocation
	{
		uint64_t VirtualAddress;
		uint32_t SizeOfBlock;
	};

	struct CodeViewHeader
	{
		uint32_t signature;
		uint32_t offset;
	};

	struct CodeViewInfoPDB20
	{
		uint32_t signature;
		uint32_t age;
	};

	struct GUID
	{
		uint32_t Data1;
		uint16_t Data2;
		uint16_t Data3;
		uint8_t  Data4[8];
	};

	struct CodeViewInfoPDB70
	{
		GUID Signature;
		uint32_t Age;
	};

	class PEView: public BinaryView
	{
		bool m_parseOnly, m_backedByDatabase;
		uint64_t m_entryPoint;

		uint64_t m_peImageBase;
		uint64_t m_imageBase;
		uint32_t m_sizeOfHeaders;
		std::vector<PEDataDirectory> m_dataDirs;
		std::vector<PESection> m_sections;
		Ref<Architecture> m_arch;
		bool m_is64;
		bool m_extractMangledTypes;
		bool m_simplifyTemplates;
		Ref<Logger> m_logger;
		bool m_relocatable = false;

		SymbolQueue* m_symbolQueue = nullptr;

		Ref<Metadata> m_symExternMappingMetadata;

		uint64_t RVAToFileOffset(uint64_t rva, bool except = true);
		uint32_t GetRVACharacteristics(uint64_t rva);
		std::string ReadString(uint64_t rva);
		uint16_t Read16(uint64_t rva);
		uint32_t Read32(uint64_t rva);
		uint64_t Read64(uint64_t rva);
		void AddPESymbol(BNSymbolType type, const std::string& dll, const std::string& name, uint64_t addr,
			BNSymbolBinding binding = NoBinding, uint64_t ordinal = 0, std::vector<Ref<TypeLibrary>> lib = {});

	protected:
		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override { return LittleEndian; }
		virtual bool PerformIsRelocatable() const override { return m_relocatable; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		PEView(BinaryView* data, bool parseOnly = false);

		virtual bool Init() override;
	};

	class PEViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		PEViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitPEViewType();
}

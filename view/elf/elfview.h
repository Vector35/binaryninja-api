#pragma once

#include "binaryninjaapi.h"
#include <exception>

#define ELF_PT_NULL    0
#define ELF_PT_LOAD    1
#define ELF_PT_DYNAMIC 2
#define ELF_PT_INTERP  3
#define ELF_PT_NOTE    4
#define ELF_PT_SHLIB   5
#define ELF_PT_PHDR    6
#define ELF_PT_TLS     7 /* Thread-local storage segment */
#define ELF_PT_NUM     8 /* Number of defined types */
#define ELF_PT_LOOS         0x60000000 /* Start of OS-specific */
#define ELF_PT_GNU_EH_FRAME 0x6474e550 /* GCC .eh_frame_hdr segment */
#define ELF_PT_GNU_STACK    0x6474e551 /* Indicates stack executability */
#define ELF_PT_GNU_RELRO    0x6474e552 /* Read-only after relocation */

#define ELF_PT_LOSUNW    0x6ffffffa
#define ELF_PT_SUNWBSS   0x6ffffffb
#define ELF_PT_SUNWSTACK 0x6ffffffa
#define ELF_PT_HISUNW    0x6fffffff
#define ELF_PT_LOPROC    0x70000000
#define ELF_PT_HIPROC    0x7fffffff

#define ELF_PT_MIPS_REGINFO  0x70000000 /* Register usage information */
#define ELF_PT_MIPS_RTPROC   0x70000001 /* Runtime procedure table */
#define ELF_PT_MIPS_OPTIONS  0x70000002
#define ELF_PT_MIPS_ABIFLAGS 0x70000003 /* FP mode requirement */

// x86-64 program header types.
// These all contain stack unwind tables.
#define ELF_PT_GNU_EH_FRAME      0x6474e550
#define ELF_PT_SUNW_EH_FRAME     0x6474e550
#define ELF_PT_SUNW_UNWIND       0x6464e550
#define ELF_PT_GNU_STACK         0x6474e551 // Indicates stack executability.
#define ELF_PT_GNU_RELRO         0x6474e552 // Read-only after relocation.
#define ELF_PT_OPENBSD_RANDOMIZE 0x65a3dbe6 // Fill with random data.
#define ELF_PT_OPENBSD_WXNEEDED  0x65a3dbe7 // Program does W^X violations.
#define ELF_PT_OPENBSD_BOOTDATA  0x65a41be6 // Section for boot arguments.
 // ARM program header types.
#define PT_ARM_ARCHEXT   0x70000000 // Platform architecture compatibility info
 // These all contain stack unwind tables.
#define PT_ARM_EXIDX     0x70000001
#define PT_ARM_UNWIND    0x70000001

 // MIPS program header types.
#define PT_MIPS_REGINFO  0x70000000 // Register usage information.
#define PT_MIPS_RTPROC   0x70000001 // Runtime procedure table.
#define PT_MIPS_OPTIONS  0x70000002 // Options segment.
#define PT_MIPS_ABIFLAGS 0x70000003 // Abiflags segment.

 // WebAssembly program header types.
 #define PT_WEBASSEMBLY_FUNCTIONS ELF_PT_LOPROC + 0 // Function definitions.

#define ELF_DT_NULL     0
#define ELF_DT_NEEDED   1
#define ELF_DT_PLTRELSZ 2
#define ELF_DT_PLTGOT   3
#define ELF_DT_HASH     4
#define ELF_DT_STRTAB   5
#define ELF_DT_SYMTAB   6
#define ELF_DT_RELA     7
#define ELF_DT_RELASZ   8
#define ELF_DT_RELAENT  9
#define ELF_DT_STRSZ    10
#define ELF_DT_DYNSYM   11
#define ELF_DT_SYMENT   11
#define ELF_DT_INIT     12
#define ELF_DT_FINI     13
#define ELF_DT_SONAME   14
#define ELF_DT_RPATH    15
#define ELF_DT_SYMBOLIC 16
#define ELF_DT_REL      17
#define ELF_DT_RELSZ    18
#define ELF_DT_RELENT   19
#define ELF_DT_PLTREL   20
#define ELF_DT_DEBUG    21
#define ELF_DT_TEXTREL  22
#define ELF_DT_JMPREL   23
#define ELF_DT_BIND_NOW 24
#define ELF_DT_INIT_ARRAY   25
#define ELF_DT_FINI_ARRAY   26
#define ELF_DT_INIT_ARRAYSZ 27
#define ELF_DT_FINI_ARRAYSZ 28
#define ELF_DT_RUNPATH      29
#define ELF_DT_FLAGS        30
#define ELF_DT_ENCODING     31
#define ELF_DT_PREINIT_ARRAY 32
#define ELF_DT_PREINIT_ARRAYSZ 33

#define ELF_DT_LOOS         0x6000000D
#define ELF_DT_SUNW_RTLDINF 0x6000000E
#define ELF_DT_HIOS         0x6FFFF000
#define ELF_DT_VALRNGLO     0x6FFFFD00
#define ELF_DT_CHECKSUM     0x6FFFFDF8
#define ELF_DT_PLTPADSZ     0x6FFFFDF9
#define ELF_DT_MOVEEN       0x6FFFFDFA
#define ELF_DT_MOVES        0x6FFFFDFB
#define ELF_DT_FEATURE_1    0x6FFFFDFC
#define ELF_DT_POSFLAG_1    0x6FFFFDFD
#define ELF_DT_SYMINSZ      0x6FFFFDFE
#define ELF_DT_SYMINENT     0x6FFFFDFF
#define ELF_DT_VALRNGH      0x6FFFFDFF
#define ELF_DT_ADDRRNGLO    0x6FFFFE00
#define ELF_DT_GNU_HASH     0x6FFFFEF5
#define ELF_DT_CONFIG       0x6FFFFEFA
#define ELF_DT_DEPAUDIT     0x6FFFFEFB
#define ELF_DT_AUDIT        0x6FFFFEFC
#define ELF_DT_PLTPAD       0x6FFFFEFD
#define ELF_DT_MOVETAB      0x6FFFFEFE
#define ELF_DT_SYMINFO      0x6FFFFEFF
#define ELF_DT_ADDRRNGHI    0x6FFFFEFF
#define ELF_DT_RELACOUNT    0x6FFFFFF9
#define ELF_DT_RELCOUNT     0x6FFFFFFA
#define ELF_DT_FLAGS_1      0x6FFFFFFB
#define ELF_DT_VERDEF       0x6FFFFFFC
#define ELF_DT_VERDEFNUM    0x6FFFFFFD
#define ELF_DT_VERNEED      0x6FFFFFFE
#define ELF_DT_VERNEEDNUM   0x6FFFFFFF
#define ELF_DT_VERSYM       0x6FFFFFF0

#define ELF_DT_LOPROC	0x70000000

#define ELF_DT_SPARC_REGISTER     0x70000001

#define ELF_DT_MIPS_RLD_VERSION   0x70000001
#define ELF_DT_MIPS_TIME_STAMP    0x70000002
#define ELF_DT_MIPS_ICHECKSUM     0x70000003
#define ELF_DT_MIPS_IVERSION      0x70000004
#define ELF_DT_MIPS_FLAGS         0x70000005
#define ELF_DT_MIPS_BASE_ADDRESS  0x70000006
#define ELF_DT_MIPS_CONFLICT      0x70000008
#define ELF_DT_MIPS_LIBLIST       0x70000009
#define ELF_DT_MIPS_LOCAL_GOTNO   0x7000000A
#define ELF_DT_MIPS_CONFLICTNO    0x7000000B
#define ELF_DT_MIPS_LIBLISTNO     0x70000010
#define ELF_DT_MIPS_SYMTABNO      0x70000011
#define ELF_DT_MIPS_UNREFEXTNO    0x70000012
#define ELF_DT_MIPS_GOTSYM        0x70000013
#define ELF_DT_MIPS_HIPAGENO      0x70000014
#define ELF_DT_MIPS_RLD_MAP       0x70000016
#define ELF_DT_MIPS_RLD_MAP_REL   0x70000035

#define ELF_DT_AUXILIARY    0x7FFFFFFD
#define ELF_DT_USED         0x7FFFFFFE
#define ELF_DT_FILTER       0x7FFFFFFF
#define ELF_DT_HIPROC       0x7FFFFFFF

#define ELF_STT_NOTYPE  0
#define ELF_STT_OBJECT  1
#define ELF_STT_FUNC    2
#define ELF_STT_SECTION 3
#define ELF_STT_FILE    4
#define ELF_STT_COMMON  5
#define ELF_STT_TLS     6
// GNU/Linux specific
#define ELF_STT_GNU_IFUNC 10

#define ELF_STB_LOCAL   0
#define ELF_STB_GLOBAL  1
#define ELF_STB_WEAK    2
#define ELF_STB_LOPROC  13
#define ELF_STB_HIPROC  15

#define ELF_ST_TYPE(t) ((t) & 0xf)
#define ELF_ST_BIND(b) ((b) >> 4)

#define ELF_RELOC_COPY      5
#define ELF_RELOC_GLOBAL    6
#define ELF_RELOC_JUMP_SLOT 7

#define ET_NONE   0         // No file type
#define ET_REL    1         // Relocatable file
#define ET_EXEC   2         // Executable file
#define ET_DYN    3         // Shared object file
#define ET_CORE   4         // Core file
#define ET_NUM    5         // Number of defined types

#define EM_NONE      0      // No machine
#define EM_M32       1      // AT&T WE 32100
#define EM_SPARC     2      // SUN SPARC
#define EM_386       3      // Intel 80386
#define EM_68K       4      // Motorola m68k family
#define EM_88K       5      // Motorola m88k family
#define EM_860       7      // Intel 80860
#define EM_MIPS      8      // MIPS R3000 big-endian
#define EM_S370      9      // IBM System/370
#define EM_MIPS_RS3_LE  10  // MIPS R3000 little-endian
#define EM_PARISC   15      // HPPA
#define EM_VPP500   17      // Fujitsu VPP500
#define EM_SPARC32PLUS  18  // Sun's "v8plus"
#define EM_960      19      // Intel 80960
#define EM_PPC      20      // PowerPC
#define EM_PPC64    21      // PowerPC 64-bit
#define EM_S390     22      // IBM S390
#define EM_V800     36      // NEC V800 series
#define EM_FR20     37      // Fujitsu FR20
#define EM_RH32     38      // TRW RH-32
#define EM_RCE      39      // Motorola RCE
#define EM_ARM      40      // ARM
#define EM_FAKE_ALPHA   41  // Digital Alpha
#define EM_SH       42      // Hitachi SH
#define EM_SPARCV9  43      // SPARC v9 64-bit
#define EM_TRICORE  44      // Siemens Tricore
#define EM_ARC      45      // Argonaut RISC Core
#define EM_H8_300   46      // Hitachi H8/300
#define EM_H8_300H  47      // Hitachi H8/300H
#define EM_H8S      48      // Hitachi H8S
#define EM_H8_500   49      // Hitachi H8/500
#define EM_IA_64    50      // Intel Merced
#define EM_MIPS_X   51      // Stanford MIPS-X
#define EM_COLDFIRE 52      // Motorola Coldfire
#define EM_68HC12   53      // Motorola M68HC12
#define EM_MMA      54      // Fujitsu MMA Multimedia Accelerator
#define EM_PCP      55      // Siemens PCP
#define EM_NCPU     56      // Sony nCPU embeeded RISC
#define EM_NDR1     57      // Denso NDR1 microprocessor
#define EM_STARCORE 58      // Motorola Start*Core processor
#define EM_ME16     59      // Toyota ME16 processor
#define EM_ST100    60      // STMicroelectronic ST100 processor
#define EM_TINYJ    61      // Advanced Logic Corp. Tinyj emb.fam
#define EM_X86_64   62      // AMD x86-64 architecture
#define EM_PDSP     63      // Sony DSP Processor
#define EM_FX66     66      // Siemens FX66 microcontroller
#define EM_ST9PLUS  67      // STMicroelectronics ST9+ 8/16 mc
#define EM_ST7      68      // STmicroelectronics ST7 8 bit mc
#define EM_68HC16   69      // Motorola MC68HC16 microcontroller
#define EM_68HC11   70      // Motorola MC68HC11 microcontroller
#define EM_68HC08   71      // Motorola MC68HC08 microcontroller
#define EM_68HC05   72      // Motorola MC68HC05 microcontroller
#define EM_SVX      73      // Silicon Graphics SVx
#define EM_ST19     74      // STMicroelectronics ST19 8 bit mc
#define EM_VAX      75      // Digital VAX
#define EM_CRIS     76      // Axis Communications 32-bit embedded processor
#define EM_JAVELIN  77      // Infineon Technologies 32-bit embedded processor
#define EM_FIREPATH 78      // Element 14 64-bit DSP Processor
#define EM_ZSP      79      // LSI Logic 16-bit DSP Processor
#define EM_MMIX     80      // Donald Knuth's educational 64-bit processor
#define EM_HUANY    81      // Harvard University machine-independent object files
#define EM_PRISM    82      // SiTera Prism
#define EM_AVR      83      // Atmel AVR 8-bit microcontroller
#define EM_FR30     84      // Fujitsu FR30
#define EM_D10V     85      // Mitsubishi D10V
#define EM_D30V     86      // Mitsubishi D30V
#define EM_V850     87      // NEC v850
#define EM_M32R     88      // Mitsubishi M32R
#define EM_MN10300  89      // Matsushita MN10300
#define EM_MN10200  90      // Matsushita MN10200
#define EM_PJ       91      // picoJava
#define EM_OPENRISC 92      // OpenRISC 32-bit embedded processor
#define EM_ARC_A5   93      // ARC Cores Tangent-A5
#define EM_XTENSA   94      // Tensilica Xtensa Architecture
#define EM_ALTERA_NIOS2 113 // Altera Nios II
#define EM_AARCH64  183     // ARM AARCH64
#define EM_TILEPRO  188     // Tilera TILEPro
#define EM_MICROBLAZE   189 // Xilinx MicroBlaze
#define EM_TILEGX   191     // Tilera TILE-Gx
#define EM_NUM      192

// Section Header Types
#define ELF_SHT_NULL     0
#define ELF_SHT_PROGBITS 1
#define ELF_SHT_SYMTAB   2
#define ELF_SHT_STRTAB   3
#define ELF_SHT_RELA     4
#define ELF_SHT_HASH     5
#define ELF_SHT_DYNAMIC  6
#define ELF_SHT_NOTE     7
#define ELF_SHT_NOBITS   8
#define ELF_SHT_REL      9
#define ELF_SHT_SHLIB    10
#define ELF_SHT_DYNSYM   11
#define ELF_SHT_LOPROC   0x70000000 // (take note that this only shows if none of the below are)
#define ELF_SHT_HIPROC   0x7fffffff // (take note that this only shows if none of the below are)
#define ELF_SHT_LOUSER   0x80000000
#define ELF_SHT_HIUSER   0xffffffff

#define ELF_SHT_EXT                 0x70000000  // PA-RISC and Intel Itanium Only - Section contains product-specific extension bits
#define ELF_SHT_UNWIND              0x70000001  // PA-RISC, Intel Itanium, and AMD64 Only - Section contains unwind function table entries for stack unwinding
#define ELF_SHT_PARISC_DOC          0x70000002  // PA-RISC Only - Section contains debug information for optimized code
#define ELF_SHT_PARISC_ANNOT        0x70000003  // PA-RISC Only - Section contains code annotations Name Value Meaning
#define ELF_SHT_IA_64_LOPSREG       0x78000000  // Intel Itanium Only - Low section of operating system identification bits (and implimentation-specific types)
#define ELF_SHT_IA_64_HIPSREG       0x7fffffff  // Intel Itanium Only - High section of operating system identification bits (and implimentation-specific types)
#define ELF_SHT_IA_64_PRIORITY_INIT 0x79000000  // Intel Itanium Only - Section contains priority initialization records

// Section Header Flags
#define ELF_SHF_WRITE            0x1         // Section is writable
#define ELF_SHF_ALLOC            0x2         // Section occupies memory during execution (is a mapped segment)
#define ELF_SHF_EXECINSTR        0x4         // Section is executable
#define ELF_SHF_MASKOS           0x0ff00000  // OS-specific semantics
#define ELF_SHF_MASKPROC         0xf0000000  // Processor specific (take note that this only shows if none of the below are)

// LLVM and GoLang Specific
#define ELF_SHF_MERGE            0x10        // Section may be merged
#define ELF_SHF_STRINGS          0x20        // Section contains strings
#define ELF_SHF_INFO_LINK        0x40        // sh_info holds section index
#define ELF_SHF_LINK_ORDER       0x80        // Special ordering requirements
#define ELF_SHF_OS_NONCONFORMING 0x100       // OS-specific processing required
#define ELF_SHF_GROUP            0x200       // Member of section group
#define ELF_SHF_TLS              0x400       // Section contains TLS data
#define ELF_SHF_COMPRESSED       0x800       // Section is compressed

// Arch Specific
#define ELF_SHF_ENTRYSECT     0x10000000  // ARM only - Section contains an entrypoint
#define ELF_SHF_COMDEF        0x80000000  // ARM only - Section may be multiply defined in the input to a link step
#define ELF_SHF_AMD64_LARGE   0x10000000  // AMD64 Only - Section can be >2GB
#define ELF_SHF_IA_64_SHORT   0x10000000  // Intel Itanium Only - Section contains objects referenced by gp, so must be position near gp
#define ELF_SHF_IA_64_NORECOV 0x20000000  // Intel Itanium Only - Section contains speculative instructions without recovery code
#define ELF_SHF_MIPS_GPREL    0x10000000  // MIPS Only - Section contains global data
#define ELF_SHF_PARISC_SHORT  0x20000000  // PA-RISC Only - Section should be near gp
#define ELF_SHF_PARISC_HUGE   0x40000000  // PA-RISC Only - Section should be allocated far from gp
#define ELF_SHF_PARISC_SBP    0x80000000  // PA-RISC Only - Section contains code compiled for static branch prediction
#define ELF_SHF_EXCLUDE       0x80000000  // PPC Only - Section is excluded from executable and SO's when they're not to be further relocated

#define EV_NONE     0       // Invalid ELF version
#define EV_CURRENT  1       // Current version
#define EV_NUM      2

#define EF_ARM_BE8  0x00800000 // ELF contains BE-8 code for ARMv6 processor

#define PF_X        (1 << 0)    // Segment is executable
#define PF_W        (1 << 1)    // Segment is writable
#define PF_R        (1 << 2)    // Segment is readable

#define ELF_SHN_UNDEF     0
#define ELF_SHN_LORESERVE 0xff00
#define ELF_SHN_LOPROC    0xff00
#define ELF_SHN_HIPROC    0xff1f
#define ELF_SHN_ABS       0xfff1
#define ELF_SHN_COMMON    0xfff2
#define ELF_SHN_HIRESERVE 0xffff

// TODO : Add these (MIPs Only):
// #define ELF_SHN_MIPS_ACOMMON    0xff00
// #define ELF_SHN_MIPS_TEXT       0xff01
// #define ELF_SHN_MIPS_DATA       0xff02
// #define ELF_SHN_MIPS_SCOMMON    0xff03
// #define ELF_SHN_MIPS_SUNDEFINED 0xff04

// ARM ONLY
#define R_ARM_TLS_DTPMOD32 0x11
#define R_ARM_TLS_DTPOFF32 0x12

namespace BinaryNinja
{
	class ElfFormatException: public std::exception
	{
		std::string m_message;

	public:
		ElfFormatException(const std::string& msg = "invalid format"): m_message(msg) {}
		virtual const char* what() const NOEXCEPT { return m_message.c_str(); }
	};

	struct ElfIdent
	{
		char signature[4];
		uint8_t fileClass;
		uint8_t encoding;
		uint8_t version;
		uint8_t os;
		uint8_t abiVersion;
		uint8_t pad[7];
	};

	struct ElfCommonHeader
	{
		uint16_t type;
		uint16_t arch;
		uint32_t version;
	};

	struct Elf32Header
	{
		uint32_t entry;
		uint32_t programHeaderOffset;
		uint32_t sectionHeaderOffset;
		uint32_t flags;
		uint16_t headerSize;
		uint16_t programHeaderSize;
		uint16_t programHeaderCount;
		uint16_t sectionHeaderSize;
		uint16_t sectionHeaderCount;
		uint16_t stringTable;
	};

	struct Elf32ProgramHeader
	{
		uint32_t type;
		uint32_t offset;
		uint32_t virtualAddress;
		uint32_t physicalAddress;
		uint32_t fileSize;
		uint32_t memorySize;
		uint32_t flags;
		uint32_t align;
	};

	struct Elf32SectionHeader
	{
		uint32_t name;
		uint32_t type;
		uint32_t flags;
		uint32_t address;
		uint32_t offset;
		uint32_t size;
		uint32_t link;
		uint32_t info;
		uint32_t align;
		uint32_t entrySize;
	};

	struct Elf64Header
	{
		uint64_t entry;
		uint64_t programHeaderOffset;
		uint64_t sectionHeaderOffset;
		uint32_t flags;
		uint16_t headerSize;
		uint16_t programHeaderSize;
		uint16_t programHeaderCount;
		uint16_t sectionHeaderSize;
		uint16_t sectionHeaderCount;
		uint16_t stringTable;
	};

	struct Elf64ProgramHeader
	{
		uint32_t type;
		uint32_t flags;
		uint64_t offset;
		uint64_t virtualAddress;
		uint64_t physicalAddress;
		uint64_t fileSize;
		uint64_t memorySize;
		uint64_t align;
	};

	struct Elf64SectionHeader
	{
		uint32_t name;
		uint32_t type;
		uint64_t flags;
		uint64_t address;
		uint64_t offset;
		uint64_t size;
		uint32_t link;
		uint32_t info;
		uint64_t align;
		uint64_t entrySize;
	};

	struct ElfSymbolTableEntry
	{
		uint32_t nameOffset;
		uint8_t type;
		BNSymbolBinding binding;
		uint8_t other;
		uint16_t section;
		uint64_t value;
		uint64_t size;
		std::string name;
		bool dynamic;
	};

	struct ELFRelocEntry
	{
		uint64_t offset, sym, relocType, addend;
		size_t sectionIdx;
		bool implicit;
		ELFRelocEntry(uint64_t o, uint64_t s, uint64_t r, uint64_t a, size_t idx, bool imp): offset(o), sym(s), relocType(r),
			addend(a), sectionIdx(idx), implicit(imp) {}
	};

	class ElfView: public BinaryView
	{
		bool m_parseOnly, m_backedByDatabase;
		uint64_t m_entryPoint;
		uint64_t m_sectionHeaderOffset, m_programHeaderOffset;
		size_t m_sectionHeaderCount, m_programHeaderCount;
		uint64_t m_fileSize;
		BNEndianness m_endian;
		size_t m_addressSize;
		ElfIdent m_ident;
		ElfCommonHeader m_commonHeader;
		Ref<Architecture> m_arch;
		Ref<Platform> m_plat = nullptr;
		uint32_t m_headerFlags;
		bool m_elf32;
		bool m_objectFile;
		Ref<Logger> m_logger;
		bool m_extractMangledTypes;
		bool m_simplifyTemplates;
		bool m_relocatable = false;
		std::map<uint64_t, std::vector<char>> m_stringTableCache;

		// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
		std::vector<Elf64SectionHeader> m_elfSections;
		std::vector<Elf64ProgramHeader> m_programHeaders;
		Elf64SectionHeader m_symbolTableSection, m_dynamicSymbolTableSection;
		Elf64SectionHeader m_auxSymbolTable, m_dynamicStringTable, m_sectionStringTable, m_sectionOpd;
		Elf64ProgramHeader m_dynamicTable;
		Elf64ProgramHeader m_tlsSegment;
		std::map<uint64_t, uint64_t> m_localGotEntries;
		std::set<uint64_t> m_gotEntryLocations;
		std::vector<BNRelocationInfo> m_relocationInfo;

		size_t m_auxSymbolTableEntrySize = 0;
		size_t m_numDynamicTableEntries = 0;
		uint64_t m_hashHeader = 0;
		uint64_t m_gnuHashHeader = 0;

		SymbolQueue* m_symbolQueue = nullptr;

		void DefineElfSymbol(BNSymbolType type, const std::string& name, uint64_t addr, bool gotEntry,
			BNSymbolBinding binding, size_t size, Ref<Type> typeObj=nullptr);

		void ApplyTypesToParentStringTable(const Elf64SectionHeader& section, const bool offset = true);
		void ApplyTypesToStringTable(const Elf64SectionHeader& section, const int64_t imageBaseAdjustment, const bool offset = true);
		std::string ReadStringTable(BinaryReader& view, const Elf64SectionHeader& section, uint64_t offset);
		bool ParseSymbolTableEntry(BinaryReader& reader, ElfSymbolTableEntry& entry, uint64_t sym,
			const Elf64SectionHeader& symbolTable, const Elf64SectionHeader& stringTable, bool dynamic);

		std::vector<ElfSymbolTableEntry> ParseSymbolTable(BinaryReader& reader, const Elf64SectionHeader& symbolTableSection,
			const Elf64SectionHeader& section, bool dynamic, size_t startEntry=0);

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override;
		virtual size_t PerformGetAddressSize() const override;
		void GetRelocEntries(BinaryReader& reader, const std::vector<Elf64SectionHeader>& sections,
			bool implicit, std::vector<ELFRelocEntry>& result);
		bool DerefPpc64Descriptor(BinaryReader& reader, uint64_t addr, uint64_t& result);
	public:
		ElfView(BinaryView* data, bool parseOnly = false);
		~ElfView();

		virtual bool Init() override;
	};

	class ElfViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		ElfViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual uint64_t ParseHeaders(BinaryView* data, ElfIdent& ident, ElfCommonHeader& commonHeader, Elf64Header& header, Ref<Architecture>* arch, Ref<Platform>* plat, std::string& errorMsg, BNEndianness& endianness);
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitElfViewType();
}

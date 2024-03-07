#pragma once

#include "binaryninjaapi.h"
#include "peview.h"
#include <exception>

#ifdef WIN32
#pragma warning(disable: 4005)
#endif

#define IMAGE_SYM_TYPE_NULL 0    // No type information or unknown base type.
#define IMAGE_SYM_TYPE_VOID 1    // Used with void pointers and functions.
#define IMAGE_SYM_TYPE_CHAR 2    // A character (signed byte).
#define IMAGE_SYM_TYPE_SHORT 3   // A 2-byte signed integer.
#define IMAGE_SYM_TYPE_INT 4     // A natural integer type on the target.
#define IMAGE_SYM_TYPE_LONG 5    // A 4-byte signed integer.
#define IMAGE_SYM_TYPE_FLOAT 6   // A 4-byte floating-point number.
#define IMAGE_SYM_TYPE_DOUBLE 7  // An 8-byte floating-point number.
#define IMAGE_SYM_TYPE_STRUCT 8  // A structure.
#define IMAGE_SYM_TYPE_UNION 9   // An union.
#define IMAGE_SYM_TYPE_ENUM 10   // An enumerated type.
#define IMAGE_SYM_TYPE_MOE 11    // A member of enumeration (a specific value).
#define IMAGE_SYM_TYPE_BYTE 12   // A byte; unsigned 1-byte integer.
#define IMAGE_SYM_TYPE_WORD 13   // A word; unsigned 2-byte integer.
#define IMAGE_SYM_TYPE_UINT 14   // An unsigned integer of natural size.
#define IMAGE_SYM_TYPE_DWORD 15  // An unsigned 4-byte integer.

#define MS_IMAGE_SYM_TYPE_FUNCTION 0x20 // Microsoft-specific

#define IMAGE_REL_I386_ABSOLUTE 0x0000
#define IMAGE_REL_I386_DIR16 0x0001
#define IMAGE_REL_I386_REL16 0x0002
#define IMAGE_REL_I386_DIR32 0x0006
#define IMAGE_REL_I386_DIR32NB 0x0007
#define IMAGE_REL_I386_SEG12 0x0009
#define IMAGE_REL_I386_SECTION 0x000A
#define IMAGE_REL_I386_SECREL 0x000B
#define IMAGE_REL_I386_TOKEN 0x000C
#define IMAGE_REL_I386_SECREL7 0x000D
#define IMAGE_REL_I386_REL32 0x0014

#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32 0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009
#define IMAGE_REL_AMD64_SECTION 0x000A
#define IMAGE_REL_AMD64_SECREL 0x000B
#define IMAGE_REL_AMD64_SECREL7 0x000C
#define IMAGE_REL_AMD64_TOKEN 0x000D
#define IMAGE_REL_AMD64_SREL32 0x000E
#define IMAGE_REL_AMD64_PAIR 0x000F
#define IMAGE_REL_AMD64_SSPAN32 0x0010

#define IMAGE_REL_ARM_ABSOLUTE 0x0000
#define IMAGE_REL_ARM_ADDR32 0x0001
#define IMAGE_REL_ARM_ADDR32NB 0x0002
#define IMAGE_REL_ARM_BRANCH24 0x0003
#define IMAGE_REL_ARM_BRANCH11 0x0004
#define IMAGE_REL_ARM_BLX24 0x0008
#define IMAGE_REL_ARM_BLX11 0x0009
#define IMAGE_REL_ARM_REL32 0x000A
#define IMAGE_REL_ARM_SECTION 0x000E
#define IMAGE_REL_ARM_SECREL 0x000F
#define IMAGE_REL_ARM_MOV32 0x0010
#define IMAGE_REL_THUMB_MOV32 0x0011
#define IMAGE_REL_THUMB_BRANCH20 0x0012
#define IMAGE_REL_THUMB_UNUSED 0x0013
#define IMAGE_REL_THUMB_BRANCH24 0x0014
#define IMAGE_REL_THUMB_BLX23 0x0015
#define IMAGE_REL_ARM_PAIR 0x0016

// The following names for armv7/thumb2 relocations are from LLVM source,
// but are commented out in favor of the names defined above,
// which correspond to Microsoft PE Format documentation:
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#type-indicators
// #define IMAGE_REL_ARM_ABSOLUTE 0x0000
// #define IMAGE_REL_ARM_ADDR32 0x0001
// #define IMAGE_REL_ARM_ADDR32NB 0x0002
// #define IMAGE_REL_ARM_BRANCH24 0x0003
// #define IMAGE_REL_ARM_BRANCH11 0x0004
// #define IMAGE_REL_ARM_TOKEN 0x0005
// #define IMAGE_REL_ARM_BLX24 0x0008
// #define IMAGE_REL_ARM_BLX11 0x0009
// #define IMAGE_REL_ARM_REL32 0x000A
// #define IMAGE_REL_ARM_SECTION 0x000E
// #define IMAGE_REL_ARM_SECREL 0x000F
// #define IMAGE_REL_ARM_MOV32A 0x0010
// #define IMAGE_REL_ARM_MOV32T 0x0011
// #define IMAGE_REL_ARM_BRANCH20T 0x0012
// #define IMAGE_REL_ARM_BRANCH24T 0x0014
// #define IMAGE_REL_ARM_BLX23T 0x0015
// #define IMAGE_REL_ARM_PAIR 0x0016

#define IMAGE_REL_ARM64_ABSOLUTE 0x0000
#define IMAGE_REL_ARM64_ADDR32 0x0001
#define IMAGE_REL_ARM64_ADDR32NB 0x0002
#define IMAGE_REL_ARM64_BRANCH26 0x0003
#define IMAGE_REL_ARM64_PAGEBASE_REL21 0x0004
#define IMAGE_REL_ARM64_REL21 0x0005
#define IMAGE_REL_ARM64_PAGEOFFSET_12A 0x0006
#define IMAGE_REL_ARM64_PAGEOFFSET_12L 0x0007
#define IMAGE_REL_ARM64_SECREL 0x0008
#define IMAGE_REL_ARM64_SECREL_LOW12A 0x0009
#define IMAGE_REL_ARM64_SECREL_HIGH12A 0x000A
#define IMAGE_REL_ARM64_SECREL_LOW12L 0x000B
#define IMAGE_REL_ARM64_TOKEN 0x000C
#define IMAGE_REL_ARM64_SECTION 0x000D
#define IMAGE_REL_ARM64_ADDR64 0x000E
#define IMAGE_REL_ARM64_BRANCH19 0x000F
#define IMAGE_REL_ARM64_BRANCH14 0x0010
#define IMAGE_REL_ARM64_REL32 0x0011

namespace BinaryNinja
{
	class COFFFormatException: public std::exception
	{
		std::string m_message;

	public:
		COFFFormatException(const std::string& msg = "invalid format"): m_message(msg) {}
		virtual const char* what() const NOEXCEPT { return m_message.c_str(); }
	};

	#pragma pack(push, 2)
	struct COFFHeader
	{
		uint16_t machine;
		uint16_t sectionCount;
		uint32_t timestamp;
		uint32_t coffSymbolTable;
		uint32_t coffSymbolCount;
		uint16_t optionalHeaderSize;
		uint16_t characteristics;
	};

	// Use this for sizeof
	struct COFFSectionHeader
	{
		uint8_t name[8];
		union
		{
			uint32_t virtualSize;
			uint32_t physicalAddress;
		};
		uint32_t virtualAddress;
		uint32_t sizeOfRawData;
		uint32_t pointerToRawData;
		uint32_t pointerToRelocs;
		uint32_t pointerToLineNumbers;
		uint16_t relocCount;
		uint16_t lineNumberCount;
		uint32_t characteristics;
	};

	// Can only find reference to this alernate COFF header in the LLVM source and docs:
	// https://llvm.org/doxygen/structllvm_1_1COFF_1_1BigObjHeader.html
	// https://github.com/llvm/llvm-project/commit/44f51e511374f467d70c37324a8e5bbf2ea270d8#diff-c8c9ae93373622c2303ca157ecdc8bf16204567b57e391381ed4740e0c38c82aR67-R82
	struct BigObj_COFFHeader
	{
		uint16_t sig1;	///< Must be IMAGE_FILE_MACHINE_UNKNOWN (0).
		uint16_t sig2;	///< Must be 0xFFFF.
		uint16_t version;
		uint16_t machine;
		uint32_t timestamp;
		uint8_t  UUID[16];
		uint32_t unused1;
		uint32_t unused2;
		uint32_t unused3;
		uint32_t unused4;
		uint32_t sectionCount;
		uint32_t coffSymbolTable;
		uint32_t coffSymbolCount;
	};

	struct COFFSection
	{
		std::string name;
		union
		{
			uint32_t virtualSize;
			uint32_t physicalAddress;
		};
		uint32_t virtualAddress;
		uint32_t sizeOfRawData;
		uint32_t pointerToRawData;
		uint32_t pointerToRelocs;
		uint32_t pointerToLineNumbers;
		uint16_t relocCount;
		uint16_t lineNumberCount;
		uint32_t characteristics;
	};


	template<typename SectionCountType> struct _COFFSymbol
	{
		union
		{
			char shortName[8];
			struct {
				uint32_t zeroes;
				uint32_t offset;
			} longName;
		} name;
		uint32_t value;
		// 1-based index into section table
		SectionCountType sectionNumber;
		uint16_t type;
		uint8_t storageClass;
		uint8_t numberOfAuxSymbols;
	};

	using COFFSymbol16 = _COFFSymbol<uint16_t>;
	using COFFSymbol32 = _COFFSymbol<uint32_t>;

	struct COFFSymbol
	{
		union
		{
			char shortName[8];
			struct {
				uint32_t zeroes;
				uint32_t offset;
			} longName;
		} name;
		uint32_t value;
		// 1-based index into section table
		union { int16_t i16; int32_t i32; } sectionNumber;
		uint16_t type;
		uint8_t storageClass;
		uint8_t numberOfAuxSymbols;
	};

	struct COFFAuxFunctionDefinition
	{
		uint32_t tagIndex;
		uint32_t totalSize;
		uint32_t pointerToLineNumber;
		uint32_t pointerToNextFunction;
		uint8_t unused[2];
	};

	struct COFFAux_bf_And_ef_Symbol
	{
		uint8_t unused0[4];
		uint16_t lineNumber;
		uint8_t unused6[6];
		uint32_t pointerToNextFunction;
		uint8_t unused16[2];
	};

	struct COFFAuxWeakExternal
	{
		uint32_t tagIndex;
		uint32_t characteristics;
		uint8_t unused[10];
	};

	struct COFFAuxFile
	{
		uint8_t fileName[18];
	};

	#pragma pack(push, 1)
	struct COFFAuxSectionDefinition
	{
		uint32_t length;
		uint16_t numberOfRelocations;
		uint16_t numberOfLineNumbers;
		uint32_t checkSum;
		uint16_t number;
		uint8_t selection;
		union {
			uint8_t unused3[3];
			struct
			{
				uint8_t unused;
				uint16_t numberHighPart;
			};
		};
	};
	#pragma pack(pop)

	union COFFAuxSymbolRecord
	{
		COFFAuxFunctionDefinition functionDefinition;
		COFFAux_bf_And_ef_Symbol bf_And_ef_Symbol;
		COFFAuxWeakExternal weakExternal;
		COFFAuxFile file;
		COFFAuxSectionDefinition sectionDefinition;
	};

	struct COFFRelocation
	{
		uint32_t virtualAddress;
		uint32_t symbolTableIndex;
		// union
		// {
			// enum x64_coff_reloc_type x64_type;
			// enum arm_coff_reloc_type arm_type;
			// enum x86_coff_reloc_type x86_type;
			uint16_t type;
		// };
		// COFFRelocation(uint32_t va, uint32_t i, uint16_t t) : virtualAddress(va), symbolTableIndex(i), type(t) {}
	};

	struct COFF_PdataFunctionTableEntry
	{
		uint32_t beginAddress;
		uint32_t endAddress;
		uint32_t unwindInformation;
	};

	#pragma pack(pop)

	class COFFView : public BinaryView
	{
		bool m_parseOnly;
		uint64_t m_entryPoint;

		uint64_t m_imageBase;
		uint32_t m_sizeOfHeaders;
		std::vector<COFFSection> m_sections;
		std::vector<COFFRelocation> m_relocs;
		Ref<Architecture> m_arch;
		bool m_is64;
		bool m_extractMangledTypes;
		bool m_simplifyTemplates;
		bool m_relocatable = false;

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override { return LittleEndian; }
		virtual bool PerformIsRelocatable() const override { return m_relocatable; }
		virtual size_t PerformGetAddressSize() const override;

		uint64_t RVAToFileOffset(uint64_t rva, bool except = true);
		uint32_t GetRVACharacteristics(uint64_t rva);
		std::string ReadString(uint64_t rva);
		uint16_t Read16(uint64_t rva);
		uint32_t Read32(uint64_t rva);
		uint64_t Read64(uint64_t rva);
		void AddCOFFSymbol(BNSymbolType type, const std::string& dll, const std::string& name, uint64_t addr,
			BNSymbolBinding binding = NoBinding, uint64_t ordinal = 0, TypeLibrary* lib = nullptr);
		// void COFFView::GetRelocs(BinaryReader& reader, const vector<COFFSection>& sections, vector<COFFRelocation>& result, const QualifiedName& coffRelocTypeName, const map<uint64_t, string>& symbolNames);

	public:
		COFFView(BinaryView* data, bool parseOnly = false);

		virtual bool Init() override;
	};

	class COFFViewType: public BinaryViewType
	{
	public:
		COFFViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
		static bool IsValidMachineType(uint16_t machineType);
		static bool IsSupportedMachineType(uint16_t machineType);
	};

	void InitCOFFViewType();
}

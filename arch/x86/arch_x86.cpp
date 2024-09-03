#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include "binaryninjaapi.h"
#include "il.h"
extern "C" {
    #include "xed-interface.h"
}
#include "arch_x86_common_architecture.h"

using namespace BinaryNinja;
using namespace std;

enum Elfx86RelocationType : uint32_t
{
	R_386_NONE              = 0,  // No relocation.
	R_386_32                = 1,  // Add symbol value.
	R_386_PC32              = 2,  // Add PC-relative symbol value.
	R_386_GOT32             = 3,  // Add PC-relative GOT offset.
	R_386_PLT32             = 4,  // Add PC-relative PLT offset.
	R_386_COPY              = 5,  // Copy data from shared object.
	R_386_GLOB_DAT          = 6,  // Set GOT entry to data address.
	R_386_JUMP_SLOT         = 7,  // Set GOT entry to code address.
	R_386_RELATIVE          = 8,  // Add load address of shared object.
	R_386_GOTOFF            = 9,  // Add GOT-relative symbol address.
	R_386_GOTPC             = 10, // Add PC-relative GOT table address.
	R_386_TLS_TPOFF         = 14, // Negative offset in static TLS block
	R_386_TLS_IE            = 15, // Absolute address of GOT for -ve static TLS
	R_386_TLS_GOTIE         = 16, // GOT entry for negative static TLS block
	R_386_TLS_LE            = 17, // Negative offset relative to static TLS
	R_386_TLS_GD            = 18, // 32 bit offset to GOT (index,off) pair
	R_386_TLS_LDM           = 19, // 32 bit offset to GOT (index,zero) pair
	R_386_16                = 20, //
	R_386_PC16              = 21, //
	R_386_8                 = 22, //
	R_386_PC8               = 23, //
	R_386_TLS_GD_32         = 24, // 32 bit offset to GOT (index,off) pair
	R_386_TLS_GD_PUSH       = 25, // pushl instruction for Sun ABI GD sequence
	R_386_TLS_GD_CALL       = 26, // call instruction for Sun ABI GD sequence
	R_386_TLS_GD_POP        = 27, // popl instruction for Sun ABI GD sequence
	R_386_TLS_LDM_32        = 28, // 32 bit offset to GOT (index,zero) pair
	R_386_TLS_LDM_PUSH      = 29, // pushl instruction for Sun ABI LD sequence
	R_386_TLS_LDM_CALL      = 30, // call instruction for Sun ABI LD sequence
	R_386_TLS_LDM_POP       = 31, // popl instruction for Sun ABI LD sequence
	R_386_TLS_LDO_32        = 32, // 32 bit offset from start of TLS block
	R_386_TLS_IE_32         = 33, // 32 bit offset to GOT static TLS offset entry
	R_386_TLS_LE_32         = 34, // 32 bit offset within static TLS block
	R_386_TLS_DTPMOD32      = 35, // GOT entry containing TLS index
	R_386_TLS_DTPOFF32      = 36, // GOT entry containing TLS offset
	R_386_TLS_TPOFF32       = 37, // GOT entry of -ve static TLS offset
	R_386_SIZE32            = 38, //
	R_386_TLS_GOTDESC       = 39, //
	R_386_TLS_DESC_CALL     = 40, //
	R_386_TLS_DESC          = 41, //
	R_386_IRELATIVE         = 42, // PLT entry resolved indirectly at runtime
	MAX_ELF_X86_RELOCATION
};

enum Elfx64RelocationType : uint32_t
{
	R_X86_64_NONE            = 0,   // No reloc
	R_X86_64_64              = 1,   // Direct 64 bit
	R_X86_64_PC32            = 2,   // PC relative 32 bit signed
	R_X86_64_GOT32           = 3,   // 32 bit GOT entry
	R_X86_64_PLT32           = 4,   // 32 bit PLT address
	R_X86_64_COPY            = 5,   // Copy symbol at runtime
	R_X86_64_GLOB_DAT        = 6,   // Create GOT entry
	R_X86_64_JUMP_SLOT       = 7,   // Create PLT entry
	R_X86_64_RELATIVE        = 8,   // Adjust by program base
	R_X86_64_GOTPCREL        = 9,   // 32 bit signed pc relative offset to GOT
	R_X86_64_32              = 10,  // Direct 32 bit zero extended
	R_X86_64_32S             = 11,  // Direct 32 bit sign extended
	R_X86_64_16              = 12,  // Direct 16 bit zero extended
	R_X86_64_PC16            = 13,  // 16 bit sign extended pc relative
	R_X86_64_8               = 14,  // Direct 8 bit sign extended
	R_X86_64_PC8             = 15,  // 8 bit sign extended pc relative
	R_X86_64_DTPMOD64        = 16,
	R_X86_64_DTPOFF64        = 17,
	R_X86_64_TPOFF64         = 18,
	R_X86_64_TLSGD           = 19,
	R_X86_64_TLSLD           = 20,
	R_X86_64_DTPOFF32        = 21,
	R_X86_64_GOTTPOFF        = 22,
	R_X86_64_TPOFF32         = 23,
	R_X86_64_PC64            = 24,
	R_X86_64_GOTOFF64        = 25,
	R_X86_64_GOTPC32         = 26,
	R_X86_64_UNKNOWN27       = 27,
	R_X86_64_UNKNOWN28       = 28,
	R_X86_64_UNKNOWN29       = 29,
	R_X86_64_UNKNOWN30       = 30,
	R_X86_64_UNKNOWN31       = 31,
	R_X86_64_SIZE32          = 32,
	R_X86_64_SIZE64          = 33,
	R_X86_64_GOTPC32_TLSDESC = 34,
	R_X86_64_TLSDESC_CALL    = 35,
	R_X86_64_TLSDESC         = 36,
	R_X86_64_IRELATIVE       = 37,
	R_X86_64_RELATIVE64      = 38,
	R_X86_64_PC32_BND        = 39,
	R_X86_64_PLT32_BND       = 40,
	R_X86_64_GOTPCRELX       = 41,
	R_X86_64_REX_GOTPCRELX   = 42,
	MAX_ELF_X64_RELOCATION
};

enum Machox86RelocationType : uint32_t
{
	GENERIC_RELOC_VANILLA = 0,
	GENERIC_RELOC_PAIR = 1,
	GENERIC_RELOC_SECTDIFF = 2,
	GENERIC_RELOC_PB_LA_PTR = 3,
	GENERIC_RELOC_LOCAL_SECTDIFF = 4,
	GENERIC_RELOC_TLV = 5,
	MACHO_MAX_X86_RELOCATION
};

enum Machox64RelocationType : uint32_t
{
	X86_64_RELOC_UNSIGNED = 0,
	X86_64_RELOC_SIGNED = 1,
	X86_64_RELOC_BRANCH = 2,
	X86_64_RELOC_GOT_LOAD = 3,
	X86_64_RELOC_GOT = 4,
	X86_64_RELOC_SUBTRACTOR = 5,
	X86_64_RELOC_SIGNED_1 = 6,
	X86_64_RELOC_SIGNED_2 = 7,
	X86_64_RELOC_SIGNED_4 = 8,
	X86_64_RELOC_TLV = 9,
	MACHO_MAX_X86_64_RELOCATION
};

enum COFFx86RelocationType : uint32_t
{
	PE_IMAGE_REL_I386_ABSOLUTE = 0x0000,  // The relocation is ignored.
	PE_IMAGE_REL_I386_DIR16    = 0x0001,  // Not supported.
	PE_IMAGE_REL_I386_REL16    = 0x0002,  // Not supported.
	PE_IMAGE_REL_I386_DIR32    = 0x0006,  // The target's 32-bit VA.
	PE_IMAGE_REL_I386_DIR32NB  = 0x0007,  // The target's 32-bit RVA.
	PE_IMAGE_REL_I386_SEG12    = 0x0009,  // Not supported.
	PE_IMAGE_REL_I386_SECTION  = 0x000A,  // The 16-bit section index of the section that contains the target. This is used to support debugging information.
	PE_IMAGE_REL_I386_SECREL   = 0x000B,  // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	PE_IMAGE_REL_I386_TOKEN    = 0x000C,  // The CLR token.
	PE_IMAGE_REL_I386_SECREL7  = 0x000D,  // A 7-bit offset from the base of the section that contains the target.
	PE_IMAGE_REL_I386_REL32    = 0x0014,  // The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions.
	MAX_PE_X86_RELOCATION
};

enum COFFx64RelocationType : uint32_t
{
	PE_IMAGE_REL_AMD64_ABSOLUTE = 0x0000, // The relocation is ignored.
	PE_IMAGE_REL_AMD64_ADDR64   = 0x0001, // The 64-bit VA of the relocation target.
	PE_IMAGE_REL_AMD64_ADDR32   = 0x0002, // The 32-bit VA of the relocation target.
	PE_IMAGE_REL_AMD64_ADDR32NB = 0x0003, // The 32-bit address without an image base (RVA).
	PE_IMAGE_REL_AMD64_REL32    = 0x0004, // The 32-bit relative address from the byte following the relocation.
	PE_IMAGE_REL_AMD64_REL32_1  = 0x0005, // The 32-bit address relative to byte distance 1 from the relocation.
	PE_IMAGE_REL_AMD64_REL32_2  = 0x0006, // The 32-bit address relative to byte distance 2 from the relocation.
	PE_IMAGE_REL_AMD64_REL32_3  = 0x0007, // The 32-bit address relative to byte distance 3 from the relocation.
	PE_IMAGE_REL_AMD64_REL32_4  = 0x0008, // The 32-bit address relative to byte distance 4 from the relocation.
	PE_IMAGE_REL_AMD64_REL32_5  = 0x0009, // The 32-bit address relative to byte distance 5 from the relocation.
	PE_IMAGE_REL_AMD64_SECTION  = 0x000A, // The 16-bit section index of the section that contains the target. This is used to support debugging information.
	PE_IMAGE_REL_AMD64_SECREL   = 0x000B, // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	PE_IMAGE_REL_AMD64_SECREL7  = 0x000C, // A 7-bit unsigned offset from the base of the section that contains the target.
	PE_IMAGE_REL_AMD64_TOKEN    = 0x000D, // CLR tokens.
	PE_IMAGE_REL_AMD64_SREL32   = 0x000E, // A 32-bit signed span-dependent value emitted into the object.
	PE_IMAGE_REL_AMD64_PAIR     = 0x000F, // A pair that must immediately follow every span-dependent value.
	PE_IMAGE_REL_AMD64_SSPAN32  = 0x0010, // A 32-bit signed span-dependent value that is applied at link time.
	MAX_PE_X64_RELOCATION
};

enum PeRelocationType : uint32_t
{
	PE_IMAGE_USER_DEFINED             = 0xffffffff, // User defined relocation type for synthesized relocations at IAT sites.
	PE_IMAGE_REL_BASED_ABSOLUTE       = 0,  // The base relocation is skipped. This type can be used to pad a block.
	PE_IMAGE_REL_BASED_HIGH           = 1,  // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
	PE_IMAGE_REL_BASED_LOW            = 2,  // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
	PE_IMAGE_REL_BASED_HIGHLOW        = 3,  // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
	PE_IMAGE_REL_BASED_HIGHADJ        = 4,  // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
	PE_IMAGE_REL_BASED_MIPS_JMPADDR   = 5,  // The relocation interpretation is dependent on the machine type. When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
	PE_IMAGE_REL_BASED_ARM_MOV32      = 5,  // This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
	PE_IMAGE_REL_BASED_RISCV_HIGH20   = 5,  // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
	PE_IMAGE_REL_BASE_RESERVED        = 6,  // Reserved, must be zero.
	PE_IMAGE_REL_BASED_THUMB_MOV32    = 7,  // This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
	PE_IMAGE_REL_BASED_RISCV_LOW12I   = 7,  // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
	PE_IMAGE_REL_BASED_RISCV_LOW12S   = 8,  // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
	PE_IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,  // The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
	PE_IMAGE_REL_BASED_DIR64          = 10, // The base relocation applies the difference to the 64-bit field at offset.
	MAX_PE_RELOCATION
};


static const char* GetRelocationString(PeRelocationType relocType)
{
	static const char* relocTable[] =
	{
		"PE_IMAGE_REL_BASED_ABSOLUTE",
		"PE_IMAGE_REL_BASED_HIGH",
		"PE_IMAGE_REL_BASED_LOW",
		"PE_IMAGE_REL_BASED_HIGHLOW",
		"PE_IMAGE_REL_BASED_HIGHADJ",
		"PE_IMAGE_REL_BASED_MIPS_JMPADDR",
		"PE_IMAGE_REL_BASED_ARM_MOV32",
		"PE_IMAGE_REL_BASED_RISCV_HIGH20",
		"PE_IMAGE_REL_BASE_RESERVED",
		"PE_IMAGE_REL_BASED_THUMB_MOV32",
		"PE_IMAGE_REL_BASED_RISCV_LOW12I",
		"PE_IMAGE_REL_BASED_RISCV_LOW12S",
		"PE_IMAGE_REL_BASED_MIPS_JMPADDR16",
		"PE_IMAGE_REL_BASED_DIR64"
	};

	if (relocType < MAX_PE_RELOCATION)
		return relocTable[relocType];
	return "Unknown relocation";
}


static const char* GetRelocationString(COFFx86RelocationType relocType)
{
	static const char* relocTable[] =
	{
		"PE_IMAGE_REL_I386_ABSOLUTE",
		"PE_IMAGE_REL_I386_DIR16",
		"PE_IMAGE_REL_I386_REL16",
		"", "", "",
		"PE_IMAGE_REL_I386_DIR32",
		"PE_IMAGE_REL_I386_DIR32NB",
		"",
		"PE_IMAGE_REL_I386_SEG12",
		"PE_IMAGE_REL_I386_SECTION",
		"PE_IMAGE_REL_I386_SECREL",
		"PE_IMAGE_REL_I386_TOKEN",
		"PE_IMAGE_REL_I386_SECREL7",
		"", "", "", "", "", "",
		"PE_IMAGE_REL_I386_REL32",
	};

	if (relocType < MAX_PE_X86_RELOCATION)
		return relocTable[relocType];
	return "Unknown x86 relocation";
}


static const char* GetRelocationString(COFFx64RelocationType relocType)
{
	static const char* relocTable[] =
	{
		"PE_IMAGE_REL_AMD64_ABSOLUTE",
		"PE_IMAGE_REL_AMD64_ADDR64",
		"PE_IMAGE_REL_AMD64_ADDR32",
		"PE_IMAGE_REL_AMD64_ADDR32NB",
		"PE_IMAGE_REL_AMD64_REL32",
		"PE_IMAGE_REL_AMD64_REL32_1",
		"PE_IMAGE_REL_AMD64_REL32_2",
		"PE_IMAGE_REL_AMD64_REL32_3",
		"PE_IMAGE_REL_AMD64_REL32_4",
		"PE_IMAGE_REL_AMD64_REL32_5",
		"PE_IMAGE_REL_AMD64_SECTION",
		"PE_IMAGE_REL_AMD64_SECREL",
		"PE_IMAGE_REL_AMD64_SECREL7",
		"PE_IMAGE_REL_AMD64_TOKEN",
		"PE_IMAGE_REL_AMD64_SREL32",
		"PE_IMAGE_REL_AMD64_PAIR",
		"PE_IMAGE_REL_AMD64_SSPAN32",
	};

	if (relocType < MAX_PE_X64_RELOCATION)
		return relocTable[relocType];
	return "Unknown x86_64 relocation";
}


static const char* GetRelocationString(Elfx86RelocationType relocType)
{
	static const char* relocTable[] =
	{
		"R_386_NONE",
		"R_386_32",
		"R_386_PC32",
		"R_386_GOT32",
		"R_386_PLT32",
		"R_386_COPY",
		"R_386_GLOB_DAT",
		"R_386_JUMP_SLOT",
		"R_386_RELATIVE",
		"R_386_GOTOFF",
		"R_386_GOTPC",
		"",
		"",
		"",
		"R_386_TLS_TPOFF",
		"R_386_TLS_IE",
		"R_386_TLS_GOTIE",
		"R_386_TLS_LE",
		"R_386_TLS_GD",
		"R_386_TLS_LDM",
		"R_386_16",
		"R_386_PC16",
		"R_386_8",
		"R_386_PC8",
		"R_386_TLS_GD_32",
		"R_386_TLS_GD_PUSH",
		"R_386_TLS_GD_CALL",
		"R_386_TLS_GD_POP",
		"R_386_TLS_LDM_32",
		"R_386_TLS_LDM_PUSH",
		"R_386_TLS_LDM_CALL",
		"R_386_TLS_LDM_POP",
		"R_386_TLS_LDO_32",
		"R_386_TLS_IE_32",
		"R_386_TLS_LE_32",
		"R_386_TLS_DTPMOD32",
		"R_386_TLS_DTPOFF32",
		"R_386_TLS_TPOFF32",
		"R_386_SIZE32",
		"R_386_TLS_GOTDESC",
		"R_386_TLS_DESC_CALL",
		"R_386_TLS_DESC",
		"R_386_IRELATIVE",
	};
	if (relocType < MAX_ELF_X86_RELOCATION)
		return relocTable[relocType];
	return "Unknown x86 relocation";
}

static const char* GetRelocationString(Elfx64RelocationType relocType)
{
	static const char* relocTable[] = {
		"R_X86_64_NONE",
		"R_X86_64_64",
		"R_X86_64_PC32",
		"R_X86_64_GOT32",
		"R_X86_64_PLT32",
		"R_X86_64_COPY",
		"R_X86_64_GLOB_DAT",
		"R_X86_64_JUMP_SLOT",
		"R_X86_64_RELATIVE",
		"R_X86_64_GOTPCREL",
		"R_X86_64_32",
		"R_X86_64_32S",
		"R_X86_64_16",
		"R_X86_64_PC16",
		"R_X86_64_8",
		"R_X86_64_PC8",
		"R_X86_64_DTPMOD64",
		"R_X86_64_DTPOFF64",
		"R_X86_64_TPOFF64",
		"R_X86_64_TLSGD",
		"R_X86_64_TLSLD",
		"R_X86_64_DTPOFF32",
		"R_X86_64_GOTTPOFF",
		"R_X86_64_TPOFF32",
		"R_X86_64_PC64",
		"R_X86_64_GOTOFF64",
		"R_X86_64_GOTPC32",
		"R_X86_64_UNKNOWN27",
		"R_X86_64_UNKNOWN28",
		"R_X86_64_UNKNOWN29",
		"R_X86_64_UNKNOWN30",
		"R_X86_64_UNKNOWN31",
		"R_X86_64_SIZE32",
		"R_X86_64_SIZE64",
		"R_X86_64_GOTPC32_TLSDESC",
		"R_X86_64_TLSDESC_CALL",
		"R_X86_64_TLSDESC",
		"R_X86_64_IRELATIVE",
		"R_X86_64_RELATIVE64",
		"R_X86_64_PC32_BND",
		"R_X86_64_PLT32_BND",
		"R_X86_64_GOTPCRELX",
		"R_X86_64_REX_GOTPCRELX"};
	if (relocType < MAX_ELF_X64_RELOCATION)
		return relocTable[relocType];
	return "Unknown x86_64 relocation";
}

static const char* GetRelocationString(Machox86RelocationType relocType)
{
	static const char* relocTable[] = {
		"GENERIC_RELOC_VANILLA",
		"GENERIC_RELOC_PAIR",
		"GENERIC_RELOC_SECTDIFF",
		"GENERIC_RELOC_PB_LA_PTR",
		"GENERIC_RELOC_LOCAL_SECTDIFF",
		"GENERIC_RELOC_TLV",
	};
	if (relocType < MACHO_MAX_X86_RELOCATION)
		return relocTable[relocType];
	return "Unknown x86 relocation";
}

static const char* GetRelocationString(Machox64RelocationType relocType)
{
	static const char* relocTable[] = {
		"X86_64_RELOC_UNSIGNED",
		"X86_64_RELOC_SIGNED",
		"X86_64_RELOC_BRANCH",
		"X86_64_RELOC_GOT_LOAD",
		"X86_64_RELOC_GOT",
		"X86_64_RELOC_SUBTRACTOR",
		"X86_64_RELOC_SIGNED_1",
		"X86_64_RELOC_SIGNED_2",
		"X86_64_RELOC_SIGNED_4",
		"X86_64_RELOC_TLV"
	};
	if (relocType < MACHO_MAX_X86_64_RELOCATION)
		return relocTable[relocType];
	return "Unknown x64 relocation";
}


bool X86CommonArchitecture::Decode(const uint8_t* data, size_t len, xed_decoded_inst_t* xedd)
{
	// Zero out structure data, and keep the current destructuring mode (32/64/etc)
	xed_decoded_inst_zero_keep_mode(xedd);

	xed3_operand_set_cet(xedd, 1);
	xed3_operand_set_mpxmode(xedd, 1);

	// Decode the data and check for errors
	xed_error_enum_t xed_error = xed_decode(xedd, data, (unsigned)len);
	switch(xed_error)
	{
	case XED_ERROR_NONE:
		return true;
	default:
		return false;
	}
}

size_t X86CommonArchitecture::GetAddressSizeBits()  const
{
	return GetAddressSize() * 8;
}

uint64_t X86CommonArchitecture::GetAddressMask() const
{
	if (GetAddressSizeBits() == 64)
		return (uint64_t)-1;
	return (((uint64_t)1) << GetAddressSizeBits()) - 1;
}

void X86CommonArchitecture::SetInstructionInfoForInstruction(uint64_t addr, InstructionInfo& result, xed_decoded_inst_t* xedd)
{
	result.length = xed_decoded_inst_get_length(xedd);

	const uint64_t               abs_br = xed_decoded_inst_get_branch_displacement(xedd) + addr + xed_decoded_inst_get_length(xedd);
	const xed_iform_enum_t   xedd_iForm = xed_decoded_inst_get_iform_enum(xedd);
	const xed_iclass_enum_t xedd_iClass = xed_decoded_inst_get_iclass(xedd);
	const uint64_t         immediateOne = xed_decoded_inst_get_unsigned_immediate(xedd);
	// 1. First parse 'generally', by instruction category, then
	// 2. break down to special cases and impliment iclass and possibly iform-specific cases

	switch (xed_decoded_inst_get_category(xedd))
	{
	case XED_CATEGORY_CALL:
	// CALL instruction with an immediate as the first operand and it's not the next instruction
		if ((abs_br != addr+result.length) && ((xedd_iForm == XED_IFORM_CALL_NEAR_RELBRz) || (xedd_iForm == XED_IFORM_CALL_NEAR_RELBRd)))
			result.AddBranch(CallDestination, abs_br);
		break;

	case XED_CATEGORY_UNCOND_BR:
		if (xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(xedd), 0)) == XED_OPERAND_RELBR)
			result.AddBranch(UnconditionalBranch, abs_br);
		else
			result.AddBranch(UnresolvedBranch);
		break;

	case XED_CATEGORY_COND_BR:
		result.AddBranch(TrueBranch, abs_br);
		result.AddBranch(FalseBranch, addr + result.length);
		break;

	case XED_CATEGORY_INTERRUPT:
		if (xed_decoded_inst_get_unsigned_immediate(xedd) == 0x80)
			result.AddBranch(SystemCall);
		else if (xedd_iClass == XED_ICLASS_INT3 || (xedd_iClass == XED_ICLASS_INT && immediateOne == 0x29))
			result.AddBranch(ExceptionBranch);
		break;

	case XED_CATEGORY_SYSCALL:
		result.AddBranch(SystemCall);
		break;

	case XED_CATEGORY_SYSRET:
		result.AddBranch(FunctionReturn);
		break;

	case XED_CATEGORY_RET:
		result.AddBranch(FunctionReturn);
		break;

	default:
		switch (xedd_iClass)
		{
		// case XED_ICLASS_UD0:
		// case XED_ICLASS_UD1:
		case XED_ICLASS_UD2:
		case XED_ICLASS_HLT:
			result.AddBranch(ExceptionBranch);
			break;

		default:
			break;
		}
		break;
	}
}

bool X86CommonArchitecture::IsConditionalJump(xed_decoded_inst_t* xedd)
{
	return (xed_decoded_inst_get_category(xedd) == XED_CATEGORY_COND_BR);
}

string X86CommonArchitecture::GetSizeString(const size_t size) const
{
	switch (size)
	{
	case 1:
		return "byte ";
	case 2:
		return "word ";
	case 4:
		return "dword ";
	case 8:
		return "qword ";
	case 10:
		return "tword ";
	case 16:
		return "oword ";
	default:
		return "";
	}
}

BNRegisterInfo X86CommonArchitecture::RegisterInfo(xed_reg_enum_t fullWidthReg, size_t offset, size_t size, bool zeroExtend)
{
	BNRegisterInfo result;
	result.fullWidthRegister = fullWidthReg;
	result.offset = offset;
	result.size = size;
	result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
	return result;
}

void X86CommonArchitecture::GetAddressSizeToken(const short bytes, vector<InstructionTextToken>& result, const bool lowerCase)
{
	// Size
	result.emplace_back(BeginMemoryOperandToken, "");
	switch (bytes)
	{
	case 1:
		if (lowerCase)
			result.emplace_back(KeywordToken, "byte ");
		else
			result.emplace_back(KeywordToken, "BYTE ");
		break;
	case 2:
		if (lowerCase)
			result.emplace_back(KeywordToken, "word ");
		else
			result.emplace_back(KeywordToken, "WORD ");
		break;
	case 4:
		if (lowerCase)
			result.emplace_back(KeywordToken, "dword ");
		else
			result.emplace_back(KeywordToken, "DWORD ");
		break;
	case 8:
		if (lowerCase)
			result.emplace_back(KeywordToken, "qword ");
		else
			result.emplace_back(KeywordToken, "QWORD ");
		break;
	case 10:
		if (lowerCase)
			result.emplace_back(KeywordToken, "tword ");
		else
			result.emplace_back(KeywordToken, "TWORD ");
		break;
	case 16:
		if (lowerCase)
			result.emplace_back(KeywordToken, "xmmword ");
		else
			result.emplace_back(KeywordToken, "XMMWORD ");
		break;
	case 32:
		if (lowerCase)
			result.emplace_back(KeywordToken, "ymmword ");
		else
			result.emplace_back(KeywordToken, "YMMWORD ");
		break;
	case 64:
		if (lowerCase)
			result.emplace_back(KeywordToken, "zmmword ");
		else
			result.emplace_back(KeywordToken, "ZMMWORD ");
		break;
	default:
		break;
	}
}

unsigned short X86CommonArchitecture::GetInstructionOpcode(const xed_decoded_inst_t* const xedd, const xed_operand_values_t* const ov, vector<InstructionTextToken>& result) const
{
	string opcode = "";
	if (xed_decoded_inst_has_mpx_prefix(xedd))
		opcode += "BND ";
	if (xed_decoded_inst_is_xacquire(xedd))
		opcode += "XACQUIRE ";
	if (xed_decoded_inst_is_xrelease(xedd))
		opcode += "XRELEASE ";
	if (xed_operand_values_has_lock_prefix(ov))
		opcode += "LOCK ";
	if (xed_operand_values_has_real_rep(ov))
	{
		if (xed_operand_values_has_rep_prefix(ov))
			opcode += "REP ";
		if (xed_operand_values_has_repne_prefix(ov))
			opcode += "REPNE ";
	}
	else if (xed_operand_values_branch_not_taken_hint(ov))
		opcode += "HINT-NOT-TAKEN ";
	else if (xed_operand_values_branch_taken_hint(ov))
		opcode += "HINT-TAKEN ";

	switch (m_disassembly_options.df)
	{
	case DF_INTEL:
		opcode += string(xed_iform_to_iclass_string_intel(xed_decoded_inst_get_iform_enum(xedd)));
		break;
	case DF_BN_INTEL:
		// To match asmx86 disassembly
		switch (xed_decoded_inst_get_iclass(xedd))
		{
		case XED_ICLASS_RET_NEAR:
			opcode += "RETN";
			break;
		case XED_ICLASS_JZ:
			opcode += "JE";
			break;
		case XED_ICLASS_JNZ:
			opcode += "JNE";
			break;
		case XED_ICLASS_JNB:
			opcode += "JAE";
			break;
		case XED_ICLASS_JNBE:
			opcode += "JA";
			break;
		case XED_ICLASS_JP:
			opcode += "JPE";
			break;
		case XED_ICLASS_JNP:
			opcode += "JPO";
			break;
		case XED_ICLASS_JNL:
			opcode += "JGE";
			break;
		case XED_ICLASS_JNLE:
			opcode += "JG";
			break;

		case XED_ICLASS_SETNB:
			opcode += "SETAE";
			break;
		case XED_ICLASS_SETZ:
			opcode += "SETE";
			break;
		case XED_ICLASS_SETNZ:
			opcode += "SETNE";
			break;
		case XED_ICLASS_SETNBE:
			opcode += "SETA";
			break;
		case XED_ICLASS_SETP:
			opcode += "SETPE";
			break;
		case XED_ICLASS_SETNP:
			opcode += "SETPO";
			break;
		case XED_ICLASS_SETNL:
			opcode += "SETGE";
			break;
		case XED_ICLASS_SETNLE:
			opcode += "SETG";
			break;

		case XED_ICLASS_CMOVNB:
			opcode += "CMOVAE";
			break;
		case XED_ICLASS_CMOVZ:
			opcode += "CMOVE";
			break;
		case XED_ICLASS_CMOVNZ:
			opcode += "CMOVNE";
			break;
		case XED_ICLASS_CMOVNBE:
			opcode += "CMOVA";
			break;
		case XED_ICLASS_CMOVP:
			opcode += "CMOVPE";
			break;
		case XED_ICLASS_CMOVNP:
			opcode += "CMOVPO";
			break;
		case XED_ICLASS_CMOVNL:
			opcode += "CMOVGE";
			break;
		case XED_ICLASS_CMOVNLE:
			opcode += "CMOVG";
			break;

		default:
			opcode += string(xed_iform_to_iclass_string_intel(xed_decoded_inst_get_iform_enum(xedd)));
		}
		break;
	case DF_ATT:
		opcode += string(xed_iform_to_iclass_string_att(xed_decoded_inst_get_iform_enum(xedd)));
		break;
	case DF_XED:
		opcode += string(xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(xedd)));
		break;
	default:
		LogError("Invalid Disassembly Flavor");
	}

	if (m_disassembly_options.lowerCase)
		for (char& c : opcode)
			c = tolower(c);
	else
		for (char& c : opcode)
			c = toupper(c);

	result.emplace_back(InstructionToken, opcode);

	return (unsigned short)opcode.length();
}

void X86CommonArchitecture::GetInstructionPadding(const unsigned int instruction_name_length, vector<InstructionTextToken>& result) const
{
	string padding = "";
	const short min = 7 < instruction_name_length ? 7 : instruction_name_length;
	for (unsigned short delim = 0; delim < (8 - min); ++delim)
		padding += ' ';
	result.emplace_back(TextToken, padding);
}

// (in theory) Exactly how XED wants the world to see x86
void X86CommonArchitecture::GetOperandTextIntel(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len, const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const
{
	xed_reg_enum_t extra_index_operand = XED_REG_INVALID;

	// Get operands
	for (unsigned int opIndex = 0; opIndex < xed_inst_noperands(xi); ++opIndex)
	{
		const xed_operand_t*          op = xed_inst_operand(xi, opIndex);
		const xed_operand_enum_t op_name = xed_operand_name(op);

		// XED's suppressed operands shouln't be represented in Intel syntax
		if (xed_operand_operand_visibility(op) == XED_OPVIS_SUPPRESSED)
		{
			if ((xed_decoded_inst_get_category(xedd) == XED_CATEGORY_STRINGOP) &&
				(op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_MEM1))
			{
				if (op_name == XED_OPERAND_MEM1)
					result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
			}
			else
				continue;
		}

		switch(op_name)
		{
		case XED_OPERAND_REG0:
		case XED_OPERAND_REG1:
		case XED_OPERAND_REG2:
		case XED_OPERAND_REG3:
		case XED_OPERAND_REG4:
		case XED_OPERAND_REG5:
		case XED_OPERAND_REG6:
		case XED_OPERAND_REG7:
		case XED_OPERAND_REG8:
		{
			string reg = "";

			const xed_reg_enum_t xedReg = xed_decoded_inst_get_reg(xedd, op_name);
			if ((xedReg >= XED_REG_X87_FIRST) && (xedReg <=  XED_REG_X87_LAST))
			{
				reg += "ST";
				reg += ('0' + (xedReg-XED_REG_X87_FIRST));
			}
			else
			{
				reg += xed_reg_enum_t2str(xedReg);
			}
			if (m_disassembly_options.lowerCase)
				for (char& c : reg)
					c = tolower(c);
			result.emplace_back(RegisterToken, reg);
			break;
		}
		case XED_OPERAND_AGEN:
		case XED_OPERAND_MEM0:
		{
			GetAddressSizeToken(xed_decoded_inst_operand_length_bits(xedd, opIndex) / 8, result, m_disassembly_options.lowerCase);

			if (m_disassembly_options.lowerCase)
				result.emplace_back(KeywordToken, "ptr ");
			else
				result.emplace_back(KeywordToken, "PTR ");
			result.emplace_back(BraceToken, "[");

			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 0);
			const bool validSegment = (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 0));
			if (validSegment)
			{
				string seg_str(xed_reg_enum_t2str(seg));
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);
				result.emplace_back(OperationToken, ":");
			}

			bool started = false;
			const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);

			int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);

			if ((base != XED_REG_INVALID) && !((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP)))
			{
				string base_str(xed_reg_enum_t2str(base));
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
				started = true;
			}
			else if ((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP))
			{
				if (xed_operand_values_has_memory_displacement(ov))
					disp += addr + len;
				else
					disp = addr + len;

				stringstream sstream;
				if (m_disassembly_options.lowerCase)
					sstream << "0x" << hex << nouppercase << disp;
				else
					sstream << "0x" << hex << uppercase << disp;

				result.emplace_back(CodeRelativeAddressToken, sstream.str(), disp, GetAddressSize());

				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				break;
			}

			const xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
			if (index != XED_REG_INVALID)
			{
				if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_INDEX_REG_IS_POINTER))
				{
					// MPX BNDLDX/BNDSTX instr are unusual in that they use
					// the index reg as distinct operand.
					extra_index_operand = index;
				}
				else  // normal path
				{
					if (started)
						result.emplace_back(OperationToken, "+");
					started = true;

					string index_str(xed_reg_enum_t2str(index));
					if (m_disassembly_options.lowerCase)
						for (char& c : index_str)
							c = tolower(c);

					result.emplace_back(RegisterToken, index_str);

					const unsigned int scale = xed_decoded_inst_get_scale(xedd, 0);
					if (scale != 1)
					{
						result.emplace_back(OperationToken, "*");
						stringstream sstream;
						sstream << scale;
						result.emplace_back(IntegerToken, sstream.str(), scale, 1);
					}
				}
			}

			const unsigned short disp_bytes = xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0) / 8;

			if (xed_operand_values_has_memory_displacement(ov) &&
				((disp != 0) || (!started && validSegment)))
			{
				stringstream sstream;
				sstream << "0x" << hex;
				if (m_disassembly_options.lowerCase)
					sstream << nouppercase;
				else
					sstream << uppercase;

				if (started)
				{
					if (disp < 0)
					{
						result.emplace_back(OperationToken, "-");
						disp = -disp;
					}
					else
						result.emplace_back(OperationToken, "+");

					if (disp_bytes == 2)
						sstream << (uint16_t)disp;
					else if (disp_bytes == 4)
						sstream << (uint32_t)disp;
					else if (disp_bytes == 8)
						sstream << (uint64_t)disp;
					else
						sstream << disp;
					result.emplace_back(IntegerToken, sstream.str(), disp, disp_bytes);
				}
				else
				{
					sstream << disp;

					if (validSegment)
						result.emplace_back(IntegerToken, sstream.str(), disp, GetAddressSize());
					else
						result.emplace_back(PossibleAddressToken, sstream.str(), disp, GetAddressSize());
				}
			}
			else if (xed_operand_values_has_memory_displacement(ov) &&
				((disp == 0) && (!started)))
			{
				result.emplace_back(IntegerToken, "0x0", disp, GetAddressSize());
			}
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}
		case XED_OPERAND_MEM1:
		{
			GetAddressSizeToken(xed_decoded_inst_operand_length_bits(xedd, opIndex) / 8, result, m_disassembly_options.lowerCase);

			if (m_disassembly_options.lowerCase)
				result.emplace_back(KeywordToken, "ptr ");
			else
				result.emplace_back(KeywordToken, "PTR ");

			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 1);
			if (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 1))
			{
				string seg_str(xed_reg_enum_t2str(seg));
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);

				result.emplace_back(OperationToken, ":");
			}

			result.emplace_back(BraceToken, "[");
			const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 1);
			if (base != XED_REG_INVALID)
			{
				string base_str(xed_reg_enum_t2str(base));
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
			}
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}
		case XED_OPERAND_IMM0:
		{
			const size_t            addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;
			const unsigned int immediateSize = xed_decoded_inst_get_operand_width(xedd) / 8;

			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			if (xed_decoded_inst_get_immediate_is_signed(xedd) && (immediateSize != 1))
			{
				const int64_t immediateValue = xed_decoded_inst_get_signed_immediate(xedd);

				if (immediateValue >= 0)
					sstream << immediateValue;  // Don't zero extend
				else
				{
					// I'm not proud of this switch statement... It was the product of a lot of pain.
					switch (immediateSize)  // For sign extentions
					{
					case 1:
						sstream << (int8_t)immediateValue;
						break;
					case 2:
						sstream << (int16_t)immediateValue;
						break;
					case 4:
						sstream << (int32_t)immediateValue;
						break;
					default:
						sstream << (int64_t)immediateValue;
					}
				}

				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			else
			{
				const uint64_t immediateValue = xed_decoded_inst_get_unsigned_immediate(xedd);
				sstream << immediateValue;
				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			break;
		}
		case XED_OPERAND_IMM1:  // The ENTER instruction
		{
			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << (uint16_t)xed_decoded_inst_get_second_immediate(xedd);
			result.emplace_back(IntegerToken, sstream.str(), xed_decoded_inst_get_second_immediate(xedd), 1);
			break;
		}
		case XED_OPERAND_PTR:  // TODO...remove?
		{
			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << xed_decoded_inst_get_branch_displacement(xedd);
			result.emplace_back(PossibleAddressToken, sstream.str(), xed_decoded_inst_get_branch_displacement(xedd), 8);
			break;
		}
		case XED_OPERAND_RELBR:
		{
			const int64_t relbr = xed_decoded_inst_get_branch_displacement(xedd) + addr + xed_decoded_inst_get_length(xedd);

			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << relbr;
			result.emplace_back(CodeRelativeAddressToken, sstream.str(), relbr, 8);
			break;
		}
		default:
		{
			result.emplace_back(KeywordToken, "unimplemented");
		}  // default case of outer switch
		}  // outer switch

		// If there is another operand and it is visable, print delimiter
		if ((opIndex != xed_inst_noperands(xi)-1) &&
			((xed_operand_operand_visibility(xed_inst_operand(xi, opIndex+1)) == XED_OPVIS_EXPLICIT) ||
			(xed_operand_operand_visibility(xed_inst_operand(xi, opIndex+1)) == XED_OPVIS_IMPLICIT)))
				result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
	}

	if (extra_index_operand != XED_REG_INVALID)
	{
		result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
		string reg = xed_reg_enum_t2str(extra_index_operand);
		if (m_disassembly_options.lowerCase)
			for (char& c : reg)
				c = tolower(c);
		result.emplace_back(RegisterToken, reg);
	}
}

// The syntax used by asmx86, that users are used to (also the only one that should be garenteed to roundtrip with asm)
void X86CommonArchitecture::GetOperandTextBNIntel(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len, const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const
{
	xed_reg_enum_t extra_index_operand = XED_REG_INVALID;

	// Get operands
	for (unsigned int opIndex = 0; opIndex < xed_inst_noperands(xi); ++opIndex)
	{
		const xed_operand_t*          op = xed_inst_operand(xi, opIndex);
		const xed_operand_enum_t op_name = xed_operand_name(op);

		// XED's suppressed operands shouln't be represented in Intel syntax
		if (xed_operand_operand_visibility(op) == XED_OPVIS_SUPPRESSED)
		{
			if ((xed_decoded_inst_get_category(xedd) == XED_CATEGORY_STRINGOP) &&
				(op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_MEM1))
			{
				if (op_name == XED_OPERAND_MEM1)
					result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
			}
			else
				continue;
		}

		switch(op_name)
		{
		case XED_OPERAND_REG0:
		case XED_OPERAND_REG1:
		case XED_OPERAND_REG2:
		case XED_OPERAND_REG3:
		case XED_OPERAND_REG4:
		case XED_OPERAND_REG5:
		case XED_OPERAND_REG6:
		case XED_OPERAND_REG7:
		case XED_OPERAND_REG8:
		{
			string reg = "";

			const xed_reg_enum_t xedReg = xed_decoded_inst_get_reg(xedd, op_name);
			if ((xedReg >= XED_REG_X87_FIRST) && (xedReg <=  XED_REG_X87_LAST))
			{
				reg += "ST";
				reg += ('0' + (xedReg - XED_REG_X87_FIRST));
			}
			// As of July 2020, the XED now outputs these registers as mm0, etc.
			// However, to maintain backward-compatibility, we need to make them mmx0, etc,
			// as they previously are
			else if ((xedReg >= XED_REG_MMX0) && (xedReg <=  XED_REG_MMX1))
			{
				reg += "MMX";
				reg += ('0' + (xedReg - XED_REG_MMX0));
			}
			else
			{
				reg += xed_reg_enum_t2str(xedReg);
			}

			if (m_disassembly_options.lowerCase)
				for (char& c : reg)
					c = tolower(c);

			result.emplace_back(RegisterToken, reg);

			// handle the {z} modifier
			if (XED_REG_K1 <= xedReg && xedReg <= XED_REG_K7)
			{
				if(xed_decoded_inst_zeroing(xedd))
				{
					if (m_disassembly_options.lowerCase)
						result.emplace_back(OperationToken, " {z}");
					else
						result.emplace_back(OperationToken, " {Z}");
				}
			}

			break;
		}
		case XED_OPERAND_AGEN:
		case XED_OPERAND_MEM0:
		{
			// Size
			if (xed_inst_iclass(xi) != XED_ICLASS_LEA)
				GetAddressSizeToken(xed_decoded_inst_operand_length_bits(xedd, opIndex) / 8, result, m_disassembly_options.lowerCase);

			result.emplace_back(BraceToken, "[");
			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 0);
			const bool validSegment = (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 0));
			if (validSegment)
			{
				string seg_str(xed_reg_enum_t2str(seg));
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);
				result.emplace_back(OperationToken, ":");
			}

			bool started = false;
			xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);

			int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);

			if ((base != XED_REG_INVALID) && !((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP)))
			{
				string base_str(xed_reg_enum_t2str(base));
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
				started = true;
			}
			else if ((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP))
			{
				if (m_disassembly_options.lowerCase)
					result.emplace_back(KeywordToken, "rel ");
				else
					result.emplace_back(KeywordToken, "REL ");

				if (xed_operand_values_has_memory_displacement(ov))
					disp += addr + len;
				else
					disp = addr + len;

				stringstream sstream;
				if (m_disassembly_options.lowerCase)
					sstream << "0x" << hex << nouppercase << disp;
				else
					sstream << "0x" << hex << uppercase << disp;

				result.emplace_back(CodeRelativeAddressToken, sstream.str(), disp, GetAddressSize());

				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				break;
			}

			const xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
			if (index != XED_REG_INVALID)
			{
				if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_INDEX_REG_IS_POINTER))
				{
					// MPX BNDLDX/BNDSTX instr are unusual in that they use
					// the index reg as distinct operand.
					extra_index_operand = index;
				}
				else  // normal path
				{
					if (started)
						result.emplace_back(OperationToken, "+");
					started = true;

					string index_str(xed_reg_enum_t2str(index));
					if (m_disassembly_options.lowerCase)
						for (char& c : index_str)
							c = tolower(c);

					result.emplace_back(RegisterToken, index_str);

					const unsigned int scale = xed_decoded_inst_get_scale(xedd, 0);
					if (scale != 1)
					{
						result.emplace_back(OperationToken, "*");
						stringstream sstream;
						sstream << scale;
						result.emplace_back(IntegerToken, sstream.str(), scale, 1);
					}
				}
			}

			const unsigned short disp_bytes = xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0) / 8;

			if (xed_operand_values_has_memory_displacement(ov) &&
				((disp != 0) || (!started && validSegment)))
			{
				stringstream sstream;
				sstream << "0x" << hex;
				if (m_disassembly_options.lowerCase)
					sstream << nouppercase;
				else
					sstream << uppercase;

				if (started)
				{
					if (disp < 0)
					{
						result.emplace_back(OperationToken, "-");
						disp = -disp;
					}
					else
						result.emplace_back(OperationToken, "+");

					if (disp_bytes == 2)
						sstream << (uint16_t)disp;
					else if (disp_bytes == 4)
						sstream << (uint32_t)disp;
					else if (disp_bytes == 8)
						sstream << (uint64_t)disp;
					else
						sstream << disp;
					result.emplace_back(IntegerToken, sstream.str(), disp, disp_bytes);
				}
				else
				{
					sstream << disp;

					if (validSegment)
						result.emplace_back(IntegerToken, sstream.str(), disp, GetAddressSize());
					else
						result.emplace_back(PossibleAddressToken, sstream.str(), disp, GetAddressSize());
				}
			}
			else if (xed_operand_values_has_memory_displacement(ov) &&
				((disp == 0) && (!started)))
			{
				result.emplace_back(IntegerToken, "0x0", disp, GetAddressSize());
			}

			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}
		case XED_OPERAND_MEM1:
		{


			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 1);
			if (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 1))
			{
				string seg_str(xed_reg_enum_t2str(seg));
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);

				result.emplace_back(OperationToken, ":");
			}

			result.emplace_back(BraceToken, "[");
			const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 1);
			if (base != XED_REG_INVALID)
			{
				string base_str(xed_reg_enum_t2str(base));
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
			}
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}
		case XED_OPERAND_IMM0:
		{
			const size_t            addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;
			const unsigned int immediateSize = xed_decoded_inst_get_operand_width(xedd) / 8;

			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			if (xed_decoded_inst_get_immediate_is_signed(xedd)  && (immediateSize != 1))
			{
				const int64_t immediateValue = xed_decoded_inst_get_signed_immediate(xedd);

				if (immediateValue >= 0)
					sstream << immediateValue;  // Don't zero extend
				else
				{
					// I'm not proud of this switch statement... It was the product of a lot of pain.
					switch (immediateSize)  // For sign extentions
					{
					case 1:
						sstream << (int8_t)immediateValue;
						break;
					case 2:
						sstream << (int16_t)immediateValue;
						break;
					case 4:
						sstream << (int32_t)immediateValue;
						break;
					default:
						sstream << (int64_t)immediateValue;
					}
				}

				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			else
			{
				const uint64_t immediateValue = xed_decoded_inst_get_unsigned_immediate(xedd);
				sstream << immediateValue;
				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			break;
		}
		case XED_OPERAND_IMM1:  // The ENTER instruction
		{
			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << (uint16_t)xed_decoded_inst_get_second_immediate(xedd);
			result.emplace_back(IntegerToken, sstream.str(), xed_decoded_inst_get_second_immediate(xedd), 1);
			break;
		}
		case XED_OPERAND_PTR:
		{
			stringstream sstream;
			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << xed_decoded_inst_get_branch_displacement(xedd);
			result.emplace_back(PossibleAddressToken, sstream.str(), xed_decoded_inst_get_branch_displacement(xedd), 8);
			break;
		}
		case XED_OPERAND_RELBR:
		{
			const int64_t relbr = xed_decoded_inst_get_branch_displacement(xedd) + addr + xed_decoded_inst_get_length(xedd);

			stringstream sstream;
			if ((xed_decoded_inst_get_iclass(xedd) == XED_ICLASS_CALL_NEAR) && (relbr == (int64_t)(addr + xed_decoded_inst_get_length(xedd))))
			{
				sstream << "$+" << xed_decoded_inst_get_length(xedd);
				result.emplace_back(OperationToken, sstream.str());
				break;
			}

			sstream << "0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << relbr;
			result.emplace_back(CodeRelativeAddressToken, sstream.str(), relbr, 8);
			break;
		}
		default:
		{
			if (m_disassembly_options.lowerCase)
				result.emplace_back(KeywordToken, "unimplemented ");
			else
				result.emplace_back(KeywordToken, "UNIMPLEMENTED ");
		}  // default case of outer switch
		}  // outer switch

		// If there is another operand and it is visable, print delimiter
		if ((opIndex != xed_inst_noperands(xi)-1) &&
			((xed_operand_operand_visibility(xed_inst_operand(xi, opIndex+1)) == XED_OPVIS_EXPLICIT) ||
				(xed_operand_operand_visibility(xed_inst_operand(xi, opIndex+1)) == XED_OPVIS_IMPLICIT)))
				result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
	}

	if (extra_index_operand != XED_REG_INVALID)
	{
		result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
		string reg = xed_reg_enum_t2str(extra_index_operand);
		if (m_disassembly_options.lowerCase)
			for (char& c : reg)
				c = tolower(c);
		result.emplace_back(RegisterToken, reg);
	}
}

void X86CommonArchitecture::GetOperandTextATT(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len, const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const
{
	unsigned i,j;
	unsigned noperands = xed_inst_noperands(xi);

	bool intel_way = false;

	if (xed_inst_get_attribute(xi, XED_ATTRIBUTE_ATT_OPERAND_ORDER_EXCEPTION))
		intel_way = true;

	// if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_INDEX_REG_IS_POINTER))
	// {
	// 	for(j=0; j<noperands; ++j)
	// 	{
	// 		i = noperands - j - 1;  // never intel_way

	// 		if(xed_operand_name(xed_inst_operand(xi,i)) == XED_OPERAND_MEM0)
	// 			cout << "%" + xed_reg_enum_t2str(xed3_operand_get_index(xedd));
	// 	}
	// }

	for(j=0; j<noperands; ++j)
	{
		if (intel_way)
			i = j;
		else
			i = noperands - j - 1;

		const xed_operand_t*          op = xed_inst_operand(xi, i);
		const xed_operand_enum_t op_name = xed_operand_name(op);

		// XED's suppressed operands shouln't be represented in Intel syntax
		if (xed_operand_operand_visibility(op) == XED_OPVIS_SUPPRESSED)
		{
			if ((xed_decoded_inst_get_category(xedd) == XED_CATEGORY_STRINGOP) &&
				(op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_MEM1))
			{
				if (op_name == XED_OPERAND_MEM1)
					result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
			}
			else
			{
				continue;
			}
		}

		switch(xed_operand_name(op))
		{
		case XED_OPERAND_REG0:
		case XED_OPERAND_REG1:
		case XED_OPERAND_REG2:
		case XED_OPERAND_REG3:
		case XED_OPERAND_REG4:
		case XED_OPERAND_REG5:
		case XED_OPERAND_REG6:
		case XED_OPERAND_REG7:
		case XED_OPERAND_REG8:
		{
			string reg = "%";

			const xed_reg_enum_t xedReg = xed_decoded_inst_get_reg(xedd, op_name);
			if ((xedReg >= XED_REG_X87_FIRST) && (xedReg <=  XED_REG_X87_LAST))
			{
				reg += "ST";
				reg += ('0' + (xedReg-XED_REG_X87_FIRST));
			}
			else
			{
				reg += xed_reg_enum_t2str(xedReg);
			}
			if (m_disassembly_options.lowerCase)
				for (char& c : reg)
					c = tolower(c);
			result.emplace_back(RegisterToken, reg);
			break;
		}
		case XED_OPERAND_AGEN:
		case XED_OPERAND_MEM0:
		{
			GetAddressSizeToken(xed_decoded_inst_operand_length_bits(xedd, i) / 8, result, m_disassembly_options.lowerCase);

			if (m_disassembly_options.lowerCase)
				result.emplace_back(KeywordToken, "ptr ");
			else
				result.emplace_back(KeywordToken, "PTR ");
			result.emplace_back(BraceToken, "[");

			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 0);
			const bool validSegment = (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 0));
			if (validSegment)
			{
				string seg_str(xed_reg_enum_t2str(seg));
				seg_str = "%" + seg_str;
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);
				result.emplace_back(OperationToken, ":");
			}

			bool started = false;
			xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);

			int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);

			if ((base != XED_REG_INVALID) && !((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP)))
			{
				string base_str(xed_reg_enum_t2str(base));
				base_str = "%" + base_str;
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
				started = true;
			}
			else if ((base == XED_REG_RIP) || (base == XED_REG_EIP) || (base == XED_REG_IP))
			{
				if (xed_operand_values_has_memory_displacement(ov))
					disp += addr + len;
				else
					disp = addr + len;

				stringstream sstream;
				if (m_disassembly_options.lowerCase)
					sstream << "0x" << hex << nouppercase << disp;
				else
					sstream << "0x" << hex << uppercase << disp;

				result.emplace_back(CodeRelativeAddressToken, sstream.str(), disp, GetAddressSize());

				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				break;
			}

			const xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
			if (index != XED_REG_INVALID)
			{
				if (started)
					result.emplace_back(OperationToken, "+");
				started = true;

				string index_str(xed_reg_enum_t2str(index));
				index_str = "%" + index_str;
				if (m_disassembly_options.lowerCase)
					for (char& c : index_str)
						c = tolower(c);

				result.emplace_back(RegisterToken, index_str);

				const unsigned int scale = xed_decoded_inst_get_scale(xedd, 0);
				if (scale != 1)
				{
					result.emplace_back(OperationToken, "*");
					stringstream sstream;
					sstream << scale;
					result.emplace_back(IntegerToken, sstream.str(), scale, 1);
				}
			}

			const unsigned short disp_bytes = xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0) / 8;

			if (xed_operand_values_has_memory_displacement(ov) &&
				((disp != 0) || (!started && validSegment)))
			{
				stringstream sstream;
				sstream << "0x" << hex;
				if (m_disassembly_options.lowerCase)
					sstream << nouppercase;
				else
					sstream << uppercase;

				if (started)
				{
					if (disp < 0)
					{
						result.emplace_back(OperationToken, "-");
						disp = -disp;
					}
					else
						result.emplace_back(OperationToken, "+");

					if (disp_bytes == 2)
						sstream << (uint16_t)disp;
					else if (disp_bytes == 4)
						sstream << (uint32_t)disp;
					else if (disp_bytes == 8)
						sstream << (uint64_t)disp;
					else
						sstream << disp;
					result.emplace_back(IntegerToken, sstream.str(), disp, disp_bytes);
				}
				else
				{
					sstream << disp;

					if (validSegment)
						result.emplace_back(IntegerToken, sstream.str(), disp, GetAddressSize());
					else
						result.emplace_back(PossibleAddressToken, sstream.str(), disp, GetAddressSize());
				}
			}
			else if (xed_operand_values_has_memory_displacement(ov) &&
				((disp == 0) && (!started)))
			{
				result.emplace_back(IntegerToken, "0x0", disp, GetAddressSize());
			}
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}

		case XED_OPERAND_MEM1:
		{
			GetAddressSizeToken(xed_decoded_inst_operand_length_bits(xedd, i) / 8, result, m_disassembly_options.lowerCase);

			if (m_disassembly_options.lowerCase)
				result.emplace_back(KeywordToken, "ptr ");
			else
				result.emplace_back(KeywordToken, "PTR ");

			// Segment
			const xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd, 1);
			if (seg != XED_REG_INVALID && !xed_operand_values_using_default_segment(ov, 1))
			{
				string seg_str(xed_reg_enum_t2str(seg));
				seg_str = "%" + seg_str;
				if (m_disassembly_options.lowerCase)
					for (char& c : seg_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, seg_str);

				result.emplace_back(OperationToken, ":");
			}

			result.emplace_back(BraceToken, "[");
			const xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 1);
			if (base != XED_REG_INVALID)
			{
				string base_str(xed_reg_enum_t2str(base));
				base_str = "%" + base_str;
				if (m_disassembly_options.lowerCase)
					for (char& c : base_str)
						c = tolower(c);
				result.emplace_back(RegisterToken, base_str);
			}
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");

			break;
		}

		case XED_OPERAND_IMM0:
		{
			const size_t            addrSize = xed_decoded_inst_get_machine_mode_bits(xedd) / 8;
			const unsigned int immediateSize = xed_decoded_inst_get_operand_width(xedd) / 8;

			stringstream sstream;
			sstream << "$0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			if (xed_decoded_inst_get_immediate_is_signed(xedd) && (immediateSize != 1))
			{
				const int64_t immediateValue = xed_decoded_inst_get_signed_immediate(xedd);

				if (immediateValue >= 0)
					sstream << immediateValue;  // Don't zero extend
				else
				{
					// I'm not proud of this switch statement... It was the product of a lot of pain.
					switch (immediateSize)  // For sign extentions
					{
					case 1:
						sstream << (int8_t)immediateValue;
						break;
					case 2:
						sstream << (int16_t)immediateValue;
						break;
					case 4:
						sstream << (int32_t)immediateValue;
						break;
					default:
						sstream << (int64_t)immediateValue;
					}
				}

				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			else
			{
				const uint64_t immediateValue = xed_decoded_inst_get_unsigned_immediate(xedd);
				sstream << immediateValue;
				if (immediateSize == addrSize)
					result.emplace_back(PossibleAddressToken, sstream.str(), immediateValue, immediateSize);
				else
					result.emplace_back(IntegerToken, sstream.str(), immediateValue, immediateSize);
			}
			break;
		}

		case XED_OPERAND_IMM1:
		{
			stringstream sstream;
			sstream << "$0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << (uint16_t)xed_decoded_inst_get_second_immediate(xedd);
			result.emplace_back(IntegerToken, sstream.str(), xed_decoded_inst_get_second_immediate(xedd), 1);
			break;
		}

		case XED_OPERAND_PTR:
		{
			stringstream sstream;
			sstream << "$0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << xed_decoded_inst_get_branch_displacement(xedd);
			result.emplace_back(PossibleAddressToken, sstream.str(), xed_decoded_inst_get_branch_displacement(xedd), 8);
			break;

		}

		case XED_OPERAND_RELBR:
		{
			const int64_t relbr = xed_decoded_inst_get_branch_displacement(xedd) + addr + xed_decoded_inst_get_length(xedd);

			stringstream sstream;
			sstream << "$0x" << hex;
			if (m_disassembly_options.lowerCase)
				sstream << nouppercase;
			else
				sstream << uppercase;

			sstream << relbr;
			result.emplace_back(CodeRelativeAddressToken, sstream.str(), relbr, 8);
			break;
		}

		default:
		{
			result.emplace_back(KeywordToken, "unimplemented");
		}  // default case of outer switch
		}  // outer switch

		// If there is another operand and it is visable, print delimiter
		if (intel_way)
		{
			if ((i != (size_t)xed_inst_noperands(xi)-1) &&
				((xed_operand_operand_visibility(xed_inst_operand(xi, i+1)) == XED_OPVIS_EXPLICIT) ||
				(xed_operand_operand_visibility(xed_inst_operand(xi, i+1)) == XED_OPVIS_IMPLICIT)))
			{
					result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
			}
		}
		else
		{
			if ((i != 0) &&
				((xed_operand_operand_visibility(xed_inst_operand(xi, noperands - j - 2)) == XED_OPVIS_EXPLICIT) ||
				(xed_operand_operand_visibility(xed_inst_operand(xi, noperands - j - 2)) == XED_OPVIS_IMPLICIT)))
			{
					result.emplace_back(OperandSeparatorToken, m_disassembly_options.separator);
			}
		}

	}
}

void X86CommonArchitecture::GetOperandTextXED(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t, const xed_operand_values_t* const, const xed_inst_t* const, vector<InstructionTextToken>& result) const
{
	char out_buffer[100];
	if (!xed_format_context(XED_SYNTAX_XED, xedd, out_buffer, 100, addr, 0, 0))
	{
		LogError("Can't disassemble");
		return;
	}

	// Find space
	int i = 0;
	for (; ; ++i)
		if ((out_buffer[i] == ' ') && (out_buffer[i+1] != ' '))
			break;

	// Convert To String
	string outstring(out_buffer+i);

	result.emplace_back(TextToken, outstring);
}

void X86CommonArchitecture::GetOperandText(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len, const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const
{
	switch (m_disassembly_options.df)
	{
	case DF_INTEL:
		GetOperandTextIntel(xedd, addr, len, ov, xi, result);
		break;

	case DF_BN_INTEL:
		GetOperandTextBNIntel(xedd, addr, len, ov, xi, result);
		break;

	case DF_ATT:
		GetOperandTextATT(xedd, addr, len, ov, xi, result);
		break;

	case DF_XED:
		GetOperandTextXED(xedd, addr, len, ov, xi, result);
		break;

	default:
		LogError("Invalid Disassembly Flavor");
	}
}

X86CommonArchitecture::X86CommonArchitecture(const string& name, size_t bits): Architecture(name), m_bits(bits)
{
	Ref<Settings> settings = Settings::Instance();
	const bool lowercase = settings->Get<bool>("arch.x86.disassembly.lowercase");
	const string flavor = settings->Get<string>("arch.x86.disassembly.syntax");
	const string separator = settings->Get<string>("arch.x86.disassembly.separator");

	DISASSEMBLY_FLAVOR_ENUM flavorEnum;

	if (flavor == "BN_INTEL")
		flavorEnum = DF_BN_INTEL;
	else if (flavor == "INTEL")
		flavorEnum = DF_INTEL;
	else if (flavor == "AT&T")
		flavorEnum = DF_ATT;
	// else if (flavor == "XED")
		// flavorEnum = DF_XED;
	else
		flavorEnum = DF_BN_INTEL;

	m_disassembly_options = DISASSEMBLY_OPTIONS(flavorEnum, lowercase, separator);
}

BNEndianness X86CommonArchitecture::GetEndianness() const
{
	return LittleEndian;
}

vector<uint32_t> X86CommonArchitecture::GetGlobalRegisters()
{
	return vector< uint32_t> {
		XED_REG_CS,
		XED_REG_DS,
		XED_REG_ES,
		XED_REG_SS,
		XED_REG_FS,
		XED_REG_GS,
		XED_REG_FSBASE,
		XED_REG_GSBASE,
		XED_REG_FLAGS,
		XED_REG_EFLAGS,
		XED_REG_RFLAGS
	};
}

vector<uint32_t> X86CommonArchitecture::GetSystemRegisters()
{
	return vector< uint32_t> {
		XED_REG_BND0,
		XED_REG_BND1,
		XED_REG_BND2,
		XED_REG_BND3,

		XED_REG_CR0,
		XED_REG_CR1,
		XED_REG_CR2,
		XED_REG_CR3,
		XED_REG_CR4,
		XED_REG_CR5,
		XED_REG_CR6,
		XED_REG_CR7,
		XED_REG_CR8,
		XED_REG_CR9,
		XED_REG_CR10,
		XED_REG_CR11,
		XED_REG_CR12,
		XED_REG_CR13,
		XED_REG_CR14,
		XED_REG_CR15,

		XED_REG_DR0,
		XED_REG_DR1,
		XED_REG_DR2,
		XED_REG_DR3,
		XED_REG_DR4,
		XED_REG_DR5,
		XED_REG_DR6,
		XED_REG_DR7,

		XED_REG_GDTR,
		XED_REG_LDTR,
		XED_REG_IDTR,
		XED_REG_TR,

		XED_REG_TSC,
		XED_REG_TSCAUX,
		XED_REG_MSRS
	};
}

bool X86CommonArchitecture::GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, maxLen, &xedd))
		return false;

	SetInstructionInfoForInstruction(addr, result, &xedd);
	return true;
}


bool X86CommonArchitecture::GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}

	if (Decode(data, len, &xedd))
	{
		len = xed_decoded_inst_get_length(&xedd);

		// If there's no instruction
		const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
		if (!xi)
			return false;

		// Opcodes
		const xed_operand_values_t* const   ov = xed_decoded_inst_operands_const(&xedd);
		unsigned short instruction_name_length = GetInstructionOpcode(&xedd, ov, result);

		// Padding
		GetInstructionPadding(instruction_name_length, result);

		// Operands
		GetOperandText(&xedd, addr, len, ov, xi, result);

		return true;
	}

	return false;
}

bool X86CommonArchitecture::GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, len, &xedd))
	{
		il.AddInstruction(il.Undefined());
		return false;
	}

	len = xed_decoded_inst_get_length(&xedd);
	return GetLowLevelILForInstruction(this, addr, il, &xedd);
}

size_t X86CommonArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
	uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	switch (op)
	{
	case LLIL_NEG:
		switch (flag)
		{
		case IL_FLAG_O:
			return il.AddExpr(LLIL_CMP_E, size, 0, il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
				il.AddExpr(LLIL_CONST, size, 0, (1LL << ((size * 8) - 1))));
		}
		break;
	case LLIL_XOR:
	case LLIL_AND:
	case LLIL_OR:
		switch (flag)
		{
		case IL_FLAG_C:
		case IL_FLAG_O:
			return il.Const(0, 0);
		case IL_FLAG_A:
			return il.Undefined();
		}
		break;
	case LLIL_MULU_DP:
		switch (flag)
		{
		case IL_FLAG_C:
		case IL_FLAG_O:
			return il.AddExpr(LLIL_CMP_NE, size * 2, 0, il.AddExpr(LLIL_LSR, size * 2, 0,
				il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
				il.AddExpr(LLIL_CONST, 1, 0, size * 8)), il.AddExpr(LLIL_CONST, size * 2, 0, 0));
		}
	default:
		break;
	}

	if (flagWriteType == IL_FLAGWRITE_VCOMI)
	{
		switch (flag)
		{
		case IL_FLAG_S:
		case IL_FLAG_O:
		case IL_FLAG_A:
			return il.Const(0, 0);
		default:
			break;
		}
	}
	if (((flagWriteType == IL_FLAGWRITE_X87COM) || (flagWriteType == IL_FLAGWRITE_X87C1Z)) && (flag == IL_FLAG_C1))
		return il.Const(0, 0);
	return Architecture::GetFlagWriteLowLevelIL(op, size, flagWriteType, flag, operands, operandCount, il);
}

size_t X86CommonArchitecture::GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il)
{
	switch (semGroup)
	{
	case IL_FLAG_GROUP_E:
		return GetFlagConditionLowLevelIL(LLFC_E, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_NE:
		return GetFlagConditionLowLevelIL(LLFC_NE, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_LT:
		return GetFlagConditionLowLevelIL(LLFC_ULT, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_LE:
		return GetFlagConditionLowLevelIL(LLFC_ULE, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_GE:
		return GetFlagConditionLowLevelIL(LLFC_UGE, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_GT:
		return GetFlagConditionLowLevelIL(LLFC_UGT, IL_FLAG_CLASS_INT, il);
	case IL_FLAG_GROUP_PE:
		return il.Flag(IL_FLAG_P);
	case IL_FLAG_GROUP_PO:
		return il.Not(0, il.Flag(IL_FLAG_P));
	default:
		return il.Unimplemented();
	}
}

string X86CommonArchitecture::GetRegisterName(uint32_t reg)
{
	string reg_str = "";
	if (m_disassembly_options.df == DF_ATT)
		reg_str += "%";

	if ((reg >= REG_X87_r(0)) && (reg <= REG_X87_r(7)))
		reg_str += "X87_R" + to_string(reg - REG_X87_r(0));
	else if (reg == REG_X87_TOP)
		reg_str += "TOP";
	else if ((reg >= XED_REG_X87_FIRST) && (reg <= XED_REG_X87_LAST))
		reg_str += "ST" + to_string(reg - XED_REG_X87_FIRST);
	else
		reg_str += xed_reg_enum_t2str((xed_reg_enum_t)reg);

	if (m_disassembly_options.lowerCase)
		for (char& c : reg_str)
			c = tolower(c);

	return reg_str;
}

string X86CommonArchitecture::GetFlagName(uint32_t flag)
{
	char result[32];
	switch (flag)
	{
	case IL_FLAG_C:
		return "c";
	case IL_FLAG_P:
		return "p";
	case IL_FLAG_A:
		return "a";
	case IL_FLAG_Z:
		return "z";
	case IL_FLAG_S:
		return "s";
	case IL_FLAG_D:
		return "d";
	case IL_FLAG_O:
		return "o";
	case IL_FLAG_C0:
		return "c0";
	case IL_FLAG_C1:
		return "c1";
	case IL_FLAG_C2:
		return "c2";
	case IL_FLAG_C3:
		return "c3";
	default:
		snprintf(result, sizeof(result), "flag%" PRIu32, flag);
		return result;
	}
}

vector<uint32_t> X86CommonArchitecture::GetAllFlags()
{
	return vector<uint32_t> {IL_FLAG_C, IL_FLAG_P, IL_FLAG_A, IL_FLAG_Z, IL_FLAG_S, IL_FLAG_D, IL_FLAG_O,
		IL_FLAG_C0, IL_FLAG_C1, IL_FLAG_C2, IL_FLAG_C3};
}

string X86CommonArchitecture::GetSemanticFlagClassName(uint32_t semClass)
{
	switch (semClass)
	{
	case IL_FLAG_CLASS_X87COM:
		return "x87com";
	case IL_FLAG_CLASS_X87COMI:
		return "x87comi";
	case IL_FLAG_CLASS_VCOMI:
		return "vcomi";
	default:
		return "";
	}
}

vector<uint32_t> X86CommonArchitecture::GetAllSemanticFlagClasses()
{
	return vector<uint32_t> {IL_FLAG_CLASS_X87COM, IL_FLAG_CLASS_X87COMI, IL_FLAG_CLASS_VCOMI};
}

string X86CommonArchitecture::GetSemanticFlagGroupName(uint32_t semGroup)
{
	switch (semGroup)
	{
	case IL_FLAG_GROUP_E:
		return "e";
	case IL_FLAG_GROUP_NE:
		return "ne";
	case IL_FLAG_GROUP_LT:
		return "lt";
	case IL_FLAG_GROUP_LE:
		return "le";
	case IL_FLAG_GROUP_GE:
		return "ge";
	case IL_FLAG_GROUP_GT:
		return "gt";
	case IL_FLAG_GROUP_PE:
		return "pe";
	case IL_FLAG_GROUP_PO:
		return "po";
	default:
		return "";
	}
}

vector<uint32_t> X86CommonArchitecture::GetAllSemanticFlagGroups()
{
	return vector<uint32_t> {IL_FLAG_GROUP_E, IL_FLAG_GROUP_NE, IL_FLAG_GROUP_LT, IL_FLAG_GROUP_LE,
		IL_FLAG_GROUP_GE, IL_FLAG_GROUP_GT, IL_FLAG_GROUP_PE, IL_FLAG_GROUP_PO};
}

string X86CommonArchitecture::GetFlagWriteTypeName(uint32_t flags)
{
	switch (flags)
	{
	case IL_FLAGWRITE_ALL:
		return "*";
	case IL_FLAGWRITE_NOCARRY:
		return "!c";
	case IL_FLAGWRITE_CO:
		return "co";
	case IL_FLAGWRITE_X87COM:
		return "x87com";
	case IL_FLAGWRITE_X87COMI:
		return "x87comi";
	case IL_FLAGWRITE_X87C1Z:
		return "x87c1z";
	case IL_FLAGWRITE_X87RND:
		return "x87rnd";
	case IL_FLAGWRITE_VCOMI:
		return "vcomi";
	default:
		return "";
	}
}

uint32_t X86CommonArchitecture::GetSemanticClassForFlagWriteType(uint32_t writeType)
{
	switch (writeType)
	{
	case IL_FLAGWRITE_X87COM:
	case IL_FLAGWRITE_X87C1Z:
	case IL_FLAGWRITE_X87RND:
		return IL_FLAG_CLASS_X87COM;
	case IL_FLAGWRITE_X87COMI:
		return IL_FLAG_CLASS_X87COMI;
	case IL_FLAGWRITE_VCOMI:
		return IL_FLAG_CLASS_VCOMI;
	default:
		return IL_FLAG_CLASS_INT;
	}
}

vector<uint32_t> X86CommonArchitecture::GetAllFlagWriteTypes()
{
	return vector<uint32_t> {IL_FLAGWRITE_ALL, IL_FLAGWRITE_NOCARRY, IL_FLAGWRITE_CO,
		IL_FLAGWRITE_X87COM, IL_FLAGWRITE_X87COMI, IL_FLAGWRITE_X87C1Z, IL_FLAGWRITE_X87RND,
		IL_FLAGWRITE_VCOMI};
}

BNFlagRole X86CommonArchitecture::GetFlagRole(uint32_t flag, uint32_t semClass)
{
	switch (semClass)
	{
	case IL_FLAG_CLASS_X87COM:
		switch (flag)
		{
		case IL_FLAG_C0:
			return CarryFlagRole;
		case IL_FLAG_C2:
			return UnorderedFlagRole;
		case IL_FLAG_C3:
			return ZeroFlagRole;
		default:
			return SpecialFlagRole;
		}

	case IL_FLAG_CLASS_VCOMI:
		switch (flag)
		{
		case IL_FLAG_C:
			return CarryFlagRole;
		case IL_FLAG_Z:
			return ZeroFlagRole;
		case IL_FLAG_P:
			return UnorderedFlagRole;
		default:
			// O, A, S cleared
			return SpecialFlagRole;
		}

	default:
		break;
	}

	switch (flag)
	{
	case IL_FLAG_C:
		return CarryFlagRole;
	case IL_FLAG_P:
		if (semClass == IL_FLAG_CLASS_X87COMI)
			return UnorderedFlagRole;
		return EvenParityFlagRole;
	case IL_FLAG_A:
		return HalfCarryFlagRole;
	case IL_FLAG_Z:
		return ZeroFlagRole;
	case IL_FLAG_S:
		return NegativeSignFlagRole;
	case IL_FLAG_O:
		return OverflowFlagRole;
	default:
		return SpecialFlagRole;
	}
}

vector<uint32_t> X86CommonArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass)
{
	if (semClass == IL_FLAG_CLASS_X87COM)
	{
		switch (cond)
		{
		case LLFC_FE:
		case LLFC_FNE:
			return vector<uint32_t>{ IL_FLAG_C3 };
		case LLFC_FLT:
		case LLFC_FGE:
			return vector<uint32_t>{ IL_FLAG_C0 };
		case LLFC_FLE:
		case LLFC_FGT:
			return vector<uint32_t>{ IL_FLAG_C0, IL_FLAG_C3 };
		case LLFC_FO:
		case LLFC_FUO:
			return vector<uint32_t>{ IL_FLAG_C2 };
		default:
			return vector<uint32_t>();
		}
	}

	switch (cond)
	{
	case LLFC_E:
	case LLFC_NE:
	case LLFC_FE:
	case LLFC_FNE:
		return vector<uint32_t>{ IL_FLAG_Z };
	case LLFC_SLT:
	case LLFC_SGE:
		return vector<uint32_t>{ IL_FLAG_S, IL_FLAG_O };
	case LLFC_ULT:
	case LLFC_UGE:
	case LLFC_FLT:
	case LLFC_FGE:
		return vector<uint32_t>{ IL_FLAG_C };
	case LLFC_SLE:
	case LLFC_SGT:
		return vector<uint32_t>{ IL_FLAG_Z, IL_FLAG_S, IL_FLAG_O };
	case LLFC_ULE:
	case LLFC_UGT:
	case LLFC_FLE:
	case LLFC_FGT:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_Z };
	case LLFC_NEG:
	case LLFC_POS:
		return vector<uint32_t>{ IL_FLAG_S };
	case LLFC_O:
	case LLFC_NO:
		return vector<uint32_t>{ IL_FLAG_O };
	case LLFC_FO:
	case LLFC_FUO:
		return vector<uint32_t>{ IL_FLAG_P };
	default:
		return vector<uint32_t>();
	}
}

vector<uint32_t> X86CommonArchitecture::GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup)
{
	switch (semGroup)
	{
	case IL_FLAG_GROUP_E:
	case IL_FLAG_GROUP_NE:
		return vector<uint32_t>{ IL_FLAG_Z };
	case IL_FLAG_GROUP_LT:
	case IL_FLAG_GROUP_GE:
		return vector<uint32_t>{ IL_FLAG_C };
	case IL_FLAG_GROUP_LE:
	case IL_FLAG_GROUP_GT:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_Z };
	case IL_FLAG_GROUP_PE:
	case IL_FLAG_GROUP_PO:
		return vector<uint32_t>{ IL_FLAG_P };
	default:
		return vector<uint32_t>();
	}
}

map<uint32_t, BNLowLevelILFlagCondition> X86CommonArchitecture::GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup)
{
	switch (semGroup)
	{
	case IL_FLAG_GROUP_E:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_E},
			{IL_FLAG_CLASS_X87COMI, LLFC_FE},
			{IL_FLAG_CLASS_VCOMI, LLFC_FE},
		};
	case IL_FLAG_GROUP_NE:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_NE},
			{IL_FLAG_CLASS_X87COMI, LLFC_FNE},
			{IL_FLAG_CLASS_VCOMI, LLFC_FNE},
		};
	case IL_FLAG_GROUP_LT:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_ULT},
			{IL_FLAG_CLASS_X87COMI, LLFC_FLT},
			{IL_FLAG_CLASS_VCOMI, LLFC_FLT},
		};
	case IL_FLAG_GROUP_LE:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_ULE},
			{IL_FLAG_CLASS_X87COMI, LLFC_FLE},
			{IL_FLAG_CLASS_VCOMI, LLFC_FLE},
		};
	case IL_FLAG_GROUP_GE:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_UGE},
			{IL_FLAG_CLASS_X87COMI, LLFC_FGE},
			{IL_FLAG_CLASS_VCOMI, LLFC_FGE},
		};
	case IL_FLAG_GROUP_GT:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_INT, LLFC_UGT},
			{IL_FLAG_CLASS_X87COMI, LLFC_FGT},
			{IL_FLAG_CLASS_VCOMI, LLFC_FGT},
		};
	case IL_FLAG_GROUP_PE:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_X87COMI, LLFC_FUO},
			{IL_FLAG_CLASS_VCOMI, LLFC_FUO},
		};
	case IL_FLAG_GROUP_PO:
		return map<uint32_t, BNLowLevelILFlagCondition> {
			{IL_FLAG_CLASS_X87COMI, LLFC_FO},
			{IL_FLAG_CLASS_VCOMI, LLFC_FO},
		};
	default:
		return map<uint32_t, BNLowLevelILFlagCondition>();
	}
}

vector<uint32_t> X86CommonArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t writeType)
{
	switch (writeType)
	{
	case IL_FLAGWRITE_ALL:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_P, IL_FLAG_A, IL_FLAG_Z, IL_FLAG_S, IL_FLAG_O };
	case IL_FLAGWRITE_NOCARRY:
		return vector<uint32_t>{ IL_FLAG_P, IL_FLAG_A, IL_FLAG_Z, IL_FLAG_S, IL_FLAG_O };
	case IL_FLAGWRITE_CO:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_O };
	case IL_FLAGWRITE_X87COM:
		return vector<uint32_t>{ IL_FLAG_C0, IL_FLAG_C1, IL_FLAG_C2, IL_FLAG_C3 };
	case IL_FLAGWRITE_X87COMI:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_Z, IL_FLAG_P };
	case IL_FLAGWRITE_X87C1Z:
	case IL_FLAGWRITE_X87RND:
		return vector<uint32_t>{ IL_FLAG_C1 };
	case IL_FLAGWRITE_VCOMI:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_P, IL_FLAG_A, IL_FLAG_Z, IL_FLAG_S, IL_FLAG_O };
	default:
		return vector<uint32_t>();
	}
}

string X86CommonArchitecture::GetRegisterStackName(uint32_t regStack)
{
	if (regStack == REG_STACK_X87)
		return "x87";
	return "";
}

vector<uint32_t> X86CommonArchitecture::GetAllRegisterStacks()
{
	return vector<uint32_t>{REG_STACK_X87};
}

BNRegisterStackInfo X86CommonArchitecture::GetRegisterStackInfo(uint32_t regStack)
{
	if (regStack == REG_STACK_X87)
	{
		BNRegisterStackInfo result;
		result.firstStorageReg = REG_X87_r(0);
		result.storageCount = 8;
		result.firstTopRelativeReg = XED_REG_ST0;
		result.topRelativeCount = 8;
		result.stackTopReg = REG_X87_TOP;
		return result;
	}
	return Architecture::GetRegisterStackInfo(regStack);
}

bool X86CommonArchitecture::CanAssemble()
{
	return true;
}

bool X86CommonArchitecture::Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors)
{
	string finalCode;

	if (GetAddressSizeBits() == 32)
		finalCode = "\tsection .text align=1\n\tbits 32\n";
	else
		finalCode = "\tsection .text align=1\n\tbits 64\n";

	char orgStr[32];
	snprintf(orgStr, sizeof(orgStr), "\torg 0x%" PRIx64 "\n", addr);
	finalCode += orgStr;

	finalCode += "%line 0 input\n";
	finalCode += code;

	Ref<TemporaryFile> inputFile = new TemporaryFile(finalCode);
	Ref<TemporaryFile> outputFile = new TemporaryFile();
	if (!inputFile->IsValid())
	{
		errors = "Unable to create temporary file for input\n";
		return false;
	}
	if (!outputFile->IsValid())
	{
		errors = "Unable to create temporary file for output\n";
		return false;
	}

	#ifdef WIN32
		string yasmPath = GetPathRelativeToBundledPluginDirectory("yasm.exe");
	#else
		string yasmPath = GetPathRelativeToBundledPluginDirectory("yasm");
	#endif

	string inputPath = inputFile->GetPath();
	string outputPath = outputFile->GetPath();

	vector<string> args = vector<string> { yasmPath, "-fbin", "-w", "-Worphan-labels", "-Werror", "-o", outputPath, inputPath };

	string output;
	bool ok = ExecuteWorkerProcess(yasmPath, args, DataBuffer(),
		output,  // _binary_ stdout is ignored
		errors,  // _text_ stderr becomes the error message
		false,  // yasm stdout is ignored (stay with default: no newline translate)
		true  // yasm stderr is known to be text (translate newlines)
	);

	if(!ok)
	{
		/* when there was a problem creating the yasm process
			OR the yasm process return code was nonzero */
		if(errors.size() == 0)
		{
			errors = yasmPath + " returned nonzero\n";
		}
	}
	else
	{
		result = outputFile->GetContents(); /* assembled bytes */
		if(result.GetLength() == 0)
		{
			errors = "Empty output from assembler\n";
			ok = false;
		}
	}

	return ok;
}

bool X86CommonArchitecture::IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}

	if (!Decode(data, len, &xedd))
		return false;
	return IsConditionalJump(&xedd);
}

bool X86CommonArchitecture::IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, len, &xedd))
		return false;
	return IsConditionalJump(&xedd);
}

bool X86CommonArchitecture::IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, len, &xedd))
		return false;
	return IsConditionalJump(&xedd);
}

bool X86CommonArchitecture::IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t, size_t len)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, len, &xedd))
		return false;
	return xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL;
}

bool X86CommonArchitecture::IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t, size_t len)
{
	xed_decoded_inst_t xedd;
	switch (m_bits)
	{
	case 64:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		break;
	case 32:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
		break;
	case 16:
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
		break;
	default:
		LogError("Invalid Processor Mode");
		return false;
	}
	if (!Decode(data, len, &xedd))
		return false;
	return (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL) && (xed_decoded_inst_get_length(&xedd) >= 5);
}

bool X86CommonArchitecture::ConvertToNop(uint8_t* data, uint64_t, size_t len)
{
	memset(data, 0x90, len);
	return true;
}

size_t X86CommonArchitecture::FindOpcodeOffset(const uint8_t* data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
	{
		if ((data[0] >= 0x26) && (data[0] <= 0x3e) && ((data[0] & 7) == 6)) // Segment prefix
			continue;
		if ((data[0] >= 0x64) && (data[0] <= 0x67)) // FS/GS prefix and size overrides
			continue;
		if (data[0] == 0xf0) // Lock prefix
			continue;
		if ((data[0] == 0xf2) || (data[0] == 0xf3)) // Rep prefixes
			continue;
		if ((GetAddressSizeBits() == 64) && (data[0] >= 0x40) && (data[0] <= 0x4f)) // REX prefix
			continue;
		break;
	}
	return i;
}

bool X86CommonArchitecture::AlwaysBranch(uint8_t* data, uint64_t, size_t len)
{
	size_t i = FindOpcodeOffset(data, len);
	if (i >= len)
		return false;

	if ((len - i) == 2)
	{
		data[i] = 0xeb;
		return true;
	}

	if ((len - i) == 5)
	{
		data[i] = 0xe9;
		return true;
	}

	if ((len - i) > 5)
	{
		memmove(&data[(len - i) - 5], data, i);
		memset(data, 0x90, (len - i) - 5);
		data[len - 5] = 0xe9;
		return true;
	}

	return false;
}

bool X86CommonArchitecture::InvertBranch(uint8_t* data, uint64_t, size_t len)
{
	size_t i = FindOpcodeOffset(data, len);
	if (i >= len)
		return false;

	if (data[i] == 0x0f)
	{
		if ((i + 1) >= len)
			return false;
		data[i + 1] ^= 1;
		return true;
	}

	data[i] ^= 1;
	return true;
}

bool X86CommonArchitecture::SkipAndReturnValue(uint8_t* data, uint64_t, size_t len, uint64_t value)
{
	if (len >= 5)
	{
		data[0] = 0xb8;
		*(uint32_t*)&data[1] = (uint32_t)value;
		memset(&data[5], 0x90, len - 5);
		return true;
	}

	if ((value == 0) && (len >= 2))
	{
		// xor eax, eax
		data[0] = 0x31;
		data[1] = 0xc0;
		memset(&data[2], 0x90, len - 2);
		return true;
	}

	return false;
}


class X86Architecture: public X86CommonArchitecture
{
protected:
	virtual size_t GetAddressSize() const override
	{
		return 4;
	}

public:
	X86Architecture(): X86CommonArchitecture("x86", 32)
	{}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector<uint32_t>{
			// 16-Bit
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+

			// 32-Bit
			XED_REG_EIP,  // 32+
			XED_REG_ESP, XED_REG_EBP, XED_REG_ESI, XED_REG_EDI,  // 32+
			XED_REG_EFLAGS,  // 32+

			XED_REG_EAX, XED_REG_ECX, XED_REG_EDX, XED_REG_EBX,  // 32+

			XED_REG_TSC, XED_REG_TSCAUX,  // 32+ (32 on 32, 64 on 64) Timestamp Counters
			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register

			XED_REG_CR0, XED_REG_CR1, XED_REG_CR2, XED_REG_CR3, XED_REG_CR4, XED_REG_CR5, XED_REG_CR6, XED_REG_CR7, XED_REG_CR8, XED_REG_CR9, XED_REG_CR10, XED_REG_CR11, XED_REG_CR12, XED_REG_CR13, XED_REG_CR14, XED_REG_CR15,  // 32+ (32 on 32, 64 on 64) Control Registers
			XED_REG_DR0, XED_REG_DR1, XED_REG_DR2, XED_REG_DR3, XED_REG_DR4, XED_REG_DR5, XED_REG_DR6, XED_REG_DR7,  // 32+ (starting in later revisions of 32) (32 on 32, 64 on 64) Debug registers

   			XED_REG_MXCSR,  // 32+ SSE (MMX) Control Reg (32 on 32, 64 on 64)

			// x87 FPU related
			REG_X87_TOP, XED_REG_X87CONTROL, XED_REG_X87STATUS, XED_REG_X87TAG, XED_REG_X87OPCODE, XED_REG_X87LASTCS,
			XED_REG_X87LASTDS, XED_REG_X87LASTIP, XED_REG_X87LASTDP, XED_REG_X87PUSH, XED_REG_X87POP, XED_REG_X87POP2,

			// 48-Bit (All 32+)
			XED_REG_GDTR,  // Global Descriptor Table Register
			XED_REG_LDTR,  // Local Descriptor Table Register
			XED_REG_IDTR,  // Interrupt Descriptor Table Register

			// 64-Bit
			XED_REG_XCR0,  // 32+ (64 on 32, 64 on 64)

			XED_REG_MSRS,

			// 80-Bit
			XED_REG_ST0, XED_REG_ST1, XED_REG_ST2, XED_REG_ST3, XED_REG_ST4, XED_REG_ST5, XED_REG_ST6, XED_REG_ST7,  // 32+ Floating point
			REG_X87_r(0), REG_X87_r(1), REG_X87_r(2), REG_X87_r(3), REG_X87_r(4), REG_X87_r(5), REG_X87_r(6), REG_X87_r(7),

			// 128-Bit
			XED_REG_XMM0, XED_REG_XMM1, XED_REG_XMM2, XED_REG_XMM3, XED_REG_XMM4, XED_REG_XMM5, XED_REG_XMM6, XED_REG_XMM7,  // 32+ SSE
		};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		return vector<uint32_t>{
			// 8-Bit
			XED_REG_AH, XED_REG_CH, XED_REG_DH, XED_REG_BH, XED_REG_AL, XED_REG_CL, XED_REG_DL, XED_REG_BL,  // 16+

			// 16-Bit
			XED_REG_IP,  // 16+
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+
			XED_REG_SP, XED_REG_BP, XED_REG_SI, XED_REG_DI,  // 16+
			XED_REG_FLAGS,  // 16+

			XED_REG_AX, XED_REG_CX, XED_REG_DX, XED_REG_BX,  // 16+

			REG_X87_TOP, // 32+
			XED_REG_X87CONTROL, XED_REG_X87STATUS, XED_REG_X87TAG, XED_REG_X87PUSH, XED_REG_X87POP,
			XED_REG_X87POP2, XED_REG_X87OPCODE, XED_REG_X87LASTCS, XED_REG_X87LASTIP, XED_REG_X87LASTDS, XED_REG_X87LASTDP,

			// 32-Bit
			XED_REG_EIP,  // 32+
			XED_REG_ESP, XED_REG_EBP, XED_REG_ESI, XED_REG_EDI,  // 32+
			XED_REG_EFLAGS,  // 32+

			XED_REG_EAX, XED_REG_ECX, XED_REG_EDX, XED_REG_EBX,  // 32+

			XED_REG_TSC, XED_REG_TSCAUX,  // 32+ (32 on 32, 64 on 64) Timestamp Counters
			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register

			XED_REG_CR0, XED_REG_CR1, XED_REG_CR2, XED_REG_CR3, XED_REG_CR4, XED_REG_CR5, XED_REG_CR6, XED_REG_CR7, XED_REG_CR8, XED_REG_CR9, XED_REG_CR10, XED_REG_CR11, XED_REG_CR12, XED_REG_CR13, XED_REG_CR14, XED_REG_CR15,  // 32+ (32 on 32, 64 on 64) Control Registers
			XED_REG_DR0, XED_REG_DR1, XED_REG_DR2, XED_REG_DR3, XED_REG_DR4, XED_REG_DR5, XED_REG_DR6, XED_REG_DR7,  // 32+ (starting in later revisions of 32) (32 on 32, 64 on 64) Debug registers

   			XED_REG_MXCSR,  // 32+ SSE (MMX) Control Reg (32 on 32, 64 on 64)

			// 48-Bit (All 32+)
			XED_REG_GDTR,  // Global Descriptor Table Register
			XED_REG_LDTR,  // Local Descriptor Table Register
			XED_REG_IDTR,  // Interrupt Descriptor Table Register

			// 64-Bit
			XED_REG_MMX0, XED_REG_MMX1, XED_REG_MMX2, XED_REG_MMX3, XED_REG_MMX4, XED_REG_MMX5, XED_REG_MMX6, XED_REG_MMX7,  // 32+ Floating point, bottom of st regs
			XED_REG_XCR0,  // 32+ (64 on 32, 64 on 64)

			XED_REG_RFLAGS,

			XED_REG_MSRS,

			// 80-Bit
			XED_REG_ST0, XED_REG_ST1, XED_REG_ST2, XED_REG_ST3, XED_REG_ST4, XED_REG_ST5, XED_REG_ST6, XED_REG_ST7,  // 32+ Floating point
			REG_X87_r(0), REG_X87_r(1), REG_X87_r(2), REG_X87_r(3), REG_X87_r(4), REG_X87_r(5), REG_X87_r(6), REG_X87_r(7),

			// 128-Bit
			XED_REG_XMM0, XED_REG_XMM1, XED_REG_XMM2, XED_REG_XMM3, XED_REG_XMM4, XED_REG_XMM5, XED_REG_XMM6, XED_REG_XMM7,  // 32+ SSE

			XED_REG_BND0, XED_REG_BND1, XED_REG_BND2, XED_REG_BND3,
		};
	}

	virtual BNRegisterInfo GetRegisterInfo(const uint32_t reg) override
	{
		switch (reg)
		{
		// 8-Bit
		case XED_REG_AH:     return RegisterInfo(XED_REG_EAX, 1, 1);
		case XED_REG_CH:     return RegisterInfo(XED_REG_ECX, 1, 1);
		case XED_REG_DH:     return RegisterInfo(XED_REG_EDX, 1, 1);
		case XED_REG_BH:     return RegisterInfo(XED_REG_EBX, 1, 1);
		case XED_REG_AL:     return RegisterInfo(XED_REG_EAX, 0, 1);
		case XED_REG_CL:     return RegisterInfo(XED_REG_ECX, 0, 1);
		case XED_REG_DL:     return RegisterInfo(XED_REG_EDX, 0, 1);
		case XED_REG_BL:     return RegisterInfo(XED_REG_EBX, 0, 1);

		// 16-Bit
		case XED_REG_IP:     return RegisterInfo(XED_REG_EIP, 0, 2);

		case XED_REG_CS:     return RegisterInfo(XED_REG_CS, 0, 2);
		case XED_REG_DS:     return RegisterInfo(XED_REG_DS, 0, 2);
		case XED_REG_ES:     return RegisterInfo(XED_REG_ES, 0, 2);
		case XED_REG_SS:     return RegisterInfo(XED_REG_SS, 0, 2);
		case XED_REG_FS:     return RegisterInfo(XED_REG_FS, 0, 2);
		case XED_REG_GS:     return RegisterInfo(XED_REG_GS, 0, 2);

		case XED_REG_SP:     return RegisterInfo(XED_REG_ESP, 0, 2);
		case XED_REG_BP:     return RegisterInfo(XED_REG_EBP, 0, 2);
		case XED_REG_SI:     return RegisterInfo(XED_REG_ESI, 0, 2);
		case XED_REG_DI:     return RegisterInfo(XED_REG_EDI, 0, 2);

		case XED_REG_FLAGS:  return RegisterInfo(XED_REG_EFLAGS, 0, 2);

		case XED_REG_AX:     return RegisterInfo(XED_REG_EAX, 0, 2);
		case XED_REG_CX:     return RegisterInfo(XED_REG_ECX, 0, 2);
		case XED_REG_DX:     return RegisterInfo(XED_REG_EDX, 0, 2);
		case XED_REG_BX:     return RegisterInfo(XED_REG_EBX, 0, 2);

		// 32-Bit
		case XED_REG_EIP:    return RegisterInfo(XED_REG_EIP, 0, 4);
		case XED_REG_FSBASE: return RegisterInfo(XED_REG_FSBASE, 0, 4);
		case XED_REG_GSBASE: return RegisterInfo(XED_REG_GSBASE, 0, 4);

		case XED_REG_ESP:    return RegisterInfo(XED_REG_ESP, 0, 4);
		case XED_REG_EBP:    return RegisterInfo(XED_REG_EBP, 0, 4);
		case XED_REG_ESI:    return RegisterInfo(XED_REG_ESI, 0, 4);
		case XED_REG_EDI:    return RegisterInfo(XED_REG_EDI, 0, 4);

		case XED_REG_EFLAGS: return RegisterInfo(XED_REG_EFLAGS, 0, 4);

		case XED_REG_EAX:    return RegisterInfo(XED_REG_EAX, 0, 4);
		case XED_REG_ECX:    return RegisterInfo(XED_REG_ECX, 0, 4);
		case XED_REG_EDX:    return RegisterInfo(XED_REG_EDX, 0, 4);
		case XED_REG_EBX:    return RegisterInfo(XED_REG_EBX, 0, 4);

		case XED_REG_TSC:    return RegisterInfo(XED_REG_TSC, 0, 4);
		case XED_REG_TSCAUX: return RegisterInfo(XED_REG_TSCAUX, 0, 4);

		case XED_REG_TR:     return RegisterInfo(XED_REG_TR, 0, 4);

		case REG_X87_TOP:              return RegisterInfo((xed_reg_enum_t)REG_X87_TOP, 0, 2);
		case XED_REG_X87CONTROL:       return RegisterInfo(XED_REG_X87CONTROL, 0, 2);
		case XED_REG_X87STATUS:        return RegisterInfo(XED_REG_X87STATUS, 0, 2);
		case XED_REG_X87TAG:           return RegisterInfo(XED_REG_X87TAG, 0, 2);
		case XED_REG_X87OPCODE:        return RegisterInfo(XED_REG_X87OPCODE, 0, 2);
		case XED_REG_X87LASTCS:        return RegisterInfo(XED_REG_X87LASTCS, 0, 2);
		case XED_REG_X87LASTDS:        return RegisterInfo(XED_REG_X87LASTDS, 0, 2);
		case XED_REG_X87LASTIP:        return RegisterInfo(XED_REG_X87LASTIP, 0, 4);
		case XED_REG_X87LASTDP:        return RegisterInfo(XED_REG_X87LASTDP, 0, 4);
		case XED_REG_X87PUSH:          return RegisterInfo(XED_REG_X87PUSH, 0, 4);
		case XED_REG_X87POP:           return RegisterInfo(XED_REG_X87POP, 0, 4);
		case XED_REG_X87POP2:          return RegisterInfo(XED_REG_X87POP2, 0, 4);

		case XED_REG_CR0:    return RegisterInfo(XED_REG_CR0, 0, 4);
		case XED_REG_CR1:    return RegisterInfo(XED_REG_CR1, 0, 4);
		case XED_REG_CR2:    return RegisterInfo(XED_REG_CR2, 0, 4);
		case XED_REG_CR3:    return RegisterInfo(XED_REG_CR3, 0, 4);
		case XED_REG_CR4:    return RegisterInfo(XED_REG_CR4, 0, 4);
		case XED_REG_CR5:    return RegisterInfo(XED_REG_CR5, 0, 4);
		case XED_REG_CR6:    return RegisterInfo(XED_REG_CR6, 0, 4);
		case XED_REG_CR7:    return RegisterInfo(XED_REG_CR7, 0, 4);
		case XED_REG_CR8:    return RegisterInfo(XED_REG_CR8, 0, 4);
		case XED_REG_CR9:    return RegisterInfo(XED_REG_CR9, 0, 4);
		case XED_REG_CR10:   return RegisterInfo(XED_REG_CR10, 0, 4);
		case XED_REG_CR11:   return RegisterInfo(XED_REG_CR11, 0, 4);
		case XED_REG_CR12:   return RegisterInfo(XED_REG_CR12, 0, 4);
		case XED_REG_CR13:   return RegisterInfo(XED_REG_CR13, 0, 4);
		case XED_REG_CR14:   return RegisterInfo(XED_REG_CR14, 0, 4);
		case XED_REG_CR15:   return RegisterInfo(XED_REG_CR15, 0, 4);

		case XED_REG_DR0:    return RegisterInfo(XED_REG_DR0, 0, 4);
		case XED_REG_DR1:    return RegisterInfo(XED_REG_DR1, 0, 4);
		case XED_REG_DR2:    return RegisterInfo(XED_REG_DR2, 0, 4);
		case XED_REG_DR3:    return RegisterInfo(XED_REG_DR3, 0, 4);
		case XED_REG_DR4:    return RegisterInfo(XED_REG_DR4, 0, 4);
		case XED_REG_DR5:    return RegisterInfo(XED_REG_DR5, 0, 4);
		case XED_REG_DR6:    return RegisterInfo(XED_REG_DR6, 0, 4);
		case XED_REG_DR7:    return RegisterInfo(XED_REG_DR7, 0, 4);

		case XED_REG_MXCSR:  return RegisterInfo(XED_REG_MXCSR, 0, 4);

		// 48-Bit
		case XED_REG_GDTR:   return RegisterInfo(XED_REG_GDTR, 0, 6);
		case XED_REG_LDTR:   return RegisterInfo(XED_REG_LDTR, 0, 6);
		case XED_REG_IDTR:   return RegisterInfo(XED_REG_IDTR, 0, 6);

		// 64-Bit
		case XED_REG_MMX0:   return RegisterInfo(XED_REG_ST0, 0, 8);
		case XED_REG_MMX1:   return RegisterInfo(XED_REG_ST1, 0, 8);
		case XED_REG_MMX2:   return RegisterInfo(XED_REG_ST2, 0, 8);
		case XED_REG_MMX3:   return RegisterInfo(XED_REG_ST3, 0, 8);
		case XED_REG_MMX4:   return RegisterInfo(XED_REG_ST4, 0, 8);
		case XED_REG_MMX5:   return RegisterInfo(XED_REG_ST5, 0, 8);
		case XED_REG_MMX6:   return RegisterInfo(XED_REG_ST6, 0, 8);
		case XED_REG_MMX7:   return RegisterInfo(XED_REG_ST7, 0, 8);

		case XED_REG_XCR0:   return RegisterInfo(XED_REG_XCR0, 0, 8);

		case XED_REG_RFLAGS: return RegisterInfo(XED_REG_RFLAGS, 0, 8);

		case XED_REG_MSRS:	 return RegisterInfo(XED_REG_MSRS, 0, 8);

		// 80-Bit
		case XED_REG_ST0:    return RegisterInfo(XED_REG_ST0, 0, 10);
		case XED_REG_ST1:    return RegisterInfo(XED_REG_ST1, 0, 10);
		case XED_REG_ST2:    return RegisterInfo(XED_REG_ST2, 0, 10);
		case XED_REG_ST3:    return RegisterInfo(XED_REG_ST3, 0, 10);
		case XED_REG_ST4:    return RegisterInfo(XED_REG_ST4, 0, 10);
		case XED_REG_ST5:    return RegisterInfo(XED_REG_ST5, 0, 10);
		case XED_REG_ST6:    return RegisterInfo(XED_REG_ST6, 0, 10);
		case XED_REG_ST7:    return RegisterInfo(XED_REG_ST7, 0, 10);

		case REG_X87_r(0):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(0), 0, 10);
		case REG_X87_r(1):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(1), 0, 10);
		case REG_X87_r(2):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(2), 0, 10);
		case REG_X87_r(3):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(3), 0, 10);
		case REG_X87_r(4):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(4), 0, 10);
		case REG_X87_r(5):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(5), 0, 10);
		case REG_X87_r(6):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(6), 0, 10);
		case REG_X87_r(7):   return RegisterInfo((xed_reg_enum_t)REG_X87_r(7), 0, 10);

		// 128-Bit
		case XED_REG_XMM0:   return RegisterInfo(XED_REG_XMM0, 0, 16);
		case XED_REG_XMM1:   return RegisterInfo(XED_REG_XMM1, 0, 16);
		case XED_REG_XMM2:   return RegisterInfo(XED_REG_XMM2, 0, 16);
		case XED_REG_XMM3:   return RegisterInfo(XED_REG_XMM3, 0, 16);
		case XED_REG_XMM4:   return RegisterInfo(XED_REG_XMM4, 0, 16);
		case XED_REG_XMM5:   return RegisterInfo(XED_REG_XMM5, 0, 16);
		case XED_REG_XMM6:   return RegisterInfo(XED_REG_XMM6, 0, 16);
		case XED_REG_XMM7:   return RegisterInfo(XED_REG_XMM7, 0, 16);

		case XED_REG_BND0:   return RegisterInfo(XED_REG_BND0, 0, 16);
		case XED_REG_BND1:   return RegisterInfo(XED_REG_BND1, 0, 16);
		case XED_REG_BND2:   return RegisterInfo(XED_REG_BND2, 0, 16);
		case XED_REG_BND3:   return RegisterInfo(XED_REG_BND3, 0, 16);

		default:
			return RegisterInfo(XED_REG_INVALID, 0, 0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return XED_REG_ESP;
	}
};


class X16Architecture: public X86CommonArchitecture
{
protected:
	virtual size_t GetAddressSize() const override
	{
		return 2;
	}

public:
	X16Architecture(): X86CommonArchitecture("x86_16", 16)
	{}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector<uint32_t> {
			// 16-Bit
			XED_REG_IP,  // 16+
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+
			XED_REG_SP, XED_REG_BP, XED_REG_SI, XED_REG_DI,  // 16+
			XED_REG_FLAGS,  // 16+

			XED_REG_AX, XED_REG_CX, XED_REG_DX, XED_REG_BX,  // 16+

			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register
		};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		return vector<uint32_t>{
			// 8-Bit
			XED_REG_AH, XED_REG_CH, XED_REG_DH, XED_REG_BH, XED_REG_AL, XED_REG_CL, XED_REG_DL, XED_REG_BL,  // 16+

			// 16-Bit
			XED_REG_IP,  // 16+
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+
			XED_REG_SP, XED_REG_BP, XED_REG_SI, XED_REG_DI,  // 16+
			XED_REG_FLAGS,  // 16+

			XED_REG_AX, XED_REG_CX, XED_REG_DX, XED_REG_BX,  // 16+

			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register
		};
	}

	virtual BNRegisterInfo GetRegisterInfo(const uint32_t reg) override
	{
		switch (reg)
		{
		// 8-Bit
		case XED_REG_AH:     return RegisterInfo(XED_REG_AX, 1, 1);
		case XED_REG_CH:     return RegisterInfo(XED_REG_CX, 1, 1);
		case XED_REG_DH:     return RegisterInfo(XED_REG_DX, 1, 1);
		case XED_REG_BH:     return RegisterInfo(XED_REG_BX, 1, 1);
		case XED_REG_AL:     return RegisterInfo(XED_REG_AX, 0, 1);
		case XED_REG_CL:     return RegisterInfo(XED_REG_CX, 0, 1);
		case XED_REG_DL:     return RegisterInfo(XED_REG_DX, 0, 1);
		case XED_REG_BL:     return RegisterInfo(XED_REG_BX, 0, 1);

		// 16-Bit
		case XED_REG_IP:     return RegisterInfo(XED_REG_IP, 0, 2);
		case XED_REG_CS:     return RegisterInfo(XED_REG_CS, 0, 2);
		case XED_REG_DS:     return RegisterInfo(XED_REG_DS, 0, 2);
		case XED_REG_ES:     return RegisterInfo(XED_REG_ES, 0, 2);
		case XED_REG_SS:     return RegisterInfo(XED_REG_SS, 0, 2);
		case XED_REG_FS:     return RegisterInfo(XED_REG_FS, 0, 2);
		case XED_REG_GS:     return RegisterInfo(XED_REG_GS, 0, 2);
		case XED_REG_FSBASE: return RegisterInfo(XED_REG_FSBASE, 0, 2);
		case XED_REG_GSBASE: return RegisterInfo(XED_REG_GSBASE, 0, 2);
		case XED_REG_SP:     return RegisterInfo(XED_REG_SP, 0, 2);
		case XED_REG_BP:     return RegisterInfo(XED_REG_BP, 0, 2);
		case XED_REG_SI:     return RegisterInfo(XED_REG_SI, 0, 2);
		case XED_REG_DI:     return RegisterInfo(XED_REG_DI, 0, 2);
		case XED_REG_FLAGS:  return RegisterInfo(XED_REG_FLAGS, 0, 2);
		case XED_REG_AX:     return RegisterInfo(XED_REG_AX, 0, 2);
		case XED_REG_CX:     return RegisterInfo(XED_REG_CX, 0, 2);
		case XED_REG_DX:     return RegisterInfo(XED_REG_DX, 0, 2);
		case XED_REG_BX:     return RegisterInfo(XED_REG_BX, 0, 2);
		case XED_REG_TR:     return RegisterInfo(XED_REG_TR, 0, 2);

		default:             return RegisterInfo(XED_REG_INVALID, 0, 0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return XED_REG_SP;
	}
};


class X64Architecture: public X86CommonArchitecture
{
protected:
	virtual size_t GetAddressSize() const override
	{
		return 8;
	}

public:
	X64Architecture(): X86CommonArchitecture("x86_64", 64)
	{}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector< uint32_t>  {
			// 16-Bit
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+
			XED_REG_SP, XED_REG_BP, XED_REG_SI, XED_REG_DI,  // 16+

			// x87 FPU related
			REG_X87_TOP, XED_REG_X87CONTROL, XED_REG_X87STATUS, XED_REG_X87TAG, XED_REG_X87OPCODE, XED_REG_X87LASTCS,
			XED_REG_X87LASTDS, XED_REG_X87LASTIP, XED_REG_X87LASTDP, XED_REG_X87PUSH, XED_REG_X87POP, XED_REG_X87POP2,

			// 48-Bit (All 32+)
			XED_REG_GDTR,  // Global Descriptor Table Register
			XED_REG_LDTR,  // Local Descriptor Table Register
			XED_REG_IDTR,  // Interrupt Descriptor Table Register

			// 64-Bit
			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register
			XED_REG_TSC, XED_REG_TSCAUX,  // 32+ (32 on 32, 64 on 64) Timestamp Counters
			XED_REG_RIP,  // 64+
			XED_REG_RSP, XED_REG_RBP, XED_REG_RSI, XED_REG_RDI,  // 64+
			XED_REG_RFLAGS,  // 64+
			XED_REG_MXCSR,  // 32+ SSE (MMX) Control Reg (32 on 32, 64 on 64)
			XED_REG_XCR0,  // 32+ (64 on 32, 64 on 64)
			XED_REG_SSP,  // 64+ Shadow Stack Reg

			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX, XED_REG_RBX,  // 64+
			XED_REG_R8, XED_REG_R9, XED_REG_R10, XED_REG_R11, XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15,  // 64+

			XED_REG_BNDCFGU, XED_REG_BNDSTATUS,  // 64 briefly. MPX control registers
			XED_REG_K0, XED_REG_K1, XED_REG_K2, XED_REG_K3, XED_REG_K4, XED_REG_K5, XED_REG_K6, XED_REG_K7,  // 64+ AVX bit-masking registers (also not confident in size)

			XED_REG_MSRS,

			XED_REG_CR0, XED_REG_CR1, XED_REG_CR2, XED_REG_CR3, XED_REG_CR4, XED_REG_CR5, XED_REG_CR6, XED_REG_CR7, XED_REG_CR8, XED_REG_CR9, XED_REG_CR10, XED_REG_CR11, XED_REG_CR12, XED_REG_CR13, XED_REG_CR14, XED_REG_CR15,  // 32+ (32 on 32, 64 on 64) Control Registers
			XED_REG_DR0, XED_REG_DR1, XED_REG_DR2, XED_REG_DR3, XED_REG_DR4, XED_REG_DR5, XED_REG_DR6, XED_REG_DR7,  // 32+ (starting in later revisions of 32) (32 on 32, 64 on 64) Debug registers

			// 80-Bit
			XED_REG_ST0, XED_REG_ST1, XED_REG_ST2, XED_REG_ST3, XED_REG_ST4, XED_REG_ST5, XED_REG_ST6, XED_REG_ST7,  // 32+ Floating point
			REG_X87_r(0), REG_X87_r(1), REG_X87_r(2), REG_X87_r(3), REG_X87_r(4), REG_X87_r(5), REG_X87_r(6), REG_X87_r(7),

			// 128-Bit
			XED_REG_BND0, XED_REG_BND1, XED_REG_BND2, XED_REG_BND3,  // 64 briefly. MPX registers

			// 512-Bit
			XED_REG_ZMM0, XED_REG_ZMM1, XED_REG_ZMM2, XED_REG_ZMM3, XED_REG_ZMM4, XED_REG_ZMM5, XED_REG_ZMM6, XED_REG_ZMM7, XED_REG_ZMM8, XED_REG_ZMM9, XED_REG_ZMM10, XED_REG_ZMM11, XED_REG_ZMM12, XED_REG_ZMM13, XED_REG_ZMM14, XED_REG_ZMM15, XED_REG_ZMM16, XED_REG_ZMM17, XED_REG_ZMM18, XED_REG_ZMM19, XED_REG_ZMM20, XED_REG_ZMM21, XED_REG_ZMM22, XED_REG_ZMM23, XED_REG_ZMM24, XED_REG_ZMM25, XED_REG_ZMM26, XED_REG_ZMM27, XED_REG_ZMM28, XED_REG_ZMM29, XED_REG_ZMM30, XED_REG_ZMM31  // 64+ AVX
		};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		return vector< uint32_t> {
			// 8-Bit
			XED_REG_AH, XED_REG_CH, XED_REG_DH, XED_REG_BH, XED_REG_AL, XED_REG_CL, XED_REG_DL, XED_REG_BL,  // 16+
			XED_REG_SPL, XED_REG_BPL, XED_REG_SIL, XED_REG_DIL,  // 64+
			XED_REG_R8B, XED_REG_R9B, XED_REG_R10B, XED_REG_R11B, XED_REG_R12B, XED_REG_R13B, XED_REG_R14B, XED_REG_R15B,  // 64+

			// 16-Bit
			XED_REG_IP,  // 16+
			XED_REG_CS, XED_REG_DS, XED_REG_ES, XED_REG_SS, XED_REG_FS, XED_REG_GS, XED_REG_FSBASE, XED_REG_GSBASE,  // 16+
			XED_REG_SP, XED_REG_BP, XED_REG_SI, XED_REG_DI,  // 16+
			XED_REG_FLAGS,  // 16+

			REG_X87_TOP, // 32+
			XED_REG_X87CONTROL, XED_REG_X87STATUS, XED_REG_X87TAG, XED_REG_X87PUSH, XED_REG_X87POP,
			XED_REG_X87POP2, XED_REG_X87OPCODE, XED_REG_X87LASTCS, XED_REG_X87LASTIP, XED_REG_X87LASTDS, XED_REG_X87LASTDP,

			XED_REG_AX, XED_REG_CX, XED_REG_DX, XED_REG_BX,  // 16+
			XED_REG_R8W, XED_REG_R9W, XED_REG_R10W, XED_REG_R11W, XED_REG_R12W, XED_REG_R13W, XED_REG_R14W, XED_REG_R15W,  // 64+

			// 32-Bit
			XED_REG_EIP,  // 32+
			XED_REG_ESP, XED_REG_EBP, XED_REG_ESI, XED_REG_EDI,  // 32+
			XED_REG_EFLAGS,  // 32+

			XED_REG_EAX, XED_REG_ECX, XED_REG_EDX, XED_REG_EBX,  // 32+
			XED_REG_R8D, XED_REG_R9D, XED_REG_R10D, XED_REG_R11D, XED_REG_R12D, XED_REG_R13D, XED_REG_R14D, XED_REG_R15D,  // 64+

			// 48-Bit (All 32+)
			XED_REG_GDTR,  // Global Descriptor Table Register
			XED_REG_LDTR,  // Local Descriptor Table Register
			XED_REG_IDTR,  // Interrupt Descriptor Table Register

			// 64-Bit
			XED_REG_TR,  // 16+ (16 on 16, 32 on 32, 64 on 64) Task Register
			XED_REG_TSC, XED_REG_TSCAUX,  // 32+ (32 on 32, 64 on 64) Timestamp Counters
			XED_REG_MMX0, XED_REG_MMX1, XED_REG_MMX2, XED_REG_MMX3, XED_REG_MMX4, XED_REG_MMX5, XED_REG_MMX6, XED_REG_MMX7,  // 32+ Floating point, bottom of st regs
			XED_REG_RIP,  // 64+
			XED_REG_RSP, XED_REG_RBP, XED_REG_RSI, XED_REG_RDI,  // 64+
			XED_REG_RFLAGS,  // 64+
			XED_REG_MXCSR,  // 32+ SSE (MMX) Control Reg (32 on 32, 64 on 64)
			XED_REG_XCR0,  // 32+ (64 on 32, 64 on 64)
			XED_REG_SSP,  // 64+ Shadow Stack Reg

			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX, XED_REG_RBX,  // 64+
			XED_REG_R8, XED_REG_R9, XED_REG_R10, XED_REG_R11, XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15,  // 64+

			XED_REG_BNDCFGU, XED_REG_BNDSTATUS,  // 64 briefly. MPX control registers
			XED_REG_K0, XED_REG_K1, XED_REG_K2, XED_REG_K3, XED_REG_K4, XED_REG_K5, XED_REG_K6, XED_REG_K7,  // 64+ AVX bit-masking registers (also not confident in size)

			XED_REG_MSRS,

			XED_REG_CR0, XED_REG_CR1, XED_REG_CR2, XED_REG_CR3, XED_REG_CR4, XED_REG_CR5, XED_REG_CR6, XED_REG_CR7, XED_REG_CR8, XED_REG_CR9, XED_REG_CR10, XED_REG_CR11, XED_REG_CR12, XED_REG_CR13, XED_REG_CR14, XED_REG_CR15,  // 32+ (32 on 32, 64 on 64) Control Registers
			XED_REG_DR0, XED_REG_DR1, XED_REG_DR2, XED_REG_DR3, XED_REG_DR4, XED_REG_DR5, XED_REG_DR6, XED_REG_DR7,  // 32+ (starting in later revisions of 32) (32 on 32, 64 on 64) Debug registers

			// 80-Bit
			XED_REG_ST0, XED_REG_ST1, XED_REG_ST2, XED_REG_ST3, XED_REG_ST4, XED_REG_ST5, XED_REG_ST6, XED_REG_ST7,  // 32+ Floating point
			REG_X87_r(0), REG_X87_r(1), REG_X87_r(2), REG_X87_r(3), REG_X87_r(4), REG_X87_r(5), REG_X87_r(6), REG_X87_r(7),

			// 128-Bit
			XED_REG_XMM0, XED_REG_XMM1, XED_REG_XMM2, XED_REG_XMM3, XED_REG_XMM4, XED_REG_XMM5, XED_REG_XMM6, XED_REG_XMM7,  // 32+ SSE
			XED_REG_XMM8, XED_REG_XMM9, XED_REG_XMM10, XED_REG_XMM11, XED_REG_XMM12, XED_REG_XMM13, XED_REG_XMM14, XED_REG_XMM15,  // 64+ SSE
			XED_REG_XMM16, XED_REG_XMM17, XED_REG_XMM18, XED_REG_XMM19, XED_REG_XMM20, XED_REG_XMM21, XED_REG_XMM22, XED_REG_XMM23, XED_REG_XMM24, XED_REG_XMM25, XED_REG_XMM26, XED_REG_XMM27, XED_REG_XMM28, XED_REG_XMM29, XED_REG_XMM30, XED_REG_XMM31,  // 64+ AVX
			XED_REG_BND0, XED_REG_BND1, XED_REG_BND2, XED_REG_BND3,  // 64 briefly. MPX registers

			// 256-Bit
			XED_REG_YMM0, XED_REG_YMM1, XED_REG_YMM2, XED_REG_YMM3, XED_REG_YMM4, XED_REG_YMM5, XED_REG_YMM6, XED_REG_YMM7, XED_REG_YMM8, XED_REG_YMM9, XED_REG_YMM10, XED_REG_YMM11, XED_REG_YMM12, XED_REG_YMM13, XED_REG_YMM14, XED_REG_YMM15, XED_REG_YMM16, XED_REG_YMM17, XED_REG_YMM18, XED_REG_YMM19, XED_REG_YMM20, XED_REG_YMM21, XED_REG_YMM22, XED_REG_YMM23, XED_REG_YMM24, XED_REG_YMM25, XED_REG_YMM26, XED_REG_YMM27, XED_REG_YMM28, XED_REG_YMM29, XED_REG_YMM30, XED_REG_YMM31,  // 64+ AVX

			// 512-Bit
			XED_REG_ZMM0, XED_REG_ZMM1, XED_REG_ZMM2, XED_REG_ZMM3, XED_REG_ZMM4, XED_REG_ZMM5, XED_REG_ZMM6, XED_REG_ZMM7, XED_REG_ZMM8, XED_REG_ZMM9, XED_REG_ZMM10, XED_REG_ZMM11, XED_REG_ZMM12, XED_REG_ZMM13, XED_REG_ZMM14, XED_REG_ZMM15, XED_REG_ZMM16, XED_REG_ZMM17, XED_REG_ZMM18, XED_REG_ZMM19, XED_REG_ZMM20, XED_REG_ZMM21, XED_REG_ZMM22, XED_REG_ZMM23, XED_REG_ZMM24, XED_REG_ZMM25, XED_REG_ZMM26, XED_REG_ZMM27, XED_REG_ZMM28, XED_REG_ZMM29, XED_REG_ZMM30, XED_REG_ZMM31  // 64+ AVX
		};
	}

	virtual BNRegisterInfo GetRegisterInfo(const uint32_t reg) override
	{
		switch (reg)
		{
		// 8-Bit
		case XED_REG_AH:        return RegisterInfo(XED_REG_RAX, 1, 1);
		case XED_REG_CH:        return RegisterInfo(XED_REG_RCX, 1, 1);
		case XED_REG_DH:        return RegisterInfo(XED_REG_RDX, 1, 1);
		case XED_REG_BH:        return RegisterInfo(XED_REG_RBX, 1, 1);
		case XED_REG_AL:        return RegisterInfo(XED_REG_RAX, 0, 1);
		case XED_REG_CL:        return RegisterInfo(XED_REG_RCX, 0, 1);
		case XED_REG_DL:        return RegisterInfo(XED_REG_RDX, 0, 1);
		case XED_REG_BL:        return RegisterInfo(XED_REG_RBX, 0, 1);

		case XED_REG_SPL:       return RegisterInfo(XED_REG_RSP, 0, 1);
		case XED_REG_BPL:       return RegisterInfo(XED_REG_RBP, 0, 1);
		case XED_REG_SIL:       return RegisterInfo(XED_REG_RSI, 0, 1);
		case XED_REG_DIL:       return RegisterInfo(XED_REG_RDI, 0, 1);

		case XED_REG_R8B:       return RegisterInfo(XED_REG_R8, 0, 1);
		case XED_REG_R9B:       return RegisterInfo(XED_REG_R9, 0, 1);
		case XED_REG_R10B:      return RegisterInfo(XED_REG_R10, 0, 1);
		case XED_REG_R11B:      return RegisterInfo(XED_REG_R11, 0, 1);
		case XED_REG_R12B:      return RegisterInfo(XED_REG_R12, 0, 1);
		case XED_REG_R13B:      return RegisterInfo(XED_REG_R13, 0, 1);
		case XED_REG_R14B:      return RegisterInfo(XED_REG_R14, 0, 1);
		case XED_REG_R15B:      return RegisterInfo(XED_REG_R15, 0, 1);

		// 16-Bit
		case XED_REG_IP:        return RegisterInfo(XED_REG_RIP, 0, 2);

		case XED_REG_CS:        return RegisterInfo(XED_REG_CS, 0, 2);
		case XED_REG_DS:        return RegisterInfo(XED_REG_DS, 0, 2);
		case XED_REG_ES:        return RegisterInfo(XED_REG_ES, 0, 2);
		case XED_REG_SS:        return RegisterInfo(XED_REG_SS, 0, 2);
		case XED_REG_FS:        return RegisterInfo(XED_REG_FS, 0, 2);
		case XED_REG_GS:        return RegisterInfo(XED_REG_GS, 0, 2);

		case XED_REG_SP:        return RegisterInfo(XED_REG_RSP, 0, 2);
		case XED_REG_BP:        return RegisterInfo(XED_REG_RBP, 0, 2);
		case XED_REG_SI:        return RegisterInfo(XED_REG_RSI, 0, 2);
		case XED_REG_DI:        return RegisterInfo(XED_REG_RDI, 0, 2);

		case XED_REG_FLAGS:     return RegisterInfo(XED_REG_RFLAGS, 0, 2);

		case XED_REG_AX:        return RegisterInfo(XED_REG_RAX, 0, 2);
		case XED_REG_CX:        return RegisterInfo(XED_REG_RCX, 0, 2);
		case XED_REG_DX:        return RegisterInfo(XED_REG_RDX, 0, 2);
		case XED_REG_BX:        return RegisterInfo(XED_REG_RBX, 0, 2);
		case XED_REG_R8W:       return RegisterInfo(XED_REG_R8, 0, 2);
		case XED_REG_R9W:       return RegisterInfo(XED_REG_R9, 0, 2);
		case XED_REG_R10W:      return RegisterInfo(XED_REG_R10, 0, 2);
		case XED_REG_R11W:      return RegisterInfo(XED_REG_R11, 0, 2);
		case XED_REG_R12W:      return RegisterInfo(XED_REG_R12, 0, 2);
		case XED_REG_R13W:      return RegisterInfo(XED_REG_R13, 0, 2);
		case XED_REG_R14W:      return RegisterInfo(XED_REG_R14, 0, 2);
		case XED_REG_R15W:      return RegisterInfo(XED_REG_R15, 0, 2);

		// 32-Bit
		case XED_REG_EIP:       return RegisterInfo(XED_REG_RIP, 0, 4);

		case XED_REG_ESP:       return RegisterInfo(XED_REG_RSP, 0, 4, true);
		case XED_REG_EBP:       return RegisterInfo(XED_REG_RBP, 0, 4, true);
		case XED_REG_ESI:       return RegisterInfo(XED_REG_RSI, 0, 4, true);
		case XED_REG_EDI:       return RegisterInfo(XED_REG_RDI, 0, 4, true);

		case REG_X87_TOP:              return RegisterInfo((xed_reg_enum_t)REG_X87_TOP, 0, 2);
		case XED_REG_X87CONTROL:       return RegisterInfo(XED_REG_X87CONTROL, 0, 2);
		case XED_REG_X87STATUS:        return RegisterInfo(XED_REG_X87STATUS, 0, 2);
		case XED_REG_X87TAG:           return RegisterInfo(XED_REG_X87TAG, 0, 2);
		case XED_REG_X87OPCODE:        return RegisterInfo(XED_REG_X87OPCODE, 0, 2);
		case XED_REG_X87LASTCS:        return RegisterInfo(XED_REG_X87LASTCS, 0, 2);
		case XED_REG_X87LASTDS:        return RegisterInfo(XED_REG_X87LASTDS, 0, 2);
		case XED_REG_X87LASTIP:        return RegisterInfo(XED_REG_X87LASTIP, 0, 8);
		case XED_REG_X87LASTDP:        return RegisterInfo(XED_REG_X87LASTDP, 0, 8);
		case XED_REG_X87PUSH:          return RegisterInfo(XED_REG_X87PUSH, 0, 8);
		case XED_REG_X87POP:           return RegisterInfo(XED_REG_X87POP, 0, 8);
		case XED_REG_X87POP2:          return RegisterInfo(XED_REG_X87POP2, 0, 8);

		case XED_REG_EFLAGS:    return RegisterInfo(XED_REG_RFLAGS, 0, 4, true);

		case XED_REG_EAX:       return RegisterInfo(XED_REG_RAX, 0, 4, true);
		case XED_REG_ECX:       return RegisterInfo(XED_REG_RCX, 0, 4, true);
		case XED_REG_EDX:       return RegisterInfo(XED_REG_RDX, 0, 4, true);
		case XED_REG_EBX:       return RegisterInfo(XED_REG_RBX, 0, 4, true);

		case XED_REG_R8D:       return RegisterInfo(XED_REG_R8, 0, 4, true);
		case XED_REG_R9D:       return RegisterInfo(XED_REG_R9, 0, 4, true);
		case XED_REG_R10D:      return RegisterInfo(XED_REG_R10, 0, 4, true);
		case XED_REG_R11D:      return RegisterInfo(XED_REG_R11, 0, 4, true);
		case XED_REG_R12D:      return RegisterInfo(XED_REG_R12, 0, 4, true);
		case XED_REG_R13D:      return RegisterInfo(XED_REG_R13, 0, 4, true);
		case XED_REG_R14D:      return RegisterInfo(XED_REG_R14, 0, 4, true);
		case XED_REG_R15D:      return RegisterInfo(XED_REG_R15, 0, 4, true);

		// 48-Bit
		case XED_REG_GDTR:      return RegisterInfo(XED_REG_GDTR, 0, 6);
		case XED_REG_LDTR:      return RegisterInfo(XED_REG_LDTR, 0, 6);
		case XED_REG_IDTR:      return RegisterInfo(XED_REG_IDTR, 0, 6);

		// 64-Bit
		case XED_REG_FSBASE:    return RegisterInfo(XED_REG_FSBASE, 0, 8);
		case XED_REG_GSBASE:    return RegisterInfo(XED_REG_GSBASE, 0, 8);
		case XED_REG_TSC:       return RegisterInfo(XED_REG_TSC, 0, 8);
		case XED_REG_TSCAUX:    return RegisterInfo(XED_REG_TSCAUX, 0, 8);
		case XED_REG_TR:        return RegisterInfo(XED_REG_TR, 0, 8);

		case XED_REG_MMX0:      return RegisterInfo(XED_REG_ST0, 0, 8);
		case XED_REG_MMX1:      return RegisterInfo(XED_REG_ST1, 0, 8);
		case XED_REG_MMX2:      return RegisterInfo(XED_REG_ST2, 0, 8);
		case XED_REG_MMX3:      return RegisterInfo(XED_REG_ST3, 0, 8);
		case XED_REG_MMX4:      return RegisterInfo(XED_REG_ST4, 0, 8);
		case XED_REG_MMX5:      return RegisterInfo(XED_REG_ST5, 0, 8);
		case XED_REG_MMX6:      return RegisterInfo(XED_REG_ST6, 0, 8);
		case XED_REG_MMX7:      return RegisterInfo(XED_REG_ST7, 0, 8);

		case XED_REG_RIP:       return RegisterInfo(XED_REG_RIP, 0, 8);

		case XED_REG_RSP:       return RegisterInfo(XED_REG_RSP, 0, 8);
		case XED_REG_RBP:       return RegisterInfo(XED_REG_RBP, 0, 8);
		case XED_REG_RSI:       return RegisterInfo(XED_REG_RSI, 0, 8);
		case XED_REG_RDI:       return RegisterInfo(XED_REG_RDI, 0, 8);

		case XED_REG_RFLAGS:    return RegisterInfo(XED_REG_RFLAGS, 0, 8);

		case XED_REG_MXCSR:     return RegisterInfo(XED_REG_MXCSR, 0, 8);
		case XED_REG_XCR0:      return RegisterInfo(XED_REG_XCR0, 0, 8);
		case XED_REG_SSP:       return RegisterInfo(XED_REG_SSP, 0, 8);

		case XED_REG_RAX:       return RegisterInfo(XED_REG_RAX, 0, 8);
		case XED_REG_RCX:       return RegisterInfo(XED_REG_RCX, 0, 8);
		case XED_REG_RDX:       return RegisterInfo(XED_REG_RDX, 0, 8);
		case XED_REG_RBX:       return RegisterInfo(XED_REG_RBX, 0, 8);
		case XED_REG_R8:        return RegisterInfo(XED_REG_R8, 0, 8);
		case XED_REG_R9:        return RegisterInfo(XED_REG_R9, 0, 8);
		case XED_REG_R10:       return RegisterInfo(XED_REG_R10, 0, 8);
		case XED_REG_R11:       return RegisterInfo(XED_REG_R11, 0, 8);
		case XED_REG_R12:       return RegisterInfo(XED_REG_R12, 0, 8);
		case XED_REG_R13:       return RegisterInfo(XED_REG_R13, 0, 8);
		case XED_REG_R14:       return RegisterInfo(XED_REG_R14, 0, 8);
		case XED_REG_R15:       return RegisterInfo(XED_REG_R15, 0, 8);

		case XED_REG_BNDCFGU:   return RegisterInfo(XED_REG_BNDCFGU, 0, 8);
		case XED_REG_BNDSTATUS: return RegisterInfo(XED_REG_BNDSTATUS, 0, 8);

		case XED_REG_K0:        return RegisterInfo(XED_REG_K0, 0, 8);
		case XED_REG_K1:        return RegisterInfo(XED_REG_K1, 0, 8);
		case XED_REG_K2:        return RegisterInfo(XED_REG_K2, 0, 8);
		case XED_REG_K3:        return RegisterInfo(XED_REG_K3, 0, 8);
		case XED_REG_K4:        return RegisterInfo(XED_REG_K4, 0, 8);
		case XED_REG_K5:        return RegisterInfo(XED_REG_K5, 0, 8);
		case XED_REG_K6:        return RegisterInfo(XED_REG_K6, 0, 8);
		case XED_REG_K7:        return RegisterInfo(XED_REG_K7, 0, 8);

		case XED_REG_CR0:       return RegisterInfo(XED_REG_CR0, 0, 8);
		case XED_REG_CR1:       return RegisterInfo(XED_REG_CR1, 0, 8);
		case XED_REG_CR2:       return RegisterInfo(XED_REG_CR2, 0, 8);
		case XED_REG_CR3:       return RegisterInfo(XED_REG_CR3, 0, 8);
		case XED_REG_CR4:       return RegisterInfo(XED_REG_CR4, 0, 8);
		case XED_REG_CR5:       return RegisterInfo(XED_REG_CR5, 0, 8);
		case XED_REG_CR6:       return RegisterInfo(XED_REG_CR6, 0, 8);
		case XED_REG_CR7:       return RegisterInfo(XED_REG_CR7, 0, 8);
		case XED_REG_CR8:       return RegisterInfo(XED_REG_CR8, 0, 8);
		case XED_REG_CR9:       return RegisterInfo(XED_REG_CR9, 0, 8);
		case XED_REG_CR10:      return RegisterInfo(XED_REG_CR10, 0, 8);
		case XED_REG_CR11:      return RegisterInfo(XED_REG_CR11, 0, 8);
		case XED_REG_CR12:      return RegisterInfo(XED_REG_CR12, 0, 8);
		case XED_REG_CR13:      return RegisterInfo(XED_REG_CR13, 0, 8);
		case XED_REG_CR14:      return RegisterInfo(XED_REG_CR14, 0, 8);
		case XED_REG_CR15:      return RegisterInfo(XED_REG_CR15, 0, 8);

		case XED_REG_DR0:       return RegisterInfo(XED_REG_DR0, 0, 8);
		case XED_REG_DR1:       return RegisterInfo(XED_REG_DR1, 0, 8);
		case XED_REG_DR2:       return RegisterInfo(XED_REG_DR2, 0, 8);
		case XED_REG_DR3:       return RegisterInfo(XED_REG_DR3, 0, 8);
		case XED_REG_DR4:       return RegisterInfo(XED_REG_DR4, 0, 8);
		case XED_REG_DR5:       return RegisterInfo(XED_REG_DR5, 0, 8);
		case XED_REG_DR6:       return RegisterInfo(XED_REG_DR6, 0, 8);
		case XED_REG_DR7:       return RegisterInfo(XED_REG_DR7, 0, 8);

		case XED_REG_MSRS:	    return RegisterInfo(XED_REG_MSRS, 0, 8);

		// 80-Bit
		case XED_REG_ST0:       return RegisterInfo(XED_REG_ST0, 0, 10);
		case XED_REG_ST1:       return RegisterInfo(XED_REG_ST1, 0, 10);
		case XED_REG_ST2:       return RegisterInfo(XED_REG_ST2, 0, 10);
		case XED_REG_ST3:       return RegisterInfo(XED_REG_ST3, 0, 10);
		case XED_REG_ST4:       return RegisterInfo(XED_REG_ST4, 0, 10);
		case XED_REG_ST5:       return RegisterInfo(XED_REG_ST5, 0, 10);
		case XED_REG_ST6:       return RegisterInfo(XED_REG_ST6, 0, 10);
		case XED_REG_ST7:       return RegisterInfo(XED_REG_ST7, 0, 10);

		case REG_X87_r(0):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(0), 0, 10);
		case REG_X87_r(1):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(1), 0, 10);
		case REG_X87_r(2):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(2), 0, 10);
		case REG_X87_r(3):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(3), 0, 10);
		case REG_X87_r(4):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(4), 0, 10);
		case REG_X87_r(5):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(5), 0, 10);
		case REG_X87_r(6):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(6), 0, 10);
		case REG_X87_r(7):      return RegisterInfo((xed_reg_enum_t)REG_X87_r(7), 0, 10);

		// 128-Bit
		case XED_REG_XMM0:      return RegisterInfo(XED_REG_ZMM0, 0, 16);
		case XED_REG_XMM1:      return RegisterInfo(XED_REG_ZMM1, 0, 16);
		case XED_REG_XMM2:      return RegisterInfo(XED_REG_ZMM2, 0, 16);
		case XED_REG_XMM3:      return RegisterInfo(XED_REG_ZMM3, 0, 16);
		case XED_REG_XMM4:      return RegisterInfo(XED_REG_ZMM4, 0, 16);
		case XED_REG_XMM5:      return RegisterInfo(XED_REG_ZMM5, 0, 16);
		case XED_REG_XMM6:      return RegisterInfo(XED_REG_ZMM6, 0, 16);
		case XED_REG_XMM7:      return RegisterInfo(XED_REG_ZMM7, 0, 16);
		case XED_REG_XMM8:      return RegisterInfo(XED_REG_ZMM8, 0, 16);
		case XED_REG_XMM9:      return RegisterInfo(XED_REG_ZMM9, 0, 16);
		case XED_REG_XMM10:     return RegisterInfo(XED_REG_ZMM10, 0, 16);
		case XED_REG_XMM11:     return RegisterInfo(XED_REG_ZMM11, 0, 16);
		case XED_REG_XMM12:     return RegisterInfo(XED_REG_ZMM12, 0, 16);
		case XED_REG_XMM13:     return RegisterInfo(XED_REG_ZMM13, 0, 16);
		case XED_REG_XMM14:     return RegisterInfo(XED_REG_ZMM14, 0, 16);
		case XED_REG_XMM15:     return RegisterInfo(XED_REG_ZMM15, 0, 16);
		case XED_REG_XMM16:     return RegisterInfo(XED_REG_ZMM16, 0, 16);
		case XED_REG_XMM17:     return RegisterInfo(XED_REG_ZMM17, 0, 16);
		case XED_REG_XMM18:     return RegisterInfo(XED_REG_ZMM18, 0, 16);
		case XED_REG_XMM19:     return RegisterInfo(XED_REG_ZMM19, 0, 16);
		case XED_REG_XMM20:     return RegisterInfo(XED_REG_ZMM20, 0, 16);
		case XED_REG_XMM21:     return RegisterInfo(XED_REG_ZMM21, 0, 16);
		case XED_REG_XMM22:     return RegisterInfo(XED_REG_ZMM22, 0, 16);
		case XED_REG_XMM23:     return RegisterInfo(XED_REG_ZMM23, 0, 16);
		case XED_REG_XMM24:     return RegisterInfo(XED_REG_ZMM24, 0, 16);
		case XED_REG_XMM25:     return RegisterInfo(XED_REG_ZMM25, 0, 16);
		case XED_REG_XMM26:     return RegisterInfo(XED_REG_ZMM26, 0, 16);
		case XED_REG_XMM27:     return RegisterInfo(XED_REG_ZMM27, 0, 16);
		case XED_REG_XMM28:     return RegisterInfo(XED_REG_ZMM28, 0, 16);
		case XED_REG_XMM29:     return RegisterInfo(XED_REG_ZMM29, 0, 16);
		case XED_REG_XMM30:     return RegisterInfo(XED_REG_ZMM30, 0, 16);
		case XED_REG_XMM31:     return RegisterInfo(XED_REG_ZMM31, 0, 16);

		case XED_REG_BND0:      return RegisterInfo(XED_REG_BND0, 0, 16);
		case XED_REG_BND1:      return RegisterInfo(XED_REG_BND1, 0, 16);
		case XED_REG_BND2:      return RegisterInfo(XED_REG_BND2, 0, 16);
		case XED_REG_BND3:      return RegisterInfo(XED_REG_BND3, 0, 16);

		// 256-Bit
		case XED_REG_YMM0:      return RegisterInfo(XED_REG_ZMM0, 0, 32);
		case XED_REG_YMM1:      return RegisterInfo(XED_REG_ZMM1, 0, 32);
		case XED_REG_YMM2:      return RegisterInfo(XED_REG_ZMM2, 0, 32);
		case XED_REG_YMM3:      return RegisterInfo(XED_REG_ZMM3, 0, 32);
		case XED_REG_YMM4:      return RegisterInfo(XED_REG_ZMM4, 0, 32);
		case XED_REG_YMM5:      return RegisterInfo(XED_REG_ZMM5, 0, 32);
		case XED_REG_YMM6:      return RegisterInfo(XED_REG_ZMM6, 0, 32);
		case XED_REG_YMM7:      return RegisterInfo(XED_REG_ZMM7, 0, 32);
		case XED_REG_YMM8:      return RegisterInfo(XED_REG_ZMM8, 0, 32);
		case XED_REG_YMM9:      return RegisterInfo(XED_REG_ZMM9, 0, 32);
		case XED_REG_YMM10:     return RegisterInfo(XED_REG_ZMM10, 0, 32);
		case XED_REG_YMM11:     return RegisterInfo(XED_REG_ZMM11, 0, 32);
		case XED_REG_YMM12:     return RegisterInfo(XED_REG_ZMM12, 0, 32);
		case XED_REG_YMM13:     return RegisterInfo(XED_REG_ZMM13, 0, 32);
		case XED_REG_YMM14:     return RegisterInfo(XED_REG_ZMM14, 0, 32);
		case XED_REG_YMM15:     return RegisterInfo(XED_REG_ZMM15, 0, 32);
		case XED_REG_YMM16:     return RegisterInfo(XED_REG_ZMM16, 0, 32);
		case XED_REG_YMM17:     return RegisterInfo(XED_REG_ZMM17, 0, 32);
		case XED_REG_YMM18:     return RegisterInfo(XED_REG_ZMM18, 0, 32);
		case XED_REG_YMM19:     return RegisterInfo(XED_REG_ZMM19, 0, 32);
		case XED_REG_YMM20:     return RegisterInfo(XED_REG_ZMM20, 0, 32);
		case XED_REG_YMM21:     return RegisterInfo(XED_REG_ZMM21, 0, 32);
		case XED_REG_YMM22:     return RegisterInfo(XED_REG_ZMM22, 0, 32);
		case XED_REG_YMM23:     return RegisterInfo(XED_REG_ZMM23, 0, 32);
		case XED_REG_YMM24:     return RegisterInfo(XED_REG_ZMM24, 0, 32);
		case XED_REG_YMM25:     return RegisterInfo(XED_REG_ZMM25, 0, 32);
		case XED_REG_YMM26:     return RegisterInfo(XED_REG_ZMM26, 0, 32);
		case XED_REG_YMM27:     return RegisterInfo(XED_REG_ZMM27, 0, 32);
		case XED_REG_YMM28:     return RegisterInfo(XED_REG_ZMM28, 0, 32);
		case XED_REG_YMM29:     return RegisterInfo(XED_REG_ZMM29, 0, 32);
		case XED_REG_YMM30:     return RegisterInfo(XED_REG_ZMM30, 0, 32);
		case XED_REG_YMM31:     return RegisterInfo(XED_REG_ZMM31, 0, 32);

		// 512-Bit
		case XED_REG_ZMM0:      return RegisterInfo(XED_REG_ZMM0, 0, 64);
		case XED_REG_ZMM1:      return RegisterInfo(XED_REG_ZMM1, 0, 64);
		case XED_REG_ZMM2:      return RegisterInfo(XED_REG_ZMM2, 0, 64);
		case XED_REG_ZMM3:      return RegisterInfo(XED_REG_ZMM3, 0, 64);
		case XED_REG_ZMM4:      return RegisterInfo(XED_REG_ZMM4, 0, 64);
		case XED_REG_ZMM5:      return RegisterInfo(XED_REG_ZMM5, 0, 64);
		case XED_REG_ZMM6:      return RegisterInfo(XED_REG_ZMM6, 0, 64);
		case XED_REG_ZMM7:      return RegisterInfo(XED_REG_ZMM7, 0, 64);
		case XED_REG_ZMM8:      return RegisterInfo(XED_REG_ZMM8, 0, 64);
		case XED_REG_ZMM9:      return RegisterInfo(XED_REG_ZMM9, 0, 64);
		case XED_REG_ZMM10:     return RegisterInfo(XED_REG_ZMM10, 0, 64);
		case XED_REG_ZMM11:     return RegisterInfo(XED_REG_ZMM11, 0, 64);
		case XED_REG_ZMM12:     return RegisterInfo(XED_REG_ZMM12, 0, 64);
		case XED_REG_ZMM13:     return RegisterInfo(XED_REG_ZMM13, 0, 64);
		case XED_REG_ZMM14:     return RegisterInfo(XED_REG_ZMM14, 0, 64);
		case XED_REG_ZMM15:     return RegisterInfo(XED_REG_ZMM15, 0, 64);
		case XED_REG_ZMM16:     return RegisterInfo(XED_REG_ZMM16, 0, 64);
		case XED_REG_ZMM17:     return RegisterInfo(XED_REG_ZMM17, 0, 64);
		case XED_REG_ZMM18:     return RegisterInfo(XED_REG_ZMM18, 0, 64);
		case XED_REG_ZMM19:     return RegisterInfo(XED_REG_ZMM19, 0, 64);
		case XED_REG_ZMM20:     return RegisterInfo(XED_REG_ZMM20, 0, 64);
		case XED_REG_ZMM21:     return RegisterInfo(XED_REG_ZMM21, 0, 64);
		case XED_REG_ZMM22:     return RegisterInfo(XED_REG_ZMM22, 0, 64);
		case XED_REG_ZMM23:     return RegisterInfo(XED_REG_ZMM23, 0, 64);
		case XED_REG_ZMM24:     return RegisterInfo(XED_REG_ZMM24, 0, 64);
		case XED_REG_ZMM25:     return RegisterInfo(XED_REG_ZMM25, 0, 64);
		case XED_REG_ZMM26:     return RegisterInfo(XED_REG_ZMM26, 0, 64);
		case XED_REG_ZMM27:     return RegisterInfo(XED_REG_ZMM27, 0, 64);
		case XED_REG_ZMM28:     return RegisterInfo(XED_REG_ZMM28, 0, 64);
		case XED_REG_ZMM29:     return RegisterInfo(XED_REG_ZMM29, 0, 64);
		case XED_REG_ZMM30:     return RegisterInfo(XED_REG_ZMM30, 0, 64);
		case XED_REG_ZMM31:     return RegisterInfo(XED_REG_ZMM31, 0, 64);

		default:                return RegisterInfo(XED_REG_INVALID, 0, 0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return XED_REG_RSP;
	}
};


class X86BaseCallingConvention: public CallingConvention
{
public:
	X86BaseCallingConvention(Architecture* arch, const string& name): CallingConvention(arch, name)
	{
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ XED_REG_EAX, XED_REG_ECX, XED_REG_EDX };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ XED_REG_EBX, XED_REG_EBP, XED_REG_ESI, XED_REG_EDI };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return XED_REG_EBX;
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return XED_REG_EAX;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return XED_REG_EDX;
	}

	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return XED_REG_ST0;
	}

	virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function*) override
	{
		RegisterValue result;
		if (flag == IL_FLAG_D)
		{
			result.state = ConstantValue;
			result.value = 0;
		}
		return result;
	}
};


class X86CdeclCallingConvention: public X86BaseCallingConvention
{
public:
	X86CdeclCallingConvention(Architecture* arch): X86BaseCallingConvention(arch, "cdecl")
	{
	}
};


class X86StdcallCallingConvention: public X86BaseCallingConvention
{
public:
	X86StdcallCallingConvention(Architecture* arch): X86BaseCallingConvention(arch, "stdcall")
	{
	}

	virtual bool IsStackAdjustedOnReturn() override
	{
		return true;
	}
};


class X86RegParmCallingConvention: public X86BaseCallingConvention
{
public:
	X86RegParmCallingConvention(Architecture* arch): X86BaseCallingConvention(arch, "regparm")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ XED_REG_EAX, XED_REG_EDX, XED_REG_ECX };
	}
};


class X86FastcallCallingConvention: public X86BaseCallingConvention
{
public:
	X86FastcallCallingConvention(Architecture* arch): X86BaseCallingConvention(arch, "fastcall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ XED_REG_ECX, XED_REG_EDX };
	}

	virtual bool IsStackAdjustedOnReturn() override
	{
		return true;
	}
};


class X86ThiscallCallingConvention: public X86BaseCallingConvention
{
public:
	X86ThiscallCallingConvention(Architecture* arch): X86BaseCallingConvention(arch, "thiscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ XED_REG_ECX };
	}

	virtual bool IsStackAdjustedOnReturn() override
	{
		return true;
	}
};


class X86LinuxSystemCallConvention: public CallingConvention
{
public:
	X86LinuxSystemCallConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_EAX, XED_REG_EBX, XED_REG_ECX, XED_REG_EDX, XED_REG_ESI, XED_REG_EDI, XED_REG_EBP };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { XED_REG_EAX, XED_REG_EDX };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { XED_REG_EBX, XED_REG_EBP, XED_REG_ESI, XED_REG_EDI };
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return XED_REG_EAX;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return XED_REG_EDX;
	}

	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return XED_REG_ST0;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};


class X64BaseCallingConvention: public CallingConvention
{
public:
	X64BaseCallingConvention(Architecture* arch, const string& name): CallingConvention(arch, name)
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return XED_REG_RAX;
	}

	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return XED_REG_ZMM0;
	}

	virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function*) override
	{
		RegisterValue result;
		if (flag == IL_FLAG_D)
		{
			result.state = ConstantValue;
			result.value = 0;
		}
		return result;
	}
};


class X64SystemVCallingConvention: public X64BaseCallingConvention
{
public:
	X64SystemVCallingConvention(Architecture* arch): X64BaseCallingConvention(arch, "sysv")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_RDI, XED_REG_RSI, XED_REG_RDX, XED_REG_RCX, XED_REG_R8, XED_REG_R9 };
	}

	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_ZMM0, XED_REG_ZMM1, XED_REG_ZMM2, XED_REG_ZMM3, XED_REG_ZMM4, XED_REG_ZMM5, XED_REG_ZMM6, XED_REG_ZMM7 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> {
			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX,
			XED_REG_RSI, XED_REG_RDI,
			XED_REG_R8, XED_REG_R9, XED_REG_R10, XED_REG_R11,
			XED_REG_ZMM0, XED_REG_ZMM1, XED_REG_ZMM2, XED_REG_ZMM3, XED_REG_ZMM4, XED_REG_ZMM5, XED_REG_ZMM6, XED_REG_ZMM7, XED_REG_ZMM8, XED_REG_ZMM9, XED_REG_ZMM10, XED_REG_ZMM11, XED_REG_ZMM12, XED_REG_ZMM13, XED_REG_ZMM14, XED_REG_ZMM15 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {
			XED_REG_RBX, XED_REG_RBP,
			XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15 };
	}
};


class X64WindowsCallingConvention: public X64BaseCallingConvention
{
public:
	X64WindowsCallingConvention(Architecture* arch): X64BaseCallingConvention(arch, "win64")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_RCX, XED_REG_RDX, XED_REG_R8, XED_REG_R9 };
	}

	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_ZMM0, XED_REG_ZMM1, XED_REG_ZMM2, XED_REG_ZMM3 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> {
			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX,
			XED_REG_R8, XED_REG_R9, XED_REG_R10, XED_REG_R11,
			XED_REG_ZMM4, XED_REG_ZMM5 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {
			XED_REG_RBX, XED_REG_RBP, XED_REG_RSI, XED_REG_RDI,
			XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15 };
	}

	virtual bool AreArgumentRegistersSharedIndex() override
	{
		return true;
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}
};


class X64LinuxSystemCallConvention: public CallingConvention
{
public:
	X64LinuxSystemCallConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> { XED_REG_RAX, XED_REG_RDI, XED_REG_RSI, XED_REG_RDX, XED_REG_R10, XED_REG_R8, XED_REG_R9 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { XED_REG_RAX, XED_REG_RCX, XED_REG_R11 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { XED_REG_RBX, XED_REG_RBP, XED_REG_RSI, XED_REG_RDI,
			XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15 };
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return XED_REG_RAX;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};


class x86MachoRelocationHandler: public RelocationHandler
{
public:

	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest,
		size_t len) override
	{
		(void)view;
		(void)arch;
		(void)len;
		auto info = reloc->GetInfo();
		uint64_t pcRelAddr = info.pcRelative ? reloc->GetAddress() : 0;
		// TODO these need tested
		// uint8_t* dest8 = (uint8_t*)dest;
		// uint16_t* dest16 = (uint16_t*)dest;
		uint32_t* dest32 = (uint32_t*)dest;
		uint32_t target = (uint32_t)reloc->GetTarget();

		switch (info.nativeType)
		{
		case (uint64_t)-1: // Magic number defined in MachOView.cpp
			// We need to write a jump absolute `jmp target`
			dest[0] = '\xe9';
			((uint32_t*)&dest[1])[0] = target - (uint32_t)reloc->GetAddress() - 5;
			break;
		case (uint64_t)-2: // Magic number defined in MachOView.cpp
			dest32[0] = target;
			break;
		case GENERIC_RELOC_VANILLA:
			switch (info.size)
			{
				// TODO these need tested
				// case 1: *dest8 = target - pcRelAddr; break;
				// case 2: *dest16 = target - pcRelAddr; break;
				case 4: *dest32 = (uint32_t)(target - pcRelAddr); break;
				default: break;
			}
			// TODO rebasing
			break;

		default:
			break;
		}

		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			switch (result[i].nativeType)
			{
			case GENERIC_RELOC_VANILLA:
				if (result[i].size != 4)
				{
					result[i].type = IgnoredRelocation;
					relocTypes.insert(result[i].nativeType);
				}
				break;
			default:
				result[i].type = UnhandledRelocation;
				relocTypes.insert(result[i].nativeType);
				break;
			}
		}

		for (auto& reloc : relocTypes)
			LogWarn("Unsupported Mach-O relocation type: %s", GetRelocationString((Machox86RelocationType)reloc));
		return true;
	}
};

class x86ElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			switch (reloc.nativeType)
			{
			case R_386_NONE:
				reloc.type = IgnoredRelocation;
				break;
			case R_386_32:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				break;
			case R_386_PC32:
			case R_386_GOT32:
			case R_386_PLT32:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				break;
			case R_386_RELATIVE:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.hasSign = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				reloc.implicitAddend = true;
				reloc.addend = 0;
				break;
			case R_386_COPY:
				reloc.type = ELFCopyRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				break;
			case R_386_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				reloc.implicitAddend = false;
				break;
			case R_386_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				reloc.implicitAddend = false;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((Elfx86RelocationType)reloc));
		return true;
	}
};

class x64MachoRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)arch;
		auto info = reloc->GetInfo();
		uint64_t pcRelAddr = info.pcRelative ? reloc->GetAddress() : 0;
		if (len < info.size)
			return false;
		uint32_t target = (uint32_t)info.target;
		uint32_t* dest32 = (uint32_t*)dest;
		uint64_t* dest64 = (uint64_t*)dest;
		switch (info.nativeType)
		{
		case X86_64_RELOC_BRANCH:
			if (info.size == 4)
				dest32[0] = dest32[0] - 4 + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_GOT_LOAD:
			dest32[0] = dest32[0] - 4 + target  - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_SIGNED:
			dest32[0] = dest32[0] + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_SIGNED_1:
			dest32[0] = dest32[0] + 1 + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_SIGNED_2:
			dest32[0] = dest32[0] + 2 + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_SIGNED_4:
			dest32[0] = dest32[0] + 4 + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_GOT:
			dest32[0] = dest32[0] + target - (uint32_t)pcRelAddr;
			break;
		case X86_64_RELOC_UNSIGNED:
			switch (info.size)
			{
				case 4: *dest32 += target - (uint32_t)pcRelAddr; break;
				case 8: *dest64 += info.target - pcRelAddr; break;
				default: break;
			}
			// TODO rebasing
			break;
		case X86_64_RELOC_SUBTRACTOR:
			if (!info.next)
				break;
			dest64[0] = dest64[0] + info.next->target - target;
			break;
		case (uint64_t) -2:
			dest64[0] = reloc->GetTarget();
			break;
		}
		return true;
	}


	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			switch (result[i].nativeType)
			{
			case X86_64_RELOC_UNSIGNED:
				result[i].hasSign = false;
				break;
			case X86_64_RELOC_BRANCH:
				result[i].pcRelative = true;
				result[i].size = 4;
				result[i].implicitAddend = true;
				break;
			case X86_64_RELOC_GOT:
			case X86_64_RELOC_GOT_LOAD:
				result[i].pcRelative = true;
				result[i].size = 4;
				result[i].implicitAddend = true;
				break;
			case X86_64_RELOC_SIGNED:
				result[i].implicitAddend = true;
				result[i].size = 4;
				result[i].hasSign = true;
				break;
			case X86_64_RELOC_SIGNED_1:
				result[i].implicitAddend = true;
				result[i].addend = 1;
				result[i].size = 4;
				result[i].hasSign = true;
				break;
			case X86_64_RELOC_SIGNED_2:
				result[i].implicitAddend = true;
				result[i].addend = 2;
				result[i].size = 4;
				result[i].hasSign = true;
				break;
			case X86_64_RELOC_SIGNED_4:
				result[i].implicitAddend = true;
				result[i].addend = 4;
				result[i].size = 4;
				result[i].hasSign = true;
				break;
			case X86_64_RELOC_SUBTRACTOR:
				// X86_64_RELOC_SUBTRACTOR should always be followed by a X86_64_RELOC_UNSIGNED
				if (i == result.size() - 1)
					result[i].type = IgnoredRelocation;
				else if ((Machox64RelocationType)result[i + 1].type != X86_64_RELOC_UNSIGNED)
					result[i].type = IgnoredRelocation;
				else
				{
					result[i + 1].type = IgnoredRelocation;
					result[i].next = new BNRelocationInfo(result[i + 1]);
					i++;
				}
				break;
			default:
				result[i].type = UnhandledRelocation;
				relocTypes.insert(result[i].nativeType);
				break;
			}
		}

		for (auto& reloc : relocTypes)
			LogWarn("Unsupported Mach-O relocation: %s", GetRelocationString((Machox64RelocationType)reloc));
		return true;
	}
};

class x64ElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		BNRelocationInfo info = reloc->GetInfo();
		switch (info.nativeType)
		{
		case R_X86_64_REX_GOTPCRELX: {
			// When we're actually applying this we don't need to change the 3 first bytes,
			// just apply it to the immediate and it's fine. However, we track all seven
			// variable bytes so we don't lie to the user.
			dest += 3;
			uint64_t pc = reloc->GetAddress() + 3;
			uint64_t addend = 0;
			if (info.implicitAddend && info.size < sizeof(addend))
				memcpy(&addend, dest, reloc->GetInfo().size);
			else
				addend = info.addend;
			uint32_t write = (uint32_t)(reloc->GetTarget() + addend - pc);
			memcpy(dest, (uint8_t*)&write, sizeof(uint32_t));
			return true;
		}
		case R_X86_64_IRELATIVE: {
			// What???????
			uint64_t write = info.addend;
			memcpy(dest, (uint8_t*)&write, sizeof(uint64_t));
			return true;
		}
		default:
			return RelocationHandler::ApplyRelocation(view, arch, reloc, dest, len);
		}
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		/*
		From the Intel AMD64 ELF Linux ABI
		A Represents the addend used to compute the value of the relocatable field.
		B Represents the base address at which a shared object has been loaded into memory during execution.
			Generally, a shared object is built with a 0 base virtual address, but the execution address will be different.
		G Represents the offset into the global offset table at which the relocation entry’s symbol
			will reside during execution.
		GOT Represents the address of the global offset table.
		L Represents the place (section offset or address) of the Procedure Linkage Table
			entry for a symbol.
		P Represents the place (section offset or address) of the storage unit being relocated (computed using r_offset).
		S Represents the value of the symbol whose index resides in the relocation entry.
		Z Represents the size of the symbol whose index resides in the relocation entry.
		The AMD64 LP64 ABI architecture uses only Elf64_Rela relocation entries with explicit addends. Theg
			r_addend member serves as the relocation addend.
		The AMD64 ILP32 ABI architecture uses only Elf32_Rela relocation entries in relocatable files. Relocations
			contained within executable files or shared objects may use either Elf32_Rela relocation or Elf32_Rel relocation.
		*/
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			switch (reloc.nativeType)
			{
			case R_X86_64_NONE:
				reloc.type = IgnoredRelocation;
				break;
			case R_X86_64_COPY:
				reloc.type = ELFCopyRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			case R_X86_64_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			case R_X86_64_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			case R_X86_64_8:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 1;
				reloc.truncateSize = 1;
				break;
			case R_X86_64_16:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 2;
				reloc.truncateSize = 2;
				break;
			case R_X86_64_32S:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = true;
				reloc.size = 4;
				reloc.truncateSize = 4;
				break;
			case R_X86_64_32:
			case R_X86_64_GOT32:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 4;
				break;
			case R_X86_64_64:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			case R_X86_64_PC32:
			case R_X86_64_PLT32:
			case R_X86_64_GOTPCREL:
			case R_X86_64_GOTPCRELX:
				// These are pointers into .got and .plt sections which aren't present
				// At some point in the future we may need to create these sections
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 4;
				reloc.truncateSize = 4;
				break;
			case R_X86_64_PC64:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			case R_X86_64_REX_GOTPCRELX:
				// The 3 bytes before the immediate that specify the registers and operand
				// encoding are variable!!! Example: 49c7c400000000 vs 4c8b25d5140000
				reloc.address -= 3;
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 7;
				reloc.truncateSize = 7;
				break;
			case R_X86_64_RELATIVE:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				reloc.implicitAddend = true;
				break;
			case R_X86_64_PC16:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 2;
				break;
			case R_X86_64_PC8:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 1;
				break;
			case R_X86_64_IRELATIVE:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 8;
				reloc.truncateSize = 8;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation: %s", GetRelocationString((Elfx64RelocationType)reloc));
		return true;
	}
};

class CoffRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		// Note: info.base contains preferred base address and the base where the image is actually loaded
		(void)view;
		(void)arch;
		(void)len;
		uint64_t* data64 = (uint64_t*)dest;
		uint32_t* data32 = (uint32_t*)dest;
		uint16_t* data16 = (uint16_t*)dest;
		auto info = reloc->GetInfo();
		uint64_t offset = 0;

		if (info.pcRelative)
		{
			int64_t relative_offset = info.target - info.address;
			offset = (uint64_t) relative_offset;
		}
		else
			offset = info.target;

		if (! info.implicitAddend && info.addend)
			offset += info.addend;

		if (! info.baseRelative)
			offset -= info.base;

		switch (info.nativeType)
		{
		// case PE_IMAGE_REL_I386_SECTION:
		case PE_IMAGE_REL_AMD64_SECTION:
			// TODO: test this implementation, but for now, just don't warn about it
			data16[0] = info.sectionIndex + 1;
			break;
		// case PE_IMAGE_REL_I386_SECREL:
		case PE_IMAGE_REL_AMD64_SECREL:
		{
			// TODO: test this implementation, but for now, just don't warn about it
			auto sections = view->GetSectionsAt(info.target);
			if (sections.size() > 0)
			{
				data32[0] = info.target - sections[0]->GetStart();
			}
			break;
		}
		default:
			if (info.size == 8)
			{
				// LogDebug("%s: address: %#" PRIx64 " target: %#" PRIx64 " base: %#" PRIx64 " offset: %#" PRIx64 " current: %#" PRIx64 " result: %#" PRIx64 "", __func__, info.address, info.target, info.base, offset, data64[0], data64[0] + offset);
				data64[0] += offset;
			}
			else if (info.size == 4)
			{
				// LogDebug("%s: address: %#" PRIx64 " target: %#" PRIx64 " base: %#" PRIx64 " offset: %#" PRIx32 " %+" PRId32 " current: %#" PRIx32 " result: %#" PRIx32 "", __func__, info.address, info.target, info.base, (uint32_t)offset, (uint32_t)offset, data32[0], data32[0] + (uint32_t)offset);
				data32[0] += (uint32_t)offset;
			}
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			if (arch->GetName() == "x86_64")
			{
				switch (reloc.nativeType)
				{
				case PE_IMAGE_REL_AMD64_ABSOLUTE:
					reloc.type = IgnoredRelocation;
					break;
				case PE_IMAGE_REL_AMD64_ADDR64:
					reloc.baseRelative = true;
					reloc.size = 8;
					break;
				case PE_IMAGE_REL_AMD64_ADDR32NB:
					reloc.baseRelative = false;
					reloc.size = 4;
					break;
				case PE_IMAGE_REL_AMD64_ADDR32:
					reloc.baseRelative = true;
					reloc.size = 4;
					break;
				case PE_IMAGE_REL_AMD64_REL32_5:
				case PE_IMAGE_REL_AMD64_REL32_4:
				case PE_IMAGE_REL_AMD64_REL32_3:
				case PE_IMAGE_REL_AMD64_REL32_2:
				case PE_IMAGE_REL_AMD64_REL32_1:
					// LogDebug("%s: %#" PRIx64 "(%#" PRIx64 ")->%#" PRIx64 " %s addend: %ld", __func__, reloc.address, reloc.target, reloc.address - reloc.target, GetRelocationString((COFFx64RelocationType)reloc.nativeType), (long) reloc.addend);
				case PE_IMAGE_REL_AMD64_REL32:
					// TODO: treat reloc.addend as offset of target from its section (see llvm/lib/ExecutionEngine/RuntimeDyld/Targets/RuntimeDyldCOFFX86_64.h:67)
					reloc.addend = -(4 + (reloc.nativeType - PE_IMAGE_REL_AMD64_REL32));
					reloc.baseRelative = false;
					reloc.pcRelative = true;
					reloc.size = 4;
					break;
				case PE_IMAGE_REL_AMD64_SECTION:
					// The 16-bit section index of the section that contains the target. This is used to support debugging information.
					reloc.baseRelative = false;
					reloc.size = 2;
					reloc.addend = 0;
				case PE_IMAGE_REL_AMD64_SECREL:
					// TODO: implement these, but for now, just don't warn about them
					// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.				reloc.baseRelative = false;
					reloc.baseRelative = false;
					reloc.size = 4;
					reloc.addend = 0;
					break;
				case PE_IMAGE_REL_AMD64_SECREL7:
					// 7-bit offset from the base of the section that contains the target
				case PE_IMAGE_REL_AMD64_TOKEN:
				case PE_IMAGE_REL_AMD64_SREL32:
				case PE_IMAGE_REL_AMD64_PAIR:
				case PE_IMAGE_REL_AMD64_SSPAN32:
				default:
					// By default, PE relocations are correct when not rebased.
					// Upon rebasing, support would need to be added to correctly process the relocation
					reloc.type = UnhandledRelocation;
					relocTypes.insert(reloc.nativeType);
				}
				for (auto& reloc : relocTypes)
					LogWarn("Unsupported COFF relocation: %s", GetRelocationString((COFFx64RelocationType)reloc));
			}
			else if (arch->GetName() == "x86")
			{
				switch (reloc.nativeType)
				{
				case PE_IMAGE_REL_I386_ABSOLUTE:
					reloc.type = IgnoredRelocation;
					break;
				case PE_IMAGE_REL_I386_REL32:
					reloc.baseRelative = false;
					reloc.pcRelative = true;
					reloc.size = 4;
					reloc.addend = -4;
					break;
				case PE_IMAGE_REL_I386_DIR32NB:
					reloc.baseRelative = false;
					reloc.size = 4;
					break;
				case PE_IMAGE_REL_I386_DIR32:
					reloc.baseRelative = true;
					reloc.size = 4;
					break;
				case PE_IMAGE_REL_I386_SECTION:
					// The 16-bit section index of the section that contains the target. This is used to support debugging information.
					reloc.baseRelative = false;
					reloc.size = 2;
					reloc.addend = 0;
				case PE_IMAGE_REL_I386_SECREL:
					// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.				reloc.baseRelative = false;
					reloc.baseRelative = false;
					reloc.size = 4;
					reloc.addend = 0;
					break;
				case PE_IMAGE_REL_I386_SEG12:
				case PE_IMAGE_REL_I386_TOKEN:
				case PE_IMAGE_REL_I386_SECREL7:
				case PE_IMAGE_REL_I386_DIR16:
				case PE_IMAGE_REL_I386_REL16:
				default:
					reloc.type = UnhandledRelocation;
					relocTypes.insert(reloc.nativeType);
				}
				for (auto& reloc : relocTypes)
					LogWarn("Unsupported COFF relocation: %s", GetRelocationString((COFFx86RelocationType)reloc));
			}
		}

		return true;
	}
};

class PeRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		// Note: info.base contains preferred base address and the base where the image is actually loaded
		(void)view;
		(void)arch;
		(void)len;
		uint64_t* data64 = (uint64_t*)dest;
		uint32_t* data32 = (uint32_t*)dest;
		uint16_t* data16 = (uint16_t*)dest;
		auto info = reloc->GetInfo();
		if ((uint32_t)info.nativeType == PE_IMAGE_USER_DEFINED)
		{
			if (info.size == 8)
			{
				data64[0] = info.target;
			}
			else if (info.size == 4)
			{
				data32[0] = (uint32_t)info.target;
			}
		}
		else if (info.size == 8)
		{
			data64[0] += info.base;
		}
		else if (info.size == 4)
		{
			data32[0] += (uint32_t)info.base;
		}
		else if (info.size == 2)
		{
			if (info.nativeType == PE_IMAGE_REL_BASED_HIGH)
			{
				data16[0] = data16[0] + (uint16_t)(info.base >> 16);
			}
			else if (info.nativeType == PE_IMAGE_REL_BASED_LOW)
			{
				data16[0] = data16[0] + (uint16_t)(info.base & 0xffff);
			}
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			switch (reloc.nativeType)
			{
			case PE_IMAGE_REL_BASED_ABSOLUTE:
				reloc.type = IgnoredRelocation;
				break;
			case PE_IMAGE_REL_BASED_HIGHLOW:
				reloc.size = 4;
				break;
			case PE_IMAGE_REL_BASED_DIR64:
				reloc.size = 8;
				break;
			case PE_IMAGE_REL_BASED_HIGH:
				reloc.size = 2;
				break;
			case PE_IMAGE_REL_BASED_LOW:
				reloc.size = 2;
				break;
			case PE_IMAGE_USER_DEFINED:
				reloc.type = StandardRelocationType;
				break;
			default:
				// By default, PE relocations are correct when not rebased.
				// Upon rebasing, support would need to be added to correctly process the relocation
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
			}
		}

		for (auto& reloc : relocTypes)
			LogWarn("Unsupported PE relocation: %s", GetRelocationString((PeRelocationType)reloc));
		return false;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
		(void)relocation;
		return BN_AUTOCOERCE_EXTERN_PTR;
	}
};


static void InitX86Settings()
{
	Ref<Settings> settings = Settings::Instance();
	settings->RegisterSetting("arch.x86.disassembly.syntax",
			R"({
			"title" : "x86 Disassembly Syntax",
			"type" : "string",
			"default" : "BN_INTEL",
			"aliases" : ["arch.x86.disassemblyFlavor"],
			"description" : "Specify disassembly syntax for the x86/x86_64 architectures.",
			"enum" : ["BN_INTEL", "INTEL", "AT&T"],
			"enumDescriptions" : [
				"Sets the disassembly syntax to a simplified Intel format. (TBD) ",
				"Sets the disassembly syntax to Intel format. (Destination on the left) ",
				"Sets the disassembly syntax to AT&T format. (Destination on the right) "],
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("arch.x86.disassembly.separator",
			R"({
			"title" : "x86 Disassembly Separator",
			"type" : "string",
			"default" : ", ",
			"aliases" : ["arch.x86.disassemblySeperator", "arch.x86.disassemblySeparator"],
			"description" : "Specify the token separator between operands.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("arch.x86.disassembly.lowercase",
			R"({
			"title" : "x86 Disassembly Case",
			"type" : "boolean",
			"default" : true,
			"aliases" : ["arch.x86.disassemblyLowercase"],
			"description" : "Specify the case for opcodes, operands, and registers.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_macho");
		AddOptionalPluginDependency("view_pe");
	}
#endif

#ifdef DEMO_EDITION
	bool X86PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitX86Settings();

		// XED Setup
		xed_tables_init();
		X86CommonArchitecture::InitializeCachedTypes();

		// Register the architectures in the global list of available architectures
		Architecture* x16 = new X16Architecture();
		Architecture::Register(x16);

		Architecture* x86 = new X86Architecture();
		Architecture::Register(x86);

		Architecture* x64 = new X64Architecture();
		Architecture::Register(x64);

		// Register calling conventions
		Ref<CallingConvention> conv;
		conv = new X86CdeclCallingConvention(x86);
		x86->RegisterCallingConvention(conv);
		x86->SetDefaultCallingConvention(conv);
		x86->SetCdeclCallingConvention(conv);
		conv = new X86StdcallCallingConvention(x86);
		x86->RegisterCallingConvention(conv);
		x86->SetStdcallCallingConvention(conv);
		conv = new X86RegParmCallingConvention(x86);
		x86->RegisterCallingConvention(conv);
		conv = new X86FastcallCallingConvention(x86);
		x86->RegisterCallingConvention(conv);
		conv = new X86ThiscallCallingConvention(x86);
		x86->RegisterCallingConvention(conv);
		conv = new X86LinuxSystemCallConvention(x86);
		x86->RegisterCallingConvention(conv);

		x86->RegisterRelocationHandler("Mach-O", new x86MachoRelocationHandler());
		x86->RegisterRelocationHandler("ELF", new x86ElfRelocationHandler());
		x86->RegisterRelocationHandler("COFF", new CoffRelocationHandler());
		x86->RegisterRelocationHandler("PE", new PeRelocationHandler());

		conv = new X64SystemVCallingConvention(x64);
		x64->RegisterCallingConvention(conv);
		x64->SetDefaultCallingConvention(conv);
		x64->SetCdeclCallingConvention(conv);
		x64->SetFastcallCallingConvention(conv);
		x64->SetStdcallCallingConvention(conv);
		conv = new X64WindowsCallingConvention(x64);
		x64->RegisterCallingConvention(conv);
		conv = new X64LinuxSystemCallConvention(x64);
		x64->RegisterCallingConvention(conv);

		x64->RegisterRelocationHandler("Mach-O", new x64MachoRelocationHandler());
		x64->RegisterRelocationHandler("ELF", new x64ElfRelocationHandler());
		x64->RegisterRelocationHandler("COFF", new CoffRelocationHandler());
		x64->RegisterRelocationHandler("PE", new PeRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file
		BinaryViewType::RegisterArchitecture("ELF", 3, LittleEndian, x86);
		BinaryViewType::RegisterArchitecture("COFF", 0x14c, LittleEndian, x86);
		BinaryViewType::RegisterArchitecture("PE", 0x14c, LittleEndian, x86);
		BinaryViewType::RegisterArchitecture("Mach-O", 0x00000007, LittleEndian, x86);

		BinaryViewType::RegisterArchitecture("ELF", 62, LittleEndian, x64);
		BinaryViewType::RegisterArchitecture("COFF", 0x8664, LittleEndian, x64);
		BinaryViewType::RegisterArchitecture("PE", 0x8664, LittleEndian, x64);
		BinaryViewType::RegisterArchitecture("Mach-O", 0x01000007, LittleEndian, x64);

		return true;
	}
}

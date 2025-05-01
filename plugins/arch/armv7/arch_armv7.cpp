#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <exception>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arch_armv7.h"
#include "il.h"

using namespace BinaryNinja;
using namespace armv7;
using namespace std;


#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

// #define DEBUG_COFF LogDebug

#define DISASM_SUCCESS 0
#define FAILED_TO_DISASSEMBLE_OPERAND 1
#define FAILED_TO_DISASSEMBLE_REGISTER 2

#define COALESCE_MAX_INSTRS 100

#define HANDLE_CASE(orig, opposite) case orig: case opposite: return (candidate == orig) || (candidate == opposite)

static bool IsRelatedCondition(Condition orig, Condition candidate)
{
	switch (orig)
	{
		HANDLE_CASE(COND_EQ, COND_NE);
		HANDLE_CASE(COND_CS, COND_CC);
		HANDLE_CASE(COND_MI, COND_PL);
		HANDLE_CASE(COND_VS, COND_VC);
		HANDLE_CASE(COND_HI, COND_LS);
		HANDLE_CASE(COND_GE, COND_LT);
		HANDLE_CASE(COND_GT, COND_LE);
		default: return false;
	}
}

static bool CanCoalesceAfterInstruction(Instruction& instr)
{
	switch (instr.operation)
	{
	case ARMV7_BX:
	case ARMV7_B:
		return false;

	case ARMV7_ADC:
	case ARMV7_ADD:
	case ARMV7_AND:
	case ARMV7_ASR:
	case ARMV7_BIC:
	case ARMV7_EOR:
	case ARMV7_LDR:
	case ARMV7_LSL:
	case ARMV7_LSR:
	case ARMV7_MOV:
	case ARMV7_MVN:
	case ARMV7_ORR:
	case ARMV7_ROR:
	case ARMV7_RRX:
	case ARMV7_RSB:
	case ARMV7_RSC:
	case ARMV7_SUB:
	case ARMV7_SBC:
	case ARMV7_MOVW:
	case ARMV7_MOVT:
	case ARMV7_LDRT:
	case ARMV7_LDRH:
	case ARMV7_LDRHT:
	case ARMV7_LDRB:
	case ARMV7_LDRBT:
	case ARMV7_LDRSH:
	case ARMV7_LDRSHT:
	case ARMV7_LDRSB:
	case ARMV7_LDRSBT:
	case ARMV7_LDRD:
	case ARMV7_ADR:
	case ARMV7_UBFX:
	case ARMV7_UXTAB:
	case ARMV7_UXTB:
	case ARMV7_UXTH:
	case ARMV7_MUL:
	case ARMV7_SDIV:
	case ARMV7_UDIV:
	case ARMV7_SBFX:
	case ARMV7_SXTB:
	case ARMV7_SXTH:
	case ARMV7_BFC:
	case ARMV7_BFI:
	case ARMV7_CLZ:
		if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
			return false;
		return true;

	default:
		return true;
	}
}

enum MachoArmRelocationType : uint32_t
{
	ARM_RELOC_VANILLA = 0,
	ARM_RELOC_PAIR = 1,
	ARM_RELOC_SECTDIFF = 2,
	ARM_RELOC_LOCAL_SECTDIFF = 3,
	ARM_RELOC_PB_LA_PTR = 4,
	ARM_RELOC_BR24 = 5,
	ARM_THUMB_RELOC_BR22 = 6,
	ARM_THUMB_32BIT_BRANCH = 7,
	ARM_RELOC_HALF = 8,
	ARM_RELOC_HALF_SECTDIFF = 9,
	MACHO_MAX_ARM_RELOCATION
};

enum ElfArmRelocationType : uint32_t
{
	R_ARM_NONE               = 0,
	R_ARM_PC24               = 1,
	R_ARM_ABS32              = 2,
	R_ARM_REL32              = 3,
	R_ARM_LDR_PC_G0          = 4,
	R_ARM_ABS16              = 5,
	R_ARM_ABS12              = 6,
	R_ARM_THM_ABS5           = 7,
	R_ARM_ABS8               = 8,
	R_ARM_SBREL32            = 9,
	R_ARM_THM_CALL           = 10,
	R_ARM_THM_PC8            = 11,
	R_ARM_BREL_ADJ           = 12,
	R_ARM_TLS_DESC           = 13,
	R_ARM_THM_SWI8           = 14,
	R_ARM_XPC25              = 15,
	R_ARM_THM_XPC22          = 16,
	R_ARM_TLS_DTPMOD32       = 17,
	R_ARM_TLS_DTPOFF32       = 18,
	R_ARM_TLS_TPOFF32        = 19,
	R_ARM_COPY               = 20,
	R_ARM_GLOB_DAT           = 21,
	R_ARM_JUMP_SLOT          = 22,
	R_ARM_RELATIVE           = 23,
	R_ARM_GOTOFF32           = 24,
	R_ARM_BASE_PREL          = 25,
	R_ARM_GOT_BREL           = 26,
	R_ARM_PLT32              = 27,
	R_ARM_CALL               = 28,
	R_ARM_JUMP24             = 29,
	R_ARM_THM_JUMP24         = 30,
	R_ARM_BASE_ABS           = 31,
	R_ARM_ALU_PCREL_7_0      = 32,
	R_ARM_ALU_PCREL_15_8     = 33,
	R_ARM_ALU_PCREL_23_15    = 34,
	R_ARM_LDR_SBREL_11_0_NC  = 35,
	R_ARM_ALU_SBREL_19_12_NC = 36,
	R_ARM_ALU_SBREL_27_20_CK = 37,
	R_ARM_TARGET1            = 38,
	R_ARM_SBREL31            = 39,
	R_ARM_V4BX               = 40,
	R_ARM_TARGET2            = 41,
	R_ARM_PREL31             = 42,
	R_ARM_MOVW_ABS_NC        = 43,
	R_ARM_MOVT_ABS           = 44,
	R_ARM_MOVW_PREL_NC       = 45,
	R_ARM_MOVT_PREL          = 46,
	R_ARM_THM_MOVW_ABS_NC    = 47,
	R_ARM_THM_MOVT_ABS       = 48,
	R_ARM_THM_MOVW_PREL_NC   = 49,
	R_ARM_THM_MOVT_PREL      = 50,
	R_ARM_THM_JUMP19         = 51,
	R_ARM_THM_JUMP6          = 52,
	R_ARM_THM_ALU_PREL_11_0  = 53,
	R_ARM_THM_PC12           = 54,
	R_ARM_ABS32_NOI          = 55,
	R_ARM_REL32_NOI          = 56,
	R_ARM_ALU_PC_G0_NC       = 57,
	R_ARM_ALU_PC_G0          = 58,
	R_ARM_ALU_PC_G1_NC       = 59,
	R_ARM_ALU_PC_G1          = 60,
	R_ARM_ALU_PC_G2          = 61,
	R_ARM_LDR_PC_G1          = 62,
	R_ARM_LDR_PC_G2          = 63,
	R_ARM_LDRS_PC_G0         = 64,
	R_ARM_LDRS_PC_G1         = 65,
	R_ARM_LDRS_PC_G2         = 66,
	R_ARM_LDC_PC_G0          = 67,
	R_ARM_LDC_PC_G1          = 68,
	R_ARM_LDC_PC_G2          = 69,
	R_ARM_ALU_SB_G0_NC       = 70,
	R_ARM_ALU_SB_G0          = 71,
	R_ARM_ALU_SB_G1_NC       = 72,
	R_ARM_ALU_SB_G1          = 73,
	R_ARM_ALU_SB_G2          = 74,
	R_ARM_LDR_SB_G0          = 75,
	R_ARM_LDR_SB_G1          = 76,
	R_ARM_LDR_SB_G2          = 77,
	R_ARM_LDRS_SB_G0         = 78,
	R_ARM_LDRS_SB_G1         = 79,
	R_ARM_LDRS_SB_G2         = 80,
	R_ARM_LDC_SB_G0          = 81,
	R_ARM_LDC_SB_G1          = 82,
	R_ARM_LDC_SB_G2          = 83,
	R_ARM_MOVW_BREL_NC       = 84,
	R_ARM_MOVT_BREL          = 85,
	R_ARM_MOVW_BREL          = 86,
	R_ARM_THM_MOVW_BREL_NC   = 87,
	R_ARM_THM_MOVT_BREL      = 88,
	R_ARM_THM_MOVW_BREL      = 89,
	R_ARM_TLS_GOTDESC        = 90,
	R_ARM_TLS_CALL           = 91,
	R_ARM_TLS_DESCSEQ        = 92,
	R_ARM_THM_TLS_CALL       = 93,
	R_ARM_PLT32_ABS          = 94,
	R_ARM_GOT_ABS            = 95,
	R_ARM_GOT_PREL           = 96,
	R_ARM_GOT_BREL12         = 97,
	R_ARM_GOTOFF12           = 98,
	R_ARM_GOTRELAX           = 99,
	R_ARM_GNU_VTENTRY        = 100,
	R_ARM_GNU_VTINHERIT      = 101,
	R_ARM_THM_JUMP11         = 102,
	R_ARM_THM_JUMP8          = 103,
	R_ARM_TLS_GD32           = 104,
	R_ARM_TLS_LDM32          = 105,
	R_ARM_TLS_LDO32          = 106,
	R_ARM_TLS_IE32           = 107,
	R_ARM_TLS_LE32           = 108,
	R_ARM_TLS_LDO12          = 109,
	R_ARM_TLS_LE12           = 110,
	R_ARM_TLS_IE12GP         = 111,
	R_ARM_ME_TOO             = 128,
	R_ARM_THM_TLS_DESCSEQ16  = 129,
	R_ARM_THM_TLS_DESCSEQ32  = 130,
	R_ARM_THM_GOT_BREL12     = 131,
	R_ARM_THM_ALU_ABS_G0_NC  = 132,
	R_ARM_THM_ALU_ABS_G1_NC  = 133,
	R_ARM_THM_ALU_ABS_G2_NC  = 134,
	R_ARM_THM_ALU_ABS_G3     = 135,
	R_ARM_IRELATIVE          = 160,
	R_ARM_RXPC25             = 249,
	R_ARM_RSBREL32           = 250,
	R_ARM_THM_RPC22          = 251,
	R_ARM_RREL32             = 252,
	R_ARM_RABS32             = 253,
	R_ARM_RPC24              = 254,
	R_ARM_RBASE              = 255
};

enum PeArmRelocationType : uint32_t
{
	PE_IMAGE_REL_ARM_ABSOLUTE   = 0x0000, // The relocation is ignored.
	PE_IMAGE_REL_ARM_ADDR32     = 0x0001, // The 32-bit VA of the target.
	PE_IMAGE_REL_ARM_ADDR32NB   = 0x0002, // The 32-bit RVA of the target.
	PE_IMAGE_REL_ARM_BRANCH24   = 0x0003, // The 24-bit relative displacement to the target.
	PE_IMAGE_REL_ARM_BRANCH11   = 0x0004, // The reference to a subroutine call. The reference consists of two 16-bit instructions with 11-bit offsets.
	PE_IMAGE_REL_ARM_BLX24      = 0x0008, // The most significant 24 or 25 bits of the signed 26-bit relative displacement of the target. Applied to an unconditional BL instruction in ARM mode. The BL is transformed to a BLX during relocation if the target is in Thumb mode.
	PE_IMAGE_REL_ARM_BLX11      = 0x0009, // The most significant 21 or 22 bits of the signed 23-bit relative displacement of the target. Applied to a contiguous 16-bit B+BL pair in Thumb mode prior to ARMv7. The BL is transformed to a BLX during relocation if the target is in ARM mode.
	PE_IMAGE_REL_ARM_REL32      = 0x000A, // TODO: description
	PE_IMAGE_REL_ARM_SECTION    = 0x000E, // The 16-bit section index of the section that contains the target. This is used to support debugging information.
	PE_IMAGE_REL_ARM_SECREL     = 0x000F, // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	PE_IMAGE_REL_ARM_MOV32      = 0x0010, // The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
	PE_IMAGE_REL_THUMB_MOV32    = 0x0011, // The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
	PE_IMAGE_REL_THUMB_BRANCH20 = 0x0012, // The instruction is fixed up with the 21-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is always zero and is not stored. This relocation corresponds to a Thumb-2 32-bit conditional B instruction.
	PE_IMAGE_REL_THUMB_UNUSED   = 0x0013, // Unused
	PE_IMAGE_REL_THUMB_BRANCH24 = 0x0014, // The instruction is fixed up with the 25-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is zero and is not stored.This relocation corresponds to a Thumb-2 B instruction.
	PE_IMAGE_REL_THUMB_BLX23    = 0x0015, // The instruction is fixed up with the 25-bit relative displacement to the 4-byte aligned target. The low 2 bits of the displacement are zero and are not stored. This relocation corresponds to a Thumb-2 BLX instruction.
	PE_IMAGE_REL_ARM_PAIR       = 0x0016, // The relocation is valid only when it immediately follows a ARM_REFHI or THUMB_REFHI. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
	MAX_ARM_PE_RELOCATION
};

enum PeRelocationType : uint32_t
{
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

static const char* GetRelocationString(MachoArmRelocationType rel)
{
	static const char* relocTable[] =
	{
		"ARM_RELOC_VANILLA",
		"ARM_RELOC_PAIR",
		"ARM_RELOC_SECTDIFF",
		"ARM_RELOC_LOCAL_SECTDIFF",
		"ARM_RELOC_PB_LA_PTR",
		"ARM_RELOC_BR24",
		"ARM_THUMB_RELOC_BR22",
		"ARM_THUMB_32BIT_BRANCH",
		"ARM_RELOC_HALF",
		"ARM_RELOC_HALF_SECTDIFF"
	};
	if (rel < MACHO_MAX_ARM_RELOCATION)
	{
		return relocTable[rel];
	}
	return "Unknown ARM relocation";
}


static const char* GetRelocationString(ElfArmRelocationType rel)
{
	static map<ElfArmRelocationType, const char*> relocTable =
	{
		{R_ARM_NONE, "R_ARM_NONE"},
		{R_ARM_PC24, "R_ARM_PC24"},
		{R_ARM_ABS32, "R_ARM_ABS32"},
		{R_ARM_REL32, "R_ARM_REL32"},
		{R_ARM_LDR_PC_G0, "R_ARM_LDR_PC_G0"},
		{R_ARM_ABS16, "R_ARM_ABS16"},
		{R_ARM_ABS12, "R_ARM_ABS12"},
		{R_ARM_THM_ABS5, "R_ARM_THM_ABS5"},
		{R_ARM_ABS8, "R_ARM_ABS8"},
		{R_ARM_SBREL32, "R_ARM_SBREL32"},
		{R_ARM_THM_CALL, "R_ARM_THM_CALL"},
		{R_ARM_THM_PC8, "R_ARM_THM_PC8"},
		{R_ARM_BREL_ADJ, "R_ARM_BREL_ADJ"},
		{R_ARM_TLS_DESC, "R_ARM_TLS_DESC"},
		{R_ARM_THM_SWI8, "R_ARM_THM_SWI8"},
		{R_ARM_XPC25, "R_ARM_XPC25"},
		{R_ARM_THM_XPC22, "R_ARM_THM_XPC22"},
		{R_ARM_TLS_DTPMOD32, "R_ARM_TLS_DTPMOD32"},
		{R_ARM_TLS_DTPOFF32, "R_ARM_TLS_DTPOFF32"},
		{R_ARM_TLS_TPOFF32, "R_ARM_TLS_TPOFF32"},
		{R_ARM_COPY, "R_ARM_COPY"},
		{R_ARM_GLOB_DAT, "R_ARM_GLOB_DAT"},
		{R_ARM_JUMP_SLOT, "R_ARM_JUMP_SLOT"},
		{R_ARM_RELATIVE, "R_ARM_RELATIVE"},
		{R_ARM_GOTOFF32, "R_ARM_GOTOFF32"},
		{R_ARM_BASE_PREL, "R_ARM_BASE_PREL"},
		{R_ARM_GOT_BREL, "R_ARM_GOT_BREL"},
		{R_ARM_PLT32, "R_ARM_PLT32"},
		{R_ARM_CALL, "R_ARM_CALL"},
		{R_ARM_JUMP24, "R_ARM_JUMP24"},
		{R_ARM_THM_JUMP24, "R_ARM_THM_JUMP24"},
		{R_ARM_BASE_ABS, "R_ARM_BASE_ABS"},
		{R_ARM_ALU_PCREL_7_0, "R_ARM_ALU_PCREL_7_0"},
		{R_ARM_ALU_PCREL_15_8, "R_ARM_ALU_PCREL_15_8"},
		{R_ARM_ALU_PCREL_23_15, "R_ARM_ALU_PCREL_23_15"},
		{R_ARM_LDR_SBREL_11_0_NC, "R_ARM_LDR_SBREL_11_0_NC"},
		{R_ARM_ALU_SBREL_19_12_NC, "R_ARM_ALU_SBREL_19_12_NC"},
		{R_ARM_ALU_SBREL_27_20_CK, "R_ARM_ALU_SBREL_27_20_CK"},
		{R_ARM_TARGET1, "R_ARM_TARGET1"},
		{R_ARM_SBREL31, "R_ARM_SBREL31"},
		{R_ARM_V4BX, "R_ARM_V4BX"},
		{R_ARM_TARGET2, "R_ARM_TARGET2"},
		{R_ARM_PREL31, "R_ARM_PREL31"},
		{R_ARM_MOVW_ABS_NC, "R_ARM_MOVW_ABS_NC"},
		{R_ARM_MOVT_ABS, "R_ARM_MOVT_ABS"},
		{R_ARM_MOVW_PREL_NC, "R_ARM_MOVW_PREL_NC"},
		{R_ARM_MOVT_PREL, "R_ARM_MOVT_PREL"},
		{R_ARM_THM_MOVW_ABS_NC, "R_ARM_THM_MOVW_ABS_NC"},
		{R_ARM_THM_MOVT_ABS, "R_ARM_THM_MOVT_ABS"},
		{R_ARM_THM_MOVW_PREL_NC, "R_ARM_THM_MOVW_PREL_NC"},
		{R_ARM_THM_MOVT_PREL, "R_ARM_THM_MOVT_PREL"},
		{R_ARM_THM_JUMP19, "R_ARM_THM_JUMP19"},
		{R_ARM_THM_JUMP6, "R_ARM_THM_JUMP6"},
		{R_ARM_THM_ALU_PREL_11_0, "R_ARM_THM_ALU_PREL_11_0"},
		{R_ARM_THM_PC12, "R_ARM_THM_PC12"},
		{R_ARM_ABS32_NOI, "R_ARM_ABS32_NOI"},
		{R_ARM_REL32_NOI, "R_ARM_REL32_NOI"},
		{R_ARM_ALU_PC_G0_NC, "R_ARM_ALU_PC_G0_NC"},
		{R_ARM_ALU_PC_G0, "R_ARM_ALU_PC_G0"},
		{R_ARM_ALU_PC_G1_NC, "R_ARM_ALU_PC_G1_NC"},
		{R_ARM_ALU_PC_G1, "R_ARM_ALU_PC_G1"},
		{R_ARM_ALU_PC_G2, "R_ARM_ALU_PC_G2"},
		{R_ARM_LDR_PC_G1, "R_ARM_LDR_PC_G1"},
		{R_ARM_LDR_PC_G2, "R_ARM_LDR_PC_G2"},
		{R_ARM_LDRS_PC_G0, "R_ARM_LDRS_PC_G0"},
		{R_ARM_LDRS_PC_G1, "R_ARM_LDRS_PC_G1"},
		{R_ARM_LDRS_PC_G2, "R_ARM_LDRS_PC_G2"},
		{R_ARM_LDC_PC_G0, "R_ARM_LDC_PC_G0"},
		{R_ARM_LDC_PC_G1, "R_ARM_LDC_PC_G1"},
		{R_ARM_LDC_PC_G2, "R_ARM_LDC_PC_G2"},
		{R_ARM_ALU_SB_G0_NC, "R_ARM_ALU_SB_G0_NC"},
		{R_ARM_ALU_SB_G0, "R_ARM_ALU_SB_G0"},
		{R_ARM_ALU_SB_G1_NC, "R_ARM_ALU_SB_G1_NC"},
		{R_ARM_ALU_SB_G1, "R_ARM_ALU_SB_G1"},
		{R_ARM_ALU_SB_G2, "R_ARM_ALU_SB_G2"},
		{R_ARM_LDR_SB_G0, "R_ARM_LDR_SB_G0"},
		{R_ARM_LDR_SB_G1, "R_ARM_LDR_SB_G1"},
		{R_ARM_LDR_SB_G2, "R_ARM_LDR_SB_G2"},
		{R_ARM_LDRS_SB_G0, "R_ARM_LDRS_SB_G0"},
		{R_ARM_LDRS_SB_G1, "R_ARM_LDRS_SB_G1"},
		{R_ARM_LDRS_SB_G2, "R_ARM_LDRS_SB_G2"},
		{R_ARM_LDC_SB_G0, "R_ARM_LDC_SB_G0"},
		{R_ARM_LDC_SB_G1, "R_ARM_LDC_SB_G1"},
		{R_ARM_LDC_SB_G2, "R_ARM_LDC_SB_G2"},
		{R_ARM_MOVW_BREL_NC, "R_ARM_MOVW_BREL_NC"},
		{R_ARM_MOVT_BREL, "R_ARM_MOVT_BREL"},
		{R_ARM_MOVW_BREL, "R_ARM_MOVW_BREL"},
		{R_ARM_THM_MOVW_BREL_NC, "R_ARM_THM_MOVW_BREL_NC"},
		{R_ARM_THM_MOVT_BREL, "R_ARM_THM_MOVT_BREL"},
		{R_ARM_THM_MOVW_BREL, "R_ARM_THM_MOVW_BREL"},
		{R_ARM_TLS_GOTDESC, "R_ARM_TLS_GOTDESC"},
		{R_ARM_TLS_CALL, "R_ARM_TLS_CALL"},
		{R_ARM_TLS_DESCSEQ, "R_ARM_TLS_DESCSEQ"},
		{R_ARM_THM_TLS_CALL, "R_ARM_THM_TLS_CALL"},
		{R_ARM_PLT32_ABS, "R_ARM_PLT32_ABS"},
		{R_ARM_GOT_ABS, "R_ARM_GOT_ABS"},
		{R_ARM_GOT_PREL, "R_ARM_GOT_PREL"},
		{R_ARM_GOT_BREL12, "R_ARM_GOT_BREL12"},
		{R_ARM_GOTOFF12, "R_ARM_GOTOFF12"},
		{R_ARM_GOTRELAX, "R_ARM_GOTRELAX"},
		{R_ARM_GNU_VTENTRY, "R_ARM_GNU_VTENTRY"},
		{R_ARM_GNU_VTINHERIT, "R_ARM_GNU_VTINHERIT"},
		{R_ARM_THM_JUMP11, "R_ARM_THM_JUMP11"},
		{R_ARM_THM_JUMP8, "R_ARM_THM_JUMP8"},
		{R_ARM_TLS_GD32, "R_ARM_TLS_GD32"},
		{R_ARM_TLS_LDM32, "R_ARM_TLS_LDM32"},
		{R_ARM_TLS_LDO32, "R_ARM_TLS_LDO32"},
		{R_ARM_TLS_IE32, "R_ARM_TLS_IE32"},
		{R_ARM_TLS_LE32, "R_ARM_TLS_LE32"},
		{R_ARM_TLS_LDO12, "R_ARM_TLS_LDO12"},
		{R_ARM_TLS_LE12, "R_ARM_TLS_LE12"},
		{R_ARM_TLS_IE12GP, "R_ARM_TLS_IE12GP"},
		{R_ARM_ME_TOO, "R_ARM_ME_TOO"},
		{R_ARM_THM_TLS_DESCSEQ16, "R_ARM_THM_TLS_DESCSEQ16"},
		{R_ARM_THM_TLS_DESCSEQ32, "R_ARM_THM_TLS_DESCSEQ32"},
		{R_ARM_THM_GOT_BREL12, "R_ARM_THM_GOT_BREL12"},
		{R_ARM_THM_ALU_ABS_G0_NC, "R_ARM_THM_ALU_ABS_G0_NC"},
		{R_ARM_THM_ALU_ABS_G1_NC, "R_ARM_THM_ALU_ABS_G1_NC"},
		{R_ARM_THM_ALU_ABS_G2_NC, "R_ARM_THM_ALU_ABS_G2_NC"},
		{R_ARM_THM_ALU_ABS_G3, "R_ARM_THM_ALU_ABS_G3"},
		{R_ARM_IRELATIVE, "R_ARM_IRELATIVE"},
		{R_ARM_RXPC25, "R_ARM_RXPC25"},
		{R_ARM_RSBREL32, "R_ARM_RSBREL32"},
		{R_ARM_THM_RPC22, "R_ARM_THM_RPC22"},
		{R_ARM_RREL32, "R_ARM_RREL32"},
		{R_ARM_RABS32, "R_ARM_RABS32"},
		{R_ARM_RPC24, "R_ARM_RPC24"},
		{R_ARM_RBASE, "R_ARM_RBASE"}
	};
	if (relocTable.count(rel))
		return relocTable.at(rel);
	return "Unknown ARM relocation";
}


static const char* GetRelocationString(PeArmRelocationType rel)
{
	static const char* relocTable[] =
	{
		"IMAGE_REL_ARM_ABSOLUTE",
		"IMAGE_REL_ARM_ADDR32",
		"IMAGE_REL_ARM_ADDR32NB",
		"IMAGE_REL_ARM_BRANCH24",
		"IMAGE_REL_ARM_BRANCH11",
		"IMAGE_REL_ARM_SECTION",
		"IMAGE_REL_ARM_SECREL",
		"IMAGE_REL_ARM_MOV32",
		"IMAGE_REL_THUMB_MOV32",
		"IMAGE_REL_THUMB_BRANCH20",
		"IMAGE_REL_THUMB_UNUSED",
		"IMAGE_REL_THUMB_BRANCH24",
		"IMAGE_REL_THUMB_BLX23",
		"IMAGE_REL_ARM_PAIR"
	};
	if (rel < MAX_ARM_PE_RELOCATION)
	{
		if (rel >= PE_IMAGE_REL_ARM_SECTION)
		{
			rel = (PeArmRelocationType) ((int)rel - PE_IMAGE_REL_ARM_SECTION + PE_IMAGE_REL_ARM_BRANCH11 + 1);
		}
		return relocTable[rel];
	}
	return "Unknown ARM relocation";
}

static bool IsELFDataRelocation(ElfArmRelocationType reloc)
{
	map<ElfArmRelocationType, bool> isDataMap =
	{
		{R_ARM_NONE, false},
		{R_ARM_PC24, false},
		{R_ARM_ABS32, true},
		{R_ARM_REL32, true},
		{R_ARM_LDR_PC_G0, false},
		{R_ARM_ABS16, true},
		{R_ARM_ABS12, false},
		{R_ARM_THM_ABS5, false},
		{R_ARM_ABS8, true},
		{R_ARM_SBREL32, true},
		{R_ARM_THM_CALL, false},
		{R_ARM_THM_PC8, false},
		{R_ARM_BREL_ADJ, true},
		{R_ARM_TLS_DESC, true},
		{R_ARM_THM_SWI8, false},
		{R_ARM_XPC25, false},
		{R_ARM_THM_XPC22, false},
		{R_ARM_TLS_DTPMOD32, true},
		{R_ARM_TLS_DTPOFF32, true},
		{R_ARM_TLS_TPOFF32, true},
		{R_ARM_COPY, true},
		{R_ARM_GLOB_DAT, true},
		{R_ARM_JUMP_SLOT, true},
		{R_ARM_RELATIVE, true},
		{R_ARM_GOTOFF32, true},
		{R_ARM_BASE_PREL, true},
		{R_ARM_GOT_BREL, true},
		{R_ARM_PLT32, false},
		{R_ARM_CALL, false},
		{R_ARM_JUMP24, false},
		{R_ARM_THM_JUMP24, false},
		{R_ARM_BASE_ABS, true},
		{R_ARM_ALU_PCREL_7_0, false},
		{R_ARM_ALU_PCREL_15_8, false},
		{R_ARM_ALU_PCREL_23_15, false},
		{R_ARM_LDR_SBREL_11_0_NC, false},
		{R_ARM_ALU_SBREL_19_12_NC, false},
		{R_ARM_ALU_SBREL_27_20_CK, false},
		{R_ARM_TARGET1, false},
		{R_ARM_SBREL31, true},
		{R_ARM_V4BX, false},
		{R_ARM_TARGET2, false},
		{R_ARM_PREL31, true},
		{R_ARM_MOVW_ABS_NC, false},
		{R_ARM_MOVT_ABS, false},
		{R_ARM_MOVW_PREL_NC, false},
		{R_ARM_MOVT_PREL, false},
		{R_ARM_THM_MOVW_ABS_NC, false},
		{R_ARM_THM_MOVT_ABS, false},
		{R_ARM_THM_MOVW_PREL_NC, false},
		{R_ARM_THM_MOVT_PREL, false},
		{R_ARM_THM_JUMP19, false},
		{R_ARM_THM_JUMP6, false},
		{R_ARM_THM_ALU_PREL_11_0, false},
		{R_ARM_THM_PC12, false},
		{R_ARM_ABS32_NOI, true},
		{R_ARM_REL32_NOI, true},
		{R_ARM_ALU_PC_G0_NC, false},
		{R_ARM_ALU_PC_G0, false},
		{R_ARM_ALU_PC_G1_NC, false},
		{R_ARM_ALU_PC_G1, false},
		{R_ARM_ALU_PC_G2, false},
		{R_ARM_LDR_PC_G1, false},
		{R_ARM_LDR_PC_G2, false},
		{R_ARM_LDRS_PC_G0, false},
		{R_ARM_LDRS_PC_G1, false},
		{R_ARM_LDRS_PC_G2, false},
		{R_ARM_LDC_PC_G0, false},
		{R_ARM_LDC_PC_G1, false},
		{R_ARM_LDC_PC_G2, false},
		{R_ARM_ALU_SB_G0_NC, false},
		{R_ARM_ALU_SB_G0, false},
		{R_ARM_ALU_SB_G1_NC, false},
		{R_ARM_ALU_SB_G1, false},
		{R_ARM_ALU_SB_G2, false},
		{R_ARM_LDR_SB_G0, false},
		{R_ARM_LDR_SB_G1, false},
		{R_ARM_LDR_SB_G2, false},
		{R_ARM_LDRS_SB_G0, false},
		{R_ARM_LDRS_SB_G1, false},
		{R_ARM_LDRS_SB_G2, false},
		{R_ARM_LDC_SB_G0, false},
		{R_ARM_LDC_SB_G1, false},
		{R_ARM_LDC_SB_G2, false},
		{R_ARM_MOVW_BREL_NC, false},
		{R_ARM_MOVT_BREL, false},
		{R_ARM_MOVW_BREL, false},
		{R_ARM_THM_MOVW_BREL_NC, false},
		{R_ARM_THM_MOVT_BREL, false},
		{R_ARM_THM_MOVW_BREL, false},
		{R_ARM_TLS_GOTDESC, true},
		{R_ARM_TLS_CALL, false},
		{R_ARM_TLS_DESCSEQ, false},
		{R_ARM_THM_TLS_CALL, false},
		{R_ARM_PLT32_ABS, true},
		{R_ARM_GOT_ABS, true},
		{R_ARM_GOT_PREL, true},
		{R_ARM_GOT_BREL12, false},
		{R_ARM_GOTOFF12, false},
		{R_ARM_GOTRELAX, false},
		{R_ARM_GNU_VTENTRY, true},
		{R_ARM_GNU_VTINHERIT, true},
		{R_ARM_THM_JUMP11, false},
		{R_ARM_THM_JUMP8, false},
		{R_ARM_TLS_GD32, true},
		{R_ARM_TLS_LDM32, true},
		{R_ARM_TLS_LDO32, true},
		{R_ARM_TLS_IE32, true},
		{R_ARM_TLS_LE32, false},
		{R_ARM_TLS_LDO12, false},
		{R_ARM_TLS_LE12, false},
		{R_ARM_TLS_IE12GP, false},
		{R_ARM_ME_TOO, false},
		{R_ARM_THM_TLS_DESCSEQ16, false},
		{R_ARM_THM_TLS_DESCSEQ32, false},
		{R_ARM_THM_GOT_BREL12, false},
		{R_ARM_THM_ALU_ABS_G0_NC, false},
		{R_ARM_THM_ALU_ABS_G1_NC, false},
		{R_ARM_THM_ALU_ABS_G2_NC, false},
		{R_ARM_THM_ALU_ABS_G3, false},
		{R_ARM_IRELATIVE, false},
		{R_ARM_RXPC25, false},
		{R_ARM_RSBREL32, false},
		{R_ARM_THM_RPC22, false},
		{R_ARM_RREL32, false},
		{R_ARM_RABS32, false},
		{R_ARM_RPC24, false},
		{R_ARM_RBASE, false}
	};
	if (!isDataMap.count(reloc))
		return false;
	return isDataMap.at(reloc);
}

static BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
{
	BNRegisterInfo result;
	result.fullWidthRegister = fullWidthReg;
	result.offset = offset;
	result.size = size;
	result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
	return result;
}

class Armv7Architecture: public ArmCommonArchitecture
{
protected:
	virtual std::string GetAssemblerTriple() override
	{
		if(m_endian == BigEndian)
			return "armv7eb-none-none";

		return "armv7-none-none";
	}

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result)
	{
		(void)addr;
		(void)maxLen;
		memset(&result, 0, sizeof(result));
		if (armv7_decompose(*(uint32_t*)data, &result, (uint32_t)addr, (uint32_t)(m_endian == BigEndian)) != 0)
			return false;
		return true;
	}

	void SetInstructionInfoForInstruction(uint64_t addr, const Instruction& instr, InstructionInfo& result)
	{
		result.length = 4;

		switch (instr.operation)
		{
		case ARMV7_BL:
			if (UNCONDITIONAL(instr.cond) && (instr.operands[0].cls == LABEL))
				result.AddBranch(CallDestination, instr.operands[0].imm, this);
			break;
		case ARMV7_BLX:
			result.archTransitionByTargetAddr = true;
			if (UNCONDITIONAL(instr.cond))
			{
				if (instr.operands[0].cls == LABEL)
					result.AddBranch(CallDestination, instr.operands[0].imm, m_thumbArch);
				else if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
					result.AddBranch(FunctionReturn); // initially indicate "blx lr" as a return since this is common and conservative; subsequent analysis determines if it's a function call
			}
			break;
		case ARMV7_BX:
			if (UNCONDITIONAL(instr.cond))
			{
				if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
					result.AddBranch(FunctionReturn);
				else
				{
					result.AddBranch(UnresolvedBranch);
					result.archTransitionByTargetAddr = true;
				}
			}
			else if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
				result.AddBranch(FalseBranch, addr + 4, this);
			break;
		case ARMV7_B:
			if (UNCONDITIONAL(instr.cond))
				result.AddBranch(UnconditionalBranch, instr.operands[0].imm, this);
			else
			{
				result.AddBranch(TrueBranch, instr.operands[0].imm, this);
				result.AddBranch(FalseBranch, addr + 4, this);
			}
			break;
		case ARMV7_POP:
			//if pop with PC in the register list treat as a return
			if (instr.operands[0].cls == REG_LIST && ((instr.operands[0].reg & REG_LIST_PC) == REG_LIST_PC))
			{
				result.AddBranch(FunctionReturn);
				if (!UNCONDITIONAL(instr.cond))
					result.AddBranch(FalseBranch, addr + 4, this);
			}
			break;
		case ARMV7_LDM:
		case ARMV7_LDMDA:
		case ARMV7_LDMDB:
		case ARMV7_LDMIA: // defaults to ARMV7_LDM
		case ARMV7_LDMIB:
			//if this is an unconditional load multiple with PC in the register list treat as a return
			if (UNCONDITIONAL(instr.cond))
			{
				if (instr.operands[1].cls == REG_LIST && ((RegisterList)instr.operands[1].reg == REG_LIST_PC))
				{
					result.archTransitionByTargetAddr = true;
					result.AddBranch(UnresolvedBranch);
				}
				else if (instr.operands[1].cls == REG_LIST && ((instr.operands[1].reg & REG_LIST_PC) == REG_LIST_PC))
					result.AddBranch(FunctionReturn);
			}
			break;
		case ARMV7_ADC:
		case ARMV7_ADD:
		case ARMV7_AND:
		case ARMV7_ASR:
		case ARMV7_BIC:
		case ARMV7_EOR:
		case ARMV7_LDR:
		case ARMV7_LSL:
		case ARMV7_LSR:
		case ARMV7_MOV:
		case ARMV7_MVN:
		case ARMV7_ORR:
		case ARMV7_ROR:
		case ARMV7_RRX:
		case ARMV7_RSB:
		case ARMV7_RSC:
		case ARMV7_SUB:
		case ARMV7_SBC:
			if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
			{
				result.archTransitionByTargetAddr = true;
				result.AddBranch(UnresolvedBranch);
				if (!UNCONDITIONAL(instr.cond))
					result.AddBranch(FalseBranch, addr + 4, this);
			}
			break;
		case ARMV7_MOVW:
		case ARMV7_MOVT:
		case ARMV7_LDRT:
		case ARMV7_LDRH:
		case ARMV7_LDRHT:
		case ARMV7_LDRB:
		case ARMV7_LDRBT:
		case ARMV7_LDRSH:
		case ARMV7_LDRSHT:
		case ARMV7_LDRSB:
		case ARMV7_LDRSBT:
		case ARMV7_LDRD:
		case ARMV7_ADR:
		case ARMV7_UBFX:
		case ARMV7_UXTAB:
		case ARMV7_UXTB:
		case ARMV7_UXTH:
		case ARMV7_MUL:
		case ARMV7_SDIV:
		case ARMV7_UDIV:
		case ARMV7_SBFX:
		case ARMV7_SXTB:
		case ARMV7_SXTH:
		case ARMV7_BFC:
		case ARMV7_BFI:
		case ARMV7_CLZ:
			if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
			{
				result.AddBranch(UnresolvedBranch);
				if (!UNCONDITIONAL(instr.cond))
					result.AddBranch(FalseBranch, addr + 4, this);
			}
			break;
		case ARMV7_SVC:
			if (instr.operands[0].cls == IMM && instr.operands[0].imm == 0)
				result.AddBranch(SystemCall);
			break;
		case ARMV7_UDF:
			result.AddBranch(ExceptionBranch);
			break;
		default:
			break;
		}
	}

	uint32_t tokenize_shift(const InstructionOperand& op, vector<InstructionTextToken>& result)
	{
		char operand[64] = {0};
		if (op.shift != SHIFT_NONE)
		{
			const char* shiftStr = get_shift(op.shift);
			if (shiftStr == NULL)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			result.emplace_back(TextToken, ", ");
			result.emplace_back(KeywordToken, shiftStr);
			snprintf(operand, sizeof(operand), "%#x", (uint32_t)op.imm);
			result.emplace_back(OperationToken, " #");
			result.emplace_back(IntegerToken, operand, op.imm);
		}
		return DISASM_SUCCESS;
	}

	void tokenize_shifted_immediate(const InstructionOperand& op,  vector<InstructionTextToken>& result)
	{
		char operand[64] = {0};
		const char* sign = "";
		switch (op.cls)
		{
			case FIMM16:
			case FIMM32:
				snprintf(operand, sizeof(operand), "%f", op.immf);
				result.emplace_back(OperationToken, "#");
				result.emplace_back(FloatingPointToken, operand);
				break;
			case FIMM64:
				snprintf(operand, sizeof(operand), "%e", op.immd);
				result.emplace_back(OperationToken, "#");
				result.emplace_back(FloatingPointToken, operand);
				break;
			case IMM:
				snprintf(operand, sizeof(operand), "%s%#x", sign, (uint32_t)op.imm);
				result.emplace_back(OperationToken, "#");
				result.emplace_back(IntegerToken, operand, op.imm);
				break;
			case IMM64:
				snprintf(operand, sizeof(operand), "%s%#" PRIx64, sign, op.imm64);
				result.emplace_back(OperationToken, "#");
				result.emplace_back(IntegerToken, operand, op.imm64);
				break;
			case LABEL:
				snprintf(operand, sizeof(operand), "%#x", op.imm);
				result.emplace_back(PossibleAddressToken, operand, op.imm);
				break;
			default:
				return;
		}

		tokenize_shift(op, result);
	}

	uint32_t tokenize_shifted_register(
		const InstructionOperand& op,
		vector<InstructionTextToken>& result)
	{
		const char* reg = NULL;
		reg = GetRegisterName((enum Register)op.reg).c_str();
		if (reg == NULL)
			return FAILED_TO_DISASSEMBLE_REGISTER;


		result.emplace_back(RegisterToken, reg);
		tokenize_shift(op, result);
		return DISASM_SUCCESS;
	}


	bool GetCoalescedLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il, Instruction& instr)
	{
		size_t remaining = len / 4;
		if (remaining > COALESCE_MAX_INSTRS)
			remaining = COALESCE_MAX_INSTRS;

		Condition cond = instr.cond;

		Instruction coalesced[COALESCE_MAX_INSTRS];
		bool liftInstruction[COALESCE_MAX_INSTRS];
		size_t disassembled = 1;

		coalesced[0] = instr;
		liftInstruction[0] = true;

		auto setsFlags = [](const Instruction& instr)
		{
			if (instr.setsFlags)
				return true;

			switch(instr.operation)
			{
				case ARMV7_CMP:
				case ARMV7_CMN:
				case ARMV7_TST:
					return true;

				case ARMV7_BL:
				case ARMV7_BLX:
					return true;

				default:
					return false;
			}
		};

		for (bool condValid[2] = {true, true}; (disassembled < remaining) && (condValid[0] || condValid[1]); disassembled++)
		{
			size_t consumed = disassembled * 4;
			auto& newInstr = coalesced[disassembled];

			if (!Disassemble(data + consumed, addr + consumed, len - consumed, newInstr))
				break;
			if (UNCONDITIONAL(newInstr.cond))
				break;
			if (!IsRelatedCondition(newInstr.cond, cond))
				break;

			liftInstruction[disassembled] = condValid[newInstr.cond != cond];
			if (!CanCoalesceAfterInstruction(newInstr))
				condValid[newInstr.cond != cond] = false;

			if (setsFlags(instr))
			{
				condValid[0] = true;
				condValid[1] = true;
			}
		}

		if (disassembled == 1)
		{
			len = 4;
			return GetLowLevelILForArmInstruction(this, addr, il, instr, GetAddressSize());
		}


		LowLevelILLabel doneLabel;
		LowLevelILLabel condLabels[2];

		BNLowLevelILLabel* doneLabelExisting = il.GetLabelForAddress(this, addr + (disassembled * 4));
		BNLowLevelILLabel* doneLabelToUse = doneLabelExisting ? doneLabelExisting : &doneLabel;

		for (size_t blockStart = 0; blockStart < disassembled;)
		{
			auto& beginInstr = coalesced[blockStart];
			size_t stateIdx = (beginInstr.cond != cond);

			// determine how many instructions to lift this iteration.
			// generally, this will be set to `disassembled`, but in the
			// event that cmp/cmn/tst instructions are used in the conditional
			// block, they each require re-evaluation of the condition on the side
			// that executed the flag setting instructions
			size_t nextFlagSet = blockStart;
			for (; nextFlagSet < disassembled; nextFlagSet++)
			{
				if (!liftInstruction[nextFlagSet])
					continue; // skip unreachable instructions

				if (setsFlags(coalesced[nextFlagSet]))
					break;
			}

			// figure out where the next block start for the *other* condition in the sequence is
			size_t otherCondNext = blockStart + 1;
			for (; otherCondNext < disassembled ; otherCondNext++)
			{
				if (!liftInstruction[otherCondNext])
					continue; // skip unreachable instructions

				if (coalesced[otherCondNext].cond != beginInstr.cond)
					break;
			}

			bool hasOtherPath = (otherCondNext < disassembled);

			il.SetCurrentAddress(this, addr + (blockStart * 4));
			il.AddInstruction(il.If(GetCondition(il, beginInstr.cond), condLabels[stateIdx],
						hasOtherPath ? condLabels[1 - stateIdx] : *doneLabelToUse));

			auto liftInstructions = [&](Condition liftCond)
			{
				size_t stateIdx = (liftCond != cond);

				il.MarkLabel(condLabels[stateIdx]);
				condLabels[stateIdx] = LowLevelILLabel();

				bool exhausted = true;
				for (size_t i = nextFlagSet + 1; (i < disassembled) && exhausted; i++)
					if (coalesced[i].cond == liftCond)
						exhausted = false;

				size_t liftIdx = blockStart;
				for (; (liftIdx <= nextFlagSet) && (liftIdx < disassembled); liftIdx++)
				{
					if (!liftInstruction[liftIdx])
						continue; // skip unreachable instructions

					auto& curInstr = coalesced[liftIdx];
					if (curInstr.cond != liftCond)
						continue;

					uint64_t instrAddr = addr + (liftIdx * 4);

					il.SetCurrentAddress(this, instrAddr);

					curInstr.cond = COND_NONE;
					GetLowLevelILForArmInstruction(this, instrAddr, il, curInstr, GetAddressSize());
					curInstr.cond = liftCond;
				}

				// CASE 1: last instr was a flag-setting instruction, do nothing, next lifting fixes it
				if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == liftCond))
					return;

				// CASE 2: no further instructions with this cond exist: goto done
				else if (exhausted)
					il.AddInstruction(il.Goto(*doneLabelToUse));

				// CASE 3: last instr was not a flag-setting instruction, goto next block of this cond (or end)
				else
					il.AddInstruction(il.Goto(condLabels[stateIdx]));
			};

			bool liftAfter = false;
			if (hasOtherPath && (otherCondNext <= nextFlagSet))
			{
				// if we have two different cases to lift, and one of them contains a flag-setting
				// instruction, make sure the condition with the the flag-setting instruction is
				// lifted last. this lets us avoid an unnecessary LLIL_GOTO to the next if statement
				if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == beginInstr.cond))
					liftInstructions(coalesced[otherCondNext].cond);
				else
					liftAfter = true;
			}

			liftInstructions(beginInstr.cond);

			if (liftAfter)
				liftInstructions(coalesced[otherCondNext].cond);

			blockStart = nextFlagSet + 1;
		}

		if (!doneLabelExisting)
			il.MarkLabel(doneLabel);

		len = disassembled * 4;
		return (doneLabelExisting == nullptr);
	}

public:
	Armv7Architecture(const char* arch, BNEndianness endian)
		: ArmCommonArchitecture(arch, endian)
	{
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
	}

	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
		if (maxLen < 4)
			return false;

		Instruction instr;
		if (!Disassemble(data, addr, maxLen, instr))
			return false;

		SetInstructionInfoForInstruction(addr, instr, result);
		return true;
	}

	static inline void GetImmToken(const InstructionOperand& op, vector<InstructionTextToken>& result)
	{
		char operand[32];
		snprintf(operand, sizeof(operand), "%#x", (uint32_t)op.imm);
		result.emplace_back(OperationToken, " #");
		result.emplace_back(IntegerToken, operand, op.imm);
	}

	static inline void GetSignedImmToken(const InstructionOperand& op, vector<InstructionTextToken>& result)
	{
		char operand[32];
		const char* neg[2] = {"-", ""};
		snprintf(operand, sizeof(operand), "%s%#x", neg[op.flags.add == 1], (uint32_t)op.imm);
		result.emplace_back(OperationToken, " #");
		result.emplace_back(IntegerToken, operand, op.imm);
	}

	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		Instruction instr;
		char padding[9];

		const char* neg[2] = {"-", ""};
		const char* wb[2] = {"", "!"};
		const char* crt[2] = {"", " ^"};
		bool first = true;
		char tmpOperand[256];

		if (!Disassemble(data, addr, len, instr))
			return false;
		len = 4;
		memset(padding, 0x20, sizeof(padding));

		const char* operation = get_full_operation(tmpOperand, sizeof(tmpOperand), &instr);
		if (operation == NULL)
			return false;
		size_t operationLen = strlen(operation);
		if (operationLen < 8)
		{
			padding[8-operationLen] = '\0';
		}
		else
			padding[1] = '\0';

		result.emplace_back(InstructionToken, operation);
		result.emplace_back(TextToken, padding);

		try
		{
		for (size_t i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].cls == NONE)
				return true;

			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");

			switch (instr.operands[i].cls)
			{
			case FIMM16:
			case FIMM32:
			case FIMM64:
			case IMM:
			case IMM64:
			case LABEL:
				tokenize_shifted_immediate(instr.operands[i], result);
				break;
			case REG:
				result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
				result.emplace_back(OperationToken, wb[instr.operands[i].flags.wb]);
				if (instr.operands[i].shift == SHIFT_NONE)
				{
					if (instr.operands[i].flags.hasElements == 1)
					{
						result.emplace_back(BraceToken, "[");
						snprintf(tmpOperand, sizeof(tmpOperand), "%d", instr.operands[i].imm);
						result.emplace_back(IntegerToken, tmpOperand, instr.operands[i].imm);
						result.emplace_back(BraceToken, "]");
					}
				}
				else if (instr.operands[i].flags.offsetRegUsed == 1)
				{
					//Register shifted by register
					result.emplace_back(TextToken, ", ");
					result.emplace_back(KeywordToken, get_shift(instr.operands[i].shift));
					result.emplace_back(TextToken, " ");
					result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
				}
				else
				{
					//Register shifted by constant
					result.emplace_back(TextToken, ", ");
					result.emplace_back(KeywordToken, get_shift(instr.operands[i].shift));
					if (instr.operands[i].shift != SHIFT_RRX)
					{
						result.emplace_back(TextToken, " ");
						GetImmToken(instr.operands[i], result);
					}
				}
				break;
			case REG_LIST:
			case REG_LIST_SINGLE:
			case REG_LIST_DOUBLE:
				{
					result.emplace_back(BraceToken, "{");
					first = true;
					uint32_t base = 0;
					if (instr.operands[i].cls == REG_LIST_SINGLE)
						base = REG_S0;
					else if (instr.operands[i].cls == REG_LIST_DOUBLE)
						base = REG_D0;

					for (int32_t j = 0; j < 32; j++)
					{
						if (((instr.operands[i].reg >> j) & 1) == 1)
						{
							if (!first)
								result.emplace_back(TextToken, ", ");
							result.emplace_back(RegisterToken, GetRegisterName((enum Register)(j + base)));
							first = false;
						}
					}
					result.emplace_back(BraceToken, "}");
					result.emplace_back(OperationToken, crt[instr.operands[i].flags.wb]);
				}
				break;
			case REG_SPEC:
				result.emplace_back(RegisterToken, get_spec_register_name(instr.operands[i].regs));
				break;
			case REG_BANKED:
				result.emplace_back(RegisterToken, get_banked_register_name(instr.operands[i].regb));
				break;
			case REG_COPROCP:
				result.emplace_back(RegisterToken, get_coproc_register_p_name(instr.operands[i].regp));
				break;
			case REG_COPROCC:
				result.emplace_back(RegisterToken, get_coproc_register_c_name(instr.operands[i].regc));
				break;
			case IFLAGS:
				result.emplace_back(KeywordToken, get_iflag(instr.operands[i].iflag));
				break;
				case ENDIAN_SPEC:
				result.emplace_back(KeywordToken, get_endian(instr.operands[i].endian));
				break;
			case DSB_OPTION:
				result.emplace_back(KeywordToken, get_dsb_option(instr.operands[i].dsbOpt));
				break;
			case MEM_ALIGNED:
				result.emplace_back(BraceToken, "[");
				result.emplace_back(BeginMemoryOperandToken, "");
				result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
				if (instr.operands[i].imm != 0)
				{
					result.emplace_back(OperationToken, ":");
					snprintf(tmpOperand, sizeof(tmpOperand), "%#x", instr.operands[i].imm);
					result.emplace_back(IntegerToken, tmpOperand, instr.operands[i].imm);
				}
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(OperationToken, wb[instr.operands[i].flags.wb]);
				break;
			case MEM_OPTION:
				result.emplace_back(BraceToken, "[");
				result.emplace_back(BeginMemoryOperandToken, "");
				result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(TextToken, ", ");
				result.emplace_back(BraceToken, "{");
				GetImmToken(instr.operands[i], result);
				result.emplace_back(BraceToken, "}");
				break;
			case MEM_PRE_IDX:
				result.emplace_back(BraceToken, "[");
				result.emplace_back(BeginMemoryOperandToken, "");
				if (instr.operands[i].flags.offsetRegUsed == 1)
				{
					result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
					result.emplace_back(TextToken, ", ");
					result.emplace_back(OperationToken, neg[instr.operands[i].flags.add == 1]);
					if (instr.operands[i].imm == 0)
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
					else if (instr.operands[i].shift == SHIFT_RRX)
					{
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
					}
					else
					{
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
						result.emplace_back(TextToken, " ");
						GetImmToken(instr.operands[i], result);
					}
				}
				else
				{
					result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
					result.emplace_back(TextToken, ", ");
					GetSignedImmToken(instr.operands[i], result);
				}
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(OperationToken, "!");
				break;
				break;
			case MEM_POST_IDX:
				result.emplace_back(BraceToken, "[");
				result.emplace_back(BeginMemoryOperandToken, "");
				result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(TextToken, ", ");
				if (instr.operands[i].flags.offsetRegUsed == 1)
				{
					result.emplace_back(OperationToken, neg[instr.operands[i].flags.add == 1]);
					if (instr.operands[i].imm == 0)
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
					else if (instr.operands[i].shift == SHIFT_RRX)
					{
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
					}
					else
					{
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
						result.emplace_back(TextToken, " ");
						GetImmToken(instr.operands[i], result);
					}
				}
				else
				{
					GetSignedImmToken(instr.operands[i], result);
				}
				break;
			case MEM_IMM:
				result.emplace_back(BraceToken, "[");
				result.emplace_back(BeginMemoryOperandToken, "");
				result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].reg));
				switch (instr.operands[i].shift)
				{
					case SHIFT_NONE:
						if (instr.operands[i].flags.offsetRegUsed == 1)
						{
							result.emplace_back(TextToken, ", ");
							result.emplace_back(OperationToken, neg[instr.operands[i].flags.add == 1]);
							result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						}
						else if (instr.operands[i].imm != 0)// || instr.operands[i].flags.add == 0)
						{
							result.emplace_back(TextToken, ", ");
							GetSignedImmToken(instr.operands[i], result);
						}
						break;
					case SHIFT_RRX:
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, neg[instr.operands[i].flags.add == 1]);
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
						break;
					default:
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, neg[instr.operands[i].flags.add == 1]);
						result.emplace_back(RegisterToken, GetRegisterName(instr.operands[i].offset));
						result.emplace_back(TextToken, ", ");
						result.emplace_back(OperationToken, get_shift(instr.operands[i].shift));
						result.emplace_back(TextToken, " ");
						GetImmToken(instr.operands[i], result);
				}
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				break;
			default:
				LogError("operandClass %d\n", instr.operands[i].cls);
				return false;
			}
		}
		}
		catch (exception&)
		{
			LogWarn("Failed to disassemble instruction with encoding: %" PRIx32 "\n", *(uint32_t*)data);
		}
		return true;
	}


	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARMV7_INTRIN_COPROC_GETONEWORD:
			return "Coproc_GetOneWord";
		case ARMV7_INTRIN_COPROC_GETTWOWORDS:
			return "Coproc_GetTwoWords";
		case ARMV7_INTRIN_COPROC_SENDONEWORD:
			return "Coproc_SendOneWord";
		case ARMV7_INTRIN_COPROC_SENDTWOWORDS:
			return "Coproc_SendTwoWords";
		case ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS:
			return "ExclusiveMonitorsPass";
		case ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS:
			return "SetExclusiveMonitors";
		default:
			return "";
		}
	}

	virtual vector<uint32_t> GetAllIntrinsics() override
	{
		return vector<uint32_t> {
				ARMV7_INTRIN_COPROC_GETONEWORD,
				ARMV7_INTRIN_COPROC_GETTWOWORDS,
				ARMV7_INTRIN_COPROC_SENDONEWORD,
				ARMV7_INTRIN_COPROC_SENDTWOWORDS,
				ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
				ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
		};
	}

	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARMV7_INTRIN_COPROC_GETONEWORD:
			return {
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("n", Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_COPROC_GETTWOWORDS:
			return {
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_COPROC_SENDONEWORD:
			return {
				NameAndType(Type::IntegerType(4, false)),
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("n", Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_COPROC_SENDTWOWORDS:
			return {
				NameAndType(Type::IntegerType(4, false)),
				NameAndType(Type::IntegerType(4, false)),
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS:
		case ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
				NameAndType("size", Type::IntegerType(1, false)),
			};
		default:
			return vector<NameAndType>();
		}
	}

	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARMV7_INTRIN_COPROC_GETONEWORD:
			return { Type::IntegerType(4, false) };
		case ARMV7_INTRIN_COPROC_GETTWOWORDS:
			return { Type::IntegerType(4, false), Type::IntegerType(4, false) };
		case ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS:
			return { Type::BoolType() };
		default:
			return vector<Confidence<Ref<Type>>>();
		}
	}

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == ARMV7_B && CONDITIONAL(instr.cond));
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == ARMV7_B && CONDITIONAL(instr.cond));
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == ARMV7_B && CONDITIONAL(instr.cond));
	}

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint32_t nop =  0xe1a00000;
		if (len < sizeof(nop))
			return false;
		for (size_t i = 0; i < len/sizeof(nop); i++)
			((uint32_t*)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		if (len < 4)
			return false;

		uint32_t *value = (uint32_t*)data;
		*value = (*value & 0x0fffffff) | (COND_NONE << 28);
		return true;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		if (len < sizeof(uint32_t))
			return false;
		uint32_t *value = (uint32_t*)data;
		Condition cond = COND_NONE;
		switch (*value >> 28)
		{
			case COND_EQ: cond = COND_NE; break;
			case COND_NE: cond = COND_EQ; break;
			case COND_CS: cond = COND_CC; break;
			case COND_CC: cond = COND_CS; break;
			case COND_MI: cond = COND_PL; break;
			case COND_PL: cond = COND_MI; break;
			case COND_VS: cond = COND_VC; break;
			case COND_VC: cond = COND_VS; break;
			case COND_HI: cond = COND_LS; break;
			case COND_LS: cond = COND_HI; break;
			case COND_GE: cond = COND_LT; break;
			case COND_LT: cond = COND_GE; break;
			case COND_GT: cond = COND_LE; break;
			case COND_LE: cond = COND_GT; break;
		}
		*value = (*value & 0x0fffffff) | (cond << 28);
		return true;
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == ARMV7_BL) || (instr.operation == ARMV7_BLX);
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == ARMV7_BL) || (instr.operation == ARMV7_BLX);
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)addr;
		//Return value is put in R0. The largest value that we can put into a single integer is 12 bits
		if (value > 0xfff || len > 4)
			return false;

		uint32_t movValueR0 = 0xe3a00000;
		uint32_t *inst = (uint32_t*)data;
		*inst = movValueR0 | (value & 0xfff);
		return true;
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
		{
			il.AddInstruction(il.Undefined());
			return false;
		}

		if (!UNCONDITIONAL(instr.cond))
			return GetCoalescedLowLevelIL(data, addr, len, il, instr);
		else
		{
			if ((instr.operation == ARMV7_MOV) && (instr.operands[0].cls == REG) && (instr.operands[0].reg == REG_LR) && (instr.operands[1].cls == REG) && (instr.operands[1].reg == REG_PC))
			{
				Instruction branchInstr;
				if (Disassemble(data + 4, addr + 4, len - 4, branchInstr) && UNCONDITIONAL(branchInstr.cond) &&
				 (((branchInstr.operands[0].cls == REG) && (branchInstr.operands[0].reg == REG_PC)) || branchInstr.operation == ARMV7_BX))
				{
					switch (branchInstr.operation)
					{
					case ARMV7_ADC:
					case ARMV7_ADD:
					case ARMV7_AND:
					case ARMV7_ASR:
					case ARMV7_BIC:
					case ARMV7_EOR:
					case ARMV7_LDR:
					case ARMV7_LSL:
					case ARMV7_LSR:
					case ARMV7_MOV:
					case ARMV7_MVN:
					case ARMV7_ORR:
					case ARMV7_ROR:
					case ARMV7_RRX:
					case ARMV7_RSB:
					case ARMV7_RSC:
					case ARMV7_SUB:
					case ARMV7_SBC:
					case ARMV7_BX:
					{
						len = 8;
						il.SetCurrentAddress(this, addr + 4);
						size_t nextInstr = il.GetInstructionCount();
						GetLowLevelILForArmInstruction(this, addr + 4, il, branchInstr, GetAddressSize());
						for (; nextInstr < il.GetInstructionCount(); nextInstr++)
						{
							if (auto tgtInstr = il.GetInstruction(nextInstr); tgtInstr.operation == LLIL_JUMP)
							{
								il.ReplaceExpr(tgtInstr.exprIndex, il.Call(tgtInstr.GetDestExpr<LLIL_JUMP>().exprIndex));
								return true;
							}
						}
						break;
					}
					default:
						break;
					};
				}
			}

			len = 4;
			return GetLowLevelILForArmInstruction(this, addr, il, instr, GetAddressSize());
		}
	}
};

ArmCommonArchitecture::ArmCommonArchitecture(const char* name, BNEndianness endian): Architecture(name), m_endian(endian)
{
}

void ArmCommonArchitecture::SetArmAndThumbArchitectures(Architecture* arm, Architecture* thumb)
{
	m_armArch = arm;
	m_thumbArch = thumb;
}

size_t ArmCommonArchitecture::GetAddressSize() const
{
	return 4;
}

BNEndianness ArmCommonArchitecture::GetEndianness() const
{
	return m_endian;
}

Ref<Architecture> ArmCommonArchitecture::GetAssociatedArchitectureByAddress(uint64_t& addr)
{
	if (addr & 1)
	{
		addr &= ~1LL;
		return m_thumbArch;
	}
	return m_armArch;
}

string ArmCommonArchitecture::GetFlagName(uint32_t flag)
{
	char result[32];
	switch (flag)
	{
	case IL_FLAG_N:
		return "n";
	case IL_FLAG_Z:
		return "z";
	case IL_FLAG_C:
		return "c";
	case IL_FLAG_V:
		return "v";
	case IL_FLAG_Q:
		return "q";
	default:
		snprintf(result, sizeof(result), "flag%" PRIu32, flag);
		return result;
	}
}

string ArmCommonArchitecture::GetFlagWriteTypeName(uint32_t flags)
{
	switch (flags)
	{
		case IL_FLAGWRITE_ALL: return "*";
		case IL_FLAGWRITE_NZ: return "nz";
		case IL_FLAGWRITE_CNZ: return "cnz";
		default:
			return "";
	}
}

BNFlagRole ArmCommonArchitecture::GetFlagRole(uint32_t flag, uint32_t)
{
	switch (flag)
	{
	case IL_FLAG_N:
		return NegativeSignFlagRole;
	case IL_FLAG_Z:
		return ZeroFlagRole;
	case IL_FLAG_C:
		return CarryFlagWithInvertedSubtractRole;
	case IL_FLAG_V:
		return OverflowFlagRole;
	default:
		return SpecialFlagRole;
	}
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t flags)
{
	switch (flags)
	{
	case IL_FLAGWRITE_ALL:
		return vector<uint32_t> { IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V };
	case IL_FLAGWRITE_NZ:
		return vector<uint32_t> { IL_FLAG_N, IL_FLAG_Z };
	case IL_FLAGWRITE_CNZ:
		return vector<uint32_t> { IL_FLAG_C, IL_FLAG_N, IL_FLAG_Z };
	default:
		return vector<uint32_t> {};
	}
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t)
{
	switch (cond)
	{
	case LLFC_E:
	case LLFC_NE:
		return vector<uint32_t>{ IL_FLAG_Z };
	case LLFC_SLT:
	case LLFC_SGE:
		return vector<uint32_t>{ IL_FLAG_N, IL_FLAG_V };
	case LLFC_ULT:
	case LLFC_UGE:
		return vector<uint32_t>{ IL_FLAG_C };
	case LLFC_SLE:
	case LLFC_SGT:
		return vector<uint32_t>{ IL_FLAG_Z, IL_FLAG_N, IL_FLAG_V };
	case LLFC_ULE:
	case LLFC_UGT:
		return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_Z };
	case LLFC_NEG:
	case LLFC_POS:
		return vector<uint32_t>{ IL_FLAG_N };
	case LLFC_O:
	case LLFC_NO:
		return vector<uint32_t>{ IL_FLAG_V };
	default:
		return vector<uint32_t>();
	}
}

size_t ArmCommonArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	switch (op)
	{
	case LLIL_SBB:
		switch (flag)
		{
		case IL_FLAG_C:
			// Copied from arm64
			// r u< a || (r == a && flag_c)
			return il.Or(0,
					il.CompareUnsignedLessThan(size,
						il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
						il.GetExprForRegisterOrConstant(operands[0], size)),
					il.And(0,
						il.CompareEqual(size,
							il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
							il.GetExprForRegisterOrConstant(operands[0], size)),
						il.Flag(IL_FLAG_C)));
		case IL_FLAG_V:
			return il.CompareEqual(0,
					il.CompareSignedLessThan(size,
						il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
						il.GetExprForRegisterOrConstant(operands[0], size)),
					il.CompareEqual(size,
						il.GetExprForRegisterOrConstant(operands[0], size),
						il.Const(size, 0)));
		}
		break;
	case LLIL_LSR:
		switch (flag)
		{
		case IL_FLAG_C:
			/*
			 * The last bit spilled out of the register by the shift lands in the carry flag.
			 * For example, `((u32)1) >> 1` sets the carry flag, `((u32)2) >> 1` clears it.
			 * We can simplify this to a bit test: `x & (1 << (shift_amt - 1))`
			 */
			return il.TestBit(0,
					il.GetExprForRegisterOrConstant(operands[0], size),
					il.Sub(size, il.GetExprForRegisterOrConstant(operands[1], size), il.Const(size, 1)));
		}
		break;
	case LLIL_LSL:
		switch (flag)
		{
		case IL_FLAG_C:
			/*
			 * Just like the carry flag for LSR, this is the last bit spilled out of the register.
			 * Also equivalent to a bit test, just indexing from the most significant bit rather
			 * than the least.
			 */
			return il.TestBit(0,
					il.GetExprForRegisterOrConstant(operands[0], size),
					il.Sub(size, il.Const(size, 8 * size), il.GetExprForRegisterOrConstant(operands[1], size)));
		}
	default:
		break;
	}

	BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
	return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
}

string ArmCommonArchitecture::GetRegisterName(uint32_t reg)
{
	if (reg >= REG_R0 && reg < REG_INVALID)
	{
		return get_register_name((enum Register)reg);
	}

	if (reg == FAKEREG_SYSCALL_INFO)
	{
		return "syscall_info";
	}

	LogError("Unknown Register: %x - Please report this as a bug.\n", reg);
	return "unknown";
}

vector<uint32_t> ArmCommonArchitecture::GetFullWidthRegisters()
{
	return vector<uint32_t>{
		REG_R0,   REG_R1,   REG_R2,   REG_R3,   REG_R4,   REG_R5,   REG_R6,   REG_R7,
		REG_R8,   REG_R9,   REG_R10,  REG_R11,  REG_R12,  REG_R13,  REG_R14,  REG_R15,
		REG_Q0,   REG_Q1,   REG_Q2,   REG_Q3,   REG_Q4,   REG_Q5,   REG_Q6,   REG_Q7,
		REG_Q8,   REG_Q9,   REG_Q10,  REG_Q11,  REG_Q12,  REG_Q13,  REG_Q14,  REG_Q15,
	};
}

vector<uint32_t> ArmCommonArchitecture::GetAllRegisters()
{
	return vector<uint32_t>{
		REG_R0,   REG_R1,   REG_R2,   REG_R3,   REG_R4,   REG_R5,   REG_R6,   REG_R7,
		REG_R8,   REG_R9,   REG_R10,  REG_R11,  REG_R12,  REG_R13,  REG_R14,  REG_R15,
		REG_S0,   REG_S1,   REG_S2,   REG_S3,   REG_S4,   REG_S5,   REG_S6,   REG_S7,
		REG_S8,   REG_S9,   REG_S10,  REG_S11,  REG_S12,  REG_S13,  REG_S14,  REG_S15,
		REG_S16,  REG_S17,  REG_S18,  REG_S19,  REG_S20,  REG_S21,  REG_S22,  REG_S23,
		REG_S24,  REG_S25,  REG_S26,  REG_S27,  REG_S28,  REG_S29,  REG_S30,  REG_S31,
		REG_D0,   REG_D1,   REG_D2,   REG_D3,   REG_D4,   REG_D5,   REG_D6,   REG_D7,
		REG_D8,   REG_D9,   REG_D10,  REG_D11,  REG_D12,  REG_D13,  REG_D14,  REG_D15,
		REG_D16,  REG_D17,  REG_D18,  REG_D19,  REG_D20,  REG_D21,  REG_D22,  REG_D23,
		REG_D24,  REG_D25,  REG_D26,  REG_D27,  REG_D28,  REG_D29,  REG_D30,  REG_D31,
		REG_Q0,   REG_Q1,   REG_Q2,   REG_Q3,   REG_Q4,   REG_Q5,   REG_Q6,   REG_Q7,
		REG_Q8,   REG_Q9,   REG_Q10,  REG_Q11,  REG_Q12,  REG_Q13,  REG_Q14,  REG_Q15,

		/* special registers */
		REGS_APSR, REGS_APSR_G, REGS_APSR_NZCVQ, REGS_APSR_NZCVQG,
		REGS_CPSR, REGS_CPSR_C, REGS_CPSR_X, REGS_CPSR_XC,
		REGS_CPSR_S, REGS_CPSR_SC, REGS_CPSR_SX, REGS_CPSR_SXC,
		REGS_CPSR_F, REGS_CPSR_FC, REGS_CPSR_FX, REGS_CPSR_FXC,
		REGS_CPSR_FS, REGS_CPSR_FSC, REGS_CPSR_FSX, REGS_CPSR_FSXC,
		REGS_SPSR, REGS_SPSR_C, REGS_SPSR_X, REGS_SPSR_XC,
		REGS_SPSR_S, REGS_SPSR_SC, REGS_SPSR_SX, REGS_SPSR_SXC,
		REGS_SPSR_F, REGS_SPSR_FC, REGS_SPSR_FX, REGS_SPSR_FXC,
		REGS_SPSR_FS, REGS_SPSR_FSC, REGS_SPSR_FSX, REGS_SPSR_FSXC,
		REGS_APSR_NZCV, REGS_FPSID, REGS_FPSCR, REGS_MVFR2,
		REGS_MVFR1, REGS_MVFR0, REGS_FPEXC, REGS_FPINST,
		REGS_FPINST2, REGS_MSP, REGS_PSP, REGS_PRIMASK,
		REGS_BASEPRI, REGS_FAULTMASK, REGS_CONTROL,

		/* fake registers */
		FAKEREG_SYSCALL_INFO
	};
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlags()
{
	return vector<uint32_t>{
		IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V, IL_FLAG_Q
	};
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlagWriteTypes()
{
	return vector<uint32_t>{
		IL_FLAGWRITE_ALL,
		IL_FLAGWRITE_NZ,
		IL_FLAGWRITE_CNZ
	};
}

BNRegisterInfo ArmCommonArchitecture::GetRegisterInfo(uint32_t reg)
{
	switch (reg)
	{
		case REG_R0:
		case REG_R1:
		case REG_R2:
		case REG_R3:
		case REG_R4:
		case REG_R5:
		case REG_R6:
		case REG_R7:
		case REG_R8:
		case REG_R9:
		case REG_R10:
		case REG_R11:
		case REG_R12:
		case REG_R13:
		case REG_R14:
		case REG_R15:
				return RegisterInfo(reg, 0, 4);
		case REG_S0:
		case REG_S1:
		case REG_S2:
		case REG_S3:
		case REG_S4:
		case REG_S5:
		case REG_S6:
		case REG_S7:
		case REG_S8:
		case REG_S9:
		case REG_S10:
		case REG_S11:
		case REG_S12:
		case REG_S13:
		case REG_S14:
		case REG_S15:
		case REG_S16:
		case REG_S17:
		case REG_S18:
		case REG_S19:
		case REG_S20:
		case REG_S21:
		case REG_S22:
		case REG_S23:
		case REG_S24:
		case REG_S25:
		case REG_S26:
		case REG_S27:
		case REG_S28:
		case REG_S29:
		case REG_S30:
		case REG_S31:
			return RegisterInfo(REG_Q0+((reg-REG_S0)/4), ((reg-REG_S0)%4) * 4, 4);
		case REG_D0:
		case REG_D1:
		case REG_D2:
		case REG_D3:
		case REG_D4:
		case REG_D5:
		case REG_D6:
		case REG_D7:
		case REG_D8:
		case REG_D9:
		case REG_D10:
		case REG_D11:
		case REG_D12:
		case REG_D13:
		case REG_D14:
		case REG_D15:
		case REG_D16:
		case REG_D17:
		case REG_D18:
		case REG_D19:
		case REG_D20:
		case REG_D21:
		case REG_D22:
		case REG_D23:
		case REG_D24:
		case REG_D25:
		case REG_D26:
		case REG_D27:
		case REG_D28:
		case REG_D29:
		case REG_D30:
		case REG_D31:
			return RegisterInfo(REG_Q0+((reg-REG_D0)/2), ((reg-REG_D0)%2) * 8, 8);
		case REG_Q0:
		case REG_Q1:
		case REG_Q2:
		case REG_Q3:
		case REG_Q4:
		case REG_Q5:
		case REG_Q6:
		case REG_Q7:
		case REG_Q8:
		case REG_Q9:
		case REG_Q10:
		case REG_Q11:
		case REG_Q12:
		case REG_Q13:
		case REG_Q14:
		case REG_Q15:
			return RegisterInfo(reg, 0, 16);
		case REGS_APSR:
		case REGS_APSR_G:
		case REGS_APSR_NZCVQ:
		case REGS_APSR_NZCVQG:
		case REGS_CPSR:
		case REGS_CPSR_C:
		case REGS_CPSR_X:
		case REGS_CPSR_XC:
		case REGS_CPSR_S:
		case REGS_CPSR_SC:
		case REGS_CPSR_SX:
		case REGS_CPSR_SXC:
		case REGS_CPSR_F:
		case REGS_CPSR_FC:
		case REGS_CPSR_FX:
		case REGS_CPSR_FXC:
		case REGS_CPSR_FS:
		case REGS_CPSR_FSC:
		case REGS_CPSR_FSX:
		case REGS_CPSR_FSXC:
		case REGS_SPSR:
		case REGS_SPSR_C:
		case REGS_SPSR_X:
		case REGS_SPSR_XC:
		case REGS_SPSR_S:
		case REGS_SPSR_SC:
		case REGS_SPSR_SX:
		case REGS_SPSR_SXC:
		case REGS_SPSR_F:
		case REGS_SPSR_FC:
		case REGS_SPSR_FX:
		case REGS_SPSR_FXC:
		case REGS_SPSR_FS:
		case REGS_SPSR_FSC:
		case REGS_SPSR_FSX:
		case REGS_SPSR_FSXC:
		case REGS_APSR_NZCV:
		case REGS_FPSID:
		case REGS_FPSCR:
		case REGS_MVFR2:
		case REGS_MVFR1:
		case REGS_MVFR0:
		case REGS_FPEXC:
		case REGS_FPINST:
		case REGS_FPINST2:
		case REGS_MSP:
		case REGS_PSP:
		case REGS_PRIMASK:
		case REGS_BASEPRI:
		case REGS_FAULTMASK:
		case REGS_CONTROL:
			return RegisterInfo(reg, 0, 4);
		case FAKEREG_SYSCALL_INFO:
			return RegisterInfo(reg, 0, 4);
	}
	return RegisterInfo(0, 0, 0);
}

uint32_t ArmCommonArchitecture::GetStackPointerRegister()
{
	return REG_SP;
}

uint32_t ArmCommonArchitecture::GetLinkRegister()
{
	return REG_LR;
}

bool ArmCommonArchitecture::CanAssemble()
{
	return true;
}

bool ArmCommonArchitecture::Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors)
{
	(void)addr;

	char *instrBytes=NULL, *err=NULL;
	int instrBytesLen=0, errLen=0;

	int assembleResult;

	string triple = GetAssemblerTriple();
	LogDebug("%s() retrieves and uses triple %s\n", __func__, triple.c_str());

	BNLlvmServicesInit();

	errors.clear();
	assembleResult = BNLlvmServicesAssemble(code.c_str(), LLVM_SVCS_DIALECT_UNSPEC,
	  triple.c_str(), LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC,
	  &instrBytes, &instrBytesLen, &err, &errLen);

	if(assembleResult || errLen) {
		errors = err;
		BNLlvmServicesAssembleFree(instrBytes, err);
		return false;
	}

	result.Clear();
	result.Append(instrBytes, instrBytesLen);
	BNLlvmServicesAssembleFree(instrBytes, err);
	return true;
}

class ArmCallingConvention: public CallingConvention
{
public:
	ArmCallingConvention(Architecture* arch): CallingConvention(arch, "cdecl")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_R0, REG_R1, REG_R2, REG_R3 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R10, REG_R11 };
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_R0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_R1;
	}
};


class LinuxArmv7SystemCallConvention: public CallingConvention
{
public:
	LinuxArmv7SystemCallConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_R7, REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_R0 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R10, REG_R11 };
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_R0;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};


class Thumb2ImportedFunctionRecognizer: public FunctionRecognizer
{
public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		// Detection for inline veneers for thumb -> arm transitions
		if (il->GetInstructionCount() == 1)
		{
			LowLevelILInstruction instr = il->GetInstruction(0);
			if ((instr.operation == LLIL_JUMP) || (instr.operation == LLIL_TAILCALL))
			{
				LowLevelILInstruction operand = instr.GetDestExpr();
				if (operand.operation == LLIL_CONST_PTR)
				{
					uint64_t entry = operand.GetConstant();
					if (entry == (func->GetStart() + 4))
					{
						Ref<Function> entryFunc = data->GetRecentAnalysisFunctionForAddress(entry);
						Ref<Symbol> sym = data->GetSymbolByAddress(entry);
						if (!entryFunc || !sym || (sym->GetType() != ImportedFunctionSymbol))
							return false;

						Confidence<Ref<Type>> type = entryFunc->GetType();
						data->DefineImportedFunction(sym, func, type);
						return true;
					}
				}
			}
		}

		return false;
	}
};


uint32_t bswap32(uint32_t x)
{
	return ((x & 0xff000000) >> 24) |
	       ((x & 0x00ff0000) >> 8) |
	       ((x & 0x0000ff00) << 8) |
	       ((x & 0x000000ff) << 24);
}

class ArmElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		(void)view;
		BNRelocationInfo info = reloc->GetInfo();
		if (len < info.size)
			return false;
		Ref<Symbol> sym = reloc->GetSymbol();
		uint32_t target = (uint32_t)reloc->GetTarget();
		uint32_t* dest32 = (uint32_t*)dest;

		auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		switch (info.nativeType)
		{
			case R_ARM_COPY:
			case R_ARM_GLOB_DAT:
			case R_ARM_JUMP_SLOT:
			case R_ARM_BASE_PREL:
			case R_ARM_GOT_BREL:
				dest32[0] = swap(target);
				break;
			case R_ARM_RELATIVE:
			case R_ARM_ABS32:
				dest32[0] = swap(swap(dest32[0]) + target);
				break;
			case R_ARM_REL32:
				dest32[0] = swap((uint32_t)((target + (info.implicitAddend ? swap(dest32[0]) : info.addend)) - reloc->GetAddress()));
				break;
			case R_ARM_CALL:
			{
				if (target & 1)
				{
					LogError("Unsupported relocation R_ARM_CALL to thumb target");
					break;
				}
				struct _bl {
					int32_t imm:24;
					uint32_t group1:4;
					uint32_t cond:4;
				};
				_bl* bl = (_bl*) dest32;
				int64_t newTarget = (target + (info.implicitAddend ? ((bl->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
				if ((newTarget - 8) > 0x3ffffff)
				{
					LogError("Unsupported relocation R_ARM_CALL @ 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
					break;
				}
				bl->imm = (newTarget - 8) >> 2;
				break;
			}
			case R_ARM_THM_CALL:
			case R_ARM_THM_JUMP24:
			{
				// TODO: not portable
				#pragma pack(push, 1)
				union _thumb32_bl_hw1 {
					uint16_t word;
					struct {
						uint16_t offHi:10; // 21-12
						uint16_t sign:1; // 31-24
						uint16_t group:5;
					};
				};

				union _thumb32_bl_hw2 {
					uint16_t word;
					struct {
						uint16_t offLo:11; //b11-1
						uint16_t j2:1; //b18
						uint16_t thumb:1;
						uint16_t j1:1; //b19
						uint16_t i2:1; //b22
						uint16_t i1:1; //b23
					};
				};
				#pragma pack(pop)

				_thumb32_bl_hw1* bl_hw1 = (_thumb32_bl_hw1*)dest;
				_thumb32_bl_hw2* bl_hw2 = (_thumb32_bl_hw2*)(dest + 2);
				int32_t curTarget = (bl_hw2->offLo << 1) | (bl_hw1->offHi << 12) | (bl_hw1->sign ? (0xffc << 20) : 0);
				int32_t newTarget = (int32_t)((target + (info.implicitAddend ? curTarget : info.addend)) - reloc->GetAddress());

				bl_hw1->sign = newTarget < 0 ? 1 : 0;
				bl_hw1->offHi = newTarget >> 12;
				bl_hw2->offLo = newTarget >> 1;

				// TODO: I/J bit handling conflicts with at least one Thumb2 supplement
				// bl_hw2->i1 = bl_hw1->sign ^ ((newTarget >> 23) & 1);
				// bl_hw2->i2 = bl_hw1->sign ^ ((newTarget >> 22) & 1);
				// bl_hw2->j1 = (newTarget >> 19) & 1;
				// bl_hw2->j2 = (newTarget >> 18) & 1;
				break;
			}
			case R_ARM_PREL31:
			{
				// if (sym)
				// {
				// 	LogError("%lx sym: %s dest32[0] %lx target: %lx", reloc->GetAddress(), sym->GetFullName().c_str(), dest32[0], target);
				// }
				// else
				// {
				// 	LogError("%lx sym: null dest32[0] %lx target: %lx", reloc->GetAddress(), dest32[0], target);
				// }
				dest32[0] = (info.implicitAddend ? dest32[0] : (uint32_t)info.addend) + (target & ~1) - (uint32_t)reloc->GetAddress();
				break;
			}
			case R_ARM_JUMP24:
			{
				if (target & 1)
				{
					LogError("Unsupported relocation R_ARM_JUMP24 to thumb target");
					break;
				}
				struct _b {
					int32_t imm:24;
					uint32_t group1:4;
					uint32_t cond:4;
				};
				_b* b = (_b*) dest32;
				int64_t newTarget = (target + (info.implicitAddend ? ((b->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
				if ((newTarget - 8) > 0x3ffffff)
				{
					LogError("Unsupported relocation R_ARM_JUMP24 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
					break;
				}
				b->imm = (newTarget - 8) >> 2;
				break;
			}
			case R_ARM_MOVW_ABS_NC:
			{
				struct _mov {
					uint32_t imm12:12;
					uint32_t rd:4;
					uint32_t imm4:4;
					uint32_t group2:8;
					uint32_t cond:4;
				};
				_mov* mov = (_mov*)dest32;
				int64_t newTarget = (target + (info.implicitAddend ? (mov->imm4 << 12 | mov->imm12) : info.addend));
				mov->imm12 = newTarget & 0xfff;
				mov->imm4 = (newTarget >> 12) & 0xf;
				break;
			}
			case R_ARM_MOVT_ABS:
			{
				struct _mov {
					uint32_t imm12:12;
					uint32_t rd:4;
					uint32_t imm4:4;
					uint32_t group2:8;
					uint32_t cond:4;
				};
				_mov* mov = (_mov*)dest32;
				int64_t newTarget = (target + (info.implicitAddend ? (mov->imm4 << 12 | mov->imm12) : info.addend));
				mov->imm12 = (newTarget >> 16) & 0xfff;
				mov->imm4 = (newTarget >> 28) & 0xf;
				break;
			}
			case R_ARM_THM_MOVW_ABS_NC:
			case R_ARM_THM_MOVT_ABS:
			{
				/*
					MOVW<c> <Rd>,#<imm16>
						|15 14 13 12 11|10 |9  8 |7 |6 |5 |4 |3  2  1  0 |15|14 13 12|11 10  9  8 |7  6  5  4  3  2  1  0|
						|1  1  1  1  0 |i  |1  0 |0 |1 |0 |0 |imm4       |0 |imm3    |Rd          |imm8                  |
					MOVT<c> <Rd>,#<imm16>
						|15 14 13 12 11|10 |9  8 |7 |6 |5 |4 |3  2  1  0 |15|14 13 12|11 10  9  8 |7  6  5  4  3  2  1  0|
						|1  1  1  1  0 |i  |1  0 |1 |1 |0 |0 |imm4       |0 |imm3    |Rd          |imm8                  |
					imm16 = imm4:i:imm3:imm8
						i    = imm16[11]    = upper_insn[10]
						imm4 = imm16[12:15] = upper_insn[3:0]
						imm3 = imm16[8:10]  = lower_insn[14:12]
						imm8 = imm16[0:7]   = lower_insn[7:0]
				*/
				#pragma pack(push, 1)
				// TODO: not portable
				// see PE_IMAGE_REL_THUMB_MOV32 for a slightly different approach to structuring this
				struct _mov {
					// lower word
					uint32_t imm4:4;
					uint32_t group2:6;
					uint32_t i:1;
					// bit 3 of group3 (bit 7 of the lower word) determines if it's movt or movw:
					// MOVT: 0b101100
					// MOVW: 0b100100
					uint32_t group3:5;
					// upper word
					uint32_t imm8:8;
					uint32_t rd:4;
					uint32_t imm3:3;
					uint32_t group1_15:1;
				};
				union _target {
					// XXX: endianness?
					struct {
						uint16_t imm8:8;
						uint16_t imm3:3;
						uint16_t i:1;
						uint16_t imm4:4;
					};
					uint16_t word;
				};
				#pragma pack(pop)
				_mov* mov = (_mov*)dest32;
				int16_t addend = mov->imm8 | (mov->imm3 << 8) | (mov->i << (8 + 3)) | (mov->imm4 << (8 + 3 + 1));
				int64_t newTarget = target + addend;
				_target t;
				if (info.nativeType == R_ARM_THM_MOVW_ABS_NC) {
					// MOVW takes the lower 16-bit word
					t.word = (newTarget & 0xffff);
				}
				else // if (info.nativeType == R_ARM_THM_MOVT_ABS)
				{
					// MOVT takes the upper 16-bit word
					t.word = (newTarget >> 16) & 0xffff;
				}
				mov->imm8 = t.imm8;
				mov->imm3 = t.imm3;
				mov->imm4 = t.imm4;
				mov->i = t.i;
				break;
			}
			case R_ARM_TLS_DTPMOD32:
				/* Default to module index 0. */
				dest32[0] = 0;
				break;
			case R_ARM_TLS_DTPOFF32:
			{
				if (sym)
					dest32[0] = sym->GetAddress();
				break;
			}
			default:
				return RelocationHandler::ApplyRelocation(view, arch, reloc, dest, len);
		}
		return false;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc: result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			reloc.pcRelative = false;
			reloc.dataRelocation = IsELFDataRelocation((ElfArmRelocationType)reloc.nativeType);
			switch (reloc.nativeType)
			{
			case R_ARM_NONE:
				reloc.type = IgnoredRelocation;
				reloc.pcRelative = true;
				break;
			case R_ARM_PREL31:
			case R_ARM_RELATIVE:
				reloc.pcRelative = true;
				break;
			case R_ARM_ABS32:
			case R_ARM_BASE_PREL:
			case R_ARM_GOT_BREL:
				break;
			case R_ARM_CALL:
			case R_ARM_JUMP24:
			case R_ARM_THM_CALL:
			case R_ARM_THM_JUMP24:
				reloc.pcRelative = true;
				break;
			case R_ARM_COPY:
				reloc.type = ELFCopyRelocationType;
				break;
			case R_ARM_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				break;
			case R_ARM_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				break;
			case R_ARM_THM_MOVW_ABS_NC:
			case R_ARM_THM_MOVT_ABS:
			case R_ARM_MOVW_ABS_NC:
			case R_ARM_MOVT_ABS:
				break;
			case R_ARM_REL32:
				reloc.pcRelative = true;
				break;
			case R_ARM_IRELATIVE:
				reloc.baseRelative = true;
				reloc.type = ELFJumpSlotRelocationType;
				break;
			case R_ARM_TLS_DTPMOD32:
				 /* Prevent higher level behavior based on associated symbol
				    (we'll do that for the corresponding R_ARM_TLS_DTPOFF32). */
				reloc.symbolIndex = 0;
				break;
			case R_ARM_TLS_DTPOFF32:
				break;
			case R_ARM_SBREL31:
			case R_ARM_PC24:
			case R_ARM_LDR_PC_G0:
			case R_ARM_ABS16:
			case R_ARM_ABS12:
			case R_ARM_ABS8:
			case R_ARM_SBREL32:
			case R_ARM_BREL_ADJ:
			case R_ARM_TLS_DESC:
			case R_ARM_XPC25:
			case R_ARM_TLS_TPOFF32:
			case R_ARM_GOTOFF32:
			case R_ARM_PLT32:
			case R_ARM_BASE_ABS:
			case R_ARM_ALU_PCREL_7_0:
			case R_ARM_ALU_PCREL_15_8:
			case R_ARM_ALU_PCREL_23_15:
			case R_ARM_LDR_SBREL_11_0_NC:
			case R_ARM_ALU_SBREL_19_12_NC:
			case R_ARM_ALU_SBREL_27_20_CK:
			case R_ARM_TARGET1:
			case R_ARM_V4BX:
			case R_ARM_TARGET2:
			case R_ARM_MOVW_PREL_NC:
			case R_ARM_MOVT_PREL:
			case R_ARM_ABS32_NOI:
			case R_ARM_REL32_NOI:
			case R_ARM_ALU_PC_G0_NC:
			case R_ARM_ALU_PC_G0:
			case R_ARM_ALU_PC_G1_NC:
			case R_ARM_ALU_PC_G1:
			case R_ARM_ALU_PC_G2:
			case R_ARM_LDR_PC_G1:
			case R_ARM_LDR_PC_G2:
			case R_ARM_LDRS_PC_G0:
			case R_ARM_LDRS_PC_G1:
			case R_ARM_LDRS_PC_G2:
			case R_ARM_LDC_PC_G0:
			case R_ARM_LDC_PC_G1:
			case R_ARM_LDC_PC_G2:
			case R_ARM_ALU_SB_G0_NC:
			case R_ARM_ALU_SB_G0:
			case R_ARM_ALU_SB_G1_NC:
			case R_ARM_ALU_SB_G1:
			case R_ARM_ALU_SB_G2:
			case R_ARM_LDR_SB_G0:
			case R_ARM_LDR_SB_G1:
			case R_ARM_LDR_SB_G2:
			case R_ARM_LDRS_SB_G0:
			case R_ARM_LDRS_SB_G1:
			case R_ARM_LDRS_SB_G2:
			case R_ARM_LDC_SB_G0:
			case R_ARM_LDC_SB_G1:
			case R_ARM_LDC_SB_G2:
			case R_ARM_MOVW_BREL_NC:
			case R_ARM_MOVT_BREL:
			case R_ARM_MOVW_BREL:

			case R_ARM_THM_ABS5:
			case R_ARM_THM_PC8:
			case R_ARM_THM_SWI8:
			case R_ARM_THM_XPC22:
			case R_ARM_THM_MOVW_PREL_NC:
			case R_ARM_THM_MOVT_PREL:
			case R_ARM_THM_JUMP19:
			case R_ARM_THM_JUMP6:
			case R_ARM_THM_ALU_PREL_11_0:
			case R_ARM_THM_PC12:
			case R_ARM_THM_MOVW_BREL_NC:
			case R_ARM_THM_MOVT_BREL:
			case R_ARM_THM_MOVW_BREL:
			case R_ARM_THM_JUMP11:
			case R_ARM_THM_JUMP8:
			case R_ARM_THM_TLS_DESCSEQ16:
			case R_ARM_THM_TLS_DESCSEQ32:
			case R_ARM_THM_RPC22:

			case R_ARM_TLS_GOTDESC:
			case R_ARM_TLS_CALL:
			case R_ARM_TLS_DESCSEQ:
			case R_ARM_THM_TLS_CALL:
			case R_ARM_PLT32_ABS:
			case R_ARM_GOT_ABS:
			case R_ARM_GOT_PREL:
			case R_ARM_GOT_BREL12:
			case R_ARM_GOTOFF12:
			case R_ARM_GOTRELAX:
			case R_ARM_GNU_VTENTRY:
			case R_ARM_GNU_VTINHERIT:
			case R_ARM_TLS_GD32:
			case R_ARM_TLS_LDM32:
			case R_ARM_TLS_LDO32:
			case R_ARM_TLS_LE32:
			case R_ARM_TLS_LDO12:
			case R_ARM_TLS_LE12:
			case R_ARM_TLS_IE12GP:
			case R_ARM_ME_TOO:
			case R_ARM_RXPC25:
			case R_ARM_RSBREL32:
			case R_ARM_RREL32:
			case R_ARM_RABS32:
			case R_ARM_RPC24:
			case R_ARM_RBASE:
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation: %s", GetRelocationString((ElfArmRelocationType)reloc));
		return true;
	}
};


class ArmMachORelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc,
		uint8_t* dest, size_t len) override
	{
		auto info = reloc->GetInfo();
		if (info.nativeType == BINARYNINJA_MANUAL_RELOCATION)
		{  // Magic number defined in MachOView.cpp for tagged pointers
			*(uint32_t*)dest = (uint32_t)info.target;
		}

		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc: result)
		{
			reloc.type = UnhandledRelocation;
			relocTypes.insert(reloc.nativeType);
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported Mach-O relocation %s", GetRelocationString((MachoArmRelocationType)reloc));
		return false;
	};
};


class ArmPERelocationHandler: public RelocationHandler
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
		if (info.size == 8)
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
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc: result)
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
			default:
				// By default, PE relocations are correct when not rebased.
				// Upon rebasing, support would need to be added to correctly process the relocation
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported PE relocation %s", GetRelocationString((PeRelocationType)reloc));
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

class ArmCOFFRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		// Note: info.base contains preferred base address and the base where the image is actually loaded
		(void)view;
		(void)arch;
		(void)len;
		BNRelocationInfo info = reloc->GetInfo();
		uint64_t target = info.target;
		// uint64_t pc = info.pcRelative ? reloc->GetAddress() : 0;
		uint64_t base = info.base;
		if (! info.baseRelative)
			target -= base;
		uint64_t address = info.address;
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		// (void)pc;
		// (void)base;
		(void)dest16;

		Ref<Architecture> associatedArch = arch->GetAssociatedArchitectureByAddress(address);

#ifdef DEBUG_COFF
		DEBUG_COFF("COFF ARCH %s: arch: %s (%s @ %#" PRIx64 ") %s relocation at %#" PRIx64 " len: %zu info.size: %zu addend: %zu pc rel: %s base rel: %s target: %#" PRIx64 " base: %#" PRIx64,
				__func__,
				arch->GetName().c_str(),
				associatedArch ? associatedArch->GetName().c_str() : "<none>",
				info.address,
				GetRelocationString((PeArmRelocationType)info.nativeType),
				reloc->GetAddress(),
				len,
				info.size,
				info.addend,
				info.pcRelative ? "yes" : "no",
				info.baseRelative ? "yes" : "no",
				info.target,
				info.base
		);
#endif /* DEBUG_COFF */

		if (len < info.size)
		{
			return false;
		}

		//auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		switch (info.nativeType)
		{
		case PE_IMAGE_REL_THUMB_MOV32:
		{
			enum _mov_type : uint16_t
			{
				MOVW = 0b100100,
				MOVT = 0b101100,
			};
			#pragma pack(push,1)
			union _mov
			{
				uint32_t word;
				struct {
					uint32_t imm4:4;
					uint32_t bits_hi_4_6:3;
					uint32_t is_movt_flag:1;
					uint32_t bits_hi_8_9:2;
					uint32_t imm1:1;
					uint32_t bits_hi_11_15:5;

					uint32_t imm8:8;
					uint32_t rd:4;
					uint32_t imm3:3;
					uint32_t bit_lo_15:1;
				};
				struct {
					// MOVW
					// 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
					// 1  1  1  1  0  i  1 0 0 1 0 0 imm4    0  imm3     Rd        imm8
					// MOVT
					// 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
					// 1  1  1  1  0  i  1 0 1 1 0 0 imm4    0  imm3     Rd        imm8
					uint32_t _imm4:4;
					uint32_t group2_4:6; // MOVW: 0b100100 (0x24) MOVT: 0b101100 (0x2c)
					uint32_t _imm1:1;
					uint32_t group2_11:5;

					uint32_t _imm8:8;
					uint32_t _rd:4;
					uint32_t _imm3:3;
					uint32_t group1_15:1;
				};
			};
			struct _target
			{

				uint16_t imm8:8;
				uint16_t imm3:3;
				uint16_t imm1:1;
				uint16_t imm4:4;
			};
			#pragma pack(pop)
			_mov* movw = (_mov*)dest32;
			if (movw->is_movt_flag != 0) //movw->group2_4 != MOVW)
			{
				LogWarn("Expected MOVW in 0x%08" PRIx32 " (0x%" PRIx16 ") at 0x%" PRIx64 " but found 0x%" PRIx32 " (0x%" PRIx32 ") movt_flag: %d",
					movw->word, MOVW, address, movw->group2_4, *dest32, movw->is_movt_flag);
			}
			_mov* movt = (_mov*)dest32 + 1;
			if (movt->is_movt_flag != 1) // movt->group2_4 != MOVT)
			{
				LogWarn("Expected MOVT in 0x%08" PRIx32 " (0x%" PRIx16 ") at 0x%" PRIx64 " but found 0x%" PRIx32 " (0x%" PRIx32 ") movt_flag: %d",
					movt->word, MOVT, address + 4, movt->group2_4, *(dest32 + 1), movt->is_movt_flag);
			}

			_target *targetHiLo = (_target*)&target;

			// This could be done more efficiently with shifts, ands, and ors, but that's the compiler's job
			movw->imm8 = targetHiLo[0].imm8;
			movw->imm3 = targetHiLo[0].imm3;
			movw->imm1 = targetHiLo[0].imm1;
			movw->imm4 = targetHiLo[0].imm4;

			movt->imm8 = targetHiLo[1].imm8;
			movt->imm3 = targetHiLo[1].imm3;
			movt->imm1 = targetHiLo[1].imm1;
			movt->imm4 = targetHiLo[1].imm4;
#ifdef DEBUG_COFF
			DEBUG_COFF(
				"COFF arm %s: address: 0x%" PRIx64 " %s %s/%s target: 0x%" PRIx64
				", base: 0x%" PRIx64
				", addend: %zu",
				__func__,
				address,
				GetRelocationString((PeArmRelocationType) info.nativeType),
				movw->is_movt_flag ? "MOVT" : "MOVW",
				movt->is_movt_flag ? "MOVT" : "MOVW",
				target,
				info.base, info.addend
			);
#endif /* DEBUG_COFF */
			break;
		}
		case PE_IMAGE_REL_THUMB_BRANCH20:
		case PE_IMAGE_REL_THUMB_BRANCH24:
		case PE_IMAGE_REL_THUMB_BLX23:
		{
			// Adapted from R_ARM_THM_CALL & R_ARM_THM_JUMP24 cases of ArmElfRelocationHandler::ApplyRelocation
			// TODO: not portable
			//       ^^^^^^^^^^^^ I believe this is because the bit-field structs will break on big-endian hosts?
			#pragma pack(push, 1)
			// Unions cover all of b (Encoding T4), bl (Encoding T1), and blx (Encoding T2)
			// conditional b (Encoding T3) only uses the low 6 bits of offHi, upper 4 are cond
			union _thumb32_bl_hw1 {
				uint16_t word;
				union {
					struct {
						uint16_t offHi:10; // 21-12
						uint16_t sign:1; // 31-24
						uint16_t group:5;
					};
					struct {
						uint16_t offHi:6; // 17-12
						uint16_t cond:4;
						uint16_t sign:1; // 31-24
						uint16_t group:5;
					} b_cond;
				};
			};

			union _thumb32_bl_hw2 {
				uint16_t word;
				struct {
					uint16_t offLo:11; //b11-1 10-0
					uint16_t j2:1; //b12 11
					uint16_t not_blx:1; //b13 12
					uint16_t j1:1; //b14 13
					uint16_t branch_and_link:1; //b15 14 (i2)
					uint16_t i1:1; //b16 15
				};
				struct {
					uint16_t offLo:11; //b11-1 10-0
					uint16_t j2:1; //b12 11
					uint16_t not_conditional:1; //b13 12
					uint16_t j1:1; //b14 13
					uint16_t branch_and_link:1; //b15 14 (i2)
					uint16_t i1:1; //b16 15
				} b_cond;

			};
			#pragma pack(pop)

			_thumb32_bl_hw1* bl_hw1 = (_thumb32_bl_hw1*)dest16;
			_thumb32_bl_hw2* bl_hw2 = (_thumb32_bl_hw2*)(dest16 + 1);

#ifdef DEBUG_COFF
			uint32_t old_value = *dest32;
			uint16_t old_value1 = bl_hw1->word;
			uint16_t old_value2 = bl_hw2->word;
#endif /* DEBUG_COFF */

			int32_t curTarget = (bl_hw2->offLo << 1) | (bl_hw1->offHi << 12) | (bl_hw1->sign ? (0xffc << 20) : 0);
			int32_t newTarget = (int32_t)((target + (info.implicitAddend ? curTarget : info.addend)) - address);
			bl_hw1->sign = newTarget < 0 ? 1 : 0;

			if (!bl_hw2->branch_and_link && !bl_hw2->b_cond.not_conditional)
				// In practice, this probably makes no difference, but it is correct for conditional b instructions
				bl_hw1->b_cond.offHi = (newTarget >> 12) & ((1 << 6) - 1);
			else
				bl_hw1->offHi = (newTarget >> 12) & ((1 << 10) - 1);
			bl_hw2->offLo = (newTarget >> 1) & ((1 << 11) - 1);

#ifdef DEBUG_COFF
			bool is_conditional_branch = !bl_hw2->branch_and_link && !bl_hw2->b_cond.not_conditional;
			DEBUG_COFF(
					"COFF thumb2 %s: %sbranch%s, target: 0x%" PRIx64
					", curTarget: 0x%" PRIx32
					", newTarget: 0x%" PRIx32
					", actual new target: 0x%" PRIx32
					", address: 0x%" PRIx64
					", base: 0x%" PRIx64
					", old/new value: 0x%" PRIx32 "/0x%" PRIx32 ":0x%" PRIx16 " 0x%" PRIx16
					" sizeof(%zu %zu)"
					,
					__func__,
					is_conditional_branch ? "conditional " :
							bl_hw2->branch_and_link ? "linking " : "",
					(bl_hw2->branch_and_link && !bl_hw2->not_blx) ? " and exchange" : "",
					target, curTarget, newTarget,
					(uint32_t) ((uint32_t) address + newTarget),
					address, info.base, old_value, *dest32, old_value1, old_value2,
					sizeof(*bl_hw1), sizeof(*bl_hw2)
			);
#endif /* DEBUG_COFF */

			break;
		}
		case PE_IMAGE_REL_THUMB_UNUSED:
			break;

		case PE_IMAGE_REL_ARM_ABSOLUTE:
			break;
		case PE_IMAGE_REL_ARM_BRANCH11:
		case PE_IMAGE_REL_ARM_BLX11:
			// obsolete: only < ARMv7
			break;
		case PE_IMAGE_REL_ARM_BRANCH24:
		case PE_IMAGE_REL_ARM_BLX24:
		{
			struct _arm_b_bl_blx {
				union {
					uint32_t word;
					struct {
						uint32_t imm24:24;
						uint32_t bit_24_blx_H:1;
						uint32_t bits_25_27:3;
						uint32_t cond:4;
					};
				};
			};
			union _target {
				int32_t word;
				struct {
					uint32_t lo_bit:1;
					uint32_t H_bit:1;
					uint32_t imm24:24;
					uint32_t unused:6;
				};
			};

			_arm_b_bl_blx* bl = (_arm_b_bl_blx*)dest;
			int32_t curTarget = bl->imm24 << 2;

			if (bl->cond == 0xf)
			{
				// BLX is unconditional, and incorporates one more bit into the target address,
				// to allow for 2-byte aligned thumb target offsets.
				// TODO: determine whether the target address should have its low bit set after relocation
				curTarget |= bl->bit_24_blx_H << 1;
			}

			_target newTarget;
			newTarget.word = (int32_t)((target + (info.implicitAddend ? curTarget : info.addend)) - address);
			bl->imm24 = newTarget.imm24;
			if (bl->cond == 0xf)
			{
				bl->bit_24_blx_H = newTarget.H_bit;
			}
#ifdef DEBUG_COFF
			bool is_conditional_branch = bl->cond != 0xff;
			DEBUG_COFF(
				"COFF arm %s: address: 0x%" PRIx64 " %s %sbranch, target: 0x%" PRIx64
				", curTarget: 0x%" PRIx32
				", newTarget: 0x%" PRIx32
				", actual new target: 0x%" PRIx32
				", base: 0x%" PRIx64
				", addend: %zu",
				__func__,
				address,
				GetRelocationString((PeArmRelocationType) info.nativeType),
				is_conditional_branch ? "conditional " : "",
				target, curTarget, newTarget.word,
				(uint32_t) ((uint32_t) address + newTarget.word),
				info.base, info.addend
			);
#endif /* DEBUG_COFF */
			break;
		}
		case PE_IMAGE_REL_ARM_MOV32:
		{
			#pragma pack(push,1)
			union _mov
			{
				uint32_t word;
				struct {
					// MOVW
					// 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
					// cond        0  0  1  1  0  0  0  0  imm4        Rd          imm12
					// MOVT
					// 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
					// cond        0  0  1  1  0  1  0  0  imm4        Rd          imm12
					uint32_t imm12:12;
					uint32_t rd:4;
					uint32_t imm4:4;
					uint32_t bits_20_21:2;
					uint32_t is_movt_flag:1;
					uint32_t bit_23:1;
					uint32_t bits_24_27:4;
					uint32_t cond:4;

				};
			};
			struct _target
			{
				uint16_t imm12:12;
				uint16_t imm4:4;
			};
			#pragma pack(pop)

			_mov* mov = (_mov*)dest32;
			int32_t newTarget = (target + (info.implicitAddend ? (mov->imm4 << 12 | mov->imm12) : info.addend));
			_target *targetHiLo = (_target*)&newTarget;

			mov->imm12 = targetHiLo[mov->is_movt_flag].imm12;
			mov->imm4 = targetHiLo[mov->is_movt_flag].imm4;
			break;
		}
		case PE_IMAGE_REL_ARM_PAIR:
			// TODO
			break;
		case PE_IMAGE_REL_ARM_SECTION:
			// dest16[0] = info.sectionIndex + 1;
			break;
		case PE_IMAGE_REL_ARM_SECREL:
		{
			// auto sections = view->GetSectionsAt(info.target);
			// if (sections.size() > 0)
			// {
			// 	dest32[0] = info.target - sections[0]->GetStart();
			// }
			break;
		}
		case PE_IMAGE_REL_ARM_ADDR32:
		case PE_IMAGE_REL_ARM_ADDR32NB:
		default:
			return RelocationHandler::ApplyRelocation(view, arch, reloc, dest, len);
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc: result)
		{
#ifdef DEBUG_COFF
			DEBUG_COFF("COFF %s relocation %s at 0x%" PRIx64, __func__, GetRelocationString((PeArmRelocationType)reloc.nativeType), reloc.address);
#endif
			switch (reloc.nativeType)
			{
			case PE_IMAGE_REL_ARM_BRANCH24:
			case PE_IMAGE_REL_ARM_BRANCH11:
			case PE_IMAGE_REL_ARM_BLX24:
			case PE_IMAGE_REL_ARM_BLX11:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = -8;
				break;
			case PE_IMAGE_REL_THUMB_BRANCH20:
			case PE_IMAGE_REL_THUMB_BRANCH24:
			case PE_IMAGE_REL_THUMB_BLX23:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = -4;
				break;
			case PE_IMAGE_REL_THUMB_MOV32:
			case PE_IMAGE_REL_ARM_MOV32:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.size = 4;
				break;
			case PE_IMAGE_REL_ARM_ABSOLUTE:
				reloc.type = IgnoredRelocation;
				break;
			case PE_IMAGE_REL_ARM_ADDR32:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.size = 4;
				reloc.addend = 0;
				break;
			case PE_IMAGE_REL_ARM_ADDR32NB:	// TODO: CHECK NB case
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = 0;
				break;
			case PE_IMAGE_REL_ARM_REL32:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = -4;
				break;
			case PE_IMAGE_REL_ARM_SECTION:
				// The 16-bit section index of the section that contains the target. This is used to support debugging information.
				// TODO: is the section index 0-based or 1-based?
				reloc.baseRelative = false;
				reloc.size = 2;
				reloc.addend = 0;
				break;
			case PE_IMAGE_REL_ARM_SECREL:
				// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.				reloc.baseRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = 0;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported COFF relocation %s", GetRelocationString((PeArmRelocationType)reloc));
		return true;
	}
};


static void RegisterArmArchitecture(const char* armName, const char* thumbName, BNEndianness endian)
{
	ArmCommonArchitecture* armv7 = new Armv7Architecture(armName, endian);
	ArmCommonArchitecture* thumb2 = InitThumb2Architecture(thumbName, endian);
	armv7->SetArmAndThumbArchitectures(armv7, thumb2);
	thumb2->SetArmAndThumbArchitectures(armv7, thumb2);

	Architecture::Register(armv7);
	Architecture::Register(thumb2);

	// Register calling convention
	Ref<CallingConvention> conv;
	conv = new ArmCallingConvention(armv7);
	armv7->RegisterCallingConvention(conv);
	armv7->SetDefaultCallingConvention(conv);
	armv7->SetCdeclCallingConvention(conv);
	armv7->SetFastcallCallingConvention(conv);
	armv7->SetStdcallCallingConvention(conv);

	conv = new LinuxArmv7SystemCallConvention(armv7);
	armv7->RegisterCallingConvention(conv);

	conv = new ArmCallingConvention(thumb2);
	thumb2->RegisterCallingConvention(conv);
	thumb2->SetDefaultCallingConvention(conv);
	thumb2->SetCdeclCallingConvention(conv);
	thumb2->SetFastcallCallingConvention(conv);
	thumb2->SetStdcallCallingConvention(conv);

	conv = new LinuxArmv7SystemCallConvention(thumb2);
	thumb2->RegisterCallingConvention(conv);

	thumb2->RegisterFunctionRecognizer(new Thumb2ImportedFunctionRecognizer());

	// Register the architectures with the binary format parsers so that they know when to use
	// these architectures for disassembling an executable file
	BinaryViewType::RegisterArchitecture("Mach-O", 0xc, endian, armv7);
	BinaryViewType::RegisterArchitecture("ELF", 0x28, endian, armv7);
	BinaryViewType::RegisterArchitecture("COFF", 0x1c0, endian, armv7); // ARM
	BinaryViewType::RegisterArchitecture("COFF", 0x1c2, endian, thumb2); // THUMB
	BinaryViewType::RegisterArchitecture("COFF", 0x1c4, endian, thumb2); // ARMNT (ARM Thumb-2)
	BinaryViewType::RegisterArchitecture("PE", 0x1c0, endian, armv7); // ARM
	BinaryViewType::RegisterArchitecture("PE", 0x1c2, endian, armv7); // THUMB
	BinaryViewType::RegisterArchitecture("PE", 0x1c4, endian, armv7); // ARMv7

	armv7->RegisterRelocationHandler("ELF", new ArmElfRelocationHandler());
	armv7->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
	armv7->RegisterRelocationHandler("PE", new ArmPERelocationHandler());
	armv7->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());

	thumb2->RegisterRelocationHandler("ELF", new ArmElfRelocationHandler());
	thumb2->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
	thumb2->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());

	armv7->GetStandalonePlatform()->AddRelatedPlatform(thumb2, thumb2->GetStandalonePlatform());
	thumb2->GetStandalonePlatform()->AddRelatedPlatform(armv7, armv7->GetStandalonePlatform());
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
	bool ARMv7PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		RegisterArmArchitecture("armv7", "thumb2", LittleEndian);
		RegisterArmArchitecture("armv7eb", "thumb2eb", BigEndian);
		return true;
	}
}

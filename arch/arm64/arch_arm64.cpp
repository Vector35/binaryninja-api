#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <cstdint>
#include <inttypes.h>
#include <map>
#include <array>
#include <stdio.h>
#include <string.h>

#include "arm64dis.h"
#include "binaryninjaapi.h"
#include "il.h"
#include "lowlevelilinstruction.h"
#include "neon_intrinsics.h"

using namespace BinaryNinja;
using namespace std;

#if defined(_MSC_VER)
	#define snprintf _snprintf
#endif

#define EMPTY(S) (S[0] == '\0')

#define BINARYNINJA_MANUAL_RELOCATION ((uint64_t)-2)

enum MachoArm64RelocationType : uint32_t
{
	ARM64_RELOC_UNSIGNED = 0,
	ARM64_RELOC_SUBTRACTOR = 1,
	ARM64_RELOC_BRANCH26 = 2,
	ARM64_RELOC_PAGE21 = 3,
	ARM64_RELOC_PAGEOFF12 = 4,
	ARM64_RELOC_GOT_LOAD_PAGE21 = 5,
	ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6,
	ARM64_RELOC_POINTER_TO_GOT = 7,
	ARM64_RELOC_TLVP_LOAD_PAGE21 = 8,
	ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9,
	ARM64_RELOC_ADDEND = 10,
	MACHO_MAX_ARM64_RELOCATION = 11
};

enum ElfArm64RelocationType : uint32_t
{
	R_ARM_NONE                    = 0,
	R_AARCH64_P32_COPY            = 180,
	R_AARCH64_P32_GLOB_DAT        = 181,
	R_AARCH64_P32_JUMP_SLOT       = 182,
	R_AARCH64_P32_RELATIVE        = 183,
	R_AARCH64_NONE                = 256,
	// Data
	R_AARCH64_ABS64 = 257,
	R_AARCH64_ABS32 = 258,
	R_AARCH64_ABS16 = 259,
	R_AARCH64_PREL64 = 260,
	R_AARCH64_PREL32 = 261,
	R_AARCH64_PREL16 = 262,
	// Instructions
	R_AARCH64_MOVW_UABS_G0 = 263,
	R_AARCH64_MOVW_UABS_G0_NC = 264,
	R_AARCH64_MOVW_UABS_G1 = 265,
	R_AARCH64_MOVW_UABS_G1_NC = 266,
	R_AARCH64_MOVW_UABS_G2 = 267,
	R_AARCH64_MOVW_UABS_G2_NC = 268,
	R_AARCH64_MOVW_UABS_G3 = 269,
	R_AARCH64_MOVW_SABS_G0 = 270,
	R_AARCH64_MOVW_SABS_G1 = 271,
	R_AARCH64_MOVW_SABS_G2 = 272,
	R_AARCH64_LD_PREL_LO19 = 273,
	R_AARCH64_ADR_PREL_LO21 = 274,
	R_AARCH64_ADR_PREL_PG_HI21 = 275,
	R_AARCH64_ADR_PREL_PG_HI21_NC = 276,
	R_AARCH64_ADD_ABS_LO12_NC = 277,
	R_AARCH64_LDST8_ABS_LO12_NC = 278,
	R_AARCH64_TSTBR14 = 279,
	R_AARCH64_CONDBR19 = 280,
	R_AARCH64_JUMP26 = 282,
	R_AARCH64_CALL26 = 283,
	R_AARCH64_LDST16_ABS_LO12_NC = 284,
	R_AARCH64_LDST32_ABS_LO12_NC = 285,
	R_AARCH64_LDST64_ABS_LO12_NC = 286,
	R_AARCH64_LDST128_ABS_LO12_NC = 299,
	R_AARCH64_MOVW_PREL_G0 = 287,
	R_AARCH64_MOVW_PREL_G0_NC = 288,
	R_AARCH64_MOVW_PREL_G1 = 289,
	R_AARCH64_MOVW_PREL_G1_NC = 290,
	R_AARCH64_MOVW_PREL_G2 = 291,
	R_AARCH64_MOVW_PREL_G2_NC = 292,
	R_AARCH64_MOVW_PREL_G3 = 293,
	R_AARCH64_MOVW_GOTOFF_G0 = 300,
	R_AARCH64_MOVW_GOTOFF_G0_NC = 301,
	R_AARCH64_MOVW_GOTOFF_G1 = 302,
	R_AARCH64_MOVW_GOTOFF_G1_NC = 303,
	R_AARCH64_MOVW_GOTOFF_G2 = 304,
	R_AARCH64_MOVW_GOTOFF_G2_NC = 305,
	R_AARCH64_MOVW_GOTOFF_G3 = 306,
	R_AARCH64_GOTREL64 = 307,
	R_AARCH64_GOTREL32 = 308,
	R_AARCH64_GOT_LD_PREL19 = 309,
	R_AARCH64_LD64_GOTOFF_LO15 = 310,
	R_AARCH64_ADR_GOT_PAGE = 311,
	R_AARCH64_LD64_GOT_LO12_NC = 312,
	R_AARCH64_LD64_GOTPAGE_LO15 = 313,

	R_AARCH64_COPY = 1024,
	R_AARCH64_GLOB_DAT = 1025,   // Create GOT entry.
	R_AARCH64_JUMP_SLOT = 1026,  // Create PLT entry.
	R_AARCH64_RELATIVE = 1027,   // Adjust by program base.
	R_AARCH64_TLS_DTPREL64 = 1028,
	R_AARCH64_TLS_DTPMOD64 = 1029,
	R_AARCH64_TLS_TPREL64 = 1030,
	R_AARCH64_TLS_DTPREL32 = 1031,
	R_AARCH64_TLSDESC = 1031,
	R_AARCH64_IRELATIVE = 1032,
};

enum PeArm64RelocationType : uint32_t
{
	PE_IMAGE_REL_ARM64_ABSOLUTE       = 0x0000, //	The relocation is ignored.
	PE_IMAGE_REL_ARM64_ADDR32         = 0x0001, //	The 32-bit VA of the target.
	PE_IMAGE_REL_ARM64_ADDR32NB       = 0x0002, //	The 32-bit RVA of the target.
	PE_IMAGE_REL_ARM64_BRANCH26       = 0x0003, //	The 26-bit relative displacement to the target, for B and BL instructions. 
	PE_IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004, //	The page base of the target, for ADRP instruction.
	PE_IMAGE_REL_ARM64_REL21          = 0x0005, //	The 12-bit relative displacement to the target, for instruction ADR
	PE_IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006, //	The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007, //	The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
	PE_IMAGE_REL_ARM64_SECREL         = 0x0008, //	The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	PE_IMAGE_REL_ARM64_SECREL_LOW12A  = 0x0009, //	Bit 0:11 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A, //	Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_SECREL_LOW12L  = 0x000B, //	Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
	PE_IMAGE_REL_ARM64_TOKEN          = 0x000C, //	CLR token.
	PE_IMAGE_REL_ARM64_SECTION        = 0x000D, //	The 16-bit section index of the section that contains the target. This is used to support debugging information.
	PE_IMAGE_REL_ARM64_ADDR64         = 0x000E, //	The 64-bit VA of the relocation target.
	PE_IMAGE_REL_ARM64_BRANCH19       = 0x000F, //	The 19-bit offset to the relocation target, for conditional B instruction.
	PE_IMAGE_REL_ARM64_BRANCH14       = 0x0010, //	The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
	IMAGE_REL_ARM64_REL32             = 0x0011, //	The 32-bit relative address from the byte following the relocation.
	MAX_PE_ARM64_RELOCATION           = 0x0012
};

static const char* GetRelocationString(MachoArm64RelocationType rel)
{
	static const char* relocTable[] = {"ARM64_RELOC_UNSIGNED", "ARM64_RELOC_SUBTRACTOR",
	    "ARM64_RELOC_BRANCH26", "ARM64_RELOC_PAGE21", "ARM64_RELOC_PAGEOFF12",
	    "ARM64_RELOC_GOT_LOAD_PAGE21", "ARM64_RELOC_GOT_LOAD_PAGEOFF12", "ARM64_RELOC_POINTER_TO_GOT",
	    "ARM64_RELOC_TLVP_LOAD_PAGE21", "ARM64_RELOC_TLVP_LOAD_PAGEOFF12", "ARM64_RELOC_ADDEND"};
	if (rel < MACHO_MAX_ARM64_RELOCATION)
	{
		return relocTable[rel];
	}
	return "Unknown Aarch64 relocation";
}


static const char* GetRelocationString(PeArm64RelocationType rel)
{
	static const char* relocTable[] = {
		"IMAGE_REL_ARM64_ABSOLUTE",
		"IMAGE_REL_ARM64_ADDR32",
		"IMAGE_REL_ARM64_ADDR32NB",
		"IMAGE_REL_ARM64_BRANCH26",
		"IMAGE_REL_ARM64_PAGEBASE_REL21",
		"IMAGE_REL_ARM64_REL21",
		"IMAGE_REL_ARM64_PAGEOFFSET_12A",
		"IMAGE_REL_ARM64_PAGEOFFSET_12L",
		"IMAGE_REL_ARM64_SECREL",
		"IMAGE_REL_ARM64_SECREL_LOW12A",
		"IMAGE_REL_ARM64_SECREL_HIGH12A",
		"IMAGE_REL_ARM64_SECREL_LOW12L",
		"IMAGE_REL_ARM64_TOKEN",
		"IMAGE_REL_ARM64_SECTION",
		"IMAGE_REL_ARM64_ADDR64",
		"IMAGE_REL_ARM64_BRANCH19",
		"IMAGE_REL_ARM64_BRANCH14",
		"IMAGE_REL_ARM64_REL32"
	};

	if (rel < MAX_PE_ARM64_RELOCATION)
	{
		return relocTable[rel];
	}
	return "Unknown Aarch64 relocation";
}


static const char* GetRelocationString(ElfArm64RelocationType rel)
{
	static map<ElfArm64RelocationType, const char*> relocMap = {
		{R_ARM_NONE,                    "R_ARM_NONE"},
		{R_AARCH64_P32_COPY,            "R_AARCH64_P32_COPY"},
		{R_AARCH64_P32_GLOB_DAT,        "R_AARCH64_P32_GLOB_DAT"},
		{R_AARCH64_P32_JUMP_SLOT,       "R_AARCH64_P32_JUMP_SLOT"},
		{R_AARCH64_P32_RELATIVE,        "R_AARCH64_P32_RELATIVE"},
		{R_AARCH64_NONE,                "R_AARCH64_NONE"},
		{R_AARCH64_ABS64,               "R_AARCH64_ABS64"},
		{R_AARCH64_ABS32,               "R_AARCH64_ABS32"},
		{R_AARCH64_ABS16,               "R_AARCH64_ABS16"},
		{R_AARCH64_PREL64,              "R_AARCH64_PREL64"},
		{R_AARCH64_PREL32,              "R_AARCH64_PREL32"},
		{R_AARCH64_PREL16,              "R_AARCH64_PREL16"},
		{R_AARCH64_MOVW_UABS_G0,        "R_AARCH64_MOVW_UABS_G0"},
		{R_AARCH64_MOVW_UABS_G0_NC,     "R_AARCH64_MOVW_UABS_G0_NC"},
		{R_AARCH64_MOVW_UABS_G1,        "R_AARCH64_MOVW_UABS_G1"},
		{R_AARCH64_MOVW_UABS_G1_NC,     "R_AARCH64_MOVW_UABS_G1_NC"},
		{R_AARCH64_MOVW_UABS_G2,        "R_AARCH64_MOVW_UABS_G2"},
		{R_AARCH64_MOVW_UABS_G2_NC,     "R_AARCH64_MOVW_UABS_G2_NC"},
		{R_AARCH64_MOVW_UABS_G3,        "R_AARCH64_MOVW_UABS_G3"},
		{R_AARCH64_MOVW_SABS_G0,        "R_AARCH64_MOVW_SABS_G0"},
		{R_AARCH64_MOVW_SABS_G1,        "R_AARCH64_MOVW_SABS_G1"},
		{R_AARCH64_MOVW_SABS_G2,        "R_AARCH64_MOVW_SABS_G2"},
		{R_AARCH64_LD_PREL_LO19,        "R_AARCH64_LD_PREL_LO19"},
		{R_AARCH64_ADR_PREL_LO21,       "R_AARCH64_ADR_PREL_LO21"},
		{R_AARCH64_ADR_PREL_PG_HI21,    "R_AARCH64_ADR_PREL_PG_HI21"},
		{R_AARCH64_ADR_PREL_PG_HI21_NC, "R_AARCH64_ADR_PREL_PG_HI21_NC"},
		{R_AARCH64_ADD_ABS_LO12_NC,     "R_AARCH64_ADD_ABS_LO12_NC"},
		{R_AARCH64_LDST8_ABS_LO12_NC,   "R_AARCH64_LDST8_ABS_LO12_NC"},
		{R_AARCH64_TSTBR14,             "R_AARCH64_TSTBR14"},
		{R_AARCH64_CONDBR19,            "R_AARCH64_CONDBR19"},
		{R_AARCH64_JUMP26,              "R_AARCH64_JUMP26"},
		{R_AARCH64_CALL26,              "R_AARCH64_CALL26"},
		{R_AARCH64_LDST16_ABS_LO12_NC,  "R_AARCH64_LDST16_ABS_LO12_NC"},
		{R_AARCH64_LDST32_ABS_LO12_NC,  "R_AARCH64_LDST32_ABS_LO12_NC"},
		{R_AARCH64_LDST64_ABS_LO12_NC,  "R_AARCH64_LDST64_ABS_LO12_NC"},
		{R_AARCH64_LDST128_ABS_LO12_NC, "R_AARCH64_LDST128_ABS_LO12_NC"},
		{R_AARCH64_MOVW_PREL_G0,        "R_AARCH64_MOVW_PREL_G0"},
		{R_AARCH64_MOVW_PREL_G0_NC,     "R_AARCH64_MOVW_PREL_G0_NC"},
		{R_AARCH64_MOVW_PREL_G1,        "R_AARCH64_MOVW_PREL_G1"},
		{R_AARCH64_MOVW_PREL_G1_NC,     "R_AARCH64_MOVW_PREL_G1_NC"},
		{R_AARCH64_MOVW_PREL_G2,        "R_AARCH64_MOVW_PREL_G2"},
		{R_AARCH64_MOVW_PREL_G2_NC,     "R_AARCH64_MOVW_PREL_G2_NC"},
		{R_AARCH64_MOVW_PREL_G3,        "R_AARCH64_MOVW_PREL_G3"},
		{R_AARCH64_MOVW_GOTOFF_G0,      "R_AARCH64_MOVW_GOTOFF_G0"},
		{R_AARCH64_MOVW_GOTOFF_G0_NC,   "R_AARCH64_MOVW_GOTOFF_G0_NC"},
		{R_AARCH64_MOVW_GOTOFF_G1,      "R_AARCH64_MOVW_GOTOFF_G1"},
		{R_AARCH64_MOVW_GOTOFF_G1_NC,   "R_AARCH64_MOVW_GOTOFF_G1_NC"},
		{R_AARCH64_MOVW_GOTOFF_G2,      "R_AARCH64_MOVW_GOTOFF_G2"},
		{R_AARCH64_MOVW_GOTOFF_G2_NC,   "R_AARCH64_MOVW_GOTOFF_G2_NC"},
		{R_AARCH64_MOVW_GOTOFF_G3,      "R_AARCH64_MOVW_GOTOFF_G3"},
		{R_AARCH64_GOTREL64,            "R_AARCH64_GOTREL64"},
		{R_AARCH64_GOTREL32,            "R_AARCH64_GOTREL32"},
		{R_AARCH64_GOT_LD_PREL19,       "R_AARCH64_GOT_LD_PREL19"},
		{R_AARCH64_LD64_GOTOFF_LO15,    "R_AARCH64_LD64_GOTOFF_LO15"},
		{R_AARCH64_ADR_GOT_PAGE,        "R_AARCH64_ADR_GOT_PAGE"},
		{R_AARCH64_LD64_GOT_LO12_NC,    "R_AARCH64_LD64_GOT_LO12_NC"},
		{R_AARCH64_LD64_GOTPAGE_LO15,   "R_AARCH64_LD64_GOTPAGE_LO15"},
		{R_AARCH64_COPY,                "R_AARCH64_COPY"},
		{R_AARCH64_GLOB_DAT,            "R_AARCH64_GLOB_DAT"},
		{R_AARCH64_JUMP_SLOT,           "R_AARCH64_JUMP_SLOT"},
		{R_AARCH64_RELATIVE,            "R_AARCH64_RELATIVE"},
		{R_AARCH64_TLS_DTPREL64,        "R_AARCH64_TLS_DTPREL64"},
		{R_AARCH64_TLS_DTPMOD64,        "R_AARCH64_TLS_DTPMOD64"},
		{R_AARCH64_TLS_TPREL64,         "R_AARCH64_TLS_TPREL64"},
		{R_AARCH64_TLS_DTPREL32,        "R_AARCH64_TLS_DTPREL32"},
		{R_AARCH64_IRELATIVE,           "R_AARCH64_IRELATIVE"}
	};

	if (relocMap.count(rel))
		return relocMap.at(rel);

	return "Unknown Aarch64 relocation";
}


class Arm64Architecture : public Architecture
{
 protected:
	size_t m_bits;
	bool m_onlyDisassembleOnAlignedAddresses;

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result)
	{
		(void)addr;
		(void)maxLen;
		memset(&result, 0, sizeof(result));

		if (m_onlyDisassembleOnAlignedAddresses && (addr % 4 != 0))
			return false;

		if (aarch64_decompose(*(uint32_t*)data, &result, addr) != 0)
			return false;
		return true;
	}


	virtual size_t GetAddressSize() const override { return 8; }


	virtual size_t GetInstructionAlignment() const override { return 4; }


	virtual size_t GetMaxInstructionLength() const override { return 4; }


	bool IsTestAndBranch(const Instruction& instr)
	{
		return instr.operation == ARM64_TBZ || instr.operation == ARM64_TBNZ;
	}


	bool IsCompareAndBranch(const Instruction& instr)
	{
		return instr.operation == ARM64_CBZ || instr.operation == ARM64_CBNZ;
	}


	bool IsConditionalBranch(const Instruction& instr)
	{
		switch (instr.operation)
		{
		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_B_AL:
		case ARM64_B_NV:
			return true;
		default:
			return false;
		}
	}


	bool IsConditionalJump(const Instruction& instr)
	{
		return IsConditionalBranch(instr) || IsTestAndBranch(instr) || IsCompareAndBranch(instr);
	}


	void SetInstructionInfoForInstruction(
	    uint64_t addr, const Instruction& instr, InstructionInfo& result)
	{
		result.length = 4;
		switch (instr.operation)
		{
		case ARM64_BL:
			if (instr.operands[0].operandClass == LABEL)
				result.AddBranch(CallDestination, instr.operands[0].immediate);
			break;

		case ARM64_B:
			if (instr.operands[0].operandClass == LABEL)
				result.AddBranch(UnconditionalBranch, instr.operands[0].immediate);
			else
				result.AddBranch(UnresolvedBranch);
			break;

		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_B_AL:
		case ARM64_B_NV:
			result.AddBranch(TrueBranch, instr.operands[0].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_TBZ:
		case ARM64_TBNZ:
			result.AddBranch(TrueBranch, instr.operands[2].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_CBZ:
		case ARM64_CBNZ:
			result.AddBranch(TrueBranch, instr.operands[1].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_BR:
		case ARM64_BRAA:
		case ARM64_BRAAZ:
		case ARM64_BRAB:
		case ARM64_BRABZ:
		case ARM64_DRPS:
			result.AddBranch(UnresolvedBranch);
			break;
		case ARM64_ERET:
		case ARM64_ERETAA:
		case ARM64_ERETAB:
		case ARM64_RET:
		case ARM64_RETAA:
		case ARM64_RETAB:
			result.AddBranch(FunctionReturn);
			break;
		case ARM64_SVC:
		case ARM64_HVC:
		case ARM64_SMC:
			result.AddBranch(SystemCall);
			break;
		case ARM64_UDF:
			result.AddBranch(ExceptionBranch);
			break;

		default:
			break;
		}
	}


	uint32_t tokenize_shift(
	    const InstructionOperand* __restrict operand, vector<InstructionTextToken>& result)
	{
		if (operand->shiftType != ShiftType_NONE)
		{
			const char* shiftStr = get_shift(operand->shiftType);
			if (shiftStr == NULL)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			result.emplace_back(TextToken, ", ");
			result.emplace_back(TextToken, shiftStr);
			if (operand->shiftValueUsed != 0)
			{
				char buf[64] = {0};
				snprintf(buf, sizeof(buf), "%#x", (uint32_t)operand->shiftValue);
				result.emplace_back(OperationToken, " #");
				result.emplace_back(IntegerToken, buf, operand->shiftValue);
			}
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_shifted_immediate(
	    const InstructionOperand* __restrict operand, vector<InstructionTextToken>& result)
	{
		char buf[64] = {0};
		const char* sign = "";
		if (operand == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;

		uint64_t imm = operand->immediate;
		if (operand->signedImm == 1 && ((int64_t)imm) < 0)
		{
			sign = "-";
			imm = -(int64_t)imm;
		}

		switch (operand->operandClass)
		{
		case FIMM32:
		{
			union
			{
				uint32_t intValue;
				float floatValue;
			} f;
			f.intValue = (uint32_t)operand->immediate;
			snprintf(buf, sizeof(buf), "%.08f", f.floatValue);
			result.emplace_back(OperationToken, "#");
			result.emplace_back(FloatingPointToken, buf);
			break;
		}
		case IMM32:
			snprintf(buf, sizeof(buf), "%s%#x", sign, (uint32_t)imm);
			result.emplace_back(OperationToken, "#");
			result.emplace_back(IntegerToken, buf, operand->immediate);
			break;
		case IMM64:
			snprintf(buf, sizeof(buf), "%s%#" PRIx64, sign, imm);
			result.emplace_back(OperationToken, "#");
			result.emplace_back(IntegerToken, buf, operand->immediate);
			break;
		case LABEL:
			snprintf(buf, sizeof(buf), "%#" PRIx64, operand->immediate);
			result.emplace_back(PossibleAddressToken, buf, operand->immediate);
			break;
		default:
			return FAILED_TO_DISASSEMBLE_OPERAND;
		}

		tokenize_shift(operand, result);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_shifted_register(const InstructionOperand* restrict operand,
	    uint32_t registerNumber, vector<InstructionTextToken>& result)
	{
		const char* reg = get_register_name(operand->reg[registerNumber]);
		if (EMPTY(reg))
			return FAILED_TO_DISASSEMBLE_REGISTER;

		result.emplace_back(RegisterToken, reg);
		tokenize_shift(operand, result);
		return DISASM_SUCCESS;
	}

	uint32_t tokenize_register(const InstructionOperand* restrict operand, uint32_t registerNumber,
	    vector<InstructionTextToken>& result)
	{
		char buf[64] = {0};

		/* case: system registers */
		if (operand->operandClass == SYS_REG)
		{
			snprintf(buf, sizeof(buf), "%s", get_system_register_name((SystemReg)operand->sysreg));
			result.emplace_back(RegisterToken, buf);
			return DISASM_SUCCESS;
		}

		if (operand->operandClass != REG && operand->operandClass != MULTI_REG)
			return OPERAND_IS_NOT_REGISTER;

		/* case: shifted registers */
		if (operand->shiftType != ShiftType_NONE)
		{
			return tokenize_shifted_register(operand, registerNumber, result);
		}

		const char* reg = get_register_name(operand->reg[registerNumber]);
		if (EMPTY(reg))
			return FAILED_TO_DISASSEMBLE_REGISTER;

		/* case: predicate registers */
		if (operand->pred_qual && operand->reg[registerNumber] >= REG_P0 &&
		    operand->reg[registerNumber] <= REG_P31)
		{
			result.emplace_back(RegisterToken, reg);
			result.emplace_back(TextToken, "/");
			result.emplace_back(TextToken, string(1, operand->pred_qual));
			return DISASM_SUCCESS;
		}

		/* case other regs */
		result.emplace_back(RegisterToken, reg);
		const char* arrspec = get_register_arrspec(operand->reg[registerNumber], operand);
		if (arrspec)
			result.emplace_back(TextToken, arrspec);

		/* only use index if this is isolated REG (not, for example, MULTIREG */
		if (operand->operandClass == REG && operand->laneUsed)
		{
			snprintf(buf, sizeof(buf), "%u", operand->lane);
			result.emplace_back(BraceToken, "[");
			result.emplace_back(IntegerToken, buf);
			result.emplace_back(BraceToken, "]");
		}

		return DISASM_SUCCESS;
	}


	uint32_t tokenize_memory_operand(
	    const InstructionOperand* restrict operand, vector<InstructionTextToken>& result)
	{
		char immBuff[32] = {0};
		char paramBuff[32] = {0};
		const char *reg0, *reg1;

		reg0 = get_register_name(operand->reg[0]);
		if (EMPTY(reg0))
			return FAILED_TO_DISASSEMBLE_REGISTER;

		const char* sign = "";
		int64_t imm = operand->immediate;
		if (operand->signedImm && (int64_t)imm < 0)
		{
			sign = "-";
			imm = -imm;
		}
		const char* startToken = "[";
		const char* endToken = "";
		result.emplace_back(BraceToken, startToken);
		result.emplace_back(BeginMemoryOperandToken, "");
		result.emplace_back(RegisterToken, reg0);
		result.emplace_back(TextToken, get_register_arrspec(operand->reg[0], operand));

		switch (operand->operandClass)
		{
		case MEM_REG:
			break;
		case MEM_PRE_IDX:
			endToken = "!";
			snprintf(immBuff, sizeof(immBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
			result.emplace_back(TextToken, ", ");
			result.emplace_back(OperationToken, "#");
			result.emplace_back(IntegerToken, immBuff, operand->immediate);
			break;
		case MEM_POST_IDX:  // [<reg>], <reg|imm>
			endToken = NULL;
			if (operand->reg[1] == REG_NONE)
			{
				snprintf(paramBuff, sizeof(paramBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(TextToken, ", ");
				result.emplace_back(OperationToken, "#");
				result.emplace_back(IntegerToken, paramBuff, operand->immediate);
			}
			else
			{
				reg1 = get_register_name(operand->reg[1]);
				if (EMPTY(reg1))
					return FAILED_TO_DISASSEMBLE_REGISTER;
				result.emplace_back(EndMemoryOperandToken, "");
				result.emplace_back(BraceToken, "]");
				result.emplace_back(TextToken, ", ");
				result.emplace_back(RegisterToken, reg1);
				result.emplace_back(TextToken, get_register_arrspec(operand->reg[1], operand));
			}
			break;
		case MEM_OFFSET:  // [<reg> optional(imm)]
			if (operand->immediate != 0)
			{
				snprintf(immBuff, sizeof(immBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
				result.emplace_back(TextToken, ", ");
				result.emplace_back(OperationToken, "#");
				result.emplace_back(IntegerToken, immBuff, operand->immediate);

				if (operand->mul_vl)
					result.emplace_back(TextToken, ", mul vl");
			}
			break;
		case MEM_EXTENDED:  // [<reg>, <reg> optional(shift optional(imm))]
			result.emplace_back(TextToken, ", ");
			reg1 = get_register_name(operand->reg[1]);
			if (EMPTY(reg1))
				return FAILED_TO_DISASSEMBLE_REGISTER;
			result.emplace_back(RegisterToken, reg1);
			result.emplace_back(TextToken, get_register_arrspec(operand->reg[1], operand));
			tokenize_shift(operand, result);
			break;
		default:
			return NOT_MEMORY_OPERAND;
		}
		if (endToken != NULL)
		{
			result.emplace_back(EndMemoryOperandToken, "");
			result.emplace_back(BraceToken, "]");
			result.emplace_back(TextToken, endToken);
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_multireg_operand(
	    const InstructionOperand* restrict operand, vector<InstructionTextToken>& result)
	{
		char index[32] = {0};
		uint32_t elementCount = 0;

		result.emplace_back(TextToken, "{");
		for (; elementCount < 4 && operand->reg[elementCount] != REG_NONE; elementCount++)
		{
			if (elementCount != 0)
				result.emplace_back(TextToken, ", ");

			if (tokenize_register(operand, elementCount, result) != 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
		}
		result.emplace_back(TextToken, "}");

		if (operand->laneUsed)
		{
			result.emplace_back(BraceToken, "[");
			snprintf(index, sizeof(index), "%d", operand->lane);
			result.emplace_back(IntegerToken, index, operand->lane);
			result.emplace_back(BraceToken, "]");
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_condition(
	    const InstructionOperand* restrict operand, vector<InstructionTextToken>& result)
	{
		const char* condStr = get_condition((Condition)operand->cond);
		if (condStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;

		result.emplace_back(TextToken, condStr);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_implementation_specific(
	    const InstructionOperand* restrict operand, vector<InstructionTextToken>& result)
	{
		char buf[32] = {0};
		get_implementation_specific(operand, buf, sizeof(buf));
		result.emplace_back(RegisterToken, buf);
		return DISASM_SUCCESS;
	}


	BNRegisterInfo RegisterInfo(
	    uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}


 public:
	Arm64Architecture() : Architecture("aarch64"), m_bits(64)
	{
		Ref<Settings> settings = Settings::Instance();
		m_onlyDisassembleOnAlignedAddresses = settings->Get<bool>("arch.aarch64.disassembly.alignRequired") ? 1 : 0;
	}

	bool CanAssemble() override { return true; }

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		(void)addr;

		int assembleResult;
		char *instrBytes = NULL, *err = NULL;
		int instrBytesLen = 0, errLen = 0;

		string prepend = ".arch_extension crc\n" ".arch_extension sm4\n"
			".arch_extension sha3\n" ".arch_extension sha2\n" ".arch_extension aes\n"
			".arch_extension crypto\n" ".arch_extension fp\n" ".arch_extension simd\n"
			".arch_extension ras\n" ".arch_extension lse\n" ".arch_extension predres\n"
			".arch_extension ccdp\n" ".arch_extension mte\n" ".arch_extension memtag\n"
			".arch_extension tlb-rmi\n" ".arch_extension pan\n" ".arch_extension pan-rwv\n"
			".arch_extension ccpp\n" ".arch_extension rcpc\n" ".arch_extension rng\n"
			".arch_extension sve\n" ".arch_extension sve2\n" ".arch_extension sve2-aes\n"
			".arch_extension sve2-sm4\n" ".arch_extension sve2-sha3\n" ".arch_extension sve2-bitperm\n"
			".arch_extension ls64\n" ".arch_extension xs\n" ".arch_extension pauth\n"
			".arch_extension flagm\n" ".arch_extension rme\n" ".arch_extension sme\n"
			".arch_extension sme-f64f64\n" ".arch_extension sme-i16i64\n" ".arch_extension hbc\n"
			".arch_extension mops\n";

		BNLlvmServicesInit();

		errors.clear();
		assembleResult =
		    BNLlvmServicesAssemble((prepend + code).c_str(), LLVM_SVCS_DIALECT_UNSPEC, "aarch64-none-none",
		        LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC, &instrBytes, &instrBytesLen, &err, &errLen);

		if (assembleResult || errLen)
		{
			errors = err;
			BNLlvmServicesAssembleFree(instrBytes, err);
			return false;
		}

		result.Clear();
		result.Append(instrBytes, instrBytesLen);
		BNLlvmServicesAssembleFree(instrBytes, err);
		return true;
	}

	virtual BNEndianness GetEndianness() const override { return LittleEndian; }


	virtual bool GetInstructionInfo(
	    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
		if (maxLen < 4)
			return false;

		Instruction instr;
		if (!Disassemble(data, addr, maxLen, instr))
			return false;

		SetInstructionInfoForInstruction(addr, instr, result);
		return true;
	}


	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
	    vector<InstructionTextToken>& result) override
	{
		len = 4;
		Instruction instr;
		bool tokenizeSuccess = false;
		char buf[9];
		if (!Disassemble(data, addr, len, instr))
			return false;

		memset(buf, 0x20, sizeof(buf));
		const char* operation = get_operation(&instr);
		if (operation == nullptr)
			return false;

		size_t operationLen = strlen(operation);
		if (operationLen < 8)
		{
			buf[8 - operationLen] = '\0';
		}
		else
			buf[1] = '\0';

		result.emplace_back(InstructionToken, operation);
		result.emplace_back(TextToken, buf);
		for (size_t i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].operandClass == NONE)
				return true;

			struct InstructionOperand *operand = &(instr.operands[i]);

			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");

			switch (instr.operands[i].operandClass)
			{
			case FIMM32:
			case IMM32:
			case IMM64:
			case LABEL:
				tokenizeSuccess = tokenize_shifted_immediate(&instr.operands[i], result) == 0;
				break;
			case MEM_REG:
			case MEM_PRE_IDX:
			case MEM_POST_IDX:
			case MEM_OFFSET:
			case MEM_EXTENDED:
				tokenizeSuccess = tokenize_memory_operand(&instr.operands[i], result) == 0;
				break;
			case REG:
			case SYS_REG:
				tokenizeSuccess = tokenize_register(&instr.operands[i], 0, result) == 0;
				break;
			case MULTI_REG:
				tokenizeSuccess = tokenize_multireg_operand(&instr.operands[i], result) == 0;
				break;
			case CONDITION:
				tokenizeSuccess = tokenize_condition(&instr.operands[i], result) == 0;
				break;
			case IMPLEMENTATION_SPECIFIC:
				tokenizeSuccess = tokenize_implementation_specific(&instr.operands[i], result) == 0;
				break;
			case NAME:
				result.emplace_back(TextToken, instr.operands[i].name);
				tokenizeSuccess = true;
				break;
			case STR_IMM: /* eg: "mul #0xe" */
				result.emplace_back(TextToken, instr.operands[i].name);
				result.emplace_back(OperationToken, " #");
				snprintf(buf, sizeof(buf), "0x%" PRIx64, instr.operands[i].immediate);
				result.emplace_back(IntegerToken, buf);
				tokenizeSuccess = true;
				break;
			case ACCUM_ARRAY: /* eg: "za[w12, #0x6]" */
				result.emplace_back(TextToken, "ZA");
				result.emplace_back(BraceToken, "[");
				snprintf(buf, sizeof(buf), "%s", get_register_name(operand->reg[0]));
				result.emplace_back(RegisterToken, buf);
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(OperationToken, " #");
				snprintf(buf, sizeof(buf), "0x%" PRIx64, operand->immediate);
				result.emplace_back(IntegerToken, buf);
				result.emplace_back(BraceToken, "]");
				tokenizeSuccess = true;
				break;
			case SME_TILE: /* eg: "z0v.b[w12, #0xb]" */
				snprintf(buf, sizeof(buf), "Z%d", operand->tile);
				result.emplace_back(TextToken, buf);
				if (operand->slice == SLICE_HORIZONTAL)
					result.emplace_back(TextToken, "h");
				else if (operand->slice == SLICE_VERTICAL)
					result.emplace_back(TextToken, "v");
				result.emplace_back(TextToken, get_arrspec_str_truncated(operand->arrSpec));
				if (operand->reg[0] != REG_NONE)
				{
					result.emplace_back(BraceToken, "[");
					snprintf(buf, sizeof(buf), "%s", get_register_name(operand->reg[0]));
					result.emplace_back(RegisterToken, buf);
					if (operand->arrSpec != ARRSPEC_FULL)
					{
						result.emplace_back(OperandSeparatorToken, ", ");
						result.emplace_back(OperationToken, " #");
						snprintf(buf, sizeof(buf), "0x%" PRIx64, instr.operands[i].immediate);
						result.emplace_back(IntegerToken, buf);
					}
					result.emplace_back(BraceToken, "]");
				}
				tokenizeSuccess = true;
				break;
			case INDEXED_ELEMENT: /* eg: "p12.d[w15, #0xf]" */
				result.emplace_back(RegisterToken, get_register_name(operand->reg[0]));
				result.emplace_back(TextToken, get_arrspec_str_truncated(operand->arrSpec));
				result.emplace_back(BraceToken, "[");
				result.emplace_back(RegisterToken, get_register_name(operand->reg[1]));
				if (operand->immediate)
				{
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(OperationToken, "#");
					snprintf(buf, sizeof(buf), "0x%" PRIx64, operand->immediate);
					result.emplace_back(IntegerToken, buf);
				}
				result.emplace_back(BraceToken, "]");
				tokenizeSuccess = true;
				break;
			default:
				LogError("operandClass %x\n", instr.operands[i].operandClass);
				return false;
			}
			if (!tokenizeSuccess)
			{
				LogError("tokenize failed operandClass %x\n", instr.operands[i].operandClass);
				return false;
			}
		}
		return true;
	}


	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_AUTDA:
			return "__autda";
		case ARM64_INTRIN_AUTDB:
			return "__autdb";
		case ARM64_INTRIN_AUTIA:
			return "__autia";
		case ARM64_INTRIN_AUTIB:
			return "__autib";
		case ARM64_INTRIN_ISB:
			return "__isb";
		case ARM64_INTRIN_WFE:
			return "__wfe";
		case ARM64_INTRIN_WFI:
			return "__wfi";
		case ARM64_INTRIN_MSR:
			return "_WriteStatusReg";
		case ARM64_INTRIN_MRS:
			return "_ReadStatusReg";
		case ARM64_INTRIN_HINT_DGH:
			return "SystemHintOp_DGH";
		case ARM64_INTRIN_ESB:
			return "SystemHintOp_ESB";
		case ARM64_INTRIN_PACDA:
			return "__pacda";
		case ARM64_INTRIN_PACDB:
			return "__pacdb";
		case ARM64_INTRIN_PACGA:
			return "__pacga";
		case ARM64_INTRIN_PACIA:
			return "__pacia";
		case ARM64_INTRIN_PACIB:
			return "__pacib";
		case ARM64_INTRIN_PSBCSYNC:
			return "SystemHintOp_PSB";
		case ARM64_INTRIN_HINT_TSB:
			return "SystemHintOp_TSB";
		case ARM64_INTRIN_HINT_CSDB:
			return "SystemHintOp_CSDB";
		case ARM64_INTRIN_HINT_BTI:
			return "SystemHintOp_BTI";
		case ARM64_INTRIN_SEV:
			return "__sev";
		case ARM64_INTRIN_SEVL:
			return "__sevl";
		case ARM64_INTRIN_DC:
			return "__dc";
		case ARM64_INTRIN_DMB:
			return "__dmb";
		case ARM64_INTRIN_DSB:
			return "__dsb";
		case ARM64_INTRIN_YIELD:
			return "__yield";
		case ARM64_INTRIN_PRFM:
			return "__prefetch";
		case ARM64_INTRIN_XPACD:
			return "__xpacd";
		case ARM64_INTRIN_XPACI:
			return "__xpaci";
		case ARM64_INTRIN_ERET:
			return "_eret";
		case ARM64_INTRIN_CLZ:
			return "_CountLeadingZeros";
		case ARM64_INTRIN_CLREX:
			return "__clrex";
		case ARM64_INTRIN_REV:
			return "_byteswap";
		case ARM64_INTRIN_RBIT:
			return "__rbit";
		case ARM64_INTRIN_AESD:
			return "__aesd";
		case ARM64_INTRIN_AESE:
			return "__aese";
		case ARM64_INTRIN_LDXR:
			return "__ldxr";
		case ARM64_INTRIN_LDXRB:
			return "__ldxrb";
		case ARM64_INTRIN_LDXRH:
			return "__ldxrh";
		case ARM64_INTRIN_LDAXR:
			return "__ldaxr";
		case ARM64_INTRIN_LDAXRB:
			return "__ldaxrb";
		case ARM64_INTRIN_LDAXRH:
			return "__ldaxrh";
		case ARM64_INTRIN_STXR:
			return "__stxr";
		case ARM64_INTRIN_STXRB:
			return "__stxrb";
		case ARM64_INTRIN_STXRH:
			return "__stxrh";
		case ARM64_INTRIN_STLXR:
			return "__stlxr";
		case ARM64_INTRIN_STLXRB:
			return "__stlxrb";
		case ARM64_INTRIN_STLXRH:
			return "__stlxrh";
		default:
			break;
		}

		return NeonGetIntrinsicName(intrinsic);
	}


	virtual std::vector<uint32_t> GetAllIntrinsics() override
	{
		// Highest intrinsic number currently is ARM64_INTRIN_NEON_END.
		// If new extensions are added please update this code.
		std::vector<uint32_t> result{ARM64_INTRIN_NEON_END};

		// Double check someone didn't insert a new intrinsic at the beginning of our enum since we rely
		// on it to fill the next array.
		static_assert(Arm64Intrinsic::ARM64_INTRIN_AUTDA == 0,
			"Invalid first Arm64Intrinsic value. Please add your intrinsic further in the enum.");
		
		// Normal intrinsics.
		for (uint32_t id = Arm64Intrinsic::ARM64_INTRIN_AUTDA; id < Arm64Intrinsic::ARM64_INTRIN_NORMAL_END; id++) {
			result.push_back(id);
		}

		// Finish populating our container with neon specific intrinsic IDs
		for (uint32_t id = NeonIntrinsic::ARM64_INTRIN_VADD_S8; id < NeonIntrinsic::ARM64_INTRIN_NEON_END; id++) {
			result.push_back(id);
		}

		return result;
	}


	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_CLZ:        // reads <Xn>
		case ARM64_INTRIN_DC:         // reads <Xt>
		case ARM64_INTRIN_MSR:
		case ARM64_INTRIN_MRS:
		case ARM64_INTRIN_PRFM:
		case ARM64_INTRIN_REV:   // reads <Xn>
		case ARM64_INTRIN_RBIT:  // reads <Xn>
			return {NameAndType(Type::IntegerType(8, false))};
		case ARM64_INTRIN_AUTDA:      // reads <Xd>, <Xn|SP>
		case ARM64_INTRIN_AUTDB:      // reads <Xd>, <Xn|SP>
		case ARM64_INTRIN_AUTIA:      // reads <Xd>, <Xn|SP>
		case ARM64_INTRIN_AUTIB:      // reads <Xd>, <Xn|SP>
		case ARM64_INTRIN_PACGA:      // reads <Xn>, <Xm|SP>
		case ARM64_INTRIN_PACDA:      // reads <Xd>, <Xn>
		case ARM64_INTRIN_PACDB:      // reads <Xd>, <Xn>
		case ARM64_INTRIN_PACIA:      // reads <Xd>, <Xn>
		case ARM64_INTRIN_PACIB:      // reads <Xd>, <Xn>
			return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false))};
		case ARM64_INTRIN_AESD:
		case ARM64_INTRIN_AESE:
			return {NameAndType(Type::IntegerType(16, false)), NameAndType(Type::IntegerType(16, false))};
		default:
			break;
		}

		return NeonGetIntrinsicInputs(intrinsic);
	}


	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_MSR:
		case ARM64_INTRIN_AUTDA:      // writes <Xd>
		case ARM64_INTRIN_AUTDB:      // writes <Xd>
		case ARM64_INTRIN_AUTIA:      // writes <Xd>
		case ARM64_INTRIN_AUTIB:      // writes <Xd>
		case ARM64_INTRIN_MRS:
		case ARM64_INTRIN_PACDA:      // writes <Xd>
		case ARM64_INTRIN_PACDB:      // writes <Xd>
		case ARM64_INTRIN_PACIA:      // writes <Xd>
		case ARM64_INTRIN_PACGA:      // writes <Xd>
		case ARM64_INTRIN_PACIB:      // writes <Xd>
		case ARM64_INTRIN_XPACD:      // writes <Xd>
		case ARM64_INTRIN_XPACI:      // writes <Xd>
		case ARM64_INTRIN_CLZ:        // writes <Xd>
		case ARM64_INTRIN_REV:        // writes <Xd>
		case ARM64_INTRIN_RBIT:       // writes <Xd>
			return {Type::IntegerType(8, false)};
		case ARM64_INTRIN_AESD:
		case ARM64_INTRIN_AESE:
			return {Type::IntegerType(16, false)};
		default:
			break;
		}

		return NeonGetIntrinsicOutputs(intrinsic);
	}


	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalBranch(instr);
	}


	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalBranch(instr);
	}


	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalJump(instr);
	}


	virtual bool IsSkipAndReturnZeroPatchAvailable(
	    const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return instr.operation == ARM64_BL || instr.operation == ARM64_BR ||
		       instr.operation == ARM64_BLR;
	}


	virtual bool IsSkipAndReturnValuePatchAvailable(
	    const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return instr.operation == ARM64_BL || instr.operation == ARM64_BR ||
		       instr.operation == ARM64_BLR;
	}


	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint32_t arm64_nop = 0xd503201f;
		if (len < sizeof(arm64_nop))
			return false;
		for (size_t i = 0; i < len / sizeof(arm64_nop); i++)
			((uint32_t*)data)[i] = arm64_nop;
		return true;
	}


	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		uint32_t* value = (uint32_t*)data;
		// Combine the immediate in the first operand with the unconditional branch opcode to form
		// an unconditional branch instruction
		*value = (5 << 26) | (uint32_t)((instr.operands[0].immediate - addr) >> 2);
		return true;
	}


	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		uint32_t* value = (uint32_t*)data;
		if (IsConditionalBranch(instr))
		{
			// The inverted branch is the inversion of the low order nibble
			*value ^= 1;
		}
		else if (IsTestAndBranch(instr) || IsCompareAndBranch(instr))
		{
			// invert bit 24
			*value ^= (1 << 24);
		}
		return true;
	}


	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)addr;
		// Return value is put in X0. The largest value that we can put into a single integer is 16 bits
		if (value > 0xffff || len > 4)
			return false;

		uint32_t movValueR0 = 0xd2800000;
		uint32_t* inst = (uint32_t*)data;
		*inst = movValueR0 | ((uint32_t)value << 5);
		return true;
	}


	virtual bool GetInstructionLowLevelIL(
	    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
		{
			il.AddInstruction(il.Undefined());
			return false;
		}

		len = 4;
		return GetLowLevelILForInstruction(this, addr, il, instr, GetAddressSize(), m_onlyDisassembleOnAlignedAddresses);
	}


	/* flags and their names */

	virtual vector<uint32_t> GetAllFlags() override
	{
		return vector<uint32_t> {IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V};
	}


	virtual string GetFlagName(uint32_t flag) override
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
		default:
			snprintf(result, sizeof(result), "flag%" PRIu32, flag);
			return result;
		}
	}

	virtual vector<uint32_t> GetAllSemanticFlagClasses() override
	{
		return vector<uint32_t> {IL_FLAG_CLASS_INT, IL_FLAG_CLASS_FLOAT};
	}

	virtual string GetSemanticFlagClassName(uint32_t semClass) override
	{
		switch (semClass) {
			case IL_FLAG_CLASS_INT:
				return "int";
			case IL_FLAG_CLASS_FLOAT:
				return "float";
			default:
				return "";
		}
	}

	virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override
	{
		switch (writeType) {
		case IL_FLAG_WRITE_ALL_FLOAT:
			return IL_FLAG_CLASS_FLOAT;
		case IL_FLAG_WRITE_ALL:
		default:
			return IL_FLAG_CLASS_INT;
		}
	}

	virtual vector<uint32_t> GetAllSemanticFlagGroups() override
	{

		return vector<uint32_t> {
			IL_FLAG_GROUP_EQ, IL_FLAG_GROUP_NE, IL_FLAG_GROUP_CS, IL_FLAG_GROUP_CC,
			IL_FLAG_GROUP_MI, IL_FLAG_GROUP_PL, IL_FLAG_GROUP_VS, IL_FLAG_GROUP_VC,
			IL_FLAG_GROUP_HI, IL_FLAG_GROUP_LS, IL_FLAG_GROUP_GE, IL_FLAG_GROUP_LT,
			IL_FLAG_GROUP_GT, IL_FLAG_GROUP_LE};
	}

	virtual string GetSemanticFlagGroupName(uint32_t semGroup) override
	{
		switch (semGroup)
		{
		case IL_FLAG_GROUP_EQ:
			return "eq";
		case IL_FLAG_GROUP_NE:
			return "ne";
		case IL_FLAG_GROUP_CS:
			return "cs";
		case IL_FLAG_GROUP_CC:
			return "cc";
		case IL_FLAG_GROUP_MI:
			return "mi";
		case IL_FLAG_GROUP_PL:
			return "pl";
		case IL_FLAG_GROUP_VS:
			return "vs";
		case IL_FLAG_GROUP_VC:
			return "vc";
		case IL_FLAG_GROUP_HI:
			return "hi";
		case IL_FLAG_GROUP_LS:
			return "ls";
		case IL_FLAG_GROUP_GE:
			return "ge";
		case IL_FLAG_GROUP_LT:
			return "lt";
		case IL_FLAG_GROUP_GT:
			return "gt";
		case IL_FLAG_GROUP_LE:
			return "le";
		default:
			return "";
		}
	}

	virtual vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override
	{
		switch (semGroup)
		{
		case IL_FLAG_GROUP_EQ:
		case IL_FLAG_GROUP_NE:
			return vector<uint32_t> {IL_FLAG_Z};
		case IL_FLAG_GROUP_CS:
		case IL_FLAG_GROUP_CC:
			return vector<uint32_t> {IL_FLAG_C};
		case IL_FLAG_GROUP_MI:
		case IL_FLAG_GROUP_PL:
			return vector<uint32_t> {IL_FLAG_N};
		case IL_FLAG_GROUP_VS:
		case IL_FLAG_GROUP_VC:
			return vector<uint32_t> {IL_FLAG_V};
		case IL_FLAG_GROUP_HI:
		case IL_FLAG_GROUP_LS:
			return vector<uint32_t> {IL_FLAG_C, IL_FLAG_Z};
		case IL_FLAG_GROUP_GE:
		case IL_FLAG_GROUP_LT:
			return vector<uint32_t> {IL_FLAG_N, IL_FLAG_V};
		case IL_FLAG_GROUP_GT:
		case IL_FLAG_GROUP_LE:
			return vector<uint32_t> {IL_FLAG_Z, IL_FLAG_N, IL_FLAG_V};
		default:
			return vector<uint32_t>();
		}
	}

	virtual map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override
	{
		switch (semGroup) {
		case IL_FLAG_GROUP_EQ:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_E},
				{IL_FLAG_CLASS_FLOAT, LLFC_FE},
			};
		case IL_FLAG_GROUP_NE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_NE},
				{IL_FLAG_CLASS_FLOAT, LLFC_FNE},
			};
		case IL_FLAG_GROUP_CS:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_UGE},
				{IL_FLAG_CLASS_FLOAT, LLFC_FGE},
			};
		case IL_FLAG_GROUP_CC:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_ULT},
				{IL_FLAG_CLASS_FLOAT, LLFC_FLT},
			};
		case IL_FLAG_GROUP_MI:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_NEG},
				{IL_FLAG_CLASS_FLOAT, LLFC_FLT},
			};
		case IL_FLAG_GROUP_PL:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_POS},
				{IL_FLAG_CLASS_FLOAT, LLFC_FGE},
			};
		case IL_FLAG_GROUP_VS:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_O},
				{IL_FLAG_CLASS_FLOAT, LLFC_FO},
			};
		case IL_FLAG_GROUP_VC:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_NO},
				{IL_FLAG_CLASS_FLOAT, LLFC_FUO},
			};
		case IL_FLAG_GROUP_HI:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_UGT},
				{IL_FLAG_CLASS_FLOAT, LLFC_FGT},
			};
		case IL_FLAG_GROUP_LS:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_ULE},
				{IL_FLAG_CLASS_FLOAT, LLFC_FLE},
			};
		case IL_FLAG_GROUP_GE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_SGE},
				{IL_FLAG_CLASS_FLOAT, LLFC_FGE},
			};
		case IL_FLAG_GROUP_LT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_SLT},
				{IL_FLAG_CLASS_FLOAT, LLFC_FLT},
			};
		case IL_FLAG_GROUP_GT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_SGT},
				{IL_FLAG_CLASS_FLOAT, LLFC_FGT},
			};
		case IL_FLAG_GROUP_LE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{IL_FLAG_CLASS_INT, LLFC_SLE},
				{IL_FLAG_CLASS_FLOAT, LLFC_FLE},
			};
		default:
			return map<uint32_t, BNLowLevelILFlagCondition>();
		}
	}

	virtual size_t GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
	{
		switch (semGroup)
		{
		case IL_FLAG_GROUP_EQ:
			return GetFlagConditionLowLevelIL(LLFC_E, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_NE:
			return GetFlagConditionLowLevelIL(LLFC_NE, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_CS:
			return GetFlagConditionLowLevelIL(LLFC_UGE, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_CC:
			return GetFlagConditionLowLevelIL(LLFC_ULT, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_MI:
			return GetFlagConditionLowLevelIL(LLFC_NEG, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_PL:
			return GetFlagConditionLowLevelIL(LLFC_POS, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_VS:
			return GetFlagConditionLowLevelIL(LLFC_O, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_VC:
			return GetFlagConditionLowLevelIL(LLFC_NO, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_HI:
			return GetFlagConditionLowLevelIL(LLFC_UGT, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_LS:
			return GetFlagConditionLowLevelIL(LLFC_ULE, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_GE:
			return GetFlagConditionLowLevelIL(LLFC_SGE, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_LT:
			return GetFlagConditionLowLevelIL(LLFC_SLT, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_GT:
			return GetFlagConditionLowLevelIL(LLFC_SGT, IL_FLAG_CLASS_INT, il);
		case IL_FLAG_GROUP_LE:
			return GetFlagConditionLowLevelIL(LLFC_SLE, IL_FLAG_CLASS_INT, il);
		default:
			return il.Unimplemented();
		}
	}


	/* flag roles */

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t) override
	{
		switch (flag)
		{
		case IL_FLAG_N:
			return NegativeSignFlagRole;
		case IL_FLAG_Z:
			return ZeroFlagRole;
		case IL_FLAG_C:
			return CarryFlagRole;
		case IL_FLAG_V:
			return OverflowFlagRole;
		default:
			return SpecialFlagRole;
		}
	}


	/* flag write types */

	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t> {IL_FLAG_WRITE_ALL, IL_FLAG_WRITE_ALL_FLOAT};
	}


	virtual string GetFlagWriteTypeName(uint32_t flags) override
	{
		switch (flags)
		{
		case IL_FLAG_WRITE_ALL:
			return "*";
		case IL_FLAG_WRITE_ALL_FLOAT:
			return "f*";
		default:
			return "";
		}
	}


	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override
	{
		switch (flags)
		{
		case IL_FLAG_WRITE_ALL:
		case IL_FLAG_WRITE_ALL_FLOAT:
			return vector<uint32_t> {IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V};
		default:
			return vector<uint32_t> {};
		}
	}


	/* override default flag setting expressions */

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size,
	    uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
	    LowLevelILFunction& il) override
	{
		switch (op)
		{
		case LLIL_SBB:
			switch (flag)
			{
			case IL_FLAG_C:
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
			}
		default:
			break;
		}

		BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
		return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
	}


	virtual string GetRegisterName(uint32_t reg_) override
	{
		if (reg_ > REG_NONE && reg_ < REG_END)
			return get_register_name((enum Register)reg_);

		if (reg_ > SYSREG_NONE && reg_ < SYSREG_END)
			return get_system_register_name((enum SystemReg)reg_);

		if (reg_ == FAKEREG_SYSREG_UNKNOWN)
			return "sysreg_unknown";

		if (reg_ == FAKEREG_SYSCALL_INFO)
			return "syscall_info";

		return "";
	}


	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector<uint32_t>{
			REG_X0,   REG_X1,  REG_X2,  REG_X3,   REG_X4,  REG_X5,  REG_X6,  REG_X7,
			REG_X8,   REG_X9,  REG_X10, REG_X11,  REG_X12, REG_X13, REG_X14, REG_X15,
			REG_X16,  REG_X17, REG_X18, REG_X19,  REG_X20, REG_X21, REG_X22, REG_X23,
			REG_X24,  REG_X25, REG_X26, REG_X27,  REG_X28, REG_X29, REG_X30, REG_SP,
			// Vector
			REG_V0,   REG_V1,  REG_V2,  REG_V3,   REG_V4,  REG_V5,  REG_V6,  REG_V7,
			REG_V8,   REG_V9,  REG_V10, REG_V11,  REG_V12, REG_V13, REG_V14, REG_V15,
			REG_V16,  REG_V17, REG_V18, REG_V19,  REG_V20, REG_V21, REG_V22, REG_V23,
			REG_V24,  REG_V25, REG_V26, REG_V27,  REG_V28, REG_V29, REG_V30, REG_V31,
			// SVE
			REG_P0,   REG_P1,  REG_P2,  REG_P3,   REG_P4,  REG_P5,  REG_P6,  REG_P7,
			REG_P8,   REG_P9,  REG_P10,  REG_P11,   REG_P12,  REG_P13,  REG_P14,  REG_P15,
			REG_P16,   REG_P17,  REG_P18,  REG_P19,   REG_P20,  REG_P21,  REG_P22,  REG_P23,
			REG_P24,   REG_P25,  REG_P26,  REG_P27,   REG_P29,  REG_P29,  REG_P30,  REG_P31,
		};
	}


	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> r = {
			/* regular registers */
			REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
			REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
			REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
			REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WSP,
			REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
			REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
			REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
			REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_SP,
			REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
			REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
			REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
			REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_V31,
			REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
			REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
			REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
			REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_B31,
			REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
			REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
			REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
			REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_H31,
			REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
			REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
			REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
			REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31,
			REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
			REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
			REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
			REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_D31,
			REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
			REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
			REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
			REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31,
			// B vectors
			REG_V0_B0, REG_V0_B1, REG_V0_B2, REG_V0_B3, REG_V0_B4, REG_V0_B5, REG_V0_B6, REG_V0_B7,
			REG_V0_B8, REG_V0_B9, REG_V0_B10, REG_V0_B11, REG_V0_B12, REG_V0_B13, REG_V0_B14, REG_V0_B15,
			REG_V1_B0, REG_V1_B1, REG_V1_B2, REG_V1_B3, REG_V1_B4, REG_V1_B5, REG_V1_B6, REG_V1_B7,
			REG_V1_B8, REG_V1_B9, REG_V1_B10, REG_V1_B11, REG_V1_B12, REG_V1_B13, REG_V1_B14, REG_V1_B15,
			REG_V2_B0, REG_V2_B1, REG_V2_B2, REG_V2_B3, REG_V2_B4, REG_V2_B5, REG_V2_B6, REG_V2_B7,
			REG_V2_B8, REG_V2_B9, REG_V2_B10, REG_V2_B11, REG_V2_B12, REG_V2_B13, REG_V2_B14, REG_V2_B15,
			REG_V3_B0, REG_V3_B1, REG_V3_B2, REG_V3_B3, REG_V3_B4, REG_V3_B5, REG_V3_B6, REG_V3_B7,
			REG_V3_B8, REG_V3_B9, REG_V3_B10, REG_V3_B11, REG_V3_B12, REG_V3_B13, REG_V3_B14, REG_V3_B15,
			REG_V4_B0, REG_V4_B1, REG_V4_B2, REG_V4_B3, REG_V4_B4, REG_V4_B5, REG_V4_B6, REG_V4_B7,
			REG_V4_B8, REG_V4_B9, REG_V4_B10, REG_V4_B11, REG_V4_B12, REG_V4_B13, REG_V4_B14, REG_V4_B15,
			REG_V5_B0, REG_V5_B1, REG_V5_B2, REG_V5_B3, REG_V5_B4, REG_V5_B5, REG_V5_B6, REG_V5_B7,
			REG_V5_B8, REG_V5_B9, REG_V5_B10, REG_V5_B11, REG_V5_B12, REG_V5_B13, REG_V5_B14, REG_V5_B15,
			REG_V6_B0, REG_V6_B1, REG_V6_B2, REG_V6_B3, REG_V6_B4, REG_V6_B5, REG_V6_B6, REG_V6_B7,
			REG_V6_B8, REG_V6_B9, REG_V6_B10, REG_V6_B11, REG_V6_B12, REG_V6_B13, REG_V6_B14, REG_V6_B15,
			REG_V7_B0, REG_V7_B1, REG_V7_B2, REG_V7_B3, REG_V7_B4, REG_V7_B5, REG_V7_B6, REG_V7_B7,
			REG_V7_B8, REG_V7_B9, REG_V7_B10, REG_V7_B11, REG_V7_B12, REG_V7_B13, REG_V7_B14, REG_V7_B15,
			REG_V8_B0, REG_V8_B1, REG_V8_B2, REG_V8_B3, REG_V8_B4, REG_V8_B5, REG_V8_B6, REG_V8_B7,
			REG_V8_B8, REG_V8_B9, REG_V8_B10, REG_V8_B11, REG_V8_B12, REG_V8_B13, REG_V8_B14, REG_V8_B15,
			REG_V9_B0, REG_V9_B1, REG_V9_B2, REG_V9_B3, REG_V9_B4, REG_V9_B5, REG_V9_B6, REG_V9_B7,
			REG_V9_B8, REG_V9_B9, REG_V9_B10, REG_V9_B11, REG_V9_B12, REG_V9_B13, REG_V9_B14, REG_V9_B15,
			REG_V10_B0, REG_V10_B1, REG_V10_B2, REG_V10_B3, REG_V10_B4, REG_V10_B5, REG_V10_B6, REG_V10_B7,
			REG_V10_B8, REG_V10_B9, REG_V10_B10, REG_V10_B11, REG_V10_B12, REG_V10_B13, REG_V10_B14, REG_V10_B15,
			REG_V11_B0, REG_V11_B1, REG_V11_B2, REG_V11_B3, REG_V11_B4, REG_V11_B5, REG_V11_B6, REG_V11_B7,
			REG_V11_B8, REG_V11_B9, REG_V11_B10, REG_V11_B11, REG_V11_B12, REG_V11_B13, REG_V11_B14, REG_V11_B15,
			REG_V12_B0, REG_V12_B1, REG_V12_B2, REG_V12_B3, REG_V12_B4, REG_V12_B5, REG_V12_B6, REG_V12_B7,
			REG_V12_B8, REG_V12_B9, REG_V12_B10, REG_V12_B11, REG_V12_B12, REG_V12_B13, REG_V12_B14, REG_V12_B15,
			REG_V13_B0, REG_V13_B1, REG_V13_B2, REG_V13_B3, REG_V13_B4, REG_V13_B5, REG_V13_B6, REG_V13_B7,
			REG_V13_B8, REG_V13_B9, REG_V13_B10, REG_V13_B11, REG_V13_B12, REG_V13_B13, REG_V13_B14, REG_V13_B15,
			REG_V14_B0, REG_V14_B1, REG_V14_B2, REG_V14_B3, REG_V14_B4, REG_V14_B5, REG_V14_B6, REG_V14_B7,
			REG_V14_B8, REG_V14_B9, REG_V14_B10, REG_V14_B11, REG_V14_B12, REG_V14_B13, REG_V14_B14, REG_V14_B15,
			REG_V15_B0, REG_V15_B1, REG_V15_B2, REG_V15_B3, REG_V15_B4, REG_V15_B5, REG_V15_B6, REG_V15_B7,
			REG_V15_B8, REG_V15_B9, REG_V15_B10, REG_V15_B11, REG_V15_B12, REG_V15_B13, REG_V15_B14, REG_V15_B15,
			REG_V16_B0, REG_V16_B1, REG_V16_B2, REG_V16_B3, REG_V16_B4, REG_V16_B5, REG_V16_B6, REG_V16_B7,
			REG_V16_B8, REG_V16_B9, REG_V16_B10, REG_V16_B11, REG_V16_B12, REG_V16_B13, REG_V16_B14, REG_V16_B15,
			REG_V17_B0, REG_V17_B1, REG_V17_B2, REG_V17_B3, REG_V17_B4, REG_V17_B5, REG_V17_B6, REG_V17_B7,
			REG_V17_B8, REG_V17_B9, REG_V17_B10, REG_V17_B11, REG_V17_B12, REG_V17_B13, REG_V17_B14, REG_V17_B15,
			REG_V18_B0, REG_V18_B1, REG_V18_B2, REG_V18_B3, REG_V18_B4, REG_V18_B5, REG_V18_B6, REG_V18_B7,
			REG_V18_B8, REG_V18_B9, REG_V18_B10, REG_V18_B11, REG_V18_B12, REG_V18_B13, REG_V18_B14, REG_V18_B15,
			REG_V19_B0, REG_V19_B1, REG_V19_B2, REG_V19_B3, REG_V19_B4, REG_V19_B5, REG_V19_B6, REG_V19_B7,
			REG_V19_B8, REG_V19_B9, REG_V19_B10, REG_V19_B11, REG_V19_B12, REG_V19_B13, REG_V19_B14, REG_V19_B15,
			REG_V20_B0, REG_V20_B1, REG_V20_B2, REG_V20_B3, REG_V20_B4, REG_V20_B5, REG_V20_B6, REG_V20_B7,
			REG_V20_B8, REG_V20_B9, REG_V20_B10, REG_V20_B11, REG_V20_B12, REG_V20_B13, REG_V20_B14, REG_V20_B15,
			REG_V21_B0, REG_V21_B1, REG_V21_B2, REG_V21_B3, REG_V21_B4, REG_V21_B5, REG_V21_B6, REG_V21_B7,
			REG_V21_B8, REG_V21_B9, REG_V21_B10, REG_V21_B11, REG_V21_B12, REG_V21_B13, REG_V21_B14, REG_V21_B15,
			REG_V22_B0, REG_V22_B1, REG_V22_B2, REG_V22_B3, REG_V22_B4, REG_V22_B5, REG_V22_B6, REG_V22_B7,
			REG_V22_B8, REG_V22_B9, REG_V22_B10, REG_V22_B11, REG_V22_B12, REG_V22_B13, REG_V22_B14, REG_V22_B15,
			REG_V23_B0, REG_V23_B1, REG_V23_B2, REG_V23_B3, REG_V23_B4, REG_V23_B5, REG_V23_B6, REG_V23_B7,
			REG_V23_B8, REG_V23_B9, REG_V23_B10, REG_V23_B11, REG_V23_B12, REG_V23_B13, REG_V23_B14, REG_V23_B15,
			REG_V24_B0, REG_V24_B1, REG_V24_B2, REG_V24_B3, REG_V24_B4, REG_V24_B5, REG_V24_B6, REG_V24_B7,
			REG_V24_B8, REG_V24_B9, REG_V24_B10, REG_V24_B11, REG_V24_B12, REG_V24_B13, REG_V24_B14, REG_V24_B15,
			REG_V25_B0, REG_V25_B1, REG_V25_B2, REG_V25_B3, REG_V25_B4, REG_V25_B5, REG_V25_B6, REG_V25_B7,
			REG_V25_B8, REG_V25_B9, REG_V25_B10, REG_V25_B11, REG_V25_B12, REG_V25_B13, REG_V25_B14, REG_V25_B15,
			REG_V26_B0, REG_V26_B1, REG_V26_B2, REG_V26_B3, REG_V26_B4, REG_V26_B5, REG_V26_B6, REG_V26_B7,
			REG_V26_B8, REG_V26_B9, REG_V26_B10, REG_V26_B11, REG_V26_B12, REG_V26_B13, REG_V26_B14, REG_V26_B15,
			REG_V27_B0, REG_V27_B1, REG_V27_B2, REG_V27_B3, REG_V27_B4, REG_V27_B5, REG_V27_B6, REG_V27_B7,
			REG_V27_B8, REG_V27_B9, REG_V27_B10, REG_V27_B11, REG_V27_B12, REG_V27_B13, REG_V27_B14, REG_V27_B15,
			REG_V28_B0, REG_V28_B1, REG_V28_B2, REG_V28_B3, REG_V28_B4, REG_V28_B5, REG_V28_B6, REG_V28_B7,
			REG_V28_B8, REG_V28_B9, REG_V28_B10, REG_V28_B11, REG_V28_B12, REG_V28_B13, REG_V28_B14, REG_V28_B15,
			REG_V29_B0, REG_V29_B1, REG_V29_B2, REG_V29_B3, REG_V29_B4, REG_V29_B5, REG_V29_B6, REG_V29_B7,
			REG_V29_B8, REG_V29_B9, REG_V29_B10, REG_V29_B11, REG_V29_B12, REG_V29_B13, REG_V29_B14, REG_V29_B15,
			REG_V30_B0, REG_V30_B1, REG_V30_B2, REG_V30_B3, REG_V30_B4, REG_V30_B5, REG_V30_B6, REG_V30_B7,
			REG_V30_B8, REG_V30_B9, REG_V30_B10, REG_V30_B11, REG_V30_B12, REG_V30_B13, REG_V30_B14, REG_V30_B15,
			REG_V31_B0, REG_V31_B1, REG_V31_B2, REG_V31_B3, REG_V31_B4, REG_V31_B5, REG_V31_B6, REG_V31_B7,
			REG_V31_B8, REG_V31_B9, REG_V31_B10, REG_V31_B11, REG_V31_B12, REG_V31_B13, REG_V31_B14, REG_V31_B15,
			// H vectors
			REG_V0_H0, REG_V0_H1, REG_V0_H2, REG_V0_H3, REG_V0_H4, REG_V0_H5, REG_V0_H6, REG_V0_H7,
			REG_V1_H0, REG_V1_H1, REG_V1_H2, REG_V1_H3, REG_V1_H4, REG_V1_H5, REG_V1_H6, REG_V1_H7,
			REG_V2_H0, REG_V2_H1, REG_V2_H2, REG_V2_H3, REG_V2_H4, REG_V2_H5, REG_V2_H6, REG_V2_H7,
			REG_V3_H0, REG_V3_H1, REG_V3_H2, REG_V3_H3, REG_V3_H4, REG_V3_H5, REG_V3_H6, REG_V3_H7,
			REG_V4_H0, REG_V4_H1, REG_V4_H2, REG_V4_H3, REG_V4_H4, REG_V4_H5, REG_V4_H6, REG_V4_H7,
			REG_V5_H0, REG_V5_H1, REG_V5_H2, REG_V5_H3, REG_V5_H4, REG_V5_H5, REG_V5_H6, REG_V5_H7,
			REG_V6_H0, REG_V6_H1, REG_V6_H2, REG_V6_H3, REG_V6_H4, REG_V6_H5, REG_V6_H6, REG_V6_H7,
			REG_V7_H0, REG_V7_H1, REG_V7_H2, REG_V7_H3, REG_V7_H4, REG_V7_H5, REG_V7_H6, REG_V7_H7,
			REG_V8_H0, REG_V8_H1, REG_V8_H2, REG_V8_H3, REG_V8_H4, REG_V8_H5, REG_V8_H6, REG_V8_H7,
			REG_V9_H0, REG_V9_H1, REG_V9_H2, REG_V9_H3, REG_V9_H4, REG_V9_H5, REG_V9_H6, REG_V9_H7,
			REG_V10_H0, REG_V10_H1, REG_V10_H2, REG_V10_H3, REG_V10_H4, REG_V10_H5, REG_V10_H6, REG_V10_H7,
			REG_V11_H0, REG_V11_H1, REG_V11_H2, REG_V11_H3, REG_V11_H4, REG_V11_H5, REG_V11_H6, REG_V11_H7,
			REG_V12_H0, REG_V12_H1, REG_V12_H2, REG_V12_H3, REG_V12_H4, REG_V12_H5, REG_V12_H6, REG_V12_H7,
			REG_V13_H0, REG_V13_H1, REG_V13_H2, REG_V13_H3, REG_V13_H4, REG_V13_H5, REG_V13_H6, REG_V13_H7,
			REG_V14_H0, REG_V14_H1, REG_V14_H2, REG_V14_H3, REG_V14_H4, REG_V14_H5, REG_V14_H6, REG_V14_H7,
			REG_V15_H0, REG_V15_H1, REG_V15_H2, REG_V15_H3, REG_V15_H4, REG_V15_H5, REG_V15_H6, REG_V15_H7,
			REG_V16_H0, REG_V16_H1, REG_V16_H2, REG_V16_H3, REG_V16_H4, REG_V16_H5, REG_V16_H6, REG_V16_H7,
			REG_V17_H0, REG_V17_H1, REG_V17_H2, REG_V17_H3, REG_V17_H4, REG_V17_H5, REG_V17_H6, REG_V17_H7,
			REG_V18_H0, REG_V18_H1, REG_V18_H2, REG_V18_H3, REG_V18_H4, REG_V18_H5, REG_V18_H6, REG_V18_H7,
			REG_V19_H0, REG_V19_H1, REG_V19_H2, REG_V19_H3, REG_V19_H4, REG_V19_H5, REG_V19_H6, REG_V19_H7,
			REG_V20_H0, REG_V20_H1, REG_V20_H2, REG_V20_H3, REG_V20_H4, REG_V20_H5, REG_V20_H6, REG_V20_H7,
			REG_V21_H0, REG_V21_H1, REG_V21_H2, REG_V21_H3, REG_V21_H4, REG_V21_H5, REG_V21_H6, REG_V21_H7,
			REG_V22_H0, REG_V22_H1, REG_V22_H2, REG_V22_H3, REG_V22_H4, REG_V22_H5, REG_V22_H6, REG_V22_H7,
			REG_V23_H0, REG_V23_H1, REG_V23_H2, REG_V23_H3, REG_V23_H4, REG_V23_H5, REG_V23_H6, REG_V23_H7,
			REG_V24_H0, REG_V24_H1, REG_V24_H2, REG_V24_H3, REG_V24_H4, REG_V24_H5, REG_V24_H6, REG_V24_H7,
			REG_V25_H0, REG_V25_H1, REG_V25_H2, REG_V25_H3, REG_V25_H4, REG_V25_H5, REG_V25_H6, REG_V25_H7,
			REG_V26_H0, REG_V26_H1, REG_V26_H2, REG_V26_H3, REG_V26_H4, REG_V26_H5, REG_V26_H6, REG_V26_H7,
			REG_V27_H0, REG_V27_H1, REG_V27_H2, REG_V27_H3, REG_V27_H4, REG_V27_H5, REG_V27_H6, REG_V27_H7,
			REG_V28_H0, REG_V28_H1, REG_V28_H2, REG_V28_H3, REG_V28_H4, REG_V28_H5, REG_V28_H6, REG_V28_H7,
			REG_V29_H0, REG_V29_H1, REG_V29_H2, REG_V29_H3, REG_V29_H4, REG_V29_H5, REG_V29_H6, REG_V29_H7,
			REG_V30_H0, REG_V30_H1, REG_V30_H2, REG_V30_H3, REG_V30_H4, REG_V30_H5, REG_V30_H6, REG_V30_H7,
			REG_V31_H0, REG_V31_H1, REG_V31_H2, REG_V31_H3, REG_V31_H4, REG_V31_H5, REG_V31_H6, REG_V31_H7,
			// S vectors
			REG_V0_S0, REG_V0_S1, REG_V0_S2, REG_V0_S3, REG_V1_S0, REG_V1_S1, REG_V1_S2, REG_V1_S3,
			REG_V2_S0, REG_V2_S1, REG_V2_S2, REG_V2_S3, REG_V3_S0, REG_V3_S1, REG_V3_S2, REG_V3_S3,
			REG_V4_S0, REG_V4_S1, REG_V4_S2, REG_V4_S3, REG_V5_S0, REG_V5_S1, REG_V5_S2, REG_V5_S3,
			REG_V6_S0, REG_V6_S1, REG_V6_S2, REG_V6_S3, REG_V7_S0, REG_V7_S1, REG_V7_S2, REG_V7_S3,
			REG_V8_S0, REG_V8_S1, REG_V8_S2, REG_V8_S3, REG_V9_S0, REG_V9_S1, REG_V9_S2, REG_V9_S3,
			REG_V10_S0, REG_V10_S1, REG_V10_S2, REG_V10_S3, REG_V11_S0, REG_V11_S1, REG_V11_S2, REG_V11_S3,
			REG_V12_S0, REG_V12_S1, REG_V12_S2, REG_V12_S3, REG_V13_S0, REG_V13_S1, REG_V13_S2, REG_V13_S3,
			REG_V14_S0, REG_V14_S1, REG_V14_S2, REG_V14_S3, REG_V15_S0, REG_V15_S1, REG_V15_S2, REG_V15_S3,
			REG_V16_S0, REG_V16_S1, REG_V16_S2, REG_V16_S3, REG_V17_S0, REG_V17_S1, REG_V17_S2, REG_V17_S3,
			REG_V18_S0, REG_V18_S1, REG_V18_S2, REG_V18_S3, REG_V19_S0, REG_V19_S1, REG_V19_S2, REG_V19_S3,
			REG_V20_S0, REG_V20_S1, REG_V20_S2, REG_V20_S3, REG_V21_S0, REG_V21_S1, REG_V21_S2, REG_V21_S3,
			REG_V22_S0, REG_V22_S1, REG_V22_S2, REG_V22_S3, REG_V23_S0, REG_V23_S1, REG_V23_S2, REG_V23_S3,
			REG_V24_S0, REG_V24_S1, REG_V24_S2, REG_V24_S3, REG_V25_S0, REG_V25_S1, REG_V25_S2, REG_V25_S3,
			REG_V26_S0, REG_V26_S1, REG_V26_S2, REG_V26_S3, REG_V27_S0, REG_V27_S1, REG_V27_S2, REG_V27_S3,
			REG_V28_S0, REG_V28_S1, REG_V28_S2, REG_V28_S3, REG_V29_S0, REG_V29_S1, REG_V29_S2, REG_V29_S3,
			REG_V30_S0, REG_V30_S1, REG_V30_S2, REG_V30_S3, REG_V31_S0, REG_V31_S1, REG_V31_S2, REG_V31_S3,
			// D vectors
			REG_V0_D0, REG_V0_D1, REG_V1_D0, REG_V1_D1, REG_V2_D0, REG_V2_D1, REG_V3_D0, REG_V3_D1,
			REG_V4_D0, REG_V4_D1, REG_V5_D0, REG_V5_D1, REG_V6_D0, REG_V6_D1, REG_V7_D0, REG_V7_D1,
			REG_V8_D0, REG_V8_D1, REG_V9_D0, REG_V9_D1, REG_V10_D0, REG_V10_D1, REG_V11_D0, REG_V11_D1,
			REG_V12_D0, REG_V12_D1, REG_V13_D0, REG_V13_D1, REG_V14_D0, REG_V14_D1, REG_V15_D0, REG_V15_D1,
			REG_V16_D0, REG_V16_D1, REG_V17_D0, REG_V17_D1, REG_V18_D0, REG_V18_D1, REG_V19_D0, REG_V19_D1,
			REG_V20_D0, REG_V20_D1, REG_V21_D0, REG_V21_D1, REG_V22_D0, REG_V22_D1, REG_V23_D0, REG_V23_D1,
			REG_V24_D0, REG_V24_D1, REG_V25_D0, REG_V25_D1, REG_V26_D0, REG_V26_D1, REG_V27_D0, REG_V27_D1,
			REG_V28_D0, REG_V28_D1, REG_V29_D0, REG_V29_D1, REG_V30_D0, REG_V30_D1, REG_V31_D0, REG_V31_D1,
			// SVE
			REG_Z0,  REG_Z1,  REG_Z2,  REG_Z3,  REG_Z4,  REG_Z5,  REG_Z6,  REG_Z7,
			REG_Z8,  REG_Z9,  REG_Z10, REG_Z11, REG_Z12, REG_Z13, REG_Z14, REG_Z15,
			REG_Z16, REG_Z17, REG_Z18, REG_Z19, REG_Z20, REG_Z21, REG_Z22, REG_Z23,
			REG_Z24, REG_Z25, REG_Z26, REG_Z27, REG_Z28, REG_Z29, REG_Z30, REG_Z31,
			REG_P0,  REG_P1,  REG_P2,  REG_P3,  REG_P4,  REG_P5,  REG_P6,  REG_P7,
			REG_P8,  REG_P9,  REG_P10, REG_P11, REG_P12, REG_P13, REG_P14, REG_P15,
			REG_P16, REG_P17, REG_P18, REG_P19, REG_P20, REG_P21, REG_P22, REG_P23,
			REG_P24, REG_P25, REG_P26, REG_P27, REG_P28, REG_P29, REG_P30, REG_P31,
			/* system registers */
			REG_OSDTRRX_EL1, REG_DBGBVR0_EL1, REG_DBGBCR0_EL1, REG_DBGWVR0_EL1,
			REG_DBGWCR0_EL1, REG_DBGBVR1_EL1, REG_DBGBCR1_EL1, REG_DBGWVR1_EL1,
			REG_DBGWCR1_EL1, REG_MDCCINT_EL1, REG_MDSCR_EL1, REG_DBGBVR2_EL1,
			REG_DBGBCR2_EL1, REG_DBGWVR2_EL1, REG_DBGWCR2_EL1, REG_OSDTRTX_EL1,
			REG_DBGBVR3_EL1, REG_DBGBCR3_EL1, REG_DBGWVR3_EL1, REG_DBGWCR3_EL1,
			REG_DBGBVR4_EL1, REG_DBGBCR4_EL1, REG_DBGWVR4_EL1, REG_DBGWCR4_EL1,
			REG_DBGBVR5_EL1, REG_DBGBCR5_EL1, REG_DBGWVR5_EL1, REG_DBGWCR5_EL1,
			REG_OSECCR_EL1, REG_DBGBVR6_EL1, REG_DBGBCR6_EL1, REG_DBGWVR6_EL1,
			REG_DBGWCR6_EL1, REG_DBGBVR7_EL1, REG_DBGBCR7_EL1, REG_DBGWVR7_EL1,
			REG_DBGWCR7_EL1, REG_DBGBVR8_EL1, REG_DBGBCR8_EL1, REG_DBGWVR8_EL1,
			REG_DBGWCR8_EL1, REG_DBGBVR9_EL1, REG_DBGBCR9_EL1, REG_DBGWVR9_EL1,
			REG_DBGWCR9_EL1, REG_DBGBVR10_EL1, REG_DBGBCR10_EL1, REG_DBGWVR10_EL1,
			REG_DBGWCR10_EL1, REG_DBGBVR11_EL1, REG_DBGBCR11_EL1, REG_DBGWVR11_EL1,
			REG_DBGWCR11_EL1, REG_DBGBVR12_EL1, REG_DBGBCR12_EL1, REG_DBGWVR12_EL1,
			REG_DBGWCR12_EL1, REG_DBGBVR13_EL1, REG_DBGBCR13_EL1, REG_DBGWVR13_EL1,
			REG_DBGWCR13_EL1, REG_DBGBVR14_EL1, REG_DBGBCR14_EL1, REG_DBGWVR14_EL1,
			REG_DBGWCR14_EL1, REG_DBGBVR15_EL1, REG_DBGBCR15_EL1, REG_DBGWVR15_EL1,
			REG_DBGWCR15_EL1, REG_OSLAR_EL1, REG_OSDLR_EL1, REG_DBGPRCR_EL1,
			REG_DBGCLAIMSET_EL1, REG_DBGCLAIMCLR_EL1, REG_TRCTRACEIDR, REG_TRCVICTLR,
			REG_TRCSEQEVR0, REG_TRCCNTRLDVR0, REG_TRCIMSPEC0, REG_TRCPRGCTLR, REG_TRCQCTLR,
			REG_TRCVIIECTLR, REG_TRCSEQEVR1, REG_TRCCNTRLDVR1, REG_TRCIMSPEC1,
			REG_TRCPROCSELR, REG_TRCVISSCTLR, REG_TRCSEQEVR2, REG_TRCCNTRLDVR2,
			REG_TRCIMSPEC2, REG_TRCVIPCSSCTLR, REG_TRCCNTRLDVR3, REG_TRCIMSPEC3,
			REG_TRCCONFIGR, REG_TRCCNTCTLR0, REG_TRCIMSPEC4, REG_TRCCNTCTLR1,
			REG_TRCIMSPEC5, REG_TRCAUXCTLR, REG_TRCSEQRSTEVR, REG_TRCCNTCTLR2,
			REG_TRCIMSPEC6, REG_TRCSEQSTR, REG_TRCCNTCTLR3, REG_TRCIMSPEC7,
			REG_TRCEVENTCTL0R, REG_TRCVDCTLR, REG_TRCEXTINSELR, REG_TRCCNTVR0,
			REG_TRCEVENTCTL1R, REG_TRCVDSACCTLR, REG_TRCEXTINSELR1, REG_TRCCNTVR1,
			REG_TRCRSR, REG_TRCVDARCCTLR, REG_TRCEXTINSELR2, REG_TRCCNTVR2,
			REG_TRCSTALLCTLR, REG_TRCEXTINSELR3, REG_TRCCNTVR3, REG_TRCTSCTLR,
			REG_TRCSYNCPR, REG_TRCCCCTLR, REG_TRCBBCTLR, REG_TRCRSCTLR16, REG_TRCSSCCR0,
			REG_TRCSSPCICR0, REG_TRCOSLAR, REG_TRCRSCTLR17, REG_TRCSSCCR1, REG_TRCSSPCICR1,
			REG_TRCRSCTLR2, REG_TRCRSCTLR18, REG_TRCSSCCR2, REG_TRCSSPCICR2,
			REG_TRCRSCTLR3, REG_TRCRSCTLR19, REG_TRCSSCCR3, REG_TRCSSPCICR3,
			REG_TRCRSCTLR4, REG_TRCRSCTLR20, REG_TRCSSCCR4, REG_TRCSSPCICR4, REG_TRCPDCR,
			REG_TRCRSCTLR5, REG_TRCRSCTLR21, REG_TRCSSCCR5, REG_TRCSSPCICR5,
			REG_TRCRSCTLR6, REG_TRCRSCTLR22, REG_TRCSSCCR6, REG_TRCSSPCICR6,
			REG_TRCRSCTLR7, REG_TRCRSCTLR23, REG_TRCSSCCR7, REG_TRCSSPCICR7,
			REG_TRCRSCTLR8, REG_TRCRSCTLR24, REG_TRCSSCSR0, REG_TRCRSCTLR9,
			REG_TRCRSCTLR25, REG_TRCSSCSR1, REG_TRCRSCTLR10, REG_TRCRSCTLR26,
			REG_TRCSSCSR2, REG_TRCRSCTLR11, REG_TRCRSCTLR27, REG_TRCSSCSR3,
			REG_TRCRSCTLR12, REG_TRCRSCTLR28, REG_TRCSSCSR4, REG_TRCRSCTLR13,
			REG_TRCRSCTLR29, REG_TRCSSCSR5, REG_TRCRSCTLR14, REG_TRCRSCTLR30,
			REG_TRCSSCSR6, REG_TRCRSCTLR15, REG_TRCRSCTLR31, REG_TRCSSCSR7, REG_TRCACVR0,
			REG_TRCACVR8, REG_TRCACATR0, REG_TRCACATR8, REG_TRCDVCVR0, REG_TRCDVCVR4,
			REG_TRCDVCMR0, REG_TRCDVCMR4, REG_TRCACVR1, REG_TRCACVR9, REG_TRCACATR1,
			REG_TRCACATR9, REG_TRCACVR2, REG_TRCACVR10, REG_TRCACATR2, REG_TRCACATR10,
			REG_TRCDVCVR1, REG_TRCDVCVR5, REG_TRCDVCMR1, REG_TRCDVCMR5, REG_TRCACVR3,
			REG_TRCACVR11, REG_TRCACATR3, REG_TRCACATR11, REG_TRCACVR4, REG_TRCACVR12,
			REG_TRCACATR4, REG_TRCACATR12, REG_TRCDVCVR2, REG_TRCDVCVR6, REG_TRCDVCMR2,
			REG_TRCDVCMR6, REG_TRCACVR5, REG_TRCACVR13, REG_TRCACATR5, REG_TRCACATR13,
			REG_TRCACVR6, REG_TRCACVR14, REG_TRCACATR6, REG_TRCACATR14, REG_TRCDVCVR3,
			REG_TRCDVCVR7, REG_TRCDVCMR3, REG_TRCDVCMR7, REG_TRCACVR7, REG_TRCACVR15,
			REG_TRCACATR7, REG_TRCACATR15, REG_TRCCIDCVR0, REG_TRCVMIDCVR0,
			REG_TRCCIDCCTLR0, REG_TRCCIDCCTLR1, REG_TRCCIDCVR1, REG_TRCVMIDCVR1,
			REG_TRCVMIDCCTLR0, REG_TRCVMIDCCTLR1, REG_TRCCIDCVR2, REG_TRCVMIDCVR2,
			REG_TRCCIDCVR3, REG_TRCVMIDCVR3, REG_TRCCIDCVR4, REG_TRCVMIDCVR4,
			REG_TRCCIDCVR5, REG_TRCVMIDCVR5, REG_TRCCIDCVR6, REG_TRCVMIDCVR6,
			REG_TRCCIDCVR7, REG_TRCVMIDCVR7, REG_TRCITCTRL, REG_TRCCLAIMSET,
			REG_TRCCLAIMCLR, REG_TRCLAR, REG_TEECR32_EL1, REG_TEEHBR32_EL1, REG_DBGDTR_EL0,
			REG_DBGDTRTX_EL0, REG_DBGVCR32_EL2, REG_SCTLR_EL1, REG_ACTLR_EL1,
			REG_CPACR_EL1, REG_RGSR_EL1, REG_GCR_EL1, REG_TRFCR_EL1, REG_TTBR0_EL1,
			REG_TTBR1_EL1, REG_TCR_EL1, REG_APIAKEYLO_EL1, REG_APIAKEYHI_EL1,
			REG_APIBKEYLO_EL1, REG_APIBKEYHI_EL1, REG_APDAKEYLO_EL1, REG_APDAKEYHI_EL1,
			REG_APDBKEYLO_EL1, REG_APDBKEYHI_EL1, REG_APGAKEYLO_EL1, REG_APGAKEYHI_EL1,
			REG_SPSR_EL1, REG_ELR_EL1, REG_SP_EL0, REG_SPSEL, REG_CURRENTEL, REG_PAN,
			REG_UAO, REG_ICC_PMR_EL1, REG_AFSR0_EL1, REG_AFSR1_EL1, REG_ESR_EL1,
			REG_ERRSELR_EL1, REG_ERXCTLR_EL1, REG_ERXSTATUS_EL1, REG_ERXADDR_EL1,
			REG_ERXPFGCTL_EL1, REG_ERXPFGCDN_EL1, REG_ERXMISC0_EL1, REG_ERXMISC1_EL1,
			REG_ERXMISC2_EL1, REG_ERXMISC3_EL1, REG_ERXTS_EL1, REG_TFSR_EL1,
			REG_TFSRE0_EL1, REG_FAR_EL1, REG_PAR_EL1, REG_PMSCR_EL1, REG_PMSICR_EL1,
			REG_PMSIRR_EL1, REG_PMSFCR_EL1, REG_PMSEVFR_EL1, REG_PMSLATFR_EL1,
			REG_PMSIDR_EL1, REG_PMBLIMITR_EL1, REG_PMBPTR_EL1, REG_PMBSR_EL1,
			REG_PMBIDR_EL1, REG_TRBLIMITR_EL1, REG_TRBPTR_EL1, REG_TRBBASER_EL1,
			REG_TRBSR_EL1, REG_TRBMAR_EL1, REG_TRBTRG_EL1, REG_PMINTENSET_EL1,
			REG_PMINTENCLR_EL1, REG_PMMIR_EL1, REG_MAIR_EL1, REG_AMAIR_EL1, REG_LORSA_EL1,
			REG_LOREA_EL1, REG_LORN_EL1, REG_LORC_EL1, REG_MPAM1_EL1, REG_MPAM0_EL1,
			REG_VBAR_EL1, REG_RMR_EL1, REG_DISR_EL1, REG_ICC_EOIR0_EL1, REG_ICC_BPR0_EL1,
			REG_ICC_AP0R0_EL1, REG_ICC_AP0R1_EL1, REG_ICC_AP0R2_EL1, REG_ICC_AP0R3_EL1,
			REG_ICC_AP1R0_EL1, REG_ICC_AP1R1_EL1, REG_ICC_AP1R2_EL1, REG_ICC_AP1R3_EL1,
			REG_ICC_DIR_EL1, REG_ICC_SGI1R_EL1, REG_ICC_ASGI1R_EL1, REG_ICC_SGI0R_EL1,
			REG_ICC_EOIR1_EL1, REG_ICC_BPR1_EL1, REG_ICC_CTLR_EL1, REG_ICC_SRE_EL1,
			REG_ICC_IGRPEN0_EL1, REG_ICC_IGRPEN1_EL1, REG_ICC_SEIEN_EL1,
			REG_CONTEXTIDR_EL1, REG_TPIDR_EL1, REG_SCXTNUM_EL1, REG_CNTKCTL_EL1,
			REG_CSSELR_EL1, REG_NZCV, REG_DAIFSET, REG_DIT, REG_SSBS, REG_TCO, REG_FPCR,
			REG_FPSR, REG_DSPSR_EL0, REG_DLR_EL0, REG_PMCR_EL0, REG_PMCNTENSET_EL0,
			REG_PMCNTENCLR_EL0, REG_PMOVSCLR_EL0, REG_PMSWINC_EL0, REG_PMSELR_EL0,
			REG_PMCCNTR_EL0, REG_PMXEVTYPER_EL0, REG_PMXEVCNTR_EL0, REG_DAIFCLR, REG_PMUSERENR_EL0,
			REG_PMOVSSET_EL0, REG_TPIDR_EL0, REG_TPIDRRO_EL0, REG_SCXTNUM_EL0,
			REG_AMCR_EL0, REG_AMUSERENR_EL0, REG_AMCNTENCLR0_EL0, REG_AMCNTENSET0_EL0,
			REG_AMCNTENCLR1_EL0, REG_AMCNTENSET1_EL0, REG_AMEVCNTR00_EL0,
			REG_AMEVCNTR01_EL0, REG_AMEVCNTR02_EL0, REG_AMEVCNTR03_EL0, REG_AMEVCNTR10_EL0,
			REG_AMEVCNTR11_EL0, REG_AMEVCNTR12_EL0, REG_AMEVCNTR13_EL0, REG_AMEVCNTR14_EL0,
			REG_AMEVCNTR15_EL0, REG_AMEVCNTR16_EL0, REG_AMEVCNTR17_EL0, REG_AMEVCNTR18_EL0,
			REG_AMEVCNTR19_EL0, REG_AMEVCNTR110_EL0, REG_AMEVCNTR111_EL0,
			REG_AMEVCNTR112_EL0, REG_AMEVCNTR113_EL0, REG_AMEVCNTR114_EL0,
			REG_AMEVCNTR115_EL0, REG_AMEVTYPER10_EL0, REG_AMEVTYPER11_EL0,
			REG_AMEVTYPER12_EL0, REG_AMEVTYPER13_EL0, REG_AMEVTYPER14_EL0,
			REG_AMEVTYPER15_EL0, REG_AMEVTYPER16_EL0, REG_AMEVTYPER17_EL0,
			REG_AMEVTYPER18_EL0, REG_AMEVTYPER19_EL0, REG_AMEVTYPER110_EL0,
			REG_AMEVTYPER111_EL0, REG_AMEVTYPER112_EL0, REG_AMEVTYPER113_EL0,
			REG_AMEVTYPER114_EL0, REG_AMEVTYPER115_EL0, REG_CNTFRQ_EL0, REG_CNTP_TVAL_EL0,
			REG_CNTP_CTL_EL0, REG_CNTP_CVAL_EL0, REG_CNTV_TVAL_EL0, REG_CNTV_CTL_EL0,
			REG_CNTV_CVAL_EL0, REG_PMEVCNTR0_EL0, REG_PMEVCNTR1_EL0, REG_PMEVCNTR2_EL0,
			REG_PMEVCNTR3_EL0, REG_PMEVCNTR4_EL0, REG_PMEVCNTR5_EL0, REG_PMEVCNTR6_EL0,
			REG_PMEVCNTR7_EL0, REG_PMEVCNTR8_EL0, REG_PMEVCNTR9_EL0, REG_PMEVCNTR10_EL0,
			REG_PMEVCNTR11_EL0, REG_PMEVCNTR12_EL0, REG_PMEVCNTR13_EL0, REG_PMEVCNTR14_EL0,
			REG_PMEVCNTR15_EL0, REG_PMEVCNTR16_EL0, REG_PMEVCNTR17_EL0, REG_PMEVCNTR18_EL0,
			REG_PMEVCNTR19_EL0, REG_PMEVCNTR20_EL0, REG_PMEVCNTR21_EL0, REG_PMEVCNTR22_EL0,
			REG_PMEVCNTR23_EL0, REG_PMEVCNTR24_EL0, REG_PMEVCNTR25_EL0, REG_PMEVCNTR26_EL0,
			REG_PMEVCNTR27_EL0, REG_PMEVCNTR28_EL0, REG_PMEVCNTR29_EL0, REG_PMEVCNTR30_EL0,
			REG_PMEVTYPER0_EL0, REG_PMEVTYPER1_EL0, REG_PMEVTYPER2_EL0, REG_PMEVTYPER3_EL0,
			REG_PMEVTYPER4_EL0, REG_PMEVTYPER5_EL0, REG_PMEVTYPER6_EL0, REG_PMEVTYPER7_EL0,
			REG_PMEVTYPER8_EL0, REG_PMEVTYPER9_EL0, REG_PMEVTYPER10_EL0,
			REG_PMEVTYPER11_EL0, REG_PMEVTYPER12_EL0, REG_PMEVTYPER13_EL0,
			REG_PMEVTYPER14_EL0, REG_PMEVTYPER15_EL0, REG_PMEVTYPER16_EL0,
			REG_PMEVTYPER17_EL0, REG_PMEVTYPER18_EL0, REG_PMEVTYPER19_EL0,
			REG_PMEVTYPER20_EL0, REG_PMEVTYPER21_EL0, REG_PMEVTYPER22_EL0,
			REG_PMEVTYPER23_EL0, REG_PMEVTYPER24_EL0, REG_PMEVTYPER25_EL0,
			REG_PMEVTYPER26_EL0, REG_PMEVTYPER27_EL0, REG_PMEVTYPER28_EL0,
			REG_PMEVTYPER29_EL0, REG_PMEVTYPER30_EL0, REG_PMCCFILTR_EL0, REG_VPIDR_EL2,
			REG_VMPIDR_EL2, REG_SCTLR_EL2, REG_ACTLR_EL2, REG_HCR_EL2, REG_MDCR_EL2,
			REG_CPTR_EL2, REG_HSTR_EL2, REG_HACR_EL2, REG_TRFCR_EL2, REG_SDER32_EL2,
			REG_TTBR0_EL2, REG_TTBR1_EL2, REG_TCR_EL2, REG_VTTBR_EL2, REG_VTCR_EL2,
			REG_VNCR_EL2, REG_VSTTBR_EL2, REG_VSTCR_EL2, REG_DACR32_EL2, REG_SPSR_EL2,
			REG_ELR_EL2, REG_SP_EL1, REG_SPSR_IRQ, REG_SPSR_ABT, REG_SPSR_UND,
			REG_SPSR_FIQ, REG_IFSR32_EL2, REG_AFSR0_EL2, REG_AFSR1_EL2, REG_ESR_EL2,
			REG_VSESR_EL2, REG_FPEXC32_EL2, REG_TFSR_EL2, REG_FAR_EL2, REG_HPFAR_EL2,
			REG_PMSCR_EL2, REG_MAIR_EL2, REG_AMAIR_EL2, REG_MPAMHCR_EL2, REG_MPAMVPMV_EL2,
			REG_MPAM2_EL2, REG_MPAMVPM0_EL2, REG_MPAMVPM1_EL2, REG_MPAMVPM2_EL2,
			REG_MPAMVPM3_EL2, REG_MPAMVPM4_EL2, REG_MPAMVPM5_EL2, REG_MPAMVPM6_EL2,
			REG_MPAMVPM7_EL2, REG_VBAR_EL2, REG_RMR_EL2, REG_VDISR_EL2, REG_ICH_AP0R0_EL2,
			REG_ICH_AP0R1_EL2, REG_ICH_AP0R2_EL2, REG_ICH_AP0R3_EL2, REG_ICH_AP1R0_EL2,
			REG_ICH_AP1R1_EL2, REG_ICH_AP1R2_EL2, REG_ICH_AP1R3_EL2, REG_ICH_VSEIR_EL2,
			REG_ICC_SRE_EL2, REG_ICH_HCR_EL2, REG_ICH_MISR_EL2, REG_ICH_VMCR_EL2,
			REG_ICH_LR0_EL2, REG_ICH_LR1_EL2, REG_ICH_LR2_EL2, REG_ICH_LR3_EL2,
			REG_ICH_LR4_EL2, REG_ICH_LR5_EL2, REG_ICH_LR6_EL2, REG_ICH_LR7_EL2,
			REG_ICH_LR8_EL2, REG_ICH_LR9_EL2, REG_ICH_LR10_EL2, REG_ICH_LR11_EL2,
			REG_ICH_LR12_EL2, REG_ICH_LR13_EL2, REG_ICH_LR14_EL2, REG_ICH_LR15_EL2,
			REG_CONTEXTIDR_EL2, REG_TPIDR_EL2, REG_SCXTNUM_EL2, REG_CNTVOFF_EL2,
			REG_CNTHCTL_EL2, REG_CNTHP_TVAL_EL2, REG_CNTHP_CTL_EL2, REG_CNTHP_CVAL_EL2,
			REG_CNTHV_TVAL_EL2, REG_CNTHV_CTL_EL2, REG_CNTHV_CVAL_EL2, REG_CNTHVS_TVAL_EL2,
			REG_CNTHVS_CTL_EL2, REG_CNTHVS_CVAL_EL2, REG_CNTHPS_TVAL_EL2,
			REG_CNTHPS_CTL_EL2, REG_CNTHPS_CVAL_EL2, REG_SCTLR_EL12, REG_CPACR_EL12,
			REG_TRFCR_EL12, REG_TTBR0_EL12, REG_TTBR1_EL12, REG_TCR_EL12, REG_SPSR_EL12,
			REG_ELR_EL12, REG_AFSR0_EL12, REG_AFSR1_EL12, REG_ESR_EL12, REG_TFSR_EL12,
			REG_FAR_EL12, REG_PMSCR_EL12, REG_MAIR_EL12, REG_AMAIR_EL12, REG_MPAM1_EL12,
			REG_VBAR_EL12, REG_CONTEXTIDR_EL12, REG_SCXTNUM_EL12, REG_CNTKCTL_EL12,
			REG_CNTP_TVAL_EL02, REG_CNTP_CTL_EL02, REG_CNTP_CVAL_EL02, REG_CNTV_TVAL_EL02,
			REG_CNTV_CTL_EL02, REG_CNTV_CVAL_EL02, REG_SCTLR_EL3, REG_ACTLR_EL3,
			REG_SCR_EL3, REG_SDER32_EL3, REG_CPTR_EL3, REG_MDCR_EL3, REG_TTBR0_EL3,
			REG_TCR_EL3, REG_SPSR_EL3, REG_ELR_EL3, REG_SP_EL2, REG_AFSR0_EL3,
			REG_AFSR1_EL3, REG_ESR_EL3, REG_TFSR_EL3, REG_FAR_EL3, REG_MAIR_EL3,
			REG_AMAIR_EL3, REG_MPAM3_EL3, REG_VBAR_EL3, REG_RMR_EL3, REG_ICC_CTLR_EL3,
			REG_ICC_SRE_EL3, REG_ICC_IGRPEN1_EL3, REG_TPIDR_EL3, REG_SCXTNUM_EL3,
			REG_CNTPS_TVAL_EL1, REG_CNTPS_CTL_EL1, REG_CNTPS_CVAL_EL1, REG_PSTATE_SPSEL,
			/* fake registers */
			FAKEREG_SYSREG_UNKNOWN, /* acts as an input/output to ARM64_INTRIN_MSR,
										ARM64_INTRIN_MRS intrinsics when the sysreg
										has no name (is implementation specific) */
			FAKEREG_SYSCALL_INFO
		};

		return r;
	}


	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override
	{
		switch (reg)
		{
			case REG_W0:
			case REG_W1:
			case REG_W2:
			case REG_W3:
			case REG_W4:
			case REG_W5:
			case REG_W6:
			case REG_W7:
			case REG_W8:
			case REG_W9:
			case REG_W10:
			case REG_W11:
			case REG_W12:
			case REG_W13:
			case REG_W14:
			case REG_W15:
			case REG_W16:
			case REG_W17:
			case REG_W18:
			case REG_W19:
			case REG_W20:
			case REG_W21:
			case REG_W22:
			case REG_W23:
			case REG_W24:
			case REG_W25:
			case REG_W26:
			case REG_W27:
			case REG_W28:
			case REG_W29:
			case REG_W30:
			case REG_WSP:
					return RegisterInfo(REG_X0 + (reg-REG_W0), 0, 4, true);
			case REG_X0:
			case REG_X1:
			case REG_X2:
			case REG_X3:
			case REG_X4:
			case REG_X5:
			case REG_X6:
			case REG_X7:
			case REG_X8:
			case REG_X9:
			case REG_X10:
			case REG_X11:
			case REG_X12:
			case REG_X13:
			case REG_X14:
			case REG_X15:
			case REG_X16:
			case REG_X17:
			case REG_X18:
			case REG_X19:
			case REG_X20:
			case REG_X21:
			case REG_X22:
			case REG_X23:
			case REG_X24:
			case REG_X25:
			case REG_X26:
			case REG_X27:
			case REG_X28:
			case REG_X29:
			case REG_X30:
			case REG_SP:
				return RegisterInfo(reg, 0, 8);
			case REG_V0:
			case REG_V1:
			case REG_V2:
			case REG_V3:
			case REG_V4:
			case REG_V5:
			case REG_V6:
			case REG_V7:
			case REG_V8:
			case REG_V9:
			case REG_V10:
			case REG_V11:
			case REG_V12:
			case REG_V13:
			case REG_V14:
			case REG_V15:
			case REG_V16:
			case REG_V17:
			case REG_V18:
			case REG_V19:
			case REG_V20:
			case REG_V21:
			case REG_V22:
			case REG_V23:
			case REG_V24:
			case REG_V25:
			case REG_V26:
			case REG_V27:
			case REG_V28:
			case REG_V29:
			case REG_V30:
			case REG_V31:
				return RegisterInfo(reg, 0, 16);
			case REG_B0:
			case REG_B1:
			case REG_B2:
			case REG_B3:
			case REG_B4:
			case REG_B5:
			case REG_B6:
			case REG_B7:
			case REG_B8:
			case REG_B9:
			case REG_B10:
			case REG_B11:
			case REG_B12:
			case REG_B13:
			case REG_B14:
			case REG_B15:
			case REG_B16:
			case REG_B17:
			case REG_B18:
			case REG_B19:
			case REG_B20:
			case REG_B21:
			case REG_B22:
			case REG_B23:
			case REG_B24:
			case REG_B25:
			case REG_B26:
			case REG_B27:
			case REG_B28:
			case REG_B29:
			case REG_B30:
			case REG_B31:
				return RegisterInfo(REG_V0+(reg-REG_B0), 0, 1);
			case REG_H0:
			case REG_H1:
			case REG_H2:
			case REG_H3:
			case REG_H4:
			case REG_H5:
			case REG_H6:
			case REG_H7:
			case REG_H8:
			case REG_H9:
			case REG_H10:
			case REG_H11:
			case REG_H12:
			case REG_H13:
			case REG_H14:
			case REG_H15:
			case REG_H16:
			case REG_H17:
			case REG_H18:
			case REG_H19:
			case REG_H20:
			case REG_H21:
			case REG_H22:
			case REG_H23:
			case REG_H24:
			case REG_H25:
			case REG_H26:
			case REG_H27:
			case REG_H28:
			case REG_H29:
			case REG_H30:
			case REG_H31:
				return RegisterInfo(REG_V0+(reg-REG_H0), 0, 2);
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
				return RegisterInfo(REG_V0+(reg-REG_S0), 0, 4);
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
				return RegisterInfo(REG_V0+(reg-REG_D0), 0, 8);
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
			case REG_Q16:
			case REG_Q17:
			case REG_Q18:
			case REG_Q19:
			case REG_Q20:
			case REG_Q21:
			case REG_Q22:
			case REG_Q23:
			case REG_Q24:
			case REG_Q25:
			case REG_Q26:
			case REG_Q27:
			case REG_Q28:
			case REG_Q29:
			case REG_Q30:
			case REG_Q31:
				return RegisterInfo(REG_V0+(reg-REG_Q0), 0, 16);
			case REG_Z0:
			case REG_Z1:
			case REG_Z2:
			case REG_Z3:
			case REG_Z4:
			case REG_Z5:
			case REG_Z6:
			case REG_Z7:
			case REG_Z8:
			case REG_Z9:
			case REG_Z10:
			case REG_Z11:
			case REG_Z12:
			case REG_Z13:
			case REG_Z14:
			case REG_Z15:
			case REG_Z16:
			case REG_Z17:
			case REG_Z18:
			case REG_Z19:
			case REG_Z20:
			case REG_Z21:
			case REG_Z22:
			case REG_Z23:
			case REG_Z24:
			case REG_Z25:
			case REG_Z26:
			case REG_Z27:
			case REG_Z28:
			case REG_Z29:
			case REG_Z30:
			case REG_Z31:
				return RegisterInfo(REG_V0+(reg-REG_Z0), 0, 16);
			case REG_P0:
			case REG_P1:
			case REG_P2:
			case REG_P3:
			case REG_P4:
			case REG_P5:
			case REG_P6:
			case REG_P7:
			case REG_P8:
			case REG_P9:
			case REG_P10:
			case REG_P11:
			case REG_P12:
			case REG_P13:
			case REG_P14:
			case REG_P15:
			case REG_P16:
			case REG_P17:
			case REG_P18:
			case REG_P19:
			case REG_P20:
			case REG_P21:
			case REG_P22:
			case REG_P23:
			case REG_P24:
			case REG_P25:
			case REG_P26:
			case REG_P27:
			case REG_P28:
			case REG_P29:
			case REG_P30:
			case REG_P31:
				return RegisterInfo(reg, 0, 32);
		}

		if (reg >= REG_V0_B0 && reg <= REG_V31_B15) {
			uint32_t r = reg - REG_V0_B0;
			uint32_t v = r / 16;
			uint32_t idx = r % 16;
			return RegisterInfo(REG_V0 + v, idx, 1);
		}

		if (reg >= REG_V0_H0 && reg <= REG_V31_H7)
		{
			uint32_t r = reg - REG_V0_H0;
			uint32_t v = r / 8;
			uint32_t idx = r % 8;
			return RegisterInfo(REG_V0 + v, idx * 2, 2);
		}

		if (reg >= REG_V0_S0 && reg <= REG_V31_S3)
		{
			uint32_t r = reg - REG_V0_S0;
			uint32_t v = r / 4;
			uint32_t idx = r % 4;
			return RegisterInfo(REG_V0 + v, idx * 4, 4);
		}

		if (reg >= REG_V0_D0 && reg <= REG_V31_D1)
		{
			uint32_t r = reg - REG_V0_D0;
			uint32_t v = r / 2;
			uint32_t idx = r % 2;
			return RegisterInfo(REG_V0 + v, idx * 8, 8);
		}

		if (reg == FAKEREG_SYSREG_UNKNOWN)
			return RegisterInfo(reg, 0, 8);

		if (reg == FAKEREG_SYSCALL_INFO)
			return RegisterInfo(reg, 0, 4);

		if (reg > SYSREG_NONE && reg < SYSREG_END)
			return RegisterInfo(reg, 0, 8);

		return RegisterInfo(0, 0, 0);
	}

	virtual uint32_t GetStackPointerRegister() override { return REG_SP; }

	virtual uint32_t GetLinkRegister() override { return REG_X30; }

	virtual vector<uint32_t> GetSystemRegisters() override
	{
		vector<uint32_t> system_regs = {};

		for (uint32_t ii = SYSREG_NONE + 1; ii < SYSREG_END; ++ii)
		{
			system_regs.push_back(ii);
		}

		system_regs.push_back(FAKEREG_SYSREG_UNKNOWN);

		return system_regs;
	}
};


class Arm64ImportedFunctionRecognizer : public FunctionRecognizer
{
 private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		// Look for the following code pattern:
		// x16.q = plt
		// x17.q = [add.q(x16.q, pltoffset)].q || x17.q = [x16.q].q
		// x16.q = add.q(x16.q, pltoffset) || x16.q = x16.q
		// jump(x17.q)

		if (il->GetInstructionCount() < 4)
			return false;

		LowLevelILInstruction adrp = il->GetInstruction(0);
		if (adrp.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction adrpOperand = adrp.GetSourceExpr<LLIL_SET_REG>();
		if (!LowLevelILFunction::IsConstantType(adrpOperand.operation))
			return false;
		if (adrpOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		uint64_t pltPage = adrpOperand.GetConstant();
		uint32_t pltReg = adrp.GetDestRegister<LLIL_SET_REG>();

		LowLevelILInstruction ld = il->GetInstruction(1);
		if (ld.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction ldOperand = ld.GetSourceExpr<LLIL_SET_REG>();
		if (ldOperand.operation != LLIL_LOAD)
			return false;
		if (ldOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		LowLevelILInstruction ldAddrOperand = ldOperand.GetSourceExpr<LLIL_LOAD>();
		uint64_t entry = pltPage;
		uint64_t targetReg;
		int64_t ldAddrRightOperandValue = 0;
		if (ldAddrOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction ldAddrLeftOperand = ldAddrOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction ldAddrRightOperand = ldAddrOperand.GetRightExpr<LLIL_ADD>();
			if (ldAddrLeftOperand.operation != LLIL_REG)
				return false;
			if (ldAddrLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;

			if (!LowLevelILFunction::IsConstantType(ldAddrRightOperand.operation))
				return false;
			ldAddrRightOperandValue = ldAddrRightOperand.GetConstant();
			entry = pltPage + ldAddrRightOperandValue;
		}
		else if (ldAddrOperand.operation != LLIL_REG)  // If theres no constant
			return false;

		targetReg = ld.GetDestRegister<LLIL_SET_REG>();
		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym)
			return false;
		if (sym->GetType() != ImportAddressSymbol)
			return false;

		LowLevelILInstruction add = il->GetInstruction(2);
		if (add.operation != LLIL_SET_REG)
			return false;
		if (add.GetDestRegister<LLIL_SET_REG>() != pltReg)
			return false;
		LowLevelILInstruction addOperand = add.GetSourceExpr<LLIL_SET_REG>();

		if (addOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction addLeftOperand = addOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction addRightOperand = addOperand.GetRightExpr<LLIL_ADD>();
			if (addLeftOperand.operation != LLIL_REG)
				return false;
			if (addLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(addRightOperand.operation))
				return false;
			if (addRightOperand.GetConstant() != ldAddrRightOperandValue)
				return false;
		}
		else if ((addOperand.operation != LLIL_REG) ||
		         (addOperand.GetSourceRegister<LLIL_REG>() != pltReg))  // Simple assignment
			return false;

		LowLevelILInstruction jump = il->GetInstruction(3);
		if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
			return false;
		LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ?
                                            jump.GetDestExpr<LLIL_JUMP>() :
                                            jump.GetDestExpr<LLIL_TAILCALL>();
		if (jumpOperand.operation != LLIL_REG)
			return false;
		if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
			return false;

		Ref<Symbol> funcSym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(funcSym);
		func->ApplyImportedTypes(funcSym);
		return true;
	}


	bool RecognizeMachoPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		DataVariable target;

		if ((il->GetInstructionCount() == 2) || (il->GetInstructionCount() == 3))
		{
			// 0: nop OR x16 = symbol@PLT
			// 1: x16 = [symbol@PLT]
			// 2: jump(x16)
			size_t instrIndex = 0;
			if (il->GetInstructionCount() == 3)
			{
				// check that the first instruction is a nop
				LowLevelILInstruction insn = il->GetInstruction(instrIndex++);
				if ((insn.operation != LLIL_NOP) && (insn.operation != LLIL_SET_REG))
					return false;
			}

			// check that the second operation is a set register
			LowLevelILInstruction load = il->GetInstruction(instrIndex++);
			if (load.operation != LLIL_SET_REG)
				return false;

			// check that the rhs is a load operand
			LowLevelILInstruction loadOperand = load.GetSourceExpr<LLIL_SET_REG>();
			if (loadOperand.operation != LLIL_LOAD)
				return false;

			// ensure that the operand is the same size as the address
			if (loadOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;

			// ensure that what we are loading is a const
			RegisterValue loadAddrConstant = loadOperand.GetValue();
			if (loadAddrConstant.state != ImportedAddressValue)
				return false;

			// check if the type of symbol is a PLT symbol
			Ref<Symbol> sym = data->GetSymbolByAddress(loadAddrConstant.value);
			if (!sym ||
			    ((sym->GetType() != ImportAddressSymbol) && (sym->GetType() != ImportedDataSymbol)))
				return false;

			// we have what looks like a PLT entry, record the targetReg
			uint32_t targetReg = load.GetDestRegister<LLIL_SET_REG>();

			// ensure we have a jump instruction
			LowLevelILInstruction jump = il->GetInstruction(instrIndex++);
			if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
				return false;

			// ensure we are jumping to a register
			LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ?
                                              jump.GetDestExpr<LLIL_JUMP>() :
                                              jump.GetDestExpr<LLIL_TAILCALL>();
			if (jumpOperand.operation != LLIL_REG)
				return false;

			// is the jump target our target register?
			if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
				return false;

			data->GetDataVariableAtAddress(loadAddrConstant.value, target);

			Ref<Type> funcType = nullptr;
			if (target.type && target.type->GetClass() == PointerTypeClass &&
					target.type.GetConfidence() >= BN_MINIMUM_CONFIDENCE)
			{
				target.type = target.type->GetChildType();
				if (target.type && target.type->GetClass() == FunctionTypeClass &&
						target.type.GetConfidence() >= BN_MINIMUM_CONFIDENCE)
					funcType = target.type.GetValue();
			}

			data->DefineImportedFunction(sym, func, funcType);
			return true;
		}
		else if (il->GetInstructionCount() == 4)
		{
			// 0: x17 = symbol@PLT (hi)
			// 1: x17 = x17 + symbol@PLT (lo)
			// 2: x16 = [symbol@PLT]
			// 3: tailcall(x16)
			size_t instrIndex = 0;

			// check that the first operation is a set register
			LowLevelILInstruction setTemp = il->GetInstruction(instrIndex++);
			if (setTemp.operation != LLIL_SET_REG)
				return false;

			uint32_t tempReg = setTemp.GetDestRegister<LLIL_SET_REG>();

			// check that the rhs is a constant
			LowLevelILInstruction temp = setTemp.GetSourceExpr<LLIL_SET_REG>();
			if (!LowLevelILFunction::IsConstantType(temp.operation))
				return false;

			LowLevelILInstruction finalAddress = il->GetInstruction(instrIndex++);
			if (finalAddress.operation != LLIL_SET_REG)
				return false;

			if (tempReg != finalAddress.GetDestRegister<LLIL_SET_REG>())
				return false;

			// check that the second operation is a set register
			LowLevelILInstruction load = il->GetInstruction(instrIndex++);
			if (load.operation != LLIL_SET_REG)
				return false;

			// check that the rhs is a load operand
			LowLevelILInstruction loadOperand = load.GetSourceExpr<LLIL_SET_REG>();
			if (loadOperand.operation != LLIL_LOAD)
				return false;

			// ensure that the operand is the same size as the address
			if (loadOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;

			// ensure that what we are loading is a const
			LowLevelILInstruction loadAddrOperand = loadOperand.GetSourceExpr<LLIL_LOAD>();
			if (loadAddrOperand.operation != LLIL_REG ||
			    loadAddrOperand.GetSourceRegister<LLIL_REG>() != tempReg)
				return false;

			RegisterValue loadAddrConstant = loadOperand.GetValue();
			if (loadAddrConstant.state != ImportedAddressValue)
				return false;

			// check if the type of symbol is a PLT/GOT symbol
			Ref<Symbol> sym = data->GetSymbolByAddress(loadAddrConstant.value);
			if (!sym ||
			    ((sym->GetType() != ImportAddressSymbol) && (sym->GetType() != ImportedDataSymbol)))
				return false;

			// we have what looks like a PLT entry, record the targetReg
			uint32_t targetReg = load.GetDestRegister<LLIL_SET_REG>();

			// ensure we have a jump instruction
			LowLevelILInstruction jump = il->GetInstruction(instrIndex++);
			if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
				return false;

			// ensure we are jumping to a register
			LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ?
                                              jump.GetDestExpr<LLIL_JUMP>() :
                                              jump.GetDestExpr<LLIL_TAILCALL>();
			if (jumpOperand.operation != LLIL_REG)
				return false;

			// is the jump target our target register?
			if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
				return false;

			data->GetDataVariableAtAddress(loadAddrConstant.value, target);

			Ref<Type> funcType = nullptr;
			if (target.type && target.type->GetClass() == PointerTypeClass &&
					target.type.GetConfidence() >= BN_MINIMUM_CONFIDENCE)
			{
				target.type = target.type->GetChildType();
				if (target.type && target.type->GetClass() == FunctionTypeClass &&
						target.type.GetConfidence() >= BN_MINIMUM_CONFIDENCE)
					funcType = target.type.GetValue();
			}

			data->DefineImportedFunction(sym, func, funcType);
			return true;
		}

		return false;
	}


 public:
	virtual bool RecognizeLowLevelIL(
	    BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		else if (RecognizeMachoPLTEntries(data, func, il))
			return true;
		return false;
	}
};


class Arm64CallingConvention : public CallingConvention
{
 public:
	Arm64CallingConvention(Architecture* arch) : CallingConvention(arch, "cdecl") {}


	Arm64CallingConvention(Architecture* arch, const string& name): CallingConvention(arch, name)
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> {REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7};
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t> {REG_V0, REG_V1, REG_V2, REG_V3, REG_V4, REG_V5, REG_V6, REG_V7};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> {REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7, REG_X8,
		    REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15, REG_X16, REG_X17, REG_X18,
		    REG_X30, REG_V0, REG_V1, REG_V2, REG_V3, REG_V4, REG_V5, REG_V6, REG_V7, REG_V16, REG_V17,
		    REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23, REG_V24, REG_V25, REG_V26, REG_V27,
		    REG_V28, REG_V29, REG_V30, REG_V31};
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25, REG_X26,
		    REG_X27, REG_X28, REG_X29};
	}


	virtual uint32_t GetIntegerReturnValueRegister() override { return REG_X0; }


	virtual uint32_t GetFloatReturnValueRegister() override { return REG_V0; }
};


class AppleArm64CallingConvention: public Arm64CallingConvention
{
public:
	AppleArm64CallingConvention(Architecture* arch): Arm64CallingConvention(arch, "apple-arm64")
	{
	}


	virtual bool AreArgumentRegistersUsedForVarArgs() override
	{
		return false;
	}
};


class LinuxArm64SystemCallConvention: public CallingConvention
{
 public:
	LinuxArm64SystemCallConvention(Architecture* arch) : CallingConvention(arch, "linux-syscall") {}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> {REG_X8, REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override { return vector<uint32_t> {REG_X0}; }


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25, REG_X26,
		    REG_X27, REG_X28, REG_X29};
	}


	virtual uint32_t GetIntegerReturnValueRegister() override { return REG_X0; }


	virtual bool IsEligibleForHeuristics() override { return false; }
};

class WindowsArm64SystemCallConvention : public CallingConvention
{
 public:
	WindowsArm64SystemCallConvention(Architecture* arch) : CallingConvention(arch, "windows-syscall")
	{}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override { return {FAKEREG_SYSCALL_INFO}; }


	virtual vector<uint32_t> GetCallerSavedRegisters() override { return vector<uint32_t> {REG_X0}; }


	virtual vector<uint32_t> GetCalleeSavedRegisters() override { return {}; }


	virtual uint32_t GetIntegerReturnValueRegister() override { return REG_X0; }


	virtual bool IsEligibleForHeuristics() override { return false; }
};

class MacosArm64SystemCallConvention : public CallingConvention
{
 public:
	MacosArm64SystemCallConvention(Architecture* arch) : CallingConvention(arch, "macos-syscall") {}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t> {REG_X16, REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override { return vector<uint32_t> {REG_X0}; }


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25, REG_X26,
		    REG_X27, REG_X28, REG_X29};
	}


	virtual uint32_t GetIntegerReturnValueRegister() override { return REG_X0; }


	virtual bool IsEligibleForHeuristics() override { return false; }
};

#define PAGE(x)        (uint32_t)((x) >> 12)
#define PAGE_OFF(x)    (uint32_t)((x)&0xfff)
#define PAGE_NO_OFF(x) (uint32_t)((x)&0xFFFFF000)

class Arm64MachoRelocationHandler : public RelocationHandler
{
 public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc,
	    uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)arch;
		(void)len;

		uint32_t insword = *(uint32_t*)dest;
		auto info = reloc->GetInfo();

		// printf("insword: 0x%X\n", insword);
		// printf("reloc->GetTarget(): 0x%llX\n", reloc->GetTarget());
		// printf("reloc->GetAddress(): 0x%llX\n", reloc->GetAddress());

		if (info.nativeType == BINARYNINJA_MANUAL_RELOCATION)
		{  // Magic number defined in MachOView.cpp for tagged pointers
			*(uint64_t*)dest = info.target;
		}
		else if (info.nativeType == ARM64_RELOC_PAGE21)
		{
			// 21 bits across IMMHI:IMMLO
			// OP=1|IMMLO=XX|10000|IMMHI=XXXXXXXXXXXXXXXXXXX|RD=XXXXX
			int64_t page_delta = PAGE(reloc->GetTarget()) - PAGE(reloc->GetAddress());
			insword = insword & 0b10011111000000000000000000011111;
			insword = insword | ((page_delta & 3) << 29);  // IMMLO
			insword = insword | ((page_delta >> 2) << 5);  // IMMHI
			*(uint32_t*)dest = insword;
		}
		else if (info.nativeType == ARM64_RELOC_PAGEOFF12)
		{
			/* verify relocation point to qualifying instructions */
			if ((insword & 0x3B000000) != 0x39000000 && (insword & 0x11C00000) != 0x11000000)
				return false;

			/* verify it's a positive/forward jump (the imm12 is unsigned) */
			int64_t delta = reloc->GetTarget() - PAGE_NO_OFF(reloc->GetAddress());
			if (delta < 0)
				return false;

			/* disassemble instruction, is last operand an immediate? is there a shift? */
			Instruction instr;
			if (aarch64_decompose(*(uint32_t*)dest, &instr, reloc->GetAddress()) != 0)
				return false;

			int n_operands = 0;
			while (instr.operands[n_operands].operandClass != NONE)
				n_operands++;

			if (instr.operands[n_operands - 1].operandClass != IMM32 &&
			    instr.operands[n_operands - 1].operandClass != IMM64)
				return false;

			int left_shift = (instr.operands[n_operands - 1].shiftValueUsed) ?
                           instr.operands[n_operands - 1].shiftValue :
                           0;

			/* re-encode */
			/* left shift is upon DECODING, we right shift to bias this */
			delta = delta >> left_shift;
			// SF=X|OP=0|S=0|100010|SH=X|IMM12=XXXXXXXXXXXX|RN=XXXXX|RD=XXXXX
			uint16_t imm12 = (insword & 0x3FFC00) >> 10;
			imm12 = PAGE_OFF(imm12 + delta);
			insword = (insword & 0xFFC003FF) | (imm12 << 10);
			*(uint32_t*)dest = insword;
		}

		return true;
	}

	virtual bool GetRelocationInfo(
	    Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;

		set<MachoArm64RelocationType> unsupportedRelocations;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			switch (result[i].nativeType)
			{
			case ARM64_RELOC_UNSIGNED:
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = false;
				break;
			case ARM64_RELOC_SUBTRACTOR:
				if (i >= result.size() - 1 || result[i + 1].nativeType != ARM64_RELOC_UNSIGNED)
					return false;
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = true;
				break;
			case ARM64_RELOC_POINTER_TO_GOT:
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = false;
				break;
			case ARM64_RELOC_PAGE21:
				// eg: the number of pages to get to <addr> in "adrp x1, <addr>"
				// printf("GetRelocationInfo(): ARM64_RELOC_PAGE21 .address=0x%llX\n", result[i].address);
				break;
			case ARM64_RELOC_PAGEOFF12:
				// eg: the 12-bit <immediate> in "add x8, x8, #<immediate>"
				// printf("GetRelocationInfo(): ARM64_RELOC_PAGEOFF12 .address=0x%llX\n",
				// result[i].address);
				break;
			case ARM64_RELOC_BRANCH26:
			case ARM64_RELOC_GOT_LOAD_PAGE21:
			case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
			case ARM64_RELOC_TLVP_LOAD_PAGE21:
			case ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
			case ARM64_RELOC_ADDEND:
			default:
				result[i].type = UnhandledRelocation;
				unsupportedRelocations.insert((MachoArm64RelocationType)result[i].nativeType);
			}
		}

		for (auto& relocType : unsupportedRelocations)
			LogWarn("Unsupported relocation: %s (%x)", GetRelocationString(relocType), relocType);
		return true;
	}
};

/* structs used in relocation handling */
struct PC_REL_ADDRESSING
{
	uint32_t Rd : 5;
	int32_t immhi : 19;
	uint32_t group1 : 5;
	uint32_t immlo : 2;
	uint32_t op : 1;
};

struct ADD_SUB_IMM
{
	uint32_t Rd : 5;
	uint32_t Rn : 5;
	uint32_t imm : 12;
	uint32_t shift : 2;
	uint32_t group1 : 5;
	uint32_t S : 1;
	uint32_t op : 1;
	uint32_t sf : 1;
};

struct UNCONDITIONAL_BRANCH
{
	int32_t imm : 26;
	uint32_t opcode : 5;
	uint32_t op : 1;
};

struct CONDITIONAL_BRANCH{
	uint32_t cond:4;
	uint32_t o0:1;
	int32_t imm:19;
	uint32_t o1:1;
	uint32_t opcode:7;
};
struct COMPARE_AND_BRANCH{
	uint32_t Rt:5;
	int32_t imm:19;
	uint32_t op:1;
	uint32_t opcode:6;
	uint32_t sf:1;
};

struct TEST_AND_BRANCH{
	uint32_t Rt:5;
	int32_t imm:14;
	uint32_t b40:5;
	uint32_t op:1;
	uint32_t opcode:6;
	uint32_t b5:1;
};

struct LDST_REG_UNSIGNED_IMM{
	uint32_t Rt:5;
	uint32_t Rn:5;
	uint32_t imm:12;
	uint32_t opc:2;
	uint32_t group1:2;
	uint32_t V:1;
	uint32_t group2:3;
	uint32_t size:2;
};

struct MOV_WIDE_IMM{
    uint32_t Rd:5;
    uint32_t imm:16;
    uint32_t shift:2;
    uint32_t opcode:6;
    uint32_t variant:3;
};

class Arm64ElfRelocationHandler : public RelocationHandler
{
 public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc,
	    uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)arch;
		auto info = reloc->GetInfo();
		if (len < info.size)
			return false;
		uint64_t* dest64 = (uint64_t*)dest;
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		// auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x :
		// bswap32(x); };
		uint64_t target = reloc->GetTarget();
		Instruction inst;
		switch (info.nativeType)
		{
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			return true;
		case R_AARCH64_P32_COPY:
		case R_AARCH64_P32_GLOB_DAT:
		case R_AARCH64_P32_JUMP_SLOT:
			dest32[0] = target;
			break;
		case R_AARCH64_COPY:
		case R_AARCH64_GLOB_DAT:
		case R_AARCH64_JUMP_SLOT:
			dest64[0] = target;
			break;
		case R_AARCH64_ADR_PREL_LO21:
			break;
		case R_AARCH64_ADR_PREL_PG_HI21:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			uint32_t imm = PAGE(info.addend + target) - PAGE(reloc->GetAddress());
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		{
			ADD_SUB_IMM* decode = (ADD_SUB_IMM*)dest;
			aarch64_decompose(dest32[0], &inst, reloc->GetAddress());
			decode->imm = target + info.addend;
			break;
		}
		case R_AARCH64_CALL26:
		case R_AARCH64_JUMP26:
		{
			UNCONDITIONAL_BRANCH* decode = (UNCONDITIONAL_BRANCH*)dest;
			aarch64_decompose(dest32[0], &inst, 0);
			decode->imm = (target + info.addend - reloc->GetAddress()) >> 2;
			break;
		}
		case R_AARCH64_ABS16:
			dest16[0] = (uint16_t)(target + info.addend);
			break;
		case R_AARCH64_ABS32:
			dest32[0] = (uint32_t)(target + info.addend);
			break;
		case R_AARCH64_ABS64:
			dest64[0] = target + info.addend;
			break;
		case R_AARCH64_PREL16:
			dest16[0] = (uint16_t)(info.addend + target - reloc->GetAddress());
			break;
		case R_AARCH64_PREL32:
			dest32[0] = (uint32_t)(info.addend + target - reloc->GetAddress());
			break;
		case R_AARCH64_PREL64:
			dest64[0] = info.addend + target - reloc->GetAddress();
			break;
		case R_AARCH64_P32_RELATIVE:
			dest32[0] = target + info.addend;
			break;
		case R_AARCH64_RELATIVE:
			dest64[0] = target + info.addend;
			break;
		case R_AARCH64_LDST8_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xfff);
			break;
		}
		case R_AARCH64_LDST16_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xffe) >> 1;
			break;
		}
		case R_AARCH64_LDST32_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xffc) >> 2;
			break;
		}
		case R_AARCH64_LDST64_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff8) >> 3;
			break;
		}
		case R_AARCH64_LDST128_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff0) >> 4;
			break;
		}
		case R_AARCH64_ADR_GOT_PAGE:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			uint32_t imm = PAGE(info.addend + target) - PAGE(reloc->GetAddress());
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case R_AARCH64_LD64_GOT_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff8) >> 3;
			break;
		}
		case R_AARCH64_MOVW_UABS_G0:
		case R_AARCH64_MOVW_UABS_G0_NC:
		{
			MOV_WIDE_IMM* decode = (MOV_WIDE_IMM*)dest;
			decode->imm = (target + info.addend);
			break;
		}
		case R_AARCH64_MOVW_UABS_G1:
		case R_AARCH64_MOVW_UABS_G1_NC:
		{
			MOV_WIDE_IMM* decode = (MOV_WIDE_IMM*)dest;
			decode->imm = (target + info.addend)>>16;
			break;
		}
		case R_AARCH64_MOVW_UABS_G2:
		case R_AARCH64_MOVW_UABS_G2_NC:
		{
			MOV_WIDE_IMM* decode = (MOV_WIDE_IMM*)dest;
			decode->imm = (target + info.addend)>>32;
			break;
		}
		case R_AARCH64_MOVW_UABS_G3:
		{
			MOV_WIDE_IMM* decode = (MOV_WIDE_IMM*)dest;
			decode->imm = (target + info.addend)>>48;
			break;
		}
		case R_AARCH64_MOVW_SABS_G0:
		case R_AARCH64_MOVW_SABS_G1:
		case R_AARCH64_MOVW_SABS_G2:
		case R_AARCH64_LD_PREL_LO19:
		case R_AARCH64_TSTBR14:
		case R_AARCH64_CONDBR19:
		case R_AARCH64_MOVW_PREL_G0:
		case R_AARCH64_MOVW_PREL_G0_NC:
		case R_AARCH64_MOVW_PREL_G1:
		case R_AARCH64_MOVW_PREL_G1_NC:
		case R_AARCH64_MOVW_PREL_G2:
		case R_AARCH64_MOVW_PREL_G2_NC:
		case R_AARCH64_MOVW_PREL_G3:
		case R_AARCH64_TLS_TPREL64:
		case R_AARCH64_TLS_DTPREL32:
		case R_AARCH64_IRELATIVE:
			return false;
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		(void)result;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			switch (reloc.nativeType)
			{
			case R_AARCH64_P32_COPY:
				reloc.type = ELFCopyRelocationType;
				reloc.size = 4;
				break;
			case R_AARCH64_P32_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				reloc.size = 4;
				break;
			case R_AARCH64_P32_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				reloc.size = 4;
				break;
			case R_AARCH64_COPY:
				reloc.type = ELFCopyRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_ABS16:
				reloc.pcRelative = false;
				reloc.size = 2;
				break;
			case R_AARCH64_PREL16:
				reloc.pcRelative = true;
				reloc.size = 2;
				break;
			case R_AARCH64_PREL32:
			case R_AARCH64_ADR_PREL_PG_HI21:
			case R_AARCH64_CALL26:
			case R_AARCH64_JUMP26:
				reloc.pcRelative = true;
				reloc.size = 4;
				break;
			case R_AARCH64_PREL64:
				reloc.pcRelative = true;
				reloc.size = 8;
				break;
			case R_AARCH64_MOVW_UABS_G0:
			case R_AARCH64_MOVW_UABS_G0_NC:
			case R_AARCH64_MOVW_UABS_G1:
			case R_AARCH64_MOVW_UABS_G1_NC:
			case R_AARCH64_MOVW_UABS_G2:
			case R_AARCH64_MOVW_UABS_G2_NC:
			case R_AARCH64_MOVW_UABS_G3:
				reloc.size = 4;
				break;
			case R_AARCH64_ABS32:
			case R_AARCH64_ADD_ABS_LO12_NC:
			case R_AARCH64_LDST8_ABS_LO12_NC:
			case R_AARCH64_LDST16_ABS_LO12_NC:
			case R_AARCH64_LDST32_ABS_LO12_NC:
			case R_AARCH64_LDST64_ABS_LO12_NC:
			case R_AARCH64_LDST128_ABS_LO12_NC:
			case R_AARCH64_ADR_GOT_PAGE:
			case R_AARCH64_LD64_GOT_LO12_NC:
				reloc.pcRelative = false;
				reloc.size = 4;
				break;
			case R_AARCH64_ABS64:
				reloc.pcRelative = false;
				reloc.size = 8;
				break;
			case R_AARCH64_P32_RELATIVE:
				reloc.pcRelative = true;
				reloc.size = 4;
				break;
			case R_AARCH64_RELATIVE:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.size = 8;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((ElfArm64RelocationType)reloc));
		return true;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
	    Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
		auto info = relocation->GetInfo();
		switch (info.nativeType)
		{
		case R_AARCH64_ADR_PREL_PG_HI21:
			return BN_NOCOERCE_EXTERN_PTR;
		default:
			return BN_AUTOCOERCE_EXTERN_PTR;
		}
	}
};


class Arm64PeRelocationHandler : public RelocationHandler
{
 public:
	virtual bool GetRelocationInfo(
	    Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = UnhandledRelocation;
			relocTypes.insert(reloc.nativeType);
		}
		for (auto& reloc : relocTypes)
			LogWarn(
			    "Unsupported PE relocation type: %s", GetRelocationString((PeArm64RelocationType)reloc));
		return false;
	}
};


class Arm64COFFRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		// Note: info.base contains preferred base address and the base where the image is actually loaded
		(void)view;
		(void)arch;
		(void)len;
		BNRelocationInfo info = reloc->GetInfo();
		uint64_t target = reloc->GetTarget();
		uint64_t pc = info.pcRelative ? reloc->GetAddress() : 0;
		uint64_t base = (info.baseRelative && !target) ? view->GetStart() : 0;
		uint64_t address = info.address;
		uint64_t* dest64 = (uint64_t*)dest;
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		(void)pc;
		(void)base;
		(void)dest16;
		(void)dest64;
		Instruction inst;

		Ref<Architecture> associatedArch = arch->GetAssociatedArchitectureByAddress(address);

		if (len < info.size)
		{
			return false;
		}

		switch (info.nativeType)
		{
		case PE_IMAGE_REL_ARM64_REL21:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			uint32_t imm = info.addend + target - reloc->GetAddress();
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case PE_IMAGE_REL_ARM64_PAGEBASE_REL21:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			uint32_t imm = PAGE(info.addend + target) - PAGE(reloc->GetAddress());
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case PE_IMAGE_REL_ARM64_PAGEOFFSET_12A:
		{
			ADD_SUB_IMM* decode = (ADD_SUB_IMM*)dest;
			aarch64_decompose(dest32[0], &inst, reloc->GetAddress());
			decode->imm = inst.operands[2].immediate + target;
			break;
		}
		case PE_IMAGE_REL_ARM64_PAGEOFFSET_12L:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & (0xfff & ~decode->size)) >> decode->size;
			break;
		}
		case PE_IMAGE_REL_ARM64_BRANCH26:
		{
			UNCONDITIONAL_BRANCH* decode = (UNCONDITIONAL_BRANCH*)dest;
			aarch64_decompose(dest32[0], &inst, 0);
			decode->imm = (inst.operands[0].immediate + target - reloc->GetAddress()) >> 2;
			break;
		}
		case PE_IMAGE_REL_ARM64_BRANCH19:
		{
			// B.cond (CONDITIONAL_BRANCH) & CBZ / CBNZ (COMPARE_AND_BRANCH)
			CONDITIONAL_BRANCH* decode = (CONDITIONAL_BRANCH*)dest;
			aarch64_decompose(dest32[0], &inst, 0);
			decode->imm = (inst.operands[0].immediate + target - reloc->GetAddress()) >> 2;
			break;
		}
		case PE_IMAGE_REL_ARM64_BRANCH14:
		{
			// TBZ / TBNZ
			TEST_AND_BRANCH* decode = (TEST_AND_BRANCH*)dest;
			aarch64_decompose(dest32[0], &inst, 0);
			decode->imm = (inst.operands[0].immediate + target - reloc->GetAddress()) >> 2;
			break;
		}
		case PE_IMAGE_REL_ARM64_SECTION:
			// TODO: test this implementation, but for now, just don't warn about it
			dest16[0] = info.sectionIndex + 1;
			break;
		case PE_IMAGE_REL_ARM64_SECREL:
		{
			// TODO: test this implementation, but for now, just don't warn about it
			auto sections = view->GetSectionsAt(info.target);
			if (sections.size() > 0)
			{
				dest32[0] = info.target - sections[0]->GetStart();
			}
			break;
		}
		case PE_IMAGE_REL_ARM64_ADDR32NB:
		case PE_IMAGE_REL_ARM64_ADDR64:
		case IMAGE_REL_ARM64_REL32:
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
		for (auto& reloc : result)
		{
			// LogDebug("%s COFF relocation %s at 0x%" PRIx64, __func__, GetRelocationString((PeArm64RelocationType)reloc.nativeType), reloc.address);
			switch (reloc.nativeType)
			{
			case PE_IMAGE_REL_ARM64_ABSOLUTE:
				reloc.type = IgnoredRelocation;
				break;
			case PE_IMAGE_REL_ARM64_ADDR32NB:
				reloc.pcRelative = false;
				reloc.baseRelative = false;
				break;
			case PE_IMAGE_REL_ARM64_BRANCH26:
			case PE_IMAGE_REL_ARM64_PAGEBASE_REL21:
			case PE_IMAGE_REL_ARM64_REL21:
			case PE_IMAGE_REL_ARM64_PAGEOFFSET_12A:
			case PE_IMAGE_REL_ARM64_BRANCH19:
			case PE_IMAGE_REL_ARM64_BRANCH14:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.size = 4;
				break;
			case PE_IMAGE_REL_ARM64_PAGEOFFSET_12L:
				if (! reloc.external)
					reloc.addend = 6;
				break;
			case PE_IMAGE_REL_ARM64_ADDR64:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.size = 8;
				break;
			case PE_IMAGE_REL_ARM64_ADDR32:
				reloc.pcRelative = false;
				reloc.baseRelative = true;
				reloc.size = 4;
				break;
			case IMAGE_REL_ARM64_REL32:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.size = 4;
				break;
			case PE_IMAGE_REL_ARM64_SECTION:
				// The 16-bit section index of the section that contains the target. This is used to support debugging information.
				reloc.baseRelative = false;
				reloc.size = 2;
				reloc.addend = 0;
				break;
			case PE_IMAGE_REL_ARM64_SECREL:
				// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.				reloc.baseRelative = false;
				reloc.baseRelative = false;
				reloc.size = 4;
				reloc.addend = 0;
				break;
			case PE_IMAGE_REL_ARM64_SECREL_LOW12A:
				// TODO
			case PE_IMAGE_REL_ARM64_SECREL_HIGH12A:
				// TODO
			case PE_IMAGE_REL_ARM64_SECREL_LOW12L:
				// TODO
			case PE_IMAGE_REL_ARM64_TOKEN:
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported PE relocation type: %s", GetRelocationString((PeArm64RelocationType)reloc));
		return false;
	}
};


static void InitAarch64Settings()
{
	Ref<Settings> settings = Settings::Instance();

	settings->RegisterSetting("arch.aarch64.disassembly.alignRequired",
			R"({
			"title" : "AARCH64 Alignment Requirement",
			"type" : "boolean",
			"default" : true,
			"description" : "Require instructions be on 4-byte aligned addresses to be disassembled."
			})");
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_macho");
		AddOptionalPluginDependency("view_pe");
	}
#endif

#ifdef DEMO_VERSION
	bool Arm64PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitAarch64Settings();

		Architecture* arm64 = new Arm64Architecture();

		Architecture::Register(arm64);

		// Register calling convention
		Ref<CallingConvention> conv;
		conv = new Arm64CallingConvention(arm64);
		arm64->RegisterCallingConvention(conv);
		arm64->SetDefaultCallingConvention(conv);
		arm64->SetCdeclCallingConvention(conv);
		arm64->SetFastcallCallingConvention(conv);
		arm64->SetStdcallCallingConvention(conv);

		conv = new LinuxArm64SystemCallConvention(arm64);
		arm64->RegisterCallingConvention(conv);

		conv = new WindowsArm64SystemCallConvention(arm64);
		arm64->RegisterCallingConvention(conv);

		conv = new AppleArm64CallingConvention(arm64);
		arm64->RegisterCallingConvention(conv);

		// Register ARM64 specific PLT trampoline recognizer
		arm64->RegisterFunctionRecognizer(new Arm64ImportedFunctionRecognizer());

		// Register ARM64 Relocation handlers
		arm64->RegisterRelocationHandler("Mach-O", new Arm64MachoRelocationHandler());
		arm64->RegisterRelocationHandler("ELF", new Arm64ElfRelocationHandler());
		arm64->RegisterRelocationHandler("PE", new Arm64PeRelocationHandler());
		arm64->RegisterRelocationHandler("COFF", new Arm64COFFRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file
		BinaryViewType::RegisterArchitecture("Mach-O", 0x0100000c, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("Mach-O", 0x0200000c, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("ELF", 0xb7, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("ELF", 0xb7, BigEndian, arm64);
		BinaryViewType::RegisterArchitecture("COFF", 0xaa64, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("PE", 0xaa64, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("PE", 0xaa64, BigEndian, arm64);

		return true;
	}
}

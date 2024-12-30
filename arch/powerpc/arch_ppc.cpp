#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <map>
#include <vector>

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
// #define MYLOG BinaryNinja::LogWarn
// #define MYLOG printf

#include "lowlevelilinstruction.h"
using namespace BinaryNinja; // for ::LogDebug, etc.

#include "assembler.h"

#include "decode/decode.h"

#include "il.h"
#include "util.h"

using namespace std;

enum MachoPpcRelocationType
{
	PPC_RELOC_VANILLA = 0,
	PPC_RELOC_PAIR = 1,
	PPC_RELOC_BR14 = 2,
	PPC_RELOC_BR24 = 3,
	PPC_RELOC_HI16 = 4,
	PPC_RELOC_LO16 = 5,
	PPC_RELOC_HA16 = 6,
	PPC_RELOC_LO14 = 7,
	PPC_RELOC_SECTDIFF = 8,
	PPC_RELOC_PB_LA_PTR = 9,
	PPC_RELOC_HI16_SECTDIFF = 10,
	PPC_RELOC_LO16_SECTDIFF = 11,
	PPC_RELOC_HA16_SECTDIFF = 12,
	PPC_RELOC_JBSR = 13,
	PPC_RELOC_LO14_SECTDIFF = 14,
	PPC_RELOC_LOCAL_SECTDIFF = 15,
	MAX_MACHO_PPC_RELOCATION
};

enum ElfPpcRelocationType
{
	R_PPC_NONE            = 0,
	R_PPC_ADDR32          = 1, // 32bit absolute address
	R_PPC_ADDR24          = 2, // 26bit address, 2 bits ignored
	R_PPC_ADDR16          = 3, // 16bit absolute address
	R_PPC_ADDR16_LO       = 4, // lower 16bit of absolute address
	R_PPC_ADDR16_HI       = 5, // high 16bit of absolute address
	R_PPC_ADDR16_HA       = 6, // adjusted high 16bit
	R_PPC_ADDR14          = 7, // 16bit address, 2 bits ignored
	R_PPC_ADDR14_BRTAKEN  = 8,
	R_PPC_ADDR14_BRNTAKEN = 9,
	R_PPC_REL24           = 10, // PC relative 26 bit
	R_PPC_REL14           = 11, // PC relative 16 bit
	R_PPC_REL14_BRTAKEN   = 12,
	R_PPC_REL14_BRNTAKEN  = 13,
	R_PPC_GOT16           = 14,
	R_PPC_GOT16_LO        = 15,
	R_PPC_GOT16_HI        = 16,
	R_PPC_GOT16_HA        = 17,
	R_PPC_PLTREL24        = 18,
	R_PPC_COPY            = 19,
	R_PPC_GLOB_DAT        = 20,
	R_PPC_JMP_SLOT        = 21,
	R_PPC_RELATIVE        = 22,
	R_PPC_LOCAL24PC       = 23,
	R_PPC_UADDR32         = 24,
	R_PPC_UADDR16         = 25,
	R_PPC_REL32           = 26,
	R_PPC_PLT32           = 27,
	R_PPC_PLTREL32        = 28,
	R_PPC_PLT16_LO        = 29,
	R_PPC_PLT16_HI        = 30,
	R_PPC_PLT16_HA        = 31,
	R_PPC_SDAREL16        = 32,
	R_PPC_SECTOFF         = 33,
	R_PPC_SECTOFF_LO      = 34,
	R_PPC_SECTOFF_HI      = 35,
	R_PPC_SECTOFF_HA      = 36,
	// PowerPC relocations defined for the TLS access ABI.
	R_PPC_TLS             = 67, // none	(sym+add)@tls
	R_PPC_DTPMOD32        = 68, // word32	(sym+add)@dtpmod
	R_PPC_TPREL16         = 69, // half16*	(sym+add)@tprel
	R_PPC_TPREL16_LO      = 70, // half16	(sym+add)@tprel@l
	R_PPC_TPREL16_HI      = 71, // half16	(sym+add)@tprel@h
	R_PPC_TPREL16_HA      = 72, // half16	(sym+add)@tprel@ha
	R_PPC_TPREL32         = 73, // word32	(sym+add)@tprel
	R_PPC_DTPREL16        = 74, // half16*	(sym+add)@dtprel
	R_PPC_DTPREL16_LO     = 75, // half16	(sym+add)@dtprel@l
	R_PPC_DTPREL16_HI     = 76, // half16	(sym+add)@dtprel@h
	R_PPC_DTPREL16_HA     = 77, // half16	(sym+add)@dtprel@ha
	R_PPC_DTPREL32        = 78, // word32	(sym+add)@dtprel
	R_PPC_GOT_TLSGD16     = 79, // half16*	(sym+add)@got@tlsgd
	R_PPC_GOT_TLSGD16_LO  = 80, // half16	(sym+add)@got@tlsgd@l
	R_PPC_GOT_TLSGD16_HI  = 81, // half16	(sym+add)@got@tlsgd@h
	R_PPC_GOT_TLSGD16_HA  = 82, // half16	(sym+add)@got@tlsgd@ha
	R_PPC_GOT_TLSLD16     = 83, // half16*	(sym+add)@got@tlsld
	R_PPC_GOT_TLSLD16_LO  = 84, // half16	(sym+add)@got@tlsld@l
	R_PPC_GOT_TLSLD16_HI  = 85, // half16	(sym+add)@got@tlsld@h
	R_PPC_GOT_TLSLD16_HA  = 86, // half16	(sym+add)@got@tlsld@ha
	R_PPC_GOT_TPREL16     = 87, // half16*	(sym+add)@got@tprel
	R_PPC_GOT_TPREL16_LO  = 88, // half16	(sym+add)@got@tprel@l
	R_PPC_GOT_TPREL16_HI  = 89, // half16	(sym+add)@got@tprel@h
	R_PPC_GOT_TPREL16_HA  = 90, // half16	(sym+add)@got@tprel@ha
	R_PPC_GOT_DTPREL16    = 91, // half16*	(sym+add)@got@dtprel
	R_PPC_GOT_DTPREL16_LO = 92, // half16*	(sym+add)@got@dtprel@l
	R_PPC_GOT_DTPREL16_HI = 93, // half16*	(sym+add)@got@dtprel@h
	R_PPC_GOT_DTPREL16_HA = 94, // half16*	(sym+add)@got@dtprel@ha

	// Embedded ELF ABI, and are not in the SVR4 ELF ABI.
	R_PPC_EMB_NADDR32       = 101,
	R_PPC_EMB_NADDR16       = 102,
	R_PPC_EMB_NADDR16_LO    = 103,
	R_PPC_EMB_NADDR16_HI    = 104,
	R_PPC_EMB_NADDR16_HA    = 105,
	R_PPC_EMB_SDAI16        = 106,
	R_PPC_EMB_SDA2I16       = 107,
	R_PPC_EMB_SDA2REL       = 108,
	R_PPC_EMB_SDA21         = 109,     // 16 bit offset in SDA
	R_PPC_EMB_MRKREF        = 110,
	R_PPC_EMB_RELSEC16      = 111,
	R_PPC_EMB_RELST_LO      = 112,
	R_PPC_EMB_RELST_HI      = 113,
	R_PPC_EMB_RELST_HA      = 114,
	R_PPC_EMB_BIT_FLD       = 115,
	R_PPC_EMB_RELSDA        = 116,     // 16 bit relative offset in SDA
	// Diab tool relocations.
	R_PPC_DIAB_SDA21_LO     = 180,     // like EMB_SDA21, but lower 16 bit
	R_PPC_DIAB_SDA21_HI     = 181,     // like EMB_SDA21, but high 16 bit
	R_PPC_DIAB_SDA21_HA     = 182,     // like EMB_SDA21, adjusted high 16
	R_PPC_DIAB_RELSDA_LO    = 183,     // like EMB_RELSDA, but lower 16 bit
	R_PPC_DIAB_RELSDA_HI    = 184,     // like EMB_RELSDA, but high 16 bit
	R_PPC_DIAB_RELSDA_HA    = 185,     // like EMB_RELSDA, adjusted high 16
	// GNU extension to support local ifunc.
	R_PPC_IRELATIVE         = 248,
	// GNU relocs used in PIC code sequences.
	R_PPC_REL16             = 249,     // half16   (sym+add-.)
	R_PPC_REL16_LO          = 250,     // half16   (sym+add-.)@l
	R_PPC_REL16_HI          = 251,     // half16   (sym+add-.)@h
	R_PPC_REL16_HA          = 252,     // half16   (sym+add-.)@ha
	// This is a phony reloc to handle any old fashioned TOC16 references that may still be in object files.
	R_PPC_TOC16             = 255,
	MAX_ELF_PPC_RELOCATION
};

static const char* GetRelocationString(MachoPpcRelocationType relocType)
{
	static const char* relocTable[] =
	{
		"PPC_RELOC_VANILLA",
		"PPC_RELOC_PAIR",
		"PPC_RELOC_BR14",
		"PPC_RELOC_BR24",
		"PPC_RELOC_HI16",
		"PPC_RELOC_LO16",
		"PPC_RELOC_HA16",
		"PPC_RELOC_LO14",
		"PPC_RELOC_SECTDIFF",
		"PPC_RELOC_PB_LA_PTR",
		"PPC_RELOC_HI16_SECTDIFF",
		"PPC_RELOC_LO16_SECTDIFF",
		"PPC_RELOC_HA16_SECTDIFF",
		"PPC_RELOC_JBSR",
		"PPC_RELOC_LO14_SECTDIFF",
		"PPC_RELOC_LOCAL_SECTDIFF"
	};
	if (relocType >= PPC_RELOC_VANILLA && relocType < MAX_MACHO_PPC_RELOCATION)
		return relocTable[relocType];
	return "Unknown PPC relocation";
}

#define HA(x) (uint16_t)((((x) >> 16) + (((x) & 0x8000) ? 1 : 0)) & 0xffff)

static const char* GetRelocationString(ElfPpcRelocationType relocType)
{
	static map<ElfPpcRelocationType, const char*> relocTable = {
		{R_PPC_NONE, "R_PPC_NONE"},
		{R_PPC_ADDR32, "R_PPC_ADDR32"},
		{R_PPC_ADDR24, "R_PPC_ADDR24"},
		{R_PPC_ADDR16, "R_PPC_ADDR16"},
		{R_PPC_ADDR16_LO, "R_PPC_ADDR16_LO"},
		{R_PPC_ADDR16_HI, "R_PPC_ADDR16_HI"},
		{R_PPC_ADDR16_HA, "R_PPC_ADDR16_HA"},
		{R_PPC_ADDR14, "R_PPC_ADDR14"},
		{R_PPC_ADDR14_BRTAKEN, "R_PPC_ADDR14_BRTAKEN"},
		{R_PPC_ADDR14_BRNTAKEN, "R_PPC_ADDR14_BRNTAKEN"},
		{R_PPC_REL24, "R_PPC_REL24"},
		{R_PPC_REL14, "R_PPC_REL14"},
		{R_PPC_REL14_BRTAKEN, "R_PPC_REL14_BRTAKEN"},
		{R_PPC_REL14_BRNTAKEN, "R_PPC_REL14_BRNTAKEN"},
		{R_PPC_GOT16, "R_PPC_GOT16"},
		{R_PPC_GOT16_LO, "R_PPC_GOT16_LO"},
		{R_PPC_GOT16_HI, "R_PPC_GOT16_HI"},
		{R_PPC_GOT16_HA, "R_PPC_GOT16_HA"},
		{R_PPC_PLTREL24, "R_PPC_PLTREL24"},
		{R_PPC_COPY, "R_PPC_COPY"},
		{R_PPC_GLOB_DAT, "R_PPC_GLOB_DAT"},
		{R_PPC_JMP_SLOT, "R_PPC_JMP_SLOT"},
		{R_PPC_RELATIVE, "R_PPC_RELATIVE"},
		{R_PPC_LOCAL24PC, "R_PPC_LOCAL24PC"},
		{R_PPC_UADDR32, "R_PPC_UADDR32"},
		{R_PPC_UADDR16, "R_PPC_UADDR16"},
		{R_PPC_REL32, "R_PPC_REL32"},
		{R_PPC_PLT32, "R_PPC_PLT32"},
		{R_PPC_PLTREL32, "R_PPC_PLTREL32"},
		{R_PPC_PLT16_LO, "R_PPC_PLT16_LO"},
		{R_PPC_PLT16_HI, "R_PPC_PLT16_HI"},
		{R_PPC_PLT16_HA, "R_PPC_PLT16_HA"},
		{R_PPC_SDAREL16, "R_PPC_SDAREL16"},
		{R_PPC_SECTOFF, "R_PPC_SECTOFF"},
		{R_PPC_SECTOFF_LO, "R_PPC_SECTOFF_LO"},
		{R_PPC_SECTOFF_HI, "R_PPC_SECTOFF_HI"},
		{R_PPC_SECTOFF_HA, "R_PPC_SECTOFF_HA"},
		{R_PPC_TLS, "R_PPC_TLS"},
		{R_PPC_DTPMOD32, "R_PPC_DTPMOD32"},
		{R_PPC_TPREL16, "R_PPC_TPREL16"},
		{R_PPC_TPREL16_LO, "R_PPC_TPREL16_LO"},
		{R_PPC_TPREL16_HI, "R_PPC_TPREL16_HI"},
		{R_PPC_TPREL16_HA, "R_PPC_TPREL16_HA"},
		{R_PPC_TPREL32, "R_PPC_TPREL32"},
		{R_PPC_DTPREL16, "R_PPC_DTPREL16"},
		{R_PPC_DTPREL16_LO, "R_PPC_DTPREL16_LO"},
		{R_PPC_DTPREL16_HI, "R_PPC_DTPREL16_HI"},
		{R_PPC_DTPREL16_HA, "R_PPC_DTPREL16_HA"},
		{R_PPC_DTPREL32, "R_PPC_DTPREL32"},
		{R_PPC_GOT_TLSGD16, "R_PPC_GOT_TLSGD16"},
		{R_PPC_GOT_TLSGD16_LO, "R_PPC_GOT_TLSGD16_LO"},
		{R_PPC_GOT_TLSGD16_HI, "R_PPC_GOT_TLSGD16_HI"},
		{R_PPC_GOT_TLSGD16_HA, "R_PPC_GOT_TLSGD16_HA"},
		{R_PPC_GOT_TLSLD16, "R_PPC_GOT_TLSLD16"},
		{R_PPC_GOT_TLSLD16_LO, "R_PPC_GOT_TLSLD16_LO"},
		{R_PPC_GOT_TLSLD16_HI, "R_PPC_GOT_TLSLD16_HI"},
		{R_PPC_GOT_TLSLD16_HA, "R_PPC_GOT_TLSLD16_HA"},
		{R_PPC_GOT_TPREL16, "R_PPC_GOT_TPREL16"},
		{R_PPC_GOT_TPREL16_LO, "R_PPC_GOT_TPREL16_LO"},
		{R_PPC_GOT_TPREL16_HI, "R_PPC_GOT_TPREL16_HI"},
		{R_PPC_GOT_TPREL16_HA, "R_PPC_GOT_TPREL16_HA"},
		{R_PPC_GOT_DTPREL16, "R_PPC_GOT_DTPREL16"},
		{R_PPC_GOT_DTPREL16_LO, "R_PPC_GOT_DTPREL16_LO"},
		{R_PPC_GOT_DTPREL16_HI, "R_PPC_GOT_DTPREL16_HI"},
		{R_PPC_GOT_DTPREL16_HA, "R_PPC_GOT_DTPREL16_HA"},
		{R_PPC_EMB_NADDR32, "R_PPC_EMB_NADDR32"},
		{R_PPC_EMB_NADDR16, "R_PPC_EMB_NADDR16"},
		{R_PPC_EMB_NADDR16_LO, "R_PPC_EMB_NADDR16_LO"},
		{R_PPC_EMB_NADDR16_HI, "R_PPC_EMB_NADDR16_HI"},
		{R_PPC_EMB_NADDR16_HA, "R_PPC_EMB_NADDR16_HA"},
		{R_PPC_EMB_SDAI16, "R_PPC_EMB_SDAI16"},
		{R_PPC_EMB_SDA2I16, "R_PPC_EMB_SDA2I16"},
		{R_PPC_EMB_SDA2REL, "R_PPC_EMB_SDA2REL"},
		{R_PPC_EMB_SDA21, "R_PPC_EMB_SDA21"},
		{R_PPC_EMB_MRKREF, "R_PPC_EMB_MRKREF"},
		{R_PPC_EMB_RELSEC16, "R_PPC_EMB_RELSEC16"},
		{R_PPC_EMB_RELST_LO, "R_PPC_EMB_RELST_LO"},
		{R_PPC_EMB_RELST_HI, "R_PPC_EMB_RELST_HI"},
		{R_PPC_EMB_RELST_HA, "R_PPC_EMB_RELST_HA"},
		{R_PPC_EMB_BIT_FLD, "R_PPC_EMB_BIT_FLD"},
		{R_PPC_EMB_RELSDA, "R_PPC_EMB_RELSDA"},
		{R_PPC_DIAB_SDA21_LO, "R_PPC_DIAB_SDA21_LO"},
		{R_PPC_DIAB_SDA21_HI, "R_PPC_DIAB_SDA21_HI"},
		{R_PPC_DIAB_SDA21_HA, "R_PPC_DIAB_SDA21_HA"},
		{R_PPC_DIAB_RELSDA_LO, "R_PPC_DIAB_RELSDA_LO"},
		{R_PPC_DIAB_RELSDA_HI, "R_PPC_DIAB_RELSDA_HI"},
		{R_PPC_DIAB_RELSDA_HA, "R_PPC_DIAB_RELSDA_HA"},
		{R_PPC_IRELATIVE, "R_PPC_IRELATIVE"},
		{R_PPC_REL16, "R_PPC_REL16"},
		{R_PPC_REL16_LO, "R_PPC_REL16_LO"},
		{R_PPC_REL16_HI, "R_PPC_REL16_HI"},
		{R_PPC_REL16_HA, "R_PPC_REL16_HA"},
		{R_PPC_TOC16, "R_PPC_TOC16"}
	};
	if (relocTable.count(relocType))
		return relocTable.at(relocType);
	return "Unknown PPC relocation";
}

/* class Architecture from binaryninjaapi.h */
class PowerpcArchitecture: public Architecture
{
	private:
	BNEndianness endian;
	size_t addressSize;
	uint32_t decodeFlags;

	/* this can maybe be moved to the API later */
	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}

	public:

	/* initialization list */
	PowerpcArchitecture(const char* name, BNEndianness endian_, size_t addressSize_=4, uint32_t decodeFlags_=DECODE_FLAGS_ALTIVEC | DECODE_FLAGS_VSX): Architecture(name)
	{
		endian = endian_;
		addressSize = addressSize_;
		decodeFlags = decodeFlags_;
		if (addressSize == 8)
			decodeFlags |= DECODE_FLAGS_PPC64;
	}

	/*************************************************************************/

	virtual BNEndianness GetEndianness() const override
	{
		//MYLOG("%s()\n", __func__);
		return endian;
	}

	virtual size_t GetAddressSize() const override
	{
		//MYLOG("%s()\n", __func__);
		return addressSize;
	}

	virtual size_t GetDefaultIntegerSize() const override
	{
		MYLOG("%s()\n", __func__);
		return addressSize;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
	}

	bool FillInstruction(Instruction* instruction, const uint8_t* data, size_t length, uint64_t address)
	{
		switch (length)
		{
			case 4:
			{
				uint32_t word32 = *(const uint32_t *) data;

				if (endian == BigEndian)
					word32 = bswap32(word32);

				return Decompose32(instruction, word32, address, decodeFlags);
			}

			default:
				MYLOG("FillInstruction: unrecognized length %d", length);
				return false;
		}
	}

	/* think "GetInstructionBranchBehavior()"

	   populates struct Instruction Info (api/binaryninjaapi.h)
	   which extends struct BNInstructionInfo (core/binaryninjacore.h)

	   tasks:
		1) set the length
		2) invoke AddBranch() for every non-sequential execution possibility

	   */
	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr,
		size_t maxLen, InstructionInfo& result) override
	{
		size_t instructionLength = GetInstructionLength(data, maxLen, decodeFlags);
		if (instructionLength == 0)
		{
			MYLOG("ERROR: not enough bytes for instruction\n");
			return false;
		}

		result.length = instructionLength;

		Instruction instruction;
		if (!FillInstruction(&instruction, data, instructionLength, addr))
		{
			MYLOG("ERROR: FillInstruction()\n");
			return false;
		}

		switch (instruction.id)
		{
			case PPC_ID_Bx:
			{
				uint64_t target = instruction.operands[0].label;

				if (instruction.flags.lk)
					result.AddBranch(CallDestination, target);
				else
					result.AddBranch(UnconditionalBranch, target);

				break;
			}

			case PPC_ID_BCx:
			{
				uint32_t bo = instruction.operands[0].uimm;
				uint64_t target = instruction.operands[2].label;

				if (target != addr + 4)
				{
					if ((bo & 0x14) == 0x14)
					{
						result.AddBranch(instruction.flags.lk ? CallDestination : UnconditionalBranch, target);
					}
					else if (!instruction.flags.lk)
					{
						result.AddBranch(FalseBranch, addr + 4);
						result.AddBranch(TrueBranch, target);
					}
				}

				break;
			}

			case PPC_ID_BCLRx:
				if (!instruction.flags.lk)
					result.AddBranch(FunctionReturn);
				else
					result.AddBranch(UnresolvedBranch);

				break;

			case PPC_ID_BCCTRx:
				result.AddBranch(UnresolvedBranch);
				break;

			case PPC_ID_TWU:
				result.AddBranch(UnresolvedBranch);
				break;

			case PPC_ID_RFI:
				result.AddBranch(UnresolvedBranch);
				break;
		}

		return true;
	}

	// Returns whether any token was pushed (ie if operand is implied)
	bool PushOperandTokens(vector<InstructionTextToken>& result, const Operand* op)
	{
		char buf[32];
		switch (op->cls)
		{
			case PPC_OP_REG_CRFD_IMPLY0:
			case PPC_OP_REG_CRFS_IMPLY0:
				if (op->reg == PPC_REG_CRF0)
					return false;

				result.emplace_back(RegisterToken, GetRegisterName(op->reg));

				break;

			case PPC_OP_REG_RA:
			case PPC_OP_REG_RB:
			case PPC_OP_REG_RD:
			case PPC_OP_REG_RS:
			case PPC_OP_REG_FRA:
			case PPC_OP_REG_FRB:
			case PPC_OP_REG_FRC:
			case PPC_OP_REG_FRD:
			case PPC_OP_REG_FRS:
			case PPC_OP_REG_CRFD:
			case PPC_OP_REG_CRFS:
			case PPC_OP_REG_AV_VA:
			case PPC_OP_REG_AV_VB:
			case PPC_OP_REG_AV_VC:
			case PPC_OP_REG_AV_VD:
			case PPC_OP_REG_AV_VS:
			case PPC_OP_REG_VSX_RA:
			case PPC_OP_REG_VSX_RA_DWORD0:
			case PPC_OP_REG_VSX_RB:
			case PPC_OP_REG_VSX_RB_DWORD0:
			case PPC_OP_REG_VSX_RC:
			case PPC_OP_REG_VSX_RC_DWORD0:
			case PPC_OP_REG_VSX_RD:
			case PPC_OP_REG_VSX_RD_DWORD0:
			case PPC_OP_REG_VSX_RS:
			case PPC_OP_REG_VSX_RS_DWORD0:
				result.emplace_back(RegisterToken, GetRegisterName(op->reg));
				break;

			case PPC_OP_UIMM:
				snprintf(buf, sizeof(buf), "0x%x", op->uimm);
				result.emplace_back(IntegerToken, buf,  op->uimm, 4);
				break;

			case PPC_OP_SIMM:
				if (op->simm < 0 && op->simm > -0x10000)
					snprintf(buf, sizeof(buf), "-0x%llx", -op->simm);
				else
					snprintf(buf, sizeof(buf), "0x%llx", op->simm);
				result.emplace_back(IntegerToken, buf, op->simm, 4);
				break;

			case PPC_OP_LABEL:
				snprintf(buf, sizeof(buf), "0x%llx", op->label);
				result.emplace_back(CodeRelativeAddressToken, buf, op->label, 4);
				break;

			case PPC_OP_CRBIT_A:
			case PPC_OP_CRBIT_B:
			case PPC_OP_CRBIT_D:
				result.emplace_back(RegisterToken, GetCRBitName(op->crbit));
				break;

			case PPC_OP_MEM_RA:
				// eg: lwz r11, 8(r11)
				//
				// TODO: it would be nice to have the option to print these
				//       in hex; printed in decimal now for backwards compatibility
				snprintf(buf, sizeof(buf), "%d", op->mem.offset);
				result.emplace_back(IntegerToken, buf, op->mem.offset, 4);

				result.emplace_back(BraceToken, "(");
				if (op->mem.reg == PPC_REG_GPR0)
					result.emplace_back(PossibleAddressToken, "0", 0, 4);
				else
					result.emplace_back(RegisterToken, GetRegisterName(op->mem.reg));
				result.emplace_back(BraceToken, ")");
				break;

			default:
				//MYLOG("pushing a ???\n");
				result.emplace_back(TextToken, "???");
		}

		return true;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		bool rc = false;
		char buf[32];
		size_t strlenMnem;
		Instruction instruction;
		const char* mnemonic = NULL;

		//MYLOG("%s()\n", __func__);
		size_t instructionLength = GetInstructionLength(data, len, decodeFlags);
		if (instructionLength == 0)
		{
			MYLOG("ERROR: not enough bytes for instruction\n");
			return false;
		}

		len = instructionLength;
		if (!FillInstruction(&instruction, data, instructionLength, addr))
		{
			MYLOG("ERROR: FillInstruction()\n");
			return false;
		}

		/* mnemonic */
		mnemonic = GetMnemonic(&instruction);
		result.emplace_back(InstructionToken, mnemonic);

		/* padding between mnemonic and operands */
		memset(buf, ' ', 8);
		strlenMnem = strlen(mnemonic);
		if (strlenMnem < 8)
			buf[8-strlenMnem] = '\0';
		else
			buf[1] = '\0';
		result.emplace_back(TextToken, buf);

		// To make IL easier to reason about, sometimes an instruction's
		// internal representation always has an operand that's omitted
		// in assembly; we take care of overriding those cases here
		OperandsList operand_list;
		memset(&operand_list, 0, sizeof(operand_list));

		// The default is to just copy every operand, to simplify the
		// alternate code path for special cases
		operand_list.numOperands = instruction.numOperands;
		for (int i = 0; i < instruction.numOperands; ++i)
		{
			operand_list.operands[i] = instruction.operands[i];
		}

		switch(instruction.id)
		{
			case PPC_ID_BCx:
				FillBcxOperands(&operand_list, &instruction);
				break;
			case PPC_ID_BCCTRx:
				FillBcctrxOperands(&operand_list, &instruction);
				break;
			case PPC_ID_BCLRx:
				FillBclrxOperands(&operand_list, &instruction);
				break;
			default:
				// Already copied by default
				;
		}

		for (int i = 0; i < operand_list.numOperands; ++i)
		{
			Operand* op = &(operand_list.operands[i]);
			bool was_pushed = PushOperandTokens(result, op);

			if (was_pushed && i < operand_list.numOperands - 1)
			{
				//MYLOG("pushing a comma\n");
				result.emplace_back(OperandSeparatorToken, ", ");
			}
		}

		return true;
	}

	static string GetIntrinsicName_ppc_ps(uint32_t intrinsic)
	{
		switch (intrinsic)
		{
		case PPC_PS_INTRIN_QUANTIZE:
			return "quantize";
		case PPC_PS_INTRIN_DEQUANTIZE:
			return "dequantize";
		default:
			break;
		}
		return "";
	}

	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case PPC_INTRIN_CNTLZW:
			return "__builtin_clz";
		case PPC_INTRIN_FRSP:
			return "float_round";
		default:
			if ((decodeFlags & DECODE_FLAGS_PS))
			{
				return GetIntrinsicName_ppc_ps(intrinsic);
			}
			break;
		}
		return "";
	}


	virtual std::vector<uint32_t> GetAllIntrinsics() override
	{
		// Highest intrinsic number currently is PPC_PS_INTRIN_END.
		// If new extensions are added please update this code.
		std::vector<uint32_t> result{PPC_PS_INTRIN_END};

		// Double check someone didn't insert a new intrinsic at the beginning of our enum since we rely
		// on it to fill the next array.
		static_assert(PPCIntrinsic::PPC_INTRIN_CNTLZW == 0,
			"Invalid first PPCIntrinsic value. Please add your intrinsic further in the enum.");

		// Normal intrinsics.
		for (uint32_t id = PPC_INTRIN_CNTLZW; id < PPCIntrinsic::PPC_INTRIN_END; id++) {
			result.push_back(id);
		}

		// PPC_PS intrinsics.
		for (uint32_t id = PPC_PS_INTRIN_QUANTIZE; id < PPCIntrinsic::PPC_PS_INTRIN_END; id++) {
			result.push_back(id);
		}

		// consider populating with separate architecture stuff, like ppc_ps stuff or something
		return result;
	}

	static vector<NameAndType> GetIntrinsicInputs_ppc_ps(uint32_t intrinsic)
	{
		switch (intrinsic)
		{
		// for now, quantize is operating on the float in, and the gqr that holds the scale
		case PPC_PS_INTRIN_QUANTIZE:
			return {NameAndType(Type::FloatType(4)), NameAndType(Type::IntegerType(4, false))};
		case PPC_PS_INTRIN_DEQUANTIZE:
			return {NameAndType(Type::IntegerType(4, false)), NameAndType(Type::FloatType(8)), NameAndType(Type::IntegerType(4, false))};
		default:
			break;
		}
		return vector<NameAndType>();
	}

	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case PPC_INTRIN_CNTLZW:		// rs
			return {NameAndType(Type::IntegerType(4, false))};
		case PPC_INTRIN_FRSP:
			return {NameAndType(Type::FloatType(4))};
		// for now, quantize is operating on the float in, and the gqr that holds the scale
		default:
			if ((decodeFlags & DECODE_FLAGS_PS))
			{
				return GetIntrinsicInputs_ppc_ps(intrinsic);
			}
			break;
		}
		return vector<NameAndType>();
	}

	static vector<Confidence<Ref<Type>>> GetIntrinsicOutputs_ppc_ps(uint32_t intrinsic)
	{
		switch(intrinsic)
		{
		case PPC_PS_INTRIN_QUANTIZE:
			// quantize returns the quantized float
			return {Type::FloatType(4)};
		case PPC_PS_INTRIN_DEQUANTIZE:
			return {Type::FloatType(4)};
		default:
			break;
		}
		return vector<Confidence<Ref<Type>>>();
	}

	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case PPC_INTRIN_CNTLZW:		// ra
			return {Type::IntegerType(4, false)};
		case PPC_INTRIN_FRSP:
			return {Type::FloatType(4)};
		default:
			if ((decodeFlags & DECODE_FLAGS_PS))
			{
				return GetIntrinsicOutputs_ppc_ps(intrinsic);
			}
			break;
		}
		return vector<Confidence<Ref<Type>>>();
	}


	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		size_t instructionLength = GetInstructionLength(data, len, decodeFlags);
		if (instructionLength == 0)
		{
			MYLOG("ERROR: not enough bytes for instruction\n");
			return false;
		}

		len = instructionLength;

		Instruction instruction;
		if (!FillInstruction(&instruction, data, instructionLength, addr))
		{
			MYLOG("ERROR: FillInstruction()\n");
			il.AddInstruction(il.Undefined());
			return false;
		}

		return GetLowLevelILForPPCInstruction(this, il, &instruction, addr);
	}

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
	{
		// MYLOG("%s(), op:%d, flagwritetype:%d, flag:%d\n", __func__, op, flagWriteType, flag);
		ExprId left, right;
		ppc_suf suf = (ppc_suf)0;

		suf = (ppc_suf)((flagWriteType - 1) % PPC_SUF_SZ);

		switch (flagWriteType)
		{
			case IL_FLAGWRITE_MTCR0:
			case IL_FLAGWRITE_MTCR1:
			case IL_FLAGWRITE_MTCR2:
			case IL_FLAGWRITE_MTCR3:
			case IL_FLAGWRITE_MTCR4:
			case IL_FLAGWRITE_MTCR5:
			case IL_FLAGWRITE_MTCR6:
			case IL_FLAGWRITE_MTCR7:
				return il.TestBit(4, il.GetExprForRegisterOrConstant(operands[0], 4), il.Const(4, 31u - flag));

			case IL_FLAGWRITE_INVL0:
			case IL_FLAGWRITE_INVL1:
			case IL_FLAGWRITE_INVL2:
			case IL_FLAGWRITE_INVL3:
			case IL_FLAGWRITE_INVL4:
			case IL_FLAGWRITE_INVL5:
			case IL_FLAGWRITE_INVL6:
			case IL_FLAGWRITE_INVL7:
			case IL_FLAGWRITE_INVALL:
				return il.Unimplemented();
		}

		auto liftOps = [&]() {
			if ((op == LLIL_SUB) || (op == LLIL_FSUB))
			{
				left = il.GetExprForRegisterOrConstant(operands[0], size);
				right = il.GetExprForRegisterOrConstant(operands[1], size);
			}
			else
			{
				left = il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount);
				right = il.Const(size, 0);
			}
		};

		switch (flag)
		{
			case IL_FLAG_XER_CA:
				if (op == LLIL_ASR)
				{
					ExprId maskExpr;

					if (operands[1].constant)
					{
						uint32_t mask = (1 << operands[1].value) - 1;
						if (!mask)
							return il.Const(0, 0);
						maskExpr = il.Const(size, mask);
					}
					else
					{
						maskExpr = il.GetExprForRegisterOrConstant(operands[1], size);
						maskExpr = il.Sub(size,
							il.ShiftLeft(size,
								il.Const(size, 1),
								maskExpr),
							il.Const(size, 1)
						);
					}

					return il.And(0,
						il.CompareSignedLessThan(size,
							il.GetExprForRegisterOrConstant(operands[0], size),
							il.Const(size, 0)
						),
						il.CompareNotEqual(size,
							il.And(size,
								il.GetExprForRegisterOrConstant(operands[0], size),
								maskExpr),
							il.Const(size, 0)
						)
					);
				}
				break;
			case IL_FLAG_LT:
			case IL_FLAG_LT_1:
			case IL_FLAG_LT_2:
			case IL_FLAG_LT_3:
			case IL_FLAG_LT_4:
			case IL_FLAG_LT_5:
			case IL_FLAG_LT_6:
			case IL_FLAG_LT_7:
				liftOps();

				if (suf == PPC_SUF_S)
					return il.CompareSignedLessThan(size, left, right);
				else if (suf == PPC_SUF_U)
					return il.CompareUnsignedLessThan(size, left, right);
				else if (suf == PPC_SUF_F)
					return il.FloatCompareLessThan(size, left, right);

			case IL_FLAG_GT:
			case IL_FLAG_GT_1:
			case IL_FLAG_GT_2:
			case IL_FLAG_GT_3:
			case IL_FLAG_GT_4:
			case IL_FLAG_GT_5:
			case IL_FLAG_GT_6:
			case IL_FLAG_GT_7:
				liftOps();

				if (suf == PPC_SUF_S)
					return il.CompareSignedGreaterThan(size, left, right);
				else if (suf == PPC_SUF_U)
					return il.CompareUnsignedGreaterThan(size, left, right);
				else if (suf == PPC_SUF_F)
					return il.FloatCompareGreaterThan(size, left, right);

			case IL_FLAG_EQ:
			case IL_FLAG_EQ_1:
			case IL_FLAG_EQ_2:
			case IL_FLAG_EQ_3:
			case IL_FLAG_EQ_4:
			case IL_FLAG_EQ_5:
			case IL_FLAG_EQ_6:
			case IL_FLAG_EQ_7:
				liftOps();
				if (suf == PPC_SUF_F)
					return il.FloatCompareEqual(size, left, right);
				else
					return il.CompareEqual(size, left, right);
		}

		BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
		return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
	}


	virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
	{
		// MYLOG("%s() semgroup:%d\n", __func__, semGroup);
		uint32_t flagBase = (semGroup / 10) * 4; // get to flags from the right cr

		switch (semGroup % 10)
		{
			case IL_FLAGGROUP_CR0_LT: return il.Flag(flagBase + IL_FLAG_LT);
			case IL_FLAGGROUP_CR0_LE: return il.Not(0, il.Flag(flagBase + IL_FLAG_GT));
			case IL_FLAGGROUP_CR0_GT: return il.Flag(flagBase + IL_FLAG_GT);
			case IL_FLAGGROUP_CR0_GE: return il.Not(0, il.Flag(flagBase + IL_FLAG_LT));
			case IL_FLAGGROUP_CR0_EQ: return il.Flag(flagBase + IL_FLAG_EQ);
			case IL_FLAGGROUP_CR0_NE: return il.Not(0, il.Flag(flagBase + IL_FLAG_EQ));
		}

		return il.Unimplemented();
	}

	virtual string GetRegisterName(uint32_t regId) override
	{
		const char *result = PowerPCRegisterName(regId);

		if (result == NULL)
			result = "";

		//MYLOG("%s(%d) returns %s\n", __func__, regId, result);
		return result;
	}

	/*************************************************************************/
	/* FLAGS API
		1) flag identifiers and names
		2) flag write types and names
		3) flag roles "which flags act like a carry flag?"
		4) map flag condition to set-of-flags
	*/
	/*************************************************************************/

	/*
		flag identifiers and names
	*/
	virtual vector<uint32_t> GetAllFlags() override
	{
		// MYLOG("%s()\n", __func__);
		return vector<uint32_t> {
			IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
			IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
			IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
			IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
			IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
			IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
			IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
			IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
			IL_FLAG_XER_SO, IL_FLAG_XER_OV, IL_FLAG_XER_CA
		};
	}

	virtual string GetFlagName(uint32_t flag) override
	{
		// MYLOG("%s() flag:%d\n", __func__, flag);
		switch(flag) {
			case IL_FLAG_LT: return "lt";
			case IL_FLAG_GT: return "gt";
			case IL_FLAG_EQ: return "eq";
			case IL_FLAG_SO: return "so";
			case IL_FLAG_LT_1: return "cr1lt";
			case IL_FLAG_GT_1: return "cr1gt";
			case IL_FLAG_EQ_1: return "cr1eq";
			case IL_FLAG_SO_1: return "cr1so";
			case IL_FLAG_LT_2: return "cr2lt";
			case IL_FLAG_GT_2: return "cr2gt";
			case IL_FLAG_EQ_2: return "cr2eq";
			case IL_FLAG_SO_2: return "cr2so";
			case IL_FLAG_LT_3: return "cr3lt";
			case IL_FLAG_GT_3: return "cr3gt";
			case IL_FLAG_EQ_3: return "cr3eq";
			case IL_FLAG_SO_3: return "cr3so";
			case IL_FLAG_LT_4: return "cr4lt";
			case IL_FLAG_GT_4: return "cr4gt";
			case IL_FLAG_EQ_4: return "cr4eq";
			case IL_FLAG_SO_4: return "cr4so";
			case IL_FLAG_LT_5: return "cr5lt";
			case IL_FLAG_GT_5: return "cr5gt";
			case IL_FLAG_EQ_5: return "cr5eq";
			case IL_FLAG_SO_5: return "cr5so";
			case IL_FLAG_LT_6: return "cr6lt";
			case IL_FLAG_GT_6: return "cr6gt";
			case IL_FLAG_EQ_6: return "cr6eq";
			case IL_FLAG_SO_6: return "cr6so";
			case IL_FLAG_LT_7: return "cr7lt";
			case IL_FLAG_GT_7: return "cr7gt";
			case IL_FLAG_EQ_7: return "cr7eq";
			case IL_FLAG_SO_7: return "cr7so";
			case IL_FLAG_XER_SO: return "xer_so";
			case IL_FLAG_XER_OV: return "xer_ov";
			case IL_FLAG_XER_CA: return "xer_ca";
			default:
				// LogWarn("Unknown flag: %#x/%d", flag, flag);
				return "ERR_FLAG_NAME";
		}
	}

	/*
		flag write types
	*/
	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t> {
			IL_FLAGWRITE_NONE,

			IL_FLAGWRITE_CR0_S, IL_FLAGWRITE_CR1_S, IL_FLAGWRITE_CR2_S, IL_FLAGWRITE_CR3_S,
			IL_FLAGWRITE_CR4_S, IL_FLAGWRITE_CR5_S, IL_FLAGWRITE_CR6_S, IL_FLAGWRITE_CR7_S,

			IL_FLAGWRITE_CR0_U, IL_FLAGWRITE_CR1_U, IL_FLAGWRITE_CR2_U, IL_FLAGWRITE_CR3_U,
			IL_FLAGWRITE_CR4_U, IL_FLAGWRITE_CR5_U, IL_FLAGWRITE_CR6_U, IL_FLAGWRITE_CR7_U,

			IL_FLAGWRITE_CR0_F, IL_FLAGWRITE_CR1_F, IL_FLAGWRITE_CR2_F, IL_FLAGWRITE_CR3_F,
			IL_FLAGWRITE_CR4_F, IL_FLAGWRITE_CR5_F, IL_FLAGWRITE_CR6_F, IL_FLAGWRITE_CR7_F,

			IL_FLAGWRITE_XER, IL_FLAGWRITE_XER_CA, IL_FLAGWRITE_XER_OV_SO,

			IL_FLAGWRITE_MTCR0, IL_FLAGWRITE_MTCR1, IL_FLAGWRITE_MTCR2, IL_FLAGWRITE_MTCR3,
			IL_FLAGWRITE_MTCR4, IL_FLAGWRITE_MTCR5, IL_FLAGWRITE_MTCR6, IL_FLAGWRITE_MTCR7,

			IL_FLAGWRITE_INVL0, IL_FLAGWRITE_INVL1, IL_FLAGWRITE_INVL2, IL_FLAGWRITE_INVL3,
			IL_FLAGWRITE_INVL4, IL_FLAGWRITE_INVL5, IL_FLAGWRITE_INVL6, IL_FLAGWRITE_INVL7,

			IL_FLAGWRITE_INVALL
		};
	}

	virtual string GetFlagWriteTypeName(uint32_t writeType) override
	{
		// MYLOG("%s() writeType:%d\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S:
				return "cr0_signed";
			case IL_FLAGWRITE_CR1_S:
				return "cr1_signed";
			case IL_FLAGWRITE_CR2_S:
				return "cr2_signed";
			case IL_FLAGWRITE_CR3_S:
				return "cr3_signed";
			case IL_FLAGWRITE_CR4_S:
				return "cr4_signed";
			case IL_FLAGWRITE_CR5_S:
				return "cr5_signed";
			case IL_FLAGWRITE_CR6_S:
				return "cr6_signed";
			case IL_FLAGWRITE_CR7_S:
				return "cr7_signed";

			case IL_FLAGWRITE_CR0_U:
				return "cr0_unsigned";
			case IL_FLAGWRITE_CR1_U:
				return "cr1_unsigned";
			case IL_FLAGWRITE_CR2_U:
				return "cr2_unsigned";
			case IL_FLAGWRITE_CR3_U:
				return "cr3_unsigned";
			case IL_FLAGWRITE_CR4_U:
				return "cr4_unsigned";
			case IL_FLAGWRITE_CR5_U:
				return "cr5_unsigned";
			case IL_FLAGWRITE_CR6_U:
				return "cr6_unsigned";
			case IL_FLAGWRITE_CR7_U:
				return "cr7_unsigned";

			case IL_FLAGWRITE_CR0_F:
				return "cr0_float";
			case IL_FLAGWRITE_CR1_F:
				return "cr1_float";
			case IL_FLAGWRITE_CR2_F:
				return "cr2_float";
			case IL_FLAGWRITE_CR3_F:
				return "cr3_floatt";
			case IL_FLAGWRITE_CR4_F:
				return "cr4_float";
			case IL_FLAGWRITE_CR5_F:
				return "cr5_float";
			case IL_FLAGWRITE_CR6_F:
				return "cr6_float";
			case IL_FLAGWRITE_CR7_F:
				return "cr7_float";

			case IL_FLAGWRITE_XER:
				return "xer";
			case IL_FLAGWRITE_XER_CA:
				return "xer_ca";
			case IL_FLAGWRITE_XER_OV_SO:
				return "xer_ov_so";

			case IL_FLAGWRITE_MTCR0:
				return "mtcr0";
			case IL_FLAGWRITE_MTCR1:
				return "mtcr1";
			case IL_FLAGWRITE_MTCR2:
				return "mtcr2";
			case IL_FLAGWRITE_MTCR3:
				return "mtcr3";
			case IL_FLAGWRITE_MTCR4:
				return "mtcr4";
			case IL_FLAGWRITE_MTCR5:
				return "mtcr5";
			case IL_FLAGWRITE_MTCR6:
				return "mtcr6";
			case IL_FLAGWRITE_MTCR7:
				return "mtcr7";

			case IL_FLAGWRITE_INVL0:
				return "invl0";
			case IL_FLAGWRITE_INVL1:
				return "invl1";
			case IL_FLAGWRITE_INVL2:
				return "invl2";
			case IL_FLAGWRITE_INVL3:
				return "invl3";
			case IL_FLAGWRITE_INVL4:
				return "invl4";
			case IL_FLAGWRITE_INVL5:
				return "invl5";
			case IL_FLAGWRITE_INVL6:
				return "invl6";
			case IL_FLAGWRITE_INVL7:
				return "invl7";

			case IL_FLAGWRITE_INVALL:
				return "invall";

			default:
				MYLOG("ERROR: unrecognized writeType\n");
				return "none";
		}
	}

	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
	{
		// MYLOG("%s() writeType:%d\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S:
			case IL_FLAGWRITE_CR0_U:
			case IL_FLAGWRITE_CR0_F:
			case IL_FLAGWRITE_MTCR0:
			case IL_FLAGWRITE_INVL0:
				return vector<uint32_t> {
					IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
				};

			case IL_FLAGWRITE_CR1_S:
			case IL_FLAGWRITE_CR1_U:
			case IL_FLAGWRITE_CR1_F:
			case IL_FLAGWRITE_MTCR1:
			case IL_FLAGWRITE_INVL1:
				return vector<uint32_t> {
					IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
				};

			case IL_FLAGWRITE_CR2_S:
			case IL_FLAGWRITE_CR2_U:
			case IL_FLAGWRITE_CR2_F:
			case IL_FLAGWRITE_MTCR2:
			case IL_FLAGWRITE_INVL2:
				return vector<uint32_t> {
					IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
				};

			case IL_FLAGWRITE_CR3_S:
			case IL_FLAGWRITE_CR3_U:
			case IL_FLAGWRITE_CR3_F:
			case IL_FLAGWRITE_MTCR3:
			case IL_FLAGWRITE_INVL3:
				return vector<uint32_t> {
					IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
				};

			case IL_FLAGWRITE_CR4_S:
			case IL_FLAGWRITE_CR4_U:
			case IL_FLAGWRITE_CR4_F:
			case IL_FLAGWRITE_MTCR4:
			case IL_FLAGWRITE_INVL4:
				return vector<uint32_t> {
					IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
				};

			case IL_FLAGWRITE_CR5_S:
			case IL_FLAGWRITE_CR5_U:
			case IL_FLAGWRITE_CR5_F:
			case IL_FLAGWRITE_MTCR5:
			case IL_FLAGWRITE_INVL5:
				return vector<uint32_t> {
					IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
				};

			case IL_FLAGWRITE_CR6_S:
			case IL_FLAGWRITE_CR6_U:
			case IL_FLAGWRITE_CR6_F:
			case IL_FLAGWRITE_MTCR6:
			case IL_FLAGWRITE_INVL6:
				return vector<uint32_t> {
					IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
				};

			case IL_FLAGWRITE_CR7_S:
			case IL_FLAGWRITE_CR7_U:
			case IL_FLAGWRITE_CR7_F:
			case IL_FLAGWRITE_MTCR7:
			case IL_FLAGWRITE_INVL7:
				return vector<uint32_t> {
					IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
				};

			case IL_FLAGWRITE_XER:
				return vector<uint32_t> {
					IL_FLAG_XER_SO, IL_FLAG_XER_OV, IL_FLAG_XER_CA
				};

			case IL_FLAGWRITE_XER_CA:
				return vector<uint32_t> {
					IL_FLAG_XER_CA
				};

			case IL_FLAGWRITE_XER_OV_SO:
				return vector<uint32_t> {
					IL_FLAG_XER_SO, IL_FLAG_XER_OV
				};

			case IL_FLAGWRITE_INVALL:
				return GetAllFlags();

			default:
				return vector<uint32_t>();
		}
	}
	virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override
	{
		// MYLOG("%s() writetype:%d", __func__, writeType);
		uint32_t flag_out = 0;

		if ((writeType < IL_FLAGWRITE_CR0_S) || (writeType > IL_FLAGWRITE_CR7_F))
		{
			flag_out = IL_FLAGCLASS_NONE;
		}
		else
		{
			flag_out = IL_FLAGCLASS_CR0_S + (writeType - IL_FLAGWRITE_CR0_S);
		}
		
		return flag_out;
	}

	/*
		flag classes
	*/
	virtual vector<uint32_t> GetAllSemanticFlagClasses() override
	{
		return vector<uint32_t> {
			IL_FLAGCLASS_NONE,

			IL_FLAGCLASS_CR0_S, IL_FLAGCLASS_CR1_S, IL_FLAGCLASS_CR2_S, IL_FLAGCLASS_CR3_S,
			IL_FLAGCLASS_CR4_S, IL_FLAGCLASS_CR5_S, IL_FLAGCLASS_CR6_S, IL_FLAGCLASS_CR7_S,

			IL_FLAGCLASS_CR0_U, IL_FLAGCLASS_CR1_U, IL_FLAGCLASS_CR2_U, IL_FLAGCLASS_CR3_U,
			IL_FLAGCLASS_CR4_U, IL_FLAGCLASS_CR5_U, IL_FLAGCLASS_CR6_U, IL_FLAGCLASS_CR7_U,

			IL_FLAGCLASS_CR0_F, IL_FLAGCLASS_CR1_F, IL_FLAGCLASS_CR2_F, IL_FLAGCLASS_CR3_F,
			IL_FLAGCLASS_CR4_F, IL_FLAGCLASS_CR5_F, IL_FLAGCLASS_CR6_F, IL_FLAGCLASS_CR7_F,
		};
	}

	virtual std::string GetSemanticFlagClassName(uint32_t semClass) override
	{
		return GetFlagWriteTypeName(semClass);
	}

	/*
	   semantic flag groups
	 */
	virtual vector<uint32_t> GetAllSemanticFlagGroups() override
	{
		return vector<uint32_t> {
			IL_FLAGGROUP_CR0_LT, IL_FLAGGROUP_CR0_LE, IL_FLAGGROUP_CR0_GT,
			IL_FLAGGROUP_CR0_GE, IL_FLAGGROUP_CR0_EQ, IL_FLAGGROUP_CR0_NE,
			IL_FLAGGROUP_CR1_LT, IL_FLAGGROUP_CR1_LE, IL_FLAGGROUP_CR1_GT,
			IL_FLAGGROUP_CR1_GE, IL_FLAGGROUP_CR1_EQ, IL_FLAGGROUP_CR1_NE,
			IL_FLAGGROUP_CR2_LT, IL_FLAGGROUP_CR2_LE, IL_FLAGGROUP_CR2_GT,
			IL_FLAGGROUP_CR2_GE, IL_FLAGGROUP_CR2_EQ, IL_FLAGGROUP_CR2_NE,
			IL_FLAGGROUP_CR3_LT, IL_FLAGGROUP_CR3_LE, IL_FLAGGROUP_CR3_GT,
			IL_FLAGGROUP_CR3_GE, IL_FLAGGROUP_CR3_EQ, IL_FLAGGROUP_CR3_NE,
			IL_FLAGGROUP_CR4_LT, IL_FLAGGROUP_CR4_LE, IL_FLAGGROUP_CR4_GT,
			IL_FLAGGROUP_CR4_GE, IL_FLAGGROUP_CR4_EQ, IL_FLAGGROUP_CR4_NE,
			IL_FLAGGROUP_CR5_LT, IL_FLAGGROUP_CR5_LE, IL_FLAGGROUP_CR5_GT,
			IL_FLAGGROUP_CR5_GE, IL_FLAGGROUP_CR5_EQ, IL_FLAGGROUP_CR5_NE,
			IL_FLAGGROUP_CR6_LT, IL_FLAGGROUP_CR6_LE, IL_FLAGGROUP_CR6_GT,
			IL_FLAGGROUP_CR6_GE, IL_FLAGGROUP_CR6_EQ, IL_FLAGGROUP_CR6_NE,
			IL_FLAGGROUP_CR7_LT, IL_FLAGGROUP_CR7_LE, IL_FLAGGROUP_CR7_GT,
			IL_FLAGGROUP_CR7_GE, IL_FLAGGROUP_CR7_EQ, IL_FLAGGROUP_CR7_NE,
		};
	}

	virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override
	{
		char name[32];
		const char* suffix;

		/* remove the cr part of the semGroup id from the equation */
		switch (semGroup % 10)
		{
			case IL_FLAGGROUP_CR0_LT: suffix = "lt"; break;
			case IL_FLAGGROUP_CR0_LE: suffix = "le"; break;
			case IL_FLAGGROUP_CR0_GT: suffix = "gt"; break;
			case IL_FLAGGROUP_CR0_GE: suffix = "ge"; break;
			case IL_FLAGGROUP_CR0_EQ: suffix = "eq"; break;
			case IL_FLAGGROUP_CR0_NE: suffix = "ne"; break;
			default: suffix = "invalid"; break;
		}

		snprintf(name, sizeof(name), "cr%d_%s", semGroup / 10, suffix);

		return std::string(name);
	}

	virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override
	{
		uint32_t flag = IL_FLAG_LT + ((semGroup / 10) * 4); // get to flags from the right cr
		flag += ((semGroup % 10) / 2);

		return { flag };
	}

	virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override
	{
		// MYLOG("%s() semgroup:%d", __func__, semGroup);
		
		uint32_t flagClassBase = IL_FLAGCLASS_CR0_S + ((semGroup / 10) * PPC_SUF_SZ);
		uint32_t groupType = semGroup % 10;

		switch (groupType)
		{
		case IL_FLAGGROUP_CR0_LT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLT},
				{flagClassBase + PPC_SUF_U, LLFC_ULT},
				{flagClassBase + PPC_SUF_F, LLFC_FLT},
			};
		case IL_FLAGGROUP_CR0_LE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLE},
				{flagClassBase + PPC_SUF_U, LLFC_ULE},
				{flagClassBase + PPC_SUF_F, LLFC_FLE}
			};
		case IL_FLAGGROUP_CR0_GT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGT},
				{flagClassBase + PPC_SUF_U, LLFC_UGT},
				{flagClassBase + PPC_SUF_F, LLFC_FGT}
			};
		case IL_FLAGGROUP_CR0_GE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGE},
				{flagClassBase + PPC_SUF_U, LLFC_UGE},
				{flagClassBase + PPC_SUF_F, LLFC_FGE}
			};
		case IL_FLAGGROUP_CR0_EQ:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_E},
				{flagClassBase + PPC_SUF_U, LLFC_E},
				{flagClassBase + PPC_SUF_F, LLFC_FE}
			};
		case IL_FLAGGROUP_CR0_NE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_NE},
				{flagClassBase + PPC_SUF_U, LLFC_NE},
				{flagClassBase + PPC_SUF_F, LLFC_FNE}
			};
		default:
			return map<uint32_t, BNLowLevelILFlagCondition>();
		}
	}

	/*
		flag roles
	*/

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
	{
		// MYLOG("%s() flag:%d, semclass:%d\n", __func__, flag, semClass);

		ppc_suf suf = (ppc_suf)0;

		suf = (ppc_suf)((semClass - 1) % PPC_SUF_SZ);

		switch (flag)
		{
			case IL_FLAG_LT:
			case IL_FLAG_LT_1:
			case IL_FLAG_LT_2:
			case IL_FLAG_LT_3:
			case IL_FLAG_LT_4:
			case IL_FLAG_LT_5:
			case IL_FLAG_LT_6:
			case IL_FLAG_LT_7:
				return (suf == PPC_SUF_S) ? NegativeSignFlagRole : SpecialFlagRole;
			case IL_FLAG_GT:
			case IL_FLAG_GT_1:
			case IL_FLAG_GT_2:
			case IL_FLAG_GT_3:
			case IL_FLAG_GT_4:
			case IL_FLAG_GT_5:
			case IL_FLAG_GT_6:
			case IL_FLAG_GT_7:
				return SpecialFlagRole; // PositiveSignFlag is >=, not >
			case IL_FLAG_EQ:
			case IL_FLAG_EQ_1:
			case IL_FLAG_EQ_2:
			case IL_FLAG_EQ_3:
			case IL_FLAG_EQ_4:
			case IL_FLAG_EQ_5:
			case IL_FLAG_EQ_6:
			case IL_FLAG_EQ_7:
				return ZeroFlagRole;
			// case IL_FLAG_SO:
			// case IL_FLAG_SO_1:
			// case IL_FLAG_SO_2:
			// case IL_FLAG_SO_3:
			// case IL_FLAG_SO_4:
			// case IL_FLAG_SO_5:
			// case IL_FLAG_SO_6:
			// case IL_FLAG_SO_7:
			// case IL_FLAG_XER_SO:
			case IL_FLAG_XER_OV:
				return OverflowFlagRole;
			case IL_FLAG_XER_CA:
				return CarryFlagRole;
			default:
				return SpecialFlagRole;
		}
	}

	/*
		flag conditions -> set of flags
		LLFC is "low level flag condition"
	*/
	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
	{
		// MYLOG("%s() cond:%d\n", __func__, cond);

		switch (cond)
		{
			case LLFC_E: /* equal */
			case LLFC_NE: /* not equal */
			case LLFC_FE:
			case LLFC_FNE:
				return vector<uint32_t>{ IL_FLAG_EQ };

			case LLFC_ULT: /* (unsigned) less than == LT */
			case LLFC_SLT: /* (signed) less than == LT */
			case LLFC_SGE: /* (signed) greater-or-equal == !LT */
			case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
			case LLFC_FLT:
			case LLFC_FGE:
				return vector<uint32_t>{ IL_FLAG_LT };

			case LLFC_SGT: /* (signed) greater-than == GT */
			case LLFC_UGT: /* (unsigned) greater-than == GT */
			case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
			case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
			case LLFC_FGT:
			case LLFC_FLE:
				return vector<uint32_t>{ IL_FLAG_GT };

			case LLFC_NEG:
			case LLFC_POS:
				/* no ppc flags (that I'm aware of) indicate sign of result */
				return vector<uint32_t>();

			case LLFC_O:
			case LLFC_NO:
				/* difficult:
					crX: 8 signed sticky versions
					XER: 1 unsigned sticky, 1 unsigned traditional */
				return vector<uint32_t>{
					IL_FLAG_XER_OV
				};

			default:
				return vector<uint32_t>();
		}
	}


	/*************************************************************************/
	/* REGISTERS API
		1) registers' ids and names
		2) register info (size)
		3) special registers: stack pointer, link register
	*/
	/*************************************************************************/

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		// MYLOG("%s()\n", __func__);

		return vector<uint32_t>{
			PPC_REG_GPR0,   PPC_REG_GPR1,   PPC_REG_GPR2,   PPC_REG_GPR3,
			PPC_REG_GPR4,   PPC_REG_GPR5,   PPC_REG_GPR6,   PPC_REG_GPR7,
			PPC_REG_GPR8,   PPC_REG_GPR9,   PPC_REG_GPR10,  PPC_REG_GPR11,
			PPC_REG_GPR12,  PPC_REG_GPR13,  PPC_REG_GPR14,  PPC_REG_GPR15,
			PPC_REG_GPR16,  PPC_REG_GPR17,  PPC_REG_GPR18,  PPC_REG_GPR19,
			PPC_REG_GPR20,  PPC_REG_GPR21,  PPC_REG_GPR22,  PPC_REG_GPR23,
			PPC_REG_GPR24,  PPC_REG_GPR25,  PPC_REG_GPR26,  PPC_REG_GPR27,
			PPC_REG_GPR28,  PPC_REG_GPR29,  PPC_REG_GPR30,  PPC_REG_GPR31
		};
	}

	#define PPC_REG_CC (PPC_REG_ENDING + 1)
	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = {
			PPC_REG_GPR0,  PPC_REG_GPR1,  PPC_REG_GPR2,  PPC_REG_GPR3,
			PPC_REG_GPR4,  PPC_REG_GPR5,  PPC_REG_GPR6,  PPC_REG_GPR7,
			PPC_REG_GPR8,  PPC_REG_GPR9,  PPC_REG_GPR10, PPC_REG_GPR11,
			PPC_REG_GPR12, PPC_REG_GPR13, PPC_REG_GPR14, PPC_REG_GPR15,
			PPC_REG_GPR16, PPC_REG_GPR17, PPC_REG_GPR18, PPC_REG_GPR19,
			PPC_REG_GPR20, PPC_REG_GPR21, PPC_REG_GPR22, PPC_REG_GPR23,
			PPC_REG_GPR24, PPC_REG_GPR25, PPC_REG_GPR26, PPC_REG_GPR27,
			PPC_REG_GPR28, PPC_REG_GPR29, PPC_REG_GPR30, PPC_REG_GPR31,

			PPC_REG_XER, PPC_REG_LR, PPC_REG_CTR,

			PPC_REG_FR0,  PPC_REG_FR1,  PPC_REG_FR2,  PPC_REG_FR3,
			PPC_REG_FR4,  PPC_REG_FR5,  PPC_REG_FR6,  PPC_REG_FR7,
			PPC_REG_FR8,  PPC_REG_FR9,  PPC_REG_FR10, PPC_REG_FR11,
			PPC_REG_FR12, PPC_REG_FR13, PPC_REG_FR14, PPC_REG_FR15,
			PPC_REG_FR16, PPC_REG_FR17, PPC_REG_FR18, PPC_REG_FR19,
			PPC_REG_FR20, PPC_REG_FR21, PPC_REG_FR22, PPC_REG_FR23,
			PPC_REG_FR24, PPC_REG_FR25, PPC_REG_FR26, PPC_REG_FR27,
			PPC_REG_FR28, PPC_REG_FR29, PPC_REG_FR30, PPC_REG_FR31,

			PPC_REG_CRF0, PPC_REG_CRF1, PPC_REG_CRF2, PPC_REG_CRF3,
			PPC_REG_CRF4, PPC_REG_CRF5, PPC_REG_CRF6, PPC_REG_CRF7,

			PPC_REG_AV_VR0,  PPC_REG_AV_VR1,  PPC_REG_AV_VR2,  PPC_REG_AV_VR3,
			PPC_REG_AV_VR4,  PPC_REG_AV_VR5,  PPC_REG_AV_VR6,  PPC_REG_AV_VR7,
			PPC_REG_AV_VR8,  PPC_REG_AV_VR9,  PPC_REG_AV_VR10, PPC_REG_AV_VR11,
			PPC_REG_AV_VR12, PPC_REG_AV_VR13, PPC_REG_AV_VR14, PPC_REG_AV_VR15,
			PPC_REG_AV_VR16, PPC_REG_AV_VR17, PPC_REG_AV_VR18, PPC_REG_AV_VR19,
			PPC_REG_AV_VR20, PPC_REG_AV_VR21, PPC_REG_AV_VR22, PPC_REG_AV_VR23,
			PPC_REG_AV_VR24, PPC_REG_AV_VR25, PPC_REG_AV_VR26, PPC_REG_AV_VR27,
			PPC_REG_AV_VR28, PPC_REG_AV_VR29, PPC_REG_AV_VR30, PPC_REG_AV_VR31,

			PPC_REG_VSX_VR0,  PPC_REG_VSX_VR1,  PPC_REG_VSX_VR2,  PPC_REG_VSX_VR3,
			PPC_REG_VSX_VR4,  PPC_REG_VSX_VR5,  PPC_REG_VSX_VR6,  PPC_REG_VSX_VR7,
			PPC_REG_VSX_VR8,  PPC_REG_VSX_VR9,  PPC_REG_VSX_VR10, PPC_REG_VSX_VR11,
			PPC_REG_VSX_VR12, PPC_REG_VSX_VR13, PPC_REG_VSX_VR14, PPC_REG_VSX_VR15,
			PPC_REG_VSX_VR16, PPC_REG_VSX_VR17, PPC_REG_VSX_VR18, PPC_REG_VSX_VR19,
			PPC_REG_VSX_VR20, PPC_REG_VSX_VR21, PPC_REG_VSX_VR22, PPC_REG_VSX_VR23,
			PPC_REG_VSX_VR24, PPC_REG_VSX_VR25, PPC_REG_VSX_VR26, PPC_REG_VSX_VR27,
			PPC_REG_VSX_VR28, PPC_REG_VSX_VR29, PPC_REG_VSX_VR30, PPC_REG_VSX_VR31,
			PPC_REG_VSX_VR32, PPC_REG_VSX_VR33, PPC_REG_VSX_VR34, PPC_REG_VSX_VR35,
			PPC_REG_VSX_VR36, PPC_REG_VSX_VR37, PPC_REG_VSX_VR38, PPC_REG_VSX_VR39,
			PPC_REG_VSX_VR40, PPC_REG_VSX_VR41, PPC_REG_VSX_VR42, PPC_REG_VSX_VR43,
			PPC_REG_VSX_VR44, PPC_REG_VSX_VR45, PPC_REG_VSX_VR46, PPC_REG_VSX_VR47,
			PPC_REG_VSX_VR48, PPC_REG_VSX_VR49, PPC_REG_VSX_VR50, PPC_REG_VSX_VR51,
			PPC_REG_VSX_VR52, PPC_REG_VSX_VR53, PPC_REG_VSX_VR54, PPC_REG_VSX_VR55,
			PPC_REG_VSX_VR56, PPC_REG_VSX_VR57, PPC_REG_VSX_VR58, PPC_REG_VSX_VR59,
			PPC_REG_VSX_VR60, PPC_REG_VSX_VR61, PPC_REG_VSX_VR62, PPC_REG_VSX_VR63,
		};

		vector<uint32_t> gqrarray = {
			PPC_REG_GQR0, PPC_REG_GQR1, PPC_REG_GQR2, PPC_REG_GQR3,
			PPC_REG_GQR4, PPC_REG_GQR5, PPC_REG_GQR6, PPC_REG_GQR7
		};


		if ((decodeFlags & DECODE_FLAGS_PS) != 0)
		{
			result.insert(result.end(), gqrarray.begin(), gqrarray.end());
		}

		return result;
	}


	virtual std::vector<uint32_t> GetGlobalRegisters() override
	{
		return vector<uint32_t>{ PPC_REG_GPR2, PPC_REG_GPR13 };
	}


	/* binja asks us about subregisters
		the full width reg is the enveloping register, if it exists,
		and also we report our offset within it (0 if we are not enveloped)
		and our size */
	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		//MYLOG("%s(%s)\n", __func__, PowerPCRegisterName(regId));

		switch(regId) {
			case PPC_REG_GPR0: return RegisterInfo(PPC_REG_GPR0, 0, addressSize);
			case PPC_REG_GPR1: return RegisterInfo(PPC_REG_GPR1, 0, addressSize);
			case PPC_REG_GPR2: return RegisterInfo(PPC_REG_GPR2, 0, addressSize);
			case PPC_REG_GPR3: return RegisterInfo(PPC_REG_GPR3, 0, addressSize);
			case PPC_REG_GPR4: return RegisterInfo(PPC_REG_GPR4, 0, addressSize);
			case PPC_REG_GPR5: return RegisterInfo(PPC_REG_GPR5, 0, addressSize);
			case PPC_REG_GPR6: return RegisterInfo(PPC_REG_GPR6, 0, addressSize);
			case PPC_REG_GPR7: return RegisterInfo(PPC_REG_GPR7, 0, addressSize);
			case PPC_REG_GPR8: return RegisterInfo(PPC_REG_GPR8, 0, addressSize);
			case PPC_REG_GPR9: return RegisterInfo(PPC_REG_GPR9, 0, addressSize);
			case PPC_REG_GPR10: return RegisterInfo(PPC_REG_GPR10, 0, addressSize);
			case PPC_REG_GPR11: return RegisterInfo(PPC_REG_GPR11, 0, addressSize);
			case PPC_REG_GPR12: return RegisterInfo(PPC_REG_GPR12, 0, addressSize);
			case PPC_REG_GPR13: return RegisterInfo(PPC_REG_GPR13, 0, addressSize);
			case PPC_REG_GPR14: return RegisterInfo(PPC_REG_GPR14, 0, addressSize);
			case PPC_REG_GPR15: return RegisterInfo(PPC_REG_GPR15, 0, addressSize);
			case PPC_REG_GPR16: return RegisterInfo(PPC_REG_GPR16, 0, addressSize);
			case PPC_REG_GPR17: return RegisterInfo(PPC_REG_GPR17, 0, addressSize);
			case PPC_REG_GPR18: return RegisterInfo(PPC_REG_GPR18, 0, addressSize);
			case PPC_REG_GPR19: return RegisterInfo(PPC_REG_GPR19, 0, addressSize);
			case PPC_REG_GPR20: return RegisterInfo(PPC_REG_GPR20, 0, addressSize);
			case PPC_REG_GPR21: return RegisterInfo(PPC_REG_GPR21, 0, addressSize);
			case PPC_REG_GPR22: return RegisterInfo(PPC_REG_GPR22, 0, addressSize);
			case PPC_REG_GPR23: return RegisterInfo(PPC_REG_GPR23, 0, addressSize);
			case PPC_REG_GPR24: return RegisterInfo(PPC_REG_GPR24, 0, addressSize);
			case PPC_REG_GPR25: return RegisterInfo(PPC_REG_GPR25, 0, addressSize);
			case PPC_REG_GPR26: return RegisterInfo(PPC_REG_GPR26, 0, addressSize);
			case PPC_REG_GPR27: return RegisterInfo(PPC_REG_GPR27, 0, addressSize);
			case PPC_REG_GPR28: return RegisterInfo(PPC_REG_GPR28, 0, addressSize);
			case PPC_REG_GPR29: return RegisterInfo(PPC_REG_GPR29, 0, addressSize);
			case PPC_REG_GPR30: return RegisterInfo(PPC_REG_GPR30, 0, addressSize);
			case PPC_REG_GPR31: return RegisterInfo(PPC_REG_GPR31, 0, addressSize);

			case PPC_REG_XER: return RegisterInfo(PPC_REG_XER, 0, 4);
			case PPC_REG_LR: return RegisterInfo(PPC_REG_LR, 0, addressSize);
			case PPC_REG_CTR: return RegisterInfo(PPC_REG_CTR, 0, addressSize);

			case PPC_REG_FR0: return RegisterInfo(PPC_REG_FR0, 0, 4);
			case PPC_REG_FR1: return RegisterInfo(PPC_REG_FR1, 0, 4);
			case PPC_REG_FR2: return RegisterInfo(PPC_REG_FR2, 0, 4);
			case PPC_REG_FR3: return RegisterInfo(PPC_REG_FR3, 0, 4);
			case PPC_REG_FR4: return RegisterInfo(PPC_REG_FR4, 0, 4);
			case PPC_REG_FR5: return RegisterInfo(PPC_REG_FR5, 0, 4);
			case PPC_REG_FR6: return RegisterInfo(PPC_REG_FR6, 0, 4);
			case PPC_REG_FR7: return RegisterInfo(PPC_REG_FR7, 0, 4);
			case PPC_REG_FR8: return RegisterInfo(PPC_REG_FR8, 0, 4);
			case PPC_REG_FR9: return RegisterInfo(PPC_REG_FR9, 0, 4);
			case PPC_REG_FR10: return RegisterInfo(PPC_REG_FR10, 0, 4);
			case PPC_REG_FR11: return RegisterInfo(PPC_REG_FR11, 0, 4);
			case PPC_REG_FR12: return RegisterInfo(PPC_REG_FR12, 0, 4);
			case PPC_REG_FR13: return RegisterInfo(PPC_REG_FR13, 0, 4);
			case PPC_REG_FR14: return RegisterInfo(PPC_REG_FR14, 0, 4);
			case PPC_REG_FR15: return RegisterInfo(PPC_REG_FR15, 0, 4);
			case PPC_REG_FR16: return RegisterInfo(PPC_REG_FR16, 0, 4);
			case PPC_REG_FR17: return RegisterInfo(PPC_REG_FR17, 0, 4);
			case PPC_REG_FR18: return RegisterInfo(PPC_REG_FR18, 0, 4);
			case PPC_REG_FR19: return RegisterInfo(PPC_REG_FR19, 0, 4);
			case PPC_REG_FR20: return RegisterInfo(PPC_REG_FR20, 0, 4);
			case PPC_REG_FR21: return RegisterInfo(PPC_REG_FR21, 0, 4);
			case PPC_REG_FR22: return RegisterInfo(PPC_REG_FR22, 0, 4);
			case PPC_REG_FR23: return RegisterInfo(PPC_REG_FR23, 0, 4);
			case PPC_REG_FR24: return RegisterInfo(PPC_REG_FR24, 0, 4);
			case PPC_REG_FR25: return RegisterInfo(PPC_REG_FR25, 0, 4);
			case PPC_REG_FR26: return RegisterInfo(PPC_REG_FR26, 0, 4);
			case PPC_REG_FR27: return RegisterInfo(PPC_REG_FR27, 0, 4);
			case PPC_REG_FR28: return RegisterInfo(PPC_REG_FR28, 0, 4);
			case PPC_REG_FR29: return RegisterInfo(PPC_REG_FR29, 0, 4);
			case PPC_REG_FR30: return RegisterInfo(PPC_REG_FR30, 0, 4);
			case PPC_REG_FR31: return RegisterInfo(PPC_REG_FR31, 0, 4);

			case PPC_REG_CRF0: return RegisterInfo(PPC_REG_CRF0, 0, 4);
			case PPC_REG_CRF1: return RegisterInfo(PPC_REG_CRF1, 0, 4);
			case PPC_REG_CRF2: return RegisterInfo(PPC_REG_CRF2, 0, 4);
			case PPC_REG_CRF3: return RegisterInfo(PPC_REG_CRF3, 0, 4);
			case PPC_REG_CRF4: return RegisterInfo(PPC_REG_CRF4, 0, 4);
			case PPC_REG_CRF5: return RegisterInfo(PPC_REG_CRF5, 0, 4);
			case PPC_REG_CRF6: return RegisterInfo(PPC_REG_CRF6, 0, 4);
			case PPC_REG_CRF7: return RegisterInfo(PPC_REG_CRF7, 0, 4);

			// TODO: make these subregisters of VSX registers
			case PPC_REG_AV_VR0: return RegisterInfo(PPC_REG_AV_VR0, 0, 4);
			case PPC_REG_AV_VR1: return RegisterInfo(PPC_REG_AV_VR1, 0, 4);
			case PPC_REG_AV_VR2: return RegisterInfo(PPC_REG_AV_VR2, 0, 4);
			case PPC_REG_AV_VR3: return RegisterInfo(PPC_REG_AV_VR3, 0, 4);
			case PPC_REG_AV_VR4: return RegisterInfo(PPC_REG_AV_VR4, 0, 4);
			case PPC_REG_AV_VR5: return RegisterInfo(PPC_REG_AV_VR5, 0, 4);
			case PPC_REG_AV_VR6: return RegisterInfo(PPC_REG_AV_VR6, 0, 4);
			case PPC_REG_AV_VR7: return RegisterInfo(PPC_REG_AV_VR7, 0, 4);
			case PPC_REG_AV_VR8: return RegisterInfo(PPC_REG_AV_VR8, 0, 4);
			case PPC_REG_AV_VR9: return RegisterInfo(PPC_REG_AV_VR9, 0, 4);
			case PPC_REG_AV_VR10: return RegisterInfo(PPC_REG_AV_VR10, 0, 4);
			case PPC_REG_AV_VR11: return RegisterInfo(PPC_REG_AV_VR11, 0, 4);
			case PPC_REG_AV_VR12: return RegisterInfo(PPC_REG_AV_VR12, 0, 4);
			case PPC_REG_AV_VR13: return RegisterInfo(PPC_REG_AV_VR13, 0, 4);
			case PPC_REG_AV_VR14: return RegisterInfo(PPC_REG_AV_VR14, 0, 4);
			case PPC_REG_AV_VR15: return RegisterInfo(PPC_REG_AV_VR15, 0, 4);
			case PPC_REG_AV_VR16: return RegisterInfo(PPC_REG_AV_VR16, 0, 4);
			case PPC_REG_AV_VR17: return RegisterInfo(PPC_REG_AV_VR17, 0, 4);
			case PPC_REG_AV_VR18: return RegisterInfo(PPC_REG_AV_VR18, 0, 4);
			case PPC_REG_AV_VR19: return RegisterInfo(PPC_REG_AV_VR19, 0, 4);
			case PPC_REG_AV_VR20: return RegisterInfo(PPC_REG_AV_VR20, 0, 4);
			case PPC_REG_AV_VR21: return RegisterInfo(PPC_REG_AV_VR21, 0, 4);
			case PPC_REG_AV_VR22: return RegisterInfo(PPC_REG_AV_VR22, 0, 4);
			case PPC_REG_AV_VR23: return RegisterInfo(PPC_REG_AV_VR23, 0, 4);
			case PPC_REG_AV_VR24: return RegisterInfo(PPC_REG_AV_VR24, 0, 4);
			case PPC_REG_AV_VR25: return RegisterInfo(PPC_REG_AV_VR25, 0, 4);
			case PPC_REG_AV_VR26: return RegisterInfo(PPC_REG_AV_VR26, 0, 4);
			case PPC_REG_AV_VR27: return RegisterInfo(PPC_REG_AV_VR27, 0, 4);
			case PPC_REG_AV_VR28: return RegisterInfo(PPC_REG_AV_VR28, 0, 4);
			case PPC_REG_AV_VR29: return RegisterInfo(PPC_REG_AV_VR29, 0, 4);
			case PPC_REG_AV_VR30: return RegisterInfo(PPC_REG_AV_VR30, 0, 4);
			case PPC_REG_AV_VR31: return RegisterInfo(PPC_REG_AV_VR31, 0, 4);

			case PPC_REG_VSX_VR0: return RegisterInfo(PPC_REG_VSX_VR0, 0, 8);
			case PPC_REG_VSX_VR1: return RegisterInfo(PPC_REG_VSX_VR1, 0, 8);
			case PPC_REG_VSX_VR2: return RegisterInfo(PPC_REG_VSX_VR2, 0, 8);
			case PPC_REG_VSX_VR3: return RegisterInfo(PPC_REG_VSX_VR3, 0, 8);
			case PPC_REG_VSX_VR4: return RegisterInfo(PPC_REG_VSX_VR4, 0, 8);
			case PPC_REG_VSX_VR5: return RegisterInfo(PPC_REG_VSX_VR5, 0, 8);
			case PPC_REG_VSX_VR6: return RegisterInfo(PPC_REG_VSX_VR6, 0, 8);
			case PPC_REG_VSX_VR7: return RegisterInfo(PPC_REG_VSX_VR7, 0, 8);
			case PPC_REG_VSX_VR8: return RegisterInfo(PPC_REG_VSX_VR8, 0, 8);
			case PPC_REG_VSX_VR9: return RegisterInfo(PPC_REG_VSX_VR9, 0, 8);
			case PPC_REG_VSX_VR10: return RegisterInfo(PPC_REG_VSX_VR10, 0, 8);
			case PPC_REG_VSX_VR11: return RegisterInfo(PPC_REG_VSX_VR11, 0, 8);
			case PPC_REG_VSX_VR12: return RegisterInfo(PPC_REG_VSX_VR12, 0, 8);
			case PPC_REG_VSX_VR13: return RegisterInfo(PPC_REG_VSX_VR13, 0, 8);
			case PPC_REG_VSX_VR14: return RegisterInfo(PPC_REG_VSX_VR14, 0, 8);
			case PPC_REG_VSX_VR15: return RegisterInfo(PPC_REG_VSX_VR15, 0, 8);
			case PPC_REG_VSX_VR16: return RegisterInfo(PPC_REG_VSX_VR16, 0, 8);
			case PPC_REG_VSX_VR17: return RegisterInfo(PPC_REG_VSX_VR17, 0, 8);
			case PPC_REG_VSX_VR18: return RegisterInfo(PPC_REG_VSX_VR18, 0, 8);
			case PPC_REG_VSX_VR19: return RegisterInfo(PPC_REG_VSX_VR19, 0, 8);
			case PPC_REG_VSX_VR20: return RegisterInfo(PPC_REG_VSX_VR20, 0, 8);
			case PPC_REG_VSX_VR21: return RegisterInfo(PPC_REG_VSX_VR21, 0, 8);
			case PPC_REG_VSX_VR22: return RegisterInfo(PPC_REG_VSX_VR22, 0, 8);
			case PPC_REG_VSX_VR23: return RegisterInfo(PPC_REG_VSX_VR23, 0, 8);
			case PPC_REG_VSX_VR24: return RegisterInfo(PPC_REG_VSX_VR24, 0, 8);
			case PPC_REG_VSX_VR25: return RegisterInfo(PPC_REG_VSX_VR25, 0, 8);
			case PPC_REG_VSX_VR26: return RegisterInfo(PPC_REG_VSX_VR26, 0, 8);
			case PPC_REG_VSX_VR27: return RegisterInfo(PPC_REG_VSX_VR27, 0, 8);
			case PPC_REG_VSX_VR28: return RegisterInfo(PPC_REG_VSX_VR28, 0, 8);
			case PPC_REG_VSX_VR29: return RegisterInfo(PPC_REG_VSX_VR29, 0, 8);
			case PPC_REG_VSX_VR30: return RegisterInfo(PPC_REG_VSX_VR30, 0, 8);
			case PPC_REG_VSX_VR31: return RegisterInfo(PPC_REG_VSX_VR31, 0, 8);
			case PPC_REG_VSX_VR32: return RegisterInfo(PPC_REG_VSX_VR32, 0, 8);
			case PPC_REG_VSX_VR33: return RegisterInfo(PPC_REG_VSX_VR33, 0, 8);
			case PPC_REG_VSX_VR34: return RegisterInfo(PPC_REG_VSX_VR34, 0, 8);
			case PPC_REG_VSX_VR35: return RegisterInfo(PPC_REG_VSX_VR35, 0, 8);
			case PPC_REG_VSX_VR36: return RegisterInfo(PPC_REG_VSX_VR36, 0, 8);
			case PPC_REG_VSX_VR37: return RegisterInfo(PPC_REG_VSX_VR37, 0, 8);
			case PPC_REG_VSX_VR38: return RegisterInfo(PPC_REG_VSX_VR38, 0, 8);
			case PPC_REG_VSX_VR39: return RegisterInfo(PPC_REG_VSX_VR39, 0, 8);
			case PPC_REG_VSX_VR40: return RegisterInfo(PPC_REG_VSX_VR40, 0, 8);
			case PPC_REG_VSX_VR41: return RegisterInfo(PPC_REG_VSX_VR41, 0, 8);
			case PPC_REG_VSX_VR42: return RegisterInfo(PPC_REG_VSX_VR42, 0, 8);
			case PPC_REG_VSX_VR43: return RegisterInfo(PPC_REG_VSX_VR43, 0, 8);
			case PPC_REG_VSX_VR44: return RegisterInfo(PPC_REG_VSX_VR44, 0, 8);
			case PPC_REG_VSX_VR45: return RegisterInfo(PPC_REG_VSX_VR45, 0, 8);
			case PPC_REG_VSX_VR46: return RegisterInfo(PPC_REG_VSX_VR46, 0, 8);
			case PPC_REG_VSX_VR47: return RegisterInfo(PPC_REG_VSX_VR47, 0, 8);
			case PPC_REG_VSX_VR48: return RegisterInfo(PPC_REG_VSX_VR48, 0, 8);
			case PPC_REG_VSX_VR49: return RegisterInfo(PPC_REG_VSX_VR49, 0, 8);
			case PPC_REG_VSX_VR50: return RegisterInfo(PPC_REG_VSX_VR50, 0, 8);
			case PPC_REG_VSX_VR51: return RegisterInfo(PPC_REG_VSX_VR51, 0, 8);
			case PPC_REG_VSX_VR52: return RegisterInfo(PPC_REG_VSX_VR52, 0, 8);
			case PPC_REG_VSX_VR53: return RegisterInfo(PPC_REG_VSX_VR53, 0, 8);
			case PPC_REG_VSX_VR54: return RegisterInfo(PPC_REG_VSX_VR54, 0, 8);
			case PPC_REG_VSX_VR55: return RegisterInfo(PPC_REG_VSX_VR55, 0, 8);
			case PPC_REG_VSX_VR56: return RegisterInfo(PPC_REG_VSX_VR56, 0, 8);
			case PPC_REG_VSX_VR57: return RegisterInfo(PPC_REG_VSX_VR57, 0, 8);
			case PPC_REG_VSX_VR58: return RegisterInfo(PPC_REG_VSX_VR58, 0, 8);
			case PPC_REG_VSX_VR59: return RegisterInfo(PPC_REG_VSX_VR59, 0, 8);
			case PPC_REG_VSX_VR60: return RegisterInfo(PPC_REG_VSX_VR60, 0, 8);
			case PPC_REG_VSX_VR61: return RegisterInfo(PPC_REG_VSX_VR61, 0, 8);
			case PPC_REG_VSX_VR62: return RegisterInfo(PPC_REG_VSX_VR62, 0, 8);
			case PPC_REG_VSX_VR63: return RegisterInfo(PPC_REG_VSX_VR63, 0, 8);

			case PPC_REG_GQR0: return RegisterInfo(PPC_REG_GQR0, 0, 4);
			case PPC_REG_GQR1: return RegisterInfo(PPC_REG_GQR1, 0, 4);
			case PPC_REG_GQR2: return RegisterInfo(PPC_REG_GQR2, 0, 4);
			case PPC_REG_GQR3: return RegisterInfo(PPC_REG_GQR3, 0, 4);
			case PPC_REG_GQR4: return RegisterInfo(PPC_REG_GQR4, 0, 4);
			case PPC_REG_GQR5: return RegisterInfo(PPC_REG_GQR5, 0, 4);
			case PPC_REG_GQR6: return RegisterInfo(PPC_REG_GQR6, 0, 4);
			case PPC_REG_GQR7: return RegisterInfo(PPC_REG_GQR7, 0, 4);

			default:
				//LogError("%s(%d == \"%s\") invalid argument", __func__,
				//  regId, PowerPCRegisterName(regId));
				return RegisterInfo(0,0,0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return PPC_REG_GPR1;
	}

	virtual uint32_t GetLinkRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return PPC_REG_LR;
	}

	/*************************************************************************/

	virtual bool CanAssemble() override
	{
		return true;
	}

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		MYLOG("%s()\n", __func__);

		/* prepend directives to command the assembler's origin and endianness */
		string src;
		char buf[1024];
		snprintf(buf, sizeof(buf), ".org %" PRIx64 "\n", addr);
		src += string(buf);
		snprintf(buf, sizeof(buf), ".endian %s\n", (endian == BigEndian) ? "big" : "little");
		src += string(buf);
		src += code;

		/* assemble */
		vector<uint8_t> byteEncoding;
		if(assemble_multiline(src, byteEncoding, errors)) {
			MYLOG("assemble_multiline() failed, errors contains: %s\n", errors.c_str());
			return false;
		}

		result.Clear();
		//for(int i=0; i<byteEncoding.size(); ++i)
		result.Append(&(byteEncoding[0]), byteEncoding.size());
		return true;
	}

	/*************************************************************************/

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;

		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) { /* BXX B-form */
			MYLOG("BXX B-form\n");
			return true;
		}

		if((iw & 0xfc0007fe) == 0x4c000020) { /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			if((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		if((iw & 0xfc0007fe) == 0x4c000420) { /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			if((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		return false;
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) {
			MYLOG("BXX B-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000420) {
			MYLOG("BXX to count reg, XL-form\n");
		} else {
			return false;
		}

		/* BO and BI exist in all 3 of the above forms */
		uint32_t bo = (iw >> 21) & 0x1F;
		if((bo & 0x1E) == 0) return true; // (--ctr)!=0 && cr_bi==0
		if((bo & 0x1E) == 2) return true; // (--ctr)==0 && cr_bi==0
		if((bo & 0x1C) == 4) return true; // cr_bi==0
		if((bo & 0x1E) == 8) return true; // (--ctr)!=0 && cr_bi==1
		if((bo & 0x1E) == 10) return true; // (--ctr)==0 && cr_bi==1
		if((bo & 0x1C) == 12) return true; // cr_bi==1
		return false;
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000001) == 0x48000001) {
			MYLOG("B I-form with LK==1\n");
			return true;
		} else if((iw & 0xfc000001) == 0x40000001) {
			MYLOG("BXX B-form with LK==1\n");
			return true;
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
			return true;
		} else if((iw & 0xfc0007ff) == 0x4c000421) {
			MYLOG("BXX to count reg, XL-form with LK==1\n");
			return true;
		}

		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return IsSkipAndReturnZeroPatchAvailable(data, addr, len);
	}

	/*************************************************************************/

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		(void)len;

		MYLOG("%s()\n", __func__);
		uint32_t nop;
		if(endian == LittleEndian)
			nop = 0x60000000;
		else
			nop = 0x00000060;
		if(len < 4)
			return false;
		for(size_t i=0; i<len/4; ++i)
			((uint32_t *)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		MYLOG("%s()\n", __func__);

		(void)len;
		(void)addr;

		uint32_t iwAfter = 0;
		uint32_t iwBefore = *(uint32_t *)data;
		if(endian == BigEndian)
			iwBefore = bswap32(iwBefore);

		if((iwBefore & 0xfc000000) == 0x40000000) { /* BXX B-form */
			MYLOG("BXX B-form\n");

			uint32_t li_aa_lk = iwBefore & 0xffff; /* grab BD,AA,LK */
			if(li_aa_lk & 0x8000) /* sign extend? */
				li_aa_lk |= 0x03FF0000;

			iwAfter = 0x48000000 | li_aa_lk;
		}
		else
		if((iwBefore & 0xfc0007fe) == 0x4c000020) { /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else
		if((iwBefore & 0xfc0007fe) == 0x4c000420) { /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else {
			return false;
		}

		if(endian == BigEndian)
			iwAfter = bswap32(iwAfter);
		*(uint32_t *)data = iwAfter;
		return true;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) {
			MYLOG("BXX B-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000420) {
			MYLOG("BXX to count reg, XL-form\n");
		} else {
			return false;
		}

		iw ^= 0x1000000;

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)data;
		(void)addr;
		(void)len;
		(void)value;
		MYLOG("%s()\n", __func__);

		if(value > 0x4000)
			return false;

		/* li (load immediate) is pseudo-op for addi rD,rA,SIMM with rA=0 */
		uint32_t iw = 0x38600000 | (value & 0xFFFF); // li (load immediate)

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;
	}

	/*************************************************************************/

};

class PpcImportedFunctionRecognizer: public FunctionRecognizer
{
	private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		MYLOG("%s()\n", __func__);
		LowLevelILInstruction lis, lwz, mtctr, tmp;
		int64_t entry, constGotBase;
		uint32_t regGotBase, regJump;

		// lis   r11, 0x1002     ; r11 -> base of GOT
		// lwz   r11, ???(r11)   ; get GOT[???]
		// mtctr r11             ; move to ctr
		// bctr                  ; branch to ctr
		if(il->GetInstructionCount() != 4)
			return false;

		//
		// LIS   r11, 0x1002
		//
		lis = il->GetInstruction(0);
		if(lis.operation != LLIL_SET_REG)
			return false;
		/* get the constant, address of GOT */
		tmp = lis.GetSourceExpr<LLIL_SET_REG>();
		if ((tmp.operation != LLIL_CONST) && (tmp.operation != LLIL_CONST_PTR) && (tmp.operation != LLIL_EXTERN_PTR))
			return false;
		constGotBase = tmp.GetConstant();
		/* get the destination register, is assigned the address of GOT */
		regGotBase = lis.GetDestRegister<LLIL_SET_REG>();
		//
		// LWZ   r11, ???(r11)
		//
		lwz = il->GetInstruction(1);
		if(lwz.operation != LLIL_SET_REG)
			return false;

		if(lwz.GetDestRegister<LLIL_SET_REG>() != regGotBase) // lwz must assign to same reg
			return false;

		tmp = lwz.GetSourceExpr<LLIL_SET_REG>(); // lwz must read from LOAD
		if(tmp.operation != LLIL_LOAD)
			return false;

		// "dereference" the load(...) to get either:
		tmp = tmp.GetSourceExpr<LLIL_LOAD>();
		// r11         (LLIL_REG)
		if(tmp.operation == LLIL_REG) {
			if(regGotBase != tmp.GetSourceRegister<LLIL_REG>()) // lwz must read from same reg
				return false;

			entry = constGotBase;
		}
		// r11 + ???   (LLIL_ADD)
		else if(tmp.operation == LLIL_ADD) {
			LowLevelILInstruction lhs, rhs;

			lhs = tmp.GetLeftExpr<LLIL_ADD>();
			rhs = tmp.GetRightExpr<LLIL_ADD>();

			if(lhs.operation != LLIL_REG)
				return false;
			if(lhs.GetSourceRegister<LLIL_REG>() != regGotBase)
				return false;

			if(rhs.operation != LLIL_CONST)
				return false;

			entry = constGotBase + rhs.GetConstant();
		}
		else {
			return false;
		}

		//
		// MTCTR
		//
		mtctr = il->GetInstruction(2);
		if(mtctr.operation != LLIL_SET_REG)
			return false;
		/* from regGotBase */
		tmp = mtctr.GetSourceExpr();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regGotBase)
			return false;
		/* to new register (probably CTR) */
		regJump = mtctr.GetDestRegister<LLIL_SET_REG>();

		//
		// JUMP
		//
		tmp = il->GetInstruction(3);
		if((tmp.operation != LLIL_JUMP) && (tmp.operation != LLIL_TAILCALL))
			return false;
		tmp = (tmp.operation == LLIL_JUMP) ? tmp.GetDestExpr<LLIL_JUMP>() : tmp.GetDestExpr<LLIL_TAILCALL>();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regJump)
			return false;

		// done!
		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym) {
			return false;
		}
		if (sym->GetType() != ImportAddressSymbol) {
			return false;
		}
		data->DefineImportedFunction(sym, func);

		return true;
	}

	bool RecognizeMachoPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		(void)data;
		(void)func;
		(void)il;

		MYLOG("%s()\n", __func__);

		return false;
	}

	public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		else if (RecognizeMachoPLTEntries(data, func, il))
			return true;
		return false;
	}
};

class PpcSvr4CallingConvention: public CallingConvention
{
public:
	PpcSvr4CallingConvention(Architecture* arch): CallingConvention(arch, "svr4")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_GPR3, PPC_REG_GPR4, PPC_REG_GPR5, PPC_REG_GPR6,
			PPC_REG_GPR7, PPC_REG_GPR8, PPC_REG_GPR9, PPC_REG_GPR10
			/* remaining arguments onto stack */
		};
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_FR1, PPC_REG_FR2, PPC_REG_FR3, PPC_REG_FR4,
			PPC_REG_FR5, PPC_REG_FR6, PPC_REG_FR7, PPC_REG_FR8,
			PPC_REG_FR9, PPC_REG_FR10, PPC_REG_FR11, PPC_REG_FR12,
			PPC_REG_FR13
		};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_GPR0, PPC_REG_GPR2, PPC_REG_GPR3, PPC_REG_GPR4,
			PPC_REG_GPR5, PPC_REG_GPR6, PPC_REG_GPR7, PPC_REG_GPR8,
			PPC_REG_GPR9, PPC_REG_GPR10, PPC_REG_GPR12,

			PPC_REG_FR0, PPC_REG_FR1, PPC_REG_FR2, PPC_REG_FR3,
			PPC_REG_FR4, PPC_REG_FR5, PPC_REG_FR6, PPC_REG_FR7,
			PPC_REG_FR8, PPC_REG_FR9, PPC_REG_FR10, PPC_REG_FR11,
			PPC_REG_FR12, PPC_REG_FR13,

			PPC_REG_LR, PPC_REG_CTR,
		};
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_GPR14, PPC_REG_GPR15, PPC_REG_GPR16, PPC_REG_GPR17,
			PPC_REG_GPR18, PPC_REG_GPR19, PPC_REG_GPR20, PPC_REG_GPR21,
			PPC_REG_GPR22, PPC_REG_GPR23, PPC_REG_GPR24, PPC_REG_GPR25,
			PPC_REG_GPR26, PPC_REG_GPR27, PPC_REG_GPR28, PPC_REG_GPR29,
			PPC_REG_GPR30, PPC_REG_GPR31
		};
	}


	virtual uint32_t GetGlobalPointerRegister() override
	{
		return PPC_REG_GPR13;
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_GPR3;
	}


	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return PPC_REG_FR1;
	}
};

class PpcLinuxSyscallCallingConvention: public CallingConvention
{
public:
	PpcLinuxSyscallCallingConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_GPR0,
			PPC_REG_GPR3, PPC_REG_GPR4, PPC_REG_GPR5, PPC_REG_GPR6,
			PPC_REG_GPR7, PPC_REG_GPR8, PPC_REG_GPR9, PPC_REG_GPR10
		};
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_GPR3
		};
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> {
			PPC_REG_GPR14, PPC_REG_GPR15, PPC_REG_GPR16, PPC_REG_GPR17,
			PPC_REG_GPR18, PPC_REG_GPR19, PPC_REG_GPR20, PPC_REG_GPR21,
			PPC_REG_GPR22, PPC_REG_GPR23, PPC_REG_GPR24, PPC_REG_GPR25,
			PPC_REG_GPR26, PPC_REG_GPR27, PPC_REG_GPR28, PPC_REG_GPR29,
			PPC_REG_GPR30, PPC_REG_GPR31
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_GPR3;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};

uint16_t bswap16(uint16_t x)
{
	return (x >> 8) | (x << 8);
}

class PpcElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)len;
		auto info = reloc->GetInfo();
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		auto swap16 = [&arch](uint16_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap16(x); };
		uint64_t target = reloc->GetTarget();
		switch (info.nativeType)
		{
		case R_PPC_ADDR16_LO:
			dest16[0] = swap16((uint16_t)((target + info.addend) & 0xffff));
			break;
		case R_PPC_ADDR16_HA:
			dest16[0] = swap16((uint16_t)((target + info.addend) >> 16));
			break;
		case R_PPC_REL24:
			dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
				(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
			break;
		case R_PPC_REL16_HA:
			dest16[0] = swap16(HA(target - reloc->GetAddress() + info.addend));
			break;
		case R_PPC_REL16_HI:
			dest16[0] = swap16((uint16_t)((target - reloc->GetAddress()+ info.addend) >> 16));
			break;
		case R_PPC_REL16_LO:
			dest16[0] = swap16((uint16_t)((target - reloc->GetAddress()+ info.addend) & 0xffff));
			break;
		case R_PPC_JMP_SLOT:
		case R_PPC_GLOB_DAT:
		case R_PPC_COPY:
			dest32[0] = swap((uint32_t)target);
			break;
		case R_PPC_PLTREL24:
			dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
				(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
			break;
		case R_PPC_LOCAL24PC:
			dest32[0] = swap((swap(dest32[0]) & 0xfc000003) |
				(uint32_t)((((target + info.addend - reloc->GetAddress()) >> 2) & 0xffffff) << 2));
			break;
		case R_PPC_ADDR32:
			dest32[0] = swap((uint32_t)(target + info.addend));
			break;
		case R_PPC_RELATIVE:
			dest32[0] = swap((uint32_t)info.base);
			break;
		case R_PPC_REL32:
			dest32[0] = swap((uint32_t)(target - reloc->GetAddress() + info.addend));
			break;
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch; (void)result;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			reloc.pcRelative = false;
			reloc.dataRelocation = false;
			switch (reloc.nativeType)
			{
			case R_PPC_NONE:
				reloc.type = IgnoredRelocation;
				break;
			case R_PPC_COPY:
				reloc.type = ELFCopyRelocationType;
				break;
			case R_PPC_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				break;
			case R_PPC_JMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				break;
			case R_PPC_ADDR16_HA:
			case R_PPC_ADDR16_LO:
				reloc.size = 2;
				break;
			case R_PPC_REL16_HA:
			case R_PPC_REL16_HI:
			case R_PPC_REL16_LO:
				reloc.size = 2;
				reloc.pcRelative = true;
				break;
			case R_PPC_REL24:
			case R_PPC_PLTREL24:
				reloc.pcRelative = true;
				break;
			case R_PPC_ADDR32:
				reloc.dataRelocation = true;
				break;
			case R_PPC_RELATIVE:
				reloc.dataRelocation = true;
				reloc.baseRelative = true;
				reloc.base += reloc.addend;
				break;
			case R_PPC_REL32:
				reloc.pcRelative = true;
				break;
			case R_PPC_LOCAL24PC:
				reloc.pcRelative = true;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((ElfPpcRelocationType)reloc));
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
		case R_PPC_ADDR16_HA:
		case R_PPC_REL16_HA:
		case R_PPC_REL16_HI:
			return BN_NOCOERCE_EXTERN_PTR;
		default:
			return BN_AUTOCOERCE_EXTERN_PTR;
		}
	}
};

class PpcMachoRelocationHandler: public RelocationHandler
{
public:
	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = UnhandledRelocation;
			relocTypes.insert(reloc.nativeType);
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported Mach-O relocation type: %s", GetRelocationString((MachoPpcRelocationType)reloc));
		return false;
	}
};

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

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		MYLOG("ARCH POWERPC compiled at %s %s\n", __DATE__, __TIME__);

		/* create, register arch in global list of available architectures */
		Architecture* ppc = new PowerpcArchitecture("ppc", BigEndian);
		Architecture::Register(ppc);

		Architecture* ppc_qpx = new PowerpcArchitecture("ppc_qpx", BigEndian, 4, DECODE_FLAGS_QPX);
		Architecture::Register(ppc_qpx);

		Architecture* ppc_spe = new PowerpcArchitecture("ppc_spe", BigEndian, 4, DECODE_FLAGS_SPE);
		Architecture::Register(ppc_spe);

		Architecture* ppc_ps = new PowerpcArchitecture("ppc_ps", BigEndian, 4, DECODE_FLAGS_PS);
		Architecture::Register(ppc_ps);

		Architecture* ppc64 = new PowerpcArchitecture("ppc64", BigEndian, 8);
		Architecture::Register(ppc64);

		Architecture* ppc_le = new PowerpcArchitecture("ppc_le", LittleEndian);
		Architecture::Register(ppc_le);

		Architecture* ppc64_le = new PowerpcArchitecture("ppc64_le", LittleEndian, 8);
		Architecture::Register(ppc64_le);

		/* calling conventions */
		Ref<CallingConvention> conv;
		conv = new PpcSvr4CallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);
		ppc->SetDefaultCallingConvention(conv);
		ppc_qpx->RegisterCallingConvention(conv);
		ppc_qpx->SetDefaultCallingConvention(conv);
		ppc_spe->RegisterCallingConvention(conv);
		ppc_spe->SetDefaultCallingConvention(conv);
		ppc_ps->RegisterCallingConvention(conv);
		ppc_ps->SetDefaultCallingConvention(conv);
		ppc64->RegisterCallingConvention(conv);
		ppc64->SetDefaultCallingConvention(conv);
		conv = new PpcLinuxSyscallCallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);
		ppc_qpx->RegisterCallingConvention(conv);
		ppc_spe->RegisterCallingConvention(conv);
		ppc_ps->RegisterCallingConvention(conv);
		ppc64->RegisterCallingConvention(conv);

		conv = new PpcSvr4CallingConvention(ppc_le);
		ppc_le->RegisterCallingConvention(conv);
		ppc_le->SetDefaultCallingConvention(conv);
		ppc64_le->RegisterCallingConvention(conv);
		ppc64_le->SetDefaultCallingConvention(conv);
		conv = new PpcLinuxSyscallCallingConvention(ppc_le);
		ppc_le->RegisterCallingConvention(conv);
		ppc64_le->RegisterCallingConvention(conv);

		/* function recognizer */
		ppc->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc_qpx->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc_spe->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc_ps->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc_le->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());

		ppc->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_qpx->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_spe->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_ps->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_le->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_le->RegisterRelocationHandler("Mach-O", new PpcMachoRelocationHandler());
		/* call the STATIC RegisterArchitecture with "Mach-O"
			which invokes the "Mach-O" INSTANCE of RegisterArchitecture,
			supplied with CPU_TYPE_POWERPC from machoview.h */
		#define MACHO_CPU_TYPE_ARM 12
		#define MACHO_CPU_TYPE_POWERPC 18 /* from machostruct.h */
		BinaryViewType::RegisterArchitecture(
			"Mach-O", /* name of the binary view type */
			MACHO_CPU_TYPE_POWERPC, /* id (key in m_arch map) */
			BigEndian,
			ppc /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"Mach-O", /* name of the binary view type */
			MACHO_CPU_TYPE_POWERPC, /* id (key in m_arch map) */
			LittleEndian,
			ppc_le /* the architecture */
		);

		/* for e_machine field in Elf32_Ehdr */
		#define EM_386 3
		#define EM_PPC 20
		#define EM_PPC64 21
		#define EM_X86_64 62
		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC, /* id (key in m_arch map) */
			BigEndian,
			ppc /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC64, /* id (key in m_arch map) */
			BigEndian,
			ppc64 /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC, /* id (key in m_arch map) */
			LittleEndian,
			ppc_le /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC64, /* id (key in m_arch map) */
			LittleEndian,
			ppc64_le /* the architecture */
		);

		return true;
	}
}

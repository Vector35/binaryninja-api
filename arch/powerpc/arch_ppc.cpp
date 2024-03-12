#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <map>
#include <vector>

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug
//#define MYLOG printf

#include "lowlevelilinstruction.h"
using namespace BinaryNinja; // for ::LogDebug, etc.

#include "disassembler.h"
#include "assembler.h"

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
	int cs_mode_local;

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
	PowerpcArchitecture(const char* name, BNEndianness endian_): Architecture(name)
	{
		endian = endian_;
		cs_mode_local = 0;
	}

	/* initialization list */
	PowerpcArchitecture(const char* name, BNEndianness endian_, int CS_MODE_): Architecture(name)
	{
		endian = endian_;
		cs_mode_local = CS_MODE_;
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
		return 4;
	}

	virtual size_t GetDefaultIntegerSize() const override
	{
		MYLOG("%s()\n", __func__);
		return 4;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
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
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);

		//MYLOG("%s()\n", __func__);

		if (maxLen < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			return false;
		}

		if (DoesQualifyForLocalDisassembly(data)) {
			result.length = 4;
			return true;
		}

		/* decompose the instruction to get branch info */
		if(powerpc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, cs_mode_local)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			return false;
		}

		uint32_t raw_insn = *(const uint32_t *) data;

		if (endian == BigEndian)
			raw_insn = bswap32(raw_insn);

		switch (raw_insn >> 26)
		{
			case 18: /* b (b, ba, bl, bla) */
			{
				uint32_t target = raw_insn & 0x03fffffc;

				/* sign extend target */
				if ((target >> 25) & 1)
					target |= 0xfc000000;

				/* account for absolute addressing */
				if (!(raw_insn & 2))
					target += (uint32_t) addr;

				if (raw_insn & 1)
					result.AddBranch(CallDestination, target);
				else
					result.AddBranch(UnconditionalBranch, target);

				break;
			}
			case 16: /* bc */
			{
				uint32_t target = raw_insn & 0xfffc;
				uint8_t bo = (raw_insn >> 21) & 0x1f;
				bool lk = raw_insn & 1;

				/* sign extend target */
				if ((target >> 15) & 1)
					target |= 0xffff0000;

				/* account for absolute addressing */
				if (!(raw_insn & 2))
					target += (uint32_t) addr;

				if (target != addr + 4)
				{
					if ((bo & 0x14) == 0x14)
						result.AddBranch(lk ? CallDestination : UnconditionalBranch, target);
					else if (!lk)
					{
						result.AddBranch(FalseBranch, addr + 4);
						result.AddBranch(TrueBranch, target);
					}
				}

				break;
			}
			case 19: /* bcctr, bclr */
			{
				uint8_t bo = (raw_insn >> 21) & 0x1f;
				bool lk = raw_insn & 1;
				bool blr = false;

				switch ((raw_insn >> 1) & 0x3ff)
				{
					case 16:
						blr = true;
						FALL_THROUGH
					case 528:
						if ((bo & 0x14) == 0x14 && !lk)
							result.AddBranch(blr ? FunctionReturn : UnresolvedBranch);

						break;
				}

				break;
			}
		}

		switch(insn->id) {
			case PPC_INS_TRAP:
				result.AddBranch(UnresolvedBranch);
				break;
			case PPC_INS_RFI:
				result.AddBranch(UnresolvedBranch);
				break;
		}

		result.length = 4;
		return true;
	}

	bool DoesQualifyForLocalDisassembly(const uint8_t *data)
	{
		uint32_t insword = *(uint32_t *)data;
		if(endian == BigEndian)
			insword = bswap32(insword);

		// 111111xxx00xxxxxxxxxx00001000000 <- fcmpo
		uint32_t tmp = insword & 0xFC6007FF;
		if (tmp==0xFC000040)
			return true;
		// 111100xxxxxxxxxxxxxxx00111010xxx <- xxpermr
		if((insword & 0xFC0007F8) == 0xF00001D0)
			return true;
		// 000100xxxxxxxxxxxxxxxxxxx000110x <- psq_lx
		// 000100xxxxxxxxxxxxxxxxxxx000111x <- psq_stx
		// 000100xxxxxxxxxxxxxxxxxxx100110x <- psq_lux
		// 000100xxxxxxxxxxxxxxxxxxx100111x <- psq_stux
		tmp = insword & 0xFC00007E;
		if (tmp==0x1000000C || tmp==0x1000000E || tmp==0x1000004C || tmp==0x1000004E)
			return true;
		// 000100xxxxxxxxxx00000xxxxx011000 <- ps_muls0
		// 000100xxxxxxxxxx00000xxxxx011001 <- ps_muls0.
		// 000100xxxxxxxxxx00000xxxxx011010 <- ps_muls1
		// 000100xxxxxxxxxx00000xxxxx011011 <- ps_muls1.
		tmp = insword & 0xFC00F83F;
		if (tmp==0x10000018 || tmp==0x10000019 || tmp==0x1000001A || tmp==0x1000001B)
			return true;

		return false;
	}

	bool PerformLocalDisassembly(const uint8_t *data, uint64_t addr, size_t &len, vector<InstructionTextToken> &result)
	{
		(void)addr;

		if (len < 4) return false;
		uint32_t insword = *(uint32_t *)data;
		if(endian == BigEndian)
			insword = bswap32(insword);

		len = 4;

		char buf[16];

		// 111111AAA00BBBBBCCCCC00001000000 "fcmpo crA,fB,fC"
		uint32_t tmp = insword & 0xFC6007FF;
		if (tmp==0xFC000040) {
			result.emplace_back(TextToken, "fcmpo");
			result.emplace_back(TextToken, "   ");
			snprintf(buf, sizeof(buf), "cr%d", (insword >> 23) & 7);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "f%d", (insword >> 16) & 31);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "f%d", (insword >> 11) & 31);
			result.emplace_back(RegisterToken, buf);
			return true;
		}

		// 111100AAAAABBBBBCCCCC00011010BCA "xxpermr vsA,vsB,vsC"
		if ((insword & 0xFC0007F8)==0xF00001D0) {
			int a = ((insword & 0x3E00000)>>21)|((insword & 0x1)<<5);
			int b = ((insword & 0x1F0000)>>16)|((insword & 0x4)<<3);
			int c = ((insword & 0xF800)>>11)|((insword & 0x2)<<4);
			result.emplace_back(TextToken, "xxpermr");
			result.emplace_back(TextToken, " ");
			snprintf(buf, sizeof(buf), "vs%d", a);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "vs%d", b);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "vs%d", c);
			result.emplace_back(RegisterToken, buf);
			return true;
		}

		// 000100AAAAABBBBBCCCCCDEEE000110x psq_lx FREG,GPR,GPR,NUM,NUM
		// 000100AAAAABBBBBCCCCCDEEE000111x psq_stx FREG,GPR,GPR,NUM,NUM
		// 000100AAAAABBBBBCCCCCDEEE100110x psq_lux FREG,GPR,GPR,NUM,NUM
		// 000100AAAAABBBBBCCCCCDEEE100111x psq_stux FREG,GPR,GPR,NUM,NUM
		tmp = insword & 0xFC00007E;
		if (tmp==0x1000000C || tmp==0x1000000E || tmp==0x1000004C || tmp==0x1000004E) {
			switch(tmp) {
				case 0x1000000C:
					result.emplace_back(TextToken, "psq_lx");
					result.emplace_back(TextToken, "  ");
					break;
				case 0x1000000E: result.emplace_back(TextToken, "psq_stx");
					result.emplace_back(TextToken, " ");
					break;
				case 0x1000004C: result.emplace_back(TextToken, "psq_lux");
					result.emplace_back(TextToken, " ");
					break;
				case 0x1000004E: result.emplace_back(TextToken, "psq_stux");
					result.emplace_back(TextToken, " ");
					break;
			}
			snprintf(buf, sizeof(buf), "f%d", (insword & 0x3E00000) >> 21);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "r%d", (insword & 0x1F0000) >> 16);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "r%d", (insword & 0xF800) >> 11);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			tmp = (insword & 0x400)>>10;
			snprintf(buf, sizeof(buf), "%d", tmp);
			result.emplace_back(IntegerToken, buf, tmp, 1);
			result.emplace_back(OperandSeparatorToken, ", ");
			tmp = (insword & 0x380)>>7;
			snprintf(buf, sizeof(buf), "%d", tmp);
			result.emplace_back(IntegerToken, buf, tmp, 1);
			return true;
		}

		// 000100AAAAABBBBB00000CCCCC011000 ps_muls0 FREG,FREG,FREG
		// 000100AAAAABBBBB00000CCCCC011001 ps_muls0. FREG,FREG,FREG
		// 000100AAAAABBBBB00000CCCCC011010 ps_muls1 FREG,FREG,FREG
		// 000100AAAAABBBBB00000CCCCC011011 ps_muls1. FREG,FREG,FREG
		tmp = insword & 0xFC00F83F;
		if (tmp==0x10000018 || tmp==0x10000019 || tmp==0x1000001A || tmp==0x1000001B) {
			switch(tmp) {
				case 0x10000018: result.emplace_back(TextToken, "ps_muls0"); break;
				case 0x10000019: result.emplace_back(TextToken, "ps_muls0."); break;
				case 0x1000001A: result.emplace_back(TextToken, "ps_muls1"); break;
				case 0x1000001B: result.emplace_back(TextToken, "ps_muls1."); break;
			}
			result.emplace_back(TextToken, " ");
			snprintf(buf, sizeof(buf), "f%d", (insword & 0x3E00000) >> 21);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "f%d", (insword & 0x1F0000) >> 16);
			result.emplace_back(RegisterToken, buf);
			result.emplace_back(OperandSeparatorToken, ", ");
			snprintf(buf, sizeof(buf), "f%d", (insword & 0x7C0) >> 6);
			result.emplace_back(RegisterToken, buf);
			return true;
		}

		return false;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		bool rc = false;
		bool capstoneWorkaround = false;
		char buf[32];
		size_t strlenMnem;
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);
		struct cs_detail *detail = &(res.detail);
		struct cs_ppc *ppc = &(detail->ppc);

		//MYLOG("%s()\n", __func__);

		if (len < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}

		if (DoesQualifyForLocalDisassembly(data))
			return PerformLocalDisassembly(data, addr, len, result);

		if(powerpc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, cs_mode_local)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			goto cleanup;
		}

		switch (insn->id)
		{
			case PPC_INS_CRAND:
			case PPC_INS_CRANDC:
			case PPC_INS_CRNAND:
			case PPC_INS_CROR:
			case PPC_INS_CRORC:
			case PPC_INS_CRNOR:
			case PPC_INS_CREQV:
			case PPC_INS_CRXOR:
			case PPC_INS_CRSET:
			case PPC_INS_CRCLR:
			case PPC_INS_CRNOT:
			case PPC_INS_CRMOVE:
				capstoneWorkaround = true;
		}

		/* mnemonic */
		result.emplace_back(InstructionToken, insn->mnemonic);

		/* padding between mnemonic and operands */
		memset(buf, ' ', 8);
		strlenMnem = strlen(insn->mnemonic);
		if(strlenMnem < 8)
			buf[8-strlenMnem] = '\0';
		else
			buf[1] = '\0';
		result.emplace_back(TextToken, buf);

		/* operands */
		for(int i=0; i<ppc->op_count; ++i) {
			struct cs_ppc_op *op = &(ppc->operands[i]);

			switch(op->type) {
				case PPC_OP_REG:
					//MYLOG("pushing a register\n");
					if (capstoneWorkaround || (insn->id == PPC_INS_ISEL && i == 3))
						result.emplace_back(TextToken, GetFlagName(op->reg - PPC_REG_R0));
					else
						result.emplace_back(RegisterToken, GetRegisterName(op->reg));
					break;
				case PPC_OP_IMM:
					//MYLOG("pushing an integer\n");

					switch(insn->id) {
						case PPC_INS_B:
						case PPC_INS_BA:
						case PPC_INS_BC:
						case PPC_INS_BCL:
						case PPC_INS_BL:
						case PPC_INS_BLA:
							snprintf(buf, sizeof(buf), "0x%llx", op->imm);
							result.emplace_back(CodeRelativeAddressToken, buf, (uint32_t) op->imm, 4);
							break;
						case PPC_INS_ADDIS:
						case PPC_INS_LIS:
						case PPC_INS_ORIS:
						case PPC_INS_XORIS:
						case PPC_INS_ORI:
							snprintf(buf, sizeof(buf), "0x%x", (uint16_t)op->imm);
							result.emplace_back(IntegerToken, buf, (uint16_t) op->imm, 4);
							break;
						default:
							if (op->imm < 0 && op->imm > -0x10000)
								snprintf(buf, sizeof(buf), "-0x%llx", -op->imm);
							else
								snprintf(buf, sizeof(buf), "0x%llx", op->imm);
							result.emplace_back(IntegerToken, buf, op->imm, 4);
					}

					break;
				case PPC_OP_MEM:
					// eg: lwz r11, 8(r11)
					snprintf(buf, sizeof(buf), "%d", op->mem.disp);
					result.emplace_back(IntegerToken, buf, op->mem.disp, 4);

					result.emplace_back(TextToken, "(");
					result.emplace_back(RegisterToken, GetRegisterName(op->mem.base));
					result.emplace_back(TextToken, ")");
					break;
				case PPC_OP_CRX:
				case PPC_OP_INVALID:
				default:
					//MYLOG("pushing a ???\n");
					result.emplace_back(TextToken, "???");
			}

			if(i < ppc->op_count-1) {
				//MYLOG("pushing a comma\n");
				result.emplace_back(OperandSeparatorToken, ", ");
			}
		}

		rc = true;
		len = 4;
		cleanup:
		return rc;
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		bool rc = false;

		if (len < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}

		//if(addr >= 0x10000300 && addr <= 0x10000320) {
		//	MYLOG("%s(data, 0x%llX, 0x%zX, il)\n", __func__, addr, len);
		//}

		struct decomp_result res;

		if (DoesQualifyForLocalDisassembly(data)) {
			il.AddInstruction(il.Unimplemented());
			rc = true;
			len = 4;
			goto cleanup;
		}

		if(powerpc_decompose(data, 4, (uint32_t)addr, endian == LittleEndian, &res, cs_mode_local)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			il.AddInstruction(il.Undefined());
			goto cleanup;
		}

		rc = GetLowLevelILForPPCInstruction(this, il, data, addr, &res, endian == LittleEndian);
		len = 4;

		cleanup:
		return rc;
	}

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
	{
		MYLOG("%s()\n", __func__);

		bool signedWrite = true;
		ExprId left, right;

		switch (flagWriteType)
		{
			case IL_FLAGWRITE_CR0_U:
			case IL_FLAGWRITE_CR1_U:
			case IL_FLAGWRITE_CR2_U:
			case IL_FLAGWRITE_CR3_U:
			case IL_FLAGWRITE_CR4_U:
			case IL_FLAGWRITE_CR5_U:
			case IL_FLAGWRITE_CR6_U:
			case IL_FLAGWRITE_CR7_U:
				signedWrite = false;
				break;

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
			if (op == LLIL_SUB)
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

				if (signedWrite)
					return il.CompareSignedLessThan(size, left, right);
				else
					return il.CompareUnsignedLessThan(size, left, right);

			case IL_FLAG_GT:
			case IL_FLAG_GT_1:
			case IL_FLAG_GT_2:
			case IL_FLAG_GT_3:
			case IL_FLAG_GT_4:
			case IL_FLAG_GT_5:
			case IL_FLAG_GT_6:
			case IL_FLAG_GT_7:
				liftOps();

				if (signedWrite)
					return il.CompareSignedGreaterThan(size, left, right);
				else
					return il.CompareUnsignedGreaterThan(size, left, right);

			case IL_FLAG_EQ:
			case IL_FLAG_EQ_1:
			case IL_FLAG_EQ_2:
			case IL_FLAG_EQ_3:
			case IL_FLAG_EQ_4:
			case IL_FLAG_EQ_5:
			case IL_FLAG_EQ_6:
			case IL_FLAG_EQ_7:
				liftOps();
				return il.CompareEqual(size, left, right);
		}

		BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
		return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
	}


	virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
	{
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
		const char *result = powerpc_reg_to_str(regId, cs_mode_local);

		if(result == NULL)
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
		MYLOG("%s()\n", __func__);
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
		MYLOG("%s(%d)\n", __func__, flag);

		switch(flag) {
			case IL_FLAG_LT: return "lt";
			case IL_FLAG_GT: return "gt";
			case IL_FLAG_EQ: return "eq";
			case IL_FLAG_SO: return "so";
			case IL_FLAG_LT_1: return "cr1_lt";
			case IL_FLAG_GT_1: return "cr1_gt";
			case IL_FLAG_EQ_1: return "cr1_eq";
			case IL_FLAG_SO_1: return "cr1_so";
			case IL_FLAG_LT_2: return "cr2_lt";
			case IL_FLAG_GT_2: return "cr2_gt";
			case IL_FLAG_EQ_2: return "cr2_eq";
			case IL_FLAG_SO_2: return "cr2_so";
			case IL_FLAG_LT_3: return "cr3_lt";
			case IL_FLAG_GT_3: return "cr3_gt";
			case IL_FLAG_EQ_3: return "cr3_eq";
			case IL_FLAG_SO_3: return "cr3_so";
			case IL_FLAG_LT_4: return "cr4_lt";
			case IL_FLAG_GT_4: return "cr4_gt";
			case IL_FLAG_EQ_4: return "cr4_eq";
			case IL_FLAG_SO_4: return "cr4_so";
			case IL_FLAG_LT_5: return "cr5_lt";
			case IL_FLAG_GT_5: return "cr5_gt";
			case IL_FLAG_EQ_5: return "cr5_eq";
			case IL_FLAG_SO_5: return "cr5_so";
			case IL_FLAG_LT_6: return "cr6_lt";
			case IL_FLAG_GT_6: return "cr6_gt";
			case IL_FLAG_EQ_6: return "cr6_eq";
			case IL_FLAG_SO_6: return "cr6_so";
			case IL_FLAG_LT_7: return "cr7_lt";
			case IL_FLAG_GT_7: return "cr7_gt";
			case IL_FLAG_EQ_7: return "cr7_eq";
			case IL_FLAG_SO_7: return "cr7_so";
			case IL_FLAG_XER_SO: return "xer_so";
			case IL_FLAG_XER_OV: return "xer_ov";
			case IL_FLAG_XER_CA: return "xer_ca";
			default: return "ERR_FLAG_NAME";
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
		MYLOG("%s(%d)\n", __func__, writeType);

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
		MYLOG("%s(%d)\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S:
			case IL_FLAGWRITE_CR0_U:
			case IL_FLAGWRITE_MTCR0:
			case IL_FLAGWRITE_INVL0:
				return vector<uint32_t> {
					IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
				};

			case IL_FLAGWRITE_CR1_S:
			case IL_FLAGWRITE_CR1_U:
			case IL_FLAGWRITE_MTCR1:
			case IL_FLAGWRITE_INVL1:
				return vector<uint32_t> {
					IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
				};

			case IL_FLAGWRITE_CR2_S:
			case IL_FLAGWRITE_CR2_U:
			case IL_FLAGWRITE_MTCR2:
			case IL_FLAGWRITE_INVL2:
				return vector<uint32_t> {
					IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
				};

			case IL_FLAGWRITE_CR3_S:
			case IL_FLAGWRITE_CR3_U:
			case IL_FLAGWRITE_MTCR3:
			case IL_FLAGWRITE_INVL3:
				return vector<uint32_t> {
					IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
				};

			case IL_FLAGWRITE_CR4_S:
			case IL_FLAGWRITE_CR4_U:
			case IL_FLAGWRITE_MTCR4:
			case IL_FLAGWRITE_INVL4:
				return vector<uint32_t> {
					IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
				};

			case IL_FLAGWRITE_CR5_S:
			case IL_FLAGWRITE_CR5_U:
			case IL_FLAGWRITE_MTCR5:
			case IL_FLAGWRITE_INVL5:
				return vector<uint32_t> {
					IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
				};

			case IL_FLAGWRITE_CR6_S:
			case IL_FLAGWRITE_CR6_U:
			case IL_FLAGWRITE_MTCR6:
			case IL_FLAGWRITE_INVL6:
				return vector<uint32_t> {
					IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
				};

			case IL_FLAGWRITE_CR7_S:
			case IL_FLAGWRITE_CR7_U:
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
		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S: return IL_FLAGCLASS_CR0_S;
			case IL_FLAGWRITE_CR0_U: return IL_FLAGCLASS_CR0_U;
			case IL_FLAGWRITE_CR1_S: return IL_FLAGCLASS_CR1_S;
			case IL_FLAGWRITE_CR1_U: return IL_FLAGCLASS_CR1_U;
			case IL_FLAGWRITE_CR2_S: return IL_FLAGCLASS_CR2_S;
			case IL_FLAGWRITE_CR2_U: return IL_FLAGCLASS_CR2_U;
			case IL_FLAGWRITE_CR3_S: return IL_FLAGCLASS_CR3_S;
			case IL_FLAGWRITE_CR3_U: return IL_FLAGCLASS_CR3_U;
			case IL_FLAGWRITE_CR4_S: return IL_FLAGCLASS_CR4_S;
			case IL_FLAGWRITE_CR4_U: return IL_FLAGCLASS_CR4_U;
			case IL_FLAGWRITE_CR5_S: return IL_FLAGCLASS_CR5_S;
			case IL_FLAGWRITE_CR5_U: return IL_FLAGCLASS_CR5_U;
			case IL_FLAGWRITE_CR6_S: return IL_FLAGCLASS_CR6_S;
			case IL_FLAGWRITE_CR6_U: return IL_FLAGCLASS_CR6_U;
			case IL_FLAGWRITE_CR7_S: return IL_FLAGCLASS_CR7_S;
			case IL_FLAGWRITE_CR7_U: return IL_FLAGCLASS_CR7_U;
		}

		return IL_FLAGCLASS_NONE;
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
		uint32_t flagClassBase = IL_FLAGCLASS_CR0_S + ((semGroup / 10) * 2);
		uint32_t groupType = semGroup % 10;

		switch (groupType)
		{
		case IL_FLAGGROUP_CR0_LT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLT},
				{flagClassBase + 1, LLFC_ULT}
			};
		case IL_FLAGGROUP_CR0_LE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SLE},
				{flagClassBase + 1, LLFC_ULE}
			};
		case IL_FLAGGROUP_CR0_GT:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGT},
				{flagClassBase + 1, LLFC_UGT}
			};
		case IL_FLAGGROUP_CR0_GE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_SGE},
				{flagClassBase + 1, LLFC_UGE}
			};
		case IL_FLAGGROUP_CR0_EQ:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_E},
				{flagClassBase + 1, LLFC_E}
			};
		case IL_FLAGGROUP_CR0_NE:
			return map<uint32_t, BNLowLevelILFlagCondition> {
				{flagClassBase    , LLFC_NE},
				{flagClassBase + 1, LLFC_NE}
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
		MYLOG("%s(%d)\n", __func__, flag);

		bool signedClass = true;

		switch (semClass)
		{
			case IL_FLAGCLASS_CR0_U:
			case IL_FLAGCLASS_CR1_U:
			case IL_FLAGCLASS_CR2_U:
			case IL_FLAGCLASS_CR3_U:
			case IL_FLAGCLASS_CR4_U:
			case IL_FLAGCLASS_CR5_U:
			case IL_FLAGCLASS_CR6_U:
			case IL_FLAGCLASS_CR7_U:
				signedClass = false;
		}

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
				return signedClass ? NegativeSignFlagRole : SpecialFlagRole;
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
		MYLOG("%s(%d)\n", __func__, cond);

		switch (cond)
		{
			case LLFC_E: /* equal */
			case LLFC_NE: /* not equal */
				return vector<uint32_t>{ IL_FLAG_EQ };

			case LLFC_ULT: /* (unsigned) less than == LT */
			case LLFC_SLT: /* (signed) less than == LT */
			case LLFC_SGE: /* (signed) greater-or-equal == !LT */
			case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
				return vector<uint32_t>{ IL_FLAG_LT };

			case LLFC_SGT: /* (signed) greater-than == GT */
			case LLFC_UGT: /* (unsigned) greater-than == GT */
			case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
			case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
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
		MYLOG("%s()\n", __func__);

		return vector<uint32_t>{
			PPC_REG_R0,   PPC_REG_R1,   PPC_REG_R2,   PPC_REG_R3,   PPC_REG_R4,   PPC_REG_R5,   PPC_REG_R6,   PPC_REG_R7,
			PPC_REG_R8,   PPC_REG_R9,   PPC_REG_R10,  PPC_REG_R11,  PPC_REG_R12,  PPC_REG_R13,  PPC_REG_R14,  PPC_REG_R15,
			PPC_REG_R16,  PPC_REG_R17,  PPC_REG_R18,  PPC_REG_R19,  PPC_REG_R20,  PPC_REG_R21,  PPC_REG_R22,  PPC_REG_R23,
			PPC_REG_R24,  PPC_REG_R25,  PPC_REG_R26,  PPC_REG_R27,  PPC_REG_R28,  PPC_REG_R29,  PPC_REG_R30,  PPC_REG_R31
		};
	}

	#define PPC_REG_CC (PPC_REG_ENDING + 1)
	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = {
			PPC_REG_CARRY,

			PPC_REG_CR0, PPC_REG_CR1, PPC_REG_CR2, PPC_REG_CR3, PPC_REG_CR4, PPC_REG_CR5, PPC_REG_CR6, PPC_REG_CR7,

			PPC_REG_CTR,

			PPC_REG_F0, PPC_REG_F1, PPC_REG_F2, PPC_REG_F3,  PPC_REG_F4, PPC_REG_F5, PPC_REG_F6, PPC_REG_F7,
			PPC_REG_F8, PPC_REG_F9, PPC_REG_F10, PPC_REG_F11, PPC_REG_F12, PPC_REG_F13, PPC_REG_F14, PPC_REG_F15,
			PPC_REG_F16, PPC_REG_F17, PPC_REG_F18, PPC_REG_F19, PPC_REG_F20, PPC_REG_F21, PPC_REG_F22, PPC_REG_F23,
			PPC_REG_F24, PPC_REG_F25, PPC_REG_F26, PPC_REG_F27, PPC_REG_F28, PPC_REG_F29, PPC_REG_F30, PPC_REG_F31,

			PPC_REG_LR,

			PPC_REG_R0, PPC_REG_R1, PPC_REG_R2, PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6, PPC_REG_R7,
			PPC_REG_R8, PPC_REG_R9, PPC_REG_R10, PPC_REG_R11, PPC_REG_R12, PPC_REG_R13, PPC_REG_R14, PPC_REG_R15,
			PPC_REG_R16, PPC_REG_R17, PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21, PPC_REG_R22, PPC_REG_R23,
			PPC_REG_R24, PPC_REG_R25, PPC_REG_R26, PPC_REG_R27, PPC_REG_R28, PPC_REG_R29, PPC_REG_R30, PPC_REG_R31,

			PPC_REG_V0, PPC_REG_V1, PPC_REG_V2, PPC_REG_V3, PPC_REG_V4, PPC_REG_V5, PPC_REG_V6, PPC_REG_V7,
			PPC_REG_V8, PPC_REG_V9, PPC_REG_V10, PPC_REG_V11, PPC_REG_V12, PPC_REG_V13, PPC_REG_V14, PPC_REG_V15,
			PPC_REG_V16, PPC_REG_V17, PPC_REG_V18, PPC_REG_V19, PPC_REG_V20, PPC_REG_V21, PPC_REG_V22, PPC_REG_V23,
			PPC_REG_V24, PPC_REG_V25, PPC_REG_V26, PPC_REG_V27, PPC_REG_V28, PPC_REG_V29, PPC_REG_V30, PPC_REG_V31,
			PPC_REG_VRSAVE,
			PPC_REG_VS0, PPC_REG_VS1, PPC_REG_VS2, PPC_REG_VS3, PPC_REG_VS4, PPC_REG_VS5, PPC_REG_VS6, PPC_REG_VS7,
			PPC_REG_VS8, PPC_REG_VS9, PPC_REG_VS10, PPC_REG_VS11, PPC_REG_VS12, PPC_REG_VS13, PPC_REG_VS14, PPC_REG_VS15,
			PPC_REG_VS16, PPC_REG_VS17, PPC_REG_VS18, PPC_REG_VS19, PPC_REG_VS20, PPC_REG_VS21, PPC_REG_VS22, PPC_REG_VS23,
			PPC_REG_VS24, PPC_REG_VS25, PPC_REG_VS26, PPC_REG_VS27, PPC_REG_VS28, PPC_REG_VS29, PPC_REG_VS30, PPC_REG_VS31,
			PPC_REG_VS32, PPC_REG_VS33, PPC_REG_VS34, PPC_REG_VS35, PPC_REG_VS36, PPC_REG_VS37, PPC_REG_VS38, PPC_REG_VS39,
			PPC_REG_VS40, PPC_REG_VS41, PPC_REG_VS42, PPC_REG_VS43, PPC_REG_VS44, PPC_REG_VS45, PPC_REG_VS46, PPC_REG_VS47,
			PPC_REG_VS48, PPC_REG_VS49, PPC_REG_VS50, PPC_REG_VS51, PPC_REG_VS52, PPC_REG_VS53, PPC_REG_VS54, PPC_REG_VS55,
			PPC_REG_VS56, PPC_REG_VS57, PPC_REG_VS58, PPC_REG_VS59, PPC_REG_VS60, PPC_REG_VS61, PPC_REG_VS62, PPC_REG_VS63
		};

		return result;
	}


	virtual std::vector<uint32_t> GetGlobalRegisters() override
	{
		return vector<uint32_t>{ PPC_REG_R2, PPC_REG_R13 };
	}


	/* binja asks us about subregisters
		the full width reg is the enveloping register, if it exists,
		and also we report our offset within it (0 if we are not enveloped)
		and our size */
	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		//MYLOG("%s(%s)\n", __func__, powerpc_reg_to_str(regId));

		switch(regId) {
			// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
			//   size_t size, bool zeroExtend = false)

			case PPC_REG_CARRY: return RegisterInfo(PPC_REG_CARRY, 0, 4);
			case PPC_REG_CR0: return RegisterInfo(PPC_REG_CR0, 0, 4);
			case PPC_REG_CR1: return RegisterInfo(PPC_REG_CR1, 0, 4);
			case PPC_REG_CR2: return RegisterInfo(PPC_REG_CR2, 0, 4);
			case PPC_REG_CR3: return RegisterInfo(PPC_REG_CR3, 0, 4);
			case PPC_REG_CR4: return RegisterInfo(PPC_REG_CR4, 0, 4);
			case PPC_REG_CR5: return RegisterInfo(PPC_REG_CR5, 0, 4);
			case PPC_REG_CR6: return RegisterInfo(PPC_REG_CR6, 0, 4);
			case PPC_REG_CR7: return RegisterInfo(PPC_REG_CR7, 0, 4);
			case PPC_REG_CTR: return RegisterInfo(PPC_REG_CTR, 0, 4);
			case PPC_REG_F0: return RegisterInfo(PPC_REG_F0, 0, 4);
			case PPC_REG_F1: return RegisterInfo(PPC_REG_F1, 0, 4);
			case PPC_REG_F2: return RegisterInfo(PPC_REG_F2, 0, 4);
			case PPC_REG_F3: return RegisterInfo(PPC_REG_F3, 0, 4);
			case PPC_REG_F4: return RegisterInfo(PPC_REG_F4, 0, 4);
			case PPC_REG_F5: return RegisterInfo(PPC_REG_F5, 0, 4);
			case PPC_REG_F6: return RegisterInfo(PPC_REG_F6, 0, 4);
			case PPC_REG_F7: return RegisterInfo(PPC_REG_F7, 0, 4);
			case PPC_REG_F8: return RegisterInfo(PPC_REG_F8, 0, 4);
			case PPC_REG_F9: return RegisterInfo(PPC_REG_F9, 0, 4);
			case PPC_REG_F10: return RegisterInfo(PPC_REG_F10, 0, 4);
			case PPC_REG_F11: return RegisterInfo(PPC_REG_F11, 0, 4);
			case PPC_REG_F12: return RegisterInfo(PPC_REG_F12, 0, 4);
			case PPC_REG_F13: return RegisterInfo(PPC_REG_F13, 0, 4);
			case PPC_REG_F14: return RegisterInfo(PPC_REG_F14, 0, 4);
			case PPC_REG_F15: return RegisterInfo(PPC_REG_F15, 0, 4);
			case PPC_REG_F16: return RegisterInfo(PPC_REG_F16, 0, 4);
			case PPC_REG_F17: return RegisterInfo(PPC_REG_F17, 0, 4);
			case PPC_REG_F18: return RegisterInfo(PPC_REG_F18, 0, 4);
			case PPC_REG_F19: return RegisterInfo(PPC_REG_F19, 0, 4);
			case PPC_REG_F20: return RegisterInfo(PPC_REG_F20, 0, 4);
			case PPC_REG_F21: return RegisterInfo(PPC_REG_F21, 0, 4);
			case PPC_REG_F22: return RegisterInfo(PPC_REG_F22, 0, 4);
			case PPC_REG_F23: return RegisterInfo(PPC_REG_F23, 0, 4);
			case PPC_REG_F24: return RegisterInfo(PPC_REG_F24, 0, 4);
			case PPC_REG_F25: return RegisterInfo(PPC_REG_F25, 0, 4);
			case PPC_REG_F26: return RegisterInfo(PPC_REG_F26, 0, 4);
			case PPC_REG_F27: return RegisterInfo(PPC_REG_F27, 0, 4);
			case PPC_REG_F28: return RegisterInfo(PPC_REG_F28, 0, 4);
			case PPC_REG_F29: return RegisterInfo(PPC_REG_F29, 0, 4);
			case PPC_REG_F30: return RegisterInfo(PPC_REG_F30, 0, 4);
			case PPC_REG_F31: return RegisterInfo(PPC_REG_F31, 0, 4);
			case PPC_REG_LR: return RegisterInfo(PPC_REG_LR, 0, 4);
			case PPC_REG_R0: return RegisterInfo(PPC_REG_R0, 0, 4);
			case PPC_REG_R1: return RegisterInfo(PPC_REG_R1, 0, 4);
			case PPC_REG_R2: return RegisterInfo(PPC_REG_R2, 0, 4);
			case PPC_REG_R3: return RegisterInfo(PPC_REG_R3, 0, 4);
			case PPC_REG_R4: return RegisterInfo(PPC_REG_R4, 0, 4);
			case PPC_REG_R5: return RegisterInfo(PPC_REG_R5, 0, 4);
			case PPC_REG_R6: return RegisterInfo(PPC_REG_R6, 0, 4);
			case PPC_REG_R7: return RegisterInfo(PPC_REG_R7, 0, 4);
			case PPC_REG_R8: return RegisterInfo(PPC_REG_R8, 0, 4);
			case PPC_REG_R9: return RegisterInfo(PPC_REG_R9, 0, 4);
			case PPC_REG_R10: return RegisterInfo(PPC_REG_R10, 0, 4);
			case PPC_REG_R11: return RegisterInfo(PPC_REG_R11, 0, 4);
			case PPC_REG_R12: return RegisterInfo(PPC_REG_R12, 0, 4);
			case PPC_REG_R13: return RegisterInfo(PPC_REG_R13, 0, 4);
			case PPC_REG_R14: return RegisterInfo(PPC_REG_R14, 0, 4);
			case PPC_REG_R15: return RegisterInfo(PPC_REG_R15, 0, 4);
			case PPC_REG_R16: return RegisterInfo(PPC_REG_R16, 0, 4);
			case PPC_REG_R17: return RegisterInfo(PPC_REG_R17, 0, 4);
			case PPC_REG_R18: return RegisterInfo(PPC_REG_R18, 0, 4);
			case PPC_REG_R19: return RegisterInfo(PPC_REG_R19, 0, 4);
			case PPC_REG_R20: return RegisterInfo(PPC_REG_R20, 0, 4);
			case PPC_REG_R21: return RegisterInfo(PPC_REG_R21, 0, 4);
			case PPC_REG_R22: return RegisterInfo(PPC_REG_R22, 0, 4);
			case PPC_REG_R23: return RegisterInfo(PPC_REG_R23, 0, 4);
			case PPC_REG_R24: return RegisterInfo(PPC_REG_R24, 0, 4);
			case PPC_REG_R25: return RegisterInfo(PPC_REG_R25, 0, 4);
			case PPC_REG_R26: return RegisterInfo(PPC_REG_R26, 0, 4);
			case PPC_REG_R27: return RegisterInfo(PPC_REG_R27, 0, 4);
			case PPC_REG_R28: return RegisterInfo(PPC_REG_R28, 0, 4);
			case PPC_REG_R29: return RegisterInfo(PPC_REG_R29, 0, 4);
			case PPC_REG_R30: return RegisterInfo(PPC_REG_R30, 0, 4);
			case PPC_REG_R31: return RegisterInfo(PPC_REG_R31, 0, 4);
			case PPC_REG_V0: return RegisterInfo(PPC_REG_V0, 0, 4);
			case PPC_REG_V1: return RegisterInfo(PPC_REG_V1, 0, 4);
			case PPC_REG_V2: return RegisterInfo(PPC_REG_V2, 0, 4);
			case PPC_REG_V3: return RegisterInfo(PPC_REG_V3, 0, 4);
			case PPC_REG_V4: return RegisterInfo(PPC_REG_V4, 0, 4);
			case PPC_REG_V5: return RegisterInfo(PPC_REG_V5, 0, 4);
			case PPC_REG_V6: return RegisterInfo(PPC_REG_V6, 0, 4);
			case PPC_REG_V7: return RegisterInfo(PPC_REG_V7, 0, 4);
			case PPC_REG_V8: return RegisterInfo(PPC_REG_V8, 0, 4);
			case PPC_REG_V9: return RegisterInfo(PPC_REG_V9, 0, 4);
			case PPC_REG_V10: return RegisterInfo(PPC_REG_V10, 0, 4);
			case PPC_REG_V11: return RegisterInfo(PPC_REG_V11, 0, 4);
			case PPC_REG_V12: return RegisterInfo(PPC_REG_V12, 0, 4);
			case PPC_REG_V13: return RegisterInfo(PPC_REG_V13, 0, 4);
			case PPC_REG_V14: return RegisterInfo(PPC_REG_V14, 0, 4);
			case PPC_REG_V15: return RegisterInfo(PPC_REG_V15, 0, 4);
			case PPC_REG_V16: return RegisterInfo(PPC_REG_V16, 0, 4);
			case PPC_REG_V17: return RegisterInfo(PPC_REG_V17, 0, 4);
			case PPC_REG_V18: return RegisterInfo(PPC_REG_V18, 0, 4);
			case PPC_REG_V19: return RegisterInfo(PPC_REG_V19, 0, 4);
			case PPC_REG_V20: return RegisterInfo(PPC_REG_V20, 0, 4);
			case PPC_REG_V21: return RegisterInfo(PPC_REG_V21, 0, 4);
			case PPC_REG_V22: return RegisterInfo(PPC_REG_V22, 0, 4);
			case PPC_REG_V23: return RegisterInfo(PPC_REG_V23, 0, 4);
			case PPC_REG_V24: return RegisterInfo(PPC_REG_V24, 0, 4);
			case PPC_REG_V25: return RegisterInfo(PPC_REG_V25, 0, 4);
			case PPC_REG_V26: return RegisterInfo(PPC_REG_V26, 0, 4);
			case PPC_REG_V27: return RegisterInfo(PPC_REG_V27, 0, 4);
			case PPC_REG_V28: return RegisterInfo(PPC_REG_V28, 0, 4);
			case PPC_REG_V29: return RegisterInfo(PPC_REG_V29, 0, 4);
			case PPC_REG_V30: return RegisterInfo(PPC_REG_V30, 0, 4);
			case PPC_REG_V31: return RegisterInfo(PPC_REG_V31, 0, 4);
			case PPC_REG_VRSAVE: return RegisterInfo(PPC_REG_VRSAVE, 0, 4);
			case PPC_REG_VS0: return RegisterInfo(PPC_REG_VS0, 0, 4);
			case PPC_REG_VS1: return RegisterInfo(PPC_REG_VS1, 0, 4);
			case PPC_REG_VS2: return RegisterInfo(PPC_REG_VS2, 0, 4);
			case PPC_REG_VS3: return RegisterInfo(PPC_REG_VS3, 0, 4);
			case PPC_REG_VS4: return RegisterInfo(PPC_REG_VS4, 0, 4);
			case PPC_REG_VS5: return RegisterInfo(PPC_REG_VS5, 0, 4);
			case PPC_REG_VS6: return RegisterInfo(PPC_REG_VS6, 0, 4);
			case PPC_REG_VS7: return RegisterInfo(PPC_REG_VS7, 0, 4);
			case PPC_REG_VS8: return RegisterInfo(PPC_REG_VS8, 0, 4);
			case PPC_REG_VS9: return RegisterInfo(PPC_REG_VS9, 0, 4);
			case PPC_REG_VS10: return RegisterInfo(PPC_REG_VS10, 0, 4);
			case PPC_REG_VS11: return RegisterInfo(PPC_REG_VS11, 0, 4);
			case PPC_REG_VS12: return RegisterInfo(PPC_REG_VS12, 0, 4);
			case PPC_REG_VS13: return RegisterInfo(PPC_REG_VS13, 0, 4);
			case PPC_REG_VS14: return RegisterInfo(PPC_REG_VS14, 0, 4);
			case PPC_REG_VS15: return RegisterInfo(PPC_REG_VS15, 0, 4);
			case PPC_REG_VS16: return RegisterInfo(PPC_REG_VS16, 0, 4);
			case PPC_REG_VS17: return RegisterInfo(PPC_REG_VS17, 0, 4);
			case PPC_REG_VS18: return RegisterInfo(PPC_REG_VS18, 0, 4);
			case PPC_REG_VS19: return RegisterInfo(PPC_REG_VS19, 0, 4);
			case PPC_REG_VS20: return RegisterInfo(PPC_REG_VS20, 0, 4);
			case PPC_REG_VS21: return RegisterInfo(PPC_REG_VS21, 0, 4);
			case PPC_REG_VS22: return RegisterInfo(PPC_REG_VS22, 0, 4);
			case PPC_REG_VS23: return RegisterInfo(PPC_REG_VS23, 0, 4);
			case PPC_REG_VS24: return RegisterInfo(PPC_REG_VS24, 0, 4);
			case PPC_REG_VS25: return RegisterInfo(PPC_REG_VS25, 0, 4);
			case PPC_REG_VS26: return RegisterInfo(PPC_REG_VS26, 0, 4);
			case PPC_REG_VS27: return RegisterInfo(PPC_REG_VS27, 0, 4);
			case PPC_REG_VS28: return RegisterInfo(PPC_REG_VS28, 0, 4);
			case PPC_REG_VS29: return RegisterInfo(PPC_REG_VS29, 0, 4);
			case PPC_REG_VS30: return RegisterInfo(PPC_REG_VS30, 0, 4);
			case PPC_REG_VS31: return RegisterInfo(PPC_REG_VS31, 0, 4);
			case PPC_REG_VS32: return RegisterInfo(PPC_REG_VS32, 0, 4);
			case PPC_REG_VS33: return RegisterInfo(PPC_REG_VS33, 0, 4);
			case PPC_REG_VS34: return RegisterInfo(PPC_REG_VS34, 0, 4);
			case PPC_REG_VS35: return RegisterInfo(PPC_REG_VS35, 0, 4);
			case PPC_REG_VS36: return RegisterInfo(PPC_REG_VS36, 0, 4);
			case PPC_REG_VS37: return RegisterInfo(PPC_REG_VS37, 0, 4);
			case PPC_REG_VS38: return RegisterInfo(PPC_REG_VS38, 0, 4);
			case PPC_REG_VS39: return RegisterInfo(PPC_REG_VS39, 0, 4);
			case PPC_REG_VS40: return RegisterInfo(PPC_REG_VS40, 0, 4);
			case PPC_REG_VS41: return RegisterInfo(PPC_REG_VS41, 0, 4);
			case PPC_REG_VS42: return RegisterInfo(PPC_REG_VS42, 0, 4);
			case PPC_REG_VS43: return RegisterInfo(PPC_REG_VS43, 0, 4);
			case PPC_REG_VS44: return RegisterInfo(PPC_REG_VS44, 0, 4);
			case PPC_REG_VS45: return RegisterInfo(PPC_REG_VS45, 0, 4);
			case PPC_REG_VS46: return RegisterInfo(PPC_REG_VS46, 0, 4);
			case PPC_REG_VS47: return RegisterInfo(PPC_REG_VS47, 0, 4);
			case PPC_REG_VS48: return RegisterInfo(PPC_REG_VS48, 0, 4);
			case PPC_REG_VS49: return RegisterInfo(PPC_REG_VS49, 0, 4);
			case PPC_REG_VS50: return RegisterInfo(PPC_REG_VS50, 0, 4);
			case PPC_REG_VS51: return RegisterInfo(PPC_REG_VS51, 0, 4);
			case PPC_REG_VS52: return RegisterInfo(PPC_REG_VS52, 0, 4);
			case PPC_REG_VS53: return RegisterInfo(PPC_REG_VS53, 0, 4);
			case PPC_REG_VS54: return RegisterInfo(PPC_REG_VS54, 0, 4);
			case PPC_REG_VS55: return RegisterInfo(PPC_REG_VS55, 0, 4);
			case PPC_REG_VS56: return RegisterInfo(PPC_REG_VS56, 0, 4);
			case PPC_REG_VS57: return RegisterInfo(PPC_REG_VS57, 0, 4);
			case PPC_REG_VS58: return RegisterInfo(PPC_REG_VS58, 0, 4);
			case PPC_REG_VS59: return RegisterInfo(PPC_REG_VS59, 0, 4);
			case PPC_REG_VS60: return RegisterInfo(PPC_REG_VS60, 0, 4);
			case PPC_REG_VS61: return RegisterInfo(PPC_REG_VS61, 0, 4);
			case PPC_REG_VS62: return RegisterInfo(PPC_REG_VS62, 0, 4);
			case PPC_REG_VS63: return RegisterInfo(PPC_REG_VS63, 0, 4);
			default:
				//LogError("%s(%d == \"%s\") invalid argument", __func__,
				//  regId, powerpc_reg_to_str(regId));
				return RegisterInfo(0,0,0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return PPC_REG_R1;
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
			PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
			PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10
			/* remaining arguments onto stack */
		};
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_F1, PPC_REG_F2, PPC_REG_F3, PPC_REG_F4,
			PPC_REG_F5, PPC_REG_F6, PPC_REG_F7, PPC_REG_F8,
			PPC_REG_F9, PPC_REG_F10, PPC_REG_F11, PPC_REG_F12,
			PPC_REG_F13
		};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R0, PPC_REG_R2, PPC_REG_R3, PPC_REG_R4,
			PPC_REG_R5, PPC_REG_R6, PPC_REG_R7, PPC_REG_R8,
			PPC_REG_R9, PPC_REG_R10, PPC_REG_R12,

			PPC_REG_F0, PPC_REG_F1, PPC_REG_F2, PPC_REG_F3,
			PPC_REG_F4, PPC_REG_F5, PPC_REG_F6, PPC_REG_F7,
			PPC_REG_F8, PPC_REG_F9, PPC_REG_F10, PPC_REG_F11,
			PPC_REG_F12, PPC_REG_F13,

			PPC_REG_LR, PPC_REG_CTR,
		};
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R14, PPC_REG_R15, PPC_REG_R16, PPC_REG_R17,
			PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21,
			PPC_REG_R22, PPC_REG_R23, PPC_REG_R24, PPC_REG_R25,
			PPC_REG_R26, PPC_REG_R27, PPC_REG_R28, PPC_REG_R29,
			PPC_REG_R30, PPC_REG_R31
		};
	}


	virtual uint32_t GetGlobalPointerRegister() override
	{
		return PPC_REG_R13;
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_R3;
	}


	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return PPC_REG_F1;
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
			PPC_REG_R0,
			PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
			PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10
		};
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R3
		};
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R14, PPC_REG_R15, PPC_REG_R16, PPC_REG_R17,
			PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21,
			PPC_REG_R22, PPC_REG_R23, PPC_REG_R24, PPC_REG_R25,
			PPC_REG_R26, PPC_REG_R27, PPC_REG_R28, PPC_REG_R29,
			PPC_REG_R30, PPC_REG_R31
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_R3;
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

#ifndef DEMO_VERSION
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

		Architecture* ppc_qpx = new PowerpcArchitecture("ppc_qpx", BigEndian, CS_MODE_QPX);
		Architecture::Register(ppc_qpx);

		Architecture* ppc_spe = new PowerpcArchitecture("ppc_spe", BigEndian, CS_MODE_SPE);
		Architecture::Register(ppc_spe);

		Architecture* ppc_ps = new PowerpcArchitecture("ppc_ps", BigEndian, CS_MODE_PS);
		Architecture::Register(ppc_ps);

		Architecture* ppc64 = new PowerpcArchitecture("ppc64", BigEndian);
		Architecture::Register(ppc64);

		Architecture* ppc_le = new PowerpcArchitecture("ppc_le", LittleEndian);
		Architecture::Register(ppc_le);

		Architecture* ppc64_le = new PowerpcArchitecture("ppc64_le", LittleEndian);
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
			EM_PPC, /* id (key in m_arch map) */
			BigEndian,
			ppc_ps /* the architecture */
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

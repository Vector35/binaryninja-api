#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mips.h"
#include "il.h"

using namespace BinaryNinja;
using namespace mips;
using namespace std;


#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

uint32_t bswap32(uint32_t x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}

uint64_t bswap64(uint64_t x)
{
	return	((x << 56) & 0xff00000000000000UL) |
		((x << 40) & 0x00ff000000000000UL) |
		((x << 24) & 0x0000ff0000000000UL) |
		((x <<  8) & 0x000000ff00000000UL) |
		((x >>  8) & 0x00000000ff000000UL) |
		((x >> 24) & 0x0000000000ff0000UL) |
		((x >> 40) & 0x000000000000ff00UL) |
		((x >> 56) & 0x00000000000000ffUL);
}

enum ElfMipsRelocationType : uint32_t
{
	R_MIPS_NONE           = 0,
	R_MIPS_16             = 1,
	R_MIPS_32             = 2,
	R_MIPS_REL32          = 3,
	R_MIPS_26             = 4,
	R_MIPS_HI16           = 5,
	R_MIPS_LO16           = 6,
	R_MIPS_GPREL16        = 7,
	R_MIPS_LITERAL        = 8,
	R_MIPS_GOT16          = 9,
	R_MIPS_PC16           = 10,
	R_MIPS_CALL16         = 11,
	R_MIPS_GPREL32        = 12,
	// The remaining relocs are defined on Irix, although they are not
	// in the MIPS ELF ABI.
	R_MIPS_UNUSED1         =  13,
	R_MIPS_UNUSED2         =  14,
	R_MIPS_UNUSED3         =  15,
	R_MIPS_SHIFT5          =  16,
	R_MIPS_SHIFT6          =  17,
	R_MIPS_64              =  18,
	R_MIPS_GOT_DISP        =  19,
	R_MIPS_GOT_PAGE        =  20,
	R_MIPS_GOT_OFST        =  21,
	//The following two relocation types are specified in the MIPS ABI
	//conformance guide version 1.2 but not yet in the psABI.
	R_MIPS_GOTHI16         =  22,
	R_MIPS_GOTLO16         =  23,
	R_MIPS_SUB             =  24,
	R_MIPS_INSERT_A        =  25,
	R_MIPS_INSERT_B        =  26,
	R_MIPS_DELETE          =  27,
	R_MIPS_HIGHER          =  28,
	R_MIPS_HIGHEST         =  29,
	// The following two relocation types are specified in the MIPS ABI
	// conformance guide version 1.2 but not yet in the psABI.
	R_MIPS_CALLHI16        = 30,
	R_MIPS_CALLLO16        = 31,
	R_MIPS_SCN_DISP        = 32,
	R_MIPS_REL16           = 33,
	R_MIPS_ADD_IMMEDIATE   = 34,
	R_MIPS_PJUMP           = 35,
	R_MIPS_RELGOT          = 36,
	R_MIPS_JALR            = 37,
	R_MIPS_TLS_DTPMOD32    = 38,  // Module number 32 bit
	R_MIPS_TLS_DTPREL32    = 39,  // Module-relative offset 32 bit
	R_MIPS_TLS_DTPMOD64    = 40,  // Module number 64 bit
	R_MIPS_TLS_DTPREL64    = 41,  // Module-relative offset 64 bit
	R_MIPS_TLS_GD          = 42,  // 16 bit GOT offset for GD
	R_MIPS_TLS_LDM         = 43,  // 16 bit GOT offset for LDM
	R_MIPS_TLS_DTPREL_HI16 = 44,  // Module-relative offset, high 16 bits
	R_MIPS_TLS_DTPREL_LO16 = 45,  // Module-relative offset, low 16 bits
	R_MIPS_TLS_GOTTPREL    = 46,  // 16 bit GOT offset for IE
	R_MIPS_TLS_TPREL32     = 47,  // TP-relative offset, 32 bit
	R_MIPS_TLS_TPREL64     = 48,  // TP-relative offset, 64 bit
	R_MIPS_TLS_TPREL_HI16  = 49,  // TP-relative offset, high 16 bits
	R_MIPS_TLS_TPREL_LO16  = 50,  // TP-relative offset, low 16 bits
	R_MIPS_GLOB_DAT        = 51,

	// This range is reserved for vendor specific relocations.
	R_MIPS_LOVENDOR  =  100,
	R_MIPS64_COPY    =  125,
	R_MIPS_COPY      =  126,
	R_MIPS_JUMP_SLOT =  127,
	R_MIPS_HIVENDOR  =  127
};


static const char* GetRelocationString(ElfMipsRelocationType rel)
{
	static map<ElfMipsRelocationType, const char*> relocTable = {
		{ R_MIPS_NONE, "R_MIPS_NONE"},
		{ R_MIPS_16, "R_MIPS_16"},
		{ R_MIPS_32, "R_MIPS_32"},
		{ R_MIPS_REL32, "R_MIPS_REL32"},
		{ R_MIPS_26, "R_MIPS_26"},
		{ R_MIPS_HI16, "R_MIPS_HI16"},
		{ R_MIPS_LO16, "R_MIPS_LO16"},
		{ R_MIPS_GPREL16, "R_MIPS_GPREL16"},
		{ R_MIPS_LITERAL, "R_MIPS_LITERAL"},
		{ R_MIPS_GOT16, "R_MIPS_GOT16"},
		{ R_MIPS_PC16, "R_MIPS_PC16"},
		{ R_MIPS_CALL16, "R_MIPS_CALL16"},
		{ R_MIPS_GPREL32, "R_MIPS_GPREL32"},
		{ R_MIPS_UNUSED1, "R_MIPS_UNUSED1"},
		{ R_MIPS_UNUSED2, "R_MIPS_UNUSED2"},
		{ R_MIPS_UNUSED3, "R_MIPS_UNUSED3"},
		{ R_MIPS_SHIFT5, "R_MIPS_SHIFT5"},
		{ R_MIPS_SHIFT6, "R_MIPS_SHIFT6"},
		{ R_MIPS_64, "R_MIPS_64"},
		{ R_MIPS_GOT_DISP, "R_MIPS_GOT_DISP"},
		{ R_MIPS_GOT_PAGE, "R_MIPS_GOT_PAGE"},
		{ R_MIPS_GOT_OFST, "R_MIPS_GOT_OFST"},
		{ R_MIPS_GOTHI16, "R_MIPS_GOTHI16"},
		{ R_MIPS_GOTLO16, "R_MIPS_GOTLO16"},
		{ R_MIPS_SUB, "R_MIPS_SUB"},
		{ R_MIPS_INSERT_A, "R_MIPS_INSERT_A"},
		{ R_MIPS_INSERT_B, "R_MIPS_INSERT_B"},
		{ R_MIPS_DELETE, "R_MIPS_DELETE"},
		{ R_MIPS_HIGHER, "R_MIPS_HIGHER"},
		{ R_MIPS_HIGHEST, "R_MIPS_HIGHEST"},
		{ R_MIPS_CALLHI16, "R_MIPS_CALLHI16"},
		{ R_MIPS_CALLLO16, "R_MIPS_CALLLO16"},
		{ R_MIPS_SCN_DISP, "R_MIPS_SCN_DISP"},
		{ R_MIPS_REL16, "R_MIPS_REL16"},
		{ R_MIPS_ADD_IMMEDIATE, "R_MIPS_ADD_IMMEDIATE"},
		{ R_MIPS_PJUMP, "R_MIPS_PJUMP"},
		{ R_MIPS_RELGOT, "R_MIPS_RELGOT"},
		{ R_MIPS_JALR, "R_MIPS_JALR"},
		{ R_MIPS_TLS_DTPMOD32, "R_MIPS_TLS_DTPMOD32"},
		{ R_MIPS_TLS_DTPREL32, "R_MIPS_TLS_DTPREL32"},
		{ R_MIPS_TLS_DTPMOD64, "R_MIPS_TLS_DTPMOD64"},
		{ R_MIPS_TLS_DTPREL64, "R_MIPS_TLS_DTPREL64"},
		{ R_MIPS_TLS_GD, "R_MIPS_TLS_GD"},
		{ R_MIPS_TLS_LDM, "R_MIPS_TLS_LDM"},
		{ R_MIPS_TLS_DTPREL_HI16, "R_MIPS_TLS_DTPREL_HI16"},
		{ R_MIPS_TLS_DTPREL_LO16, "R_MIPS_TLS_DTPREL_LO16"},
		{ R_MIPS_TLS_GOTTPREL, "R_MIPS_TLS_GOTTPREL"},
		{ R_MIPS_TLS_TPREL32, "R_MIPS_TLS_TPREL32"},
		{ R_MIPS_TLS_TPREL64, "R_MIPS_TLS_TPREL64"},
		{ R_MIPS_TLS_TPREL_HI16, "R_MIPS_TLS_TPREL_HI16"},
		{ R_MIPS_TLS_TPREL_LO16, "R_MIPS_TLS_TPREL_LO16"},
		{ R_MIPS_GLOB_DAT, "R_MIPS_GLOB_DAT"},
		{ R_MIPS_LOVENDOR, "R_MIPS_LOVENDOR"},
		{ R_MIPS64_COPY, "R_MIPS64_COPY"},
		{ R_MIPS_COPY, "R_MIPS_COPY"},
		{ R_MIPS_JUMP_SLOT, "R_MIPS_JUMP_SLOT"},
		{ R_MIPS_HIVENDOR, "R_MIPS_HIVENDOR"}
	};

	if (relocTable.count(rel))
		return relocTable.at(rel);
	return "Unknown MIPS relocation";
}

class MipsArchitecture: public Architecture
{
protected:
	size_t m_bits;
	BNEndianness m_endian;
	uint32_t m_enablePseudoOps;

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result)
	{
		memset(&result, 0, sizeof(result));
		if (mips_decompose((uint32_t*)data, maxLen,  &result, m_bits == 64 ? MIPS_64 : MIPS_32, addr, m_endian, m_enablePseudoOps) != 0)
			return false;
		return true;
	}

	virtual size_t GetAddressSize() const override
	{
		return m_bits / 8;
	}

	size_t InstructionHasBranchDelay(const Instruction& instr)
	{
		switch (instr.operation)
		{
			case MIPS_B:
			case MIPS_BAL:
			case MIPS_BEQ:
			case MIPS_BEQL:
			case MIPS_BEQZ:
			case MIPS_BGEZ:
			case MIPS_BGEZAL:
			case MIPS_BGEZALL:
			case MIPS_BGEZL:
			case MIPS_BGTZ:
			case MIPS_BGTZL:
			case MIPS_BLEZ:
			case MIPS_BLEZL:
			case MIPS_BLTZ:
			case MIPS_BLTZAL:
			case MIPS_BLTZALL:
			case MIPS_BLTZL:
			case MIPS_BNE:
			case MIPS_BNEL:
			case MIPS_JR:
			case MIPS_JR_HB:
			case MIPS_J:
			case MIPS_JAL:
			case MIPS_JALR:
			case MIPS_JALR_HB:
			case MIPS_BC1F:
			case MIPS_BC1FL:
			case MIPS_BC1T:
			case MIPS_BC1TL:
			case MIPS_BC2FL:
			case MIPS_BC2TL:
			case MIPS_BC2F:
			case MIPS_BC2T:
				return 1;
			default:
				return 0;
		}
	}


	bool InstructionIsUnalignedMemAccess(const Instruction& instr)
	{
		switch (instr.operation)
		{
		case MIPS_LWL:
		case MIPS_LWR:
		case MIPS_SWL:
		case MIPS_SWR:
			return true;
		default:
			return false;
		}
	}


	bool IsConditionalBranch(const Instruction& instr)
	{
		switch (instr.operation)
		{
			case MIPS_BEQZ:
			case MIPS_BGEZ:
			case MIPS_BGTZ:
			case MIPS_BLEZ:
			case MIPS_BLTZ:
			case MIPS_BGEZL:
			case MIPS_BGTZL:
			case MIPS_BLEZL:
			case MIPS_BLTZL:
			case MIPS_BEQ:
			case MIPS_BNE:
			case MIPS_BEQL:
			case MIPS_BNEL:
			case MIPS_BC1F:
			case MIPS_BC1FL:
			case MIPS_BC1T:
			case MIPS_BC1TL:
			case MIPS_BC2FL:
			case MIPS_BC2TL:
			case MIPS_BC2F:
			case MIPS_BC2T:
				return true;
			default:
				return false;
		}
	}

	void SetInstructionInfoForInstruction(uint64_t addr, const Instruction& instr, InstructionInfo& result)
	{
		result.length = 4;

		auto hasBranchDelay = InstructionHasBranchDelay(instr);

		switch (instr.operation)
		{
		//case MIPS_JALX: //This case jumps to a different processor mode microMIPS32/MIPS32/MIPS16e
		//	break;
		//Branch/jump and link immediate
		case MIPS_BAL:
			if (instr.operands[0].immediate != addr + 8)
				result.AddBranch(CallDestination, instr.operands[0].immediate, nullptr, hasBranchDelay);
			else
				result.branchDelay = 1; // We have a "get pc" mnemonic; do nothing
			break;

		case MIPS_JAL:
			result.AddBranch(CallDestination, instr.operands[0].immediate, nullptr, hasBranchDelay);
			break;

		//Jmp to register register value is unknown
		case MIPS_JALR:
		case MIPS_JALR_HB:
			result.branchDelay = 1;
			break;

		case MIPS_BGEZAL:
		case MIPS_BLTZAL:
		case MIPS_BGEZALL:
		case MIPS_BLTZALL:
			result.AddBranch(CallDestination, instr.operands[1].immediate, nullptr, hasBranchDelay);
			break;

		//Unconditional branch and jump
		case MIPS_B:
		case MIPS_J:
			result.AddBranch(UnconditionalBranch, instr.operands[0].immediate, nullptr, hasBranchDelay);
			break;

		//Conditional branch instructions
		case MIPS_BEQZ:
		case MIPS_BGEZ:
		case MIPS_BGTZ:
		case MIPS_BLEZ:
		case MIPS_BLTZ:
		case MIPS_BGEZL:
		case MIPS_BGTZL:
		case MIPS_BLEZL:
		case MIPS_BLTZL:
			result.AddBranch(TrueBranch, instr.operands[1].immediate, nullptr, hasBranchDelay);
			//need to jump over the branch delay slot and current instruction
			result.AddBranch(FalseBranch, addr + 8, nullptr, hasBranchDelay);
			break;

		case MIPS_BEQ:
		case MIPS_BNE:
		case MIPS_BEQL:
		case MIPS_BNEL:
			result.AddBranch(TrueBranch, instr.operands[2].immediate, nullptr, hasBranchDelay);
			//need to jump over the branch delay slot and current instruction
			result.AddBranch(FalseBranch, addr + 8, nullptr, hasBranchDelay);
			break;

		//Jmp reg isntructions, if they are jumping to the return address register then it is a function return
		case MIPS_JR:
		case MIPS_JR_HB:
			if (instr.operands[0].reg == REG_RA)
				result.AddBranch(FunctionReturn, 0, nullptr, hasBranchDelay);
			else
				result.AddBranch(UnresolvedBranch, 0, nullptr, hasBranchDelay);
			break;
		case MIPS_BC1F:
		case MIPS_BC1FL:
		case MIPS_BC1T:
		case MIPS_BC1TL:
		case MIPS_BC2FL:
		case MIPS_BC2TL:
		case MIPS_BC2F:
		case MIPS_BC2T:
			result.AddBranch(TrueBranch, instr.operands[0].immediate, nullptr, hasBranchDelay);
			//need to jump over the branch delay slot and current instruction
			result.AddBranch(FalseBranch, addr + 8, nullptr, hasBranchDelay);
			break;

		//Exception return instruction
		case MIPS_ERET:
			result.AddBranch(FunctionReturn, 0, nullptr, hasBranchDelay);
			break;

		default:
			break;
		}
	}

public:
	MipsArchitecture(const std::string& name, BNEndianness endian, size_t bits): Architecture(name), m_bits(bits), m_endian(endian)
	{
		Ref<Settings> settings = Settings::Instance();
		m_enablePseudoOps = settings->Get<bool>("arch.mips.disassembly.pseudoOps") ? 1 : 0;
	}

	virtual BNEndianness GetEndianness() const override
	{
		return m_endian;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 8; // To disassemble delay slots, allow two instructions
	}

	virtual size_t GetOpcodeDisplayLength() const override
	{
		return 4;
	}

	virtual bool CanAssemble() override
	{
		return true;
	}

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		(void)addr;

		int assembleResult;
		char *instrBytes=NULL, *err=NULL;
		int instrBytesLen=0, errLen=0;

		BNLlvmServicesInit();

		errors.clear();
		const char* triple = "mips-pc-none-o32";
		if (m_endian == LittleEndian)
			triple = "mipsel-pc-none-o32";

		assembleResult = BNLlvmServicesAssemble(code.c_str(), LLVM_SVCS_DIALECT_UNSPEC,
			triple, LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC,
			&instrBytes, &instrBytesLen, &err, &errLen);

		if(assembleResult || errLen)
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

	bool InstructionIsBranchLikely(Instruction& instr)
	{
		switch (instr.operation)
		{
			case MIPS_BEQL:
			case MIPS_BNEL:
			case MIPS_BGTZL:
			case MIPS_BGEZL:
			case MIPS_BLTZL:
			case MIPS_BLEZL:
			case MIPS_BC1TL:
			case MIPS_BC1FL:
			case MIPS_BC2FL:
			case MIPS_BC2TL:
			case MIPS_BGEZALL:
			case MIPS_BLTZALL:
				return true;
			default:
				return false;
		}
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		Instruction instr, secondInstr;
		if (!Disassemble(data, addr, len, instr))
		{
			il.AddInstruction(il.Undefined());
			return false;
		}

		if (InstructionHasBranchDelay(instr) == 1)
		{
			if (len < 8)
			{
				LogWarn("Can not lift instruction with delay slot @ 0x%08" PRIx64, addr);
				return false;
			}

			if (!Disassemble(data + instr.size, addr + instr.size, len - instr.size, secondInstr))
			{
				il.AddInstruction(il.Undefined());
				return false;
			}

			bool status = true;
			bool isBranchLikely = InstructionIsBranchLikely(instr);
			if (isBranchLikely)
			{
				InstructionInfo instrInfo;
				LowLevelILLabel trueCode, falseCode;
				SetInstructionInfoForInstruction(addr, instr, instrInfo);
				il.AddInstruction(il.If(GetConditionForInstruction(il, instr, GetAddressSize()), trueCode, falseCode));
				il.MarkLabel(trueCode);
				il.SetCurrentAddress(this, addr + instr.size);
				GetLowLevelILForInstruction(this, addr + instr.size, il, secondInstr, GetAddressSize());
				for (size_t i = 0; i < instrInfo.branchCount; i++)
				{
					if (instrInfo.branchType[i] == TrueBranch)
					{
						BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(this, instrInfo.branchTarget[i]);
						if (trueLabel)
							il.AddInstruction(il.Goto(*trueLabel));
						else
							il.AddInstruction(il.Jump(il.ConstPointer(GetAddressSize(), instrInfo.branchTarget[i])));
						break;
					}
				}
				il.MarkLabel(falseCode);
			}
			else
			{
				size_t nop;

				// ensure we have space to preserve one register in case the delay slot
				// clobbers a value needed by the branch. this will be eliminated when
				// normal LLIL is generated from Lifted IL if we don't need it
				il.SetCurrentAddress(this, addr + instr.size);
				nop = il.Nop();
				il.AddInstruction(nop);

				GetLowLevelILForInstruction(this, addr + instr.size, il, secondInstr, GetAddressSize());

				LowLevelILInstruction delayed;
				uint32_t clobbered = BN_INVALID_REGISTER;
				size_t instrIdx = il.GetInstructionCount();
				if (instrIdx != 0)
				{
					// FIXME: this assumes that the instruction in the delay slot
					// only changed registers in the last IL instruction that it
					// added -- strictly speaking we should be starting from the
					// first instruction that could have been added and follow all
					// paths to the end of that instruction.
					delayed = il.GetInstruction(instrIdx - 1);
					if ((delayed.operation == LLIL_SET_REG) && (delayed.address == (addr + instr.size)))
						clobbered = delayed.GetDestRegister<LLIL_SET_REG>();
				}

				il.SetCurrentAddress(this, addr);

				if ((instr.operation == MIPS_JR) && (instr.operands[0].reg == REG_T9) &&
						(secondInstr.operation == MIPS_ADDIU) && (secondInstr.operands[0].reg == REG_SP) &&
						(secondInstr.operands[1].reg == REG_SP) && (secondInstr.operands[2].immediate < 0x80000000))
				{
					il.AddInstruction(il.TailCall(il.Register(4, REG_T9)));
				}
				else
				{
					status = GetLowLevelILForInstruction(this, addr, il, instr, GetAddressSize());
				}

				if (clobbered != BN_INVALID_REGISTER)
				{
					// FIXME: this approach will break with any of the REG_SPLIT operations as well
					// any use of partial registers -- this approach needs to be expanded substantially
					// to be correct in the general case. also, it uses LLIL_TEMP(1) for the simple reason
					// that the mips lifter only uses LLIL_TEMP(0) at the moment.
					LowLevelILInstruction lifted = il.GetInstruction(instrIdx);
					if ((lifted.operation == LLIL_IF || lifted.operation == LLIL_CALL) && (lifted.address == addr))
					{
						bool replace = false;

						lifted.VisitExprs([&](const LowLevelILInstruction& expr) -> bool {
							if (expr.operation == LLIL_REG && expr.GetSourceRegister<LLIL_REG>() == clobbered)
							{
								// Replace all reads from the clobbered register to a temp register
								// that we're going to set (by replacing the earlier nop we added)
								il.ReplaceExpr(expr.exprIndex, il.Register(expr.size, LLIL_TEMP(1)));
								replace = true;
							}
							return true;
						});

						if (replace)
						{
							// Preserve the value of the clobbered register by replacing the LLIL_NOP
							// instruction we added at the beginning with an assignment to the temp
							// register we rewrote in the LLIL_IF condition expression
							il.SetCurrentAddress(this, addr + instr.size);
							il.ReplaceExpr(nop, il.SetRegister(delayed.size, LLIL_TEMP(1), il.Register(delayed.size, delayed.GetDestRegister<LLIL_SET_REG>())));
							il.SetCurrentAddress(this, addr);
						}
					}
				}
			}

			len = instr.size + secondInstr.size;
			return status;
		}
		else if (InstructionIsUnalignedMemAccess(instr) && len >= 8
			&& Disassemble(data + 4, addr + 4, len - 4, secondInstr))
		{
			Instruction* left = nullptr;
			Instruction* right = nullptr;
			Instruction* base;
			uint32_t addrToUse;
			bool store = false;
			bool proceed = true;

			switch (instr.operation)
			{
			case MIPS_SWL:
				store = true;
				// fall through
			case MIPS_LWL:
				proceed = (secondInstr.operation == (store ? MIPS_SWR : MIPS_LWR));
				left = &instr;
				right = &secondInstr;
				break;

			case MIPS_SWR:
				store = true;
				// fall through
			case MIPS_LWR:
				proceed = (secondInstr.operation == (store ? MIPS_SWL : MIPS_LWL));
				left = &secondInstr;
				right = &instr;
				break;

			default:
				proceed = false;
				break;
			}

			proceed = proceed && (instr.operands[0].reg == secondInstr.operands[0].reg);

			if (m_endian == BigEndian)
			{
				proceed = proceed && ((left->operands[1].immediate + 3) == right->operands[1].immediate);
				addrToUse = (uint32_t)addr + ((&instr == left) ? 0 : 4);
				base = left;
			}
			else
			{
				proceed = proceed && (left->operands[1].immediate == (right->operands[1].immediate + 3));
				addrToUse = (uint32_t)addr + ((&instr == right) ? 0 : 4);
				base = right;
			}

			if (proceed)
			{
				len = 8;
				il.SetCurrentAddress(this, addrToUse);
				base->operation = store ? MIPS_SW : MIPS_LW;
				return GetLowLevelILForInstruction(this, addrToUse, il, *base, GetAddressSize());
			}
		}

		len = instr.size;
		return GetLowLevelILForInstruction(this, addr, il, instr, GetAddressSize());
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

	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		Instruction instr;
		char operand[64];
		char padding[9];
		const char* reg = NULL;
		if (!Disassemble(data, addr, len, instr))
			return false;

		len = instr.size;
		memset(padding, 0x20, sizeof(padding));
		const char* operation = get_operation(instr.operation);
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
		for (size_t i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].operandClass == NONE)
				return true;

			int32_t imm = instr.operands[i].immediate;
			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");

			switch (instr.operands[i].operandClass)
			{
			case IMM:
				if (imm < -9)
					snprintf(operand, sizeof(operand), "-%#x", -imm);
				else if (imm < 0)
					snprintf(operand, sizeof(operand), "-%d", -imm);
				else if (imm < 10)
					snprintf(operand, sizeof(operand), "%d", imm);
				else
					snprintf(operand, sizeof(operand), "%#x", imm);

				result.emplace_back(IntegerToken, operand, imm);
				break;
			case LABEL:
				snprintf(operand, sizeof(operand), "%#x", imm);
				result.emplace_back(PossibleAddressToken, operand, imm);
				break;
			case REG:
				reg = get_register((Reg)instr.operands[i].reg);
				if (reg == NULL)
				{
					return false;
				}
				result.emplace_back(RegisterToken, reg);
				break;
			case FLAG:
				reg = get_flag((Flag)instr.operands[i].reg);
				if (reg == NULL)
				{
					return false;
				}
				result.push_back(InstructionTextToken(RegisterToken, reg));
				break;
			case HINT:
				reg = get_hint((Hint)instr.operands[i].reg);
				if (reg == NULL)
				{
					return false;
				}
				result.emplace_back(RegisterToken, reg);
				break;
			case MEM_IMM:
				result.emplace_back(BeginMemoryOperandToken, "");
				if (imm != 0)
				{
					if (imm < -9)
						snprintf(operand, sizeof(operand), "-%#x", -imm);
					else if (imm < 0)
						snprintf(operand, sizeof(operand), "-%d", -imm);
					else if (imm < 10)
						snprintf(operand, sizeof(operand), "%d", imm);
					else
						snprintf(operand, sizeof(operand), "%#x", imm);
					result.emplace_back(IntegerToken, operand, imm);
				}
				if (instr.operands[i].reg == REG_ZERO)
					break;
				result.emplace_back(BraceToken, "(");
				reg = get_register((Reg)instr.operands[i].reg);
				if (reg == NULL)
					return false;
				result.emplace_back(RegisterToken, reg);
				result.emplace_back(BraceToken, ")");
				result.emplace_back(EndMemoryOperandToken, "");
				break;
			case MEM_REG:
				result.emplace_back(BeginMemoryOperandToken, "");
				reg = get_register((Reg)imm);
				if (reg == NULL)
					return false;
				result.emplace_back(RegisterToken, reg);
				result.emplace_back(BraceToken, "(");

				reg = get_register((Reg)instr.operands[i].reg);
				if (reg == NULL)
					return false;
				result.emplace_back(RegisterToken, reg);
				result.emplace_back(BraceToken, ")");
				result.emplace_back(EndMemoryOperandToken, "");
				break;
			default:
				LogError("operandClass %x\n", instr.operands[i].operandClass);
				return false;
			}
		}
		return true;
	}

	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
			case MIPS_INTRIN_WSBH:
				return "__wsbh";
			case MIPS_INTRIN_MFC0:
				return "moveFromCoprocessor";
			case MIPS_INTRIN_MFC_UNIMPLEMENTED:
				return "moveFromCoprocessorUnimplemented";
			case MIPS_INTRIN_MTC0:
				return "moveToCoprocessor";
			case MIPS_INTRIN_MTC_UNIMPLEMENTED:
				return "moveToCoprocessorUnimplemented";
			case MIPS_INTRIN_DMFC0:
				return "moveDwordFromCoprocessor";
			case MIPS_INTRIN_DMFC_UNIMPLEMENTED:
				return "moveDwordFromCoprocessorUnimplemented";
			case MIPS_INTRIN_DMTC0:
				return "moveDwordToCoprocessor";
			case MIPS_INTRIN_DMTC_UNIMPLEMENTED:
				return "moveDwordToCoprocessorUnimplemented";
			default:
				return "";
		}
	}

	virtual vector<uint32_t> GetAllIntrinsics() override
	{
		return vector<uint32_t>{
			MIPS_INTRIN_WSBH,
			MIPS_INTRIN_MFC0,
			MIPS_INTRIN_MFC_UNIMPLEMENTED,
			MIPS_INTRIN_MTC0,
			MIPS_INTRIN_MTC_UNIMPLEMENTED,
			MIPS_INTRIN_DMFC0,
			MIPS_INTRIN_DMFC_UNIMPLEMENTED,
			MIPS_INTRIN_DMTC0,
			MIPS_INTRIN_DMTC_UNIMPLEMENTED,
		};
	}

	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
			case MIPS_INTRIN_WSBH:
				return {NameAndType(Type::IntegerType(4, false))};
			case MIPS_INTRIN_MFC0:
				return {
					NameAndType("register", Type::IntegerType(4, false)),
				};
			case MIPS_INTRIN_MFC_UNIMPLEMENTED:
				return {
					NameAndType("coprocessor", Type::IntegerType(4, false)),
					NameAndType("register", Type::IntegerType(4, false)),
					NameAndType("selector", Type::IntegerType(4, false)),
				};
			case MIPS_INTRIN_MTC0:
				return {
					NameAndType("register", Type::IntegerType(4, false)),
					NameAndType("value", Type::IntegerType(4, false)),
				};
			case MIPS_INTRIN_MTC_UNIMPLEMENTED:
				return {
					NameAndType("coprocessor", Type::IntegerType(4, false)),
					NameAndType("register", Type::IntegerType(4, false)),
					NameAndType("selector", Type::IntegerType(4, false)),
					NameAndType("value", Type::IntegerType(4, false)),
				};
			case MIPS_INTRIN_DMFC0:
				return {
					NameAndType("register", Type::IntegerType(8, false)),
				};
			case MIPS_INTRIN_DMFC_UNIMPLEMENTED:
				return {
					NameAndType("coprocessor", Type::IntegerType(4, false)),
					NameAndType("register", Type::IntegerType(4, false)),
					NameAndType("selector", Type::IntegerType(4, false)),
				};
			case MIPS_INTRIN_DMTC0:
				return {
					NameAndType("register", Type::IntegerType(8, false)),
					NameAndType("value", Type::IntegerType(8, false)),
				};
			case MIPS_INTRIN_DMTC_UNIMPLEMENTED:
				return {
					NameAndType("coprocessor", Type::IntegerType(4, false)),
					NameAndType("register", Type::IntegerType(4, false)),
					NameAndType("selector", Type::IntegerType(4, false)),
					NameAndType("value", Type::IntegerType(8, false)),
				};
			default:
				return vector<NameAndType>();
		}
	}

	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
			case MIPS_INTRIN_WSBH:
				return {Type::IntegerType(4, false)};
			case MIPS_INTRIN_MFC0:
			case MIPS_INTRIN_MFC_UNIMPLEMENTED:
				return {Type::IntegerType(4, false)};
			case MIPS_INTRIN_DMFC0:
			case MIPS_INTRIN_DMFC_UNIMPLEMENTED:
				return {Type::IntegerType(8, false)};
			default:
				return vector<Confidence<Ref<Type>>>();
		}
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

		return IsConditionalBranch(instr);
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		return (instr.operation == MIPS_BAL) || (instr.operation == MIPS_JAL);
	}

	// virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	// {
	// 	Instruction instr;
	// 	if (!Disassemble(data, addr, len, instr))
	// 		return false;

	// 	return (instr.operation == MIPS_BAL) || (instr.operation == MIPS_JAL);
	// }

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint32_t nop =  0;
		if (len < sizeof(nop))
			return false;
		for (size_t i = 0; i < len/sizeof(nop); i++)
			((uint32_t*)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		uint32_t *value = (uint32_t*)data;
		uint32_t instValue = *value;

		if (GetEndianness() == LittleEndian)
			instValue = bswap32(instValue);

		instValue = (0x00000010 | (instValue & 0xffff0000));

		if (GetEndianness() == LittleEndian)
			instValue = bswap32(instValue);

		*value = instValue;
		return true;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		(void)len;
		uint32_t *value = (uint32_t*)data;

		uint32_t instValue = *value;
		if (GetEndianness() == LittleEndian)
			instValue = bswap32(instValue);

		uint32_t op = instValue >> 25;
		switch (op)
		{
			case 1: //REGIMM
				op = (instValue >> 16) & 0xf;
				switch (op)
				{
					case 0:	//BLTZ
					case 1: //BGEZ
					case 2: //BLTZL
					case 3: //BGEZL
					case 0x10: //BLTZAL
					case 0x11: //BGEZAL
					case 0x12: //BLTZALL
					case 0x13: //BGEZALL
						//Invert the bit
						instValue ^= 0x00000100;
						break;
					default:
						return false;
				}
				break;
			case 4: //BEQ
			case 5: //BNE
			case 6: //BLEZ
			case 7: //BGTZ
			case 0x14: //BEQL
			case 0x15: //BNEL
			case 0x16: //BLEZL
			case 0x17: //BGTZL
				//Invert the bit
				instValue ^= 0x00000004;
				break;
			default:
				return false;
		}
		if (GetEndianness() == LittleEndian)
			instValue = bswap32(instValue);

		*value = instValue;
		return true;
	}
	/*
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
	*/
	virtual string GetRegisterName(uint32_t reg) override
	{
		const char* regsz = nullptr;
		//Integers compared here are according to the list returned by GetAllRegisters
		if (reg < END_REG)
			regsz = get_register((Reg)reg);
		if (regsz == nullptr)
			return "";
		return regsz;
	}

	virtual string GetFlagName(uint32_t reg) override
	{
		const char* regsz = nullptr;
		if (reg < END_FLAG)
			regsz = get_flag((Flag)reg);
		if (regsz == nullptr)
			return "";
		return regsz;
	}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector<uint32_t>{
			REG_ZERO,  REG_AT,  REG_V0,  REG_V1,  REG_A0,  REG_A1,  REG_A2,  REG_A3,
			REG_T0,    REG_T1,  REG_T2,  REG_T3,  REG_T4,  REG_T5,  REG_T6,  REG_T7,
			REG_S0,    REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
			REG_T8,    REG_T9,  REG_K0,  REG_K1,  REG_GP,  REG_SP,  REG_FP,  REG_RA,
			CPREG_0,       CPREG_1,       CPREG_2,       CPREG_3,       CPREG_4,       CPREG_5,       CPREG_6,       CPREG_7,
			CPREG_8,       CPREG_9,       CPREG_10,      CPREG_11,      CPREG_12,      CPREG_13,      CPREG_14,      CPREG_15,
			CPREG_16,      CPREG_17,      CPREG_18,      CPREG_19,      CPREG_20,      CPREG_21,      CPREG_22,      CPREG_23,
			CPREG_24,      CPREG_25,      CPREG_26,      CPREG_27,      CPREG_28,      CPREG_29,      CPREG_30,      CPREG_31,
			FPREG_F0,      FPREG_F1,      FPREG_F2,      FPREG_F3,      FPREG_F4,      FPREG_F5,      FPREG_F6,      FPREG_F7,
			FPREG_F8,      FPREG_F9,      FPREG_F10,     FPREG_F11,     FPREG_F12,     FPREG_F13,     FPREG_F14,     FPREG_F15,
			FPREG_F16,     FPREG_F17,     FPREG_F18,     FPREG_F19,     FPREG_F20,     FPREG_F21,     FPREG_F22,     FPREG_F23,
			FPREG_F24,     FPREG_F25,     FPREG_F26,     FPREG_F27,     FPREG_F28,     FPREG_F29,     FPREG_F30,     FPREG_F31,
			FPCCREG_FCC0,  FPCCREG_FCC1,  FPCCREG_FCC2,  FPCCREG_FCC3,  FPCCREG_FCC4,  FPCCREG_FCC5,  FPCCREG_FCC6,  FPCCREG_FCC7,
			REG_LO, REG_HI,
			// Coprocessor 0 register 0
			REG_INDEX,
			REG_MVP_CONTROL,
			REG_MVP_CONF0,
			REG_MVP_CONF1,
			// Coprocessor 0 register 1
			REG_RANDOM,
			REG_VPE_CONTROL,
			REG_VPE_CONF0,
			REG_VPE_CONF1,
			REG_YQ_MASK,
			REG_VPE_SCHEDULE,
			REG_VPE_SCHE_FBACK,
			REG_VPE_OPT,
			// Coprocessor 0 register 2
			REG_ENTRY_LO0,
			REG_TC_STATUS,
			REG_TC_BIND,
			REG_TC_RESTART,
			REG_TC_HALT,
			REG_TC_CONTEXT,
			REG_TC_SCHEDULE,
			REG_TC_SCHE_FBACK,
			// Coprocessor 0 register 3
			REG_ENTRY_LO1,
			// Coprocessor 0 register 4
			REG_CONTEXT,
			REG_CONTEXT_CONFIG,
			// Coprocessor 0 register 5
			REG_PAGE_MASK,
			REG_PAGE_GRAIN,
			// Coprocessor 0 register 6
			REG_WIRED,
			REG_SRS_CONF0,
			REG_SRS_CONF1,
			REG_SRS_CONF2,
			REG_SRS_CONF3,
			REG_SRS_CONF4,
			// Coprocessor 0 register 7
			REG_HWR_ENA,
			// Coprocessor 0 register 8
			REG_BAD_VADDR,
			// Coprocessor 0 register 9
			REG_COUNT,
			// Coprocessor 0 register 10
			REG_ENTRY_HI,
			// Coprocessor 0 register 11
			REG_COMPARE,
			// Coprocessor 0 register 12
			REG_STATUS,
			REG_INT_CTL,
			REG_SRS_CTL,
			REG_SRS_MAP,
			// Coprocessor 0 register 13
			REG_CAUSE,
			// Coprocessor 0 register 14
			REG_EPC,
			// Coprocessor 0 register 15
			REG_PR_ID,
			REG_EBASE,
			// Coprocessor 0 register 16
			REG_CONFIG,
			REG_CONFIG1,
			REG_CONFIG2,
			REG_CONFIG3,
			// Coprocessor 0 register 17
			REG_LLADDR,
			// Coprocessor 0 register 18
			REG_WATCH_LO,
			// Coprocessor 0 register 19
			REG_WATCH_HI,
			// Coprocessor 0 register 20
			REG_XCONTEXT,
			// Coprocessor 0 register 23
			REG_DEBUG,
			REG_TRACE_CONTROL,
			REG_TRACE_CONTROL2,
			REG_USER_TRACE_DATA,
			REG_TRACE_BPC,
			// Coprocessor 0 register 24
			REG_DEPC,
			// Coprocessor 0 register 25
			REG_PERF_CNT,
			// Coprocessor 0 register 26
			REG_ERR_CTL,
			// Coprocessor 0 register 27
			REG_CACHE_ERR0,
			REG_CACHE_ERR1,
			REG_CACHE_ERR2,
			REG_CACHE_ERR3,
			// Coprocessor 0 register 28
			REG_TAG_LO,
			REG_DATA_LO,
			// Coprocessor 0 register 29
			REG_TAG_HI,
			REG_DATA_HI,
			// Coprocessor 0 register 30
			REG_ERROR_EPC,
			// Coprocessor 0 register 31
			REG_DESAVE,
		};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		return vector<uint32_t>{
			REG_ZERO,      REG_AT,        REG_V0,        REG_V1,        REG_A0,        REG_A1,        REG_A2,        REG_A3,
			REG_T0,        REG_T1,        REG_T2,        REG_T3,        REG_T4,        REG_T5,        REG_T6,        REG_T7,
			REG_S0,        REG_S1,        REG_S2,        REG_S3,        REG_S4,        REG_S5,        REG_S6,        REG_S7,
			REG_T8,        REG_T9,        REG_K0,        REG_K1,        REG_GP,        REG_SP,        REG_FP,        REG_RA,
			CPREG_0,       CPREG_1,       CPREG_2,       CPREG_3,       CPREG_4,       CPREG_5,       CPREG_6,       CPREG_7,
			CPREG_8,       CPREG_9,       CPREG_10,      CPREG_11,      CPREG_12,      CPREG_13,      CPREG_14,      CPREG_15,
			CPREG_16,      CPREG_17,      CPREG_18,      CPREG_19,      CPREG_20,      CPREG_21,      CPREG_22,      CPREG_23,
			CPREG_24,      CPREG_25,      CPREG_26,      CPREG_27,      CPREG_28,      CPREG_29,      CPREG_30,      CPREG_31,
			FPREG_F0,      FPREG_F1,      FPREG_F2,      FPREG_F3,      FPREG_F4,      FPREG_F5,      FPREG_F6,      FPREG_F7,
			FPREG_F8,      FPREG_F9,      FPREG_F10,     FPREG_F11,     FPREG_F12,     FPREG_F13,     FPREG_F14,     FPREG_F15,
			FPREG_F16,     FPREG_F17,     FPREG_F18,     FPREG_F19,     FPREG_F20,     FPREG_F21,     FPREG_F22,     FPREG_F23,
			FPREG_F24,     FPREG_F25,     FPREG_F26,     FPREG_F27,     FPREG_F28,     FPREG_F29,     FPREG_F30,     FPREG_F31,
			REG_LO, REG_HI,
			// Coprocessor 0 register 0
			REG_INDEX,
			REG_MVP_CONTROL,
			REG_MVP_CONF0,
			REG_MVP_CONF1,
			// Coprocessor 0 register 1
			REG_RANDOM,
			REG_VPE_CONTROL,
			REG_VPE_CONF0,
			REG_VPE_CONF1,
			REG_YQ_MASK,
			REG_VPE_SCHEDULE,
			REG_VPE_SCHE_FBACK,
			REG_VPE_OPT,
			// Coprocessor 0 register 2
			REG_ENTRY_LO0,
			REG_TC_STATUS,
			REG_TC_BIND,
			REG_TC_RESTART,
			REG_TC_HALT,
			REG_TC_CONTEXT,
			REG_TC_SCHEDULE,
			REG_TC_SCHE_FBACK,
			// Coprocessor 0 register 3
			REG_ENTRY_LO1,
			// Coprocessor 0 register 4
			REG_CONTEXT,
			REG_CONTEXT_CONFIG,
			// Coprocessor 0 register 5
			REG_PAGE_MASK,
			REG_PAGE_GRAIN,
			// Coprocessor 0 register 6
			REG_WIRED,
			REG_SRS_CONF0,
			REG_SRS_CONF1,
			REG_SRS_CONF2,
			REG_SRS_CONF3,
			REG_SRS_CONF4,
			// Coprocessor 0 register 7
			REG_HWR_ENA,
			// Coprocessor 0 register 8
			REG_BAD_VADDR,
			// Coprocessor 0 register 9
			REG_COUNT,
			// Coprocessor 0 register 10
			REG_ENTRY_HI,
			// Coprocessor 0 register 11
			REG_COMPARE,
			// Coprocessor 0 register 12
			REG_STATUS,
			REG_INT_CTL,
			REG_SRS_CTL,
			REG_SRS_MAP,
			// Coprocessor 0 register 13
			REG_CAUSE,
			// Coprocessor 0 register 14
			REG_EPC,
			// Coprocessor 0 register 15
			REG_PR_ID,
			REG_EBASE,
			// Coprocessor 0 register 16
			REG_CONFIG,
			REG_CONFIG1,
			REG_CONFIG2,
			REG_CONFIG3,
			// Coprocessor 0 register 17
			REG_LLADDR,
			// Coprocessor 0 register 18
			REG_WATCH_LO,
			// Coprocessor 0 register 19
			REG_WATCH_HI,
			// Coprocessor 0 register 20
			REG_XCONTEXT,
			// Coprocessor 0 register 23
			REG_DEBUG,
			REG_TRACE_CONTROL,
			REG_TRACE_CONTROL2,
			REG_USER_TRACE_DATA,
			REG_TRACE_BPC,
			// Coprocessor 0 register 24
			REG_DEPC,
			// Coprocessor 0 register 25
			REG_PERF_CNT,
			// Coprocessor 0 register 26
			REG_ERR_CTL,
			// Coprocessor 0 register 27
			REG_CACHE_ERR0,
			REG_CACHE_ERR1,
			REG_CACHE_ERR2,
			REG_CACHE_ERR3,
			// Coprocessor 0 register 28
			REG_TAG_LO,
			REG_DATA_LO,
			// Coprocessor 0 register 29
			REG_TAG_HI,
			REG_DATA_HI,
			// Coprocessor 0 register 30
			REG_ERROR_EPC,
			// Coprocessor 0 register 31
			REG_DESAVE,
		};
	}

	virtual vector<uint32_t> GetAllFlags() override
	{
		return vector<uint32_t>{
			FPCCREG_FCC0,  FPCCREG_FCC1,  FPCCREG_FCC2,  FPCCREG_FCC3,  FPCCREG_FCC4,  FPCCREG_FCC5,  FPCCREG_FCC6,  FPCCREG_FCC7
		};
	}

	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override
	{
		BNRegisterInfo result = {reg, 0, m_bits / 8, NoExtend};
		return result;
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return REG_SP;
	}

	virtual uint32_t GetLinkRegister() override
	{
		return REG_RA;
	}

	virtual vector<uint32_t> GetSystemRegisters() override
	{
		return vector< uint32_t> {
			// Coprocessor 0 register 0
			REG_INDEX,
			REG_MVP_CONTROL,
			REG_MVP_CONF0,
			REG_MVP_CONF1,
			// Coprocessor 0 register 1
			REG_RANDOM,
			REG_VPE_CONTROL,
			REG_VPE_CONF0,
			REG_VPE_CONF1,
			REG_YQ_MASK,
			REG_VPE_SCHEDULE,
			REG_VPE_SCHE_FBACK,
			REG_VPE_OPT,
			// Coprocessor 0 register 2
			REG_ENTRY_LO0,
			REG_TC_STATUS,
			REG_TC_BIND,
			REG_TC_RESTART,
			REG_TC_HALT,
			REG_TC_CONTEXT,
			REG_TC_SCHEDULE,
			REG_TC_SCHE_FBACK,
			// Coprocessor 0 register 3
			REG_ENTRY_LO1,
			// Coprocessor 0 register 4
			REG_CONTEXT,
			REG_CONTEXT_CONFIG,
			// Coprocessor 0 register 5
			REG_PAGE_MASK,
			REG_PAGE_GRAIN,
			// Coprocessor 0 register 6
			REG_WIRED,
			REG_SRS_CONF0,
			REG_SRS_CONF1,
			REG_SRS_CONF2,
			REG_SRS_CONF3,
			REG_SRS_CONF4,
			// Coprocessor 0 register 7
			REG_HWR_ENA,
			// Coprocessor 0 register 8
			REG_BAD_VADDR,
			// Coprocessor 0 register 9
			REG_COUNT,
			// Coprocessor 0 register 10
			REG_ENTRY_HI,
			// Coprocessor 0 register 11
			REG_COMPARE,
			// Coprocessor 0 register 12
			REG_STATUS,
			REG_INT_CTL,
			REG_SRS_CTL,
			REG_SRS_MAP,
			// Coprocessor 0 register 13
			REG_CAUSE,
			// Coprocessor 0 register 14
			REG_EPC,
			// Coprocessor 0 register 15
			REG_PR_ID,
			REG_EBASE,
			// Coprocessor 0 register 16
			REG_CONFIG,
			REG_CONFIG1,
			REG_CONFIG2,
			REG_CONFIG3,
			// Coprocessor 0 register 17
			REG_LLADDR,
			// Coprocessor 0 register 18
			REG_WATCH_LO,
			// Coprocessor 0 register 19
			REG_WATCH_HI,
			// Coprocessor 0 register 20
			REG_XCONTEXT,
			// Coprocessor 0 register 23
			REG_DEBUG,
			REG_TRACE_CONTROL,
			REG_TRACE_CONTROL2,
			REG_USER_TRACE_DATA,
			REG_TRACE_BPC,
			// Coprocessor 0 register 24
			REG_DEPC,
			// Coprocessor 0 register 25
			REG_PERF_CNT,
			// Coprocessor 0 register 26
			REG_ERR_CTL,
			// Coprocessor 0 register 27
			REG_CACHE_ERR0,
			REG_CACHE_ERR1,
			REG_CACHE_ERR2,
			REG_CACHE_ERR3,
			// Coprocessor 0 register 28
			REG_TAG_LO,
			REG_DATA_LO,
			// Coprocessor 0 register 29
			REG_TAG_HI,
			REG_DATA_HI,
			// Coprocessor 0 register 30
			REG_ERROR_EPC,
			// Coprocessor 0 register 31
			REG_DESAVE,
		};
	}

};

class MipsO32CallingConvention: public CallingConvention
{
public:
	MipsO32CallingConvention(Architecture* arch): CallingConvention(arch, "o32")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_A0, REG_A1, REG_A2, REG_A3 };
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3, REG_T0, REG_T1,
			REG_T2, REG_T3, REG_T4, REG_T5, REG_T6, REG_T7, REG_T8, REG_T9 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return REG_GP;
	}

	virtual vector<uint32_t> GetImplicitlyDefinedRegisters() override
	{
		return vector<uint32_t> { REG_T9 };
	}

	virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override
	{
		RegisterValue result;
		if (reg == REG_T9)
		{
			result.state = ConstantPointerValue;
			result.value = func->GetStart();
		}
		return result;
	}
};

class MipsN64CallingConvention: public CallingConvention
{
public:
	MipsN64CallingConvention(Architecture* arch): CallingConvention(arch, "n64")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			REG_A0, REG_A1, REG_A2, REG_A3,
			REG_A4, REG_A5, REG_A6, REG_A7,
		};
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return false;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5,
			REG_A6, REG_A7, REG_T4, REG_T5, REG_T6, REG_T7, REG_T8, REG_T9, REG_RA,
			FPREG_F0, FPREG_F1, FPREG_F2, FPREG_F3, FPREG_F4, FPREG_F5, FPREG_F6, FPREG_F7, FPREG_F8,
			FPREG_F9, FPREG_F10, FPREG_F11, FPREG_F12, FPREG_F13, FPREG_F14, FPREG_F15, FPREG_F16, FPREG_F17,
			FPREG_F18, FPREG_F19, FPREG_F20, FPREG_F21, FPREG_F22, FPREG_F23, };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP, FPREG_F24, FPREG_F25, FPREG_F26, FPREG_F27, FPREG_F28, FPREG_F29, FPREG_F30, FPREG_F31 };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return REG_GP;
	}

	virtual vector<uint32_t> GetImplicitlyDefinedRegisters() override
	{
		return vector<uint32_t> { REG_T9 };
	}

	virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override
	{
		RegisterValue result;
		if (reg == REG_T9)
		{
			result.state = ConstantPointerValue;
			result.value = func->GetStart();
		}
		return result;
	}
};

class MipsLinuxSyscallCallingConvention: public CallingConvention
{
public:
	MipsLinuxSyscallCallingConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_V0, REG_A0, REG_A1, REG_A2, REG_A3 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP };
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};

class MipsLinuxRtlResolveCallingConvention: public CallingConvention
{
public:
	MipsLinuxRtlResolveCallingConvention(Architecture* arch): CallingConvention(arch, "linux-rtlresolve")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			REG_T7, /* return address of caller of PLT stub */
			REG_T8 /* symbol index */
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_T0;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};

class MipsImportedFunctionRecognizer: public FunctionRecognizer
{
private:
	bool RecognizeELFPLTEntries0(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		// Look for the following code pattern:
		// $t7 = got_hi
		// $t9 = [$t7 + got_lo].d
		// $t8 = $t7 + got_lo
		// OPTIONAL: $t7 = got_hi
		// tailcall($t9)
		if (il->GetInstructionCount() < 4)
			return false;
		if (il->GetInstructionCount() > 5)
			return false;

		LowLevelILInstruction lui = il->GetInstruction(0);
		if (lui.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction luiOperand = lui.GetSourceExpr<LLIL_SET_REG>();
		if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
			return false;
		if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		uint64_t pltHi = luiOperand.GetConstant();
		uint32_t pltReg = lui.GetDestRegister<LLIL_SET_REG>();

		LowLevelILInstruction ld = il->GetInstruction(1);
		if (ld.operation != LLIL_SET_REG)
			return false;
		uint32_t targetReg = ld.GetDestRegister<LLIL_SET_REG>();
		LowLevelILInstruction ldOperand = ld.GetSourceExpr<LLIL_SET_REG>();
		if (ldOperand.operation != LLIL_LOAD)
			return false;
		if (ldOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		LowLevelILInstruction ldAddrOperand = ldOperand.GetSourceExpr<LLIL_LOAD>();
		uint64_t entry = pltHi;
		int64_t ldAddrRightOperandValue = 0;

		if ((ldAddrOperand.operation == LLIL_ADD) || (ldAddrOperand.operation == LLIL_SUB))
		{
			LowLevelILInstruction ldAddrLeftOperand = ldAddrOperand.GetRawOperandAsExpr(0);
			LowLevelILInstruction ldAddrRightOperand = ldAddrOperand.GetRawOperandAsExpr(1);
			if (ldAddrLeftOperand.operation != LLIL_REG)
				return false;
			if (ldAddrLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(ldAddrRightOperand.operation))
				return false;
			ldAddrRightOperandValue = ldAddrRightOperand.GetConstant();
			if (ldAddrOperand.operation == LLIL_SUB)
				ldAddrRightOperandValue = -ldAddrRightOperandValue;
			entry = pltHi + ldAddrRightOperandValue;
		}
		else if (ldAddrOperand.operation != LLIL_REG) //If theres no constant
			return false;

		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym)
			return false;
		if (sym->GetType() != ImportAddressSymbol)
			return false;

		LowLevelILInstruction add = il->GetInstruction(2);
		if (add.operation != LLIL_SET_REG)
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
			if (addRightOperand.GetConstant() != (ldAddrRightOperandValue & 0xffffffff))
				return false;
		}
		else if ((addOperand.operation != LLIL_REG) || (addOperand.GetSourceRegister<LLIL_REG>() != pltReg)) //Simple assignment
			return false;

		LowLevelILInstruction jump = il->GetInstruction(3);
		if (jump.operation == LLIL_SET_REG)
		{
			if (il->GetInstructionCount() != 5)
				return false;
			if (jump.GetDestRegister<LLIL_SET_REG>() != pltReg)
				return false;
			LowLevelILInstruction luiOperand = jump.GetSourceExpr<LLIL_SET_REG>();
			if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
				return false;
			if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;
			if (((uint64_t) luiOperand.GetConstant()) != pltHi)
				return false;
			jump = il->GetInstruction(4);
		}

		if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
			return false;
		LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
		if (jumpOperand.operation != LLIL_REG)
			return false;
		if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
			return false;

		Ref<Symbol> funcSym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(funcSym);
		func->ApplyImportedTypes(funcSym);
		return true;
	}


	bool RecognizeELFPLTEntries1(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		LowLevelILInstruction tmp, left, right;

		// Look for the following code pattern:
		// 0: $t9 = [$gp - ????]	// get to base of GOT
		// 1: $t7 = $ra				// transmit address so RTLD!service_stub() can return to caller
		// 2: $t8 = ??				// transmit symbol index to RTLD!service_stub()
		// 3: call($t9)				// call RTLD!service_stub()
		// 4: tailcall(??)
		if (il->GetInstructionCount() != 5)
			return false;

		// test instruction0
		tmp = il->GetInstruction(0); // $t9 = ...
		if (tmp.operation != LLIL_SET_REG) return false;
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // [$gp - ????]
		if (tmp.operation != LLIL_LOAD) return false;
		tmp = tmp.GetSourceExpr<LLIL_LOAD>(); // $gp - ????
		if (tmp.operation != LLIL_SUB) return false;
		auto value = il->GetExprValue(tmp); // accept if Binja has resolved to a value
		//if (value.state != ConstantValue) return false;
		//uint64_t got_base = value.value;

		// test instruction1
		tmp = il->GetInstruction(1); // $t7 = $ra
		if (tmp.operation != LLIL_SET_REG) return false;
		if (tmp.GetDestRegister<LLIL_SET_REG>() != REG_T7) return false; // $t7
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // $ra
		if (tmp.operation != LLIL_REG) return false;
		if (tmp.GetSourceRegister<LLIL_REG>() != REG_RA) return false;

		// test instruction2
		tmp = il->GetInstruction(2); // $t8 = ????
		if (tmp.operation != LLIL_SET_REG) return false;
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // ????
		value = il->GetExprValue(tmp); // accept if Binja has resolved to a value
		if (value.state != ConstantValue) return false;

		// test instruction3
		tmp = il->GetInstruction(3); // call($t9)
		if (tmp.operation != LLIL_CALL) return false;
		tmp = tmp.GetDestExpr<LLIL_CALL>(); // ????
		if (tmp.GetSourceRegister<LLIL_REG>() != REG_T9) return false;

		// test instruction4
		tmp = il->GetInstruction(4); // tailcall(??)
		if (tmp.operation != LLIL_TAILCALL) return false;

		// There should be three symbols:
		// 1. ImportedFunctionSymbol has address of the PLT stub (where we are now)
		// 2. ImportAddressSymbol has address of corresponding GOT entry
		// 3. ExternalSymbol has address of corresponding address in .extern
		//
		// We need to locate #3, resolve its type, and apply it to #1
		Ref<Symbol> pltSym = data->GetSymbolByAddress(func->GetStart());

		if (pltSym)
		{
			for (auto& extSym : data->GetSymbolsByName(pltSym->GetRawName()))
			{
				if (extSym->GetType() == ExternalSymbol)
				{
					DataVariable var;
					if (data->GetDataVariableAtAddress(extSym->GetAddress(), var))
					{
						func->ApplyImportedTypes(pltSym, var.type);
					}

					return true;
				}
			}
		}

		return false;
	}

public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries0(data, func, il))
			return true;

		if (RecognizeELFPLTEntries1(data, func, il))
			return true;

		return false;
	}
};

class MipsElfRelocationHandler: public RelocationHandler
{
public:

	bool GetGpAddr(Ref<BinaryView> view, int32_t& gpAddr)
	{
		auto sym = view->GetSymbolByRawName("_gp");
		if (!sym)
			sym = view->GetSymbolByRawName("__gnu_local_gp");
		if (!sym)
			return false;
		gpAddr = (int32_t)sym->GetAddress();
		return true;
	}


	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		if (len < 4)
			return false;
		// All ELF MIPS relocations are implicitAddend
		auto info = reloc->GetInfo();
		auto addr = reloc->GetAddress();
		auto symbol = reloc->GetSymbol();
		uint64_t target = reloc->GetTarget();

		uint32_t* dest32 = (uint32_t*)dest;
		uint64_t* dest64 = (uint64_t*)dest;
		auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		auto swap64 = [&arch](uint64_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap64(x); };
		uint32_t inst = swap(dest32[0]);
		uint64_t inst64 = swap64(dest64[0]);
		switch (info.nativeType)
		{
		case R_MIPS_JUMP_SLOT:
		case R_MIPS_COPY:
			dest32[0] = swap((uint32_t)target);
			break;
		case R_MIPS64_COPY:
			dest64[0] = swap64(target);
			break;
		case R_MIPS_32:
			dest32[0] = swap((uint32_t)(inst + target));
			break;
		case R_MIPS_64:
			dest64[0] = swap64(inst64 + target);
			break;
		case R_MIPS_HI16:
		{
			// Find the first _LO16 in the list of relocations
			BNRelocationInfo* cur = info.next;
			while (cur && (cur->nativeType != R_MIPS_LO16))
			{
				cur = cur->next;
			}

			if (cur)
			{
				uint32_t inst2 = *(uint32_t*)(cur->relocationDataCache);
				Instruction instruction;
				memset(&instruction, 0, sizeof(instruction));
				if (mips_decompose(&inst2, sizeof(uint32_t), &instruction, MIPS_32, cur->address, arch->GetEndianness(), 1))
					break;

				int32_t immediate = swap(inst2) & 0xffff;
				// ADDIU and LW has a signed immediate we have to subtract
				if (instruction.operation == MIPS_ADDIU)
				{
					immediate = instruction.operands[2].immediate;
				}
				else if (instruction.operation == MIPS_LW)
				{
					immediate = instruction.operands[1].immediate;
				}
				uint32_t ahl = ((inst & 0xffff) << 16) + immediate;

				// ((AHL + S) – (short)(AHL + S)) >> 16
				dest32[0] = swap((uint32_t)(
					(inst & ~0xffff) |
					(((ahl + target) - (short)(ahl + target)) >> 16)
				));
			}
			else
			{
				LogError("No corresponding R_MIPS_LO16 relocation for R_MIPS_HI16 relocation");
			}
			break;
		}
		case R_MIPS_LO16:
		{
			uint32_t ahl = ((inst & 0xffff) + target) & 0xffff;
			dest32[0] = swap((inst & ~0xffff) | (ahl & 0xffff));
			break;
		}
		case R_MIPS_26:
		{
			// ((A << 2) | (P & 0xf0000000) + S) >> 2
			uint32_t A = (inst & ~0xfc000000) << 2;
			uint32_t P = (uint32_t)addr;
			uint32_t S = (uint32_t)target;
			uint32_t realTarget = (A | (P & 0xf0000000)) + S;
			dest32[0] = swap(((realTarget >> 2) & ~0xfc000000) | (inst & 0xfc000000));
			break;
		}
		case R_MIPS_GOT16:
		case R_MIPS_CALL16:
		{
			int32_t gpAddr;
			if (!GetGpAddr(view, gpAddr))
				break;
			int32_t vRel16 = (int32_t)(target - gpAddr);
			dest32[0] = swap((inst & ~0xffff) | (vRel16 & 0xffff));
			break;
		}
		case R_MIPS_REL32:
		{
			uint32_t originalValue = inst;
			uint64_t displacement = target;
			dest32[0] = swap((uint32_t)(originalValue + displacement));
			break;
		}
		default:
			break;
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			result[i].size = 4;
			result[i].pcRelative = false;
			result[i].dataRelocation = true;
			switch (result[i].nativeType)
			{
			case R_MIPS_NONE:
			case R_MIPS_JALR: // Note: optimization hint that can safely be ignored TODO: link-time mutable opcode bytes
				result[i].type = IgnoredRelocation;
				break;
			case R_MIPS_COPY:
			case R_MIPS64_COPY:
				result[i].type = ELFCopyRelocationType;
				break;
			case R_MIPS_JUMP_SLOT:
				result[i].type = ELFJumpSlotRelocationType;
				break;
			case R_MIPS_HI16:
			{
				result[i].dataRelocation = false;
				result[i].pcRelative = false;
				// MIPS_HI16 relocations can have multiple MIPS_LO16 relocations following them
				for (size_t j = i + 1; j < result.size(); j++)
				{
					if (result[j].nativeType == R_MIPS_LO16 && result[j].symbolIndex == result[i].symbolIndex)
					{
						result[j].type = StandardRelocationType;
						result[j].size = 4;
						result[j].pcRelative = false;
						result[j].dataRelocation = false;
						result[i].next = new BNRelocationInfo(result[j]);
						break;
					}
				}
				break;
			}
			case R_MIPS_LO16:
				result[i].pcRelative = false;
				result[i].dataRelocation = false;
				break;
			case R_MIPS_26:
				result[i].pcRelative = true;
				result[i].dataRelocation = false;
				break;
			case R_MIPS_GOT16:
			case R_MIPS_CALL16:
			{
				// Note: GP addr not avaiable pre-view-finalization, however symbol may exist
				int32_t gpAddr;
				if (!GetGpAddr(view, gpAddr))
				{
					result[i].type = UnhandledRelocation;
					LogWarn("Unsupported relocation type: %s : Unable to locate _gp symbol.", GetRelocationString((ElfMipsRelocationType)result[i].nativeType));
				}
				break;
			}
			case R_MIPS_32:
			case R_MIPS_64:
				break;

			case R_MIPS_REL32:
				/* elfview delivers relocs on a symbol's GOT entry with symbolIndex populated */
				if (result[i].symbolIndex)
				{
					/* UNSUPPORTED! need a binary with R_MIPS_REL32 on GOT entry to test */
					while(0);
				}
				else
				{
					break;
				}
			default:
				result[i].type = UnhandledRelocation;
				LogWarn("Unsupported relocation type: %llu (%s) @0x%llX", result[i].nativeType,
					GetRelocationString((ElfMipsRelocationType)result[i].nativeType), result[i].address);
			}
		}
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
		size_t result;

		switch (info.nativeType)
		{
			case R_MIPS_HI16:
			case R_MIPS_LO16:
			case R_MIPS_CALL16:
			case R_MIPS_GOT16:
				result = BN_NOCOERCE_EXTERN_PTR;
				break;
			default:
				result = BN_AUTOCOERCE_EXTERN_PTR;
				break;
		}

		return result;
	}
};

static void InitMipsSettings()
{
	Ref<Settings> settings = Settings::Instance();

	settings->RegisterSetting("arch.mips.disassembly.pseudoOps",
			R"({
			"title" : "MIPS Disassembly Pseudo-Op",
			"type" : "boolean",
			"default" : true,
			"description" : "Enable use of pseudo-op instructions in MIPS disassembly."
			})");
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_pe");
	}
#endif

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		InitMipsSettings();

		Architecture* mipsel = new MipsArchitecture("mipsel32", LittleEndian, 32);
		Architecture* mipseb = new MipsArchitecture("mips32", BigEndian, 32);
		Architecture* mips64eb = new MipsArchitecture("mips64", BigEndian, 64);

		Architecture::Register(mipsel);
		Architecture::Register(mipseb);
		Architecture::Register(mips64eb);

		/* calling conventions */
		MipsO32CallingConvention* o32LE = new MipsO32CallingConvention(mipsel);
		MipsO32CallingConvention* o32BE = new MipsO32CallingConvention(mipseb);
		MipsN64CallingConvention* n64BE = new MipsN64CallingConvention(mips64eb);

		mipsel->RegisterCallingConvention(o32LE);
		mipseb->RegisterCallingConvention(o32BE);
		mipsel->SetDefaultCallingConvention(o32LE);
		mipseb->SetDefaultCallingConvention(o32BE);
		mips64eb->RegisterCallingConvention(n64BE);
		mips64eb->SetDefaultCallingConvention(n64BE);

		MipsLinuxSyscallCallingConvention* linuxSyscallLE = new MipsLinuxSyscallCallingConvention(mipsel);
		MipsLinuxSyscallCallingConvention* linuxSyscallBE = new MipsLinuxSyscallCallingConvention(mipseb);
		mipsel->RegisterCallingConvention(linuxSyscallLE);
		mipseb->RegisterCallingConvention(linuxSyscallBE);

		mipsel->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mipsel));
		mipseb->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mipseb));
		mips64eb->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mips64eb));

		/* function recognizers */
		mipsel->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());
		mipseb->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());

		mipsel->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mipseb->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mips64eb->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file

		/* since elfXX_hdr.e_machine == EM_MIPS (8) on both mips and mips64, we adopt the following
		   convention to disambiguate: shift in elf64_hdr.e_ident[EI_CLASS]: */
		#define EM_MIPS (8)
		#define EI_CLASS_32 (1)
		#define EI_CLASS_64 (2)
		#define ARCH_ID_MIPS32 ((EI_CLASS_32<<16)|EM_MIPS) /* 0x10008 */
		#define ARCH_ID_MIPS64 ((EI_CLASS_64<<16)|EM_MIPS) /* 0x20008 */
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS64, BigEndian, mips64eb);
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS32, LittleEndian, mipsel);
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS32, BigEndian, mipseb);
		BinaryViewType::RegisterArchitecture("PE", 0x166, LittleEndian, mipsel);
		return true;
	}
}

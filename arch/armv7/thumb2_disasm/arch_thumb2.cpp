#define _CRT_SECURE_NO_WARNINGS

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"

// registers, etc.
#include "arch_armv7.h"
#include "spec.h"
#include "disassembler.h"
#include "il.h"

using namespace BinaryNinja;
using namespace armv7;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

static Ref<Enumeration> get_msr_op_enum()
{
	EnumerationBuilder builder;
	builder.AddMemberWithValue("msp", REGS_MSP);
	builder.AddMemberWithValue("psp", REGS_PSP);
	builder.AddMemberWithValue("basepri", REGS_BASEPRI);
	builder.AddMemberWithValue("basepri_max", REGS_BASEPRI_MAX);
	builder.AddMemberWithValue("primask", REGS_PRIMASK);
	builder.AddMemberWithValue("faultmask", REGS_FAULTMASK);
	builder.AddMemberWithValue("control", REGS_CONTROL);
	builder.AddMemberWithValue("ipsr", REGS_IPSR);
	builder.AddMemberWithValue("epsr", REGS_EPSR);
	builder.AddMemberWithValue("iepsr", REGS_IEPSR);
	builder.AddMemberWithValue("apsr", REGS_APSR);
	builder.AddMemberWithValue("apsr_g", REGS_APSR_G);
	builder.AddMemberWithValue("apsr_nzcvq", REGS_APSR_NZCVQ);
	builder.AddMemberWithValue("apsr_nzcvqg", REGS_APSR_NZCVQG);
	builder.AddMemberWithValue("iapsr", REGS_IAPSR);
	builder.AddMemberWithValue("iapsr_g", REGS_IAPSR_G);
	builder.AddMemberWithValue("iapsr_nzcvq", REGS_IAPSR_NZCVQ);
	builder.AddMemberWithValue("iapsr_nzcvqg", REGS_IAPSR_NZCVQG);
	builder.AddMemberWithValue("eapsr", REGS_EAPSR);
	builder.AddMemberWithValue("eapsr_g", REGS_EAPSR_G);
	builder.AddMemberWithValue("eapsr_nzcvq", REGS_EAPSR_NZCVQ);
	builder.AddMemberWithValue("eapsr_nzcvqg", REGS_EAPSR_NZCVQG);
	builder.AddMemberWithValue("xpsr", REGS_XPSR);
	builder.AddMemberWithValue("xpsr_g", REGS_XPSR_G);
	builder.AddMemberWithValue("xpsr_nzcvq", REGS_XPSR_NZCVQ);
	builder.AddMemberWithValue("xpsr_nzcvqg", REGS_XPSR_NZCVQG);
	builder.AddMemberWithValue("cpsr", REGS_CPSR);
	builder.AddMemberWithValue("cpsr_c", REGS_CPSR_C);
	builder.AddMemberWithValue("cpsr_x", REGS_CPSR_X);
	builder.AddMemberWithValue("cpsr_xc", REGS_CPSR_XC);
	builder.AddMemberWithValue("cpsr_s", REGS_CPSR_S);
	builder.AddMemberWithValue("cpsr_sc", REGS_CPSR_SC);
	builder.AddMemberWithValue("cpsr_sx", REGS_CPSR_SX);
	builder.AddMemberWithValue("cpsr_sxc", REGS_CPSR_SXC);
	builder.AddMemberWithValue("cpsr_f", REGS_CPSR_F);
	builder.AddMemberWithValue("cpsr_fc", REGS_CPSR_FC);
	builder.AddMemberWithValue("cpsr_fx", REGS_CPSR_FX);
	builder.AddMemberWithValue("cpsr_fxc", REGS_CPSR_FXC);
	builder.AddMemberWithValue("cpsr_fs", REGS_CPSR_FS);
	builder.AddMemberWithValue("cpsr_fsc", REGS_CPSR_FSC);
	builder.AddMemberWithValue("cpsr_fsx", REGS_CPSR_FSX);
	builder.AddMemberWithValue("cpsr_fsxc", REGS_CPSR_FSXC);
	builder.AddMemberWithValue("spsr", REGS_SPSR);
	builder.AddMemberWithValue("spsr_c", REGS_SPSR_C);
	builder.AddMemberWithValue("spsr_x", REGS_SPSR_X);
	builder.AddMemberWithValue("spsr_xc", REGS_SPSR_XC);
	builder.AddMemberWithValue("spsr_s", REGS_SPSR_S);
	builder.AddMemberWithValue("spsr_sc", REGS_SPSR_SC);
	builder.AddMemberWithValue("spsr_sx", REGS_SPSR_SX);
	builder.AddMemberWithValue("spsr_sxc", REGS_SPSR_SXC);
	builder.AddMemberWithValue("spsr_f", REGS_SPSR_F);
	builder.AddMemberWithValue("spsr_fc", REGS_SPSR_FC);
	builder.AddMemberWithValue("spsr_fx", REGS_SPSR_FX);
	builder.AddMemberWithValue("spsr_fxc", REGS_SPSR_FXC);
	builder.AddMemberWithValue("spsr_fs", REGS_SPSR_FS);
	builder.AddMemberWithValue("spsr_fsc", REGS_SPSR_FSC);
	builder.AddMemberWithValue("spsr_fsx", REGS_SPSR_FSX);
	builder.AddMemberWithValue("spsr_fsxc", REGS_SPSR_FSXC);
	builder.AddMemberWithValue("apsr_nzcv", REGS_APSR_NZCV);
	Ref<Enumeration> _enum = builder.Finalize();
	return _enum;
}

static Ref<Enumeration> GetVfpStatusRegisterEnum()
{
	EnumerationBuilder builder;
	builder.AddMemberWithValue("fpsid", REGS_FPSID);
	builder.AddMemberWithValue("fpscr", REGS_FPSCR);
	builder.AddMemberWithValue("mvfr2", REGS_MVFR2);
	builder.AddMemberWithValue("mvfr1", REGS_MVFR1);
	builder.AddMemberWithValue("mvfr0", REGS_MVFR0);
	builder.AddMemberWithValue("fpexc", REGS_FPEXC);
	builder.AddMemberWithValue("fpinst", REGS_FPINST);
	builder.AddMemberWithValue("fpinst2", REGS_FPINST2);
	Ref<Enumeration> _enum = builder.Finalize();
	return _enum;
}

/* class Architecture from binaryninjaapi.h */
class Thumb2Architecture: public ArmCommonArchitecture
{
protected:
	virtual std::string GetAssemblerTriple() override
	{
		if(m_endian == BigEndian)
			return "thumbv7eb-none-none";

		return "thumbv7-none-none";
	}

	bool populateDecomposeRequest(decomp_request *req, const uint8_t *data, size_t len,
		uint64_t addr, int inIfThen, int inIfThenLast)
	{
		if (!data || len < 2)
			return false;
		req->instr_word16 = 0;
		req->instr_word32 = 0;
		if(m_endian == LittleEndian) {
			req->instr_word16 = *(uint16_t *)data;
			if(len >= 4) {
				req->instr_word32 = ((*(uint16_t *)data)<<16) | *(uint16_t *)(data + 2);
			}
		}
		else {
			req->instr_word16 = (data[0] << 8) | data[1];
			if(len >= 4) {
				req->instr_word32 = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
			}
		}

		req->arch = ARCH_ARMv7;
		req->instrSet = INSTRSET_THUMB2;
		req->inIfThen = inIfThen;
		req->inIfThenLast = inIfThenLast;
		req->carry_in = 0;
		req->addr = (uint32_t)addr;
		return true;
	}

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, decomp_result& result)
	{
		(void)addr;
		(void)maxLen;
		decomp_request request;

		if (!populateDecomposeRequest(&request, data, maxLen, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN))
			return false;

		memset(&result, 0, sizeof(result));
		if (thumb_decompose(&request, &result) != STATUS_OK)
			return false;
		return true;
	}

public:
	/* initialization list */
	Thumb2Architecture(const char* name, BNEndianness endian): ArmCommonArchitecture(name, endian)
	{
	}

	/*************************************************************************/

	virtual size_t GetMaxInstructionLength() const override
	{
		return 18; // IT blocks can have up to four following associated instructions
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 2;
	}

	virtual size_t GetOpcodeDisplayLength() const override
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
		decomp_request request;
		decomp_result decomp;

		if (!populateDecomposeRequest(&request, data, maxLen, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN))
			return false;

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;
		if ((decomp.instrSize / 8) > maxLen)
			return false;
		if ((decomp.status & STATUS_UNDEFINED) || (!decomp.format))
			return false;

		result.length = decomp.instrSize / 8;

		if ((decomp.mnem == armv7::ARMV7_IT) && (decomp.fields[FIELD_mask] != 0))
		{
			// IT block: consume all instructions and handle contained branches
			uint32_t offset = decomp.instrSize / 8;
			uint32_t mask = decomp.fields[FIELD_mask];
			uint32_t cond = decomp.fields[FIELD_firstcond];

			size_t instrCount;
			if (mask & 1)
				instrCount = 4;
			else if (mask & 2)
				instrCount = 3;
			else if (mask & 4)
				instrCount = 2;
			else
				instrCount = 1;

			// First branch/return in each condition path
			bool trueTerminated = false;
			bool falseTerminated = false;
			bool trueBranched = false;
			bool falseBranched = false;
			bool trueReturned = false;
			bool falseReturned = false;

			uint64_t trueBranchTargetAddr = 0;
			uint64_t falseBranchTargetAddr = 0;

			for (size_t i = 0; i < instrCount; i++)
			{
				bool isTrue = (i == 0) || (((mask >> (4 - i)) & 1) == (cond & 1));

				InstructionInfo innerResult;
				if (!GetInstructionInfo(data + offset, addr + offset, maxLen - offset, innerResult))
					break;
				if ((offset + innerResult.length) > maxLen)
					break;

				bool& terminated = isTrue ? trueTerminated : falseTerminated;
				bool& branched = isTrue ? trueBranched : falseBranched;
				bool& returned = isTrue ? trueReturned : falseReturned;
				uint64_t& branchTarget = isTrue ? trueBranchTargetAddr : falseBranchTargetAddr;

				// Only process if the conditional branch we're following isn't terminated
				// Otherwise, just track if the arch is switching and the offset
				if (!terminated)
				{
					for (size_t j = 0; j < innerResult.branchCount; j++)
					{
						switch (innerResult.branchType[j])
						{
						case UnconditionalBranch:
						case TrueBranch:
						case FalseBranch:
							branched = true;
							terminated = true;
							branchTarget = innerResult.branchTarget[j];
							break;
						case FunctionReturn:
							returned = true;
							terminated = true;
							break;
						case CallDestination:
							result.AddBranch(CallDestination, innerResult.branchTarget[j],
								innerResult.branchArch[j] ? m_armArch : this);
							break;
						case UnresolvedBranch:
						case IndirectBranch:
						case ExceptionBranch:
							// We don't know the branch target so just set terminated
							terminated = true;
							break;
						default:
							break;
						}
					}
				}

				if (innerResult.archTransitionByTargetAddr)
					result.archTransitionByTargetAddr = true;

				offset += innerResult.length;
			}

			result.length = offset;

			uint64_t fallThroughAddr = (addr + offset) & 0xffffffffLL;
			// The targets for true/false branches either go somewhere or fall through to the next instr
			uint64_t trueTargetAddr = trueBranched ? trueBranchTargetAddr : fallThroughAddr;
			uint64_t falseTargetAddr = falseBranched ? falseBranchTargetAddr : fallThroughAddr;

			if (trueReturned && falseReturned)
			{
				// If both paths return
				result.AddBranch(FunctionReturn);
			}
			else if (trueTargetAddr != falseTargetAddr)
			{
				// True and false go to different locations (either branch or fallthrough)
				result.AddBranch(TrueBranch, trueTargetAddr, this);
				result.AddBranch(FalseBranch, falseTargetAddr, this);
			}
			else if (trueTargetAddr != fallThroughAddr)
			{
				// True and false branch to the same location that isn't the fallthrough address
				result.AddBranch(UnconditionalBranch, trueTargetAddr, this);
			}

			return true;
		}

		switch (decomp.mnem)
		{
		case armv7::ARMV7_LDR:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REG) && (decomp.fields[decomp.format->operands[0].field0] == 15))
			{
				result.AddBranch(UnresolvedBranch);
				result.archTransitionByTargetAddr = true;
			}
			break;

		case ARMV7_LDM:
		case ARMV7_LDMDA:
		case ARMV7_LDMDB:
		case ARMV7_LDMIA: // defaults to ARMV7_LDM
		case ARMV7_LDMIB:
			if ((decomp.format->operandCount > 1) && (decomp.format->operands[1].type == OPERAND_FORMAT_REGISTERS)
				&& (decomp.fields[decomp.format->operands[1].field0] & (1 << 15)))
			{
				result.AddBranch(UnresolvedBranch);
				result.archTransitionByTargetAddr = true;
			}
			break;
		case armv7::ARMV7_ADD:
		case armv7::ARMV7_ADC:
		case armv7::ARMV7_EOR:
		case armv7::ARMV7_SUB:
		case armv7::ARMV7_SBC:
		case armv7::ARMV7_RSB:
		case armv7::ARMV7_RSC:
		case armv7::ARMV7_BIC:
		case armv7::ARMV7_ORR:
		case armv7::ARMV7_LSL:
		case armv7::ARMV7_LSR:
		case armv7::ARMV7_ASR:
		case armv7::ARMV7_ROR:
		case armv7::ARMV7_RRX:
		case armv7::ARMV7_MOV:
		case armv7::ARMV7_MVN:
		case armv7::ARMV7_MOVW:
		case armv7::ARMV7_MOVT:
		case armv7::ARMV7_LDRT:
		case armv7::ARMV7_LDRH:
		case armv7::ARMV7_LDRHT:
		case armv7::ARMV7_LDRB:
		case armv7::ARMV7_LDRBT:
		case armv7::ARMV7_LDRSH:
		case armv7::ARMV7_LDRSHT:
		case armv7::ARMV7_LDRSB:
		case armv7::ARMV7_LDRSBT:
		case armv7::ARMV7_LDRD:
		case armv7::ARMV7_ADR:
		case armv7::ARMV7_UBFX:
		case armv7::ARMV7_UXTAB:
		case armv7::ARMV7_UXTB:
		case armv7::ARMV7_UXTH:
		case armv7::ARMV7_MUL:
		case armv7::ARMV7_SDIV:
		case armv7::ARMV7_UDIV:
		case armv7::ARMV7_SBFX:
		case armv7::ARMV7_SXTB:
		case armv7::ARMV7_SXTH:
		case armv7::ARMV7_BFC:
		case armv7::ARMV7_BFI:
		case armv7::ARMV7_CLZ:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REG) && (decomp.fields[decomp.format->operands[0].field0] == 15))
				result.AddBranch(UnresolvedBranch);
			break;

		case armv7::ARMV7_B:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				result.AddBranch(UnconditionalBranch, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
			} else {
				result.AddBranch(TrueBranch, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
				result.AddBranch(FalseBranch, (addr + result.length) & 0xffffffffLL, this);
			}
			break;

		case armv7::ARMV7_BX:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				if ((decomp.format->operands[0].type == OPERAND_FORMAT_LR) ||
					((decomp.format->operands[0].type == OPERAND_FORMAT_REG) &&
						(decomp.fields[decomp.format->operands[0].field0] == 14))) {
						result.AddBranch(FunctionReturn);
						result.archTransitionByTargetAddr = true;
				} else {
					result.AddBranch(UnresolvedBranch);
					result.archTransitionByTargetAddr = true;
				}
			}
			break;

		case armv7::ARMV7_BL:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				result.AddBranch(CallDestination, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
			}
			break;

		case armv7::ARMV7_BLX:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				if (decomp.format->operands[0].type == OPERAND_FORMAT_IMM) {
					uint64_t target;
					if (addr & 2)
						target = (decomp.fields[decomp.format->operands[0].field0] + 2 + addr) & 0xffffffffLL;
					else
						target = (decomp.fields[decomp.format->operands[0].field0] + 4 + addr) & 0xffffffffLL;
					result.AddBranch(CallDestination, target, m_armArch);
				} else if ((decomp.format->operands[0].type == OPERAND_FORMAT_LR) ||
					((decomp.format->operands[0].type == OPERAND_FORMAT_REG) &&
						(decomp.fields[decomp.format->operands[0].field0] == 14))) {
						result.AddBranch(FunctionReturn); // initially indicate "blx lr" as a return since this is common and conservative; subsequent analysis determines if it's a function call
				}
				result.archTransitionByTargetAddr = true;
			}
			break;

		case armv7::ARMV7_CBNZ:
		case armv7::ARMV7_CBZ:
			result.AddBranch(TrueBranch, (decomp.fields[decomp.format->operands[1].field0] + addr) & 0xffffffffLL, this);
			result.AddBranch(FalseBranch, (addr + result.length) & 0xffffffffLL, this);
			break;

		case armv7::ARMV7_POP:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REGISTERS) &&
				(decomp.fields[FIELD_registers] & (1 << 15))) {
				result.AddBranch(FunctionReturn);
			}
			break;

		case armv7::ARMV7_SVC:
			result.AddBranch(SystemCall);
			break;

		case armv7::ARMV7_TBB:
		case armv7::ARMV7_TBH:
			result.AddBranch(UnresolvedBranch);
			break;

		case armv7::ARMV7_UDF:
			result.AddBranch(ExceptionBranch);
			break;

		default:
			break;
		}

		return true;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		decomp_request request;
		decomp_result decomp;

		if (!populateDecomposeRequest(&request, data, len, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN))
			return false;

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;

		if (decomp.status & STATUS_UNDEFINED) {
			len = decomp.instrSize / 8;
			result.emplace_back(InstructionToken, "undefined");
			return true;
		}

		if ((decomp.instrSize / 8) > len)
			return false;

		if (!decomp.format)
			return false;

		char padding[9];
		memset(padding, 0x20, sizeof(padding));
		string operation = get_thumb_operation_name(&decomp);
		size_t operationLen = operation.size();
		if (operationLen < 8)
		{
			padding[8-operationLen] = '\0';
		}
		else
			padding[1] = '\0';

		result.emplace_back(InstructionToken, operation);
		if (decomp.format->operandCount > 0)
			result.emplace_back(TextToken, padding);

		for (size_t i = 0; i < decomp.format->operandCount; i++)
		{
			int j;
			const instruction_operand_format& operand = decomp.format->operands[i];
			uint32_t value, r, bits, shift_t, shift_n, add, imm32, reg;
			char buf[16];
			char offset[32];
			char regname[16];
			char secondname[16];
			bool first;

			switch (operand.type)
			{
			case OPERAND_FORMAT_MEMORY_ONE_REG:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(value) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");

					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");

				value = decomp.fields[operand.field1];
				if (value < 10)
					snprintf(offset, sizeof(offset), "-%d", value);
				else
					snprintf(offset, sizeof(offset), "-0x%x", value);
				result.emplace_back(IntegerToken, offset, -(int64_t)value);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname))
					strcpy(regname, "undefined");
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(decomp.fields[FIELD_add] && value==0) {
					/* omit the case where we are adding 0 */
					while(0);
				}
				else {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");

					const char *fmt;
					if(decomp.fields[FIELD_add])
						fmt = (value < 10) ? "%d":"0x%x";
					else
						fmt = (value < 10) ? "-%d":"-0x%x";

					snprintf(offset, sizeof(offset), fmt, value);
					result.emplace_back(IntegerToken, offset, -(int64_t)value);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if (value != 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(!(decomp.fields[FIELD_add] && value == 0)) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");
					if(decomp.fields[FIELD_add]) {
						if (value < 10)
							snprintf(offset, sizeof(offset), "%d", value);
						else
							snprintf(offset, sizeof(offset), "0x%x", value);
						result.emplace_back(IntegerToken, offset, value);
					} else {
						if (value < 10)
							snprintf(offset, sizeof(offset), "-%d", value);
						else
							snprintf(offset, sizeof(offset), "-0x%x", value);
						result.emplace_back(IntegerToken, offset, -(int64_t)value);
					}
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);

				shift_t = decomp.fields[FIELD_shift_t];
				shift_n = decomp.fields[FIELD_shift_n];

				if(shift_n != 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
					if(shift_t == SRType_LSL) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsl #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_LSR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_ASR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "asr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_RRX) {
						if(shift_n != 1) {
							snprintf(offset, sizeof(offset), "%d", shift_n);
							result.emplace_back(TextToken, "rrx #");
							result.emplace_back(IntegerToken, offset, shift_n);
						}
						else {
							result.emplace_back(TextToken, "rrx");
						}
					} else if(shift_t == SRType_ROR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "ror #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else {
						result.emplace_back(TextToken, "undefined");
					}
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_ROTATION:
				value = decomp.fields[FIELD_rotation];

				if(value) {
					if(i>0)
						result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "ror #");
					snprintf(buf, sizeof(buf), "%d", value);
					result.emplace_back(IntegerToken, buf, 1);
				}

				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);
				result.emplace_back(TextToken, ", lsl #");
				result.emplace_back(IntegerToken, "1", 1);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_SP_IMM:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "sp");

				value = decomp.fields[operand.field0];
				if(value) {
					result.emplace_back(TextToken, ", #");

					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "sp");

				value = decomp.fields[operand.field0];
				if (value != 0) {
					result.emplace_back(TextToken, ", #");
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_PC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "[");
				result.emplace_back(RegisterToken, "pc");
				result.emplace_back(TextToken, "]");
				break;

			case OPERAND_FORMAT_IMM64: /* 64 bit immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if(IS_FIELD_PRESENT(&decomp, FIELD_imm64h) && IS_FIELD_PRESENT(&decomp, FIELD_imm64l)){
					uint64_t imm64 = 0;
					imm64 |= decomp.fields[FIELD_imm64h];
					imm64 <<= 32;
					imm64 |= decomp.fields[FIELD_imm64l];
					/* this will be '#' for lone numerals, 'p' for coprocessor, etc. */
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);

					if(imm64 < 10)
						snprintf(offset, sizeof(offset), "%" PRIu64, imm64);
					else
						snprintf(offset, sizeof(offset), "0x%" PRIx64, imm64);
					result.emplace_back(IntegerToken, offset, imm64);
				}
				/* could be closing '}' for stuff like coprocessor {<option>} in ldc */
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.suffix);
				break;

			case OPERAND_FORMAT_IMM: /* immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				value = decomp.fields[operand.field0];

				/* this will be '#' for lone numerals, 'p' for coprocessor, etc. */
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);

				if (decomp.mnem == armv7::ARMV7_B || decomp.mnem == armv7::ARMV7_BL) {
					value += 4 + (uint32_t)addr;
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(PossibleAddressToken, offset, value);
				} else if (decomp.mnem == armv7::ARMV7_BX || decomp.mnem == armv7::ARMV7_BLX) {
					if (addr & 2)
						value += 2 + (uint32_t)addr;
					else
						value += 4 + (uint32_t)addr;
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(PossibleAddressToken, offset, value);
				} else if (decomp.mnem == armv7::ARMV7_CBZ || decomp.mnem == armv7::ARMV7_CBNZ) {
					value += (uint32_t)addr;
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(PossibleAddressToken, offset, value);
				} else {
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}

				/* could be closing '}' for stuff like coprocessor {<option>} in ldc */
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.suffix);

				break;

			case OPERAND_FORMAT_OPTIONAL_IMM: /* optional immediate fields */
				value = decomp.fields[operand.field0];
				if(value != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				break;

			case OPERAND_FORMAT_ADD_IMM: /* immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);

				value = decomp.fields[operand.field0];
				if(decomp.fields[FIELD_add]) {
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				} else {
					if (value < 10)
						snprintf(offset, sizeof(offset), "-%d", value);
					else
						snprintf(offset, sizeof(offset), "-0x%x", value);
					result.emplace_back(IntegerToken, offset, -(int64_t)value);
				}
				break;

			case OPERAND_FORMAT_OPTIONAL_ADD_IMM: /* optional immediate fields */
				value = decomp.fields[operand.field0];
				if(value != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);
					if(decomp.fields[FIELD_add]) {
						if (value < 10)
							snprintf(offset, sizeof(offset), "%d", value);
						else
							snprintf(offset, sizeof(offset), "0x%x", value);
						result.emplace_back(IntegerToken, offset, value);
					} else {
						if (value < 10)
							snprintf(offset, sizeof(offset), "-%d", value);
						else
							snprintf(offset, sizeof(offset), "-0x%x", value);
						result.emplace_back(IntegerToken, offset, -(int64_t)value);
					}
				}
				break;

			case OPERAND_FORMAT_ZERO:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");
				result.emplace_back(IntegerToken, "0", 0);
				break;

			case OPERAND_FORMAT_REG: /* register fields */
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_REG_FP: /* floating-point regs s0..s31, d0..d31, q0..q15 */
				value = decomp.fields[operand.field0];
				if(operand.prefix[0] == 'q')
					value >>= 1;
				/* prefix should be 'd', 'q', or 'v' */
				snprintf(regname, sizeof(regname), "%s%d", operand.prefix, value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_REG_INDEX: /* floating-point regs s0..s31, d0..d31, q0..q15 */
				value = decomp.fields[operand.field0];
				if(operand.prefix[0] == 'q')
					value >>= 1;
				/* prefix should be 'd', 'q', or 'v' */
				snprintf(regname, sizeof(regname), "%s%d[%d]", operand.prefix, value, decomp.fields[operand.field1]);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_FPSCR:
				switch(decomp.fields[FIELD_FPSCR]) {
					case 0:
						snprintf(regname, sizeof(regname), "fpsid");
						break;
					case 1:
						snprintf(regname, sizeof(regname), "fpscr");
						break;
					case 5:
						snprintf(regname, sizeof(regname), "mvfr2");
						break;
					case 6:
						snprintf(regname, sizeof(regname), "mvfr1");
						break;
					case 7:
						snprintf(regname, sizeof(regname), "mvfr0");
						break;
					case 8:
						snprintf(regname, sizeof(regname), "fpexc");
						break;
					case 9:
						snprintf(regname, sizeof(regname), "fpinst");
						break;
					case 10:
						snprintf(regname, sizeof(regname), "fpinst2");
						break;
					default:
						snprintf(regname, sizeof(regname), "error");
						break;
				}

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;
			case OPERAND_FORMAT_SP:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "sp");
				break;

			case OPERAND_FORMAT_PC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "pc");
				break;

			case OPERAND_FORMAT_LR:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "lr");
				break;

			case OPERAND_FORMAT_COPROC: /* coproc eg: "p12" */
				value = decomp.fields[operand.field0];
				snprintf(buf, sizeof(buf), "p%d", value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, buf);
				break;

			case OPERAND_FORMAT_COPROC_REG: /* coproc register fields eg: "c4" */
				value = decomp.fields[operand.field0];
				snprintf(buf, sizeof(buf), "c%d", value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, buf);
				break;

			case OPERAND_FORMAT_LIST: /* register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				if(decomp.group == INSN_GROUP_NEON) {
					unsigned int n = decomp.fields[FIELD_n];

					snprintf(regname, sizeof(regname), "d%d", n);
					result.emplace_back(RegisterToken, regname);

					if(IS_FIELD_PRESENT(&decomp, FIELD_length)) {
						unsigned int inc = 1;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];

						int length = decomp.fields[FIELD_length];

						for(int i=1; i<length; ++i) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d", (n + i * inc) % 32);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}

				result.emplace_back(TextToken, "}");
				break;
			case OPERAND_FORMAT_REGISTERS_INDEXED: /* indexed register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				if(decomp.group == INSN_GROUP_NEON) {
					unsigned int d = decomp.fields[FIELD_d];


					if(IS_FIELD_PRESENT(&decomp, FIELD_length)) {
						unsigned int inc = 1;
						unsigned int index = 0;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];
						if(IS_FIELD_PRESENT(&decomp, FIELD_index))
							index = decomp.fields[FIELD_index];

						int length = decomp.fields[FIELD_length];

						snprintf(regname, sizeof(regname), "d%d[%d]", d, index);
						result.emplace_back(RegisterToken, regname);
						for(int i=1; i<length; ++i) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d[%d]", (d + i * inc) % 32, index);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}

				result.emplace_back(TextToken, "}");
				break;

			case OPERAND_FORMAT_REGISTERS: /* register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				// for neon instruction, the list of registers is {1,2,3,4} long
				// and is d<Dd>[, d<Dd+1>][, d<Dd+2>][, d<Dd+3>]
				//
				// some instructions have d, d2, d3, d4
				// others just have d, but have regs
				if(decomp.group == INSN_GROUP_NEON) {
					char leader = 'd';
					if (IS_FIELD_PRESENT(&decomp, FIELD_single_regs)){
						if (decomp.fields[FIELD_single_regs] == 1) {
							leader = 's';
						}
					}
					unsigned int d = decomp.fields[FIELD_d];

					snprintf(regname, sizeof(regname), "%c%d%s", leader, d, operand.suffix);
					result.emplace_back(RegisterToken, regname);

					if(IS_FIELD_PRESENT(&decomp, FIELD_regs)) {
						unsigned int inc = 1;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];

						int regs = decomp.fields[FIELD_regs];

						for(int i=1; i<regs; ++i) {
							if (d+(i*inc) >= 32 && leader == 's') break;
							if (i >= 16 && leader == 'd') break;
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "%c%d%s", leader, (d + i * inc) % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
					}
					else {
						int d2=-1, d3=-1, d4=-1;

						if(IS_FIELD_PRESENT(&decomp, FIELD_d2)) d2 = decomp.fields[FIELD_d2];
						if(IS_FIELD_PRESENT(&decomp, FIELD_d3)) d3 = decomp.fields[FIELD_d3];
						if(IS_FIELD_PRESENT(&decomp, FIELD_d4)) d4 = decomp.fields[FIELD_d4];

						if(d2>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d2] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
						if(d3>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d3] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
						if(d4>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d4] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}
				else {
					r = 0;
					bits = decomp.fields[FIELD_registers];

					first = true;
					while(bits) {
						if(bits & 1) {
							if(0 != get_reg_name(r, regname)) {
								strcpy(regname, "undefined");
							}

							if (!first)
								result.emplace_back(OperandSeparatorToken, ", ");
							result.emplace_back(RegisterToken, regname);
							first = false;
						}

						r += 1;
						bits >>= 1;
					}
				}

				result.emplace_back(TextToken, "}");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_ALIGNED:
				if (i > 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
				}

				/* get name of register */
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}

				//printf("alignment: %d\n", decomp.fields[FIELD_alignment]);
				//printf("index_align: %d\n", decomp.fields[FIELD_index_align]);
				//printf("align: %d\n", decomp.fields[FIELD_align]);

				value = decomp.fields[FIELD_alignment];

				result.emplace_back(TextToken, "[");
				result.emplace_back(RegisterToken, regname);
				if(value != 1) {
					result.emplace_back(TextToken, ":");
					snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);

				}
				result.emplace_back(TextToken, "]");

				break;

			case OPERAND_FORMAT_ENDIAN: /* endian specifier */
				if (i > 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
				}

				result.emplace_back(TextToken, decomp.fields[FIELD_E] ? "be":"le");
				break;

			case OPERAND_FORMAT_SHIFT: /* "{,<shift>}" field */
				shift_t = decomp.fields[FIELD_shift_t];
				shift_n = decomp.fields[FIELD_shift_n];

				if(shift_n != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if(shift_t == SRType_LSL) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsl #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_LSR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_ASR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "asr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_RRX) {
						if(shift_n != 1) {
							snprintf(offset, sizeof(offset), "%d", shift_n);
							result.emplace_back(TextToken, "rrx #");
							result.emplace_back(IntegerToken, offset, shift_n);
						}
						else {
							result.emplace_back(TextToken, "rrx");
						}
					} else if(shift_t == SRType_ROR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "ror #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else {
						result.emplace_back(TextToken, "undefined");
					}
				}
				break;

			case OPERAND_FORMAT_IFLAGS:
				j = 0;
				if (decomp.fields[FIELD_A])
					buf[j++] = 'A';
				if (decomp.fields[FIELD_I])
					buf[j++] = 'I';
				if (decomp.fields[FIELD_F])
					buf[j++] = 'F';
				buf[j] = '\0';

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				if(!j)
					result.emplace_back(TextToken, "none");
				else
					result.emplace_back(TextToken, buf);

				break;

			case OPERAND_FORMAT_BARRIER_OPTION:
				{
					const char *lookup[16] = {"#0x0", "#0x1", "OSHST", "OSH", "#0x4",
						"#0x5", "NSHST", "NSH", "#0x8", "#0x9", "ISHST", "ISH",
						"#0xC", "#0xD", "ST", "SY"};

					bool do_lookup = true;
					uint32_t opt = decomp.fields[FIELD_barrier_option];

					/* isb's barrier option is limited to SY, other values are reserved
						and capstone and libopcode print a decimal value */
					if(decomp.mnem == armv7::ARMV7_ISB && opt != 15)
						do_lookup = false;
					if(opt > 15)
						do_lookup = false;

					/* lookup or num */
					if(do_lookup)
						result.emplace_back(TextToken, lookup[opt]);
					else {
						snprintf(buf, sizeof(buf), "#0x%x", opt);
						result.emplace_back(TextToken, buf);
					}
				}
				break;

			case OPERAND_FORMAT_FIRSTCOND: /* if-then cases */
				value = decomp.fields[FIELD_firstcond];
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if(value == 15)
					result.emplace_back(TextToken, "al");
				else
					result.emplace_back(TextToken, get_thumb_condition_name(value));
				break;

			case OPERAND_FORMAT_LABEL: /* <label> field becomes [PC,#<+/-><imm32>] */
				add = decomp.fields[FIELD_add];
				imm32 = decomp.fields[FIELD_imm32];

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "pc");

				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");

				if (add) {
					if (imm32 < 10)
						snprintf(offset, sizeof(offset), "%d", imm32);
					else
						snprintf(offset, sizeof(offset), "0x%x", imm32);
					result.emplace_back(IntegerToken, offset, imm32);
				} else {
					if (imm32 < 10)
						snprintf(offset, sizeof(offset), "-%d", imm32);
					else
						snprintf(offset, sizeof(offset), "-0x%x", imm32);
					result.emplace_back(IntegerToken, offset, -(int64_t)imm32);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_RT_MRC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				reg = decomp.fields[FIELD_Rt_mrc];
				if(reg == 15)
					result.emplace_back(RegisterToken, "apsr_nzcv");
				else {
					get_reg_name(REG_R0 + reg, regname);
					result.emplace_back(RegisterToken, regname);
				}
				break;

			case OPERAND_FORMAT_SPEC_REG:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				if (decomp.mnem == ARMV7_MSR) {
					uint32_t mask = decomp.fields[FIELD_mask];

					/* then this is the system level form */
					if(IS_FIELD_PRESENT(&decomp, FIELD_write_spsr)) {
						const char *c="", *x="", *s="", *f="";
						if(mask) {
							if(mask & 1) c = "c";
							if(mask & 2) x = "x";
							if(mask & 4) s = "s";
							if(mask & 8) f = "f";
						}

						/* is it SPSR write? */
						if(decomp.fields[FIELD_write_spsr]) {
							if(mask)
								snprintf(buf, sizeof(buf), "spsr_%s%s%s%s", f, s, x, c);
							else
								strcpy(buf, "spsr");
						}
						else {
							if(mask)
								snprintf(buf, sizeof(buf), "cpsr_%s%s%s%s", f, s, x, c);
							else
								strcpy(buf, "cpsr");
						}

						result.emplace_back(RegisterToken, buf);
					}
					/* application level form */
					else {
						uint32_t mask = (decomp.fields[FIELD_write_nzcvq] << 1) | decomp.fields[FIELD_write_g];
						uint8_t sysm = decomp.fields[FIELD_SYSm];
						bool xPSR = ((sysm >> 2) & 1) == 1;
						switch (sysm >> 3) {
							case 0: /* xPSR access */
							{
								string reg_name = "";
								string reg_bits = "";
								if (xPSR)
									switch (sysm & 7) {
									case 5: // '101' == IPSR
										result.emplace_back(RegisterToken, "ipsr");
										break;
									case 6: // '110' == EPSR
										result.emplace_back(RegisterToken, "epsr");
										break;
									case 7: // '111' == IEPSR
										result.emplace_back(RegisterToken, "iepsr");
										break;
									}
								else
								{
									switch (sysm & 3)
									{
									case 0:
										reg_name = "apsr";
										break;
									case 1:
										reg_name = "iapsr";
										break;
									case 2:
										reg_name = "eapsr";
										break;
									case 3:
										reg_name = "xpsr";
										break;
									}
									switch(mask) {
									case 0: // unpredictable
										break;
									case 1: // '01' == write_g
										/* aka CPSR_f */
										result.emplace_back(RegisterToken, reg_name + "_g");
										break;
									case 2:	// '10' == write_nzcvq
										/* aka CPSR_s */
										result.emplace_back(RegisterToken, reg_name + "_nzcvq");
										break;
									case 3: // '11' == write_nzcvq | write_g
										/* aka CPSR_fs */
										result.emplace_back(RegisterToken, reg_name + "_nzcvqg");
										break;
									}
								}
								break;
							}
							case 1: /* SP access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "msp");
										break;
									case 1:
										result.emplace_back(RegisterToken, "psp");
										break;
									/* default? */
								}
								break;
							case 2: /* Priority mask or CONTROL access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "primask");
										break;
									case 1:
										result.emplace_back(RegisterToken, "basepri");
										break;
									case 2:
										result.emplace_back(RegisterToken, "basepri_max");
										break;
									case 3:
										result.emplace_back(RegisterToken, "faultmask");
										break;
									case 4:
										result.emplace_back(RegisterToken, "control");
										break;
								}
								break;
							/* default? */
						}
					}
				}
				else
				if (decomp.mnem == ARMV7_MRS) {
					if (decomp.fields[FIELD_read_spsr]) {
						result.emplace_back(RegisterToken, "spsr");
					} else {
						uint8_t sysm = decomp.fields[FIELD_SYSm];
						switch (sysm >> 3) {
							case 0: /* xPSR access */
								switch (sysm & 7)
								{
								case 0:
									result.emplace_back(RegisterToken, "apsr");
									break;
								case 1:
									result.emplace_back(RegisterToken, "iapsr");
									break;
								case 2:
									result.emplace_back(RegisterToken, "eapsr");
									break;
								case 3:
									result.emplace_back(RegisterToken, "xpsr");
									break;
								case 5: // '101' == IPSR
									result.emplace_back(RegisterToken, "ipsr");
									break;
								case 6: // '110' == EPSR
									result.emplace_back(RegisterToken, "epsr");
									break;
								case 7: // '111' == IEPSR
									result.emplace_back(RegisterToken, "iepsr");
									break;
								}
								break;
							case 1: /* SP access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "msp");
										break;
									case 1:
										result.emplace_back(RegisterToken, "psp");
										break;
									/* default? */
								}
								break;
							case 2: /* Priority mask or CONTROL access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "primask");
										break;
									case 1:
									case 2:
										result.emplace_back(RegisterToken, "basepri");
										break;
									case 3:
										result.emplace_back(RegisterToken, "faultmask");
										break;
									case 4:
										result.emplace_back(RegisterToken, "control");
										break;
								}
								break;
							/* default? */
						}
					}
				}

				break;

			default:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);
				break;
			}

			switch (operand.writeback)
			{
			case WRITEBACK_YES:
				result.emplace_back(TextToken, "!");
				break;
			case WRITEBACK_OPTIONAL:
				if (thumb_has_writeback(&decomp))
					result.emplace_back(TextToken, "!");
				break;
			default:
				break;
			}
		}

		len = decomp.instrSize / 8;
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
		case ARMV7_INTRIN_COPROC_STORE:
			return "Coproc_Store";
		case ARMV7_INTRIN_COPROC_LOAD:
			return "Coproc_Load";
		case ARMV7_INTRIN_COPROC_DATAPROCESSING:
			return "Coproc_DataProcessing";
		case ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS:
			return "ExclusiveMonitorsPass";
		case ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS:
			return "SetExclusiveMonitors";
		case ARMV7_INTRIN_SEL:
			return "__sel";
		case ARMV7_INTRIN_VRINTA:
			return "__vrinta";
		case ARMV7_INTRIN_VMAXNM:
			return "__vmaxnm";
		case ARMV7_INTRIN_VMINNM:
			return "__vminnm";
		case ARMV7_INTRIN_VMAX:
			return "__vmax";
		case ARMV7_INTRIN_VMIN:
			return "__vmin";
		case ARMV7_INTRIN_VPMAX:
			return "__vpmax";
		case ARMV7_INTRIN_VPMIN:
			return "__vpmin";
		case ARMV7_INTRIN_VREV16:
			return "__vrev16";
		case ARMV7_INTRIN_VREV32:
			return "__vrev32";
		case ARMV7_INTRIN_VREV64:
			return "__vrev64";
		case ARMV7_INTRIN_VEXT:
			return "__vext";
		case ARMV7_INTRIN_VCGT:
			return "__vcgt";
		case ARMV7_INTRIN_VCEQ:
			return "__vceq";
		case ARMV7_INTRIN_VTBL:
			return "__vtbl";
		case ARMV7_INTRIN_VTBX:
			return "__vtbx";
		case ARMV7_INTRIN_VDUP:
			return "__vdup";
		case ARMV7_INTRIN_VABD:
			return "__vabd";
		case ARMV7_INTRIN_VABDL:
			return "__vabdl";
		case ARMV7_INTRIN_VABA:
			return "__vaba";
		case ARMV7_INTRIN_VABAL:
			return "__vabal";
		case ARMV7_INTRIN_VADD:
			return "__vadd";
		case ARMV7_INTRIN_VSUB:
			return "__vsub";
		case ARMV7_INTRIN_VADDL:
			return "__vaddl";
		case ARMV7_INTRIN_VADDW:
			return "__vaddw";
		case ARMV7_INTRIN_VRADDHN:
			return "__vraddhn";
		case ARMV7_INTRIN_VRSHR:
			return "__vrshr";
		case ARMV7_INTRIN_VRSHL:
			return "__vrshl";
		case ARMV7_INTRIN_VSRA:
			return "__vsra";
		case ARMV7_INTRIN_VRSRA:
			return "__vrsra";
		case ARMV7_INTRIN_VSRI:
			return "__vsri";
		case ARMV7_INTRIN_VSLI:
			return "__vsli";
		case ARMV7_INTRIN_VLD2:
			return "__vld2";
		case ARMV7_INTRIN_VLD4:
			return "__vld4";
		case ARMV7_INTRIN_VST2:
			return "__vst2";
		case ARMV7_INTRIN_VST4:
			return "__vst4";
		case ARMV7_INTRIN_VSHL:
			return "__vshl";
		case ARMV7_INTRIN_VSHR:
			return "__vshr";
		case ARMV7_INTRIN_VSHLL:
			return "__vshll";
		case ARMV7_INTRIN_VBIF:
			return "__vbif";
		case ARMV7_INTRIN_VBIT:
			return "__vbit";
		case ARMV7_INTRIN_VBSL:
			return "__vbsl";
		case ARMV7_INTRIN_VQADD:
			return "__vqadd";
		case ARMV7_INTRIN_VHADD:
			return "__vhadd";
		case ARMV7_INTRIN_VQSHL:
			return "__vqshl";
		case ARMV7_INTRIN_VQRSHL:
			return "__vqrshl";
		case ARMV7_INTRIN_VQSHRN:
			return "__vqshrn";
		case ARMV7_INTRIN_VQSHRUN:
			return "__vqshrun";
		case ARMV7_INTRIN_VQRSHRN:
			return "__vqrshrn";
		case ARMV7_INTRIN_VQRSHRUN:
			return "__vqrshrun";
		case ARMV7_INTRIN_VQMOVN:
			return "__vqmovn";
		case ARMV7_INTRIN_VQMOVUN:
			return "__vqmovun";
		case ARMV7_INTRIN_VMLA:
			return "__vmla";
		case ARMV7_INTRIN_VMLS:
			return "__vmls";
		case ARMV7_INTRIN_VMLAL:
			return "__vmlal";
		case ARMV7_INTRIN_VMLSL:
			return "__vmlsl";
		case ARMV7_INTRIN_VMUL:
			return "__vmul";
		case ARMV7_INTRIN_VQDMULL:
			return "__vqdmull";
		case ARMV7_INTRIN_SSAT:
			return "__ssat";
		case ARMV7_INTRIN_SSAT16:
			return "__ssat16";
		case ARMV7_INTRIN_USAT:
			return "__usat";
		case ARMV7_INTRIN_USAT16:
			return "__usat16";
		case ARMV7_INTRIN_SRS:
			return "__srs";
		case ARMV7_INTRIN_RFE:
			return "__rfe";
		case ARMV7_INTRIN_QADD:
			return "__qadd";
		case ARMV7_INTRIN_QSUB:
			return "__qsub";
		case ARMV7_INTRIN_QDADD:
			return "__qdadd";
		case ARMV7_INTRIN_QDSUB:
			return "__qdsub";
		case ARMV7_INTRIN_QADD16:
			return "__qadd16";
		case ARMV7_INTRIN_QADD8:
			return "__qadd8";
		case ARMV7_INTRIN_QSUB16:
			return "__qsub16";
		case ARMV7_INTRIN_QSUB8:
			return "__qsub8";
		case ARMV7_INTRIN_UQADD16:
			return "__uqadd16";
		case ARMV7_INTRIN_UQADD8:
			return "__uqadd8";
		case ARMV7_INTRIN_UQSUB16:
			return "__uqsub16";
		case ARMV7_INTRIN_UQSUB8:
			return "__uqsub8";
		case ARMV7_INTRIN_SXTAB16:
			return "__sxtab16";
		case ARMV7_INTRIN_SXTB16:
			return "__sxtb16";
		case ARMV7_INTRIN_UXTAB16:
			return "__uxtab16";
		case ARMV7_INTRIN_UXTB16:
			return "__uxtb16";
		case ARMV7_INTRIN_SADD16:
			return "__sadd16";
		case ARMV7_INTRIN_SADD8:
			return "__sadd8";
		case ARMV7_INTRIN_UADD16:
			return "__uadd16";
		case ARMV7_INTRIN_UADD8:
			return "__uadd8";
		case ARMV7_INTRIN_SHADD16:
			return "__shadd16";
		case ARMV7_INTRIN_SHADD8:
			return "__shadd8";
		case ARMV7_INTRIN_UHADD16:
			return "__uhadd16";
		case ARMV7_INTRIN_UHADD8:
			return "__uhadd8";
		case ARMV7_INTRIN_SASX:
			return "__sasx";
		case ARMV7_INTRIN_UASX:
			return "__uasx";
		case ARMV7_INTRIN_SHASX:
			return "__shasx";
		case ARMV7_INTRIN_UHASX:
			return "__uhasx";
		case ARMV7_INTRIN_SSAX:
			return "__ssax";
		case ARMV7_INTRIN_USAX:
			return "__usax";
		case ARMV7_INTRIN_SSUB16:
			return "__ssub16";
		case ARMV7_INTRIN_SSUB8:
			return "__ssub8";
		case ARMV7_INTRIN_SHSUB8:
			return "__shsub8";
		case ARMV7_INTRIN_SHSUB16:
			return "__shsub16";
		case ARMV7_INTRIN_UHSUB8:
			return "__uhsub8";
		case ARMV7_INTRIN_UHSUB16:
			return "__uhsub16";
		case ARMV7_INTRIN_USUB8:
			return "__usub8";
		case ARMV7_INTRIN_USUB16:
			return "__usub16";
		case ARMV7_INTRIN_SMLAD:
			return "__smlad";
		case ARMV7_INTRIN_SMLADX:
			return "__smladx";
		case ARMV7_INTRIN_SMUAD:
			return "__smuad";
		case ARMV7_INTRIN_SMUADX:
			return "__smuadx";
		case ARMV7_INTRIN_SMUSD:
			return "__smusd";
		case ARMV7_INTRIN_SMUSDX:
			return "__smusdx";
		case ARMV7_INTRIN_SMLSD:
			return "__smlsd";
		case ARMV7_INTRIN_SMLSDX:
			return "__smlsdx";
		case ARMV7_INTRIN_SMLSLD:
			return "__smlsld";
		case ARMV7_INTRIN_SMLSLDX:
			return "__smlsldx";
		case ARMV7_INTRIN_SMLAWB:
			return "__smlawb";
		case ARMV7_INTRIN_SMLAWT:
			return "__smlawt";
		case ARMV7_INTRIN_SMLABB:
			return "__smlabb";
		case ARMV7_INTRIN_SMLABT:
			return "__smlabt";
		case ARMV7_INTRIN_SMLATB:
			return "__smlatb";
		case ARMV7_INTRIN_SMLATT:
			return "__smlatt";
		case ARMV7_INTRIN_SMLALD:
			return "__smlald";
		case ARMV7_INTRIN_SMLALDX:
			return "__smlaldx";
		case ARMV7_INTRIN_USAD8:
			return "__usad8";
		case ARMV7_INTRIN_USADA8:
			return "__usada8";
		case ARMV7_INTRIN_QSAX:
			return "__qsax";
		case ARMV7_INTRIN_UQASX:
			return "__uqasx";
		case ARMV7_INTRIN_UQSAX:
			return "__uqsax";
		case ARMV7_INTRIN_DBG:
			return "__dbg";
		case ARMV7_INTRIN_DMB_SY:
			return "__dmb_SY";
		case ARMV7_INTRIN_DMB_ST:
			return "__dmb_ST";
		case ARMV7_INTRIN_DMB_ISH:
			return "__dmb_ISH";
		case ARMV7_INTRIN_DMB_ISHST:
			return "__dmb_ISHST";
		case ARMV7_INTRIN_DMB_NSH:
			return "__dmb_NSH";
		case ARMV7_INTRIN_DMB_NSHST:
			return "__dmb_NSHST";
		case ARMV7_INTRIN_DMB_OSH:
			return "__dmb_OSH";
		case ARMV7_INTRIN_DMB_OSHST:
			return "__dmb_OSHST";
		case ARMV7_INTRIN_DSB_SY:
			return "__dsb_SY";
		case ARMV7_INTRIN_DSB_ST:
			return "__dsb_ST";
		case ARMV7_INTRIN_DSB_ISH:
			return "__dsb_ISH";
		case ARMV7_INTRIN_DSB_ISHST:
			return "__dsb_ISHST";
		case ARMV7_INTRIN_DSB_NSH:
			return "__dsb_NSH";
		case ARMV7_INTRIN_DSB_NSHST:
			return "__dsb_NSHST";
		case ARMV7_INTRIN_DSB_OSH:
			return "__dsb_OSH";
		case ARMV7_INTRIN_DSB_OSHST:
			return "__dsb_OSHST";
		case ARMV7_INTRIN_ISB:
			return "__isb";
		case ARMV7_INTRIN_MRS:
			return "__mrs";
		case ARMV7_INTRIN_MSR:
			return "__msr";
		case ARMV7_INTRIN_VMRS:
			return "__vmrs";
		case ARMV7_INTRIN_VMSR:
			return "__vmsr";
		case ARMV7_INTRIN_YIELD:
			return "__yield";
		case ARMV7_INTRIN_SEV:
			return "__sev";
		case ARMV7_INTRIN_WFE:
			return "__wfe";
		case ARMV7_INTRIN_WFI:
			return "__wfi";
		case ARMV7_INTRIN_HINT:
			return "__hint";
		case ARMV7_INTRIN_UNPREDICTABLE:
			return "__unpredictable";
		case ARMV7_INTRIN_HVC:
			return "__hvc";
		case ARMV7_INTRIN_SMC:
			return "__smc";
		case ARM_M_INTRIN_SET_BASEPRI:
			return "__set_BASEPRI";
		case ARMV7_INTRIN_CPS:
			return "__cps";
		case ARMV7_INTRIN_CPSID:
			return "__cpsid";
		case ARMV7_INTRIN_CPSIE:
			return "__cpsie";
		case ARMV7_INTRIN_SETEND:
			return "__setend";
		case ARMV7_INTRIN_CLREX:
			return "__clrex";
		case ARMV7_INTRIN_PLD:
			return "__pld";
		case ARMV7_INTRIN_CRC32B:
			return "__crc32b";
		case ARMV7_INTRIN_CRC32CB:
			return "__crc32cb";
		case ARMV7_INTRIN_CRC32CH:
			return "__crc32ch";
		case ARMV7_INTRIN_CRC32CW:
			return "__crc32cw";
		case ARMV7_INTRIN_CRC32H:
			return "__crc32h";
		case ARMV7_INTRIN_CRC32W:
			return "__crc32w";
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
			ARMV7_INTRIN_COPROC_STORE,
			ARMV7_INTRIN_COPROC_LOAD,
			ARMV7_INTRIN_COPROC_DATAPROCESSING,
			ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS,
			ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS,
			ARMV7_INTRIN_SETEND,
			ARMV7_INTRIN_SEL,
			ARMV7_INTRIN_VRINTA,
			ARMV7_INTRIN_VMAXNM,
			ARMV7_INTRIN_VMINNM,
			ARMV7_INTRIN_VMAX,
			ARMV7_INTRIN_VMIN,
			ARMV7_INTRIN_VPMAX,
			ARMV7_INTRIN_VPMIN,
			ARMV7_INTRIN_VREV16,
			ARMV7_INTRIN_VREV32,
			ARMV7_INTRIN_VREV64,
			ARMV7_INTRIN_VEXT,
			ARMV7_INTRIN_VCGT,
			ARMV7_INTRIN_VCEQ,
			ARMV7_INTRIN_VTBL,
			ARMV7_INTRIN_VTBX,
			ARMV7_INTRIN_VDUP,
			ARMV7_INTRIN_VABD,
			ARMV7_INTRIN_VABDL,
			ARMV7_INTRIN_VABA,
			ARMV7_INTRIN_VABAL,
			ARMV7_INTRIN_VADDL,
			ARMV7_INTRIN_VADDW,
			ARMV7_INTRIN_VRADDHN,
			ARMV7_INTRIN_VRSHR,
			ARMV7_INTRIN_VRSHL,
			ARMV7_INTRIN_VSRA,
			ARMV7_INTRIN_VRSRA,
			ARMV7_INTRIN_VSRI,
			ARMV7_INTRIN_VSLI,
			ARMV7_INTRIN_VLD2,
			ARMV7_INTRIN_VLD4,
			ARMV7_INTRIN_VST2,
			ARMV7_INTRIN_VST4,
			ARMV7_INTRIN_VSHL,
			ARMV7_INTRIN_VSHR,
			ARMV7_INTRIN_VSHLL,
			ARMV7_INTRIN_VBIF,
			ARMV7_INTRIN_VBIT,
			ARMV7_INTRIN_VBSL,
			ARMV7_INTRIN_VQADD,
			ARMV7_INTRIN_VHADD,
			ARMV7_INTRIN_VQSHL,
			ARMV7_INTRIN_VQRSHL,
			ARMV7_INTRIN_VQSHRN,
			ARMV7_INTRIN_VQSHRUN,
			ARMV7_INTRIN_VQRSHRN,
			ARMV7_INTRIN_VQRSHRUN,
			ARMV7_INTRIN_VQMOVN,
			ARMV7_INTRIN_VQMOVUN,
			ARMV7_INTRIN_VMLA,
			ARMV7_INTRIN_VMLS,
			ARMV7_INTRIN_VMLAL,
			ARMV7_INTRIN_VMLSL,
			ARMV7_INTRIN_VMUL,
			ARMV7_INTRIN_VQDMULL,
			ARMV7_INTRIN_SSAT,
			ARMV7_INTRIN_SSAT16,
			ARMV7_INTRIN_USAT,
			ARMV7_INTRIN_USAT16,
			ARMV7_INTRIN_SRS,
			ARMV7_INTRIN_RFE,
			ARMV7_INTRIN_QADD,
			ARMV7_INTRIN_QSUB,
			ARMV7_INTRIN_QDADD,
			ARMV7_INTRIN_QDSUB,
			ARMV7_INTRIN_QADD16,
			ARMV7_INTRIN_QADD8,
			ARMV7_INTRIN_QSUB16,
			ARMV7_INTRIN_QSUB8,
			ARMV7_INTRIN_UQADD16,
			ARMV7_INTRIN_UQADD8,
			ARMV7_INTRIN_UQSUB16,
			ARMV7_INTRIN_UQSUB8,
			ARMV7_INTRIN_SXTAB16,
			ARMV7_INTRIN_SXTB16,
			ARMV7_INTRIN_UXTAB16,
			ARMV7_INTRIN_UXTB16,
			ARMV7_INTRIN_SADD16,
			ARMV7_INTRIN_SADD8,
			ARMV7_INTRIN_SHADD16,
			ARMV7_INTRIN_SHADD8,
			ARMV7_INTRIN_UHADD16,
			ARMV7_INTRIN_UHADD8,
			ARMV7_INTRIN_SASX,
			ARMV7_INTRIN_UASX,
			ARMV7_INTRIN_SHASX,
			ARMV7_INTRIN_UHASX,
			ARMV7_INTRIN_SSAX,
			ARMV7_INTRIN_USAX,
			ARMV7_INTRIN_SSUB16,
			ARMV7_INTRIN_SSUB8,
			ARMV7_INTRIN_SHSUB8,
			ARMV7_INTRIN_SHSUB16,
			ARMV7_INTRIN_UHSUB8,
			ARMV7_INTRIN_UHSUB16,
			ARMV7_INTRIN_USUB8,
			ARMV7_INTRIN_USUB16,
			ARMV7_INTRIN_SMLAD,
			ARMV7_INTRIN_SMLADX,
			ARMV7_INTRIN_SMUAD,
			ARMV7_INTRIN_SMUADX,
			ARMV7_INTRIN_SMUSD,
			ARMV7_INTRIN_SMUSDX,
			ARMV7_INTRIN_SMLSD,
			ARMV7_INTRIN_SMLSDX,
			ARMV7_INTRIN_SMLSLD,
			ARMV7_INTRIN_SMLSLDX,
			ARMV7_INTRIN_SMLAWB,
			ARMV7_INTRIN_SMLAWT,
			ARMV7_INTRIN_SMLABB,
			ARMV7_INTRIN_SMLABT,
			ARMV7_INTRIN_SMLATB,
			ARMV7_INTRIN_SMLATT,
			ARMV7_INTRIN_SMLALD,
			ARMV7_INTRIN_SMLALDX,
			ARMV7_INTRIN_USAD8,
			ARMV7_INTRIN_USADA8,
			ARMV7_INTRIN_QSAX,
			ARMV7_INTRIN_UQASX,
			ARMV7_INTRIN_UQSAX,
			ARMV7_INTRIN_DBG,
			ARMV7_INTRIN_CLREX,
			ARMV7_INTRIN_PLD,
			ARMV7_INTRIN_CRC32B,
			ARMV7_INTRIN_CRC32CB,
			ARMV7_INTRIN_CRC32CH,
			ARMV7_INTRIN_CRC32CW,
			ARMV7_INTRIN_CRC32H,
			ARMV7_INTRIN_CRC32W,
			ARMV7_INTRIN_DMB_SY,
			ARMV7_INTRIN_DMB_ST,
			ARMV7_INTRIN_DMB_ISH,
			ARMV7_INTRIN_DMB_ISHST,
			ARMV7_INTRIN_DMB_NSH,
			ARMV7_INTRIN_DMB_NSHST,
			ARMV7_INTRIN_DMB_OSH,
			ARMV7_INTRIN_DMB_OSHST,
			ARMV7_INTRIN_DSB_SY,
			ARMV7_INTRIN_DSB_ST,
			ARMV7_INTRIN_DSB_ISH,
			ARMV7_INTRIN_DSB_ISHST,
			ARMV7_INTRIN_DSB_NSH,
			ARMV7_INTRIN_DSB_NSHST,
			ARMV7_INTRIN_DSB_OSH,
			ARMV7_INTRIN_DSB_OSHST,
			ARMV7_INTRIN_ISB,
			ARMV7_INTRIN_MRS,
			ARMV7_INTRIN_MSR,
			ARMV7_INTRIN_VMRS,
			ARMV7_INTRIN_VMSR,
			ARMV7_INTRIN_YIELD,
			ARMV7_INTRIN_SEV,
			ARMV7_INTRIN_WFE,
			ARMV7_INTRIN_WFI,
			ARMV7_INTRIN_HINT,
			ARMV7_INTRIN_UNPREDICTABLE,
			ARMV7_INTRIN_HVC,
			ARMV7_INTRIN_SMC,
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
		case ARMV7_INTRIN_COPROC_STORE:
		case ARMV7_INTRIN_COPROC_LOAD:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType("d", Type::IntegerType(1, false)),
				NameAndType("long_transfer", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_COPROC_DATAPROCESSING:
			return {
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType("opc1", Type::IntegerType(1, false)),
				NameAndType("d", Type::IntegerType(1, false)),
				NameAndType("n", Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
				NameAndType("opc2", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_EXCLUSIVE_MONITORS_PASS:
		case ARMV7_INTRIN_SET_EXCLUSIVE_MONITORS:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
				NameAndType("size", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_SMC:
			return {
				NameAndType("imm", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_HVC:
			return {
				NameAndType("imm", Type::IntegerType(2, false)),
			};
		case ARMV7_INTRIN_SEL:
			return {
				NameAndType("rn", Type::IntegerType(4, false)),
				NameAndType("rm", Type::IntegerType(4, false)),
				NameAndType("ge", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_QADD:
		case ARMV7_INTRIN_QSUB:
		case ARMV7_INTRIN_QDADD:
		case ARMV7_INTRIN_QDSUB:
		case ARMV7_INTRIN_QADD16:
		case ARMV7_INTRIN_QADD8:
		case ARMV7_INTRIN_QSUB16:
		case ARMV7_INTRIN_QSUB8:
		case ARMV7_INTRIN_UQADD16:
		case ARMV7_INTRIN_UQADD8:
		case ARMV7_INTRIN_UQSUB16:
		case ARMV7_INTRIN_UQSUB8:
		case ARMV7_INTRIN_QSAX:
		case ARMV7_INTRIN_UQASX:
		case ARMV7_INTRIN_UQSAX:
		case ARMV7_INTRIN_SXTAB16:
		case ARMV7_INTRIN_UXTAB16:
		case ARMV7_INTRIN_SADD16:
		case ARMV7_INTRIN_SADD8:
		case ARMV7_INTRIN_UADD16:
		case ARMV7_INTRIN_UADD8:
		case ARMV7_INTRIN_SHADD16:
		case ARMV7_INTRIN_SHADD8:
		case ARMV7_INTRIN_UHADD16:
		case ARMV7_INTRIN_UHADD8:
		case ARMV7_INTRIN_SASX:
		case ARMV7_INTRIN_UASX:
		case ARMV7_INTRIN_SHASX:
		case ARMV7_INTRIN_UHASX:
		case ARMV7_INTRIN_SSAX:
		case ARMV7_INTRIN_USAX:
		case ARMV7_INTRIN_SSUB16:
		case ARMV7_INTRIN_SSUB8:
		case ARMV7_INTRIN_SHSUB8:
		case ARMV7_INTRIN_SHSUB16:
		case ARMV7_INTRIN_UHSUB8:
		case ARMV7_INTRIN_UHSUB16:
		case ARMV7_INTRIN_USUB8:
		case ARMV7_INTRIN_USUB16:
		case ARMV7_INTRIN_USAD8:
		case ARMV7_INTRIN_SMUAD:
		case ARMV7_INTRIN_SMUADX:
		case ARMV7_INTRIN_SMUSD:
		case ARMV7_INTRIN_SMUSDX:
			return {
				NameAndType("source1", Type::IntegerType(4, false)),
				NameAndType("source2", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_SMLAD:
		case ARMV7_INTRIN_SMLADX:
		case ARMV7_INTRIN_SMLSD:
		case ARMV7_INTRIN_SMLSDX:
		case ARMV7_INTRIN_SMLAWB:
		case ARMV7_INTRIN_SMLAWT:
		case ARMV7_INTRIN_SMLABB:
		case ARMV7_INTRIN_SMLABT:
		case ARMV7_INTRIN_SMLATB:
		case ARMV7_INTRIN_SMLATT:
			return {
				NameAndType("source1", Type::IntegerType(4, false)),
				NameAndType("source2", Type::IntegerType(4, false)),
				NameAndType("accumulator", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_SMLSLD:
		case ARMV7_INTRIN_SMLSLDX:
		case ARMV7_INTRIN_SMLALD:
		case ARMV7_INTRIN_SMLALDX:
			return {
				NameAndType("source1", Type::IntegerType(4, false)),
				NameAndType("source2", Type::IntegerType(4, false)),
				NameAndType("accumulator", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_SXTB16:
		case ARMV7_INTRIN_UXTB16:
			return {
				NameAndType("source", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_USADA8:
			return {
				NameAndType("source1", Type::IntegerType(4, false)),
				NameAndType("source2", Type::IntegerType(4, false)),
				NameAndType("accumulator", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_VRINTA:
			return {
				NameAndType("source_register", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_VMAXNM:
		case ARMV7_INTRIN_VMINNM:
			return {
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VMAX:
		case ARMV7_INTRIN_VMIN:
		case ARMV7_INTRIN_VPMAX:
		case ARMV7_INTRIN_VPMIN:
		case ARMV7_INTRIN_VCGT:
		case ARMV7_INTRIN_VHADD:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VCEQ:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_float", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VREV16:
		case ARMV7_INTRIN_VREV32:
		case ARMV7_INTRIN_VREV64:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VEXT:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
				NameAndType("index", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_SSAT:
		case ARMV7_INTRIN_SSAT16:
		case ARMV7_INTRIN_USAT16:
		case ARMV7_INTRIN_USAT:
			return {
				NameAndType("saturate_to", Type::IntegerType(4, false)),
				NameAndType("source", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_VTBL:
			return {
				NameAndType("length", Type::IntegerType(1, false)),
				NameAndType("table0", Type::IntegerType(8, false)),
				NameAndType("table1", Type::IntegerType(8, false)),
				NameAndType("table2", Type::IntegerType(8, false)),
				NameAndType("table3", Type::IntegerType(8, false)),
				NameAndType("indices", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VTBX:
			return {
				NameAndType("length", Type::IntegerType(1, false)),
				NameAndType("table0", Type::IntegerType(8, false)),
				NameAndType("table1", Type::IntegerType(8, false)),
				NameAndType("table2", Type::IntegerType(8, false)),
				NameAndType("table3", Type::IntegerType(8, false)),
				NameAndType("indices", Type::IntegerType(8, false)),
				NameAndType("destination", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VDUP:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("index", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_VABD:
		case ARMV7_INTRIN_VABDL:
		case ARMV7_INTRIN_VADD:
		case ARMV7_INTRIN_VSUB:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VABA:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("accumulator", Type::IntegerType(16, false)),
				NameAndType("source1", Type::IntegerType(16, false)),
				NameAndType("source2", Type::IntegerType(16, false)),
			};
		case ARMV7_INTRIN_VABAL:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("accumulator", Type::IntegerType(16, false)),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VADDL:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VADDW:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(16, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VRADDHN:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source1", Type::IntegerType(16, false)),
				NameAndType("source2", Type::IntegerType(16, false)),
			};
		case ARMV7_INTRIN_VRSHR:
		case ARMV7_INTRIN_VRSHL:
		case ARMV7_INTRIN_VSHL:
		case ARMV7_INTRIN_VSHR:
		case ARMV7_INTRIN_VSHLL:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("shift", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VBIF:
		case ARMV7_INTRIN_VBIT:
		case ARMV7_INTRIN_VBSL:
			return {
				NameAndType("destination", Type::IntegerType(8, false)),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VSRA:
		case ARMV7_INTRIN_VRSRA:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("accumulator", Type::IntegerType(8, false)),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("shift", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VSRI:
		case ARMV7_INTRIN_VSLI:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("destination", Type::IntegerType(8, false)),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("shift", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VLD2:
		case ARMV7_INTRIN_VLD4:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("alignment", Type::IntegerType(1, false)),
				NameAndType("index", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_VST2:
		case ARMV7_INTRIN_VST4:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("alignment", Type::IntegerType(1, false)),
				NameAndType("index", Type::IntegerType(1, false)),
				NameAndType("source0", Type::IntegerType(8, false)),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
				NameAndType("source3", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VQADD:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_VQSHL:
		case ARMV7_INTRIN_VQRSHL:
		case ARMV7_INTRIN_VQSHRN:
		case ARMV7_INTRIN_VQSHRUN:
		case ARMV7_INTRIN_VQRSHRN:
		case ARMV7_INTRIN_VQRSHRUN:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source_unsigned", Type::BoolType()),
				NameAndType("destination_unsigned", Type::BoolType()),
				NameAndType("source", Type::IntegerType(
					(intrinsic == ARMV7_INTRIN_VQSHL || intrinsic == ARMV7_INTRIN_VQRSHL) ? 8 : 16, false)),
				NameAndType("shift", Type::IntegerType(
					(intrinsic == ARMV7_INTRIN_VQSHL || intrinsic == ARMV7_INTRIN_VQRSHL) ? 8 : 16, false)),
			};
		case ARMV7_INTRIN_VQMOVN:
		case ARMV7_INTRIN_VQMOVUN:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("source_unsigned", Type::BoolType()),
				NameAndType("destination_unsigned", Type::BoolType()),
				NameAndType("source", Type::IntegerType(16, false)),
			};
		case ARMV7_INTRIN_VMLA:
		case ARMV7_INTRIN_VMLS:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("accumulator", Type::IntegerType(8, false)),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("scalar", Type::IntegerType(8, false)),
				NameAndType("index", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_VMLAL:
		case ARMV7_INTRIN_VMLSL:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("accumulator", Type::IntegerType(16, false)),
				NameAndType("source", Type::IntegerType(8, false)),
				NameAndType("scalar", Type::IntegerType(8, false)),
				NameAndType("index", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_VMUL:
		case ARMV7_INTRIN_VQDMULL:
			return {
				NameAndType("size", Type::IntegerType(1, false)),
				NameAndType("is_unsigned", Type::BoolType()),
				NameAndType("source1", Type::IntegerType(8, false)),
				NameAndType("source2", Type::IntegerType(8, false)),
			};
		case ARMV7_INTRIN_SRS:
			return {
				NameAndType("mode", Type::IntegerType(1, false)),
				NameAndType("increment", Type::BoolType()),
				NameAndType("wordhigher", Type::BoolType()),
				NameAndType("writeback", Type::BoolType()),
			};
		case ARMV7_INTRIN_RFE:
			return {
				NameAndType("base_register", Type::IntegerType(4, false)),
				NameAndType("increment", Type::BoolType()),
				NameAndType("wordhigher", Type::BoolType()),
				NameAndType("writeback", Type::BoolType()),
			};
		case ARMV7_INTRIN_CPS:
			return {
				NameAndType("mode", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_SETEND:
			return {
				NameAndType("endian", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_CPSID:
		case ARMV7_INTRIN_CPSIE:
			return {
				NameAndType("iflags", Type::IntegerType(1, false)),
				NameAndType("mode", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_MRS:
			// return {NameAndType(Type::IntegerType(4, false))};
			return {
				NameAndType("msr", Confidence<Ref<Type>>(Type::EnumerationType(this, get_msr_op_enum(), 4, false), BN_FULL_CONFIDENCE))
			};
		case ARMV7_INTRIN_MSR:
			// return {NameAndType(Type::IntegerType(4, false))};
			return {
				NameAndType("msr", Confidence<Ref<Type>>(Type::EnumerationType(this, get_msr_op_enum(), 4, false), BN_FULL_CONFIDENCE)),
				NameAndType(Type::IntegerType(4, false))
			};
		case ARMV7_INTRIN_VMRS:
			return {
				NameAndType("status_register", Confidence<Ref<Type>>(Type::EnumerationType(this, GetVfpStatusRegisterEnum(), 4, false), BN_FULL_CONFIDENCE)),
			};
		case ARMV7_INTRIN_VMSR:
			return {
				NameAndType("status_register", Confidence<Ref<Type>>(Type::EnumerationType(this, GetVfpStatusRegisterEnum(), 4, false), BN_FULL_CONFIDENCE)),
				NameAndType("source_register", Type::IntegerType(4, false)),
			};
		case ARMV7_INTRIN_DBG:
			return {NameAndType(Type::IntegerType(1, false))};
		case ARMV7_INTRIN_HINT:
			return {NameAndType("imm", Type::IntegerType(1, false))};
		case ARMV7_INTRIN_PLD:
			return {
				NameAndType("address", Type::PointerType(4, Confidence(Type::VoidType(), 0), Confidence(false), Confidence(false), PointerReferenceType)),
			};
		case ARMV7_INTRIN_CRC32B:
		case ARMV7_INTRIN_CRC32CB:
			return {
				NameAndType("accumulator", Type::IntegerType(4, false)),
				NameAndType("value", Type::IntegerType(1, false)),
			};
		case ARMV7_INTRIN_CRC32H:
		case ARMV7_INTRIN_CRC32CH:
			return {
				NameAndType("accumulator", Type::IntegerType(4, false)),
				NameAndType("value", Type::IntegerType(2, false)),
			};
		case ARMV7_INTRIN_CRC32W:
		case ARMV7_INTRIN_CRC32CW:
			return {
				NameAndType("accumulator", Type::IntegerType(4, false)),
				NameAndType("value", Type::IntegerType(4, false)),
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
		case ARMV7_INTRIN_SADD16:
		case ARMV7_INTRIN_SADD8:
		case ARMV7_INTRIN_UADD16:
		case ARMV7_INTRIN_UADD8:
		case ARMV7_INTRIN_SASX:
		case ARMV7_INTRIN_UASX:
		case ARMV7_INTRIN_SSAX:
		case ARMV7_INTRIN_USAX:
		case ARMV7_INTRIN_SSUB16:
		case ARMV7_INTRIN_SSUB8:
		case ARMV7_INTRIN_USUB8:
		case ARMV7_INTRIN_USUB16:
			return { Type::IntegerType(4, false), Type::IntegerType(4, false) };
		case ARMV7_INTRIN_MRS:
		case ARMV7_INTRIN_VMRS:
		case ARMV7_INTRIN_SEL:
		case ARMV7_INTRIN_QADD:
		case ARMV7_INTRIN_QSUB:
		case ARMV7_INTRIN_QDADD:
		case ARMV7_INTRIN_QDSUB:
		case ARMV7_INTRIN_QADD16:
		case ARMV7_INTRIN_QADD8:
		case ARMV7_INTRIN_QSUB16:
		case ARMV7_INTRIN_QSUB8:
		case ARMV7_INTRIN_UQADD16:
		case ARMV7_INTRIN_UQADD8:
		case ARMV7_INTRIN_UQSUB16:
		case ARMV7_INTRIN_UQSUB8:
		case ARMV7_INTRIN_QSAX:
		case ARMV7_INTRIN_UQASX:
		case ARMV7_INTRIN_SXTAB16:
		case ARMV7_INTRIN_SXTB16:
		case ARMV7_INTRIN_UXTAB16:
		case ARMV7_INTRIN_UXTB16:
		case ARMV7_INTRIN_SHADD16:
		case ARMV7_INTRIN_SHADD8:
		case ARMV7_INTRIN_UHADD16:
		case ARMV7_INTRIN_UHADD8:
		case ARMV7_INTRIN_SHASX:
		case ARMV7_INTRIN_UHASX:
		case ARMV7_INTRIN_SHSUB8:
		case ARMV7_INTRIN_SHSUB16:
		case ARMV7_INTRIN_UHSUB8:
		case ARMV7_INTRIN_UHSUB16:
		case ARMV7_INTRIN_USAD8:
		case ARMV7_INTRIN_USADA8:
		case ARMV7_INTRIN_SMLAD:
		case ARMV7_INTRIN_SMLADX:
		case ARMV7_INTRIN_SMUAD:
		case ARMV7_INTRIN_SMUADX:
		case ARMV7_INTRIN_SMUSD:
		case ARMV7_INTRIN_SMUSDX:
		case ARMV7_INTRIN_SMLSD:
		case ARMV7_INTRIN_SMLSDX:
		case ARMV7_INTRIN_SMLAWB:
		case ARMV7_INTRIN_SMLAWT:
		case ARMV7_INTRIN_SMLABB:
		case ARMV7_INTRIN_SMLABT:
		case ARMV7_INTRIN_SMLATB:
		case ARMV7_INTRIN_SMLATT:
		case ARMV7_INTRIN_UQSAX:
		case ARMV7_INTRIN_VRINTA:
		case ARMV7_INTRIN_VMAXNM:
		case ARMV7_INTRIN_VMINNM:
		case ARMV7_INTRIN_SSAT:
		case ARMV7_INTRIN_SSAT16:
		case ARMV7_INTRIN_USAT:
		case ARMV7_INTRIN_USAT16:
		case ARMV7_INTRIN_CRC32B:
		case ARMV7_INTRIN_CRC32CB:
		case ARMV7_INTRIN_CRC32CH:
		case ARMV7_INTRIN_CRC32CW:
		case ARMV7_INTRIN_CRC32H:
		case ARMV7_INTRIN_CRC32W:
			return {Type::IntegerType(4, false)};
		case ARMV7_INTRIN_SMLSLD:
		case ARMV7_INTRIN_SMLSLDX:
		case ARMV7_INTRIN_SMLALD:
		case ARMV7_INTRIN_SMLALDX:
			return {Type::IntegerType(4, false), Type::IntegerType(4, false)};
		case ARMV7_INTRIN_VLD2:
			return {Type::IntegerType(8, false), Type::IntegerType(8, false)};
		case ARMV7_INTRIN_VLD4:
			return {Type::IntegerType(8, false), Type::IntegerType(8, false), Type::IntegerType(8, false), Type::IntegerType(8, false)};
		case ARMV7_INTRIN_VTBL:
		case ARMV7_INTRIN_VTBX:
		case ARMV7_INTRIN_VDUP:
		case ARMV7_INTRIN_VABD:
		case ARMV7_INTRIN_VABA:
		case ARMV7_INTRIN_VRSHR:
		case ARMV7_INTRIN_VRSHL:
		case ARMV7_INTRIN_VSRA:
		case ARMV7_INTRIN_VRSRA:
		case ARMV7_INTRIN_VSRI:
		case ARMV7_INTRIN_VSLI:
		case ARMV7_INTRIN_VRADDHN:
		case ARMV7_INTRIN_VSHL:
		case ARMV7_INTRIN_VSHR:
		case ARMV7_INTRIN_VMAX:
		case ARMV7_INTRIN_VMIN:
		case ARMV7_INTRIN_VPMAX:
		case ARMV7_INTRIN_VPMIN:
		case ARMV7_INTRIN_VREV16:
		case ARMV7_INTRIN_VREV32:
		case ARMV7_INTRIN_VREV64:
		case ARMV7_INTRIN_VEXT:
		case ARMV7_INTRIN_VCGT:
		case ARMV7_INTRIN_VCEQ:
		case ARMV7_INTRIN_VADD:
		case ARMV7_INTRIN_VSUB:
		case ARMV7_INTRIN_VQADD:
		case ARMV7_INTRIN_VHADD:
		case ARMV7_INTRIN_VQSHL:
		case ARMV7_INTRIN_VQRSHL:
		case ARMV7_INTRIN_VQSHRN:
		case ARMV7_INTRIN_VQSHRUN:
		case ARMV7_INTRIN_VQRSHRN:
		case ARMV7_INTRIN_VQRSHRUN:
		case ARMV7_INTRIN_VQMOVN:
		case ARMV7_INTRIN_VQMOVUN:
		case ARMV7_INTRIN_VMLA:
		case ARMV7_INTRIN_VMLS:
		case ARMV7_INTRIN_VMUL:
		case ARMV7_INTRIN_VBIF:
		case ARMV7_INTRIN_VBIT:
		case ARMV7_INTRIN_VBSL:
			return {Type::IntegerType(8, false)};
		case ARMV7_INTRIN_VABAL:
		case ARMV7_INTRIN_VABDL:
		case ARMV7_INTRIN_VADDL:
		case ARMV7_INTRIN_VADDW:
		case ARMV7_INTRIN_VSHLL:
		case ARMV7_INTRIN_VMLAL:
		case ARMV7_INTRIN_VMLSL:
		case ARMV7_INTRIN_VQDMULL:
			return {Type::IntegerType(16, false)};
		case ARMV7_INTRIN_MSR:
			// return {Type::IntegerType(4, false)};
			return {};
		default:
			return vector<Confidence<Ref<Type>>>();
		}
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		decomp_request request;
		decomp_result decomp;

		if (!populateDecomposeRequest(&request, data, len, addr, IFTHEN_NO, IFTHENLAST_NO))
			return false;

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;
		if ((decomp.instrSize / 8) > len)
			return false;
		if ((decomp.status & STATUS_UNDEFINED) || (!decomp.format))
			return false;

		if ((decomp.mnem == armv7::ARMV7_IT) && (decomp.fields[FIELD_mask] != 0))
		{
			// If then block, emit IL for the instructions within the block
			uint32_t offset = decomp.instrSize / 8;
			uint32_t mask = decomp.fields[FIELD_mask];
			uint32_t cond = decomp.fields[FIELD_firstcond];

			// Calculate number of instructions
			size_t instrCount;
			if (decomp.fields[FIELD_mask] & 1)
				instrCount = 4;
			else if (decomp.fields[FIELD_mask] & 2)
				instrCount = 3;
			else if (decomp.fields[FIELD_mask] & 4)
				instrCount = 2;
			else
				instrCount = 1;

			// decompose all instructions in the if-then block
			vector<uint32_t> addrsTrue, addrsFalse;
			vector<decomp_result> decompsTrue, decompsFalse;

			for (size_t i = 0; i < instrCount; i++)
			{
				if (offset >= len || (len - offset) < 2)
					return false;

				bool isTrue = (i == 0) || (((mask >> (4 - i)) & 1) == (cond & 1));
				size_t remainingLen = len - offset;

				if (!populateDecomposeRequest(&request, data+offset, remainingLen, addr+offset,
					IFTHEN_YES, ((i + 1) >= instrCount) ? IFTHENLAST_YES : IFTHENLAST_NO))
					return false;

				if (thumb_decompose(&request, &decomp) != STATUS_OK)
					return false;
				if ((decomp.instrSize / 8) > remainingLen)
					return false;
				if ((decomp.status & STATUS_UNDEFINED) || (!decomp.format))
					return false;

				if (isTrue) {
					addrsTrue.push_back(request.addr);
					decompsTrue.push_back(decomp);
				}
				else {
					addrsFalse.push_back(request.addr);
					decompsFalse.push_back(decomp);
				}

				offset += decomp.instrSize / 8;
			}

			// generate IL
			LowLevelILLabel labelTrue, labelFalse, labelDone;

			il.AddInstruction(il.If(GetCondition(il, cond), labelTrue, labelFalse));

			// generate IL for "true" if-else members
			il.MarkLabel(labelTrue);

			for (size_t i = 0; i < decompsTrue.size(); i++)
			{
				il.SetCurrentAddress(this, addrsTrue[i]);
				GetLowLevelILForThumbInstruction(this, il, &(decompsTrue[i]), true);
			}

			if (decompsFalse.empty()) {
				il.MarkLabel(labelFalse);
			}
			else {
				il.AddInstruction(il.Goto(labelDone));
				il.MarkLabel(labelFalse);

				// generate IL for "false" if-else members
				for (int i = 0; i < decompsFalse.size(); i++)
				{
					il.SetCurrentAddress(this, addrsFalse[i]);
					GetLowLevelILForThumbInstruction(this, il, &(decompsFalse[i]), true);
				}

				il.MarkLabel(labelDone);
			}

			len = offset;
			return true;
		}
		else
		{
			len = decomp.instrSize / 8;
			return GetLowLevelILForThumbInstruction(this, il, &decomp);
		}
	}

	/*************************************************************************/

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		decomp_result decomp;
		if (!Disassemble(data, addr, len, decomp))
			return false;

		return (decomp.mnem == ARMV7_B && CONDITIONAL(decomp.fields[FIELD_cond]));
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		decomp_result decomp;
		if (!Disassemble(data, addr, len, decomp))
			return false;

		return (decomp.mnem == ARMV7_B && CONDITIONAL(decomp.fields[FIELD_cond]));
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	/*************************************************************************/

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint16_t nop =  0x4600;
		if (len < sizeof(nop))
			return false;
		for (size_t i = 0; i < len/sizeof(nop); i++)
			((uint16_t*)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;

		if (len == sizeof(uint16_t)) {
			uint16_t *value = (uint16_t*)data;
			*value = (*value & 0x00ff) | (COND_NONE << 12);
			return true;
		} else if (len == sizeof(uint32_t)) {
			uint32_t *value = (uint32_t*)data;

			uint8_t j1_bit = (*value >> 29) & 1;
			uint8_t j2_bit = (*value >> 27) & 1;
			uint8_t s_bit = (*value >> 10) & 1;
			uint8_t w = (s_bit << 3) | (s_bit << 2) | (j2_bit << 1) | (j1_bit << 0);
			*value = (*value & 0b11111111111111111111110000111111) | ((w & 0x0f) << 6);
			*value = (*value & 0b11000111111111111111111111111111) | ((0b111) << 27);

			return true;
		}

		return false;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		if (len == sizeof(uint16_t)) {
			uint16_t *value = (uint16_t*)data;
			Condition cond = COND_NONE;
			switch ((*value & 0x0f00) >> 8)
			{
				case armv7::COND_EQ: cond = armv7::COND_NE; break;
				case armv7::COND_NE: cond = armv7::COND_EQ; break;
				case armv7::COND_CS: cond = armv7::COND_CC; break;
				case armv7::COND_CC: cond = armv7::COND_CS; break;
				case armv7::COND_MI: cond = armv7::COND_PL; break;
				case armv7::COND_PL: cond = armv7::COND_MI; break;
				case armv7::COND_VS: cond = armv7::COND_VC; break;
				case armv7::COND_VC: cond = armv7::COND_VS; break;
				case armv7::COND_HI: cond = armv7::COND_LS; break;
				case armv7::COND_LS: cond = armv7::COND_HI; break;
				case armv7::COND_GE: cond = armv7::COND_LT; break;
				case armv7::COND_LT: cond = armv7::COND_GE; break;
				case armv7::COND_GT: cond = armv7::COND_LE; break;
				case armv7::COND_LE: cond = armv7::COND_GT; break;
			}
			*value = (*value & 0xf0ff) | (cond << 8);
			return true;
		} else if (len == sizeof(uint32_t)) {
			uint32_t *value = (uint32_t*)data;
			Condition cond = COND_NONE;
			switch ((*value & 0b0000000000000000001111000000) >> 6)
			{
				case armv7::COND_EQ: cond = armv7::COND_NE; break;
				case armv7::COND_NE: cond = armv7::COND_EQ; break;
				case armv7::COND_CS: cond = armv7::COND_CC; break;
				case armv7::COND_CC: cond = armv7::COND_CS; break;
				case armv7::COND_MI: cond = armv7::COND_PL; break;
				case armv7::COND_PL: cond = armv7::COND_MI; break;
				case armv7::COND_VS: cond = armv7::COND_VC; break;
				case armv7::COND_VC: cond = armv7::COND_VS; break;
				case armv7::COND_HI: cond = armv7::COND_LS; break;
				case armv7::COND_LS: cond = armv7::COND_HI; break;
				case armv7::COND_GE: cond = armv7::COND_LT; break;
				case armv7::COND_LT: cond = armv7::COND_GE; break;
				case armv7::COND_GT: cond = armv7::COND_LE; break;
				case armv7::COND_LE: cond = armv7::COND_GT; break;
			}
			*value = (*value & 0b11111111111111111111110000111111) | (cond << 6) ;
			return true;
		}
		return false;
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)data;
		(void)addr;
		(void)len;
		(void)value;
		return false;
	}

	/*************************************************************************/

	virtual std::vector<uint32_t> GetSystemRegisters() override
	{
		return vector<uint32_t>{
			// Special registers (and global)
			REGS_APSR,
			REGS_APSR_G,
			REGS_APSR_NZCVQ,
			REGS_APSR_NZCVQG,
			REGS_CPSR,
			REGS_CPSR_C,
			REGS_CPSR_X,
			REGS_CPSR_XC,
			REGS_CPSR_S,
			REGS_CPSR_SC,
			REGS_CPSR_SX,
			REGS_CPSR_SXC,
			REGS_CPSR_F,
			REGS_CPSR_FC,
			REGS_CPSR_FX,
			REGS_CPSR_FXC,
			REGS_CPSR_FS,
			REGS_CPSR_FSC,
			REGS_CPSR_FSX,
			REGS_CPSR_FSXC,
			REGS_SPSR,
			REGS_SPSR_C,
			REGS_SPSR_X,
			REGS_SPSR_XC,
			REGS_SPSR_S,
			REGS_SPSR_SC,
			REGS_SPSR_SX,
			REGS_SPSR_SXC,
			REGS_SPSR_F,
			REGS_SPSR_FC,
			REGS_SPSR_FX,
			REGS_SPSR_FXC,
			REGS_SPSR_FS,
			REGS_SPSR_FSC,
			REGS_SPSR_FSX,
			REGS_SPSR_FSXC,
			REGS_APSR_NZCV,
			REGS_FPSID, // 0
			REGS_FPSCR, // 1
			REGS_MVFR2, // 5
			REGS_MVFR1, // 6
			REGS_MVFR0, // 7
			REGS_FPEXC, // 8
			REGS_FPINST, // 9
			REGS_FPINST2, //10
			REGS_MSP,
			REGS_PSP,

			// these are M-profile only (special)
			REGS_PRIMASK,
			REGS_BASEPRI,
			REGS_FAULTMASK,
			REGS_CONTROL,
		};
	}
};

ArmCommonArchitecture* InitThumb2Architecture(const char* name, BNEndianness endian)
{
	return new Thumb2Architecture(name, endian);
}

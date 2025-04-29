
#include "llil_lift_check.h"

using namespace BinaryNinja;

LowLevelILVerifier::LowLevelILVerifier(Ref<LowLevelILFunction> function): m_il(function)
{
	m_logger = new Logger("LiftCheck");
	m_arch = m_il->GetArchitecture();
}


#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_logger->LogErrorF("{:?} {} " message, expr, #condition, ## __VA_ARGS__ );   \
			result = false;                                                               \
		}                                                                                 \
	}                                                                                     \
	while (false)

bool LowLevelILVerifier::CheckExprSize(const LowLevelILInstruction& expr, std::optional<size_t> requiredSize)
{
	bool result = true;
	switch (expr.operation)
	{
	case LLIL_REG:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		auto reg = expr.GetSourceRegister<LLIL_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto info = m_arch->GetRegisterInfo(reg);
			CHECK(expr.size == info.size, "attempting to load {:#x} bytes out of a {:#x} byte register", expr.size, info.size);
		}
		break;
	}
	case LLIL_REG_SPLIT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size * 2 == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		auto hi = expr.GetHighRegister<LLIL_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(hi))
		{
			auto info = m_arch->GetRegisterInfo(hi);
			CHECK(expr.size == info.size, "attempting to load {:#x} bytes out of a {:#x} byte hi register", expr.size, info.size);
		}
		auto lo = expr.GetLowRegister<LLIL_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto info = m_arch->GetRegisterInfo(lo);
			CHECK(expr.size == info.size, "attempting to load {:#x} bytes out of a {:#x} byte lo register", expr.size, info.size);
		}
		break;
	}
	case LLIL_FLAG:
	{
		if (requiredSize.has_value() && *requiredSize != 0)
		{
			CHECK(expr.size == *requiredSize, "op producing boolean (0 size) value where {:#x} bytes are expected", *requiredSize);
		}
		CHECK(expr.size == 0, "op should be boolean (0 size) but is {:#x} size", expr.size);
		break;
	}
	case LLIL_LOAD:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		// TODO: Is this correct for eg arm64_32
		result &= CheckExprSize(expr.GetSourceExpr<LLIL_LOAD>(), m_arch->GetAddressSize());
		break;
	}
	case LLIL_POP:
	case LLIL_CONST:
	case LLIL_CONST_PTR:
	case LLIL_EXTERN_PTR:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		break;
	}
	case LLIL_CMP_E:
	case LLIL_CMP_NE:
	case LLIL_CMP_SLE:
	case LLIL_CMP_ULE:
	case LLIL_CMP_SLT:
	case LLIL_CMP_ULT:
	case LLIL_CMP_SGE:
	case LLIL_CMP_UGE:
	case LLIL_CMP_SGT:
	case LLIL_CMP_UGT:
	{
		if (requiredSize.has_value() && *requiredSize != 0)
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where boolean (0 size) is expected", *requiredSize);
		}
		CHECK(expr.size != 0, "op should not be comparing as zero width");
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_ADC:
	case LLIL_SBB:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		result &= CheckExprSize(expr.GetCarryExpr(), 0);
		break;
	}
	case LLIL_RLC:
	case LLIL_RRC:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		// rotate amounts just need to be >= 1 byte
		CHECK(expr.GetRightExpr().size != 0, "can't rotate by a 0 byte expression");

		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), std::nullopt);
		result &= CheckExprSize(expr.GetCarryExpr(), 0);
		break;
	}
	case LLIL_ADD:
	case LLIL_SUB:
	case LLIL_AND:
	case LLIL_OR:
	case LLIL_XOR:
	case LLIL_MUL:
	case LLIL_DIVU:
	case LLIL_DIVS:
	case LLIL_MODU:
	case LLIL_MODS:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_LSL:
	case LLIL_LSR:
	case LLIL_ASR:
	case LLIL_ROL:
	case LLIL_ROR:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		// rotate amounts just need to be >= 1 byte
		CHECK(expr.GetRightExpr().size != 0, "can't rotate by a 0 byte expression");

		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), std::nullopt);
		break;
	}
	case LLIL_MULS_DP:
	case LLIL_MULU_DP:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size * 2 == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size * 2, *requiredSize);
		}
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_DIVS_DP:
	case LLIL_DIVU_DP:
	case LLIL_MODS_DP:
	case LLIL_MODU_DP:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size * 2);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_NEG:
	case LLIL_NOT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		result &= CheckExprSize(expr.GetSourceExpr(), expr.size);
		break;
	}
	case LLIL_SX:
	case LLIL_ZX:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		size_t srcSize = expr.GetSourceExpr().size;
		CHECK(srcSize < expr.size, "expanding op to {:#x} bytes is invalid; source is already {:#x} bytes", expr.size, srcSize);

		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_LOW_PART:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		size_t srcSize = expr.GetSourceExpr().size;
		CHECK(srcSize > expr.size, "truncating op to {:#x} bytes is invalid; source is already {:#x} bytes", expr.size, srcSize);

		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_BOOL_TO_INT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		result &= CheckExprSize(expr.GetSourceExpr(), 0);
		break;
	}
	case LLIL_UNIMPL_MEM:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}

		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	default:
	{
		m_logger->LogInfoF("Unhandled expr operation: {:?}", expr);
		break;
	}
	}
	return result;
}
#undef CHECK


#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_logger->LogErrorF("{:?} {} " message, instr, #condition, ## __VA_ARGS__ );  \
			result = false;                                                               \
		}                                                                                 \
	}                                                                                     \
	while (false)

bool LowLevelILVerifier::CheckInstrSize(const LowLevelILInstruction& instr)
{
	bool result = true;

	switch (instr.operation)
	{
	case LLIL_SET_REG:
	{
		size_t instrSize = instr.size;

		// TODO: how to do sanity checking for temp registers?
		auto reg = instr.GetDestRegister<LLIL_SET_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto info = m_arch->GetRegisterInfo(reg);

			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			// As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			// namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			// nightmare semantics on the upper 96 bits + 128 bits
			CHECK(instrSize == info.size, "setting {} byte register {} to {} byte value", info.size, m_arch->GetRegisterName(reg), instrSize);
		}

		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG>(), instrSize);
		break;
	}
	case LLIL_SET_REG_SPLIT:
	{
		size_t instrSize = instr.size;

		// TODO: how to do sanity checking for temp registers?
		auto hi = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(hi))
		{
			auto info = m_arch->GetRegisterInfo(hi);
			CHECK(instrSize == info.size, "setting {} byte hi register {} to {} byte value", info.size, m_arch->GetRegisterName(hi), instrSize);
		}
		auto lo = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto info = m_arch->GetRegisterInfo(lo);
			CHECK(instrSize == info.size, "setting {} byte lo register {} to {} byte value", info.size, m_arch->GetRegisterName(lo), instrSize);
		}

		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG_SPLIT>(), instrSize * 2);
		break;
	}
	case LLIL_SET_FLAG:
	{
		size_t instrSize = 0;
		CHECK(instr.size == 0, "set flag size should be zero, is {:#x}", instr.size);
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_FLAG>(), instrSize);
		break;
	}
	case LLIL_STORE:
	{
		size_t instrSize = instr.size;
		CHECK(instr.size != 0, "storing a zero byte value");

		// TODO: Is this correct for eg arm64_32
		result &= CheckExprSize(instr.GetDestExpr<LLIL_STORE>(), m_arch->GetAddressSize());
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_STORE>(), instrSize);
		break;
	}
	case LLIL_PUSH:
		CHECK(instr.size != 0, "pushing a 0 byte value");
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_PUSH>(), instr.size);
		break;
	case LLIL_JUMP:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_JUMP>(), std::nullopt);
		break;
	case LLIL_JUMP_TO:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_JUMP_TO>(), std::nullopt);
		break;
	case LLIL_CALL:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_CALL>(), std::nullopt);
		break;
	case LLIL_TAILCALL:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_TAILCALL>(), std::nullopt);
		break;
	case LLIL_SYSCALL:
		break;
	case LLIL_RET:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_RET>(), std::nullopt);
		break;
	case LLIL_IF:
		result &= CheckExprSize(instr.GetConditionExpr<LLIL_IF>(), 0);
		break;
	case LLIL_GOTO:
		// TODO: Check target
		break;
	case LLIL_INTRINSIC:
	{
		auto expectInputs = m_arch->GetIntrinsicInputs(instr.GetIntrinsic<LLIL_INTRINSIC>());
		auto expectOutputs = m_arch->GetIntrinsicOutputs(instr.GetIntrinsic<LLIL_INTRINSIC>());
		auto actualInputs = instr.GetParameterExprs<LLIL_INTRINSIC>();
		auto actualOutputs = instr.GetOutputRegisterOrFlagList<LLIL_INTRINSIC>();

		CHECK(expectInputs.size() == actualInputs.size(), "intrinsic expects {} inputs but has {}", expectInputs.size(), actualInputs.size());
		CHECK(expectOutputs.size() == actualOutputs.size(), "intrinsic expects {} outputs but has {}", expectOutputs.size(), actualOutputs.size());

		if (expectInputs.size() == actualInputs.size())
		{
			for (size_t i = 0; i < expectInputs.size(); i++)
			{
				auto expectSize = expectInputs[i].type->GetWidth();
				auto actualSize = actualInputs[i].size;
				CHECK(expectSize == actualSize, "intrinsic argument {} size expects {:#x} but is {:#x}", i, expectSize, actualSize);
			}
		}
		if (expectOutputs.size() == actualOutputs.size())
		{
			for (size_t i = 0; i < expectOutputs.size(); i++)
			{
				auto expectSize = expectOutputs[i]->GetWidth();
				auto actualSize = actualOutputs[i].isFlag ? 0 : m_arch->GetRegisterInfo(actualOutputs[i].index).size;
				CHECK(expectSize == actualSize, "intrinsic output {} size expects {:#x} but is {:#x}", i, expectSize, actualSize);
			}
		}
		break;
	}
	case LLIL_NOP:
		break;
	case LLIL_NORET:
	case LLIL_UNDEF:
	case LLIL_BP:
	case LLIL_TRAP:
		break;
	default:
		CheckExprSize(instr, std::nullopt);
		break;
	}
	return result;
}

#undef CHECK


bool LowLevelILVerifier::Verify()
{
	/*
		Invariants:
		-[ ] All blocks either branch to existing blocks or terminate
		-[x] Sizes of expressions are consistent
		-[ ] Base level instructions are of a limited subset of operations (setreg, call, etc)
		-[ ] Child expressions are of a limited subset of operations (eg NOT goto)
		-[ ] Expression parameters are in valid range
		-[ ] Each expression has as most 1 parent
	 */

	if (!m_il->GetFunction())
	{
		// Bare ILs don't matter
		return true;
	}
	if (m_il == m_il->GetSSAForm())
	{
		// TODO: SSA form
		return true;
	}

	bool result = true;

	// Check expr sizes
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex ++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			result &= CheckInstrSize(instr);
		}
	}

	return result;
}

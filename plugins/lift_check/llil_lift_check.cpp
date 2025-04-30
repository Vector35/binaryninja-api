
#include "llil_lift_check.h"

using namespace BinaryNinja;

enum
{
	ValidInNonSSA = 1 << 0,
	ValidInSSA    = 1 << 1,
	ValidAsParent = 1 << 2,
	ValidAsChild  = 1 << 3,
};

static std::unordered_map<BNLowLevelILOperation, int> g_instructionValidity = {{
	{ LLIL_NOP,                          ValidInNonSSA |              ValidAsParent | ValidAsChild },
	{ LLIL_SET_REG,                      ValidInNonSSA |              ValidAsParent                },
	{ LLIL_SET_REG_SPLIT,                ValidInNonSSA |              ValidAsParent                },
	{ LLIL_SET_FLAG,                     ValidInNonSSA |              ValidAsParent                },
	{ LLIL_SET_REG_STACK_REL,            ValidInNonSSA |              ValidAsParent                },
	{ LLIL_REG_STACK_PUSH,               ValidInNonSSA |              ValidAsParent                },
	{ LLIL_ASSERT,                       ValidInNonSSA |              ValidAsParent                },
	{ LLIL_FORCE_VER,                    ValidInNonSSA |              ValidAsParent                },
	{ LLIL_LOAD,                         ValidInNonSSA |                              ValidAsChild },
	{ LLIL_STORE,                        ValidInNonSSA |              ValidAsParent                },
	{ LLIL_PUSH,                         ValidInNonSSA |              ValidAsParent                },
	{ LLIL_POP,                          ValidInNonSSA |                              ValidAsChild },
	{ LLIL_REG,                          ValidInNonSSA |                              ValidAsChild },
	{ LLIL_REG_SPLIT,                    ValidInNonSSA |                              ValidAsChild },
	{ LLIL_REG_STACK_REL,                ValidInNonSSA |                              ValidAsChild },
	{ LLIL_REG_STACK_POP,                ValidInNonSSA |                              ValidAsChild },
	{ LLIL_REG_STACK_FREE_REG,           ValidInNonSSA |              ValidAsParent                },
	{ LLIL_REG_STACK_FREE_REL,           ValidInNonSSA |              ValidAsParent                },
	{ LLIL_CONST,                        ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CONST_PTR,                    ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_EXTERN_PTR,                   ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FLOAT_CONST,                  ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FLAG,                         ValidInNonSSA |                              ValidAsChild },
	{ LLIL_FLAG_BIT,                     ValidInNonSSA |                              ValidAsChild },
	{ LLIL_ADD,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ADC,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_SUB,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_SBB,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_AND,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_OR,                           ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_XOR,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_LSL,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_LSR,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ASR,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ROL,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_RLC,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ROR,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_RRC,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MUL,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MULU_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MULS_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_DIVU,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_DIVU_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_DIVS,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_DIVS_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MODU,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MODU_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MODS,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_MODS_DP,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_NEG,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_NOT,                          ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_SX,                           ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ZX,                           ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_LOW_PART,                     ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_JUMP,                         ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_JUMP_TO,                      ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_CALL,                         ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_CALL_STACK_ADJUST,            ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_TAILCALL,                     ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_RET,                          ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_NORET,                        ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_IF,                           ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_GOTO,                         ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_FLAG_COND,                    0                                                         },
	{ LLIL_FLAG_GROUP,                   0                                                         },
	{ LLIL_CMP_E,                        ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_NE,                       ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_SLT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_ULT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_SLE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_ULE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_SGE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_UGE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_SGT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CMP_UGT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_TEST_BIT,                     ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_BOOL_TO_INT,                  ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ADD_OVERFLOW,                 ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_SYSCALL,                      ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_BP,                           ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_TRAP,                         ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_INTRINSIC,                    ValidInNonSSA | ValidInSSA | ValidAsParent                },
	{ LLIL_UNDEF,                        ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ LLIL_UNIMPL,                       ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ LLIL_UNIMPL_MEM,                   ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ LLIL_FADD,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FSUB,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FMUL,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FDIV,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FSQRT,                        ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FNEG,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FABS,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FLOAT_TO_INT,                 ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_INT_TO_FLOAT,                 ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FLOAT_CONV,                   ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_ROUND_TO_INT,                 ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FLOOR,                        ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_CEIL,                         ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FTRUNC,                       ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_E,                       ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_NE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_LT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_LE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_GE,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_GT,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_O,                       ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_FCMP_UO,                      ValidInNonSSA | ValidInSSA |                 ValidAsChild },
	{ LLIL_SET_REG_SSA,                                  ValidInSSA | ValidAsParent                },
	{ LLIL_SET_REG_SSA_PARTIAL,                          ValidInSSA | ValidAsParent                },
	{ LLIL_SET_REG_SPLIT_SSA,                            ValidInSSA | ValidAsParent                },
	{ LLIL_SET_REG_STACK_REL_SSA,                        ValidInSSA | ValidAsParent                },
	{ LLIL_SET_REG_STACK_ABS_SSA,                        ValidInSSA | ValidAsParent                },
	{ LLIL_REG_SPLIT_DEST_SSA,                           ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_DEST_SSA,                           ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_SSA,                                      ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_SSA_PARTIAL,                              ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_SPLIT_SSA,                                ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_REL_SSA,                            ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_ABS_SSA,                            ValidInSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_FREE_REL_SSA,                       ValidInSSA | ValidAsParent                },
	{ LLIL_REG_STACK_FREE_ABS_SSA,                       ValidInSSA | ValidAsParent                },
	{ LLIL_SET_FLAG_SSA,                                 ValidInSSA | ValidAsParent                },
	{ LLIL_ASSERT_SSA,                                   ValidInSSA | ValidAsParent                },
	{ LLIL_FORCE_VER_SSA,                                ValidInSSA | ValidAsParent                },
	{ LLIL_FLAG_SSA,                                     ValidInSSA |                 ValidAsChild },
	{ LLIL_FLAG_BIT_SSA,                                 ValidInSSA |                 ValidAsChild },
	{ LLIL_CALL_SSA,                                     ValidInSSA | ValidAsParent                },
	{ LLIL_SYSCALL_SSA,                                  ValidInSSA | ValidAsParent                },
	{ LLIL_TAILCALL_SSA,                                 ValidInSSA | ValidAsParent                },
	{ LLIL_CALL_PARAM,                                   ValidInSSA |                 ValidAsChild },
	{ LLIL_CALL_STACK_SSA,                               ValidInSSA |                 ValidAsChild },
	{ LLIL_CALL_OUTPUT_SSA,                              ValidInSSA |                 ValidAsChild },
	{ LLIL_SEPARATE_PARAM_LIST_SSA,                      ValidInSSA |                 ValidAsChild },
	{ LLIL_SHARED_PARAM_SLOT_SSA,                        ValidInSSA |                 ValidAsChild },
	{ LLIL_MEMORY_INTRINSIC_OUTPUT_SSA,                  ValidInSSA |                 ValidAsChild },
	{ LLIL_LOAD_SSA,                                     ValidInSSA |                 ValidAsChild },
	{ LLIL_STORE_SSA,                                    ValidInSSA | ValidAsParent                },
	{ LLIL_INTRINSIC_SSA,                                ValidInSSA | ValidAsParent                },
	{ LLIL_MEMORY_INTRINSIC_SSA,                         ValidInSSA | ValidAsParent                },
	{ LLIL_REG_PHI,                                      ValidInSSA | ValidAsParent                },
	{ LLIL_REG_STACK_PHI,                                ValidInSSA | ValidAsParent                },
	{ LLIL_FLAG_PHI,                                     ValidInSSA | ValidAsParent                },
	{ LLIL_MEM_PHI,                                      ValidInSSA |                 ValidAsChild }
}};

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
		// TODO: how to do sanity checking for temp registers?
		auto reg = instr.GetDestRegister<LLIL_SET_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto info = m_arch->GetRegisterInfo(reg);

			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			// As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			// namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			// nightmare semantics on the upper 96 bits + 128 bits
			CHECK(info.size == instr.size, "setting {} byte register {} to {} byte value", info.size, m_arch->GetRegisterName(reg), instr.size);
		}

		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG>(), instr.size);
		break;
	}
	case LLIL_SET_REG_SPLIT:
	{
		// TODO: how to do sanity checking for temp registers?
		auto hi = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(hi))
		{
			auto info = m_arch->GetRegisterInfo(hi);
			CHECK(info.size == instr.size, "setting {} byte hi register {} to {} byte value", info.size, m_arch->GetRegisterName(hi), instr.size);
		}
		auto lo = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto info = m_arch->GetRegisterInfo(lo);
			CHECK(info.size == instr.size, "setting {} byte lo register {} to {} byte value", info.size, m_arch->GetRegisterName(lo), instr.size);
		}

		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG_SPLIT>(), instr.size * 2);
		break;
	}
	case LLIL_SET_FLAG:
	{
		CHECK(instr.size == 0, "set flag size should be zero, is {:#x}", instr.size);
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_FLAG>(), 0);
		break;
	}
	case LLIL_STORE:
	{
		CHECK(instr.size != 0, "storing a zero byte value");

		// TODO: Is this correct for eg arm64_32
		result &= CheckExprSize(instr.GetDestExpr<LLIL_STORE>(), m_arch->GetAddressSize());
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_STORE>(), instr.size);
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
		m_logger->LogWarnF("Unexpected root instruction: {:?}", instr);
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
		-[x] Base level instructions are of a limited subset of operations (setreg, call, etc)
		-[x] Child expressions are of a limited subset of operations (eg NOT goto)
		-[ ] Expression parameters are in valid range
		-[ ] Each expression has as most 1 parent
		-[ ] Expr address aligns with instruction
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
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			result &= CheckInstrSize(instr);
		}
	}

	// Check exprs are where we expect them to be
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex ++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			result &= CheckInstrSize(instr);

			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (auto found = g_instructionValidity.find(expr.operation); found != g_instructionValidity.end())
				{
					// We always check Non-SSA form (only the core generates SSA forms and I'd *like* to believe it is correct)
					if ((found->second & ValidInNonSSA) == 0)
					{
						result = false;
						m_logger->LogWarnF("Instruction {:?} is not valid in non-ssa form", expr);
					}
					if (expr.exprIndex == instr.exprIndex)
					{
						if ((found->second & ValidAsParent) == 0)
						{
							result = false;
							m_logger->LogWarnF("Instruction {:?} is not valid as parent instruction", expr);
						}
					}
					else
					{
						if ((found->second & ValidAsChild) == 0)
						{
							result = false;
							m_logger->LogWarnF("Instruction {:?} is not valid as child instruction", expr);
						}
					}
				}
				else
				{
					result = false;
					m_logger->LogWarnF("Unknown instruction operation {:?}", expr);
				}
				return true;
			});
		}
	}

	return result;
}

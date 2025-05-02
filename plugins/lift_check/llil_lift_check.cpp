
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


bool LowLevelILVerifier::CheckExprSize(const LowLevelILInstruction& expr, std::optional<size_t> requiredSize)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_logger->LogErrorF("{:#x} {:?} {} " message, m_il->GetFunction()->GetStart(), expr, #condition, ## __VA_ARGS__ );   \
			result = false;                                                               \
		}                                                                                 \
	}                                                                                     \
	while (false)

	bool result = true;
	switch (expr.operation)
	{
	case LLIL_NOP:
		break;
	case LLIL_LOAD:
	{
		if (requiredSize.has_value())
		{
			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			// As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			// namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			// nightmare semantics on the upper 96 bits + 128 bits

			if (expr.size < *requiredSize)
			{
				m_logger->LogDebugF("{:?} loading only {:#x} bytes out of {:#x} byte memory", expr, expr.size, *requiredSize);
			}
			else
			{
				CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
			}
		}
		CHECK(expr.size != 0, "op should have a size");
		// TODO: Is this correct for eg arm64_32
		result &= CheckExprSize(expr.GetSourceExpr<LLIL_LOAD>(), m_arch->GetAddressSize());
		break;
	}
	case LLIL_POP:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
		break;
	}
	case LLIL_REG:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		auto reg = expr.GetSourceRegister<LLIL_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto info = m_arch->GetRegisterInfo(reg);

			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			// As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			// namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			// nightmare semantics on the upper 96 bits + 128 bits
			if (expr.size < info.size)
			{
				m_logger->LogDebugF("{:?} loading only {:#x} bytes out of {:#x} byte register {}", expr, expr.size, info.size, m_arch->GetRegisterName(reg));
			}
			else
			{
				CHECK(expr.size == info.size, "attempting to load {:#x} bytes out of {:#x} byte register {}", expr.size, info.size, m_arch->GetRegisterName(reg));
			}
		}
		break;
	}
	case LLIL_REG_SPLIT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size * 2 == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

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
	case LLIL_REG_STACK_REL:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		auto regStack = expr.GetSourceRegisterStack<LLIL_REG_STACK_REL>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(expr.size == firstInfo.size, "attempting to load {:#x} bytes out of a {:#x} byte register stack", expr.size, firstInfo.size);
		break;
	}
	case LLIL_REG_STACK_POP:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		auto regStack = expr.GetSourceRegisterStack<LLIL_REG_STACK_POP>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(expr.size == firstInfo.size, "attempting to load {:#x} bytes out of a {:#x} byte register stack", expr.size, firstInfo.size);
		break;
	}
	case LLIL_CONST:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		// LLIL_CONST explicitly can be a boolean (0 size)
		break;
	}
	case LLIL_CONST_PTR:
	case LLIL_EXTERN_PTR:
	case LLIL_FLOAT_CONST:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		// But these ones cannot be a boolean
		CHECK(expr.size != 0, "op should have a size");
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
	case LLIL_FLAG_BIT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
		auto bit = expr.GetBitIndex<LLIL_FLAG_BIT>();
		auto bitWidth = expr.size * 8;
		CHECK(bit < bitWidth, "trying to set bit {} on a {} bit result value", bit, bitWidth);
		break;
	}
	case LLIL_TEST_BIT:
	{
		// Like LLIL_CMP_xx, LLIL_TEST_BIT's size is the size of its inputs, producing a 0-size value
		if (requiredSize.has_value() && *requiredSize != 0)
		{
			CHECK(expr.size == *requiredSize, "op producing boolean (0 size) value where {:#x} bytes are expected", *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
		result &= CheckExprSize(expr.GetLeftExpr<LLIL_TEST_BIT>(), expr.size);
		result &= CheckExprSize(expr.GetRightExpr<LLIL_TEST_BIT>(), std::nullopt);
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
	case LLIL_FCMP_E:
	case LLIL_FCMP_NE:
	case LLIL_FCMP_LT:
	case LLIL_FCMP_LE:
	case LLIL_FCMP_GE:
	case LLIL_FCMP_GT:
	case LLIL_FCMP_O:
	case LLIL_FCMP_UO:
	{
		if (requiredSize.has_value() && *requiredSize != 0)
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where boolean (0 size) is expected", *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
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
		CHECK(expr.size != 0, "op should have a size");
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
		CHECK(expr.size != 0, "op should have a size");

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
	case LLIL_FADD:
	case LLIL_FSUB:
	case LLIL_FMUL:
	case LLIL_FDIV:
	case LLIL_ADD_OVERFLOW: // overflowed result of an add, args are same as add and result is same size
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
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
		CHECK(expr.size != 0, "op should have a size");

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
		CHECK(expr.size != 0, "op should have a size");
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
		CHECK(expr.size != 0, "op should have a size");
		result &= CheckExprSize(expr.GetLeftExpr(), expr.size * 2);
		result &= CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_NEG:
	case LLIL_NOT:
	case LLIL_FSQRT:
	case LLIL_FNEG:
	case LLIL_FABS:
	case LLIL_ROUND_TO_INT:
	case LLIL_FLOOR:
	case LLIL_CEIL:
	case LLIL_FTRUNC:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
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
		CHECK(expr.size != 0, "op should have a size");

		size_t srcSize = expr.GetSourceExpr().size;
		CHECK(srcSize <= expr.size, "expanding op to {:#x} bytes is invalid; source is already {:#x} bytes", expr.size, srcSize);

		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_LOW_PART:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		size_t srcSize = expr.GetSourceExpr().size;
		CHECK(srcSize >= expr.size, "truncating op to {:#x} bytes is invalid; source is already {:#x} bytes", expr.size, srcSize);

		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_BOOL_TO_INT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		result &= CheckExprSize(expr.GetSourceExpr(), 0);
		break;
	}
	case LLIL_FLOAT_TO_INT:
	case LLIL_INT_TO_FLOAT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
		// Expr size is result size, input size is anything
		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_FLOAT_CONV:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");
		// Expr size is result size, input size is anything
		result &= CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_UNDEF:
		break;
	case LLIL_UNIMPL:
		break;
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
#undef CHECK
}


bool LowLevelILVerifier::CheckInstrSize(const LowLevelILInstruction& instr)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_logger->LogErrorF("{:#x} {:?} {} " message, m_il->GetFunction()->GetStart(), instr, #condition, ## __VA_ARGS__ );  \
			result = false;                                                               \
		}                                                                                 \
	}                                                                                     \
	while (false)

	bool result = true;

	switch (instr.operation)
	{
	case LLIL_NOP:
		break;
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
			if (info.size > instr.size)
			{
				m_logger->LogDebugF("{:?} setting {:#x} byte register {} to {:#x} byte value", instr, info.size, m_arch->GetRegisterName(reg), instr.size);
			}
			else
			{
				CHECK(info.size == instr.size, "setting {:#x} byte register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(reg), instr.size);
			}
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
			CHECK(info.size == instr.size, "setting {:#x} byte hi register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(hi), instr.size);
		}
		auto lo = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto info = m_arch->GetRegisterInfo(lo);
			CHECK(info.size == instr.size, "setting {:#x} byte lo register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(lo), instr.size);
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
	case LLIL_SET_REG_STACK_REL:
	{
		auto regStack = instr.GetDestRegisterStack<LLIL_SET_REG_STACK_REL>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(firstInfo.size == instr.size, "setting {:#x} byte register stack {} with {:#x} byte value", firstInfo.size, m_arch->GetRegisterStackName(regStack), instr.size);

		// TODO: Check relative offset in stack?
		result &= CheckExprSize(instr.GetDestExpr<LLIL_SET_REG_STACK_REL>(), std::nullopt);
		result &= CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG_STACK_REL>(), instr.size);
		break;
	}
	case LLIL_REG_STACK_PUSH:
	{
		auto regStack = instr.GetDestRegisterStack<LLIL_REG_STACK_PUSH>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(firstInfo.size == instr.size, "pushing {:#x} byte register stack {} with {:#x} byte value", firstInfo.size, m_arch->GetRegisterStackName(regStack), instr.size);

		result &= CheckExprSize(instr.GetSourceExpr<LLIL_REG_STACK_PUSH>(), instr.size);
		break;
	}
	case LLIL_ASSERT:
		break;
	case LLIL_FORCE_VER:
		break;
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
	case LLIL_REG_STACK_FREE_REG:
		break;
	case LLIL_REG_STACK_FREE_REL:
		// TODO: Check relative offset in stack?
		result &= CheckExprSize(instr.GetDestExpr<LLIL_REG_STACK_FREE_REL>(), std::nullopt);
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
	case LLIL_CALL_STACK_ADJUST:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_CALL_STACK_ADJUST>(), std::nullopt);
		break;
	case LLIL_TAILCALL:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_TAILCALL>(), std::nullopt);
		break;
	case LLIL_RET:
		result &= CheckExprSize(instr.GetDestExpr<LLIL_RET>(), std::nullopt);
		break;
	case LLIL_NORET:
		break;
	case LLIL_IF:
		result &= CheckExprSize(instr.GetConditionExpr<LLIL_IF>(), 0);
		break;
	case LLIL_GOTO:
		break;
	case LLIL_SYSCALL:
		break;
	case LLIL_BP:
		break;
	case LLIL_TRAP:
		break;
	case LLIL_INTRINSIC:
	{
		auto expectInputs = m_arch->GetIntrinsicInputs(instr.GetIntrinsic<LLIL_INTRINSIC>());
		auto expectOutputs = m_arch->GetIntrinsicOutputs(instr.GetIntrinsic<LLIL_INTRINSIC>());
		auto actualInputs = instr.GetParameterExprs<LLIL_INTRINSIC>();
		auto actualOutputs = instr.GetOutputRegisterOrFlagList<LLIL_INTRINSIC>();

		// Not even going to take a chance on msvc breaking min() here
		for (size_t i = 0; i < (std::min)(actualInputs.size(), expectInputs.size()); i++)
		{
			auto expectSize = expectInputs[i].type->GetWidth();
			auto actualSize = actualInputs[i].size;
			CHECK(expectSize == actualSize, "intrinsic argument {} size expects {:#x} but is {:#x}", i, expectSize, actualSize);
		}
		for (size_t i = 0; i < (std::min)(actualOutputs.size(), expectOutputs.size()); i++)
		{
			auto expectSize = expectOutputs[i]->GetWidth();
			auto actualSize = actualOutputs[i].isFlag ? 0 : m_arch->GetRegisterInfo(actualOutputs[i].index).size;
			CHECK(expectSize == actualSize, "intrinsic output {} size expects {:#x} but is {:#x}", i, expectSize, actualSize);
		}
		break;
	}
	case LLIL_UNDEF:
		break;
	case LLIL_UNIMPL:
		break;
	case LLIL_UNIMPL_MEM:
		CheckExprSize(instr.GetSourceExpr<LLIL_UNIMPL_MEM>(), std::nullopt);
		break;
	default:
		m_logger->LogDebugF("Unexpected root instruction: {:?}", instr);
		CheckExprSize(instr, std::nullopt);
		break;
	}
	return result;
#undef CHECK
}


bool LowLevelILVerifier::CheckExprOperands(const BinaryNinja::LowLevelILInstruction& expr)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_logger->LogErrorF("{:#x} {:?} {} " message, m_il->GetFunction()->GetStart(), expr, #condition, ## __VA_ARGS__ );   \
			result = false;                                                               \
		}                                                                                 \
	}                                                                                     \
	while (false)


#undef CHECEK
	bool result = true;
	switch (expr.operation)
	{
	case LLIL_NOP: break;
	case LLIL_SET_REG:
	{
		auto reg = expr.GetDestRegister<LLIL_SET_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto name = m_arch->GetRegisterName(reg);
			CHECK(!name.empty(), "unknown register index {}", reg);
		}
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG>());
		break;
	}
	case LLIL_SET_REG_SPLIT:
	{
		auto hi = expr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(hi))
		{
			auto name = m_arch->GetRegisterName(hi);
			CHECK(!name.empty(), "unknown high register index {}", hi);
		}
		auto lo = expr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto name = m_arch->GetRegisterName(lo);
			CHECK(!name.empty(), "unknown low register index {}", lo);
		}
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG_SPLIT>());
		break;
	}
	case LLIL_SET_FLAG:
	{
		auto flag = expr.GetDestFlag<LLIL_SET_FLAG>();
		auto name = m_arch->GetFlagName(flag);
		CHECK(!name.empty(), "unknown flag index {}", flag);
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_SET_FLAG>());
		break;
	}
	case LLIL_SET_REG_STACK_REL:
	{
		auto regStack = expr.GetDestRegisterStack<LLIL_SET_REG_STACK_REL>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_SET_REG_STACK_REL>());
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG_STACK_REL>());
		break;
	}
	case LLIL_REG_STACK_PUSH:
	{
		auto regStack = expr.GetDestRegisterStack<LLIL_REG_STACK_PUSH>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_REG_STACK_PUSH>());
		break;
	}
	case LLIL_ASSERT:
	{
		auto reg = expr.GetSourceRegister<LLIL_ASSERT>();
		// rss says: technically you can assert on a temp, but only if the definition
		// of the temp register dominates the assert
		// he also says that you have to do this on the SSA form (because dominators)
		// so TODO: that, maybe
		CHECK(!LLIL_REG_IS_TEMP(reg), "cannot assert on temp register {}", reg);
		auto name = m_arch->GetRegisterName(reg);
		CHECK(!name.empty(), "unknown register index {}", reg);
		// todo: probably no way to check that a PossibleValueSet is valid
//		auto constraint = expr.GetConstraint<LLIL_ASSERT>();
		break;
	}
	case LLIL_FORCE_VER:
	{
		auto reg = expr.GetDestRegister<LLIL_FORCE_VER>();
		// similar thing rss said above
		CHECK(!LLIL_REG_IS_TEMP(reg), "cannot force version on temp register {}", reg);
		auto name = m_arch->GetRegisterName(reg);
		CHECK(!name.empty(), "unknown register index {}", reg);
		break;
	}
	case LLIL_STORE:
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_STORE>());
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_STORE>());
		break;
	case LLIL_PUSH:
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_PUSH>());
		break;
	case LLIL_REG_STACK_FREE_REG:
	{
		auto reg = expr.GetDestRegister<LLIL_REG_STACK_FREE_REG>();
		auto name = m_arch->GetRegisterName(reg);
		CHECK(!name.empty(), "unknown register index {}", reg);
		auto regStack = m_arch->GetRegisterStackForRegister(reg);
		auto regStackName = m_arch->GetRegisterStackName(regStack);
		CHECK(!regStackName.empty(), "register {} is not in any register stack", name);
		break;
	}
	case LLIL_REG_STACK_FREE_REL:
	{
		auto regStack = expr.GetDestRegisterStack<LLIL_REG_STACK_FREE_REL>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_REG_STACK_FREE_REL>());
		break;
	}
	case LLIL_JUMP:
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_JUMP>());
		break;
	case LLIL_JUMP_TO:
	{
		auto targets = expr.GetTargets<LLIL_JUMP_TO>();
		std::unordered_set<size_t> seenValues;
		std::unordered_set<uint64_t> seenDests;
		for (auto& [value, dest] : targets)
		{
			if (!seenValues.insert(value).second)
			{
				m_logger->LogErrorF("{:?} {} duplicate jump target value {}", expr, value);
				result = false;
			}
			if (!seenDests.insert(dest).second)
			{
				m_logger->LogErrorF("{:?} {} duplicate jump target dest {}", expr, dest);
				result = false;
			}
		}
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_JUMP_TO>());
		break;
	}
	case LLIL_CALL:
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_CALL>());
		break;
	case LLIL_CALL_STACK_ADJUST:
	{
		for (auto& [regStack, offset]: expr.GetRegisterStackAdjustments<LLIL_CALL_STACK_ADJUST>())
		{
			auto name = m_arch->GetRegisterStackName(regStack);
			CHECK(!name.empty(), "unknown register stack index {}", regStack);
		}
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_CALL_STACK_ADJUST>());
		break;
	}
	case LLIL_TAILCALL:
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_TAILCALL>());
		break;
	case LLIL_RET:
		result &= CheckExprOperands(expr.GetDestExpr<LLIL_RET>());
		break;
	case LLIL_NORET:
		break;
	case LLIL_IF:
	{
		size_t instrCount = m_il->GetInstructionCount();
		size_t trueTarget = expr.GetTrueTarget<LLIL_IF>();
		size_t falseTarget = expr.GetFalseTarget<LLIL_IF>();
		CHECK(trueTarget < instrCount, "true target {} out of range of function with {} instructions", trueTarget, instrCount);
		CHECK(falseTarget < instrCount, "false target {} out of range of function with {} instructions", falseTarget, instrCount);
		result &= CheckExprOperands(expr.GetConditionExpr<LLIL_IF>());
		break;
	}
	case LLIL_GOTO:
	{
		size_t instrCount = m_il->GetInstructionCount();
		size_t target = expr.GetTarget<LLIL_GOTO>();
		CHECK(target < instrCount, "target {} out of range of function with {} instructions", target, instrCount);
		break;
	}
	case LLIL_SYSCALL:
		// Apparently syscall number is not exposed at LLIL
		break;
	case LLIL_BP:
		break;
	case LLIL_TRAP:
		// Pretty sure trap vector value is unconstrained
		break;
	case LLIL_INTRINSIC:
	{
		auto intrinsic = expr.GetIntrinsic<LLIL_INTRINSIC>();
		auto name = m_arch->GetIntrinsicName(intrinsic);
		CHECK(!name.empty(), "unknown intrinsic index {}", intrinsic);

		auto expectInputs = m_arch->GetIntrinsicInputs(expr.GetIntrinsic<LLIL_INTRINSIC>());
		auto expectOutputs = m_arch->GetIntrinsicOutputs(expr.GetIntrinsic<LLIL_INTRINSIC>());
		auto actualInputs = expr.GetParameterExprs<LLIL_INTRINSIC>();
		auto actualOutputs = expr.GetOutputRegisterOrFlagList<LLIL_INTRINSIC>();

		CHECK(expectInputs.size() == actualInputs.size(), "intrinsic expects {} inputs but has {}", expectInputs.size(), actualInputs.size());
		CHECK(expectOutputs.size() == actualOutputs.size(), "intrinsic expects {} outputs but has {}", expectOutputs.size(), actualOutputs.size());

		for (auto& input: actualInputs)
		{
			result &= CheckExprOperands(input);
		}
		for (auto& output: actualOutputs)
		{
			if (output.isFlag)
			{
				auto flagName = m_arch->GetFlagName(output.index);
				CHECK(!flagName.empty(), "unknown flag index {}", output.index);
			}
			else
			{
				auto regName = m_arch->GetRegisterName(output.index);
				CHECK(!regName.empty(), "unknown register index {}", output.index);
			}
		}
		break;
	}
	case LLIL_UNDEF:
		break;
	case LLIL_UNIMPL:
		break;
	case LLIL_UNIMPL_MEM:
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_UNIMPL_MEM>());
		break;
	case LLIL_LOAD:
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_LOAD>());
		break;
	case LLIL_POP:
		break;
	case LLIL_REG:
	{
		auto reg = expr.GetSourceRegister<LLIL_REG>();
		if (!LLIL_REG_IS_TEMP(reg))
		{
			auto name = m_arch->GetRegisterName(reg);
			CHECK(!name.empty(), "unknown register index {}", reg);
		}
		break;
	}
	case LLIL_REG_SPLIT:
	{
		auto hi = expr.GetHighRegister<LLIL_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(hi))
		{
			auto name = m_arch->GetRegisterName(hi);
			CHECK(!name.empty(), "unknown high register index {}", hi);
		}
		auto lo = expr.GetLowRegister<LLIL_REG_SPLIT>();
		if (!LLIL_REG_IS_TEMP(lo))
		{
			auto name = m_arch->GetRegisterName(lo);
			CHECK(!name.empty(), "unknown low register index {}", lo);
		}
		break;
	}
	case LLIL_REG_STACK_REL:
	{
		auto regStack = expr.GetSourceRegisterStack<LLIL_REG_STACK_REL>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		result &= CheckExprOperands(expr.GetSourceExpr<LLIL_REG_STACK_REL>());
		break;
	}
	case LLIL_REG_STACK_POP:
	{
		auto regStack = expr.GetSourceRegisterStack<LLIL_REG_STACK_POP>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		break;
	}
	case LLIL_CONST:
	case LLIL_CONST_PTR:
	case LLIL_EXTERN_PTR: // could check this actually exists in the bv but not critical
	case LLIL_FLOAT_CONST: // could check float is real but that is hard
		break;
	case LLIL_FLAG:
	{
		auto flag = expr.GetSourceFlag<LLIL_FLAG>();
		auto name = m_arch->GetFlagName(flag);
		CHECK(!name.empty(), "unknown flag index {}", flag);
		break;
	}
	case LLIL_FLAG_BIT:
	{
		auto flag = expr.GetSourceFlag<LLIL_FLAG_BIT>();
		auto name = m_arch->GetFlagName(flag);
		CHECK(!name.empty(), "unknown flag index {}", flag);
		break;
	}
	case LLIL_NEG:
	case LLIL_NOT:
	case LLIL_FSQRT:
	case LLIL_FNEG:
	case LLIL_FABS:
	case LLIL_ROUND_TO_INT: // float->float, round towards nearest (x86 frndint which rounds to nearest)
	case LLIL_FLOOR:
	case LLIL_CEIL:
	case LLIL_FTRUNC: // float->float, round towards zero (ppc fctiwz which rounds towards zero, and apparently fctiw is unimplemented)
	case LLIL_SX:
	case LLIL_ZX:
	case LLIL_LOW_PART:
	case LLIL_BOOL_TO_INT:
	case LLIL_FLOAT_TO_INT: // float->int, rounding unspecified (x86 lifter uses this for both cvtss2si and cvttss2si)
	case LLIL_INT_TO_FLOAT: // int->float
	case LLIL_FLOAT_CONV: // float->float, rounding unspecified (x86 lifter uses for cvtsd2ss and that depends on FPU status word)
		// TODO: do we want to check inputs look like ints / floats where relevant
		result &= CheckExprOperands(expr.GetSourceExpr());
		break;
	case LLIL_TEST_BIT:
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
	case LLIL_FCMP_E:
	case LLIL_FCMP_NE:
	case LLIL_FCMP_LT:
	case LLIL_FCMP_LE:
	case LLIL_FCMP_GE:
	case LLIL_FCMP_GT:
	case LLIL_FCMP_O:
	case LLIL_FCMP_UO:
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
	case LLIL_FADD:
	case LLIL_FSUB:
	case LLIL_FMUL:
	case LLIL_FDIV:
	case LLIL_ADD_OVERFLOW:
	case LLIL_LSL:
	case LLIL_LSR:
	case LLIL_ASR:
	case LLIL_ROL:
	case LLIL_ROR:
	case LLIL_MULS_DP:
	case LLIL_MULU_DP:
	case LLIL_DIVS_DP:
	case LLIL_DIVU_DP:
	case LLIL_MODS_DP:
	case LLIL_MODU_DP:
		// TODO: do we want to check inputs look like ints / floats where relevant
		result &= CheckExprOperands(expr.GetLeftExpr());
		result &= CheckExprOperands(expr.GetRightExpr());
		break;
	case LLIL_ADC:
	case LLIL_SBB:
	case LLIL_RLC:
	case LLIL_RRC:
		result &= CheckExprOperands(expr.GetLeftExpr());
		result &= CheckExprOperands(expr.GetRightExpr());
		result &= CheckExprOperands(expr.GetCarryExpr());
		break;
	default:
		m_logger->LogErrorF("Unhandled expr operation: {:?}", expr);
		break;
	}
	return result;
}

bool LowLevelILVerifier::Verify()
{
	/*
		Invariants:
		-[ ] All blocks either branch to existing blocks or terminate
		-[x] No jumping to entry block
		-[x] Sizes of expressions are consistent
		-[x] Base level instructions are of a limited subset of operations (setreg, call, etc)
		-[x] Child expressions are of a limited subset of operations (eg NOT goto)
		-[x] Expression parameters are in valid range
		-[x] Each expression has as most 1 parent
		-[ ] Expr address aligns with instruction
		-[x] Nothing in the flags attr except on lifted IL
		-[ ] JUMP_TO has unique targets
		-[ ] Lifted IL: not more than 1 pop per tree
		-[ ] Lifted IL: no conflicting flag writes in the same tree (dont have two subs in same instr)
		-[ ] (not possible through API) GetFlagWriteLowLevelIL when it resolves a flag calls the arch to get the value for a flag and that expr must not set flags

		(low priority)
		-[ ] suspiciously long expr tree
		-[ ] SSA should not version a subregister (no REG_SSA with subreg)

		(mlil)
		all register parameters to a call need to be in the llil ssa call param list
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

	// Check block layout
	auto entryBlock = m_il->GetBasicBlockForInstruction(0);
	if (!entryBlock)
	{
		m_logger->LogWarnF("no entry block for function");
		result = false;
	}
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (auto& outgoing: bb->GetOutgoingEdges())
		{
			// TODO: This is currently valid but we want this to eventually be lifted as a tailcall
			if (outgoing.target == entryBlock)
			{
				m_logger->LogDebugF("block {:#x} jumps to entry block", bb->GetStart());
//				result = false;
			}
		}
	}

	// Check exprs don't set flags
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (expr.flags != 0)
				{
					LogErrorF("Found flags set by LLIL expression (should only be set on Lifted IL): {:?}", expr);
					result = false;
				}
				return true;
			});
		}
	}

	// Check expr sizes
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			result &= CheckInstrSize(instr);
		}
	}

	// Check expr operands
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			result &= CheckExprOperands(instr);
		}
	}

	// Check exprs are where we expect them to be
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex ++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (auto found = g_instructionValidity.find(expr.operation); found != g_instructionValidity.end())
				{
					// We always check Non-SSA form (only the core generates SSA forms and I'd *like* to believe it is correct)
					if ((found->second & ValidInNonSSA) == 0)
					{
						result = false;
						m_logger->LogErrorF("Instruction {:?} is not valid in non-ssa form", expr);
					}
					if (expr.exprIndex == instr.exprIndex)
					{
						// TODO: In practice this happens due to bugs in the core's flags resolver
						// You get LLIL_FSUB as a root expression because we cannot determine that it is free of side effects
						// Also, apparently this could apply to basically _any_ expr operation because any expr could have side effects
						// rss used the example of "pop + pop"
						if ((found->second & ValidAsParent) == 0)
						{
							result = false;
							m_logger->LogDebugF("Instruction {:?} is not expected to be parent instruction", expr);
						}
					}
					else
					{
						if ((found->second & ValidAsChild) == 0)
						{
							result = false;
							m_logger->LogErrorF("Instruction {:?} is not valid as child instruction", expr);
						}
					}
				}
				else
				{
					result = false;
					m_logger->LogErrorF("Unknown instruction operation {:?}", expr);
				}
				return true;
			});
		}
	}

	// Check exprs are used at most once
	std::unordered_set<size_t> seenExprs;
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (seenExprs.insert(expr.exprIndex).second == false)
				{
					result = false;
					m_logger->LogErrorF("Expression {:?} used more than once", expr);
				}
				return true;
			});
		}
	}

	return result;
}

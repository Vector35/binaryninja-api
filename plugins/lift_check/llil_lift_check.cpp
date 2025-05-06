
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


LowLevelILVerifier::LowLevelILVerifier(
	BNFunctionGraphType graphType,
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function
):
	ILVerifier(graphType)
{
	m_il = function;
	m_arch = m_il->GetArchitecture();
}


LowLevelILVerifier::LowLevelILVerifier(Ref<LowLevelILFunction> function):
	LowLevelILVerifier(LowLevelILFunctionGraph, function)
{
}


void LowLevelILVerifier::CheckExprSize(const LowLevelILInstruction& expr, std::optional<size_t> requiredSize)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("{} " message, #condition, ## __VA_ARGS__)));   \
		}                                                                                 \
	}                                                                                     \
	while (false)

	switch (expr.operation)
	{
	case LLIL_NOP:
		break;
	case LLIL_LOAD:
	{
		if (requiredSize.has_value())
		{
			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			//  As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			//  namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			//  nightmare semantics on the upper 96 bits + 128 bits

			if (expr.size < *requiredSize)
			{
				m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, expr, fmt::format("loading only {:#x} bytes out of {:#x} byte memory", expr.size, *requiredSize)));
			}
			else
			{
				CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
			}
		}
		CHECK(expr.size != 0, "op should have a size");
		// TODO: Is this correct for eg arm64_32
		CheckExprSize(expr.GetSourceExpr<LLIL_LOAD>(), m_arch->GetAddressSize());
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
		if (LLIL_REG_IS_TEMP(reg))
		{
			if (auto found = m_tempRegSizes.find(reg); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == expr.size,
					"attempting to load {:#x} bytes out of {:#x} byte temporary register temp{} (first seen at {:?})",
					expr.size,
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(reg),
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("Using unknown/yet unseen temporary register temp{}", LLIL_GET_TEMP_REG_INDEX(reg))));
			}
		}
		else
		{
			auto info = m_arch->GetRegisterInfo(reg);

			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			//  As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			//  namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			//  nightmare semantics on the upper 96 bits + 128 bits
			if (expr.size < info.size)
			{
				m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, expr, fmt::format("loading only {:#x} bytes out of {:#x} byte register {}", expr.size, info.size, m_arch->GetRegisterName(reg))));
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
		if (LLIL_REG_IS_TEMP(hi))
		{
			if (auto found = m_tempRegSizes.find(hi); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == expr.size,
					"attempting to load {:#x} bytes out of {:#x} byte temporary register temp{} (first seen at {:?})",
					expr.size,
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(hi),
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("Using unknown/yet unseen temporary register temp{}", LLIL_GET_TEMP_REG_INDEX(hi))));
			}
		}
		else
		{
			auto info = m_arch->GetRegisterInfo(hi);
			CHECK(expr.size == info.size, "attempting to load {:#x} bytes out of a {:#x} byte hi register", expr.size, info.size);
		}
		auto lo = expr.GetLowRegister<LLIL_REG_SPLIT>();
		if (LLIL_REG_IS_TEMP(lo))
		{
			if (auto found = m_tempRegSizes.find(lo); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == expr.size,
					"attempting to load {:#x} bytes out of {:#x} byte temporary register temp{} (first seen at {:?})",
					expr.size,
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(lo),
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("Using unknown/yet unseen temporary register temp{}", LLIL_GET_TEMP_REG_INDEX(lo))));
			}
		}
		else
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
	case LLIL_FLAG_COND:
	{
		if (requiredSize.has_value())
		{
			CHECK(*requiredSize == 0, "op expecting to produce {:#x} byte value but should be producing boolean (0 size)", *requiredSize);
		}
		CHECK(expr.size == 0, "op should be boolean (0 size) but is {:#x} size", expr.size);
		break;
	}
	case LLIL_FLAG_GROUP:
	{
		if (requiredSize.has_value())
		{
			CHECK(*requiredSize == 0, "op expecting to produce {:#x} byte value but should be producing boolean (0 size)", *requiredSize);
		}
		CHECK(expr.size == 0, "op should be boolean (0 size) but is {:#x} size", expr.size);
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
		CheckExprSize(expr.GetLeftExpr<LLIL_TEST_BIT>(), expr.size);
		CheckExprSize(expr.GetRightExpr<LLIL_TEST_BIT>(), std::nullopt);
		break;
	}
	case LLIL_CMP_E:
	case LLIL_CMP_NE:
	{
		if (requiredSize.has_value() && *requiredSize != 0)
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where boolean (0 size) is expected", *requiredSize);
		}
		// CMP_E and CMP_NE can operate on flags and therefore can be a boolean (0 size)
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
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
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
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
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
		CheckExprSize(expr.GetCarryExpr(), 0);
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

		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), std::nullopt);
		CheckExprSize(expr.GetCarryExpr(), 0);
		break;
	}
	case LLIL_ADD:
	case LLIL_SUB:
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
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_AND:
	case LLIL_OR:
	case LLIL_XOR:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		// 0 size is a boolean operation, allowed
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
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

		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), std::nullopt);
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
		CheckExprSize(expr.GetLeftExpr(), expr.size);
		CheckExprSize(expr.GetRightExpr(), expr.size);
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
		CheckExprSize(expr.GetLeftExpr(), expr.size * 2);
		CheckExprSize(expr.GetRightExpr(), expr.size);
		break;
	}
	case LLIL_NEG:
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
		CheckExprSize(expr.GetSourceExpr(), expr.size);
		break;
	}
	case LLIL_NOT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		// 0 size is a boolean operation, allowed
		CheckExprSize(expr.GetSourceExpr(), expr.size);
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

		CheckExprSize(expr.GetSourceExpr(), std::nullopt);
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

		CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	case LLIL_BOOL_TO_INT:
	{
		if (requiredSize.has_value())
		{
			CHECK(expr.size == *requiredSize, "op producing {:#x} byte value where {:#x} bytes are expected", expr.size, *requiredSize);
		}
		CHECK(expr.size != 0, "op should have a size");

		CheckExprSize(expr.GetSourceExpr(), 0);
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
		CheckExprSize(expr.GetSourceExpr(), std::nullopt);
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
		CheckExprSize(expr.GetSourceExpr(), std::nullopt);
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

		CheckExprSize(expr.GetSourceExpr(), std::nullopt);
		break;
	}
	default:
	{
		m_diagnostics.push_back(Diagnostic::Diag(RemarkSeverity, this, "Unhandled expr operation"));
		break;
	}
	}
#undef CHECK
}


void LowLevelILVerifier::CheckInstrSize(const LowLevelILInstruction& instr)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_diagnostics.push_back(Diagnostic::Error(this, instr, fmt::format("{} " message, #condition, ## __VA_ARGS__)));   \
		}                                                                                 \
	}                                                                                     \
	while (false)


	switch (instr.operation)
	{
	case LLIL_NOP:
		break;
	case LLIL_SET_REG:
	{
		CHECK(instr.size != 0, "op should have a size");

		auto reg = instr.GetDestRegister<LLIL_SET_REG>();
		if (LLIL_REG_IS_TEMP(reg))
		{
			if (auto found = m_tempRegSizes.find(reg); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == instr.size,
					"setting {:#x} byte temporary register temp{} to {:#x} bytes (first seen at {:?})",
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(reg),
					instr.size,
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				TempRegisterInfo info;
				info.reg = reg;
				info.width = instr.size;
				info.seenExpr = instr.exprIndex;
				m_tempRegSizes.insert({ reg, info });
			}
		}
		else
		{
			auto info = m_arch->GetRegisterInfo(reg);

			// TODO: There is a bug in our x86 lifter that stems from having incomplete sub-register support
			//  As per discussion with rss, this is actually the "best" behavior in certain circumstances,
			//  namely x86's vmulss which operates on the low 32 bits of a 256 bit register and does
			//  nightmare semantics on the upper 96 bits + 128 bits
			if (info.size > instr.size)
			{
				m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, instr, fmt::format("setting {:#x} byte register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(reg), instr.size)));
			}
			else
			{
				CHECK(info.size == instr.size, "setting {:#x} byte register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(reg), instr.size);
			}
		}

		CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG>(), instr.size);
		break;
	}
	case LLIL_SET_REG_SPLIT:
	{
		CHECK(instr.size != 0, "op should have a size");
		auto hi = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (LLIL_REG_IS_TEMP(hi))
		{
			if (auto found = m_tempRegSizes.find(hi); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == instr.size,
					"setting {:#x} byte temporary register temp{} to {:#x} bytes (first seen at {:?})",
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(hi),
					instr.size,
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				TempRegisterInfo info;
				info.reg = hi;
				info.width = instr.size;
				info.seenExpr = instr.exprIndex;
				m_tempRegSizes.insert({ hi, info });
			}
		}
		else
		{
			auto info = m_arch->GetRegisterInfo(hi);
			CHECK(info.size == instr.size, "setting {:#x} byte hi register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(hi), instr.size);
		}
		auto lo = instr.GetHighRegister<LLIL_SET_REG_SPLIT>();
		if (LLIL_REG_IS_TEMP(lo))
		{
			if (auto found = m_tempRegSizes.find(lo); found != m_tempRegSizes.end())
			{
				CHECK(
					found->second.width == instr.size,
					"setting {:#x} byte temporary register temp{} to {:#x} bytes (first seen at {:?})",
					found->second.width,
					LLIL_GET_TEMP_REG_INDEX(lo),
					instr.size,
					m_il->GetExpr(found->second.seenExpr)
				);
			}
			else
			{
				TempRegisterInfo info;
				info.reg = lo;
				info.width = instr.size;
				info.seenExpr = instr.exprIndex;
				m_tempRegSizes.insert({ lo, info });
			}

		}
		else
		{
			auto info = m_arch->GetRegisterInfo(lo);
			CHECK(info.size == instr.size, "setting {:#x} byte lo register {} to {:#x} byte value", info.size, m_arch->GetRegisterName(lo), instr.size);
		}

		CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG_SPLIT>(), instr.size * 2);
		break;
	}
	case LLIL_SET_FLAG:
	{
		CHECK(instr.size == 0, "set flag size should be zero, is {:#x}", instr.size);
		CheckExprSize(instr.GetSourceExpr<LLIL_SET_FLAG>(), 0);
		break;
	}
	case LLIL_SET_REG_STACK_REL:
	{
		CHECK(instr.size != 0, "op should have a size");
		auto regStack = instr.GetDestRegisterStack<LLIL_SET_REG_STACK_REL>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(firstInfo.size == instr.size, "setting {:#x} byte register stack {} with {:#x} byte value", firstInfo.size, m_arch->GetRegisterStackName(regStack), instr.size);

		// TODO: Check relative offset in stack?
		CheckExprSize(instr.GetDestExpr<LLIL_SET_REG_STACK_REL>(), std::nullopt);
		CheckExprSize(instr.GetSourceExpr<LLIL_SET_REG_STACK_REL>(), instr.size);
		break;
	}
	case LLIL_REG_STACK_PUSH:
	{
		CHECK(instr.size != 0, "op should have a size");
		auto regStack = instr.GetDestRegisterStack<LLIL_REG_STACK_PUSH>();
		auto info = m_arch->GetRegisterStackInfo(regStack);
		auto firstReg = info.firstStorageReg;
		auto firstInfo = m_arch->GetRegisterInfo(firstReg);
		CHECK(firstInfo.size == instr.size, "pushing {:#x} byte register stack {} with {:#x} byte value", firstInfo.size, m_arch->GetRegisterStackName(regStack), instr.size);

		CheckExprSize(instr.GetSourceExpr<LLIL_REG_STACK_PUSH>(), instr.size);
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
		CheckExprSize(instr.GetDestExpr<LLIL_STORE>(), m_arch->GetAddressSize());
		CheckExprSize(instr.GetSourceExpr<LLIL_STORE>(), instr.size);
		break;
	}
	case LLIL_PUSH:
		CHECK(instr.size != 0, "pushing a 0 byte value");
		CheckExprSize(instr.GetSourceExpr<LLIL_PUSH>(), instr.size);
		break;
	case LLIL_REG_STACK_FREE_REG:
		break;
	case LLIL_REG_STACK_FREE_REL:
		// TODO: Check relative offset in stack?
		CheckExprSize(instr.GetDestExpr<LLIL_REG_STACK_FREE_REL>(), std::nullopt);
		break;
	case LLIL_JUMP:
		CheckExprSize(instr.GetDestExpr<LLIL_JUMP>(), std::nullopt);
		break;
	case LLIL_JUMP_TO:
		CheckExprSize(instr.GetDestExpr<LLIL_JUMP_TO>(), std::nullopt);
		break;
	case LLIL_CALL:
		CheckExprSize(instr.GetDestExpr<LLIL_CALL>(), std::nullopt);
		break;
	case LLIL_CALL_STACK_ADJUST:
		CheckExprSize(instr.GetDestExpr<LLIL_CALL_STACK_ADJUST>(), std::nullopt);
		break;
	case LLIL_TAILCALL:
		CheckExprSize(instr.GetDestExpr<LLIL_TAILCALL>(), std::nullopt);
		break;
	case LLIL_RET:
		CheckExprSize(instr.GetDestExpr<LLIL_RET>(), std::nullopt);
		break;
	case LLIL_NORET:
		break;
	case LLIL_IF:
		CheckExprSize(instr.GetConditionExpr<LLIL_IF>(), 0);
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
		CheckExprSize(instr, std::nullopt);
		break;
	}
#undef CHECK
}


void LowLevelILVerifier::CheckExprOperands(const BinaryNinja::LowLevelILInstruction& expr)
{
#define CHECK(condition, message, ...)                                                    \
	do                                                                                    \
	{                                                                                     \
		if (!(condition))                                                                 \
		{                                                                                 \
			m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("{} " message, #condition, ## __VA_ARGS__)));   \
		}                                                                                 \
	}                                                                                     \
	while (false)

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
		CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG>());
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
		CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG_SPLIT>());
		break;
	}
	case LLIL_SET_FLAG:
	{
		auto flag = expr.GetDestFlag<LLIL_SET_FLAG>();
		auto name = m_arch->GetFlagName(flag);
		CHECK(!name.empty(), "unknown flag index {}", flag);
		CheckExprOperands(expr.GetSourceExpr<LLIL_SET_FLAG>());
		break;
	}
	case LLIL_SET_REG_STACK_REL:
	{
		auto regStack = expr.GetDestRegisterStack<LLIL_SET_REG_STACK_REL>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		CheckExprOperands(expr.GetDestExpr<LLIL_SET_REG_STACK_REL>());
		CheckExprOperands(expr.GetSourceExpr<LLIL_SET_REG_STACK_REL>());
		break;
	}
	case LLIL_REG_STACK_PUSH:
	{
		auto regStack = expr.GetDestRegisterStack<LLIL_REG_STACK_PUSH>();
		auto name = m_arch->GetRegisterStackName(regStack);
		CHECK(!name.empty(), "unknown register stack index {}", regStack);
		CheckExprOperands(expr.GetSourceExpr<LLIL_REG_STACK_PUSH>());
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
		CheckExprOperands(expr.GetDestExpr<LLIL_STORE>());
		CheckExprOperands(expr.GetSourceExpr<LLIL_STORE>());
		break;
	case LLIL_PUSH:
		CheckExprOperands(expr.GetSourceExpr<LLIL_PUSH>());
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
		CheckExprOperands(expr.GetDestExpr<LLIL_REG_STACK_FREE_REL>());
		break;
	}
	case LLIL_JUMP:
		CheckExprOperands(expr.GetDestExpr<LLIL_JUMP>());
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
				m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("{} duplicate jump target value {}", value)));
			}
			if (!seenDests.insert(dest).second)
			{
				m_diagnostics.push_back(Diagnostic::Error(this, expr, fmt::format("{} duplicate jump target dest {}", dest)));
			}
		}
		CheckExprOperands(expr.GetDestExpr<LLIL_JUMP_TO>());
		break;
	}
	case LLIL_CALL:
		CheckExprOperands(expr.GetDestExpr<LLIL_CALL>());
		break;
	case LLIL_CALL_STACK_ADJUST:
	{
		for (auto& [regStack, offset]: expr.GetRegisterStackAdjustments<LLIL_CALL_STACK_ADJUST>())
		{
			auto name = m_arch->GetRegisterStackName(regStack);
			CHECK(!name.empty(), "unknown register stack index {}", regStack);
		}
		CheckExprOperands(expr.GetDestExpr<LLIL_CALL_STACK_ADJUST>());
		break;
	}
	case LLIL_TAILCALL:
		CheckExprOperands(expr.GetDestExpr<LLIL_TAILCALL>());
		break;
	case LLIL_RET:
		CheckExprOperands(expr.GetDestExpr<LLIL_RET>());
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
		CheckExprOperands(expr.GetConditionExpr<LLIL_IF>());
		break;
	}
	case LLIL_GOTO:
	{
		size_t instrCount = m_il->GetInstructionCount();
		size_t target = expr.GetTarget<LLIL_GOTO>();
		CHECK(target < instrCount, "target {} out of range of function with {} instructions", target, instrCount);
		auto targetBlock = m_il->GetBasicBlockForInstruction(target);
		CHECK(targetBlock != nullptr, "target {} has no basic block? (probably need to call Finalize again)", target);
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
			CheckExprOperands(input);
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
		CheckExprOperands(expr.GetSourceExpr<LLIL_UNIMPL_MEM>());
		break;
	case LLIL_LOAD:
		CheckExprOperands(expr.GetSourceExpr<LLIL_LOAD>());
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
		CheckExprOperands(expr.GetSourceExpr<LLIL_REG_STACK_REL>());
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
	case LLIL_FLAG_COND:
	{
		auto condition = expr.GetFlagCondition<LLIL_FLAG_COND>();
		CHECK(condition <= LLFC_FUO, "unknown flag condition {}", condition);
		auto semClass = expr.GetSemanticFlagClass<LLIL_FLAG_COND>();
		if (semClass != 0)
		{
			auto name = m_arch->GetSemanticFlagClassName(semClass);
			CHECK(!name.empty(), "unknown semantic flag class {}", semClass);
		}
		break;
	}
	case LLIL_FLAG_GROUP:
	{
		auto semGroup = expr.GetSemanticFlagGroup<LLIL_FLAG_GROUP>();
		auto name = m_arch->GetSemanticFlagGroupName(semGroup);
		CHECK(!name.empty(), "unknown semantic flag group {}", semGroup);
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
		CheckExprOperands(expr.GetSourceExpr());
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
		CheckExprOperands(expr.GetLeftExpr());
		CheckExprOperands(expr.GetRightExpr());
		break;
	case LLIL_ADC:
	case LLIL_SBB:
	case LLIL_RLC:
	case LLIL_RRC:
		CheckExprOperands(expr.GetLeftExpr());
		CheckExprOperands(expr.GetRightExpr());
		CheckExprOperands(expr.GetCarryExpr());
		break;
	default:
		m_diagnostics.push_back(Diagnostic::Error(this, expr, "Unhandled expr operation"));
		break;
	}
#undef CHECK
}


void LowLevelILVerifier::Verify()
{
	/*
		Invariants:
		-[-] All blocks either branch to existing blocks or terminate
		     (n/i for now)
		-[-] No jumping to entry block
		     (currently allowed)
		-[x] All blocks have source blocks
		-[x] Sizes of expressions are consistent
		-[-] Base level instructions are of a limited subset of operations (setreg, call, etc)
		     (they can technically be value expressions, e.g. subtractions, for setting flags)
		     (this feels like a bug, but it's apparently desired behavior)
		-[x] Child expressions are of a limited subset of operations (eg NOT goto)
		-[x] Expression parameters are in valid range
			-[x] JUMP_TO has unique targets
		-[-] Each expression has as most 1 parent
		     (flags resolver breaks this)
		-[x] Expr address aligns with instruction
		-[x] Nothing in the flags attr except on lifted IL
		     (apparently broken in x86 for x87.pop)
		(low priority)
		-[ ] suspiciously long expr tree
		     (not actually a bug, just sus)
		*/

	if (!m_il->GetFunction())
	{
		// Bare ILs don't matter
		m_diagnostics.push_back(Diagnostic::Error(this, "Not applicable to bare IL functions"));
		return;
	}
	if (m_il == m_il->GetSSAForm())
	{
		// TODO: SSA form
		m_diagnostics.push_back(Diagnostic::Error(this, "Not applicable to SSA forms"));
		return;
	}

	// Check block layout
	auto entryBlock = m_il->GetBasicBlockForInstruction(0);
	if (!entryBlock)
	{
		m_diagnostics.push_back(Diagnostic::Diag(WarningSeverity, this, "no entry block for function"));
	}
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (auto& outgoing: bb->GetOutgoingEdges())
		{
			auto source = bb->GetSourceBlock();
			if (!source)
			{
				m_diagnostics.push_back(Diagnostic::Error(this, fmt::format("block {}->{} has no source block? (probably need to call Finalize again or something)", bb->GetStart(), bb->GetEnd())));
				source = bb;
			}
			// TODO: This is currently valid but we want this to eventually be lifted as a tailcall
			if (outgoing.target == entryBlock)
			{
				m_diagnostics.push_back(Diagnostic::Diag(WarningSeverity, this, fmt::format("block {:#x}->{:#x} jumps to entry block (probably a bug in core's Finalize)", source->GetStart(), source->GetEnd())));
			}
		}
	}

	// Check expr sizes
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			CheckInstrSize(instr);
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
						m_diagnostics.push_back(Diagnostic::Error(this, expr, "Expression is not valid in non-ssa form"));
					}
					if (expr.exprIndex == instr.exprIndex)
					{
						// TODO: In practice this happens due to bugs in the core's flags resolver
						//  You get LLIL_FSUB as a root expression because we cannot determine that it is free of side effects
						//  Also, apparently this could apply to basically _any_ expr operation because any expr could have side effects
						//  rss used the example of "pop + pop"
						if ((found->second & ValidAsParent) == 0)
						{
							m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, expr, "Expression is not expected to be parent instruction"));
						}
					}
					else
					{
						if ((found->second & ValidAsChild) == 0)
						{
							m_diagnostics.push_back(Diagnostic::Error(this, expr, "Instruction is not valid as child expression"));
						}
					}
				}
				else
				{
					m_diagnostics.push_back(Diagnostic::Error(this, expr, "Unknown expression operation"));
				}
				return true;
			});
		}
	}

	// Check expr operands
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			CheckExprOperands(instr);
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
					// TODO: This is sometimes due to a bug in FlagsResolver
					//  where it doesn't duplicate the expressions used in the condition
					m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, expr, "Expression used more than once (probably a bug in core's FlagsResolver)"));
				}
				return true;
			});
		}
	}

	// Check exprs have addresses
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (expr.address == 0)
				{
					m_diagnostics.push_back(Diagnostic::Error(this, expr, "Found expression with no address"));
				}
				return true;
			});
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
					m_diagnostics.push_back(Diagnostic::Error(this,  expr, "Found flags set by LLIL expression (should only be set on Lifted IL)"));
				}
				return true;
			});
		}
	}
}


#include "lifted_il_lift_check.h"

using namespace BinaryNinja;

enum
{
	ValidInNonSSA = 1 << 0,
	ValidAsParent = 1 << 1,
	ValidAsChild  = 1 << 2,
};

static std::unordered_map<BNLowLevelILOperation, int> g_instructionValidity = {{
	{ LLIL_NOP,                          ValidInNonSSA | ValidAsParent | ValidAsChild },
	{ LLIL_SET_REG,                      ValidInNonSSA | ValidAsParent                },
	{ LLIL_SET_REG_SPLIT,                ValidInNonSSA | ValidAsParent                },
	{ LLIL_SET_FLAG,                     ValidInNonSSA | ValidAsParent                },
	{ LLIL_SET_REG_STACK_REL,            ValidInNonSSA | ValidAsParent                },
	{ LLIL_REG_STACK_PUSH,               ValidInNonSSA | ValidAsParent                },
	{ LLIL_ASSERT,                       0 |             ValidAsParent                },
	{ LLIL_FORCE_VER,                    0 |             ValidAsParent                },
	{ LLIL_LOAD,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_STORE,                        ValidInNonSSA | ValidAsParent                },
	{ LLIL_PUSH,                         ValidInNonSSA | ValidAsParent                },
	{ LLIL_POP,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_REG,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_REG_SPLIT,                    ValidInNonSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_REL,                ValidInNonSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_POP,                ValidInNonSSA |                 ValidAsChild },
	{ LLIL_REG_STACK_FREE_REG,           ValidInNonSSA | ValidAsParent                },
	{ LLIL_REG_STACK_FREE_REL,           ValidInNonSSA | ValidAsParent                },
	{ LLIL_CONST,                        ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CONST_PTR,                    ValidInNonSSA |                 ValidAsChild },
	{ LLIL_EXTERN_PTR,                   ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLOAT_CONST,                  ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLAG,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLAG_BIT,                     ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ADD,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ADC,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_SUB,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_SBB,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_AND,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_OR,                           ValidInNonSSA |                 ValidAsChild },
	{ LLIL_XOR,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_LSL,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_LSR,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ASR,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ROL,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_RLC,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ROR,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_RRC,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MUL,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MULU_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MULS_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_DIVU,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_DIVU_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_DIVS,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_DIVS_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MODU,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MODU_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MODS,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_MODS_DP,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_NEG,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_NOT,                          ValidInNonSSA |                 ValidAsChild },
	{ LLIL_SX,                           ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ZX,                           ValidInNonSSA |                 ValidAsChild },
	{ LLIL_LOW_PART,                     ValidInNonSSA |                 ValidAsChild },
	{ LLIL_JUMP,                         ValidInNonSSA | ValidAsParent                },
	{ LLIL_JUMP_TO,                      ValidInNonSSA | ValidAsParent                },
	{ LLIL_CALL,                         ValidInNonSSA | ValidAsParent                },
	{ LLIL_CALL_STACK_ADJUST,            0 |             ValidAsParent                },
	{ LLIL_TAILCALL,                     ValidInNonSSA | ValidAsParent                },
	{ LLIL_RET,                          ValidInNonSSA | ValidAsParent                },
	{ LLIL_NORET,                        ValidInNonSSA | ValidAsParent                },
	{ LLIL_IF,                           ValidInNonSSA | ValidAsParent                },
	{ LLIL_GOTO,                         ValidInNonSSA | ValidAsParent                },
	{ LLIL_FLAG_COND,                    ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLAG_GROUP,                   ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_E,                        ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_NE,                       ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_SLT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_ULT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_SLE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_ULE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_SGE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_UGE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_SGT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CMP_UGT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_TEST_BIT,                     ValidInNonSSA |                 ValidAsChild },
	{ LLIL_BOOL_TO_INT,                  ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ADD_OVERFLOW,                 ValidInNonSSA |                 ValidAsChild },
	{ LLIL_SYSCALL,                      ValidInNonSSA | ValidAsParent                },
	{ LLIL_BP,                           ValidInNonSSA | ValidAsParent                },
	{ LLIL_TRAP,                         ValidInNonSSA | ValidAsParent                },
	{ LLIL_INTRINSIC,                    ValidInNonSSA | ValidAsParent                },
	{ LLIL_UNDEF,                        ValidInNonSSA | ValidAsParent | ValidAsChild },
	{ LLIL_UNIMPL,                       ValidInNonSSA | ValidAsParent | ValidAsChild },
	{ LLIL_UNIMPL_MEM,                   ValidInNonSSA | ValidAsParent | ValidAsChild },
	{ LLIL_FADD,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FSUB,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FMUL,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FDIV,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FSQRT,                        ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FNEG,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FABS,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLOAT_TO_INT,                 ValidInNonSSA |                 ValidAsChild },
	{ LLIL_INT_TO_FLOAT,                 ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLOAT_CONV,                   ValidInNonSSA |                 ValidAsChild },
	{ LLIL_ROUND_TO_INT,                 ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FLOOR,                        ValidInNonSSA |                 ValidAsChild },
	{ LLIL_CEIL,                         ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FTRUNC,                       ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_E,                       ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_NE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_LT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_LE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_GE,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_GT,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_O,                       ValidInNonSSA |                 ValidAsChild },
	{ LLIL_FCMP_UO,                      ValidInNonSSA |                 ValidAsChild },
	{ LLIL_SET_REG_SSA,                  0 |             ValidAsParent                },
	{ LLIL_SET_REG_SSA_PARTIAL,          0 |             ValidAsParent                },
	{ LLIL_SET_REG_SPLIT_SSA,            0 |             ValidAsParent                },
	{ LLIL_SET_REG_STACK_REL_SSA,        0 |             ValidAsParent                },
	{ LLIL_SET_REG_STACK_ABS_SSA,        0 |             ValidAsParent                },
	{ LLIL_REG_SPLIT_DEST_SSA,           0 |                             ValidAsChild },
	{ LLIL_REG_STACK_DEST_SSA,           0 |                             ValidAsChild },
	{ LLIL_REG_SSA,                      0 |                             ValidAsChild },
	{ LLIL_REG_SSA_PARTIAL,              0 |                             ValidAsChild },
	{ LLIL_REG_SPLIT_SSA,                0 |                             ValidAsChild },
	{ LLIL_REG_STACK_REL_SSA,            0 |                             ValidAsChild },
	{ LLIL_REG_STACK_ABS_SSA,            0 |                             ValidAsChild },
	{ LLIL_REG_STACK_FREE_REL_SSA,       0 |             ValidAsParent                },
	{ LLIL_REG_STACK_FREE_ABS_SSA,       0 |             ValidAsParent                },
	{ LLIL_SET_FLAG_SSA,                 0 |             ValidAsParent                },
	{ LLIL_ASSERT_SSA,                   0 |             ValidAsParent                },
	{ LLIL_FORCE_VER_SSA,                0 |             ValidAsParent                },
	{ LLIL_FLAG_SSA,                     0 |                             ValidAsChild },
	{ LLIL_FLAG_BIT_SSA,                 0 |                             ValidAsChild },
	{ LLIL_CALL_SSA,                     0 |             ValidAsParent                },
	{ LLIL_SYSCALL_SSA,                  0 |             ValidAsParent                },
	{ LLIL_TAILCALL_SSA,                 0 |             ValidAsParent                },
	{ LLIL_CALL_PARAM,                   0 |                             ValidAsChild },
	{ LLIL_CALL_STACK_SSA,               0 |                             ValidAsChild },
	{ LLIL_CALL_OUTPUT_SSA,              0 |                             ValidAsChild },
	{ LLIL_SEPARATE_PARAM_LIST_SSA,      0 |                             ValidAsChild },
	{ LLIL_SHARED_PARAM_SLOT_SSA,        0 |                             ValidAsChild },
	{ LLIL_MEMORY_INTRINSIC_OUTPUT_SSA,  0 |                             ValidAsChild },
	{ LLIL_LOAD_SSA,                     0 |                             ValidAsChild },
	{ LLIL_STORE_SSA,                    0 |             ValidAsParent                },
	{ LLIL_INTRINSIC_SSA,                0 |             ValidAsParent                },
	{ LLIL_MEMORY_INTRINSIC_SSA,         0 |             ValidAsParent                },
	{ LLIL_REG_PHI,                      0 |             ValidAsParent                },
	{ LLIL_REG_STACK_PHI,                0 |             ValidAsParent                },
	{ LLIL_FLAG_PHI,                     0 |             ValidAsParent                },
	{ LLIL_MEM_PHI,                      0 |                             ValidAsChild }
}};

LiftedILVerifier::LiftedILVerifier(BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> function):
	LowLevelILVerifier(function)
{

}


size_t LiftedILVerifier::GetTreePopCount(const BinaryNinja::LowLevelILInstruction& expr)
{
	size_t popCount = 0;
	expr.VisitExprs([&](const LowLevelILInstruction& subExpr) {
		if (subExpr.operation == LLIL_POP)
		{
			popCount++;
		}
		return true;
	});
	return popCount;
}


size_t LiftedILVerifier::GetTreeFlagWriteCount(const BinaryNinja::LowLevelILInstruction& expr)
{
	size_t flagWriteCount = 0;
	expr.VisitExprs([&](const LowLevelILInstruction& subExpr) {
		if (subExpr.flags != 0)
		{
			flagWriteCount++;
		}
		return true;
	});
	return flagWriteCount;
}


void LiftedILVerifier::Verify()
{
	/*
		Invariants:
		-[-] All blocks either branch to existing blocks or terminate
		     (n/i for now)
		-[-] No jumping to entry block
		     (currently allowed)
		-[x] All blocks have source blocks
		-[x] Sizes of expressions are consistent
		-[x] Base level instructions are of a limited subset of operations (setreg, call, etc) or set flags
		-[x] Child expressions are of a limited subset of operations (eg NOT goto)
		-[x] Expression parameters are in valid range
			-[x] JUMP_TO has unique targets
		-[x] Each expression has as most 1 parent
		-[x] Expr address aligns with instruction
		(low priority)
		-[ ] suspiciously long expr tree
		     (not actually a bug, just sus)
		-[x] not more than 1 pop per tree
		-[x] no conflicting flag writes in the same tree (don't have two subs in same instr)
		-[ ] (not possible through API) GetFlagWriteLowLevelIL when it resolves a flag calls the arch to get the value for a flag and that expr must not set flags
	*/
	if (!m_il->GetFunction())
	{
		// Bare ILs don't matter
		m_diagnostics.push_back(Diagnostic::Error(this, "Not applicable to bare IL functions"));
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
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			instr.VisitExprs([&](const LowLevelILInstruction& expr) {
				if (auto found = g_instructionValidity.find(expr.operation); found != g_instructionValidity.end())
				{
					// We always check Non-SSA form (no Lifted IL SSA)
					if ((found->second & ValidInNonSSA) == 0)
					{
						m_diagnostics.push_back(Diagnostic::Error(this, expr, "Expression is not valid in non-ssa form"));
					}
					if (expr.exprIndex == instr.exprIndex)
					{
						if ((found->second & ValidAsParent) == 0 && expr.flags == 0)
						{
							m_diagnostics.push_back(Diagnostic::Diag(WarningSeverity, this, expr, "Expression is not expected to be parent instruction without setting flags"));
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
					m_diagnostics.push_back(Diagnostic::Error(this, expr, "Expression used more than once"));
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

	// Check not more than 1 pop per tree
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			if (GetTreePopCount(instr) > 1)
			{
				m_diagnostics.push_back(Diagnostic::Error(this, instr, "Found more than 1 pop in instruction"));
			}
		}
	}

	// Check not more than 1 flag write per tree
	for (auto& bb: m_il->GetBasicBlocks())
	{
		for (size_t instrIndex = bb->GetStart(); instrIndex != bb->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			if (GetTreeFlagWriteCount(instr) > 1)
			{
				m_diagnostics.push_back(Diagnostic::Error(this, instr, "Found more than 1 flag write in instruction"));
			}
		}
	}
}

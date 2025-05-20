
#include "mlil_lift_check.h"

using namespace BinaryNinja;

enum
{
	ValidInNonSSA = 1 << 0,
	ValidInSSA    = 1 << 1,
	ValidAsParent = 1 << 2,
	ValidAsChild  = 1 << 3,
};

static std::unordered_map<BNMediumLevelILOperation, int> g_instructionValidity = {{
	{ MLIL_NOP,                         ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ MLIL_SET_VAR,                     ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_SET_VAR_FIELD,               ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_SET_VAR_SPLIT,               ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_ASSERT,                      ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_FORCE_VER,                   ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_LOAD,                        ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_LOAD_STRUCT,                 ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_STORE,                       ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_STORE_STRUCT,                ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_VAR,                         ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_VAR_FIELD,                   ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_VAR_SPLIT,                   ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_ADDRESS_OF,                  ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ADDRESS_OF_FIELD,            ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CONST,                       ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CONST_DATA,                  ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CONST_PTR,                   ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_EXTERN_PTR,                  ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FLOAT_CONST,                 ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_IMPORT,                      ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ADD,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ADC,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SUB,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SBB,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_AND,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_OR,                          ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_XOR,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_LSL,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_LSR,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ASR,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ROL,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_RLC,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ROR,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_RRC,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MUL,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MULU_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MULS_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_DIVU,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_DIVU_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_DIVS,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_DIVS_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MODU,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MODU_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MODS,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MODS_DP,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_NEG,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_NOT,                         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SX,                          ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ZX,                          ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_LOW_PART,                    ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_JUMP,                        ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_JUMP_TO,                     ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_RET_HINT,                    0             | 0          | ValidAsParent | 0            },
	{ MLIL_CALL,                        ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_CALL_UNTYPED,                ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_CALL_OUTPUT,                 ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_CALL_PARAM,                  ValidInNonSSA | 0          | 0             | ValidAsChild },
	{ MLIL_SEPARATE_PARAM_LIST,         ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SHARED_PARAM_SLOT,           ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_RET,                         ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_NORET,                       ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_IF,                          ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_GOTO,                        ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_CMP_E,                       ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_NE,                      ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_SLT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_ULT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_SLE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_ULE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_SGE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_UGE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_SGT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CMP_UGT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_TEST_BIT,                    ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_BOOL_TO_INT,                 ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ADD_OVERFLOW,                ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SYSCALL,                     ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_SYSCALL_UNTYPED,             ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_TAILCALL,                    ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_TAILCALL_UNTYPED,            ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_INTRINSIC,                   ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_FREE_VAR_SLOT,               ValidInNonSSA | 0          | ValidAsParent | 0            },
	{ MLIL_BP,                          ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_TRAP,                        ValidInNonSSA | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_UNDEF,                       ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ MLIL_UNIMPL,                      ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ MLIL_UNIMPL_MEM,                  ValidInNonSSA | ValidInSSA | ValidAsParent | ValidAsChild },
	{ MLIL_FADD,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FSUB,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FMUL,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FDIV,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FSQRT,                       ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FNEG,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FABS,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FLOAT_TO_INT,                ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_INT_TO_FLOAT,                ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FLOAT_CONV,                  ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ROUND_TO_INT,                ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FLOOR,                       ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CEIL,                        ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FTRUNC,                      ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_E,                      ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_NE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_LT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_LE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_GE,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_GT,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_O,                      ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_FCMP_UO,                     ValidInNonSSA | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_SET_VAR_SSA,                 0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SET_VAR_SSA_FIELD,           0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SET_VAR_SPLIT_SSA,           0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SET_VAR_ALIASED,             0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SET_VAR_ALIASED_FIELD,       0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_VAR_SSA,                     0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_VAR_SSA_FIELD,               0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_VAR_ALIASED,                 0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_VAR_ALIASED_FIELD,           0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_VAR_SPLIT_SSA,               0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_ASSERT_SSA,                  0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_FORCE_VER_SSA,               0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_CALL_SSA,                    0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_CALL_UNTYPED_SSA,            0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SYSCALL_SSA,                 0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_SYSCALL_UNTYPED_SSA,         0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_TAILCALL_SSA,                0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_TAILCALL_UNTYPED_SSA,        0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_CALL_PARAM_SSA,              0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_CALL_OUTPUT_SSA,             0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_MEMORY_INTRINSIC_OUTPUT_SSA, 0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_LOAD_SSA,                    0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_LOAD_STRUCT_SSA,             0             | ValidInSSA | 0             | ValidAsChild },
	{ MLIL_STORE_SSA,                   0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_STORE_STRUCT_SSA,            0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_INTRINSIC_SSA,               0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_MEMORY_INTRINSIC_SSA,        0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_FREE_VAR_SLOT_SSA,           0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_VAR_PHI,                     0             | ValidInSSA | ValidAsParent | 0            },
	{ MLIL_MEM_PHI,                     0             | ValidInSSA | ValidAsParent | 0            },
}};

MediumLevelILVerifier::MediumLevelILVerifier(
	BNFunctionGraphType graphType,
	Ref<MediumLevelILFunction> function
): ILVerifier(graphType)
{
	m_il = function;
	m_arch = m_il->GetArchitecture();
}


MediumLevelILVerifier::MediumLevelILVerifier(Ref<MediumLevelILFunction> function):
	MediumLevelILVerifier(MediumLevelILFunctionGraph, function)
{
}


Ref<Type> DerefNamedTypeReference(Ref<BinaryView> bv, Ref<Type> type)
{
	if (!type)
		return type;

	std::unordered_set<QualifiedName> seen;
	while (type->IsNamedTypeRefer())
	{
		// Check for NTR cycle
		if (!seen.insert(type->GetNamedTypeReference()->GetName()).second)
		{
			break;
		}
		auto target = bv->GetTypeByRef(type->GetNamedTypeReference());
		// If the type doesn't exist, just refer to the NTR (it's the best we can do)
		if (target)
		{
			// Otherwise, deref and keep going
			type = target;
		}
	}
	// (the core impl of this has a section for offset pointers, assuming we don't care here)
	// (if this comes back to bite you later, haha ouch)
	return type;
}


void MediumLevelILVerifier::CheckExprSize(const MediumLevelILInstruction& expr, std::optional<size_t> requiredSize)
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

#undef CHECK
}


void MediumLevelILVerifier::CheckInstrSize(const MediumLevelILInstruction& instr)
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
	case MLIL_NOP:
		break;
	case MLIL_SET_VAR:
	{
		// var = (...)
		auto var = instr.GetDestVariable<MLIL_SET_VAR>();

		auto varType = DerefNamedTypeReference(m_il->GetFunction()->GetView(), m_il->GetFunction()->GetVariableType(var));
		CHECK(varType, "variable {} has a type", m_il->GetFunction()->GetVariableNameOrDefault(var));

		auto varSize = 0;
		if (varType)
		{
			varSize = varType->IsBool() ? 0 : varType->GetWidth();
		}

		CheckExprSize(instr.GetSourceExpr<MLIL_SET_VAR>(), varSize);
		break;
	}
	case MLIL_SET_VAR_FIELD:
	{
		// var:x.y = (...).y
		// set bytes (x ..< x+y) on var, so dest is y bytes and var can be anything
		auto var = instr.GetDestVariable<MLIL_SET_VAR_FIELD>();
		auto offset = instr.GetOffset<MLIL_SET_VAR_FIELD>();

		auto varType = DerefNamedTypeReference(m_il->GetFunction()->GetView(), m_il->GetFunction()->GetVariableType(var));
		CHECK(varType, "variable {} has a type", m_il->GetFunction()->GetVariableNameOrDefault(var));

		if (varType)
		{
			auto varSize = varType->IsBool() ? 0 : varType->GetWidth();
			CHECK(offset < varSize, "setting offset {:#x} out of bounds in variable of size {:#x}", offset, varSize);
		}

		CheckExprSize(instr.GetSourceExpr<MLIL_SET_VAR_FIELD>(), instr.size);
		break;
	}
	case MLIL_SET_VAR_SPLIT:
	{
		// (high:low).2x = (...).2x
		// where x is size of instr, high and low are x bytes, even though the actual write is 2x
		auto high = instr.GetHighVariable<MLIL_SET_VAR_SPLIT>();
		auto low = instr.GetLowVariable<MLIL_SET_VAR_SPLIT>();

		auto highType = DerefNamedTypeReference(m_il->GetFunction()->GetView(), m_il->GetFunction()->GetVariableType(high));
		CHECK(highType, "variable {} has a type", m_il->GetFunction()->GetVariableNameOrDefault(high));

		auto lowType = DerefNamedTypeReference(m_il->GetFunction()->GetView(), m_il->GetFunction()->GetVariableType(low));
		CHECK(lowType, "variable {} has a type", m_il->GetFunction()->GetVariableNameOrDefault(low));

		// Split bools is not a thing
		CHECK(instr.size != 0, "op should have a size");

		if (highType && lowType)
		{
			CHECK(!highType->IsBool(), "cannot set split vars with bools");
			CHECK(!lowType->IsBool(), "cannot set split vars with bools");

			CHECK(highType->GetWidth() == lowType->GetWidth(), "setting split vars {} and {} of mismatching sizes {:#x} and {:#x}", m_il->GetFunction()->GetVariableNameOrDefault(high), m_il->GetFunction()->GetVariableNameOrDefault(low), highType->GetWidth(), lowType->GetWidth());
		}

		CheckExprSize(instr.GetSourceExpr<MLIL_SET_VAR_SPLIT>(), instr.size * 2);
		break;
	}
	case MLIL_ASSERT:
		// assert(var, pvs) we can't really do anything about this
		break;
	case MLIL_FORCE_VER:
		// var#2 = var#1 is a no-op in terms of size
		break;
	case MLIL_STORE:
	{
		// [expr].x = (...).x
		CHECK(instr.size != 0, "op should have a size");

		// TODO: Is this correct for eg arm64_32
		CheckExprSize(instr.GetDestExpr<MLIL_STORE>(), m_arch->GetAddressSize());
		CheckExprSize(instr.GetSourceExpr<MLIL_STORE>(), instr.size);
		break;
	}
	case MLIL_STORE_STRUCT:
	{
		// expr->foo.x = (...).x
		// expr has to have the type of a structure
		// can't check that the foo field actually exists because it could be __offset(xxx)

		// Pretty sure you can't store struct a flag
		CHECK(instr.size != 0, "op should have a size");

		auto dest = instr.GetDestExpr<MLIL_STORE_STRUCT>();
		auto destType = m_il->GetExprType(dest);
		CHECK(destType, "store struct dest should have a type");
		CHECK(destType->IsPointer(), "store struct should be storing to a pointer to struct");

		auto destDeref = destType->GetChildType();
		auto destStruct = DerefNamedTypeReference(m_il->GetFunction()->GetView(), destDeref);
		CHECK(destStruct, "store struct should be pointing to a struct");
		CHECK(destStruct->IsStructure(), "store struct should be pointer to struct, not {:?}", destStruct);

		CheckExprSize(instr.GetSourceExpr<MLIL_STORE_STRUCT>(), instr.size);
		break;
	}
	case MLIL_JUMP:
	case MLIL_JUMP_TO:
	case MLIL_RET_HINT:
	case MLIL_CALL:
	case MLIL_CALL_UNTYPED:
	case MLIL_RET:
	case MLIL_NORET:
	case MLIL_IF:
	case MLIL_GOTO:
	case MLIL_SYSCALL:
	case MLIL_SYSCALL_UNTYPED:
	case MLIL_TAILCALL:
	case MLIL_TAILCALL_UNTYPED:
	case MLIL_INTRINSIC:
	case MLIL_FREE_VAR_SLOT:
	case MLIL_BP:
	case MLIL_TRAP:
	case MLIL_UNDEF:
	case MLIL_UNIMPL:
	case MLIL_UNIMPL_MEM:
		m_diagnostics.push_back(Diagnostic::Diag(NoteSeverity, this, instr, "Unimplemented"));
		break;
	default:
		return CheckExprSize(instr, std::nullopt);
	}

#undef CHECK
}


void MediumLevelILVerifier::CheckExprOperands(const MediumLevelILInstruction& expr)
{

}


void MediumLevelILVerifier::Verify()
{
	/*
		Invariants:
		-[-] All blocks either branch to existing blocks or terminate
		     (n/i for now)
		-[-] No jumping to entry block
		     (currently allowed)
		-[x] All blocks have source blocks
		-[ ] Sizes of expressions are consistent
		-[ ] Base level instructions are of a limited subset of operations (setreg, call, etc)
		     (they can technically be value expressions, e.g. subtractions, for setting flags)
		     (this feels like a bug, but it's apparently desired behavior)
		-[ ] Child expressions are of a limited subset of operations (eg NOT goto)
		-[ ] Expression parameters are in valid range
		-[ ] Each expression has as most 1 parent
		     (flags resolver breaks this)
		-[ ] Expr address aligns with instruction
			-[ ] Mappings exist LLIL<->MLIL and line up
		-[ ] All register parameters to a call need to be in llil ssa call param list
	 */
	if (m_il == m_il->GetSSAForm())
	{
		// Not checking SSA forms, because they cannot be modified by customer code
		// and are our internal problem to deal with :)
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
			MediumLevelILInstruction instr = m_il->GetInstruction(instrIndex);
			CheckInstrSize(instr);
		}
	}

}

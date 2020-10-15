#include <stdio.h>
#include <inttypes.h>
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


#ifndef _WIN32
#include <libgen.h>
#include <dlfcn.h>
static string GetPluginsDirectory()
{
	Dl_info info;
	if (!dladdr((void *)BNGetBundledPluginDirectory, &info))
		return NULL;

	stringstream ss;
	ss << dirname((char *)info.dli_fname) << "/plugins/";
	return ss.str();
}
#else
static string GetPluginsDirectory()
{
	return "C:\\Program Files\\Vector35\\BinaryNinja\\plugins\\";
}
#endif


static void PrintIndent(size_t indent)
{
	for (size_t i = 0; i < indent; i++)
		printf("    ");
}


static void PrintOperation(BNMediumLevelILOperation operation)
{
#define ENUM_PRINTER(op) \
	case op: \
		printf(#op); \
		break;

	switch (operation)
	{
	ENUM_PRINTER(MLIL_NOP)
	ENUM_PRINTER(MLIL_SET_VAR)
	ENUM_PRINTER(MLIL_SET_VAR_FIELD)
	ENUM_PRINTER(MLIL_SET_VAR_SPLIT)
	ENUM_PRINTER(MLIL_LOAD)
	ENUM_PRINTER(MLIL_LOAD_STRUCT)
	ENUM_PRINTER(MLIL_STORE)
	ENUM_PRINTER(MLIL_STORE_STRUCT)
	ENUM_PRINTER(MLIL_VAR)
	ENUM_PRINTER(MLIL_VAR_FIELD)
	ENUM_PRINTER(MLIL_ADDRESS_OF)
	ENUM_PRINTER(MLIL_ADDRESS_OF_FIELD)
	ENUM_PRINTER(MLIL_CONST)
	ENUM_PRINTER(MLIL_CONST_PTR)
	ENUM_PRINTER(MLIL_EXTERN_PTR)
	ENUM_PRINTER(MLIL_ADD)
	ENUM_PRINTER(MLIL_ADC)
	ENUM_PRINTER(MLIL_SUB)
	ENUM_PRINTER(MLIL_SBB)
	ENUM_PRINTER(MLIL_AND)
	ENUM_PRINTER(MLIL_OR)
	ENUM_PRINTER(MLIL_XOR)
	ENUM_PRINTER(MLIL_LSL)
	ENUM_PRINTER(MLIL_LSR)
	ENUM_PRINTER(MLIL_ASR)
	ENUM_PRINTER(MLIL_ROL)
	ENUM_PRINTER(MLIL_RLC)
	ENUM_PRINTER(MLIL_ROR)
	ENUM_PRINTER(MLIL_RRC)
	ENUM_PRINTER(MLIL_MUL)
	ENUM_PRINTER(MLIL_MULU_DP)
	ENUM_PRINTER(MLIL_MULS_DP)
	ENUM_PRINTER(MLIL_DIVU)
	ENUM_PRINTER(MLIL_DIVU_DP)
	ENUM_PRINTER(MLIL_DIVS)
	ENUM_PRINTER(MLIL_DIVS_DP)
	ENUM_PRINTER(MLIL_MODU)
	ENUM_PRINTER(MLIL_MODU_DP)
	ENUM_PRINTER(MLIL_MODS)
	ENUM_PRINTER(MLIL_MODS_DP)
	ENUM_PRINTER(MLIL_NEG)
	ENUM_PRINTER(MLIL_NOT)
	ENUM_PRINTER(MLIL_SX)
	ENUM_PRINTER(MLIL_ZX)
	ENUM_PRINTER(MLIL_LOW_PART)
	ENUM_PRINTER(MLIL_JUMP)
	ENUM_PRINTER(MLIL_JUMP_TO)
	ENUM_PRINTER(MLIL_CALL)
	ENUM_PRINTER(MLIL_CALL_UNTYPED)
	ENUM_PRINTER(MLIL_CALL_OUTPUT)
	ENUM_PRINTER(MLIL_CALL_PARAM)
	ENUM_PRINTER(MLIL_RET)
	ENUM_PRINTER(MLIL_NORET)
	ENUM_PRINTER(MLIL_IF)
	ENUM_PRINTER(MLIL_GOTO)
	ENUM_PRINTER(MLIL_CMP_E)
	ENUM_PRINTER(MLIL_CMP_NE)
	ENUM_PRINTER(MLIL_CMP_SLT)
	ENUM_PRINTER(MLIL_CMP_ULT)
	ENUM_PRINTER(MLIL_CMP_SLE)
	ENUM_PRINTER(MLIL_CMP_ULE)
	ENUM_PRINTER(MLIL_CMP_SGE)
	ENUM_PRINTER(MLIL_CMP_UGE)
	ENUM_PRINTER(MLIL_CMP_SGT)
	ENUM_PRINTER(MLIL_CMP_UGT)
	ENUM_PRINTER(MLIL_TEST_BIT)
	ENUM_PRINTER(MLIL_BOOL_TO_INT)
	ENUM_PRINTER(MLIL_ADD_OVERFLOW)
	ENUM_PRINTER(MLIL_SYSCALL)
	ENUM_PRINTER(MLIL_SYSCALL_UNTYPED)
	ENUM_PRINTER(MLIL_TAILCALL)
	ENUM_PRINTER(MLIL_TAILCALL_UNTYPED)
	ENUM_PRINTER(MLIL_BP)
	ENUM_PRINTER(MLIL_TRAP)
	ENUM_PRINTER(MLIL_UNDEF)
	ENUM_PRINTER(MLIL_UNIMPL)
	ENUM_PRINTER(MLIL_UNIMPL_MEM)
	ENUM_PRINTER(MLIL_SET_VAR_SSA)
	ENUM_PRINTER(MLIL_SET_VAR_SSA_FIELD)
	ENUM_PRINTER(MLIL_SET_VAR_SPLIT_SSA)
	ENUM_PRINTER(MLIL_SET_VAR_ALIASED)
	ENUM_PRINTER(MLIL_SET_VAR_ALIASED_FIELD)
	ENUM_PRINTER(MLIL_VAR_SSA)
	ENUM_PRINTER(MLIL_VAR_SSA_FIELD)
	ENUM_PRINTER(MLIL_VAR_ALIASED)
	ENUM_PRINTER(MLIL_VAR_ALIASED_FIELD)
	ENUM_PRINTER(MLIL_CALL_SSA)
	ENUM_PRINTER(MLIL_CALL_UNTYPED_SSA)
	ENUM_PRINTER(MLIL_SYSCALL_SSA)
	ENUM_PRINTER(MLIL_SYSCALL_UNTYPED_SSA)
	ENUM_PRINTER(MLIL_TAILCALL_SSA)
	ENUM_PRINTER(MLIL_TAILCALL_UNTYPED_SSA)
	ENUM_PRINTER(MLIL_CALL_PARAM_SSA)
	ENUM_PRINTER(MLIL_CALL_OUTPUT_SSA)
	ENUM_PRINTER(MLIL_LOAD_SSA)
	ENUM_PRINTER(MLIL_LOAD_STRUCT_SSA)
	ENUM_PRINTER(MLIL_STORE_SSA)
	ENUM_PRINTER(MLIL_STORE_STRUCT_SSA)
	ENUM_PRINTER(MLIL_VAR_PHI)
	ENUM_PRINTER(MLIL_MEM_PHI)
	default:
		printf("<invalid operation %" PRId32 ">", operation);
		break;
	}
}


static void PrintVariable(MediumLevelILFunction* func, const Variable& var)
{
	string name = func->GetFunction()->GetVariableName(var);
	if (name.size() == 0)
		printf("<no name>");
	else
		printf("%s", name.c_str());
}


static void PrintILExpr(const MediumLevelILInstruction& instr, size_t indent)
{
	PrintIndent(indent);
	PrintOperation(instr.operation);
	printf("\n");

	indent++;

	for (auto& operand : instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case IntegerMediumLevelOperand:
			PrintIndent(indent);
			printf("int 0x%" PRIx64 "\n", operand.GetInteger());
			break;

		case IndexMediumLevelOperand:
			PrintIndent(indent);
			printf("index %" PRIdPTR "\n", operand.GetIndex());
			break;

		case ExprMediumLevelOperand:
			PrintILExpr(operand.GetExpr(), indent);
			break;

		case VariableMediumLevelOperand:
			PrintIndent(indent);
			printf("var ");
			PrintVariable(instr.function, operand.GetVariable());
			printf("\n");
			break;

		case SSAVariableMediumLevelOperand:
			PrintIndent(indent);
			printf("ssa var ");
			PrintVariable(instr.function, operand.GetSSAVariable().var);
			printf("#%" PRIdPTR "\n", operand.GetSSAVariable().version);
			break;

		case IndexListMediumLevelOperand:
			PrintIndent(indent);
			printf("index list ");
			for (auto i : operand.GetIndexList())
				printf("%" PRIdPTR " ", i);
			printf("\n");
			break;

		case VariableListMediumLevelOperand:
			PrintIndent(indent);
			printf("var list ");
			for (auto& i : operand.GetVariableList())
			{
				PrintVariable(instr.function, i);
				printf(" ");
			}
			printf("\n");
			break;

		case SSAVariableListMediumLevelOperand:
			PrintIndent(indent);
			printf("ssa var list ");
			for (auto& i : operand.GetSSAVariableList())
			{
				PrintVariable(instr.function, i.var);
				printf("#%" PRIdPTR " ", i.version);
			}
			printf("\n");
			break;

		case ExprListMediumLevelOperand:
			PrintIndent(indent);
			printf("expr list\n");
			for (auto& i : operand.GetExprList())
				PrintILExpr(i, indent + 1);
			break;

		default:
			PrintIndent(indent);
			printf("<invalid operand>\n");
			break;
		}
	}
}


int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Expected input filename\n");
		return 1;
	}

	// In order to initiate the bundled plugins properly, the location
	// of where bundled plugins directory is must be set. Since
	// libbinaryninjacore is in the path get the path to it and use it to
	// determine the plugins directory
	SetBundledPluginDirectory(GetPluginsDirectory());
	InitPlugins();

	Ref<BinaryData> bd = new BinaryData(new FileMetadata(), argv[1]);
	Ref<BinaryView> bv;
	for (auto type : BinaryViewType::GetViewTypes())
	{
		if (type->IsTypeValidForData(bd) && type->GetName() != "Raw")
		{
			bv = type->Create(bd);
			break;
		}
	}

	if (!bv || bv->GetTypeName() == "Raw")
	{
		fprintf(stderr, "Input file does not appear to be an exectuable\n");
		return -1;
	}

	bv->UpdateAnalysisAndWait();

	// Go through all functions in the binary
	for (auto& func : bv->GetAnalysisFunctionList())
	{
		// Get the name of the function and display it
		Ref<Symbol> sym = func->GetSymbol();
		if (sym)
			printf("Function %s:\n", sym->GetFullName().c_str());
		else
			printf("Function at 0x%" PRIx64 ":\n", func->GetStart());

		// Fetch the medium level IL for the function
		Ref<MediumLevelILFunction> il = func->GetMediumLevelIL();
		if (!il)
		{
			printf("    Does not have MLIL\n\n");
			continue;
		}

		// Loop through all blocks in the function
		for (auto& block : il->GetBasicBlocks())
		{
			// Loop though each instruction in the block
			for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
			{
				// Fetch IL instruction
				MediumLevelILInstruction instr = (*il)[instrIndex];

				// Display core's intrepretation of the IL instruction
				vector<InstructionTextToken> tokens;
				il->GetInstructionText(func, func->GetArchitecture(), instrIndex, tokens);
				printf("    %" PRIdPTR " @ 0x%" PRIx64 "  ", instrIndex, instr.address);
				for (auto& token: tokens)
					printf("%s", token.text.c_str());
				printf("\n");

				// Generically parse the IL tree and display the parts
				PrintILExpr(instr, 2);

				// Example of using visitors to find all constants in the instruction
				instr.VisitExprs([&](const MediumLevelILInstruction& expr) {
					bool status = MediumLevelILFunction::IsConstantType(expr.operation);
					if (status)
						printf("        Found constant 0x%" PRIx64 "\n", expr.GetConstant());
					return !status;
				});

				// Example of using the templated accessors for efficiently parsing load instructions
				instr.VisitExprs([&](const MediumLevelILInstruction& expr) {
					switch (expr.operation)
					{
					case MLIL_LOAD:
						if (expr.GetSourceExpr<MLIL_LOAD>().operation == MLIL_CONST_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
								expr.GetSourceExpr<MLIL_LOAD>().GetConstant<MLIL_CONST_PTR>());
							return false; // Done parsing this
						}
						else if (expr.GetSourceExpr<MLIL_LOAD>().operation == MLIL_EXTERN_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
								expr.GetSourceExpr<MLIL_LOAD>().GetConstant<MLIL_EXTERN_PTR>());
							return false; // Done parsing this
						}
						break;
					default:
						break;
					}
					return true; // Parse any subexpressions
				});
			}
		}

		printf("\n");
	}

	// Shutting down is required to allow for clean exit of the core
	BNShutdown();

	return 0;
}

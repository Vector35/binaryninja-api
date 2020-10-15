#include <stdio.h>
#include <inttypes.h>
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

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


static void PrintOperation(BNLowLevelILOperation operation)
{
#define ENUM_PRINTER(op) \
	case op: \
		printf(#op); \
		break;

	switch (operation)
	{
	ENUM_PRINTER(LLIL_NOP)
	ENUM_PRINTER(LLIL_SET_REG)
	ENUM_PRINTER(LLIL_SET_REG_SPLIT)
	ENUM_PRINTER(LLIL_SET_FLAG)
	ENUM_PRINTER(LLIL_LOAD)
	ENUM_PRINTER(LLIL_STORE)
	ENUM_PRINTER(LLIL_PUSH)
	ENUM_PRINTER(LLIL_POP)
	ENUM_PRINTER(LLIL_REG)
	ENUM_PRINTER(LLIL_CONST)
	ENUM_PRINTER(LLIL_CONST_PTR)
	ENUM_PRINTER(LLIL_EXTERN_PTR)
	ENUM_PRINTER(LLIL_FLAG)
	ENUM_PRINTER(LLIL_FLAG_BIT)
	ENUM_PRINTER(LLIL_ADD)
	ENUM_PRINTER(LLIL_ADC)
	ENUM_PRINTER(LLIL_SUB)
	ENUM_PRINTER(LLIL_SBB)
	ENUM_PRINTER(LLIL_AND)
	ENUM_PRINTER(LLIL_OR)
	ENUM_PRINTER(LLIL_XOR)
	ENUM_PRINTER(LLIL_LSL)
	ENUM_PRINTER(LLIL_LSR)
	ENUM_PRINTER(LLIL_ASR)
	ENUM_PRINTER(LLIL_ROL)
	ENUM_PRINTER(LLIL_RLC)
	ENUM_PRINTER(LLIL_ROR)
	ENUM_PRINTER(LLIL_RRC)
	ENUM_PRINTER(LLIL_MUL)
	ENUM_PRINTER(LLIL_MULU_DP)
	ENUM_PRINTER(LLIL_MULS_DP)
	ENUM_PRINTER(LLIL_DIVU)
	ENUM_PRINTER(LLIL_DIVU_DP)
	ENUM_PRINTER(LLIL_DIVS)
	ENUM_PRINTER(LLIL_DIVS_DP)
	ENUM_PRINTER(LLIL_MODU)
	ENUM_PRINTER(LLIL_MODU_DP)
	ENUM_PRINTER(LLIL_MODS)
	ENUM_PRINTER(LLIL_MODS_DP)
	ENUM_PRINTER(LLIL_NEG)
	ENUM_PRINTER(LLIL_NOT)
	ENUM_PRINTER(LLIL_SX)
	ENUM_PRINTER(LLIL_ZX)
	ENUM_PRINTER(LLIL_LOW_PART)
	ENUM_PRINTER(LLIL_JUMP)
	ENUM_PRINTER(LLIL_JUMP_TO)
	ENUM_PRINTER(LLIL_CALL)
	ENUM_PRINTER(LLIL_CALL_STACK_ADJUST)
	ENUM_PRINTER(LLIL_TAILCALL)
	ENUM_PRINTER(LLIL_RET)
	ENUM_PRINTER(LLIL_NORET)
	ENUM_PRINTER(LLIL_IF)
	ENUM_PRINTER(LLIL_GOTO)
	ENUM_PRINTER(LLIL_FLAG_COND)
	ENUM_PRINTER(LLIL_CMP_E)
	ENUM_PRINTER(LLIL_CMP_NE)
	ENUM_PRINTER(LLIL_CMP_SLT)
	ENUM_PRINTER(LLIL_CMP_ULT)
	ENUM_PRINTER(LLIL_CMP_SLE)
	ENUM_PRINTER(LLIL_CMP_ULE)
	ENUM_PRINTER(LLIL_CMP_SGE)
	ENUM_PRINTER(LLIL_CMP_UGE)
	ENUM_PRINTER(LLIL_CMP_SGT)
	ENUM_PRINTER(LLIL_CMP_UGT)
	ENUM_PRINTER(LLIL_TEST_BIT)
	ENUM_PRINTER(LLIL_BOOL_TO_INT)
	ENUM_PRINTER(LLIL_ADD_OVERFLOW)
	ENUM_PRINTER(LLIL_SYSCALL)
	ENUM_PRINTER(LLIL_BP)
	ENUM_PRINTER(LLIL_TRAP)
	ENUM_PRINTER(LLIL_UNDEF)
	ENUM_PRINTER(LLIL_UNIMPL)
	ENUM_PRINTER(LLIL_UNIMPL_MEM)
	ENUM_PRINTER(LLIL_SET_REG_SSA)
	ENUM_PRINTER(LLIL_SET_REG_SSA_PARTIAL)
	ENUM_PRINTER(LLIL_SET_REG_SPLIT_SSA)
	ENUM_PRINTER(LLIL_REG_SPLIT_DEST_SSA)
	ENUM_PRINTER(LLIL_REG_SSA)
	ENUM_PRINTER(LLIL_REG_SSA_PARTIAL)
	ENUM_PRINTER(LLIL_SET_FLAG_SSA)
	ENUM_PRINTER(LLIL_FLAG_SSA)
	ENUM_PRINTER(LLIL_FLAG_BIT_SSA)
	ENUM_PRINTER(LLIL_CALL_SSA)
	ENUM_PRINTER(LLIL_SYSCALL_SSA)
	ENUM_PRINTER(LLIL_TAILCALL_SSA)
	ENUM_PRINTER(LLIL_CALL_PARAM)
	ENUM_PRINTER(LLIL_CALL_STACK_SSA)
	ENUM_PRINTER(LLIL_CALL_OUTPUT_SSA)
	ENUM_PRINTER(LLIL_LOAD_SSA)
	ENUM_PRINTER(LLIL_STORE_SSA)
	ENUM_PRINTER(LLIL_REG_PHI)
	ENUM_PRINTER(LLIL_FLAG_PHI)
	ENUM_PRINTER(LLIL_MEM_PHI)
	default:
		printf("<invalid operation %" PRId32 ">", operation);
		break;
	}
}


static void PrintFlagCondition(BNLowLevelILFlagCondition cond)
{
	switch (cond)
	{
	ENUM_PRINTER(LLFC_E)
	ENUM_PRINTER(LLFC_NE)
	ENUM_PRINTER(LLFC_SLT)
	ENUM_PRINTER(LLFC_ULT)
	ENUM_PRINTER(LLFC_SLE)
	ENUM_PRINTER(LLFC_ULE)
	ENUM_PRINTER(LLFC_SGE)
	ENUM_PRINTER(LLFC_UGE)
	ENUM_PRINTER(LLFC_SGT)
	ENUM_PRINTER(LLFC_UGT)
	ENUM_PRINTER(LLFC_NEG)
	ENUM_PRINTER(LLFC_POS)
	ENUM_PRINTER(LLFC_O)
	ENUM_PRINTER(LLFC_NO)
	default:
		printf("<invalid condition>");
		break;
	}
}


static void PrintRegister(LowLevelILFunction* func, uint32_t reg)
{
	if (LLIL_REG_IS_TEMP(reg))
		printf("temp%d", LLIL_GET_TEMP_REG_INDEX(reg));
	else
	{
		string name = func->GetArchitecture()->GetRegisterName(reg);
		if (name.size() == 0)
			printf("<no name>");
		else
			printf("%s", name.c_str());
	}
}


static void PrintFlag(LowLevelILFunction* func, uint32_t flag)
{
	if (LLIL_REG_IS_TEMP(flag))
		printf("cond:%d", LLIL_GET_TEMP_REG_INDEX(flag));
	else
	{
		string name = func->GetArchitecture()->GetFlagName(flag);
		if (name.size() == 0)
			printf("<no name>");
		else
			printf("%s", name.c_str());
	}
}


static void PrintILExpr(const LowLevelILInstruction& instr, size_t indent)
{
	PrintIndent(indent);
	PrintOperation(instr.operation);
	printf("\n");

	indent++;

	for (auto& operand : instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case IntegerLowLevelOperand:
			PrintIndent(indent);
			printf("int 0x%" PRIx64 "\n", operand.GetInteger());
			break;

		case IndexLowLevelOperand:
			PrintIndent(indent);
			printf("index %" PRIdPTR "\n", operand.GetIndex());
			break;

		case ExprLowLevelOperand:
			PrintILExpr(operand.GetExpr(), indent);
			break;

		case RegisterLowLevelOperand:
			PrintIndent(indent);
			printf("reg ");
			PrintRegister(instr.function, operand.GetRegister());
			printf("\n");
			break;

		case FlagLowLevelOperand:
			PrintIndent(indent);
			printf("flag ");
			PrintFlag(instr.function, operand.GetFlag());
			printf("\n");
			break;

		case FlagConditionLowLevelOperand:
			PrintIndent(indent);
			printf("flag condition ");
			PrintFlagCondition(operand.GetFlagCondition());
			printf("\n");
			break;

		case SSARegisterLowLevelOperand:
			PrintIndent(indent);
			printf("ssa reg ");
			PrintRegister(instr.function, operand.GetSSARegister().reg);
			printf("#%" PRIdPTR "\n", operand.GetSSARegister().version);
			break;

		case SSAFlagLowLevelOperand:
			PrintIndent(indent);
			printf("ssa flag ");
			PrintFlag(instr.function, operand.GetSSAFlag().flag);
			printf("#%" PRIdPTR "\n", operand.GetSSAFlag().version);
			break;

		case IndexListLowLevelOperand:
			PrintIndent(indent);
			printf("index list ");
			for (auto i : operand.GetIndexList())
				printf("%" PRIdPTR " ", i);
			printf("\n");
			break;

		case SSARegisterListLowLevelOperand:
			PrintIndent(indent);
			printf("ssa reg list ");
			for (auto& i : operand.GetSSARegisterList())
			{
				PrintRegister(instr.function, i.reg);
				printf("#%" PRIdPTR " ", i.version);
			}
			printf("\n");
			break;

		case SSAFlagListLowLevelOperand:
			PrintIndent(indent);
			printf("ssa reg list ");
			for (auto& i : operand.GetSSAFlagList())
			{
				PrintFlag(instr.function, i.flag);
				printf("#%" PRIdPTR " ", i.version);
			}
			printf("\n");
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

		// Fetch the low level IL for the function
		Ref<LowLevelILFunction> il = func->GetLowLevelIL();
		if (!il)
		{
			printf("    Does not have LLIL\n\n");
			continue;
		}

		// Loop through all blocks in the function
		for (auto& block : il->GetBasicBlocks())
		{
			// Loop though each instruction in the block
			for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
			{
				// Fetch IL instruction
				LowLevelILInstruction instr = (*il)[instrIndex];

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
				instr.VisitExprs([&](const LowLevelILInstruction& expr) {
					switch (expr.operation)
					{
					case LLIL_CONST:
					case LLIL_CONST_PTR:
					case LLIL_EXTERN_PTR:
						printf("        Found constant 0x%" PRIx64 "\n", expr.GetConstant());
						return false; // Done parsing this
					default:
						break;
					}
					return true; // Parse any subexpressions
				});

				// Example of using the templated accessors for efficiently parsing load instructions
				instr.VisitExprs([&](const LowLevelILInstruction& expr) {
					switch (expr.operation)
					{
					case LLIL_LOAD:
						if (expr.GetSourceExpr<LLIL_LOAD>().operation == LLIL_CONST_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
								expr.GetSourceExpr<LLIL_LOAD>().GetConstant<LLIL_CONST_PTR>());
							return false; // Done parsing this
						}
						else if (expr.GetSourceExpr<LLIL_LOAD>().operation == LLIL_EXTERN_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
								expr.GetSourceExpr<LLIL_LOAD>().GetConstant<LLIL_EXTERN_PTR>());
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

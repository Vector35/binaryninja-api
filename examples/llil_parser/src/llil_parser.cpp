#include <cstdio>
#include <cinttypes>
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


static void PrintIndent(size_t indent)
{
	for (size_t i = 0; i < indent; i++)
		printf("    ");
}


static void PrintOperation(BNLowLevelILOperation operation)
{
	auto name = CoreEnumToString(operation);
	if (name)
		printf("%s", name->c_str());
	else
		printf("<invalid operation %" PRId32 ">", operation);
}


static void PrintFlagCondition(BNLowLevelILFlagCondition cond)
{
	auto name = CoreEnumToString(cond);
	if (name)
		printf("%s", name->c_str());
	else
		printf("<invalid condition>");
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
			for (auto i : operand.GetSSARegisterList())
			{
				PrintRegister(instr.function, i.reg);
				printf("#%" PRIdPTR " ", i.version);
			}
			printf("\n");
			break;

		case SSAFlagListLowLevelOperand:
			PrintIndent(indent);
			printf("ssa reg list ");
			for (auto i : operand.GetSSAFlagList())
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


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Expected input filename\n");
		return 1;
	}

	// In order to initiate the bundled plugins properly, the location
	// of where bundled plugins directory is must be set.
	SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	Ref<BinaryView> bv = BinaryNinja::Load(argv[1]);
	if (!bv || bv->GetTypeName() == "Raw")
	{
		fprintf(stderr, "Input file does not appear to be an executable\n");
		return -1;
	}

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
				for (auto& token : tokens)
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
						return false;  // Done parsing this
					default:
						break;
					}
					return true;  // Parse any subexpressions
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
							return false;  // Done parsing this
						}
						else if (expr.GetSourceExpr<LLIL_LOAD>().operation == LLIL_EXTERN_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
							    expr.GetSourceExpr<LLIL_LOAD>().GetConstant<LLIL_EXTERN_PTR>());
							return false;  // Done parsing this
						}
						break;
					default:
						break;
					}
					return true;  // Parse any subexpressions
				});
			}
		}

		printf("\n");
	}

	// Close the file so that the resources can be freed
	bv->GetFile()->Close();

	// Shutting down is required to allow for clean exit of the core
	BNShutdown();

	return 0;
}

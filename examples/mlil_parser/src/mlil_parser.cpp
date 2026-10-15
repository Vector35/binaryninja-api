#include <cstdio>
#include <cinttypes>
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


static void PrintIndent(size_t indent)
{
	for (size_t i = 0; i < indent; i++)
		printf("    ");
}


static void PrintOperation(BNMediumLevelILOperation operation)
{
	auto name = CoreEnumToString(operation);
	if (name)
		printf("%s", name->c_str());
	else
		printf("<invalid operation %" PRId32 ">", operation);
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
			for (auto i : operand.GetVariableList())
			{
				PrintVariable(instr.function, i);
				printf(" ");
			}
			printf("\n");
			break;

		case SSAVariableListMediumLevelOperand:
			PrintIndent(indent);
			printf("ssa var list ");
			for (auto i : operand.GetSSAVariableList())
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


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Expected input filename\n");
		return 1;
	}

	// In order to initiate the bundled plugins properly, the location
	// of where bundled plugins directory  must be set
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
				for (auto& token : tokens)
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
							return false;  // Done parsing this
						}
						else if (expr.GetSourceExpr<MLIL_LOAD>().operation == MLIL_EXTERN_PTR)
						{
							printf("        Loading from address 0x%" PRIx64 "\n",
							    expr.GetSourceExpr<MLIL_LOAD>().GetConstant<MLIL_EXTERN_PTR>());
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

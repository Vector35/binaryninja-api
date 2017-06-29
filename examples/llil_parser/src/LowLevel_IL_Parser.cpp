/*
LLIL Parser - Binary Ninja C++ API Sample
 - Robert Yates - 22/JUN/17
 */

#include "LowLevel_IL_Parser.h"
#include <iostream>
#include <sstream>

int main(int argc, char* argv[])
{

	try
	{
		ShowBanner();


		if (argc != 2)
		{
			printf("Usage: %s <input file>", argv[0]);
			exit(-1);
		}

		std::string inputName = argv[1];

		SetBundledPluginDirectory(get_plugins_directory());
		InitCorePlugins();
		InitUserPlugins();

		auto bd = BinaryData(new FileMetadata(), inputName.c_str());
		BinaryView *bv;

		for (auto type : BinaryViewType::GetViewTypes())
		{
			if (type->IsTypeValidForData(&bd) && type->GetName() != "Raw")
			{
				bv = type->Create(&bd);
				break;
			}
		}

		printf("[i] Starting analysis\n");
		bv->UpdateAnalysis();

		while (bv->GetAnalysisProgress().state != IdleState);
		printf("[i] Analysis done\n");

		LlilParser myParser(bv);
		myParser.decodeWholeFunction(bv->GetAnalysisFunctionList()[0]);

		/*
		// Show Single LLIL in function x at index x
		myParser.decodeIndexInFunction(0x407930, 0);
		
		// Decode a whole function by address
		myParser.decodeWholeFunction(0x407930);
		
		// Decode all functions
		for (const auto& f : bv->GetAnalysisFunctionList())
		{
			// Decode a whole function by BinaryNinja::Function object
			myParser.decodeWholeFunction(f);
		}
		*/

	}
	catch (const std::exception& e)
	{
		printf("An Exception Occured: %s\n", e.what());
	}

	printf("[i] Finished\n");
}



LlilParser::LlilParser(BinaryView *bv)
	: m_bv(bv)
{
	m_currentFunction.clear();
	m_tabs = 0;
	m_currentInstructionId = 0;
}

void LlilParser::showIndent() const
{
	for (int i = 0; i < m_tabs; i++)
		printf(" ");
}

void LlilParser::analysisInstruction(const BNLowLevelILInstruction& insn)
{

	auto instructionSynatx = g_llilSyntaxMap.find(insn.operation);
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> llil = m_currentFunction[0]->GetLowLevelIL();
	if (instructionSynatx == g_llilSyntaxMap.end())
		throw std::runtime_error("Error unknown LLIL\n");

	showIndent();
	printf("Instruction: %s\n", getLowLevelILOperationName(insn.operation).c_str());
	m_tabs += 3;

	int operandId = 0;
	for (const auto& operand : instructionSynatx->second)
	{
		if (operand.type == OperandType::kExpr)
		{
			// In this case the value in the operands[x] field is a new instruction & expression index value
			BNLowLevelILInstruction nextInstruction = llil->operator[](insn.operands[operandId]);
			analysisInstruction(nextInstruction); // recursion begins :)
		}
		else if (operand.type == OperandType::kReg)
		{
			// In this case the register id is in the first operands field and we use Arch to translate
			showIndent();
			printf("Reg: %s\n", m_bv->GetDefaultArchitecture()->GetRegisterName(static_cast<uint32_t>(insn.operands[0])).c_str());
			m_tabs += 3;
		}
		else if (operand.type == OperandType::kInt)
		{
			// In this case the operand is simply a value
			showIndent();
			printf("Value: %zX\n", insn.operands[0]);
			m_tabs += 3;
		}
		else if (operand.type == OperandType::kFlag)
		{
			// In this case the operand is a flag
			printf("Flag: %s\n", m_bv->GetDefaultArchitecture()->GetFlagName(static_cast<uint32_t>(insn.operands[0])).c_str());
			m_tabs += 3;
		}
		else if (operand.type == OperandType::kIntList)
		{
			// In this case we have an array of llil targets
			std::vector<uint64_t> intList = llil->GetOperandList(llil->GetIndexForInstruction(m_currentInstructionId), operandId);
			showIndent();
			printf("Target LLIL Indices: ");
			for (const auto i : intList)
			{
				printf("%zd ", i);
			}
			printf("\n");
		}
		else
		{
			printf("[e] LLIL Parser: Not Handled -> OperandPurpose: %d OperandType: %d\n", operand.purpose, operand.type);
		}


		operandId++;
	}


}

void LlilParser::decodeIndexInFunction(uint64_t functionAddress, int indexIl)
{

	m_currentFunction = m_bv->GetAnalysisFunctionsForAddress(functionAddress);
	if (m_currentFunction.size() < 1)
		throw std::runtime_error("Error no functions at requested address\n");

	BinaryNinja::Function *function = m_currentFunction[0];
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> llil = function->GetLowLevelIL();

	m_currentInstructionId = indexIl;
	BNLowLevelILInstruction currentInstruction = llil->operator[](llil->GetIndexForInstruction(indexIl));


	analysisInstruction(currentInstruction);
	m_tabs = 0;

}

void LlilParser::decodeWholeFunction(BinaryNinja::Function *function)
{
	m_currentFunction.clear();
	m_currentFunction.push_back(function);

	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> llil = function->GetLowLevelIL();

	for (size_t i = 0; i < llil->GetInstructionCount(); i++)
	{
		
		m_currentInstructionId = i;
		BNLowLevelILInstruction currentInstruction = llil->operator[](llil->GetIndexForInstruction(i));
		
		printf("\n[%zx][%zd]---------------------------------------------------------------------------\n", currentInstruction.address, i);

		analysisInstruction(currentInstruction);
		m_tabs = 0;
	}

}

void LlilParser::decodeWholeFunction(uint64_t functionAddress)
{

	m_currentFunction = m_bv->GetAnalysisFunctionsForAddress(functionAddress);
	if (m_currentFunction.size() < 1)
		throw std::runtime_error("Error no functions at requested address or possible invalid BundledPluginDirectory\n");

	BinaryNinja::Function *function = m_currentFunction[0];
	BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> llil = function->GetLowLevelIL();

	

	for (size_t i = 0; i < llil->GetInstructionCount(); i++)
	{
		m_currentInstructionId = i;
		BNLowLevelILInstruction currentInstruction = llil->operator[](llil->GetIndexForInstruction(i));
		printf("\n[%zx][%zd]---------------------------------------------------------------------------\n", currentInstruction.address, i);

		analysisInstruction(currentInstruction);
		m_tabs = 0;
	}

}

void ShowBanner()
{

	printf (".____    .____    .___.____      __________                                   \n");
	printf ("|    |   |    |   |   |    |     \\______   \\_____ _______  ______ ___________ \n");
	printf ("|    |   |    |   |   |    |      |     ___/\\__  \\\\_  __ \\/  ___// __ \\_  __ \\\n");
	printf ("|    |___|    |___|   |    |___   |    |     / __ \\|  | \\/\\___ \\\\  ___/|  | \\/\n");
	printf ("|_______ \\_______ \\___|_______ \\  |____|    (____  /__|  /____  >\\___  >__|   \n");
	printf ("        \\/       \\/           \\/                 \\/           \\/     \\/    \n");
	printf("====================================================================================\n\n");

}

#ifndef _WIN32
#include <libgen.h>
#include <dlfcn.h>
std::string get_plugins_directory()
{
    Dl_info info;
    if (!dladdr((void *)BNGetBundledPluginDirectory, &info))
        return NULL;

    std::stringstream ss;
    ss << dirname((char *)info.dli_fname) << "/plugins/";
    return ss.str();
}
#else
std::string get_plugins_directory()
{
    return "C:\\Program Files\\Vector35\\BinaryNinja\\plugins\\";
}
#endif

const std::string LlilParser::getLowLevelILOperationName(BNLowLevelILOperation id) const
{

	switch (id)
	{
	case LLIL_NOP:
		return "LLIL_NOP";
	case LLIL_SET_REG:
		return "LLIL_SET_REG";
	case LLIL_SET_REG_SPLIT:
		return "LLIL_SET_REG_SPLIT";
	case LLIL_SET_FLAG:
		return "LLIL_SET_FLAG";
	case LLIL_LOAD:
		return "LLIL_LOAD";
	case LLIL_STORE:
		return "LLIL_STORE";
	case LLIL_PUSH:
		return "LLIL_PUSH";
	case LLIL_POP:
		return "LLIL_POP";
	case LLIL_REG:
		return "LLIL_REG";
	case LLIL_CONST:
		return "LLIL_CONST";
	case LLIL_CONST_PTR:
		return "LLIL_CONST_PTR";
	case LLIL_FLAG:
		return "LLIL_FLAG";
	case LLIL_FLAG_BIT:
		return "LLIL_FLAG_BIT";
	case LLIL_ADD:
		return "LLIL_ADD";
	case LLIL_ADC:
		return "LLIL_ADC";
	case LLIL_SUB:
		return "LLIL_SUB";
	case LLIL_SBB:
		return "LLIL_SBB";
	case LLIL_AND:
		return "LLIL_AND";
	case LLIL_OR:
		return "LLIL_OR";
	case LLIL_XOR:
		return "LLIL_XOR";
	case LLIL_LSL:
		return "LLIL_LSL";
	case LLIL_LSR:
		return "LLIL_LSR";
	case LLIL_ASR:
		return "LLIL_ASR";
	case LLIL_ROL:
		return "LLIL_ROL";
	case LLIL_RLC:
		return "LLIL_RLC";
	case LLIL_ROR:
		return "LLIL_ROR";
	case LLIL_RRC:
		return "LLIL_RRC";
	case LLIL_MUL:
		return "LLIL_MUL";
	case LLIL_MULU_DP:
		return "LLIL_MULU_DP";
	case LLIL_MULS_DP:
		return "LLIL_MULS_DP";
	case LLIL_DIVU:
		return "LLIL_DIVU";
	case LLIL_DIVU_DP:
		return "LLIL_DIVU_DP";
	case LLIL_DIVS:
		return "LLIL_DIVS";
	case LLIL_DIVS_DP:
		return "LLIL_DIVS_DP";
	case LLIL_MODU:
		return "LLIL_MODU";
	case LLIL_MODU_DP:
		return "LLIL_MODU_DP";
	case LLIL_MODS:
		return "LLIL_MODS";
	case LLIL_MODS_DP:
		return "LLIL_MODS_DP";
	case LLIL_NEG:
		return "LLIL_NEG";
	case LLIL_NOT:
		return "LLIL_NOT";
	case LLIL_SX:
		return "LLIL_SX";
	case LLIL_ZX:
		return "LLIL_ZX";
	case LLIL_LOW_PART:
		return "LLIL_LOW_PART";
	case LLIL_JUMP:
		return "LLIL_JUMP";
	case LLIL_JUMP_TO:
		return "LLIL_JUMP_TO";
	case LLIL_CALL:
		return "LLIL_CALL";
	case LLIL_RET:
		return "LLIL_RET";
	case LLIL_NORET:
		return "LLIL_NORET";
	case LLIL_IF:
		return "LLIL_IF";
	case LLIL_GOTO:
		return "LLIL_GOTO";
	case LLIL_FLAG_COND:
		return "LLIL_FLAG_COND";
	case LLIL_CMP_E:
		return "LLIL_CMP_E";
	case LLIL_CMP_NE:
		return "LLIL_CMP_NE";
	case LLIL_CMP_SLT:
		return "LLIL_CMP_SLT";
	case LLIL_CMP_ULT:
		return "LLIL_CMP_ULT";
	case LLIL_CMP_SLE:
		return "LLIL_CMP_SLE";
	case LLIL_CMP_ULE:
		return "LLIL_CMP_ULE";
	case LLIL_CMP_SGE:
		return "LLIL_CMP_SGE";
	case LLIL_CMP_UGE:
		return "LLIL_CMP_UGE";
	case LLIL_CMP_SGT:
		return "LLIL_CMP_SGT";
	case LLIL_CMP_UGT:
		return "LLIL_CMP_UGT";
	case LLIL_TEST_BIT:
		return "LLIL_TEST_BIT";
	case LLIL_BOOL_TO_INT:
		return "LLIL_BOOL_TO_INT";
	case LLIL_ADD_OVERFLOW:
		return "LLIL_ADD_OVERFLOW";
	case LLIL_SYSCALL:
		return "LLIL_SYSCALL";
	case LLIL_BP:
		return "LLIL_BP";
	case LLIL_TRAP:
		return "LLIL_TRAP";
	case LLIL_UNDEF:
		return "LLIL_UNDEF";
	case LLIL_UNIMPL:
		return "LLIL_UNIMPL";
	case LLIL_UNIMPL_MEM:
		return "LLIL_UNIMPL_MEM";
	case LLIL_SET_REG_SSA:
		return "LLIL_SET_REG_SSA";
	case LLIL_SET_REG_SSA_PARTIAL:
		return "LLIL_SET_REG_SSA_PARTIAL";
	case LLIL_SET_REG_SPLIT_SSA:
		return "LLIL_SET_REG_SPLIT_SSA";
	case LLIL_REG_SPLIT_DEST_SSA:
		return "LLIL_REG_SPLIT_DEST_SSA";
	case LLIL_REG_SSA:
		return "LLIL_REG_SSA";
	case LLIL_REG_SSA_PARTIAL:
		return "LLIL_REG_SSA_PARTIAL";
	case LLIL_SET_FLAG_SSA:
		return "LLIL_SET_FLAG_SSA";
	case LLIL_FLAG_SSA:
		return "LLIL_FLAG_SSA";
	case LLIL_FLAG_BIT_SSA:
		return "LLIL_FLAG_BIT_SSA";
	case LLIL_CALL_SSA:
		return "LLIL_CALL_SSA";
	case LLIL_SYSCALL_SSA:
		return "LLIL_SYSCALL_SSA";
	case LLIL_CALL_PARAM_SSA:
		return "LLIL_CALL_PARAM_SSA";
	case LLIL_CALL_STACK_SSA:
		return "LLIL_CALL_STACK_SSA";
	case LLIL_CALL_OUTPUT_SSA:
		return "LLIL_CALL_OUTPUT_SSA";
	case LLIL_LOAD_SSA:
		return "LLIL_LOAD_SSA";
	case LLIL_STORE_SSA:
		return "LLIL_STORE_SSA";
	case LLIL_REG_PHI:
		return "LLIL_REG_PHI";
	case LLIL_FLAG_PHI:
		return "LLIL_FLAG_PHI";
	case LLIL_MEM_PHI:
		return "LLIL_MEM_PHI";
	}

	return "Unknown";
	//throw std::runtime_error("GetLowLevelILOperationName Failure");

}
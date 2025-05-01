#define _CRT_SECURE_NO_WARNINGS

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>
#include <tuple>
#include <unordered_map>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"


using namespace BinaryNinja;
using namespace std;

#if defined(_MSC_VER)
	#define snprintf _snprintf
#endif


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	void TailCallTranslation(Ref<AnalysisContext> analysisContext)
	{
		Ref<Function> function = analysisContext->GetFunction();
		Ref<BinaryView> data = function->GetView();

		bool updated = false;
		uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
		InstructionInfo iInfo;

		// Look for jumps to other functions
		Ref<LowLevelILFunction> llilFunc = analysisContext->GetLowLevelILFunction();
		for (auto& i : llilFunc->GetBasicBlocks())
		{
			// if (m_owner->IsAborted())
			// 	return;

			Ref<Architecture> arch = i->GetArchitecture();
			size_t instrIndex = i->GetEnd() - 1;
			LowLevelILInstruction instr = llilFunc->GetInstruction(instrIndex);
			if (instr.operation != LLIL_JUMP)
				continue;

			uint64_t platformAddr;
			LowLevelILInstruction destExpr = instr.GetDestExpr<LLIL_JUMP>();
			RegisterValue target = destExpr.GetValue();
			if (target.IsConstant())
				platformAddr = target.value;
			else if (target.state
			         == ImportedAddressValue)  // Call to imported function, look up type from import symbol
				platformAddr = target.value;
			else if (target.state == ExternalPointerValue && target.offset == 0)
				platformAddr = target.value;
			else
				continue;

			size_t opLen = data->Read(opcode, instr.address, arch->GetMaxInstructionLength());
			if (!opLen || !arch->GetInstructionInfo(opcode, instr.address, opLen, iInfo))
				continue;
			Ref<Platform> platform = iInfo.archTransitionByTargetAddr ?
                                         function->GetPlatform()->GetAssociatedPlatformByAddress(platformAddr) :
                                         function->GetPlatform();
			if (platform)
			{
				bool canReturn = true;
				Ref<Function> targetFunc = nullptr;
				if (target.state == ImportedAddressValue)
				{
					DataVariable var;
					if (data->GetDataVariableAtAddress(target.value, var))
					{
						if (var.type && (var.type->GetClass() == PointerTypeClass)
						    && (var.type->GetChildType()->GetClass() == FunctionTypeClass))
							canReturn = var.type->GetChildType()->CanReturn().GetValue();
					}
				}
				else if (target.state == ExternalPointerValue && target.offset == 0)
				{
					targetFunc = data->GetAnalysisFunction(platform, platformAddr);
					if (targetFunc)
						canReturn = targetFunc->CanReturn();
				}
				else
				{
					targetFunc = data->GetAnalysisFunction(platform, platformAddr);
					if (targetFunc)
						canReturn = targetFunc->CanReturn();
					else
						continue;
				}

				updated = true;
				instr.Replace(llilFunc->TailCall(destExpr.exprIndex, instr));
				analysisContext->Inform("directRefs", "insert", platformAddr, i->GetArchitecture(), instr.address);

				if (!canReturn)
				{
					analysisContext->Inform("directNoReturnCalls", "insert", i->GetArchitecture(), instr.address);
					i->GetSourceBlock()->SetCanExit(false);
					i->SetCanExit(false);
				}
			}
		}

		if (!updated)
			return;

		// Updates found, regenerate SSA form
		llilFunc->GenerateSSAForm();
	}


	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Ref<Workflow> customTailCallWorkflow = Workflow::Instance("core.function.baseAnalysis")->Clone("CustomTailCallWorkflow");
		customTailCallWorkflow->RegisterActivity(new Activity("extension.translateTailCalls", &TailCallTranslation));
		customTailCallWorkflow->Replace("core.function.translateTailCalls", "extension.translateTailCalls");
		customTailCallWorkflow->Remove("core.function.translateTailCalls");
		Workflow::RegisterWorkflow(customTailCallWorkflow,
		    R"#({
			"title" : "Tail Call Translation (Example)",
			"description" : "This analysis stands in as an example to demonstrate Binary Ninja's extensible analysis APIs.",
			"targetType" : "function"
			})#");

		return true;
	}
}

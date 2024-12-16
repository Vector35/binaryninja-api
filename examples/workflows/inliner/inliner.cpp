#define _CRT_SECURE_NO_WARNINGS

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <mutex>
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

	// TODO: Replace with analysis cache opaque datastore.
	std::mutex g_mutex;
	unordered_map<void*, unordered_map<uint64_t, set<uint64_t>>> g_callSiteInlines;

	void FunctionInliner(Ref<AnalysisContext> analysisContext)
	{
		std::unique_lock<std::mutex> lock(g_mutex);

		Ref<Function> function = analysisContext->GetFunction();
		Ref<BinaryView> data = function->GetView();
		auto gItr = g_callSiteInlines.find(data->GetObject());
		if (gItr == g_callSiteInlines.end())
			return;

		auto itr = gItr->second.find(function->GetStart());
		if (itr == gItr->second.end())
			return;

		auto& callSiteInlines = itr->second;
		lock.unlock();

		bool updated = false;
		uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
		InstructionInfo iInfo;
		Ref<LowLevelILFunction> llilFunc = analysisContext->GetLowLevelILFunction();
		for (const auto inlineAddr : callSiteInlines)
		{
			// if (m_owner->IsAborted())
			// 	return;

			for (auto& i : llilFunc->GetBasicBlocks())
			{
				Ref<Architecture> arch = i->GetArchitecture();
				for (size_t instrIndex = i->GetStart(); instrIndex < i->GetEnd(); instrIndex++)
				{
					LowLevelILInstruction instr = llilFunc->GetInstruction(instrIndex);

					if (instr.address != inlineAddr)
						continue;

					if (instr.operation != LLIL_CALL)
					{
						LogWarn(
						    "Failed to inline function at: 0x%" PRIx64 ". Mapping to LLIL_CALL Failed!", instr.address);
						continue;
					}

					uint64_t platformAddr;
					LowLevelILInstruction destExpr = instr.GetDestExpr<LLIL_CALL>();
					RegisterValue target = destExpr.GetValue();
					if (target.IsConstant())
						platformAddr = target.value;
					else
					{
						LogWarn(
						    "Failed to inline function at: 0x%" PRIx64 ". Destination not Constant!", instr.address);
						continue;
					}

					size_t opLen = data->Read(opcode, instr.address, arch->GetMaxInstructionLength());
					if (!opLen || !arch->GetInstructionInfo(opcode, instr.address, opLen, iInfo))
						continue;
					Ref<Platform> platform = iInfo.archTransitionByTargetAddr ?
                                                 function->GetPlatform()->GetAssociatedPlatformByAddress(platformAddr) :
                                                 function->GetPlatform();
					if (platform)
					{
						Ref<Function> targetFunc = data->GetAnalysisFunction(platform, platformAddr);
						auto targetLlil = targetFunc->GetLowLevelIL();
						LowLevelILLabel inlineStartLabel;
						llilFunc->MarkLabel(inlineStartLabel);
						instr.Replace(llilFunc->Goto(inlineStartLabel));

						llilFunc->PrepareToCopyFunction(targetLlil);
						for (auto& ti : targetLlil->GetBasicBlocks())
						{
							llilFunc->PrepareToCopyBlock(ti);
							for (size_t tinstrIndex = ti->GetStart(); tinstrIndex < ti->GetEnd(); tinstrIndex++)
							{
								LowLevelILInstruction tinstr = targetLlil->GetInstruction(tinstrIndex);
								if (tinstr.operation == LLIL_RET)
								{
									LowLevelILLabel label;
									label.operand = instrIndex + 1;
									llilFunc->AddInstruction(llilFunc->Goto(label));
								}
								else
									llilFunc->AddInstruction(tinstr.CopyTo(llilFunc));
							}
						}
						llilFunc->Finalize();
					}

					updated = true;
					break;
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
		auto inlinerIsValid = [](BinaryView* view, Function* func) {
			if (auto workflow = func->GetWorkflow(); workflow)
				return workflow->Contains("extension.functionInliner");
			return false;
		};

		// PluginCommand::RegisterForFunction(
		// 	"Optimizer\\Inline All Calls to Current Function",
		// 	"Inline all calls to the current function.",
		// 	[](BinaryView* view, Function* func) {
		// 		LogError("TODO Inline Current Function: %" PRIx64, func->GetStart());
		// 	}, inlinerIsValid);

		PluginCommand::RegisterForFunction(
		    "Optimizer\\Inline Function at Current Call Site", "Inline function call at current call site.",
		    [](BinaryView* view, Function* func) {
			    // TODO func->Inform("inlinedCallSites")
			    // TODO resolve multiple embedded inlines
			    std::lock_guard<std::mutex> lock(g_mutex);
			    g_callSiteInlines[view->GetObject()][func->GetStart()].insert(view->GetCurrentOffset());
			    func->Reanalyze();
		    },
		    inlinerIsValid);

		Ref<Workflow> inlinerWorkflow = Workflow::Instance("core.function.baseAnalysis")->Clone("InlinerWorkflow");
		inlinerWorkflow->RegisterActivity(new Activity("extension.functionInliner", &FunctionInliner));
		inlinerWorkflow->Insert("core.function.translateTailCalls", "extension.functionInliner");
		Workflow::RegisterWorkflow(inlinerWorkflow,
		    R"#({
			"title" : "Function Inliner (Example)",
			"description" : "This analysis stands in as an example to demonstrate Binary Ninja's extensible analysis APIs.",
			"targetType" : "function"
			})#");

		return true;
	}
}

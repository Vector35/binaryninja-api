
#include "binaryninjaapi.h"
#include "llil_lift_check.h"

using namespace BinaryNinja;

extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		auto checkActivityFn = [](Ref<AnalysisContext> context) {
			if (!context->GetLowLevelILFunction())
				return;
			auto verifier = LowLevelILVerifier(context->GetLowLevelILFunction());
			if (!verifier.Verify())
			{
				LogErrorF("Verify failed for {:#x}", context->GetFunction()->GetStart());
			}
		};

		Ref<Workflow> oldFunctionMetaWorkflow = Workflow::Instance("core.function.metaAnalysis");
		Ref<Workflow> newFunctionMetaWorkflow = oldFunctionMetaWorkflow->Clone("core.function.metaAnalysis");
		newFunctionMetaWorkflow->RegisterActivity(R"~({
			"title": "LLIL Lift Check",
			"name": "analysis.llil.liftCheck",
			"description": "This analysis step checks various conditions on LLIL functions.",
			"eligibility": {
				"auto": {}
			}
		})~", checkActivityFn);
		newFunctionMetaWorkflow->Insert("core.function.generateMediumLevelIL", "analysis.llil.liftCheck");
		Workflow::RegisterWorkflow(newFunctionMetaWorkflow);
		return true;
	}
}


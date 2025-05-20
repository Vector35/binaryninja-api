
#include "binaryninjaapi.h"
#include "lifted_il_lift_check.h"
#include "llil_lift_check.h"
#include "mlil_lift_check.h"

using namespace BinaryNinja;

static Ref<Logger> g_logger;

void ReportVerifier(Ref<AnalysisContext> context, ILVerifier& verifier)
{
	auto diags = verifier.GetDiagnostics();
	size_t notes = 0;
	size_t remarks = 0;
	size_t warnings = 0;
	size_t errors = 0;

	for (auto& diag: diags)
	{
		switch (diag.severity)
		{
		case IgnoredSeverity:
			break;
		case NoteSeverity:
			notes += 1;
			break;
		case RemarkSeverity:
			remarks += 1;
			break;
		case WarningSeverity:
			warnings += 1;
			break;
		case ErrorSeverity:
		case FatalSeverity:
			errors += 1;
			break;
		}
	}

	bool debug = Settings::Instance()->Get<bool>("analysis.liftCheck.debug", context->GetBinaryView());

	if (errors > 0)
	{
		g_logger->LogErrorF(
			"{} {:#x} failed: {} errors, {} warnings",
			verifier.GetILType(),
			context->GetFunction()->GetStart(),
			errors,
			warnings
		);
	}
	else if (warnings > 0 || (debug && notes > 0 && remarks > 0))
	{
		g_logger->LogErrorF(
			"{:#x} passed: {} errors, {} warnings",
			context->GetFunction()->GetStart(),
			errors,
			warnings
		);
	}
	for (auto& diag: diags)
	{
		switch (diag.severity)
		{
		case IgnoredSeverity:
			break;
		case NoteSeverity:
			if (debug)
			{
				g_logger->LogInfoF("    {}", diag.message);
			}
			break;
		case RemarkSeverity:
			if (debug)
			{
				g_logger->LogInfoF("    {}", diag.message);
			}
			break;
		case WarningSeverity:
			g_logger->LogWarnF("    {}", diag.message);
			break;
		case ErrorSeverity:
		case FatalSeverity:
			g_logger->LogErrorF("    {}", diag.message);
			break;

		}
	}
}


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		g_logger = new Logger("LiftCheck");

		Settings::Instance()->RegisterSetting("analysis.liftCheck.debug", R"~({
			"title" : "Show Debug Diagnostics",
			"type" : "boolean",
			"default" : false,
			"description" : "Show all the diagnostics, even the notes which are not errors or warnings."
		})~");

		auto checkLiftedILFunction = [](Ref<AnalysisContext> context) {
			if (!context->GetLiftedILFunction())
				return;
			auto verifier = LiftedILVerifier(context->GetLiftedILFunction());
			verifier.Verify();
			ReportVerifier(context, verifier);
		};
		auto checkLLILFunction = [](Ref<AnalysisContext> context) {
			if (!context->GetLowLevelILFunction())
				return;
			auto verifier = LowLevelILVerifier(context->GetLowLevelILFunction());
			verifier.Verify();
			ReportVerifier(context, verifier);
		};
		auto checkMLILFunction = [](Ref<AnalysisContext> context) {
			if (!context->GetMediumLevelILFunction())
				return;
			auto verifier = MediumLevelILVerifier(context->GetMediumLevelILFunction());
			verifier.Verify();
			ReportVerifier(context, verifier);
		};

		Ref<Workflow> oldFunctionMetaWorkflow = Workflow::Instance("core.function.metaAnalysis");
		Ref<Workflow> newFunctionMetaWorkflow = oldFunctionMetaWorkflow->Clone("core.function.metaAnalysis");
		newFunctionMetaWorkflow->RegisterActivity(R"~({
			"title": "Lifted IL Lift Check",
			"name": "analysis.liftCheck.liftedIL",
			"description": "This analysis step checks various conditions on Lifted IL functions.",
			"eligibility": {
				"auto": {
					"default": false
				}
			}
		})~", checkLiftedILFunction);
		newFunctionMetaWorkflow->RegisterActivity(R"~({
			"title": "LLIL Lift Check",
			"name": "analysis.liftCheck.llil",
			"description": "This analysis step checks various conditions on LLIL functions.",
			"eligibility": {
				"auto": {
					"default": false
				}
			}
		})~", checkLLILFunction);
		newFunctionMetaWorkflow->RegisterActivity(R"~({
			"title": "MLIL Lift Check",
			"name": "analysis.liftCheck.mlil",
			"description": "This analysis step checks various conditions on MLIL functions.",
			"eligibility": {
				"auto": {
					"default": false
				}
			}
		})~", checkMLILFunction);
		newFunctionMetaWorkflow->Insert("core.function.analyzeAndExpandFlags", "analysis.liftCheck.liftedIL");
		newFunctionMetaWorkflow->Insert("core.function.generateMediumLevelIL", "analysis.liftCheck.llil");
		newFunctionMetaWorkflow->Insert("core.function.generateHighLevelIL", "analysis.liftCheck.mlil");
		Workflow::RegisterWorkflow(newFunctionMetaWorkflow);
		return true;
	}
}


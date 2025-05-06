
#include "binaryninjaapi.h"
#include "lifted_il_lift_check.h"
#include "llil_lift_check.h"

using namespace BinaryNinja;

static Ref<Logger> g_logger;

void ReportVerifier(Ref<AnalysisContext> context, ILVerifier& verifier)
{
	std::vector<ILVerifier::Diagnostic> notes;
	std::vector<ILVerifier::Diagnostic> remarks;
	std::vector<ILVerifier::Diagnostic> warnings;
	std::vector<ILVerifier::Diagnostic> errors;

	for (auto& diag: verifier.GetDiagnostics())
	{
		switch (diag.severity)
		{
		case IgnoredSeverity:
			break;
		case NoteSeverity:
			notes.push_back(diag);
			break;
		case RemarkSeverity:
			remarks.push_back(diag);
			break;
		case WarningSeverity:
			warnings.push_back(diag);
			break;
		case ErrorSeverity:
		case FatalSeverity:
			errors.push_back(diag);
			break;
		}
	}

	bool debug = Settings::Instance()->Get<bool>("analysis.liftCheck.debug", context->GetBinaryView());

	if (errors.size() > 0)
	{
		g_logger->LogErrorF(
			"{:#x} failed: {} errors, {} warnings",
			context->GetFunction()->GetStart(),
			errors.size(),
			warnings.size()
		);
	}
	else if (warnings.size() > 0 || (debug && notes.size() > 0 && remarks.size() > 0))
	{
		g_logger->LogErrorF(
			"{:#x} passed: {} errors, {} warnings",
			context->GetFunction()->GetStart(),
			errors.size(),
			warnings.size()
		);
	}
	if (debug)
	{
		for (auto& diag: notes)
		{
			g_logger->LogInfoF("    {}", diag.message);
		}
		for (auto& diag: remarks)
		{
			g_logger->LogInfoF("    {}", diag.message);
		}
	}
	for (auto& diag: warnings)
	{
		g_logger->LogWarnF("    {}", diag.message);
	}
	for (auto& diag: errors)
	{
		g_logger->LogErrorF("    {}", diag.message);
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
		newFunctionMetaWorkflow->Insert("core.function.analyzeAndExpandFlags", "analysis.liftCheck.liftedIL");
		newFunctionMetaWorkflow->Insert("core.function.generateMediumLevelIL", "analysis.liftCheck.llil");
		Workflow::RegisterWorkflow(newFunctionMetaWorkflow);
		return true;
	}
}


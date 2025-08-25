#include "DxeResolver.h"
#include "PeiResolver.h"
#include "binaryninjaapi.h"
#include <thread>

using namespace BinaryNinja;

static Ref<BackgroundTask> m_efiBackgroundTask = nullptr;

bool IsValid(BinaryView* view)
{
	if (!view)
		return false;

	auto platform = view->GetDefaultPlatform();
	return (platform && platform->GetName().find("efi-") != std::string::npos);
}


void RunCommand(Ref<BinaryView> view)
{
	m_efiBackgroundTask = new BackgroundTask("Running EFI resolver...", true);
	thread resolverThread([view]() {
		LogInfo("Identifying EFI module type...");
		EFIModuleType moduleType = identifyModuleType(view);

		auto undo = view->BeginUndoActions();
		if (moduleType == PEI)
		{
			m_efiBackgroundTask->SetProgressText("Resolving PEIM...");
			auto resolver = PeiResolver(view, m_efiBackgroundTask);
			resolver.resolvePei();
		}
		else if (moduleType == DXE)
		{
			m_efiBackgroundTask->SetProgressText("Resolving DXE protocols...");
			auto resolver = DxeResolver(view, m_efiBackgroundTask);
			resolver.resolveDxe();
			m_efiBackgroundTask->SetProgressText("Resolving MM related protocols...");
			resolver.resolveSmm();
		}
		view->CommitUndoActions(undo);
		m_efiBackgroundTask->Finish();
	});

	resolverThread.detach();
}


void RunWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (IsValid(view))
		RunCommand(view);
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		EfiGuidRenderer::Register();
		auto workflow = Workflow::Get("core.module.metaAnalysis")->Clone();
		workflow->RegisterActivity(R"~({
			"title": "EFI Resolver",
			"name": "analysis.efi.efiResolver",
			"role": "action",
			"description": "This analysis step resolves EFI protocol interfaces and propagates type information.",
			"eligibility": {
				"runOnce": true,
				"auto": {}
			},
			"dependencies": {
				"downstream": ["core.module.update"]
			}
		})~", &RunWorkflow);

		workflow->InsertAfter("core.module.extendedAnalysis", "analysis.efi.efiResolver");
		Workflow::RegisterWorkflow(workflow);
		PluginCommand::Register("Run EFI Resolver", "Resolve EFI interfaces and types", &RunCommand, &IsValid);
		return true;
	}
}

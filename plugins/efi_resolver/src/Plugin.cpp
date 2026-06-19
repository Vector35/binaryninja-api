#include "DxeResolver.h"
#include "PeiResolver.h"
#include "binaryninjaapi.h"
#include <exception>
#include <thread>

using namespace BinaryNinja;

bool IsValid(BinaryView* view)
{
	if (!view)
		return false;

	auto platform = view->GetDefaultPlatform();
	return (platform && platform->GetName().find("efi-") != std::string::npos);
}


static void RunResolver(Ref<BinaryView> view, Ref<BackgroundTask> task)
{
	LogInfo("Identifying EFI module type...");
	EFIModuleType moduleType = identifyModuleType(view);

	auto undo = view->BeginUndoActions();
	if (moduleType == PEI)
	{
		task->SetProgressText("Resolving PEIM...");
		auto resolver = PeiResolver(view, task);
		resolver.resolvePei();
	}
	else if (moduleType == DXE)
	{
		task->SetProgressText("Resolving DXE protocols...");
		auto resolver = DxeResolver(view, task);
		resolver.resolveDxe();
		task->SetProgressText("Resolving MM related protocols...");
		resolver.resolveSmm();
	}
	view->CommitUndoActions(undo);
	task->Finish();
}


static void StartResolverThread(Ref<BinaryView> view)
{
	Ref<BackgroundTask> task = new BackgroundTask("Running EFI resolver...", true);
	thread resolverThread([view, task]() {
		try
		{
			RunResolver(view, task);
		}
		catch (std::exception& e)
		{
			LogErrorForException(e, "EFI resolver failed with uncaught exception: %s", e.what());
		}
		catch (...)
		{
			LogError("EFI resolver failed with unknown uncaught exception.");
		}
	});

	resolverThread.detach();
}


void RunCommand(Ref<BinaryView> view)
{
	StartResolverThread(view);
}


void RunWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (IsValid(view))
		StartResolverThread(view);
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

#include "DxeResolver.h"
#include "PeiResolver.h"
#include "binaryninjaapi.h"
#include <exception>
#include <thread>

using namespace BinaryNinja;

struct EfiWorkflowState
{
	EFIModuleType moduleType = UNKNOWN;
	bool initializedEntry = false;
	bool propagatedEntryTypes = false;
	bool resolvedProtocols = false;
};

bool IsValid(BinaryView* view)
{
	if (!view)
		return false;

	auto platform = view->GetDefaultPlatform();
	return (platform && platform->GetName().find("efi-") != std::string::npos);
}


static bool IdentifyAndInitializeEntry(Ref<BinaryView> view, Ref<BackgroundTask> task, EfiWorkflowState& state)
{
	LogInfo("Identifying EFI module type...");
	state.moduleType = identifyModuleType(view);

	if (state.moduleType == PEI)
	{
		if (task)
			task->SetProgressText("Initializing PEIM entry...");
		PeiResolver resolver(view, task);
		state.initializedEntry = resolver.setModuleEntry(PEI);
	}
	else if (state.moduleType == DXE)
	{
		if (task)
			task->SetProgressText("Initializing DXE entry...");
		DxeResolver resolver(view, task);
		state.initializedEntry = resolver.setModuleEntry(DXE);
	}
	else
	{
		LogAlertF("Could not identify EFI module type");
		return false;
	}

	return state.initializedEntry;
}


static bool PropagateEntryTypes(Ref<BinaryView> view, Ref<BackgroundTask> task, EfiWorkflowState& state)
{
	if (!state.initializedEntry)
		return false;

	if (state.moduleType == PEI)
	{
		if (task)
			task->SetProgressText("Propagating PEIM entry types...");
		PeiResolver resolver(view, task);
		state.propagatedEntryTypes = resolver.propagateEntryTypes();
	}
	else if (state.moduleType == DXE)
	{
		if (task)
			task->SetProgressText("Propagating DXE entry types...");
		DxeResolver resolver(view, task);
		state.propagatedEntryTypes = resolver.propagateEntryTypes();
	}

	return state.propagatedEntryTypes;
}


static bool ResolveProtocols(Ref<BinaryView> view, Ref<BackgroundTask> task, EfiWorkflowState& state)
{
	if (!state.propagatedEntryTypes)
		return false;

	if (state.moduleType == PEI)
	{
		if (task)
			task->SetProgressText("Resolving PEIM...");
		auto resolver = PeiResolver(view, task);
		state.resolvedProtocols = resolver.resolvePei();
	}
	else if (state.moduleType == DXE)
	{
		if (task)
			task->SetProgressText("Resolving DXE protocols...");
		auto resolver = DxeResolver(view, task);
		state.resolvedProtocols = resolver.resolveDxe();
		if (state.resolvedProtocols)
		{
			if (task)
				task->SetProgressText("Resolving MM related protocols...");
			state.resolvedProtocols = resolver.resolveSmm();
		}
	}

	return state.resolvedProtocols;
}


static void RunCommandStages(Ref<BinaryView> view, Ref<BackgroundTask> task)
{
	EfiWorkflowState state;
	if (!IdentifyAndInitializeEntry(view, task, state))
		return;
	view->UpdateAnalysisAndWait();

	if (!PropagateEntryTypes(view, task, state))
		return;
	view->UpdateAnalysisAndWait();

	if (!ResolveProtocols(view, task, state))
		return;
	view->UpdateAnalysisAndWait();
}


void RunCommand(Ref<BinaryView> view)
{
	Ref<BackgroundTask> task = new BackgroundTask("Running EFI resolver...", true);
	std::thread resolverThread([view, task]() {
		try
		{
			RunCommandStages(view, task);
		}
		catch (std::exception& e)
		{
			LogErrorForException(e, "EFI resolver failed with uncaught exception: %s", e.what());
		}
		catch (...)
		{
			LogError("EFI resolver failed with unknown uncaught exception.");
		}
		task->Finish();
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
			"description": "Resolve EFI protocol interfaces and propagate type information.",
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

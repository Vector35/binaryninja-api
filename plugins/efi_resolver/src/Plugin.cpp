#include "DxeResolver.h"
#include "PeiResolver.h"
#include "binaryninjaapi.h"
#include <exception>
#include <thread>

using namespace BinaryNinja;

// The next phase is persisted with the view so an interrupted workflow can resume.
// Complete is only reached after analysis of the final resolver phase has finished.
// Keep these values stable for saved databases.
enum class EfiStage : uint64_t
{
	InitializeEntry = 0,
	PropagateEntryTypes = 1,
	PeiPointers = 2,
	PeiServicePointers = 3,
	PeiDescriptors = 4,
	PeiServices = 5,
	DxeProtocols = 6,
	SmmTables = 7,
	SmmServices = 8,
	SmiHandlers = 9,
	Finish = 10,
	Complete = 100,
	Failed = 101
};

static constexpr const char* EFI_PROPAGATION_METADATA = "efi.resolver.pendingPropagation";
static constexpr const char* EFI_STAGE_METADATA = "efi.resolver.nextStage";

bool IsValid(BinaryView* view)
{
	if (!view)
		return false;

	auto platform = view->GetDefaultPlatform();
	return (platform && platform->GetName().find("efi-") != std::string::npos);
}


static EfiStage RunStage(Ref<BinaryView> view, Ref<BackgroundTask> task, EfiStage stage, TypePropagation& propagation)
{
	if (propagation.HasPendingFunctions())
	{
		propagation.ProcessNextFunction();
		return stage;
	}

	auto moduleType = identifyModuleType(view);
	if (moduleType == UNKNOWN)
	{
		LogAlertF("Could not identify EFI module type");
		return EfiStage::Failed;
	}

	switch (stage)
	{
	case EfiStage::InitializeEntry:
	{
		if (task)
			task->SetProgressText("Initializing EFI entry...");
		Resolver resolver(view, task, propagation);
		return resolver.setModuleEntry(moduleType) ? EfiStage::PropagateEntryTypes : EfiStage::Failed;
	}
	case EfiStage::PropagateEntryTypes:
	{
		if (task)
			task->SetProgressText("Propagating EFI entry types...");
		Resolver resolver(view, task, propagation);
		if (!resolver.propagateEntryTypes())
			return EfiStage::Failed;
		return moduleType == PEI ? EfiStage::PeiPointers : EfiStage::DxeProtocols;
	}
	case EfiStage::PeiPointers:
		return PeiResolver(view, task, propagation).resolvePlatformPointers() ? EfiStage::PeiServicePointers : EfiStage::Failed;
	case EfiStage::PeiServicePointers:
		return PeiResolver(view, task, propagation).resolveServicePointers() ? EfiStage::PeiDescriptors : EfiStage::Failed;
	case EfiStage::PeiDescriptors:
		return PeiResolver(view, task, propagation).resolvePeiDescriptors() ? EfiStage::PeiServices : EfiStage::Failed;
	case EfiStage::PeiServices:
		return PeiResolver(view, task, propagation).resolvePeiServices() ? EfiStage::Finish : EfiStage::Failed;
	case EfiStage::DxeProtocols:
		return DxeResolver(view, task, propagation).resolveDxe() ? EfiStage::SmmTables : EfiStage::Failed;
	case EfiStage::SmmTables:
	{
		DxeResolver resolver(view, task, propagation);
		if (!resolver.resolveSmmTables("EFI_SMM_GET_SMST_LOCATION2", "EFI_SMM_SYSTEM_TABLE2*")
			|| !resolver.resolveSmmTables("EFI_MM_GET_MMST_LOCATION", "EFI_MM_SYSTEM_TABLE*"))
			return EfiStage::Failed;
		return EfiStage::SmmServices;
	}
	case EfiStage::SmmServices:
		return DxeResolver(view, task, propagation).resolveSmmServices() ? EfiStage::SmiHandlers : EfiStage::Failed;
	case EfiStage::SmiHandlers:
		return DxeResolver(view, task, propagation).resolveSmiHandlers() ? EfiStage::Finish : EfiStage::Failed;
	case EfiStage::Finish:
	case EfiStage::Complete:
		return EfiStage::Complete;
	default:
		return EfiStage::Failed;
	}
}


static void RunCommandStages(Ref<BinaryView> view, Ref<BackgroundTask> task)
{
	TypePropagation propagation(view);
	auto stage = EfiStage::InitializeEntry;
	while (stage != EfiStage::Complete && stage != EfiStage::Failed && !task->IsCancelled())
	{
		stage = RunStage(view, task, stage, propagation);
		view->UpdateAnalysisAndWait();
	}
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


static EfiStage GetWorkflowStage(Ref<BinaryView> view)
{
	auto metadata = view->QueryMetadata(EFI_STAGE_METADATA);
	return metadata ? static_cast<EfiStage>(metadata->GetUnsignedInteger()) : EfiStage::InitializeEntry;
}


static bool IsWorkflowEligible(Ref<Activity>, Ref<AnalysisContext> analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	return IsValid(view) && GetWorkflowStage(view) < EfiStage::Complete;
}


void RunWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	auto nextStage = EfiStage::Failed;
	// Inspect IL and discover annotations on the workflow thread. Only the
	// resulting writes are dispatched to the main thread in short undo scopes.
	TypePropagation propagation(view, true);
	try
	{
		if (IsValid(view))
		{
			propagation.RestoreState(view->QueryMetadata(EFI_PROPAGATION_METADATA));
			nextStage = RunStage(view, nullptr, GetWorkflowStage(view), propagation);
		}
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "EFI resolver failed with uncaught exception: %s", e.what());
	}
	catch (...)
	{
		LogError("EFI resolver failed with unknown uncaught exception.");
	}

	Ref<Metadata> pending;
	if (nextStage < EfiStage::Complete && propagation.HasPendingFunctions())
		pending = propagation.SaveState();
	propagation.GetUpdates().Apply([&]() {
		if (pending)
			view->StoreMetadata(EFI_PROPAGATION_METADATA, pending, MetadataStorePersistent);
		else
			view->RemoveMetadata(EFI_PROPAGATION_METADATA);
		view->StoreMetadata(EFI_STAGE_METADATA, new Metadata(static_cast<uint64_t>(nextStage)), MetadataStorePersistent);
	});
	// Disable only after finishing (or failing), including when an explicit
	// eligibility override would otherwise force the continuation to keep running.
	if (nextStage >= EfiStage::Complete)
		WorkflowMachine(view).SetOverride("analysis.efi.efiResolver", false);

	// Return to the workflow after each phase. The downstream core.module.update
	// subflow drains pending analysis before this continuation is invoked again.
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		EfiGuidRenderer::Register();
		auto workflow = Workflow::Get("core.module.metaAnalysis")->Clone();
		workflow->RegisterActivity(new Activity(R"~({
			"title": "EFI Resolver",
			"name": "analysis.efi.efiResolver",
			"role": "action",
			"description": "Resolve EFI protocol interfaces and propagate type information.",
			"eligibility": {
				"continuation": true,
				"auto": {}
			},
			"dependencies": {
				"downstream": ["core.module.update"]
			}
		})~", &RunWorkflow, &IsWorkflowEligible));

		workflow->InsertAfter("core.module.extendedAnalysis", "analysis.efi.efiResolver");
		Workflow::RegisterWorkflow(workflow);
		PluginCommand::Register("Run EFI Resolver", "Resolve EFI interfaces and types", &RunCommand, &IsValid);
		return true;
	}
}

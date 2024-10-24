#include "rtti.h"

#include <thread>

using namespace BinaryNinja;

static Ref<BackgroundTask> rttiBackgroundTask = nullptr;
static Ref<BackgroundTask> vftBackgroundTask = nullptr;

void ScanRTTI(Ref<BinaryView> view)
{
	std::thread scanThread([view = std::move(view)]() {
		rttiBackgroundTask = new BackgroundTask("Scanning for RTTI...", false);
		auto processor = MicrosoftRTTIProcessor(view);
		processor.ProcessRTTI();
		view->StoreMetadata(VIEW_METADATA_MSVC, processor.SerializedMetadata(), true);
		rttiBackgroundTask->Finish();
	});
	scanThread.detach();
}

void ScanVFT(Ref<BinaryView> view)
{
	std::thread scanThread([view = std::move(view)]() {
		vftBackgroundTask = new BackgroundTask("Scanning for VFTs...", false);
		auto processor = MicrosoftRTTIProcessor(view);
		processor.ProcessVFT();
		view->StoreMetadata(VIEW_METADATA_MSVC, processor.SerializedMetadata(), true);
		vftBackgroundTask->Finish();
	});
	scanThread.detach();
}

bool MetadataExists(Ref<BinaryView> view)
{
	return view->QueryMetadata(VIEW_METADATA_MSVC) != nullptr;
}


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		// TODO: In the future we will have a module level workflow which:
		// TODO:	1. Symbolizes RTTI information
		// TODO:	2. Creates Virtual Function Tables
		// TODO:	3. Populates MSVC metadata entry
		// TODO: And a function level workflow which:
		// TODO:	1. Uses MSVC metadata to identify if a function is apart of a VFT
		// TODO:	2. Identify if the function is unique to a class, renaming and retyping if true
		// TODO:	3. Identify functions which address a VFT and are probably a constructor (alloc use), retyping if true
		// TODO:	4. Identify functions which address a VFT and are probably a deconstructor (free use), retyping if true

		// Ref<Workflow> msvcWorkflow = Workflow::Instance("core.function.defaultAnalysis")->Clone("MSVCWorkflow");
		// msvcWorkflow->RegisterActivity(new Activity("extension.msvc.rttiAnalysis", &RTTIAnalysis));
		// msvcWorkflow->Insert("core.module.defaultAnalysis", "extension.msvc.rttiAnalysis");
		// Workflow::RegisterWorkflow(msvcWorkflow,
		// 	R"#({
		// 	"title" : "MSVC Workflow",
		// 	"description" : "Analyze MSVC RTTI",
		// 	"capabilities" : []
		// 	})#");

		PluginCommand::Register("MSVC\\Find RTTI", "Scans for all RTTI in view.", ScanRTTI);
		PluginCommand::Register("MSVC\\Find VFTs", "Scans for all VFTs in the view.", ScanVFT, MetadataExists);

		return true;
	}
}
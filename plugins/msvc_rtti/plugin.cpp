#include "rtti.h"

#include <thread>

using namespace BinaryNinja;

static Ref<BackgroundTask> rttiBackgroundTask = nullptr;
static Ref<BackgroundTask> vftBackgroundTask = nullptr;


bool MetadataExists(Ref<BinaryView> view)
{
	return view->QueryMetadata(VIEW_METADATA_MSVC) != nullptr;
}


void RTTIAnalysis(Ref<AnalysisContext> analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	auto platform = view->GetDefaultPlatform();
	if (!platform)
		return;
	auto platformName = platform->GetName();
	// We currently only want to check for MSVC rtti on windows platforms
	if (platformName.find("window") == std::string::npos)
		return;
	auto processor = MicrosoftRTTIProcessor(view);
	processor.ProcessRTTI();
	view->StoreMetadata(VIEW_METADATA_MSVC, processor.SerializedMetadata(), true);
}


void VFTAnalysis(Ref<AnalysisContext> analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (!MetadataExists(view))
		return;
	auto processor = MicrosoftRTTIProcessor(view);
	processor.ProcessVFT();
	view->StoreMetadata(VIEW_METADATA_MSVC, processor.SerializedMetadata(), true);
}


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		// TODO: In the future we will have a function level workflow which:
		// TODO:	1. Uses MSVC metadata to identify if a function is apart of a VFT
		// TODO:		a. Or possibly we can tag some info to the function as apart of the VFT analysis, this would save a lookup.
		// TODO:	2. Identify if the function is unique to a class, renaming and retyping if true
		// TODO:	3. Identify functions which address a VFT and are probably a constructor (alloc use), retyping if true
		// TODO:	4. Identify functions which address a VFT and are probably a deconstructor (free use), retyping if true
		Ref<Workflow> msvcMetaWorkflow = Workflow::Instance("core.module.metaAnalysis")->Clone("core.module.metaAnalysis");

		// Add RTTI analysis.
		msvcMetaWorkflow->RegisterActivity(R"~({
			"title": "MSVC RTTI Analysis",
			"name": "plugin.msvc.rttiAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize msvc rtti information.",
			"eligibility": {
				"runOnce": true,
				"auto": {}
			}
		})~", &RTTIAnalysis);
		// Add Virtual Function Table analysis.
		msvcMetaWorkflow->RegisterActivity(R"~({
			"title": "MSVC VFT Analysis",
			"name": "plugin.msvc.vftAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize msvc virtual function table information.",
			"eligibility": {
				"runOnce": true,
				"auto": {}
			}
		})~", &VFTAnalysis);

		// Run rtti before debug info is applied.
		msvcMetaWorkflow->Insert("core.module.loadDebugInfo", "plugin.msvc.rttiAnalysis");
		// Run vft after functions have analyzed (so that the virtual functions have analyzed)
		msvcMetaWorkflow->Insert("core.module.notifyCompletion", "plugin.msvc.vftAnalysis");
		Workflow::RegisterWorkflow(msvcMetaWorkflow);

		return true;
	}
}
#include "rtti.h"
#include "microsoft.h"
#include "itanium.h"

#include <thread>

using namespace BinaryNinja;

// TODO: Split the activities so that there is two for microsoft and itanium.

bool MetadataExists(const Ref<BinaryView>& view)
{
	return view->QueryMetadata(VIEW_METADATA_RTTI) != nullptr;
}


void RTTIAnalysis(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	auto platform = view->GetDefaultPlatform();
	if (!platform)
		return;
	auto platformName = platform->GetName();
	if (platformName.find("window") != std::string::npos)
	{
		// We currently only want to check for MSVC rtti on windows platforms
		auto processor = RTTI::Microsoft::MicrosoftRTTIProcessor(view);
		processor.ProcessRTTI();
		view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
	}
	else
	{
		// TODO: We currently only want to check for itanium rtti on non windows platforms
		// TODO: This needs to always run.
		auto processor = RTTI::Itanium::ItaniumRTTIProcessor(view);
		processor.ProcessRTTI();
		view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
	}
}


void VFTAnalysis(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (!MetadataExists(view))
		return;
	// TODO: Run for both itanium and ms (depending on platform)
	auto processor = RTTI::Microsoft::MicrosoftRTTIProcessor(view);
	processor.ProcessVFT();
	auto itaniumProcessor = RTTI::Itanium::ItaniumRTTIProcessor(view);
	itaniumProcessor.ProcessVTT();
	view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
}


void MakeItaniumRTTIHere(Ref<BinaryView> view, uint64_t addr)
{
	auto processor = RTTI::Itanium::ItaniumRTTIProcessor(view);
	processor.ProcessRTTI(addr);
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
		Ref<Workflow> rttiMetaWorkflow = Workflow::Instance("core.module.metaAnalysis")->Clone("core.module.metaAnalysis");

		PluginCommand::RegisterForAddress("Itanium\\Make RTTI Here", "", MakeItaniumRTTIHere);

		// Add RTTI analysis.
		rttiMetaWorkflow->RegisterActivity(R"~({
			"title": "RTTI Analysis",
			"name": "plugin.rtti.rttiAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize rtti information.",
			"eligibility": {
				"runOnce": true,
				"auto": {}
			}
		})~", &RTTIAnalysis);
		// Add Virtual Function Table analysis.
		rttiMetaWorkflow->RegisterActivity(R"~({
			"title": "VFT Analysis",
			"name": "plugin.rtti.vftAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize virtual function table information.",
			"eligibility": {
				"runOnce": true,
				"auto": {}
			}
		})~", &VFTAnalysis);

		// Run rtti before debug info is applied.
		rttiMetaWorkflow->Insert("core.module.loadDebugInfo", "plugin.rtti.rttiAnalysis");
		// Run vft after functions have analyzed (so that the virtual functions have analyzed)
		rttiMetaWorkflow->Insert("core.module.notifyCompletion", "plugin.rtti.vftAnalysis");
		Workflow::RegisterWorkflow(rttiMetaWorkflow);

		return true;
	}
}
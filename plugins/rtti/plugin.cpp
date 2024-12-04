#include "rtti.h"
#include "microsoft.h"
#include "itanium.h"

using namespace BinaryNinja;


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

	auto processor = RTTI::Itanium::ItaniumRTTIProcessor(view);
	processor.ProcessRTTI();
	view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
}


void VFTAnalysis(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (!MetadataExists(view))
		return;
	auto microsoftProcessor = RTTI::Microsoft::MicrosoftRTTIProcessor(view);
	microsoftProcessor.ProcessVFT();
	// TODO: We have to store the data for the second processor to pick up the info.
	view->StoreMetadata(VIEW_METADATA_RTTI, microsoftProcessor.SerializedMetadata(), true);
	auto itaniumProcessor = RTTI::Itanium::ItaniumRTTIProcessor(view);
	itaniumProcessor.ProcessVFT();
	view->StoreMetadata(VIEW_METADATA_RTTI, itaniumProcessor.SerializedMetadata(), true);
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
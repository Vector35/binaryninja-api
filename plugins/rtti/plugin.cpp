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
		try
		{
			auto processor = RTTI::Microsoft::MicrosoftRTTIProcessor(view);
			processor.ProcessRTTI();
			view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
		}
		catch (std::exception& e)
		{
			LogErrorForException(e, "MSVC RTTI Analysis failed with uncaught exception: %s", e.what());
		}
	}

	try
	{
		auto processor = RTTI::Itanium::ItaniumRTTIProcessor(view);
		processor.ProcessRTTI();
		view->StoreMetadata(VIEW_METADATA_RTTI, processor.SerializedMetadata(), true);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Itanium RTTI Analysis failed with uncaught exception: %s", e.what());
	}
}


void VFTAnalysis(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	if (!MetadataExists(view))
		return;
	try
	{
		auto microsoftProcessor = RTTI::Microsoft::MicrosoftRTTIProcessor(view);
		microsoftProcessor.ProcessVFT();
		// TODO: We have to store the data for the second processor to pick up the info.
		view->StoreMetadata(VIEW_METADATA_RTTI, microsoftProcessor.SerializedMetadata(), true);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "MSVC VFT Analysis failed with uncaught exception: %s", e.what());
	}

	try
	{
		auto itaniumProcessor = RTTI::Itanium::ItaniumRTTIProcessor(view);
		itaniumProcessor.ProcessVFT();
		view->StoreMetadata(VIEW_METADATA_RTTI, itaniumProcessor.SerializedMetadata(), true);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Itanium VFT Analysis failed with uncaught exception: %s", e.what());
	}
}


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
		bool RTTIPluginInit()
#else
		BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		// TODO: In the future we will have a function level workflow which:
		// TODO:	1. Uses MSVC metadata to identify if a function is apart of a VFT
		// TODO:		a. Or possibly we can tag some info to the function as apart of the VFT analysis, this would save a lookup.
		// TODO:	2. Identify if the function is unique to a class, renaming and retyping if true
		// TODO:	3. Identify functions which address a VFT and are probably a constructor (alloc use), retyping if true
		// TODO:	4. Identify functions which address a VFT and are probably a deconstructor (free use), retyping if true
		Ref<Workflow> rttiMetaWorkflow = Workflow::Get("core.module.metaAnalysis")->Clone();

		// Add RTTI analysis.
		rttiMetaWorkflow->RegisterActivity(R"~({
			"title": "RTTI Analysis",
			"name": "analysis.rtti.rttiAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize rtti information.",
			"aliases": ["plugin.msvc.rttiAnalysis"],
			"eligibility": {
				"runOnce": true,
				"auto": {}
			}
		})~", &RTTIAnalysis);
		// Add Virtual Function Table analysis.
		rttiMetaWorkflow->RegisterActivity(R"~({
			"title": "VFT Analysis",
			"name": "analysis.rtti.vftAnalysis",
			"role": "action",
			"description": "This analysis step attempts to parse and symbolize virtual function table information.",
			"aliases": ["plugin.msvc.vftAnalysis"],
			"eligibility": {
				"runOnce": true,
				"auto": {}
			},
			"dependencies": {
				"downstream": ["core.module.update"]
			}
		})~", &VFTAnalysis);

		// Run rtti before debug info is applied.
		rttiMetaWorkflow->Insert("core.module.loadDebugInfo", "analysis.rtti.rttiAnalysis");
		// Run vft after functions have analyzed (so that the virtual functions have analyzed)
		rttiMetaWorkflow->InsertAfter("core.module.extendedAnalysis", "analysis.rtti.vftAnalysis");
		Workflow::RegisterWorkflow(rttiMetaWorkflow);

		return true;
	}
}
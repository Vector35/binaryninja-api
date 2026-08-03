#include <binaryninjaapi.h>

#include <filesystem>

#include "processor.h"
#include "provider.h"

using namespace BinaryNinja;

namespace {
	void ExportBinExport(BinaryView* view)
	{
		const std::string inputFilename = view->GetFile()->GetFilename();
		std::filesystem::path outputPath = inputFilename.empty() ? "export.BinExport" : inputFilename;
		outputPath.replace_extension(".BinExport");

		if (IsUIEnabled())
		{
			std::string selectedPath;
			if (!GetSaveFileNameInput(
					selectedPath, "Export BinExport", "BinExport files (*.BinExport)", outputPath.string()))
				return;
			outputPath = selectedPath;
		}
		else if (inputFilename.empty())
		{
			LogError("Cannot export an unsaved view to BinExport in headless mode");
			return;
		}

		bool success;
		{
			BinDiffProcessor processor(*view);
			for (const auto& function : view->GetAnalysisFunctionList())
				processor.AddFunction(*function);
			success = processor.Process(outputPath.string());
		}
		if (!success && IsUIEnabled())
		{
			ShowMessageBox("BinExport Failed", "The BinExport file could not be written. See the log for details.",
				OKButtonSet, ErrorIcon);
		}
	}
}  // namespace

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool GoogleBinDiffPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		PluginCommand::Register("BinExport", "Export to BinDiff binary", ExportBinExport);

		SimilarityProviderType::Register(new GoogleSimilarityProviderType());
		return true;
	}
}

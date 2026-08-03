#include <binaryninjaapi.h>

#include "processor.h"
#include "provider.h"

using namespace BinaryNinja;

namespace {
	void ExportBinExport(BinaryView* view)
	{
		const std::string inputFilename = view->GetFile()->GetFilename();
		std::string outputPath = inputFilename.empty() ? "export.BinExport" : inputFilename;
		if (!inputFilename.empty())
		{
			const size_t separator = outputPath.find_last_of("/\\");
			const size_t filenameStart = separator == std::string::npos ? 0 : separator + 1;
			const size_t extension = outputPath.find_last_of('.');
			if ((extension != std::string::npos) && (extension > filenameStart))
				outputPath.resize(extension);
			outputPath += ".BinExport";
		}

		if (IsUIEnabled())
		{
			std::string selectedPath;
			if (!GetSaveFileNameInput(selectedPath, "Export BinExport", "BinExport files (*.BinExport)", outputPath))
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
			success = processor.Process(outputPath);
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

//
// Created by kat on 5/22/23.
//

#include "dscpicker.h"
#include <sharedcacheapi.h>
#include "progresstask.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

void DisplayDSCPicker(UIContext* ctx, Ref<BinaryView> dscView)
{
	auto getImageNames = [dscView](QVariant var) {
		auto controller = SharedCacheController::GetController(*dscView);
		if (!controller)
			return QStringList();

		QStringList entries = {};
		for (const auto& img : controller->GetImages())
			entries.push_back(QString::fromStdString(img.name));
		return entries;
	};

	auto getChosenImage = [ctx](QVariant var) {
		QStringList entries = var.toStringList();

		auto choiceDialog = new MetadataChoiceDialog(ctx ? ctx->mainWindow() : nullptr, "Pick Image", "Select", entries);
		choiceDialog->AddWidthRequiredByItem(ctx, 300);
		choiceDialog->AddHeightRequiredByItem(ctx, 150);
		choiceDialog->exec();

		if (!choiceDialog->GetChosenEntry().has_value())
			return QVariant("");

		return QVariant(QString::fromStdString(entries.at((qsizetype)choiceDialog->GetChosenEntry().value().idx).toStdString()));
	};

	auto loadSelectedImage = [dscView](QVariant var) {
		auto selectedImageName = var.toString().toStdString();
		if (selectedImageName.empty())
			return;

		if (auto controller = SharedCacheController::GetController(*dscView))
		{
			if (const auto selectedImage = controller->GetImageWithName( selectedImageName))
			{
				controller->ApplyImage(*dscView, *selectedImage);
				dscView->AddAnalysisOption("linearsweep");
				dscView->AddAnalysisOption("pointersweep");
				dscView->UpdateAnalysis();
			}
		}
	};


	BackgroundThread::create(ctx ? ctx->mainWindow() : nullptr)
		->thenBackground([getImageNames](QVariant var){ return getImageNames(var); })
		->thenMainThread([getChosenImage](QVariant var){ return getChosenImage(var); })
		->thenBackground([loadSelectedImage](QVariant var){ return loadSelectedImage(var); })
		->start();
}

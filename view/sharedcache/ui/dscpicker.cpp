//
// Created by kat on 5/22/23.
//

#include "dscpicker.h"
#include <sharedcacheapi.h>
#include "progresstask.h"

#include <utility>

using namespace BinaryNinja;

void DisplayDSCPicker(UIContext* ctx, Ref<BinaryView> dscView)
{
	BackgroundThread::create(ctx ? ctx->mainWindow() : nullptr)->thenBackground(
		[dscView=dscView](QVariant var) {
			QStringList entries;
			Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(dscView);

			for (const auto& img : cache->GetAvailableImages())
			  entries.push_back(QString::fromStdString(img));

			return entries;
		})->thenMainThread([ctx](QVariant var){
			QStringList entries = var.toStringList();

			auto choiceDialog = new MetadataChoiceDialog(ctx ? ctx->mainWindow() : nullptr, "Pick Image", "Select", entries);
			choiceDialog->AddWidthRequiredByItem(ctx, 300);
			choiceDialog->AddHeightRequiredByItem(ctx, 150);
			choiceDialog->exec();

			if (choiceDialog->GetChosenEntry().has_value())
				return QVariant(QString::fromStdString(entries.at((qsizetype)choiceDialog->GetChosenEntry().value().idx).toStdString()));
			else
				return QVariant("");
		})->thenBackground([dscView=dscView](QVariant var){
			if (var.toString().isEmpty())
				return;
			Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(dscView);
			cache->LoadImageWithInstallName(var.toString().toStdString());
		})->start();
}

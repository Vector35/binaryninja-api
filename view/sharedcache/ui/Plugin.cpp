//
// Created by kat on 8/6/24.
//
#include <binaryninjaapi.h>
#include "SharedCacheUINotifications.h"
#include "dsctriage.h"

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		UINotifications::init();
		UIAction::registerAction("Load Image by Name");
		UIAction::registerAction("Load Section by Address");
		UIAction::registerAction("Load ADDRHERE");
		UIAction::registerAction("Load IMGHERE");

		DSCTriageViewType::Register();

		return true;
	}
}
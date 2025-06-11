//
// Created by kat on 8/6/24.
//
#include <binaryninjaapi.h>
#include "KernelCacheUINotifications.h"
#include "kctriage.h"

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		UINotifications::init();
		UIAction::registerAction("KC Load IMGHERE");

		KCTriageViewType::Register();

		return true;
	}
}
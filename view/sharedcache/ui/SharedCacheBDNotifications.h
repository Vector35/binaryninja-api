//
// Created by kat on 8/22/24.
//

#pragma once

#include <binaryninjaapi.h>
#include "ui/uicontext.h"
#include "SharedCacheUINotifications.h"

using namespace BinaryNinja;

class SharedCacheBDNotifications : public BinaryDataNotification
{
public:
	SharedCacheBDNotifications(Ref<BinaryView> view);
	void OnAnalysisFunctionAdded(BinaryView* view, Function* func) override;
	void OnDataVariableAdded(BinaryView* view, const DataVariable& var) override;
	void OnSectionAdded(BinaryView* data, Section* section) override;
};

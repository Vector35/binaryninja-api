#pragma once

#include "uicontext.h"

class NotificationListener: UIContextNotification
{
	static NotificationListener* m_instance;
public:
	virtual void OnContextOpen(UIContext* context) override;
	virtual void OnContextClose(UIContext* context) override;
	virtual bool OnBeforeOpenDatabase(UIContext* context, FileMetadataRef metadata) override;
	virtual bool OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data) override;
	virtual bool OnBeforeOpenFile(UIContext* context, FileContext* file) override;
	virtual void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual bool OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual bool OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnViewChange(UIContext* context, ViewFrame* frame, const QString& type) override;
	virtual void OnAddressChange(UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location) override;

	static void init();
};
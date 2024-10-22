//
// Created by kat on 5/8/23.
//
#include "ui/uicontext.h"

#ifndef SHAREDCACHE_NOTIFICATIONS_H
#define SHAREDCACHE_NOTIFICATIONS_H

class UINotifications : public UIContextNotification {
	static UINotifications* m_instance;

	std::vector<size_t> m_sessionsAlreadyDisplayedPickerFor;

public:
	virtual void OnViewChange(UIContext *context, ViewFrame *frame, const QString &type) override;
	// bool OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data) override;
	void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) override;

	static void init();
};


#endif //SHAREDCACHE_NOTIFICATIONS_H

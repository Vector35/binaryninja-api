#pragma once

#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "filter.h"

class ViewFrame;
class FunctionList;

class BINARYNINJAUIAPI FunctionsView: public QWidget, public DockContextHandler, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	BinaryViewRef m_data;

	FunctionList* m_funcList;
	FilteredView* m_funcFilter;

	bool m_updatesPending;
	QTimer* m_updateTimer;

public:
	FunctionsView(ViewFrame* frame, BinaryViewRef data);
	virtual ~FunctionsView();

	FunctionList* getFunctionList() { return m_funcList; }
	FilteredView* getFunctionFilter() { return m_funcFilter; }

	virtual void OnBinaryDataWritten(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataInserted(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataRemoved(BinaryNinja::BinaryView* data, uint64_t offset, uint64_t len) override;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void notifyFontChanged() override;
	virtual bool shouldBeVisible(ViewFrame* frame) override;

private Q_SLOTS:
	void updateTimerEvent();
};

#pragma once

#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "filter.h"
#include "symbollist.h"

class ViewFrame;
class SymbolList;

class BINARYNINJAUIAPI SymbolsView: public QWidget, public DockContextHandler, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	BinaryViewRef m_data;

	SymbolList* m_funcList;
	FilteredView* m_funcFilter;

	bool m_updatesPending;
	QTimer* m_updateTimer;

public:
	SymbolsView(ViewFrame* frame, BinaryViewRef data);
	virtual ~SymbolsView();

	SymbolList* getSymbolList() { return m_funcList; }
	FilteredView* getFunctionFilter() { return m_funcFilter; }

	virtual void OnBinaryDataWritten(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataInserted(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataRemoved(BinaryNinja::BinaryView* data, uint64_t offset, uint64_t len) override;

	bool getShowExports() const { return m_funcList->getShowExports(); }
	bool getShowImports() const { return m_funcList->getShowImports(); }
	bool getShowFunctions() const { return m_funcList->getShowFunctions(); }
	bool getShowDataVars() const { return m_funcList->getShowDataVars(); }

	void toggleExports() { m_funcList->toggleExports(); }
	void toggleImports() { m_funcList->toggleImports(); }
	void toggleFunctions() { m_funcList->toggleFunctions(); }
	void toggleDataVars() { m_funcList->toggleDataVars(); }

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void notifyFontChanged() override;
	virtual bool shouldBeVisible(ViewFrame* frame) override;

private Q_SLOTS:
	void updateTimerEvent();
};

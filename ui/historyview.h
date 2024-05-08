#pragma once

#include "filter.h"
#include "sidebarwidget.h"
#include <qsortfilterproxymodel.h>
#include <qstandarditemmodel.h>
#include <qtreeview.h>


class BINARYNINJAUIAPI HistorySidebarWidget : public SidebarWidget, public FilterTarget
{
	Q_OBJECT
	QTreeView* m_tree;
	QStandardItemModel* m_model;
	QSortFilterProxyModel* m_proxyModel;

	QWidget* m_header;
	FilteredView* m_libFilter;
	BinaryViewRef m_data;
	ContextMenuManager* m_contextMenuManager;
	Menu m_contextMenu;
	bool m_updating = false;

	std::unordered_map<std::string, QPersistentModelIndex> m_idIndices;

	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void setFilter(const std::string& filter) override;

	virtual void contextMenuEvent(QContextMenuEvent*) override;

	void itemDoubleClicked(const QModelIndex& index);
	void scrollBarRangeChanged(int min, int max);

	void populateTree();

  public:
	HistorySidebarWidget(BinaryViewRef data);

	void notifyFontChanged() override;
	QWidget* headerWidget() override { return m_header; }
};


class BINARYNINJAUIAPI HistorySidebarWidgetType : public SidebarWidgetType
{
  public:
	HistorySidebarWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
};

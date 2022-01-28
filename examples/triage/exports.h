#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericExportsModel : public QAbstractItemModel
{
	std::vector<SymbolRef> m_allEntries, m_entries;
	int m_addrCol, m_nameCol, m_ordinalCol;
	int m_totalCols, m_sortCol;
	Qt::SortOrder m_sortOrder;

	void performSort(int col, Qt::SortOrder order);

  public:
	GenericExportsModel(BinaryViewRef data);

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;
	void setFilter(const std::string& filterText);

	SymbolRef getSymbol(const QModelIndex& index);

	bool HasOrdinalCol() const { return m_ordinalCol != -1; }
	int GetOrdinalCol() const { return m_ordinalCol; }
};


class TriageView;
class ExportsWidget;

class ExportsTreeView : public QTreeView, public FilterTarget
{
	BinaryViewRef m_data;
	ExportsWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericExportsModel* m_model;

  public:
	ExportsTreeView(ExportsWidget* parent, TriageView* view, BinaryViewRef data);

	virtual void setFilter(const std::string& filterText) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void exportSelected(const QModelIndex& cur, const QModelIndex& prev);
	void exportDoubleClicked(const QModelIndex& cur);
};


class ExportsWidget : public QWidget
{
	FilteredView* m_filter;

  public:
	ExportsWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	void showFilter(const QString& filter);
};

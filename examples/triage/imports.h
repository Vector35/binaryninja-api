#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericImportsModel : public QAbstractItemModel
{
	std::vector<SymbolRef> m_allEntries, m_entries;
	bool m_hasModules;
	int m_nameCol, m_moduleCol, m_ordinalCol;
	int m_totalCols, m_sortCol;
	Qt::SortOrder m_sortOrder;

	QString getNamespace(SymbolRef sym) const;
	void performSort(int col, Qt::SortOrder order);

  public:
	GenericImportsModel(BinaryViewRef data);

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
class ImportsWidget;

class ImportsTreeView : public QTreeView, public FilterTarget
{
	BinaryViewRef m_data;
	ImportsWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericImportsModel* m_model;

  public:
	ImportsTreeView(ImportsWidget* parent, TriageView* view, BinaryViewRef data);

	virtual void setFilter(const std::string& filterText) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void importSelected(const QModelIndex& cur, const QModelIndex& prev);
	void importDoubleClicked(const QModelIndex& cur);
};


class ImportsWidget : public QWidget
{
	FilteredView* m_filter;

  public:
	ImportsWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	void showFilter(const QString& filter);
};

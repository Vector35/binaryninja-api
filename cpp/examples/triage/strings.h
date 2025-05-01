#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericStringsModel : public QAbstractItemModel
{
    BinaryViewRef m_data;
	std::vector<BNStringReference> m_allEntries, m_entries;
	int m_totalCols, m_sortCol;
	Qt::SortOrder m_sortOrder;

	void performSort(int col, Qt::SortOrder order);

  public:
	GenericStringsModel(QWidget* parent, BinaryViewRef data);

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;
	void setFilter(const std::string& filterText);

	BNStringReference getStringRefAt(const QModelIndex& index) const;
	QString stringRefToQString(const BNStringReference& index) const;
};


class TriageView;
class StringsWidget;

class StringsTreeView : public QTreeView, public FilterTarget
{
	BinaryViewRef m_data;
	StringsWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericStringsModel* m_model;

  public:
	StringsTreeView(StringsWidget* parent, TriageView* view, BinaryViewRef data);

	virtual void setFilter(const std::string& filterText) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void stringSelected(const QModelIndex& cur, const QModelIndex& prev);
	void stringDoubleClicked(const QModelIndex& cur);
};


class StringsWidget : public QWidget
{
	FilteredView* m_filter;

  public:
	StringsWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	void showFilter(const QString& filter);
};
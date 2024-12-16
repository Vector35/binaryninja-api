#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericEntryModel : public QAbstractItemModel
{
	BinaryViewRef m_data;
	std::vector<FunctionRef> m_allEntries, m_entries;
	Qt::SortOrder m_sortOrder;
	int m_sortCol;

	void performSort(int col, Qt::SortOrder order);

  public:
	GenericEntryModel(QWidget* parent, BinaryViewRef data);

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;
	void setFilter(const std::string& filterText);

	FunctionRef getEntry(const QModelIndex& index);
};


class TriageView;
class EntryWidget;

class EntryTreeView : public QTreeView, public FilterTarget
{
	BinaryViewRef m_data;
	EntryWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericEntryModel* m_model;

  public:
	EntryTreeView(EntryWidget* parent, TriageView* view, BinaryViewRef data);

	virtual void setFilter(const std::string& filterText) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void entrySelected(const QModelIndex& cur, const QModelIndex& prev);
	void entryDoubleClicked(const QModelIndex& cur);
};


class EntryWidget : public QWidget
{
	FilteredView* m_filter;

  public:
	EntryWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	void showFilter(const QString& filter);
};

#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QTimer>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericExportsModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	BinaryViewRef m_data;
	std::vector<SymbolRef> m_allEntries, m_entries;
	std::string m_filter;
	Qt::SortOrder m_sortOrder;
	int m_sortCol;
	bool m_hasOrdinals;
	QTimer* m_updateTimer;

	void performSort(int col, Qt::SortOrder order);
	void updateModel();

  signals:
	void modelUpdate();

  public:
	GenericExportsModel(BinaryViewRef data);
	virtual ~GenericExportsModel();

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;
	void setFilter(const std::string& filterText);

	SymbolRef getSymbol(const QModelIndex& index);

	virtual void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnSymbolAdded(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;
	virtual void OnSymbolUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;
	virtual void OnSymbolRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;
};


class TriageView;
class ExportsWidget;

class ExportsTreeView : public QTreeView, public FilterTarget
{
	Q_OBJECT

	BinaryViewRef m_data;
	ExportsWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericExportsModel* m_model;
	QModelIndexList m_selection;
	int m_scroll;

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

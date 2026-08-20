#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QTimer>
#include <QtWidgets/QTreeView>
#include "filter.h"


class GenericStringsModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

    BinaryViewRef m_data;
	std::vector<BNStringReference> m_allEntries, m_entries;
	int m_totalCols, m_sortCol;
	Qt::SortOrder m_sortOrder;
	QTimer* m_updateTimer;

	QString m_filter;
	FilterOptions m_filterOptions;
	QRegularExpression m_filterRegex;

	// Read from arbitrary threads while processing notifications.
	std::atomic<bool> m_updatesPaused = false;
	// Read/written from arbitrary threads while processing notifications.
	std::atomic<bool> m_needsUpdate = true;
	// Tracks if notifications arrived while paused
	std::atomic<bool> m_dirtyWhilePaused = false;

	void performSort(int col, Qt::SortOrder order);
	void updateModel();
	void applyFilter();

	void updateTimer(bool);
	void setNeedsUpdate(bool);
	void onBinaryViewNotification();

signals:
	void updateTimerOnUIThread();

  public:
	GenericStringsModel(QWidget* parent, BinaryViewRef data);
	virtual ~GenericStringsModel();

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;

	void setFilter(const QString& filterText, FilterOptions options);

	void pauseUpdates();
	void resumeUpdates();

	BNStringReference getStringRefAt(const QModelIndex& index) const;
	QString stringRefToQString(const BNStringReference& index) const;

	virtual void OnStringFound(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;
	virtual void OnStringRemoved(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;
	virtual void OnDerivedStringFound(BinaryNinja::BinaryView* data, const BinaryNinja::DerivedString& str) override;
	virtual void OnDerivedStringRemoved(BinaryNinja::BinaryView* data, const BinaryNinja::DerivedString& str) override;
};


class TriageView;
class StringsWidget;

class StringsTreeView : public QTreeView, public FilterTarget
{
	Q_OBJECT

	BinaryViewRef m_data;
	StringsWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	GenericStringsModel* m_model;

	void updateColumnWidths();

  public:
	StringsTreeView(StringsWidget* parent, TriageView* view, BinaryViewRef data);
	void copySelection();
	bool canCopySelection() const;

	virtual void setFilter(const std::string& filterText, FilterOptions options) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void ensureSelection() override;
	virtual void activateSelection() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual bool event(QEvent* event) override;
	virtual void showEvent(QShowEvent* event) override;
	virtual void hideEvent(QHideEvent* event) override;

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

//
// Created by kat on 8/15/24.
//

#include <sharedcacheapi.h>
#include <binaryninjaapi.h>
#include "uitypes.h"
#include "viewframe.h"
#include "animation.h"
#include "uicontext.h"

#include <QTableView>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>
#include <QHeaderView>
#include "filter.h"

#ifndef BINARYNINJA_DSCTRIAGE_H
#define BINARYNINJA_DSCTRIAGE_H


class DSCCacheBlocksView : public QWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	Ref<SharedCacheAPI::SharedCache> m_cache;

	uint64_t m_backingCacheCount = 0;
	std::vector<SharedCacheAPI::BackingCache> m_backingCaches;

	std::atomic<BNDSCViewLoadProgress> m_currentProgress;
	std::vector<uint64_t> m_blockSizeRatios;
	std::vector<uint64_t> m_targetBlockSizeForAnimation;
	uint64_t m_averageBlockSizeForAnimationInterp = 0;
	std::vector<uint64_t> m_blockLuminance;
	Animation* m_blockWaveAnimation;
	Animation* m_blockExpandAnimation;
	Animation* m_blockAutoselectAnimation;

	int m_selectedBlock = -1;

	int getBlockIndexAtPosition(const QPoint& clickPosition);

	void blockSelected(int index);

public:
	DSCCacheBlocksView(QWidget* parent, BinaryViewRef data, Ref<SharedCacheAPI::SharedCache> cache);
	virtual ~DSCCacheBlocksView() override;

protected:
	void mousePressEvent(QMouseEvent* event) override;
	void mouseReleaseEvent(QMouseEvent* event) override;
	void mouseDoubleClickEvent(QMouseEvent* event) override;
	void mouseMoveEvent(QMouseEvent* event) override;
	void keyPressEvent(QKeyEvent* event) override;
	void keyReleaseEvent(QKeyEvent* event) override;
	void focusInEvent(QFocusEvent* event) override;
	void focusOutEvent(QFocusEvent* event) override;
	void enterEvent(QEnterEvent* event) override;
	void leaveEvent(QEvent* event) override;
	void paintEvent(QPaintEvent* event) override;
	void resizeEvent(QResizeEvent* event) override;

public:
	QSize sizeHint() const override;
	QSize minimumSizeHint() const override;

signals:
	void loadDone();
	void selectionChanged(const SharedCacheAPI::BackingCache& index, bool automatic);
};


class CollapsibleSection : public QWidget
{
	Q_OBJECT

	QLabel* m_titleLabel;
	QLabel* m_subtitleRightLabel;
	QPushButton* m_collapseButton;

	bool m_collapsed = true;

	Animation* m_onContentAddedAnimation;

	QWidget* m_contentWidgetContainer;
	QWidget* m_contentWidget;

protected:
	QSize sizeHint() const override;

public:
	CollapsibleSection(QWidget* parent);
	void setTitle(const QString& title);
	void setSubtitleRight(const QString& subtitle);

	void setContentWidget(QWidget* contentWidget);

	void setCollapsed(bool collapsed, bool animated = true);
	bool isCollapsed() const { return m_collapsed; }
};


class FilterableTableView : public QTableView, public FilterTarget {
	Q_OBJECT

	bool m_filterByHiding;

public:
	FilterableTableView(QWidget* parent = nullptr, bool filterByHiding = true)
		: QTableView(parent), m_filterByHiding(filterByHiding) {
		viewport()->installEventFilter(this);
	}

	~FilterableTableView() override {}

	void setFilter(const std::string& filter) override {
		if (!m_filterByHiding)
		{
			emit filterTextChanged(QString::fromStdString(filter));
			return;
		}
		QString qFilter = QString::fromStdString(filter);
		for (int row = 0; row < model()->rowCount(); ++row) {
			bool match = false;
			for (int col = 0; col < model()->columnCount(); ++col) {
				QModelIndex index = model()->index(row, col);
				QString data = model()->data(index).toString();
				if (data.contains(qFilter, Qt::CaseInsensitive)) {
					match = true;
					break;
				}
			}
			setRowHidden(row, !match);
		}
	}

	void scrollToFirstItem() override {
		if (model()->rowCount() > 0) {
			scrollTo(model()->index(0, 0));
		}
	}

	void scrollToCurrentItem() override {
		QModelIndex currentIndex = selectionModel()->currentIndex();
		if (currentIndex.isValid()) {
			scrollTo(currentIndex);
		}
	}

	void selectFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex firstIndex = model()->index(0, 0);
			selectionModel()->select(firstIndex, QItemSelectionModel::ClearAndSelect);
		}
	}

	void activateFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex firstIndex = model()->index(0, 0);
			setCurrentIndex(firstIndex);
			emit activated(firstIndex);
		}
	}

	bool eventFilter(QObject* obj, QEvent* event) override {
		if (event->type() == QEvent::KeyPress) {
			QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);
			if (keyEvent->key() == Qt::Key_Escape) {
				clearSelection();
				return true;
			}
			if (keyEvent->key() == Qt::Key_Enter || keyEvent->key() == Qt::Key_Return) {
				emit activated(currentIndex());
				return true;
			}
		}
		return QTableView::eventFilter(obj, event);
	}

signals:
	void filterTextChanged(const QString& text);
};

class SymbolTableView;

class SymbolTableModel : public QAbstractTableModel {
	Q_OBJECT

	SymbolTableView* m_parent;
	std::string m_filter;
	std::vector<SharedCacheAPI::DSCSymbol> m_symbols;

public:
	explicit SymbolTableModel(SymbolTableView* parent);

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	void updateSymbols();

	void setFilter(std::string text);

	const SharedCacheAPI::DSCSymbol& symbolAt(int row) const;
};


class SymbolTableView : public QTableView, public FilterTarget
{
	Q_OBJECT
	friend class SymbolTableModel;

	std::vector<SharedCacheAPI::DSCSymbol> m_symbols;

	SymbolTableModel* m_model;

public:
	SymbolTableView(QWidget* parent, Ref<SharedCacheAPI::SharedCache> cache);
	virtual ~SymbolTableView() override;

	void scrollToFirstItem() override {
		if (model()->rowCount() > 0) {
			scrollTo(model()->index(0, 0));
		}
	}

	void scrollToCurrentItem() override {
		QModelIndex currentIndex = selectionModel()->currentIndex();
		if (currentIndex.isValid()) {
			scrollTo(currentIndex);
		}
	}

	void selectFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex firstIndex = model()->index(0, 0);
			selectionModel()->select(firstIndex, QItemSelectionModel::ClearAndSelect);
		}
	}

	void activateFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex firstIndex = model()->index(0, 0);
			setCurrentIndex(firstIndex);
			emit activated(firstIndex);
		}
	}

	SharedCacheAPI::DSCSymbol getSymbolAtRow(int row) const
	{
		return m_model->symbolAt(row);
	}

	void setFilter(const std::string& filter) override;
};


class DSCTriageView : public QWidget, public View
{
	BinaryViewRef m_data;
	QVBoxLayout* m_layout;
	Ref<SharedCacheAPI::SharedCache> m_cache;

	SplitTabWidget* m_triageTabs;
	DockableTabCollection* m_triageCollection;

	SplitTabWidget* m_bottomRegionTabs;
	DockableTabCollection* m_bottomRegionCollection;

	std::vector<SharedCacheAPI::SharedCacheMachOHeader> m_headers;

public:
	DSCTriageView(QWidget* parent, BinaryViewRef data);
	BinaryViewRef getData() override;
	void setSelectionOffsets(BNAddressRange range) override {};
	QFont getFont() override;
	bool navigate(uint64_t offset) override;
	uint64_t getCurrentOffset() override;
};


class DSCTriageViewType : public ViewType
{
public:
	DSCTriageViewType();
	int getPriority(BinaryViewRef data, const QString& filename) override;
	QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void Register();
};


#endif	// BINARYNINJA_DSCTRIAGE_H

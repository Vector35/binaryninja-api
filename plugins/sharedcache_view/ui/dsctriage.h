#include <QFutureWatcher>
#include <QHeaderView>
#include <QItemDelegate>
#include <QPainter>
#include <QPointer>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTableView>
#include <binaryninjaapi.h>
#include <progresstask.h>
#include <sharedcacheapi.h>
#include <memory>
#include "filter.h"
#include "stringstable.h"
#include "symboltable.h"
#include "ui/fontsettings.h"
#include "uicontext.h"
#include "uitypes.h"
#include "viewframe.h"

#ifndef BINARYNINJA_DSCTRIAGE_H
#define BINARYNINJA_DSCTRIAGE_H

using namespace BinaryNinja;
using namespace SharedCacheAPI;


class AddressColorDelegate : public QStyledItemDelegate
{
public:
	explicit AddressColorDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
	{
		QStyleOptionViewItem opt = option;
		initStyleOption(&opt, index);

		opt.font = getMonospaceFont(qobject_cast<QWidget*>(parent()));
		opt.palette.setColor(QPalette::Text, getThemeColor(BNThemeColor::AddressColor));
		opt.displayAlignment = Qt::AlignCenter | Qt::AlignVCenter;

		QStyledItemDelegate::paint(painter, opt, index);
	}
};


class LoadedDelegate : public QItemDelegate
{
Q_OBJECT

public:
	explicit LoadedDelegate(QObject* parent = nullptr) : QItemDelegate(parent) {}

	void paint(QPainter *painter, const QStyleOptionViewItem &option,
			   const QModelIndex &index) const override
	{
		if (!index.isValid())
			return;

		painter->save();

		// Highlight if the item is selected
		if (option.state & QStyle::State_Selected)
			painter->fillRect(option.rect, option.palette.highlight());

		// "1" is the indicator that its loaded.
		if (index.data(Qt::DisplayRole).toString() == "1")
		{
			QPixmap loadedIcon;
			pixmapForBWMaskIcon(":/icons/images/check.png", &loadedIcon, SidebarHeaderTextColor);
			if (!loadedIcon.isNull())
			{
				QSize pixmapSize(20, 20);
				QPixmap scaledPixmap = loadedIcon.scaled(pixmapSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);

				// Calculate the rectangle for centering the pixmap
				int x = option.rect.x() + (option.rect.width() - scaledPixmap.width()) / 2; // Center horizontally
				int y = option.rect.y() + (option.rect.height() - scaledPixmap.height()) / 2; // Center vertically
				QRect iconRect(x, y, scaledPixmap.width(), scaledPixmap.height());

				// Draw the pixmap
				painter->drawPixmap(iconRect, scaledPixmap);
			}
		}

		painter->restore();
	}

	QSize sizeHint(const QStyleOptionViewItem &option,
				   const QModelIndex &index) const override
	{
		Q_UNUSED(option);
		Q_UNUSED(index);
		return {50, 24};
	}

	void setEditorData(QWidget *editor, const QModelIndex &index) const override
	{
		Q_UNUSED(editor);
		Q_UNUSED(index);
	}
};


class FilterableTableView : public QTableView, public FilterTarget {
	Q_OBJECT

	std::string m_filter;
	FilterOptions m_filterOptions;
	bool m_filterByHiding;

public:
	explicit FilterableTableView(QWidget* parent = nullptr, bool filterByHiding = true)
		: QTableView(parent), m_filterByHiding(filterByHiding) {
		viewport()->installEventFilter(this);
		setFont(getMonospaceFont(parent));
	}

	~FilterableTableView() override = default;

	void setFilter(const std::string& filter, FilterOptions options) override {
		m_filter = filter;
		m_filterOptions = options;
		QString qFilter = QString::fromStdString(m_filter);
		if (!m_filterByHiding)
		{
			emit filterTextChanged(qFilter);
			return;
		}
		bool caseSensitive = options.testFlag(CaseSensitiveOption);
		for (int row = 0; row < model()->rowCount(); ++row) {
			bool match = false;
			for (int col = 0; col < model()->columnCount(); ++col) {
				QModelIndex index = model()->index(row, col);
				QString data = model()->data(index).toString();
				if (data.contains(qFilter, caseSensitive ? Qt::CaseSensitive : Qt::CaseInsensitive)) {
					match = true;
					break;
				}
			}
			setRowHidden(row, !match);
		}
	}

	void scrollToFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex top = indexAt(rect().topLeft());
			if (top.isValid()) {
				scrollTo(top);
			}
		}
	}

	void scrollToCurrentItem() override {
		QModelIndex currentIndex = selectionModel()->currentIndex();
		if (currentIndex.isValid()) {
			scrollTo(currentIndex);
		}
	}

	void ensureSelection() override {
		QModelIndex current = selectionModel()->currentIndex();
		if (current.isValid() && !isRowHidden(current.row()))
			return;

		if (auto top = indexAt(rect().topLeft()); top.isValid())
		{
			selectionModel()->select(top, QItemSelectionModel::ClearAndSelect);
			setCurrentIndex(top);
		}
	}


	void activateSelection() override {
		ensureSelection();
		if (auto current = selectionModel()->currentIndex(); current.isValid())
			emit activated(current);
	}

signals:
	void filterTextChanged(const QString& text);
};


class DSCTriageView : public QWidget, public View, public UIContextNotification
{
	BinaryViewRef m_data;
	QVBoxLayout* m_layout;

	SplitTabWidget* m_triageTabs;
	DockableTabCollection* m_triageCollection;

	FilterableTableView* m_imageTable;
	QStandardItemModel* m_imageModel;

	SymbolTableView* m_symbolTable;
	TriageTablePanel* m_symbolsPanel;
	QPointer<QFutureWatcher<std::vector<SharedCacheAPI::CacheSymbol>>> m_symbolsWatcher;

	StringsTableView* m_stringsTable;
	TriageTablePanel* m_stringsPanel;
	QTimer* m_stringsPollTimer;
	std::unique_ptr<SharedCacheAPI::CacheStringScanner> m_stringScanner;

	FilterableTableView* m_regionTable;

	FilterableTableView* m_mappingTable;
	QStandardItemModel* m_mappingModel;

	QStandardItemModel* m_regionModel;

public:
	DSCTriageView(QWidget* parent, BinaryViewRef data);
	~DSCTriageView() override;
	BinaryViewRef getData() override;
	void setSelectionOffsets(BNAddressRange range) override {};
	QFont getFont() override;
	bool navigate(uint64_t offset) override;
	uint64_t getCurrentOffset() override;
	SelectionInfoForXref getSelectionForXref() override;

	void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	void RefreshData();

protected:
	void showEvent(QShowEvent* event) override;
	void hideEvent(QHideEvent* event) override;

private:
	void loadImagesWithAddr(const std::vector<uint64_t>& addresses, bool includeDependencies = false,
		std::optional<uint64_t> navigateTo = std::nullopt);
	void setImageLoaded(uint64_t imageHeaderAddr);
	void navigateToAddress(uint64_t address);
	QWidget* initImageTable();
	void initSymbolTable();
	bool startSymbolLoad();
	void initStringsTab();
	bool startStringScan();
	void pollStringScan();
	void promptToLoadImage(const std::string& imageName, uint64_t address, uint64_t navigateTo);
	void loadStringRegion(const SharedCacheAPI::CacheString& string, std::optional<uint64_t> navigateTo);
	void initCacheInfoTables();
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

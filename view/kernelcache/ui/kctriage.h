#include <QHeaderView>
#include <QItemDelegate>
#include <QPainter>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTableView>
#include <binaryninjaapi.h>
#include <kernelcacheapi.h>
#include <progresstask.h>
#include "filter.h"
#include "ui/fontsettings.h"
#include "uicontext.h"
#include "uitypes.h"
#include "viewframe.h"

#ifndef BINARYNINJA_KCTRIAGE_H
#define BINARYNINJA_KCTRIAGE_H


using namespace KernelCacheAPI;


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


class MonospaceFontDelegate : public QStyledItemDelegate {
public:
	explicit MonospaceFontDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override {
		QStyleOptionViewItem opt = option;
		initStyleOption(&opt, index);

		opt.font = getMonospaceFont(qobject_cast<QWidget*>(parent()));

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

	bool m_filterByHiding;

public:
	explicit FilterableTableView(QWidget* parent = nullptr, bool filterByHiding = true)
		: QTableView(parent), m_filterByHiding(filterByHiding) {
		viewport()->installEventFilter(this);
		setFont(getMonospaceFont(parent));
	}

	~FilterableTableView() override = default;

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

	void selectFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex top = indexAt(rect().topLeft());
			if (top.isValid()) {
				selectionModel()->select(top, QItemSelectionModel::ClearAndSelect);
				setCurrentIndex(top);
			}
		}
	}

	void activateFirstItem() override {
		if (model()->rowCount() > 0) {
			QModelIndex topLeft = indexAt(rect().topLeft());
			if (topLeft.isValid()) {
				setCurrentIndex(topLeft);
				emit activated(topLeft);
			}
		}
	}

signals:
	void filterTextChanged(const QString& text);
};


class SymbolTableProxyModel : public QSortFilterProxyModel
{
Q_OBJECT

public:
	explicit SymbolTableProxyModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent), m_timer(new QTimer(this))
	{
		m_timer->setSingleShot(true);
		connect(m_timer, &QTimer::timeout, this, &SymbolTableProxyModel::delayedFilterChanged);
	}

	void setFilterString(const QString& filter)
	{
		QRegularExpression newRegEx(QRegularExpression::escape(filter), QRegularExpression::CaseInsensitiveOption);
		if (m_filter != newRegEx) {
			m_filter = std::move(newRegEx);
			m_timer->start(200);
		}
	}

protected:
	bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override
	{
		if (m_filter.pattern().isEmpty())
			return true;

		for (int column = 0; column < sourceModel()->columnCount(source_parent); ++column)
		{
			QModelIndex index = sourceModel()->index(source_row, column, source_parent);
			QString data = sourceModel()->data(index).toString();
			if (m_filter.match(data).hasMatch())
				return true;
		}
		return false;
	}

private slots:
	void delayedFilterChanged()
	{
		invalidateFilter();
	}

private:
	QRegularExpression m_filter;
	QTimer* m_timer;
};


class SymbolTableView : public QTableView, public FilterTarget
{
Q_OBJECT
	friend class SymbolTableModel;

	std::vector<KernelCacheAPI::KCSymbol> m_symbols;
	QStandardItemModel* m_model;
	SymbolTableProxyModel* m_proxyModel;

public:
	SymbolTableView(QWidget* parent, Ref<KernelCache>& cache)
		: QTableView(parent), m_model(new QStandardItemModel(this)), m_proxyModel(new SymbolTableProxyModel(this))
	{
		m_proxyModel->setSourceModel(m_model);
		setModel(m_proxyModel);

		// Set up the headers
		m_model->setColumnCount(3);
		m_model->setHorizontalHeaderLabels({"Address", "Name", "Image"});
		setFont(getMonospaceFont(parent));
		setItemDelegateForColumn(0, new AddressColorDelegate(this));
		setItemDelegateForColumn(1, new MonospaceFontDelegate(this));
		setItemDelegateForColumn(2, new MonospaceFontDelegate(this));

		// Configure view settings
		horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
		horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
		horizontalHeader()->resizeSection(1, 400);
		horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
		setEditTriggers(QAbstractItemView::NoEditTriggers);
		setSelectionBehavior(QAbstractItemView::SelectRows);
		setSelectionMode(QAbstractItemView::SingleSelection);
		verticalHeader()->setVisible(false);

		setSortingEnabled(true);

		BackgroundThread::create(this)->thenBackground([this, cache](){
			m_symbols = cache->LoadAllSymbolsAndWait();
		})->thenMainThread([this](){
			updateSymbols();
		})->start();
	}

	~SymbolTableView() override = default;

	void updateSymbols()
	{
		m_model->removeRows(0, m_model->rowCount());
		for (const auto& symbol : m_symbols)
		{
			QList<QStandardItem*> row;
			row << new QStandardItem(QString("0x%1").arg(symbol.address, 0, 16))
				<< new QStandardItem(QString::fromStdString(symbol.name))
				<< new QStandardItem(QString::fromStdString(symbol.image));
			m_model->appendRow(row);
		}
	}

	KernelCacheAPI::KCSymbol getSymbolAtRow(int row) const
	{
		QModelIndex proxyIndex = m_proxyModel->index(row, 0);
		QModelIndex sourceIndex = m_proxyModel->mapToSource(proxyIndex);
		return m_symbols[sourceIndex.row()];
	}

	void scrollToFirstItem() override
	{
		scrollToTop();
	}

	void scrollToCurrentItem() override
	{
		scrollTo(selectionModel()->currentIndex());
	}

	void selectFirstItem() override
	{
		if (m_proxyModel->rowCount() > 0) {
			QModelIndex idx = m_proxyModel->index(0, 0);
			if (idx.isValid()) {
				selectionModel()->select(idx, QItemSelectionModel::ClearAndSelect);
				setCurrentIndex(idx);
			}
		}
	}

	void activateFirstItem() override
	{
		if (m_proxyModel->rowCount() > 0) {
			QModelIndex idx = m_proxyModel->index(0, 0);
			if (idx.isValid()) {
				setCurrentIndex(idx);
				emit activated(idx);
			}
		}
	}

	void setFilter(const std::string& text) override
	{
		m_proxyModel->setFilterString(QString::fromStdString(text));
	}
};


class KCTriageView : public QWidget, public View, public UIContextNotification
{
	BinaryViewRef m_data;
	QVBoxLayout* m_layout;

	Ref<KernelCacheAPI::KernelCache> m_cache;

	SplitTabWidget* m_triageTabs;
	DockableTabCollection* m_triageCollection;

	FilterableTableView* m_imageTable;
	QStandardItemModel* m_imageModel;

	SymbolTableView* m_symbolTable;

	std::mutex m_headersMutex;
	std::shared_ptr<std::vector<KernelCacheAPI::KernelCacheMachOHeader>> m_headers;

public:
	KCTriageView(QWidget* parent, BinaryViewRef data);
	~KCTriageView() override;
	BinaryViewRef getData() override;
	void setSelectionOffsets(BNAddressRange range) override {};
	QFont getFont() override;
	bool navigate(uint64_t offset) override;
	uint64_t getCurrentOffset() override;

private:
	void loadImagesWithAddr(const std::vector<uint64_t>& addresses);
	void setImageLoaded(const uint64_t imageHeaderAddr);
	QWidget* initImageTable();
	void initSymbolTable();
};


class KCTriageViewType : public ViewType
{
public:
	KCTriageViewType();
	int getPriority(BinaryViewRef data, const QString& filename) override;
	QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void Register();
};


#endif	// BINARYNINJA_KCTRIAGE_H

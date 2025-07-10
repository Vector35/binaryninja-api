#include <QHeaderView>
#include <QItemDelegate>
#include <QPainter>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTableView>
#include <binaryninjaapi.h>
#include <progresstask.h>
#include <kernelcacheapi.h>
#include "filter.h"
#include "symboltable.h"
#include "ui/fontsettings.h"
#include "uicontext.h"
#include "uitypes.h"
#include "viewframe.h"

#ifndef BINARYNINJA_KCTRIAGE_H
	#define BINARYNINJA_KCTRIAGE_H

using namespace BinaryNinja;
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


class KCTriageView : public QWidget, public View, public UIContextNotification
{
	BinaryViewRef m_data;
	QVBoxLayout* m_layout;

	SplitTabWidget* m_triageTabs;
	DockableTabCollection* m_triageCollection;

	FilterableTableView* m_imageTable;
	QStandardItemModel* m_imageModel;

	SymbolTableView* m_symbolTable;
public:
	KCTriageView(QWidget* parent, BinaryViewRef data);
	~KCTriageView() override;
	BinaryViewRef getData() override;
	void setSelectionOffsets(BNAddressRange range) override {};
	QFont getFont() override;
	bool navigate(uint64_t offset) override;
	uint64_t getCurrentOffset() override;
	SelectionInfoForXref getSelectionForXref() override;

	void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	void RefreshData();

private:
	void loadImagesWithAddr(const std::vector<uint64_t>& addresses, bool includeDependencies = false);
	void setImageLoaded(uint64_t imageHeaderAddr);
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

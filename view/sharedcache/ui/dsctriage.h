//
// Created by kat on 8/15/24.
//

#include <binaryninjaapi.h>
#include <QItemDelegate>
#include <QStyledItemDelegate>

#include "uitypes.h"
#include "viewframe.h"
#include "animation.h"
#include "uicontext.h"

#include "filter.h"
#include "symboltable.h"

#include "ui/fontsettings.h"

#ifndef BINARYNINJA_DSCTRIAGE_H
#define BINARYNINJA_DSCTRIAGE_H

class AddressColorDelegate : public QStyledItemDelegate
{

public:
	explicit AddressColorDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
	{
		QStyleOptionViewItem opt = option;
		initStyleOption(&opt, index);

		opt.palette.setColor(QPalette::Text, getThemeColor(BNThemeColor::AddressColor));
		opt.displayAlignment = Qt::AlignCenter | Qt::AlignVCenter;

		QStyledItemDelegate::paint(painter, opt, index);
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
			auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
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

class DSCTriageView : public QWidget, public View, public UIContextNotification
{
	BinaryViewRef m_data;
	QVBoxLayout* m_layout;

	SplitTabWidget* m_triageTabs;
	DockableTabCollection* m_triageCollection;

	QStandardItemModel* m_imageModel;

	SymbolTableView* m_symbolTable;

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
	void setImageLoaded(uint64_t imageHeaderAddr);
};


class DSCTriageViewType : public ViewType
{
public:
	DSCTriageViewType();
	int getPriority(BinaryViewRef data, const QString& filename) override;
	QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void Register();
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

#endif	// BINARYNINJA_DSCTRIAGE_H

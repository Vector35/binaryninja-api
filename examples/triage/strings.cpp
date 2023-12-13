#include <string.h>
#include <algorithm>
#include "strings.h"
#include "view.h"
#include "fontsettings.h"


GenericStringsModel::GenericStringsModel(QWidget* parent, BinaryViewRef data) : QAbstractItemModel(parent)
{
	m_data = data;
	m_totalCols = 3;
	m_sortCol = 0;
	m_sortOrder = Qt::AscendingOrder;
	m_allEntries = data->GetStrings();
	m_entries = m_allEntries;
}


int GenericStringsModel::columnCount(const QModelIndex&) const
{
	return m_totalCols;
}


int GenericStringsModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant GenericStringsModel::data(const QModelIndex& index, int role) const
{
	switch (role)
	{
	case Qt::DisplayRole:
		if (!index.isValid() || index.row() >= (int)m_entries.size())
			return QVariant();
		if (index.column() == 0)
			return QString("0x") + QString::number(m_entries[index.row()].start, 16);
		if (index.column() == 1)
			return QString::number(m_entries[index.row()].length);
		if (index.column() == 2)
			return stringRefToQString(m_entries[index.row()]).replace("\n", "\\n");
		break;
	case Qt::ForegroundRole:
		if (index.column() == 0)
			return getThemeColor(AddressColor);
		break;
	}

	return QVariant();
}


QVariant GenericStringsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();
	if (role != Qt::DisplayRole)
		return QVariant();
	if (section == 0)
		return QString("Address");
	if (section == 1)
		return QString("Length");
	if (section == 2)
		return QString("String");
	return QVariant();
}


QModelIndex GenericStringsModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size())
		return QModelIndex();
	if (col >= m_totalCols)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex GenericStringsModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


QString GenericStringsModel::stringRefToQString(const BNStringReference& stringRef) const
{
	QString qstr;
	BinaryNinja::DataBuffer stringBuffer = m_data->ReadBuffer(stringRef.start, stringRef.length);

	if (stringRef.type == BNStringType::Utf32String)
	{	
		char32_t* data = (char32_t*)stringBuffer.GetData();
		qstr = QString::fromUcs4(data, stringRef.length / 4);
	} 
	else if (stringRef.type == BNStringType::Utf16String)
	{
		char16_t* data = (char16_t*)stringBuffer.GetData();
		qstr = QString::fromUtf16(data, stringRef.length / 2);
	}
	else 
	{
		char* data = (char*)stringBuffer.GetData();
		qstr = QString::fromUtf8(data, stringBuffer.GetLength());
	}

	return qstr;
}


BNStringReference GenericStringsModel::getStringRefAt(const QModelIndex& index) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return BNStringReference{};
	return m_entries[index.row()];
}

void GenericStringsModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](BNStringReference a, BNStringReference b) {
		if (col == 0)
		{
			if (order == Qt::AscendingOrder)
				return a.start < b.start;
			else
				return a.start > b.start;
		}
		else if (col == 1)
		{
			if (order == Qt::AscendingOrder)
				return a.length < b.length;
			else
				return a.length > b.length;
		}
		else if (col == 2)
		{	
			QString s = stringRefToQString(a);
			QString s2 = stringRefToQString(b);

			if (order == Qt::AscendingOrder)
				return s < s2;
			else
				return s > s2;
		}
		return false;
	});
}


void GenericStringsModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	m_sortCol = col;
	m_sortOrder = order;
	performSort(col, order);
	endResetModel();
}


void GenericStringsModel::setFilter(const std::string& filterText)
{
	beginResetModel();
	m_entries.clear();
	for (auto& entry : m_allEntries)
	{
		auto s = stringRefToQString(entry).toStdString();
		
		if (FilteredView::match(s, filterText))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


StringsTreeView::StringsTreeView(StringsWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when strings are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });

	m_model = new GenericStringsModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	sortByColumn(0, Qt::AscendingOrder);

	setFont(getMonospaceFont(this));

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &StringsTreeView::stringSelected);
	connect(this, &QTreeView::doubleClicked, this, &StringsTreeView::stringDoubleClicked);
}


void StringsTreeView::stringSelected(const QModelIndex& cur, const QModelIndex&)
{
	BNStringReference stringRef = m_model->getStringRefAt(cur);
	if (stringRef.start == 0)
		return;

	m_view->setCurrentOffset(stringRef.start);
}


void StringsTreeView::stringDoubleClicked(const QModelIndex& cur)
{
	BNStringReference stringRef = m_model->getStringRefAt(cur);
	if (stringRef.start == 0)
		return;

	ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
	if (viewFrame)
	{
		viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(),  stringRef.start);
	}
}


void StringsTreeView::setFilter(const std::string& filterText)
{
	m_model->setFilter(filterText);
}


void StringsTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void StringsTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void StringsTreeView::selectFirstItem()
{
	setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void StringsTreeView::activateFirstItem()
{
	stringDoubleClicked(m_model->index(0, 0, QModelIndex()));
}


void StringsTreeView::closeFilter()
{
	setFocus(Qt::OtherFocusReason);
}


void StringsTreeView::keyPressEvent(QKeyEvent* event)
{
	if ((event->text().size() == 1) && (event->text()[0] > ' ') && (event->text()[0] <= '~'))
	{
		m_parent->showFilter(event->text());
		event->accept();
	}
	else if ((event->key() == Qt::Key_Return) || (event->key() == Qt::Key_Enter))
	{
		QList<QModelIndex> sel = selectionModel()->selectedIndexes();
		if (sel.size() != 0)
			stringDoubleClicked(sel[0]);
	}
	QTreeView::keyPressEvent(event);
}


StringsWidget::StringsWidget(QWidget* parent, TriageView* view, BinaryViewRef data) : QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	StringsTreeView* strings = new StringsTreeView(this, view, data);
	m_filter = new FilteredView(this, strings, strings);
	m_filter->setFilterPlaceholderText("Search strings");
	layout->addWidget(m_filter, 1);
	setLayout(layout);
	setMinimumSize(UIContext::getScaledWindowSize(100, 196));
}


void StringsWidget::showFilter(const QString& filter)
{
	m_filter->showFilter(filter);
}
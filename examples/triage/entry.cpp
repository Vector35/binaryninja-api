#include <cstring>
#include <algorithm>
#include "entry.h"
#include "view.h"
#include "fontsettings.h"


const int AddressColumn = 0;
const int NameColumn = 1;
const int ColumnCount = 2;


GenericEntryModel::GenericEntryModel(QWidget* parent, BinaryViewRef data): QAbstractItemModel(parent)
{
	m_data = data;
	m_sortOrder = Qt::AscendingOrder;
	m_allEntries = data->GetAllEntryFunctions();
	m_entries = m_allEntries;
}


int GenericEntryModel::columnCount(const QModelIndex&) const
{
	return ColumnCount;
}


int GenericEntryModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant GenericEntryModel::data(const QModelIndex& index, int role) const
{
	switch (role)
	{
	case Qt::DisplayRole:
		if (!index.isValid() || index.row() >= (int)m_entries.size())
			return QVariant();
		if (index.column() == AddressColumn)
			return QString("0x") + QString::number(m_entries[index.row()]->GetStart(), 16);
		if (index.column() == NameColumn)
			return QString::fromStdString(m_entries[index.row()]->GetSymbol()->GetFullName());
		break;
	case Qt::ForegroundRole:
		if (index.column() == AddressColumn)
			return getThemeColor(AddressColor);
		if (index.column() == NameColumn)
			return getThemeColor(ExportColor);
		break;
	default:
		break;
	}

	return QVariant();
}


QVariant GenericEntryModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();
	if (role != Qt::DisplayRole)
		return QVariant();
	if (section == AddressColumn)
		return QString("Address");
	if (section == NameColumn)
		return QString("Name");
	return QVariant();
}


QModelIndex GenericEntryModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size())
		return QModelIndex();
	if (col >= ColumnCount)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex GenericEntryModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


FunctionRef GenericEntryModel::getEntry(const QModelIndex& index)
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return nullptr;
	return m_entries[index.row()];
}


void GenericEntryModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](FunctionRef a, FunctionRef b) {
		if (col == AddressColumn)
		{
			if (a->GetStart() != b->GetStart())
			{
				if (order == Qt::AscendingOrder)
					return a->GetStart() < b->GetStart();
				else
					return a->GetStart() > b->GetStart();
			}
			if (order == Qt::AscendingOrder)
				return a->GetSymbol()->GetFullName() < b->GetSymbol()->GetFullName();
			else
				return a->GetSymbol()->GetFullName() > b->GetSymbol()->GetFullName();
		}
		else if (col == NameColumn)
		{
			if (order == Qt::AscendingOrder)
				return a->GetSymbol()->GetFullName() < b->GetSymbol()->GetFullName();
			else
				return a->GetSymbol()->GetFullName() > b->GetSymbol()->GetFullName();
		}
		return false;
	});
}


void GenericEntryModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	m_sortCol = col;
	m_sortOrder = order;
	performSort(col, order);
	endResetModel();
}


void GenericEntryModel::setFilter(const std::string& filterText)
{
	beginResetModel();
	m_entries.clear();
	for (auto& entry : m_allEntries)
	{
		if (FilteredView::match(entry->GetSymbol()->GetFullName(), filterText))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


EntryTreeView::EntryTreeView(EntryWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when imports are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });

	m_model = new GenericEntryModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	sortByColumn(AddressColumn, Qt::AscendingOrder);

	setColumnWidth(AddressColumn, 90);

	setFont(getMonospaceFont(this));

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &EntryTreeView::entrySelected);
	connect(this, &QTreeView::doubleClicked, this, &EntryTreeView::entryDoubleClicked);
}


void EntryTreeView::entrySelected(const QModelIndex& cur, const QModelIndex&)
{
	FunctionRef func = m_model->getEntry(cur);
	if (func)
		m_view->setCurrentOffset(func->GetStart());
}


void EntryTreeView::entryDoubleClicked(const QModelIndex& cur)
{
	FunctionRef func = m_model->getEntry(cur);
	if (func)
	{
		ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
		if (viewFrame)
		{
			if (BinaryNinja::Settings::Instance()->Get<bool>("ui.view.graph.preferred") &&
				viewFrame->getCurrentBinaryView() &&
				func->GetStart() > 0)
			{
				viewFrame->navigate("Graph:" + viewFrame->getCurrentDataType(), func->GetStart());
			}
			else
			{
				viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), func->GetStart());
			}
		}
	}
}


void EntryTreeView::setFilter(const std::string& filterText)
{
	m_model->setFilter(filterText);
}


void EntryTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void EntryTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void EntryTreeView::selectFirstItem()
{
	setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void EntryTreeView::activateFirstItem()
{
	entryDoubleClicked(m_model->index(0, 0, QModelIndex()));
}


void EntryTreeView::closeFilter()
{
	setFocus(Qt::OtherFocusReason);
}


void EntryTreeView::keyPressEvent(QKeyEvent* event)
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
			entryDoubleClicked(sel[0]);
	}
	QTreeView::keyPressEvent(event);
}


EntryWidget::EntryWidget(QWidget* parent, TriageView* view, BinaryViewRef data) : QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	EntryTreeView* entry = new EntryTreeView(this, view, data);
	m_filter = new FilteredView(this, entry, entry);
	m_filter->setFilterPlaceholderText("Search entry functions");
	layout->addWidget(m_filter, 1);
	setLayout(layout);
	setMinimumSize(UIContext::getScaledWindowSize(100, 196));
}


void EntryWidget::showFilter(const QString& filter)
{
	m_filter->showFilter(filter);
}

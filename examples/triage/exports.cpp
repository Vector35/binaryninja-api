#include <algorithm>
#include "exports.h"
#include "view.h"
#include "fontsettings.h"


GenericExportsModel::GenericExportsModel(BinaryViewRef data)
{
	m_addrCol = 0;
	m_nameCol = 1;
	m_ordinalCol = -1;
	m_totalCols = 2;
	m_sortCol = 0;
	m_sortOrder = Qt::AscendingOrder;
	for (auto& sym : data->GetSymbolsOfType(FunctionSymbol))
	{
		if ((sym->GetBinding() == GlobalBinding) || (sym->GetBinding() == WeakBinding))
			m_allEntries.push_back(sym);
	}
	for (auto& sym : data->GetSymbolsOfType(DataSymbol))
	{
		if ((sym->GetBinding() == GlobalBinding) || (sym->GetBinding() == WeakBinding))
			m_allEntries.push_back(sym);
	}
	if (data->GetTypeName() == "PE")
	{
		m_ordinalCol = 0;
		m_addrCol = 1;
		m_nameCol = 2;
		m_totalCols = 3;
	}
	m_entries = m_allEntries;
}


int GenericExportsModel::columnCount(const QModelIndex&) const
{
	return m_totalCols;
}


int GenericExportsModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant GenericExportsModel::data(const QModelIndex& index, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();
	if (index.row() >= (int)m_entries.size())
		return QVariant();
	if (index.column() == m_addrCol)
		return QString("0x") + QString::number(m_entries[index.row()]->GetAddress(), 16);
	if (index.column() == m_nameCol)
		return QString::fromStdString(m_entries[index.row()]->GetFullName());
	if (index.column() == m_ordinalCol)
		return QString::number(m_entries[index.row()]->GetOrdinal());
	return QVariant();
}


QVariant GenericExportsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();
	if (role != Qt::DisplayRole)
		return QVariant();
	if (section == m_addrCol)
		return QString("Address");
	if (section == m_nameCol)
		return QString("Name");
	if (section == m_ordinalCol)
		return QString("Ordinal");
	return QVariant();
}


QModelIndex GenericExportsModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size())
		return QModelIndex();
	if (col >= m_totalCols)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex GenericExportsModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


SymbolRef GenericExportsModel::getSymbol(const QModelIndex& index)
{
	if (index.row() >= (int)m_entries.size())
		return nullptr;
	return m_entries[index.row()];
}


void GenericExportsModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](SymbolRef a, SymbolRef b) {
		if (col == m_addrCol)
		{
			if (order == Qt::AscendingOrder)
				return a->GetAddress() < b->GetAddress();
			else
				return a->GetAddress() > b->GetAddress();
		}
		else if (col == m_nameCol)
		{
			if (order == Qt::AscendingOrder)
				return a->GetFullName() < b->GetFullName();
			else
				return a->GetFullName() > b->GetFullName();
		}
		else if (col == m_ordinalCol)
		{
			if (order == Qt::AscendingOrder)
				return a->GetOrdinal() < b->GetOrdinal();
			else
				return a->GetOrdinal() > b->GetOrdinal();
		}
		return false;
	});
}


void GenericExportsModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	m_sortCol = col;
	m_sortOrder = order;
	performSort(col, order);
	endResetModel();
}


void GenericExportsModel::setFilter(const std::string& filterText)
{
	beginResetModel();
	m_entries.clear();
	for (auto& entry : m_allEntries)
	{
		if (FilteredView::match(entry->GetFullName(), filterText))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


ExportsTreeView::ExportsTreeView(ExportsWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when imports are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });

	m_model = new GenericExportsModel(m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	sortByColumn(0, Qt::AscendingOrder);
	if (m_model->HasOrdinalCol())
		setColumnWidth(m_model->GetOrdinalCol(), 55);

	setFont(getMonospaceFont(this));

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &ExportsTreeView::exportSelected);
	connect(this, &QTreeView::doubleClicked, this, &ExportsTreeView::exportDoubleClicked);
}


void ExportsTreeView::exportSelected(const QModelIndex& cur, const QModelIndex&)
{
	SymbolRef sym = m_model->getSymbol(cur);
	if (sym)
		m_view->setCurrentOffset(sym->GetAddress());
}


void ExportsTreeView::exportDoubleClicked(const QModelIndex& cur)
{
	SymbolRef sym = m_model->getSymbol(cur);
	if (sym)
	{
		ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
		if (viewFrame)
		{
			if (m_data->GetAnalysisFunctionsForAddress(sym->GetAddress()).size() > 0)
				viewFrame->navigate("Graph:" + viewFrame->getCurrentDataType(), sym->GetAddress());
			else
				viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), sym->GetAddress());
		}
	}
}


void ExportsTreeView::setFilter(const std::string& filterText)
{
	m_model->setFilter(filterText);
}


void ExportsTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void ExportsTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void ExportsTreeView::selectFirstItem()
{
	setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void ExportsTreeView::activateFirstItem()
{
	exportDoubleClicked(m_model->index(0, 0, QModelIndex()));
}


void ExportsTreeView::closeFilter()
{
	setFocus(Qt::OtherFocusReason);
}


void ExportsTreeView::keyPressEvent(QKeyEvent* event)
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
			exportDoubleClicked(sel[0]);
	}
	QTreeView::keyPressEvent(event);
}


ExportsWidget::ExportsWidget(QWidget* parent, TriageView* view, BinaryViewRef data) : QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	ExportsTreeView* exports = new ExportsTreeView(this, view, data);
	m_filter = new FilteredView(this, exports, exports);
	m_filter->setFilterPlaceholderText("Search exports");
	layout->addWidget(m_filter, 1);
	setLayout(layout);
	setMinimumSize(UIContext::getScaledWindowSize(100, 196));
}


void ExportsWidget::showFilter(const QString& filter)
{
	m_filter->showFilter(filter);
}

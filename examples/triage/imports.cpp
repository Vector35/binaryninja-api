#include <string.h>
#include <algorithm>
#include "imports.h"
#include "view.h"
#include "fontsettings.h"


GenericImportsModel::GenericImportsModel(BinaryViewRef data)
{
	m_nameCol = 1;
	m_moduleCol = -1;
	m_ordinalCol = -1;
	m_totalCols = 2;
	m_sortCol = 0;
	m_sortOrder = Qt::AscendingOrder;
	m_allEntries = data->GetSymbolsOfType(ImportAddressSymbol);
	for (auto& sym: m_allEntries)
	{
		if ((sym->GetNameSpace().size() != 1) || (sym->GetNameSpace()[0] != "BNINTERNALNAMESPACE"))
		{
			m_hasModules = true;
			break;
		}
	}
	if (m_hasModules)
	{
		m_nameCol = 3;
		m_moduleCol = 1;
		m_ordinalCol = 2;
		m_totalCols = 4;
	}
	m_entries = m_allEntries;
}


int GenericImportsModel::columnCount(const QModelIndex&) const
{
	return m_totalCols;
}


int GenericImportsModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant GenericImportsModel::data(const QModelIndex& index, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();
	if (index.row() >= (int)m_entries.size())
		return QVariant();
	if (index.column() == 0)
		return QString("0x") + QString::number(m_entries[index.row()]->GetAddress(), 16);
	if (index.column() == m_nameCol)
		return QString::fromStdString(m_entries[index.row()]->GetFullName());
	if (index.column() == m_moduleCol)
		return getNamespace(m_entries[index.row()]);
	if (index.column() == m_ordinalCol)
		return QString::number(m_entries[index.row()]->GetOrdinal());
	return QVariant();
}


QVariant GenericImportsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();
	if (role != Qt::DisplayRole)
		return QVariant();
	if (section == 0)
		return QString("Entry");
	if (section == m_nameCol)
		return QString("Name");
	if (section == m_moduleCol)
		return QString("Module");
	if (section == m_ordinalCol)
		return QString("Ordinal");
	return QVariant();
}


QModelIndex GenericImportsModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size())
		return QModelIndex();
	if (col >= m_totalCols)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex GenericImportsModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


SymbolRef GenericImportsModel::getSymbol(const QModelIndex& index)
{
	if (index.row() >= (int)m_entries.size())
		return nullptr;
	return m_entries[index.row()];
}


QString GenericImportsModel::getNamespace(SymbolRef sym) const
{
	QString name = QString::fromStdString(sym->GetNameSpace().GetString());
	if (name == "BNINTERNALNAMESPACE")
		return "";
	return name;
}


void GenericImportsModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](SymbolRef a, SymbolRef b) {
		if (col == 0)
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
		else if (col == m_moduleCol)
		{
			if (order == Qt::AscendingOrder)
				return getNamespace(a) < getNamespace(b);
			else
				return getNamespace(a) > getNamespace(b);
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


void GenericImportsModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	m_sortCol = col;
	m_sortOrder = order;
	performSort(col, order);
	endResetModel();
}


void GenericImportsModel::setFilter(const std::string& filterText)
{
	beginResetModel();
	m_entries.clear();
	for (auto& entry: m_allEntries)
	{
		if (FilteredView::match(entry->GetFullName(), filterText))
			m_entries.push_back(entry);
		else if (FilteredView::match(getNamespace(entry).toStdString(), filterText))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


ImportsTreeView::ImportsTreeView(ImportsWidget* parent, TriageView* view, BinaryViewRef data): QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when imports are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });

	m_model = new GenericImportsModel(m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	sortByColumn(0, Qt::AscendingOrder);
	if (m_model->HasOrdinalCol())
		setColumnWidth(m_model->GetOrdinalCol(), 55);

	setFont(getMonospaceFont(this));

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &ImportsTreeView::importSelected);
	connect(this, &QTreeView::doubleClicked, this, &ImportsTreeView::importDoubleClicked);
}


void ImportsTreeView::importSelected(const QModelIndex& cur, const QModelIndex&)
{
	SymbolRef sym = m_model->getSymbol(cur);
	if (sym)
		m_view->setCurrentOffset(sym->GetAddress());
}


void ImportsTreeView::importDoubleClicked(const QModelIndex& cur)
{
	SymbolRef sym = m_model->getSymbol(cur);
	if (sym)
	{
		ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
		if (viewFrame)
			viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), sym->GetAddress());
	}
}


void ImportsTreeView::setFilter(const std::string& filterText)
{
	m_model->setFilter(filterText);
}


void ImportsTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void ImportsTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void ImportsTreeView::selectFirstItem()
{
	setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void ImportsTreeView::activateFirstItem()
{
	importDoubleClicked(m_model->index(0, 0, QModelIndex()));
}


void ImportsTreeView::closeFilter()
{
	setFocus(Qt::OtherFocusReason);
}


void ImportsTreeView::keyPressEvent(QKeyEvent* event)
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
			importDoubleClicked(sel[0]);
	}
	QTreeView::keyPressEvent(event);
}


ImportsWidget::ImportsWidget(QWidget* parent, TriageView* view, BinaryViewRef data): QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	ImportsTreeView* imports = new ImportsTreeView(this, view, data);
	m_filter = new FilteredView(this, imports, imports);
	layout->addWidget(m_filter, 1);
	setLayout(layout);
	setMinimumSize(UIContext::getScaledWindowSize(100, 196));
}


void ImportsWidget::showFilter(const QString& filter)
{
	m_filter->showFilter(filter);
}

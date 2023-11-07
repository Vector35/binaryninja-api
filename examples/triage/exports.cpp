#include <QtWidgets/QScrollBar>
#include <algorithm>
#include "exports.h"
#include "view.h"
#include "fontsettings.h"


const int OrdinalColumn = 0;
const int AddressColumn = 1;
const int NameColumn = 2;
const int ColumnCount = 3;


const int ColumnVisibleRole = Qt::UserRole;


GenericExportsModel::GenericExportsModel(QWidget* parent, BinaryViewRef data): QAbstractItemModel(parent), BinaryDataNotification(FunctionUpdates | SymbolUpdates)
{
	m_sortOrder = Qt::AscendingOrder;
	m_data = data;
	m_hasOrdinals = false;
	if (data->GetTypeName() == "PE")
	{
		m_hasOrdinals = true;
	}

	m_updateTimer = new QTimer(this);
	m_updateTimer->setSingleShot(true);
	m_updateTimer->setInterval(500);
	connect(m_updateTimer, &QTimer::timeout, this, &GenericExportsModel::updateModel);
	connect(this, &GenericExportsModel::modelUpdate, this, [=]() {
		if (m_updateTimer->isActive())
			return;
		m_updateTimer->start();
	});

	m_data->RegisterNotification(this);

	updateModel();
	m_entries = m_allEntries;
}


GenericExportsModel::~GenericExportsModel()
{
	m_data->UnregisterNotification(this);
}


void GenericExportsModel::updateModel()
{
	beginResetModel();
	m_allEntries.clear();
	for (auto& sym : m_data->GetSymbolsOfType(FunctionSymbol))
	{
		if ((sym->GetBinding() == GlobalBinding) || (sym->GetBinding() == WeakBinding))
			m_allEntries.push_back(sym);
	}
	for (auto& sym : m_data->GetSymbolsOfType(DataSymbol))
	{
		if ((sym->GetBinding() == GlobalBinding) || (sym->GetBinding() == WeakBinding))
			m_allEntries.push_back(sym);
	}
	endResetModel();

	setFilter(m_filter);
}


int GenericExportsModel::columnCount(const QModelIndex&) const
{
	return ColumnCount;
}


int GenericExportsModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant GenericExportsModel::data(const QModelIndex& index, int role) const
{
	switch (role)
	{
	case Qt::DisplayRole:
		if (role != Qt::DisplayRole)
			return QVariant();
		if (!index.isValid() || index.row() >= (int)m_entries.size())
			return QVariant();
		if (index.column() == AddressColumn)
			return QString("0x") + QString::number(m_entries[index.row()]->GetAddress(), 16);
		if (index.column() == NameColumn)
			return QString::fromStdString(m_entries[index.row()]->GetFullName());
		if (index.column() == OrdinalColumn)
			return QString::number(m_entries[index.row()]->GetOrdinal());
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


QVariant GenericExportsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();

	if (role == ColumnVisibleRole)
	{
		if (section == OrdinalColumn)
			return QVariant(m_hasOrdinals);
		return true;
	}

	if (role != Qt::DisplayRole)
		return QVariant();
	if (section == AddressColumn)
		return QString("Address");
	if (section == NameColumn)
		return QString("Name");
	if (section == OrdinalColumn)
		return QString("Ordinal");
	return QVariant();
}


QModelIndex GenericExportsModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size())
		return QModelIndex();
	if (col >= ColumnCount)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex GenericExportsModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


SymbolRef GenericExportsModel::getSymbol(const QModelIndex& index)
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return nullptr;
	return m_entries[index.row()];
}


void GenericExportsModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](SymbolRef a, SymbolRef b) {
		if (col == AddressColumn)
		{
			if (a->GetAddress() != b->GetAddress())
			{
				if (order == Qt::AscendingOrder)
					return a->GetAddress() < b->GetAddress();
				else
					return a->GetAddress() > b->GetAddress();
			}
			if (order == Qt::AscendingOrder)
				return a->GetFullName() < b->GetFullName();
			else
				return a->GetFullName() > b->GetFullName();
		}
		else if (col == NameColumn)
		{
			if (order == Qt::AscendingOrder)
				return a->GetFullName() < b->GetFullName();
			else
				return a->GetFullName() > b->GetFullName();
		}
		else if (col == OrdinalColumn)
		{
			if (a->GetOrdinal() != b->GetOrdinal())
			{
				if (order == Qt::AscendingOrder)
					return a->GetOrdinal() < b->GetOrdinal();
				else
					return a->GetOrdinal() > b->GetOrdinal();
			}
			if (a->GetAddress() != b->GetAddress())
			{
				if (order == Qt::AscendingOrder)
					return a->GetAddress() < b->GetAddress();
				else
					return a->GetAddress() > b->GetAddress();
			}
			if (order == Qt::AscendingOrder)
				return a->GetFullName() < b->GetFullName();
			else
				return a->GetFullName() > b->GetFullName();
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
	m_filter = filterText;
	beginResetModel();
	m_entries.clear();
	for (auto& entry : m_allEntries)
	{
		if (FilteredView::match(entry->GetFullName(), filterText))
			m_entries.push_back(entry);
		else if (FilteredView::match(std::to_string(entry->GetOrdinal()), filterText))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


void GenericExportsModel::OnAnalysisFunctionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Function* func)
{
	emit modelUpdate();
}


void GenericExportsModel::OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Function* func)
{
	emit modelUpdate();
}


void GenericExportsModel::OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func)
{
	emit modelUpdate();
}


void GenericExportsModel::OnSymbolAdded(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	emit modelUpdate();
}


void GenericExportsModel::OnSymbolUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	emit modelUpdate();
}


void GenericExportsModel::OnSymbolRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	emit modelUpdate();
}


ExportsTreeView::ExportsTreeView(ExportsWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	m_selection.clear();
	m_scroll = 0;

	// Allow view-specific shortcuts when imports are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });

	m_model = new GenericExportsModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	sortByColumn(AddressColumn, Qt::AscendingOrder);

	setColumnWidth(OrdinalColumn, 55);
	for (int i = 0; i < m_model->columnCount(QModelIndex()); i ++)
	{
		setColumnHidden(i, !m_model->headerData(i, Qt::Horizontal, ColumnVisibleRole).toBool());
	}

	setFont(getMonospaceFont(this));

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &ExportsTreeView::exportSelected);
	connect(this, &QTreeView::doubleClicked, this, &ExportsTreeView::exportDoubleClicked);

	connect(m_model, &QAbstractItemModel::modelAboutToBeReset, this, [=]() {
		m_selection = selectionModel()->selectedIndexes();
		m_scroll = verticalScrollBar()->value();
	});
	connect(m_model, &QAbstractItemModel::modelReset, this, [=]() {
		for (auto& idx : m_selection)
		{
			setCurrentIndex(idx);
		}
		verticalScrollBar()->setValue(m_scroll);
	});
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
			if (BinaryNinja::Settings::Instance()->Get<bool>("ui.view.graph.preferred") &&
				viewFrame->getCurrentBinaryView() &&
				m_data->GetAnalysisFunctionsForAddress(sym->GetAddress()).size() > 0)
			{
				viewFrame->navigate("Graph:" + viewFrame->getCurrentDataType(), sym->GetAddress());
			}
			else
			{
				viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), sym->GetAddress());
			}
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

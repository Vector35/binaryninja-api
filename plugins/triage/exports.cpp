#include <QtWidgets/QScrollBar>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtCore/QStringList>
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
	m_updateTimer->setInterval(500);
	connect(m_updateTimer, &QTimer::timeout, this, &GenericExportsModel::updateModel);
	connect(this, &GenericExportsModel::updateTimerOnUIThread, this, [=, this]() {
		updateTimer(m_needsUpdate);
	}, Qt::QueuedConnection);

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
	if (!m_needsUpdate)
		return;

	setNeedsUpdate(false);
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

	setFilter(m_filter, m_filterOptions);
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


void GenericExportsModel::setFilter(const std::string& filterText, FilterOptions options)
{
	m_filter = filterText;
	m_filterOptions = options;
	beginResetModel();
	m_entries.clear();

	bool caseSensitive = options.testFlag(FilterOption::CaseSensitiveOption);
	for (auto& entry : m_allEntries)
	{
		if (FilteredView::match(entry->GetFullName(), filterText, caseSensitive))
			m_entries.push_back(entry);
		else if (FilteredView::match(std::to_string(entry->GetOrdinal()), filterText, caseSensitive))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


void GenericExportsModel::setNeedsUpdate(bool needed)
{
	if (m_needsUpdate.exchange(needed) == needed)
		return;

	updateTimer(needed);
}


void GenericExportsModel::updateTimer(bool needsUpdate)
{
	if (needsUpdate && !m_updateTimer->isActive())
		m_updateTimer->start();
	if (!needsUpdate && m_updateTimer->isActive())
		m_updateTimer->stop();
}

void GenericExportsModel::pauseUpdates()
{
	m_updatesPaused = true;
	m_dirtyWhilePaused = false;
	setNeedsUpdate(false);
}

void GenericExportsModel::resumeUpdates()
{
	m_updatesPaused = false;
	// Only refresh if we got notifications while paused
	if (m_dirtyWhilePaused.exchange(false))
		setNeedsUpdate(true);
}

void GenericExportsModel::onBinaryViewNotification()
{
	if (m_updatesPaused)
	{
		// Track that updates occurred while hidden
		m_dirtyWhilePaused = true;
		return;
	}

	// This can be called from any thread so we cannot directly
	// update the timer. Emitting a signal is relatively expensive
	// given how frequently we receive notifications, so we only
	// emit a signal if we didn't already need an update.
	if (!m_needsUpdate.exchange(true))
		emit updateTimerOnUIThread();
}


void GenericExportsModel::OnSymbolAdded(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	if ((sym->GetBinding() == GlobalBinding) || (sym->GetBinding() == WeakBinding))
		onBinaryViewNotification();
}


void GenericExportsModel::OnSymbolUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	onBinaryViewNotification();
}


void GenericExportsModel::OnSymbolRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym)
{
	onBinaryViewNotification();
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
	m_actionHandler.setActionContext([=, this]() { return m_view->actionContext(); });

	setFont(getMonospaceFont(this));

	m_model = new GenericExportsModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setAllColumnsShowFocus(true);
	sortByColumn(AddressColumn, Qt::AscendingOrder);

	setColumnWidth(OrdinalColumn, 55);
	for (int i = 0; i < m_model->columnCount(QModelIndex()); i ++)
	{
		setColumnHidden(i, !m_model->headerData(i, Qt::Horizontal, ColumnVisibleRole).toBool());
	}


	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &ExportsTreeView::exportSelected);
	connect(this, &QTreeView::doubleClicked, this, &ExportsTreeView::exportDoubleClicked);

	connect(m_model, &QAbstractItemModel::modelAboutToBeReset, this, [=, this]() {
		m_selection = selectionModel()->selectedIndexes();
		m_scroll = verticalScrollBar()->value();
	});
	connect(m_model, &QAbstractItemModel::modelReset, this, [=, this]() {
		for (auto& idx : m_selection)
		{
			setCurrentIndex(idx);
		}
		verticalScrollBar()->setValue(m_scroll);
	});

	m_actionHandler.bindAction("Copy", UIAction([this]() { copySelection(); }, [this]() { return canCopySelection(); }));
}

void ExportsTreeView::copySelection()
{
	if (!model() || !selectionModel())
		return;

	QModelIndexList rows = selectionModel()->selectedRows();
	if (rows.isEmpty())
		return;

	std::sort(rows.begin(), rows.end(), [](const QModelIndex& a, const QModelIndex& b) { return a.row() < b.row(); });

	QStringList lines;
	for (const QModelIndex& rowIndex : rows)
	{
		QStringList cells;
		for (int column = 0; column < m_model->columnCount(QModelIndex()); column++)
		{
			if (isColumnHidden(column))
				continue;

			QModelIndex idx = m_model->index(rowIndex.row(), column, QModelIndex());
			cells << m_model->data(idx, Qt::DisplayRole).toString();
		}
		lines << cells.join("\t");
	}

	if (QClipboard* clipboard = QGuiApplication::clipboard())
		clipboard->setText(lines.join("\n"));
}


bool ExportsTreeView::canCopySelection() const
{
	return !selectionModel()->selectedRows().isEmpty();
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


void ExportsTreeView::setFilter(const std::string& filterText, FilterOptions options)
{
	m_model->setFilter(filterText, options);
}


void ExportsTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void ExportsTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void ExportsTreeView::ensureSelection()
{
	if (auto current = currentIndex(); !current.isValid())
		setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void ExportsTreeView::activateSelection()
{
	ensureSelection();
	if (auto current = currentIndex(); current.isValid())
		exportDoubleClicked(current);
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
	else if (event->matches(QKeySequence::Copy))
	{
		copySelection();
		event->accept();
		return;
	}
	QTreeView::keyPressEvent(event);
}

void ExportsTreeView::showEvent(QShowEvent* event)
{
	QTreeView::showEvent(event);
	m_model->resumeUpdates();
}


void ExportsTreeView::hideEvent(QHideEvent* event)
{
	QTreeView::hideEvent(event);
	m_model->pauseUpdates();
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

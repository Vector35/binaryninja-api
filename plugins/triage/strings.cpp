#include <string.h>
#include <algorithm>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtCore/QStringList>
#include <QtCore/QEvent>
#include <QtCore/QTimer>
#include <QtWidgets/QHeaderView>
#include "strings.h"
#include "view.h"
#include "fontsettings.h"


GenericStringsModel::GenericStringsModel(QWidget* parent, BinaryViewRef data) : QAbstractItemModel(parent), BinaryDataNotification(StringUpdates)
{
	m_data = data;
	m_totalCols = 3;
	m_sortCol = 0;
	m_sortOrder = Qt::AscendingOrder;

	m_updateTimer = new QTimer(this);
	m_updateTimer->setInterval(500);
	connect(m_updateTimer, &QTimer::timeout, this, &GenericStringsModel::updateModel);
	connect(this, &GenericStringsModel::updateTimerOnUIThread, this, [=, this]() {
		updateTimer(m_needsUpdate);
	}, Qt::QueuedConnection);

	m_data->RegisterNotification(this);

	updateModel();
}


GenericStringsModel::~GenericStringsModel()
{
	m_data->UnregisterNotification(this);
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


void GenericStringsModel::applyFilter()
{
	m_entries.clear();
	for (auto& entry : m_allEntries)
	{
		auto s = stringRefToQString(entry);

		bool match;
		if (m_filterOptions.testFlag(UseRegexOption))
		{
			match = m_filterRegex.match(s).hasMatch();
		}
		else
		{
			match = s.contains(m_filter, m_filterOptions.testFlag(CaseSensitiveOption) ? Qt::CaseSensitive : Qt::CaseInsensitive);
		}

		if (match)
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
}


void GenericStringsModel::setFilter(const QString& filterText, FilterOptions options)
{
	m_filter = filterText;
	m_filterOptions = options;
	bool caseSensitive = options.testFlag(CaseSensitiveOption);
	m_filterRegex = QRegularExpression(filterText, caseSensitive ? QRegularExpression::NoPatternOption : QRegularExpression::CaseInsensitiveOption);
	beginResetModel();
	applyFilter();
	endResetModel();
}


void GenericStringsModel::updateModel()
{
	if (!m_needsUpdate)
		return;

	setNeedsUpdate(false);
	beginResetModel();
	m_allEntries = m_data->GetStrings();
	applyFilter();
	endResetModel();
}


void GenericStringsModel::setNeedsUpdate(bool needed)
{
	if (m_needsUpdate.exchange(needed) == needed)
		return;

	updateTimer(needed);
}


void GenericStringsModel::updateTimer(bool needsUpdate)
{
	if (needsUpdate && !m_updateTimer->isActive())
		m_updateTimer->start();
	if (!needsUpdate && m_updateTimer->isActive())
		m_updateTimer->stop();
}


void GenericStringsModel::pauseUpdates()
{
	m_updatesPaused = true;
	m_dirtyWhilePaused = false;
	setNeedsUpdate(false);
}


void GenericStringsModel::resumeUpdates()
{
	m_updatesPaused = false;
	// Only refresh if we got notifications while paused
	if (m_dirtyWhilePaused.exchange(false))
		setNeedsUpdate(true);
}


void GenericStringsModel::onBinaryViewNotification()
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


void GenericStringsModel::OnStringFound(BinaryNinja::BinaryView* view, BNStringType type, uint64_t offset, size_t len)
{
	onBinaryViewNotification();
}


void GenericStringsModel::OnStringRemoved(BinaryNinja::BinaryView* view, BNStringType type, uint64_t offset, size_t len)
{
	onBinaryViewNotification();
}


void GenericStringsModel::OnDerivedStringFound(BinaryNinja::BinaryView* view, const BinaryNinja::DerivedString& str)
{
	onBinaryViewNotification();
}


void GenericStringsModel::OnDerivedStringRemoved(BinaryNinja::BinaryView* view, const BinaryNinja::DerivedString& str)
{
	onBinaryViewNotification();
}


StringsTreeView::StringsTreeView(StringsWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when strings are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=, this]() { return m_view->actionContext(); });

	m_model = new GenericStringsModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setAllColumnsShowFocus(true);
	sortByColumn(0, Qt::AscendingOrder);

	setFont(getMonospaceFont(this));

	// Set column resize modes - use Interactive to avoid O(n) recalculation on every update
	header()->setSectionResizeMode(QHeaderView::Interactive);
	header()->setSectionResizeMode(2, QHeaderView::Stretch); // String column stretches to fill

	updateColumnWidths();

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &StringsTreeView::stringSelected);
	connect(this, &QTreeView::doubleClicked, this, &StringsTreeView::stringDoubleClicked);

	m_actionHandler.bindAction("Copy", UIAction([this]() { copySelection(); }, [this]() { return canCopySelection(); }));
}


void StringsTreeView::updateColumnWidths()
{
	// Size address and length columns based on their headers, not contents
	header()->resizeSection(0, header()->sectionSizeHint(0) + 20);
	header()->resizeSection(1, header()->sectionSizeHint(1) + 20);
}


bool StringsTreeView::event(QEvent* event)
{
	// Update column widths when font or style changes (e.g., UI scale change)
	if (event->type() == QEvent::FontChange || event->type() == QEvent::StyleChange)
	{
		// Defer update until after Qt recalculates font metrics
		QTimer::singleShot(0, this, &StringsTreeView::updateColumnWidths);
	}
	return QTreeView::event(event);
}


void StringsTreeView::copySelection()
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


bool StringsTreeView::canCopySelection() const
{
	return !selectionModel()->selectedRows().isEmpty();
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


void StringsTreeView::setFilter(const std::string& filterText, FilterOptions options)
{
	m_model->setFilter(QString::fromStdString(filterText), options);
}


void StringsTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void StringsTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void StringsTreeView::ensureSelection()
{
	if (auto current = currentIndex(); !current.isValid())
		setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void StringsTreeView::activateSelection()
{
	ensureSelection();
	if (auto current = currentIndex(); current.isValid())
		stringDoubleClicked(current);
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
	else if (event->matches(QKeySequence::Copy))
	{
		copySelection();
		event->accept();
		return;
	}
	QTreeView::keyPressEvent(event);
}


void StringsTreeView::showEvent(QShowEvent* event)
{
	QTreeView::showEvent(event);
	m_model->resumeUpdates();
}


void StringsTreeView::hideEvent(QHideEvent* event)
{
	QTreeView::hideEvent(event);
	m_model->pauseUpdates();
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

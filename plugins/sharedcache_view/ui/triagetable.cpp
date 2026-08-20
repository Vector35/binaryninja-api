#include "triagetable.h"

#include "addresstext.h"
#include "theme.h"
#include "ui/fontsettings.h"

#include <algorithm>
#include <cctype>
#include <QHeaderView>


using namespace SharedCacheAPI;


TriageTableModel::TriageTableModel(QWidget* parent) : QAbstractTableModel(parent)
{
	// TODO: Need to implement updating this font if it is changed by the user
	m_font = getMonospaceFont(parent);
}


TriageTableModel::FilterParams TriageTableModel::MakeFilterParams(const FilterSnapshot& snapshot)
{
	return {snapshot.text, snapshot.options,
		QRegularExpression(QString::fromStdString(snapshot.text),
			snapshot.options.testFlag(CaseSensitiveOption) ? QRegularExpression::NoPatternOption
														   : QRegularExpression::CaseInsensitiveOption),
		snapshot.matchImageNames};
}


bool TriageTableModel::MatchesText(const FilterParams& params, const std::string& text,
	uint64_t address, uint32_t addressWidth, const QString& imageName)
{
	if (params.options.testFlag(UseRegexOption))
	{
		if (params.regex.match(QString::fromUtf8(text.c_str(), text.size())).hasMatch())
			return true;
		if (params.regex.match(QString::fromStdString(AddressText(address, addressWidth))).hasMatch())
			return true;
		return params.matchImageNames && params.regex.match(imageName).hasMatch();
	}

	const bool caseSensitive = params.options.testFlag(CaseSensitiveOption);
	const auto contains = [&](const std::string& haystack) {
		if (caseSensitive)
			return haystack.find(params.text) != std::string::npos;
		const auto lower = [](char c) {
			return std::tolower(static_cast<unsigned char>(c));
		};
		auto it = std::search(haystack.begin(), haystack.end(), params.text.begin(), params.text.end(),
			[lower](char c1, char c2) { return lower(c1) == lower(c2); });
		return it != haystack.end();
	};

	if (contains(text))
		return true;
	if (contains(AddressText(address, addressWidth)))
		return true;
	return params.matchImageNames && contains(imageName.toStdString());
}


void ImageNameLookup::build(const SharedCacheController& controller)
{
	auto state = std::make_shared<State>();
	for (const auto& image : controller.GetImages())
	{
		const auto lastSlash = image.name.find_last_of('/');
		const size_t baseOffset = lastSlash == std::string::npos ? 0 : lastSlash + 1;
		state->imageNames[image.headerAddress] =
			QString::fromUtf8(image.name.data() + baseOffset, image.name.size() - baseOffset);
		state->imagePaths[image.headerAddress] = QString::fromStdString(image.name);
	}
	for (const auto& region : controller.GetRegions())
	{
		state->maxAddress = std::max(state->maxAddress, region.start + region.size);
		if (!region.imageStart.has_value())
			state->nonImageRegionNames[region.start] = QString::fromStdString(region.name);
	}
	m_state = std::move(state);
}


QString ImageNameLookup::displayName(const State& state, std::optional<uint64_t> imageStart,
	uint64_t regionStart)
{
	if (imageStart)
	{
		if (auto it = state.imageNames.find(*imageStart); it != state.imageNames.end())
			return it->second;
	}
	if (auto it = state.nonImageRegionNames.find(regionStart); it != state.nonImageRegionNames.end())
		return it->second;
	return {};
}


QString ImageNameLookup::tooltip(const State& state, std::optional<uint64_t> imageStart,
	uint64_t regionStart)
{
	if (imageStart)
	{
		if (auto it = state.imagePaths.find(*imageStart); it != state.imagePaths.end())
			return it->second;
	}
	if (auto it = state.nonImageRegionNames.find(regionStart); it != state.nonImageRegionNames.end())
		return it->second;
	return {};
}


QString ImageNameLookup::displayName(std::optional<uint64_t> imageStart, uint64_t regionStart) const
{
	return displayName(*m_state, imageStart, regionStart);
}


QString ImageNameLookup::tooltip(std::optional<uint64_t> imageStart, uint64_t regionStart) const
{
	return tooltip(*m_state, imageStart, regionStart);
}


QString ImageNameLookup::widestImageColumnText() const
{
	QString widest;
	const auto updateWidest = [&widest](const std::map<uint64_t, QString>& names) {
		for (const auto& [_, name] : names)
			if (name.size() > widest.size())
				widest = name;
	};
	updateWidest(m_state->imageNames);
	updateWidest(m_state->nonImageRegionNames);
	return widest;
}


void TriageTableModel::setFilter(const std::string& text, FilterOptions options)
{
	m_filterText = text;
	m_filterOptions = options;
	applyFilter();
}


void TriageTableModel::setMatchImageNames(bool match)
{
	if (m_matchImageNames == match)
		return;
	m_matchImageNames = match;
	if (!m_filterText.empty())
		applyFilter();
}


void TriageTableModel::promoteSortColumn(int column, Qt::SortOrder order)
{
	std::erase_if(m_sortKeys, [column](const auto& key) { return key.first == column; });
	m_sortKeys.insert(m_sortKeys.begin(), {column, order});
}


TriageTableView::TriageTableView(QWidget* parent) : QTableView(parent)
{
	setFont(getMonospaceFont(this));
	setWordWrap(false);
	verticalHeader()->setVisible(false);

	// Match the dense row sizing of the regular strings and symbols views.
	const int charHeight = (int)(QFontMetricsF(getMonospaceFont(this)).height() + getExtraFontSpacing());
	verticalHeader()->setDefaultSectionSize(charHeight);
	verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
	horizontalHeader()->setStretchLastSection(true);
	// With row selection, the default section highlighting bolds every column header whenever a
	// row is selected.
	horizontalHeader()->setHighlightSections(false);
	setShowGrid(false);

	setEditTriggers(QAbstractItemView::NoEditTriggers);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);
}


void TriageTableView::setTriageModel(TriageTableModel* model, int sortColumn)
{
	m_model = model;
	setModel(model);

	sortByColumn(sortColumn, Qt::AscendingOrder);
	setSortingEnabled(true);

	m_busyOverlay = new QLabel(viewport());
	m_busyOverlay->setAlignment(Qt::AlignCenter);
	m_busyOverlay->setAutoFillBackground(true);
	m_busyOverlay->setContentsMargins(16, 8, 16, 8);
	m_busyOverlay->hide();
	const auto updateOverlay = [this](bool) {
		if (m_model->isSorting())
			m_busyOverlay->setText(QStringLiteral("Sorting…"));
		else if (m_model->isFiltering())
			m_busyOverlay->setText(QStringLiteral("Filtering…"));
		m_busyOverlay->setVisible(m_model->isSorting() || m_model->isFiltering());
		positionBusyOverlay();
	};
	connect(m_model, &TriageTableModel::filteringChanged, this, updateOverlay);
	connect(m_model, &TriageTableModel::sortingChanged, this, updateOverlay);
}


void TriageTableView::fitColumn(int column, const std::vector<QString>& contents)
{
	const QFontMetricsF metrics(getMonospaceFont(this));
	// Room for the header's sort indicator.
	const int padding = (int)metrics.horizontalAdvance(QStringLiteral("  "));
	qreal width = metrics.horizontalAdvance(
		m_model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString());
	for (const auto& content : contents)
		width = std::max(width, metrics.horizontalAdvance(content));
	setColumnWidth(column, (int)width + padding);
}


void TriageTableView::savePosition()
{
	const auto current = selectionModel()->currentIndex();
	const auto top = indexAt(QPoint(0, 0));
	m_model->saveRowIdentities(current.isValid() ? current.row() : -1, top.isValid() ? top.row() : -1);
}


void TriageTableView::restorePosition()
{
	const auto [selectedRow, topRow] = m_model->takeSavedRows();
	if (selectedRow >= 0)
		selectionModel()->setCurrentIndex(m_model->index(selectedRow, 0),
			QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
	if (topRow >= 0)
		scrollTo(m_model->index(topRow, 0), QAbstractItemView::PositionAtTop);
}


void TriageTableView::setFilter(const std::string& filter, FilterOptions options)
{
	m_model->setFilter(filter, options);
}


void TriageTableView::scrollToFirstItem()
{
	if (model()->rowCount() > 0)
	{
		QModelIndex top = indexAt(rect().topLeft());
		if (top.isValid())
			scrollTo(top);
	}
}


void TriageTableView::scrollToCurrentItem()
{
	QModelIndex currentIndex = selectionModel()->currentIndex();
	if (currentIndex.isValid())
		scrollTo(currentIndex);
}


void TriageTableView::ensureSelection()
{
	QModelIndex current = selectionModel()->currentIndex();
	if (current.isValid() || model()->rowCount() == 0)
		return;

	if (auto top = indexAt(rect().topLeft()); top.isValid())
	{
		selectionModel()->select(top, QItemSelectionModel::ClearAndSelect);
		setCurrentIndex(top);
	}
}


void TriageTableView::activateSelection()
{
	// Return from the filter moves focus to the table rather than activating a row. Activating
	// loads an image or navigates, which is too aggressive to trigger from the filter field.
	// A selection is ensured so the table is immediately navigable with the arrow keys.
	ensureSelection();
	closeFilter();
}


void TriageTableView::resizeEvent(QResizeEvent* event)
{
	QTableView::resizeEvent(event);
	if (m_busyOverlay)
		positionBusyOverlay();
}


void TriageTableView::positionBusyOverlay()
{
	m_busyOverlay->adjustSize();
	m_busyOverlay->move((viewport()->width() - m_busyOverlay->width()) / 2,
		(viewport()->height() - m_busyOverlay->height()) / 2);
}


TriageTablePanel::TriageTablePanel(QWidget* parent, TriageTableView* table,
	const QString& filterPlaceholder, QString rowNoun)
	: QWidget(parent), m_table(table), m_rowNoun(std::move(rowNoun))
{
	m_filterEdit = new FilterEdit(table);
	m_filterEdit->setPlaceholderText(filterPlaceholder);
	m_filterEdit->showRegexToggle(true);
	connect(m_filterEdit, &FilterEdit::textChanged, this, &TriageTablePanel::applyFilter);
	connect(m_filterEdit, &FilterEdit::optionsChanged, this, &TriageTablePanel::applyFilter);

	m_statusLabel = new QLabel(this);
	m_statusLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	// Tabular numbers keep the status text from shifting as its numbers change.
	QFont statusFont = m_statusLabel->font();
	statusFont.setFeature("tnum", 1);
	m_statusLabel->setFont(statusFont);

	m_footerLayout = new QHBoxLayout;
	m_footerLayout->addWidget(m_statusLabel);
	m_footerLayout->setAlignment(Qt::AlignLeft);

	auto layout = new QVBoxLayout(this);
	layout->addWidget(m_filterEdit);
	layout->addWidget(m_table);
	layout->addLayout(m_footerLayout);

	// Frees the loaded content once the tab has been hidden for this long.
	constexpr int clearDelayMs = 60 * 1000;
	m_clearTimer = new QTimer(this);
	m_clearTimer->setInterval(clearDelayMs);
	m_clearTimer->setSingleShot(true);
	connect(m_clearTimer, &QTimer::timeout, this, &TriageTablePanel::clearContent);

	const auto model = m_table->triageModel();
	connect(model, &TriageTableModel::filteringChanged, this, [this](bool) { updateStatusLabel(); });
	connect(model, &TriageTableModel::sortingChanged, this, [this](bool active) {
		updateStatusLabel();
		if (!active)
			restoreWhenIdle();
	});
}


void TriageTablePanel::applyFilter()
{
	const QString text = m_filterEdit->text();
	const FilterOptions options = m_filterEdit->getFilterOptions();
	if (options.testFlag(UseRegexOption))
	{
		const QRegularExpression regex(text);
		if (!regex.isValid())
		{
			m_filterEdit->setRegexValidationError(regex.errorString());
			return;
		}
	}

	m_filterEdit->setRegexValidationError({});
	m_table->setFilter(text.toStdString(), options);
}


void TriageTablePanel::addFooterWidget(QWidget* widget)
{
	m_footerLayout->insertWidget(m_footerLayout->count() - 1, widget);
}


QAction* TriageTablePanel::addFilterToggle(const QString& iconPath, const QString& toolTip,
	std::function<void(bool)> onToggled)
{
	QPixmap offPixmap;
	pixmapForBWMaskIcon(iconPath, &offPixmap);
	QPixmap onPixmap;
	pixmapForBWMaskIcon(iconPath, &onPixmap, m_filterEdit->palette().color(QPalette::Highlight), "filterOn");
	auto action = m_filterEdit->addAction(QIcon(offPixmap), QLineEdit::TrailingPosition);
	action->setCheckable(true);
	action->setToolTip(toolTip);
	connect(action, &QAction::toggled, this,
		[action, offIcon = QIcon(offPixmap), onIcon = QIcon(onPixmap),
			onToggled = std::move(onToggled)](bool checked) {
			action->setIcon(checked ? onIcon : offIcon);
			onToggled(checked);
		});
	return action;
}


QPushButton* TriageTablePanel::addSelectionButton(const QString& text)
{
	auto button = new QPushButton(text);
	button->setEnabled(false);
	const auto update = [this, button] {
		button->setEnabled(m_table->selectionModel()->hasSelection());
	};
	connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, button, update);
	connect(m_table->triageModel(), &QAbstractItemModel::modelReset, button, update);
	addFooterWidget(button);
	return button;
}


void TriageTablePanel::setLoader(std::function<bool()> loader)
{
	m_loader = std::move(loader);
}


void TriageTablePanel::setClearHandler(std::function<void()> handler)
{
	m_clearHandler = std::move(handler);
}


void TriageTablePanel::setBaselineCount(std::function<size_t()> baselineCount)
{
	m_baselineCount = std::move(baselineCount);
}


void TriageTablePanel::setViewVisible(bool visible)
{
	m_viewVisible = visible;
	updateActive();
}


void TriageTablePanel::setCurrentTabWidget(QWidget* current)
{
	m_tabCurrent = (current == this);
	updateActive();
}


void TriageTablePanel::updateActive()
{
	// The content is on screen only when the triage view is visible and this tab is current.
	if (m_viewVisible && m_tabCurrent)
	{
		m_clearTimer->stop();
		if (!m_loadStarted && m_loader)
		{
			m_loadStarted = m_loader();
			// The loader owns the status label, for its progress text, until the load finishes.
			m_loaderOwnsStatus = m_loadStarted;
		}
	}
	else if (m_loadStarted && !m_clearTimer->isActive())
	{
		// Begin the countdown from when the content first went off screen. Later transitions
		// while still off screen must not extend it.
		m_clearTimer->start();
	}
}


void TriageTablePanel::clearContent()
{
	if (!m_loadStarted)
		return;

	// Clearing abandons any running sort, whose end signal must not consume the saved position.
	m_restorePending = false;
	if (m_clearHandler)
		m_clearHandler();
	m_table->savePosition();
	m_table->triageModel()->clearRows();
	m_loadStarted = false;
	m_loaderOwnsStatus = false;
	m_statusLabel->setText("");
}


void TriageTablePanel::resetContent()
{
	clearContent();
	updateActive();
}


void TriageTablePanel::finishLoad()
{
	// Restore the saved position once the sort over the now complete content commits.
	m_restorePending = true;
	m_table->sortByColumn(m_table->horizontalHeader()->sortIndicatorSection(),
		m_table->horizontalHeader()->sortIndicatorOrder());
	m_loaderOwnsStatus = false;
	updateStatusLabel();
}


void TriageTablePanel::updateStatusLabel()
{
	if (!m_loadStarted || m_loaderOwnsStatus)
		return;

	const auto model = m_table->triageModel();
	if (model->isSorting())
	{
		m_statusLabel->setText(QStringLiteral("Sorting…"));
		return;
	}
	if (model->isFiltering())
	{
		m_statusLabel->setText(QStringLiteral("Filtering…"));
		return;
	}

	const QLocale locale;
	const auto shown = static_cast<qulonglong>(model->rowCount(QModelIndex()));
	if (!model->hasTextFilter())
	{
		m_statusLabel->setText(QString("%1 %2").arg(locale.toString(shown), m_rowNoun));
		return;
	}
	const auto baseline =
		static_cast<qulonglong>(m_baselineCount ? m_baselineCount() : model->totalRowCount());
	m_statusLabel->setText(
		QString("%1 / %2 %3").arg(locale.toString(shown), locale.toString(baseline), m_rowNoun));
}


void TriageTablePanel::restoreWhenIdle()
{
	if (!m_restorePending)
		return;
	// A sort's end signal also fires when the sort is abandoned for a filter change or superseded
	// by a newer sort, with the follow-up job starting just after, so the check is deferred one
	// event-loop turn. Follow-up chains always end with a committed sort.
	QTimer::singleShot(0, this, [this] {
		const auto model = m_table->triageModel();
		if (!m_restorePending || model->isSorting() || model->isFiltering())
			return;
		m_restorePending = false;
		m_table->restorePosition();
	});
}

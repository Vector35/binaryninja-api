#pragma once

#include <sharedcacheapi.h>

#include "backgroundsortfilterrows.h"
#include "filter.h"

#include <QBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableView>
#include <QTimer>
#include <algorithm>
#include <compare>
#include <concepts>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdint.h>
#include <unordered_map>
#include <utility>
#include <vector>


/*! Name lookups for a table's Image column, keyed by image header address and region start
	address.
*/
class ImageNameLookup
{
public:
	struct State
	{
		std::map<uint64_t, QString> imageNames;
		// Names of regions not associated with an image, keyed by region start.
		// regions within images should be resolved in imageNames instead.
		std::map<uint64_t, QString> nonImageRegionNames;
		// Full image paths for the Image column tooltip.
		std::map<uint64_t, QString> imagePaths;
		uint64_t maxAddress = 0;
	};

private:
	std::shared_ptr<const State> m_state = std::make_shared<const State>();

public:
	// Build the lookups from the controller's images and regions.
	void build(const SharedCacheAPI::SharedCacheController& controller);

	std::shared_ptr<const State> snapshot() const { return m_state; }

	static QString displayName(
		const State& state, std::optional<uint64_t> imageStart, uint64_t regionStart);
	static QString tooltip(const State& state, std::optional<uint64_t> imageStart, uint64_t regionStart);

	// The Image column display name: the image's base name, or the region's name for rows
	// outside any image.
	QString displayName(std::optional<uint64_t> imageStart, uint64_t regionStart) const;

	// The Image column tooltip: the image's full path, or the region's name for rows outside
	// any image.
	QString tooltip(std::optional<uint64_t> imageStart, uint64_t regionStart) const;

	// The widest text the Image column can display, for sizing it: the longest image name or
	// non-image region name.
	QString widestImageColumnText() const;

	// The end of the highest region, for sizing zero-padded address text.
	uint64_t maxAddress() const { return m_state->maxAddress; }
};


/*! A row that resolves to an image and region, so it can be displayed and ranked in the Image
	column. \c imageStart is 0 when the row is outside any image; \c regionStart is 0 when it is
	outside any region.
*/
template <typename Row>
concept RowWithImageColumn = requires(const Row& row) {
	{ row.imageStart } -> std::convertible_to<uint64_t>;
	{ row.regionStart } -> std::convertible_to<uint64_t>;
};


/*! A three-way ordering of rows by their Image-column display name (the image's base name, or the
	region's name for rows outside any image), resolving each name to a dense integer rank once so
	comparisons are integer-only rather than repeated string compares.
*/
template <RowWithImageColumn Row>
std::function<std::strong_ordering(const Row&, const Row&)> ImageColumnOrdering(
	const ImageNameLookup::State& names)
{
	struct NameEntry
	{
		const QString* name;
		bool isImage;
		uint64_t key;
	};
	std::vector<NameEntry> entries;
	entries.reserve(names.imageNames.size() + names.nonImageRegionNames.size());
	for (const auto& [address, name] : names.imageNames)
		entries.push_back({&name, true, address});
	for (const auto& [start, name] : names.nonImageRegionNames)
		entries.push_back({&name, false, start});
	std::sort(entries.begin(), entries.end(),
		[](const NameEntry& a, const NameEntry& b) { return *a.name < *b.name; });

	struct NameRanks
	{
		std::unordered_map<uint64_t, int> imageRanks;
		std::unordered_map<uint64_t, int> regionRanks;
	};
	auto ranks = std::make_shared<NameRanks>();
	int rank = -1;
	const QString* previousName = nullptr;
	for (const auto& entry : entries)
	{
		// Identical names share a rank, matching equality under name comparison.
		if (!previousName || *entry.name != *previousName)
		{
			rank++;
			previousName = entry.name;
		}
		(entry.isImage ? ranks->imageRanks : ranks->regionRanks)[entry.key] = rank;
	}

	return [ranks](const Row& a, const Row& b) {
		// Unknown names rank first like the empty string.
		const auto rankOf = [&ranks](const Row& row) {
			if (row.imageStart)
			{
				if (auto it = ranks->imageRanks.find(row.imageStart); it != ranks->imageRanks.end())
					return it->second;
			}
			if (auto it = ranks->regionRanks.find(row.regionStart); it != ranks->regionRanks.end())
				return it->second;
			return -1;
		};
		return rankOf(a) <=> rankOf(b);
	};
}


/*! Shared portion of the triage view's flat table models: the filter state and the text matching
	common to the tables. Row storage lives in the typed subclass \c TriageTableRowsModel.
*/
class TriageTableModel : public QAbstractTableModel
{
Q_OBJECT
protected:
	struct FilterParams
	{
		std::string text;
		FilterOptions options;
		QRegularExpression regex;
		bool matchImageNames;
	};

	// The filter state, captured on the GUI thread for the worker-thread predicate factories.
	struct FilterSnapshot
	{
		std::string text;
		FilterOptions options;
		bool matchImageNames;
	};

	QFont m_font;

	// Rendered width of the highest cache address, for zero-padded address display.
	uint32_t m_addressWidth = 16;

	std::string m_filterText;
	FilterOptions m_filterOptions;
	bool m_matchImageNames = false;

	// Active sort keys, most significant first.
	std::vector<std::pair<int, Qt::SortOrder>> m_sortKeys;

	explicit TriageTableModel(QWidget* parent);

	// Promote `column` to the most significant sort key, keeping the rest as lower-priority keys.
	void promoteSortColumn(int column, Qt::SortOrder order);

	FilterSnapshot filterSnapshot() const { return {m_filterText, m_filterOptions, m_matchImageNames}; }

	// Materialize a snapshot's matching state. Call once per work chunk on the worker threads:
	// QRegularExpression::match takes the instance's mutex, so a shared instance serializes them.
	static FilterParams MakeFilterParams(const FilterSnapshot& snapshot);

	// Whether the filter matches the row's primary text, its rendered address, or its image name.
	// Pass an empty image name when image name matching is disabled.
	static bool MatchesText(const FilterParams& params, const std::string& text, uint64_t address,
		uint32_t addressWidth, const QString& imageName);

	// Re-apply the filter state to the rows.
	virtual void applyFilter() = 0;

public:
	uint32_t addressWidth() const { return m_addressWidth; }

	void setFilter(const std::string& text, FilterOptions options);

	// Whether the filter also matches against the Image column. Re-applies any active filter.
	void setMatchImageNames(bool match);

	bool hasTextFilter() const { return !m_filterText.empty(); }

	virtual bool isFiltering() const = 0;
	virtual bool isSorting() const = 0;

	// Count of all rows fetched so far, ignoring any filter.
	virtual size_t totalRowCount() const = 0;

	// Drop all rows, freeing their storage, while retaining the filter settings.
	virtual void clearRows() = 0;

	// Capture the identities of the given display rows for a `takeSavedRows` lookup after a
	// content reload. Pass -1 to leave a slot empty.
	virtual void saveRowIdentities(int selectedRow, int topRow) = 0;
	// Consume the identities captured by `saveRowIdentities`, returning their current display
	// rows as {selected, top}, with -1 where a row is no longer displayed.
	virtual std::pair<int, int> takeSavedRows() = 0;

Q_SIGNALS:
	// Emitted when background filtering starts and finishes.
	void filteringChanged(bool active);
	// Emitted when background sorting starts and finishes.
	void sortingChanged(bool active);
};


/*! Typed row storage for triage table models: rows sorted and filtered on the worker pool, plus
	the row identity bookkeeping that restores positions across a content reload.
*/
template <typename Row>
class TriageTableRowsModel : public TriageTableModel
{
public:
	using Predicate = typename BackgroundSortFilterRows<Row>::Predicate;
	using PredicateFactory = typename BackgroundSortFilterRows<Row>::PredicateFactory;
	using Comparator = typename BackgroundSortFilterRows<Row>::Comparator;

	int rowCount(const QModelIndex& parent) const override
	{
		Q_UNUSED(parent);
		return static_cast<int>(m_rows.displayCount());
	}

	const Row& rowAt(int row) const { return m_rows.displayAt(row); }

	void appendRows(std::vector<Row> rows) { m_rows.append(std::move(rows)); }

	bool isFiltering() const override { return m_rows.filtering(); }
	bool isSorting() const override { return m_rows.sorting(); }

	size_t totalRowCount() const override { return m_rows.totalCount(); }

	void clearRows() override { m_rows.clear(); }

	void saveRowIdentities(int selectedRow, int topRow) override
	{
		m_savedSelection = selectedRow >= 0 ? std::optional<Row>(rowAt(selectedRow)) : std::nullopt;
		m_savedTopRow = topRow >= 0 ? std::optional<Row>(rowAt(topRow)) : std::nullopt;
	}

	std::pair<int, int> takeSavedRows() override
	{
		int selectedRow = -1;
		int topRow = -1;
		const int count = static_cast<int>(m_rows.displayCount());
		for (int row = 0; row < count && (selectedRow < 0 || topRow < 0); row++)
		{
			const Row& candidate = m_rows.displayAt(row);
			if (selectedRow < 0 && m_savedSelection && rowsEquivalent(candidate, *m_savedSelection))
				selectedRow = row;
			if (topRow < 0 && m_savedTopRow && rowsEquivalent(candidate, *m_savedTopRow))
				topRow = row;
		}
		m_savedSelection.reset();
		m_savedTopRow.reset();
		return {selectedRow, topRow};
	}

	// Sort by `column` as the most significant key, keeping previously clicked columns as
	// lower-priority keys so successive sorts compose into a multi-key order.
	void sort(int column, Qt::SortOrder order) override
	{
		promoteSortColumn(column, order);
		struct SortKey
		{
			KeyOrdering ordering;
			bool descending;
		};

		std::vector<SortKey> keys;
		keys.reserve(m_sortKeys.size());
		for (const auto& [keyColumn, keyOrder] : m_sortKeys)
		{
			if (auto ordering = orderingForColumn(keyColumn))
				keys.push_back({std::move(ordering), keyOrder == Qt::DescendingOrder});
		}

		m_rows.sort([keys = std::move(keys), finalComparator = m_finalComparator](
						const Row& a, const Row& b) {
			for (const auto& key : keys)
			{
				const std::strong_ordering ordering = key.ordering(a, b);
				if (ordering != 0)
					return key.descending ? ordering > 0 : ordering < 0;
			}
			return finalComparator(a, b);
		});
	}

protected:
	explicit TriageTableRowsModel(QWidget* parent) :
		TriageTableModel(parent),
		m_rows({
			std::bind_front(&TriageTableRowsModel::beginResetModel, this),
			std::bind_front(&TriageTableRowsModel::endResetModel, this),
			std::bind_front(&TriageTableRowsModel::beginInsertRows, this, QModelIndex()),
			std::bind_front(&TriageTableRowsModel::endInsertRows, this),
			std::bind_front(&TriageTableRowsModel::filteringChanged, this),
			std::bind_front(&TriageTableRowsModel::sortingChanged, this),
		})
	{}

	// Whether two rows are the same row, for position save and restore.
	virtual bool rowsEquivalent(const Row& a, const Row& b) const = 0;

	// The ascending three-way ordering for a column, or null if the column is not sortable.
	using KeyOrdering = std::function<std::strong_ordering(const Row&, const Row&)>;
	virtual KeyOrdering orderingForColumn(int column) const = 0;

	// The final tiebreak appended after the sort keys so the order is total and reproducible.
	Comparator m_finalComparator;

	// This base member is destroyed after derived model members, so predicates and comparators
	// passed to it must capture worker-safe snapshots rather than reading derived model state.
	BackgroundSortFilterRows<Row> m_rows;
	// Rows captured by `saveRowIdentities` for restoring positions across a content reload.
	std::optional<Row> m_savedSelection;
	std::optional<Row> m_savedTopRow;
};


/*! Shared behavior for the triage view's tables: dense monospace styling, filter target
	plumbing, the busy overlay, and position save and restore across content reloads.
*/
class TriageTableView : public QTableView, public FilterTarget
{
Q_OBJECT
	TriageTableModel* m_model = nullptr;
	QLabel* m_busyOverlay = nullptr;

	void positionBusyOverlay();

public:
	TriageTableModel* triageModel() const { return m_model; }

	// Capture the identities of the selected row and the first visible row ahead of a content
	// reload.
	void savePosition();
	// Re-select and re-scroll to the rows captured by `savePosition`, where still displayed.
	void restorePosition();

	void setFilter(const std::string& filter, FilterOptions options) override;

	void scrollToFirstItem() override;
	void scrollToCurrentItem() override;
	void ensureSelection() override;
	void activateSelection() override;

protected:
	explicit TriageTableView(QWidget* parent);

	// Attach the model, set the column the table initially sorts by, and finish the setup that
	// depends on the model. Must be called exactly once from the derived constructor.
	void setTriageModel(TriageTableModel* model, int sortColumn);

	// Fit the column to the widest of its header and `contents` in the monospace font, plus room
	// for the header's sort indicator. The column remains user-resizable.
	void fitColumn(int column, const std::vector<QString>& contents);

	// Fit each fixed-content column to its possible contents. Called when the name sources
	// change. Only the last column stretches.
	virtual void applyDefaultColumnWidths() = 0;

	void resizeEvent(QResizeEvent* event) override;
};


/*! A triage tab hosting an expensive table: a filter field above the table and a footer with a
	status label. The content loads when the tab first comes on screen, is cleared after the tab
	has been off screen for a delay, and the table's position is saved and restored across the
	reload.
*/
class TriageTablePanel : public QWidget
{
Q_OBJECT
	TriageTableView* m_table;
	FilterEdit* m_filterEdit;
	QHBoxLayout* m_footerLayout;
	QLabel* m_statusLabel;
	QTimer* m_clearTimer;
	QString m_rowNoun;

	std::function<bool()> m_loader;
	std::function<void()> m_clearHandler;
	std::function<size_t()> m_baselineCount;

	bool m_loadStarted = false;
	bool m_viewVisible = false;
	bool m_tabCurrent = false;
	bool m_restorePending = false;
	bool m_loaderOwnsStatus = false;

	void updateActive();
	void applyFilter();
	void updateStatusLabel();
	void restoreWhenIdle();

public:
	// `rowNoun` names the rows in the footer's counts, e.g. "symbols".
	TriageTablePanel(QWidget* parent, TriageTableView* table, const QString& filterPlaceholder,
		QString rowNoun);

	TriageTableView* table() const { return m_table; }
	FilterEdit* filterEdit() const { return m_filterEdit; }
	// The loader owns the status label, for its progress text, until `finishLoad`.
	QLabel* statusLabel() const { return m_statusLabel; }

	// Insert a widget ahead of the status label in the footer.
	void addFooterWidget(QWidget* widget);

	// Add a checkable icon action to the filter field, highlighting the icon while checked.
	QAction* addFilterToggle(const QString& iconPath, const QString& toolTip,
		std::function<void(bool)> onToggled);

	// Add a footer button that is enabled only while the table has a selection.
	QPushButton* addSelectionButton(const QString& text);

	// Starts loading the table's content when the tab first comes on screen. Returns false if
	// loading cannot begin yet, retrying on the next activation.
	void setLoader(std::function<bool()> loader);
	// Invoked before the rows are cleared, to stop and free the owner's loader state.
	void setClearHandler(std::function<void()> handler);
	// Count of rows eligible for display ignoring any text filter, the denominator of the
	// footer's filtered count. Defaults to the model's total row count.
	void setBaselineCount(std::function<size_t()> baselineCount);

	// Track whether the triage view is on screen and which triage tab is current.
	void setViewVisible(bool visible);
	void setCurrentTabWidget(QWidget* current);

	// Call when the load has delivered every row: applies the selected sort, restores the saved
	// position once it commits, and returns the status label to the panel.
	void finishLoad();

	// Discard the content immediately and reload it if the tab is on screen.
	void resetContent();

	// Free the content. The filter widgets keep their state and the position is saved, so a
	// reload reproduces the same view.
	void clearContent();
};

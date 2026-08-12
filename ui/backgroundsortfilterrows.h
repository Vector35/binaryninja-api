#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>
#include <optional>
#include <utility>
#include <vector>

#include <QFuture>
#include <QFutureWatcher>
#include <QThread>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentMap>
#include <QtConcurrent/QtConcurrentRun>

#include "base/assertions.h"
#include "binaryninjacore.h"

/*! The non-template portion of \c BackgroundSortFilterRows.
	Contains the background job state machine, watcher lifecycle, and abandonment protocol,
	which are independent of the row type.

	\ingroup filter
*/
class BackgroundSortFilterRowsBase
{
public:
	// Model integration points. The reset and insert hooks bracket changes to the display rows,
	// matching the corresponding QAbstractItemModel methods.
	struct ModelHooks
	{
		std::function<void()> beginResetModel;
		std::function<void()> endResetModel;
		std::function<void(int first, int last)> beginInsertRows;
		std::function<void()> endInsertRows;
		// Optional. Called when background filtering starts and finishes.
		std::function<void(bool active)> filteringChanged;
		// Optional. Called when background sorting starts and finishes.
		std::function<void(bool active)> sortingChanged;
	};

	explicit BackgroundSortFilterRowsBase(ModelHooks hooks) : m_hooks(std::move(hooks)) {}
	virtual ~BackgroundSortFilterRowsBase() { shutdown(); }

	BackgroundSortFilterRowsBase(const BackgroundSortFilterRowsBase&) = delete;
	BackgroundSortFilterRowsBase& operator=(const BackgroundSortFilterRowsBase&) = delete;

	bool busy() const { return m_jobActive; }
	bool filtering() const { return m_jobActive && m_jobKind == JobKind::Filter; }
	bool sorting() const { return m_jobActive && m_jobKind == JobKind::Sort; }

protected:
	enum class JobKind
	{
		Filter,
		Sort,
	};

	void assertOwningThread() const { BN_ASSERT(QThread::currentThread() == m_owningThread); }

	// Abandon any in-flight job, wait for its workers to notice, and destroy the watcher
	// immediately so a queued finished signal cannot run a commit handler afterwards. Derived
	// destructors must call this before the row storage the workers read is destroyed.
	void shutdown()
	{
		m_filterGeneration.fetch_add(1);
		m_future.waitForFinished();
		m_watcher.reset();
	}

	// Like `shutdown`, but leaves the object reusable. Returns it to the idle state and notifies
	// that the abandoned job is no longer running. The job's result is discarded, not committed.
	void abandonJob()
	{
		if (!m_jobActive)
			return;
		shutdown();
		m_jobActive = false;
		if (m_jobKind == JobKind::Filter && m_hooks.filteringChanged)
			m_hooks.filteringChanged(false);
		else if (m_jobKind == JobKind::Sort && m_hooks.sortingChanged)
			m_hooks.sortingChanged(false);
	}

	// Registers `future` as the running job. Its completion invokes `commitJob` back on the
	// owning thread. `filterGeneration` must be the value the job's workers compare against.
	void beginJob(JobKind kind, uint64_t filterGeneration, QFuture<void> future)
	{
		BN_ASSERT(!m_jobActive);
		m_jobActive = true;
		m_jobKind = kind;
		m_jobFilterGeneration = filterGeneration;
		m_future = std::move(future);
		m_watcher = std::make_unique<QFutureWatcher<void>>();
		QObject::connect(
			m_watcher.get(), &QFutureWatcherBase::finished, m_watcher.get(), [this] { finishJob(); });
		if (kind == JobKind::Filter && m_hooks.filteringChanged)
			m_hooks.filteringChanged(true);
		else if (kind == JobKind::Sort && m_hooks.sortingChanged)
			m_hooks.sortingChanged(true);
		m_watcher->setFuture(m_future);
	}

	// Whether the filter changed after the current or just-finished job captured its generation.
	bool filterChangedDuringJob() const { return m_jobFilterGeneration != m_filterGeneration.load(); }

	// Called on the owning thread when the registered job's future finishes.
	virtual void commitJob(JobKind kind) = 0;

	ModelHooks m_hooks;
	// Bumped when the filtered set becomes stale: on a filter-predicate change, and on teardown.
	// Filter workers watch it to drop a superseded filter pass. Sort workers watch it too, because a
	// filter change invalidates the display snapshot they are reordering, and commitSortJob reads it
	// (via filterChangedDuringJob) to recognize that case and re-filter before re-sorting.
	std::atomic<uint64_t> m_filterGeneration = 0;

private:
	void finishJob()
	{
		// This is invoked by the watcher's finished signal so the watcher cannot be deleted
		// directly here.
		m_watcher.release()->deleteLater();
		m_jobActive = false;
		commitJob(m_jobKind);
	}

	QThread* m_owningThread = QThread::currentThread();
	uint64_t m_jobFilterGeneration = 0;
	bool m_jobActive = false;
	JobKind m_jobKind = JobKind::Filter;
	std::unique_ptr<QFutureWatcher<void>> m_watcher;
	QFuture<void> m_future;
};

/*! Append-only row storage for table models that filters and sorts rows on the worker pool.

	Filtering and sorting run as QtConcurrent jobs. Changing the filter abandons a running job at
	its next check and re-runs with the latest predicate, so rapid filter changes stay responsive.
	Appends and sorts requested while a job is running are deferred and applied when the job
	commits, allowing the job to read the rows without locking.

	All methods must be called on the thread the object was created on (the GUI thread for table
	models): the job state machine and row vectors are single-thread-confined, with the worker
	threads communicating back only through the watcher's queued finished signal, and reading only
	the atomic generation counters and the unmutated rows. The filter predicate and comparator are
	called concurrently from worker threads and must be thread-safe.

	\ingroup filter
*/
template <typename Row>
class BackgroundSortFilterRows : public BackgroundSortFilterRowsBase
{
public:
	using Predicate = std::function<bool(const Row&)>;
	using PredicateFactory = std::function<Predicate()>;
	using Comparator = std::function<bool(const Row&, const Row&)>;
	// Display entries are indices into the master rows. 32 bits suffices: a QAbstractItemModel
	// addresses rows with int, so it can never display more than INT_MAX of them.
	using Index = uint32_t;

	explicit BackgroundSortFilterRows(ModelHooks hooks) : BackgroundSortFilterRowsBase(std::move(hooks)) {}

	~BackgroundSortFilterRows() override
	{
		// The workers read the row storage, so they must be stopped before it is destroyed.
		shutdown();
	}

	// Number of rows a view should currently display. Either all rows, or the matches of the
	// committed filter.
	size_t displayCount() const { return m_display.size(); }

	// The row at display position `index`, resolving through the filter/sort index.
	const Row& displayAt(size_t index) const
	{
		BN_ASSERT(index < m_display.size());
		return m_rows[m_display[index]];
	}

	// Count of all rows, ignoring any filter, including rows whose append is deferred.
	size_t totalCount() const { return m_rows.size() + m_pendingRows.size(); }

	// Drop all rows and free their storage, returning to the empty state and abandoning any
	// running job. The filter and sort settings are retained, so rows appended afterward are
	// filtered as before.
	void clear()
	{
		assertOwningThread();
		abandonJob();
		m_hooks.beginResetModel();
		// Assigning fresh vectors releases the capacity rather than retaining it like clear().
		m_rows = std::vector<Row>{};
		m_display = std::vector<Index>{};
		m_pendingRows = std::vector<Row>{};
		m_pendingSort.reset();
		m_maintainSortOnAppend = false;
		m_hooks.endResetModel();
	}

	void append(std::vector<Row> rows) { appendRows(std::move(rows), true); }

	void setFilter(Predicate filter)
	{
		if (filter)
			setFilterFactory([filter] { return filter; });
		else
			setFilterFactory(nullptr);
	}

	// Like `setFilter`, but the factory is invoked once per work chunk on the worker thread to
	// create that chunk's predicate. Use this when the predicate holds state that is expensive
	// to share across threads, e.g. a QRegularExpression, whose internal mutex serializes
	// concurrent matches on a shared instance.
	void setFilterFactory(PredicateFactory factory)
	{
		assertOwningThread();
		m_filterFactory = std::move(factory);
		m_filter = m_filterFactory ? m_filterFactory() : Predicate();
		m_filterGeneration.fetch_add(1);
		// An active job notices the generation change, finishes early, and re-applies on completion.
		if (!busy())
			applyCurrentFilter();
	}

	void sort(Comparator comparator)
	{
		assertOwningThread();
		m_activeSort = comparator;
		// Bump the sort generation so a sort already running notices and bails out promptly rather
		// than sorting rows whose result this newer request will discard.
		m_sortGeneration.fetch_add(1);
		if (busy())
		{
			m_pendingSort = std::move(comparator);
			return;
		}
		startSortJob(std::move(comparator));
	}

protected:
	void commitJob(JobKind kind) override
	{
		if (kind == JobKind::Sort)
			commitSortJob();
		else
			commitFilterJob();
	}

private:
	void appendRows(std::vector<Row> rows, bool resortAfterAppend)
	{
		assertOwningThread();
		if (rows.empty())
			return;

		if (busy())
		{
			m_pendingRows.insert(m_pendingRows.end(), std::make_move_iterator(rows.begin()),
				std::make_move_iterator(rows.end()));
			return;
		}

		// Collect the master indices of the new rows that the filter accepts. An unset filter
		// accepts all of them.
		const Index base = static_cast<Index>(m_rows.size());
		std::vector<Index> newDisplay;
		for (size_t i = 0; i < rows.size(); i++)
			if (!m_filter || m_filter(rows[i]))
				newDisplay.push_back(base + static_cast<Index>(i));

		if (!newDisplay.empty())
		{
			const int oldCount = static_cast<int>(m_display.size());
			m_hooks.beginInsertRows(oldCount, oldCount + static_cast<int>(newDisplay.size()) - 1);
		}

		// Retain every row for later filter changes, even those not currently displayed.
		m_rows.insert(
			m_rows.end(), std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
		m_display.insert(m_display.end(), newDisplay.begin(), newDisplay.end());

		if (!newDisplay.empty())
			m_hooks.endInsertRows();

		if (resortAfterAppend && !newDisplay.empty() && m_maintainSortOnAppend && m_activeSort)
			startSortJob(m_activeSort);
	}

	// Parallel merge sort of `display` (indices into `rows`) by `comparator`. Returns the sorted
	// indices, or nullopt if `filterGeneration` stopped matching `currentFilterGeneration` (the
	// filter changed) or `sortGeneration` stopped matching `currentSortGeneration` (a newer sort was
	// requested) mid-sort, meaning the result should be discarded.
	static std::optional<std::vector<Index>> parallelSort(std::vector<Index> display,
		const std::vector<Row>& rows, const Comparator& comparator, uint64_t filterGeneration,
		const std::atomic<uint64_t>& currentFilterGeneration, uint64_t sortGeneration,
		const std::atomic<uint64_t>& currentSortGeneration)
	{
		if (display.size() < 2)
			return display;

		struct Abandoned{};
		std::atomic<bool> abandoned = false;
		// Wraps the comparator to compare rows by index and bail out promptly if the filter or
		// sort changes mid-job.
		const auto guarded = [&](size_t& comparisons) {
			return [&](Index a, Index b) {
				if ((++comparisons & 0xfff) == 0
					&& (currentFilterGeneration.load(std::memory_order_relaxed) != filterGeneration
						|| currentSortGeneration.load(std::memory_order_relaxed) != sortGeneration))
					throw Abandoned {};
				return comparator(rows[a], rows[b]);
			};
		};

		// Sort chunks of the indices in parallel, then merge adjacent chunks pairwise, with each
		// merge round also running in parallel. A chunk is the half-open range [first, second).
		const size_t threadCount =
			std::clamp<size_t>(QThreadPool::globalInstance()->maxThreadCount(), 1, 64);
		const size_t chunkSize = std::max<size_t>(1, (display.size() + threadCount - 1) / threadCount);
		using Range = std::pair<size_t, size_t>;
		std::vector<Range> chunks;
		chunks.reserve((display.size() + chunkSize - 1) / chunkSize);
		for (size_t begin = 0; begin < display.size(); begin += chunkSize)
			chunks.emplace_back(begin, std::min(begin + chunkSize, display.size()));

		QtConcurrent::blockingMap(chunks, [&](const Range& chunk) {
			size_t comparisons = 0;
			try
			{
				std::sort(display.begin() + chunk.first, display.begin() + chunk.second, guarded(comparisons));
			}
			catch (const Abandoned&)
			{
				abandoned = true;
			}
		});

		while (chunks.size() > 1 && !abandoned)
		{
			// Pair up adjacent chunks. Each pair (i, i + 1) is merged about their shared boundary
			// chunks[i].second. An odd final chunk is already sorted and carries forward unchanged.
			std::vector<size_t> pairs;
			std::vector<Range> mergedChunks;
			pairs.reserve(chunks.size() / 2);
			mergedChunks.reserve((chunks.size() + 1) / 2);
			for (size_t i = 0; i < chunks.size(); i += 2)
			{
				if (i + 1 < chunks.size())
				{
					pairs.push_back(i);
					mergedChunks.emplace_back(chunks[i].first, chunks[i + 1].second);
				}
				else
				{
					mergedChunks.push_back(chunks[i]);
				}
			}
			QtConcurrent::blockingMap(pairs, [&](size_t i) {
				size_t comparisons = 0;
				try
				{
					std::inplace_merge(display.begin() + chunks[i].first, display.begin() + chunks[i].second,
						display.begin() + chunks[i + 1].second, guarded(comparisons));
				}
				catch (const Abandoned&)
				{
					abandoned = true;
				}
			});
			chunks = std::move(mergedChunks);
		}

		if (abandoned)
			return std::nullopt;
		return display;
	}

	void startSortJob(Comparator comparator)
	{
		const uint64_t filterGeneration = m_filterGeneration.load();
		const uint64_t sortGeneration = m_sortGeneration.load();
		m_sortResult = std::make_shared<std::vector<Index>>();
		auto result = m_sortResult;

		// The display indices are not mutated while the job is active (appends and sorts are
		// deferred), so the worker sorts a copy and reads m_rows without locking. An abandoned sort
		// leaves the shared result empty, which commitSortJob never reads.
		auto future = QtConcurrent::run(
			[this, filterGeneration, sortGeneration, comparator, result, display = m_display]() mutable {
				// parallelSort spends almost all of its time blocked in QtConcurrent::blockingMap
				// waiting on the same pool this driver runs on. Release this slot for the duration so
				// the pool can run a replacement worker, otherwise a saturated pool could leave the
				// inner map with no thread to run on. reserveThread reclaims the slot on the way out.
				QThreadPool* pool = QThreadPool::globalInstance();
				pool->releaseThread();
				struct Reclaim
				{
					QThreadPool* pool;
					~Reclaim() { pool->reserveThread(); }
				} reclaim {pool};

				if (auto sorted = parallelSort(std::move(display), m_rows, comparator, filterGeneration,
						m_filterGeneration, sortGeneration, m_sortGeneration))
					*result = std::move(*sorted);
			});
		beginJob(JobKind::Sort, filterGeneration, std::move(future));
	}

	void commitSortJob()
	{
		auto result = std::move(m_sortResult);

		// The filter changed while sorting. Re-apply it and queue the sort to run afterwards.
		if (filterChangedDuringJob())
		{
			if (m_hooks.sortingChanged)
				m_hooks.sortingChanged(false);
			applyCurrentFilter();
			return;
		}

		// A newer sort was requested while this one ran. Skip straight to it.
		if (m_pendingSort)
		{
			auto next = std::move(*m_pendingSort);
			m_pendingSort.reset();
			drainPendingRows();
			startSortJob(std::move(next));
			return;
		}

		// Rows appended while this sort was running were not part of the worker's display snapshot.
		// Add them and rerun the active sort over the full display set.
		if (!m_pendingRows.empty())
		{
			drainPendingRows();
			if (m_activeSort)
				startSortJob(m_activeSort);
			else if (m_hooks.sortingChanged)
				m_hooks.sortingChanged(false);
			return;
		}

		m_hooks.beginResetModel();
		m_display = std::move(*result);
		// Only start maintaining the sort across future appends once a sort has committed over
		// actual rows. This keeps the initial bulk load cheap: the sort indicator is set on the
		// empty model and rows stream in arrival order without re-sorting each batch, until the
		// caller issues the final sort over the complete content.
		m_maintainSortOnAppend = m_activeSort && !m_rows.empty();
		m_hooks.endResetModel();

		if (m_hooks.sortingChanged)
			m_hooks.sortingChanged(false);
	}

	void applyCurrentFilter()
	{
		drainPendingRows();

		if (!m_filter)
		{
			m_hooks.beginResetModel();
			// With no filter the display is every row, in master order.
			m_display.resize(m_rows.size());
			std::iota(m_display.begin(), m_display.end(), Index{0});
			m_hooks.endResetModel();
			if (m_hooks.filteringChanged)
				m_hooks.filteringChanged(false);
			applySortAfterDisplayChange();
			return;
		}

		const uint64_t filterGeneration = m_filterGeneration.load();
		PredicateFactory factory = m_filterFactory;

		constexpr size_t chunkSize = 1024 * 1024;
		std::vector<std::pair<size_t, size_t>> chunks;
		for (size_t begin = 0; begin < m_rows.size(); begin += chunkSize)
			chunks.emplace_back(begin, std::min(begin + chunkSize, m_rows.size()));

		m_filterResult = QtConcurrent::mapped(chunks,
			[this, filterGeneration, factory](const std::pair<size_t, size_t>& chunk) {
				std::vector<Index> matches;
				if (m_filterGeneration.load() != filterGeneration)
					return matches;
				// Materialize the chunk's own predicate so predicate state is never shared across
				// worker threads.
				const Predicate filter = factory();
				for (size_t i = chunk.first; i < chunk.second; i++)
				{
					// Bail out promptly if the filter changes mid-chunk.
					if ((i & 0xfff) == 0 && m_filterGeneration.load() != filterGeneration)
						return matches;
					if (filter(m_rows[i]))
						matches.push_back(static_cast<Index>(i));
				}
				return matches;
			});
		beginJob(JobKind::Filter, filterGeneration, m_filterResult);
	}

	void commitFilterJob()
	{
		auto result = std::move(m_filterResult);

		// The filter changed while the job ran. Run it again with the current predicate.
		if (filterChangedDuringJob())
		{
			applyCurrentFilter();
			return;
		}

		std::vector<Index> matches;
		for (const auto& chunkMatches : result.results())
			matches.insert(matches.end(), chunkMatches.begin(), chunkMatches.end());

		m_hooks.beginResetModel();
		m_display = std::move(matches);
		m_hooks.endResetModel();

		drainPendingRows();
		if (m_hooks.filteringChanged)
			m_hooks.filteringChanged(false);
		applySortAfterDisplayChange();
	}

	void drainPendingRows()
	{
		if (m_pendingRows.empty())
			return;
		auto pending = std::move(m_pendingRows);
		m_pendingRows = {};
		appendRows(std::move(pending), false);
	}

	void applyPendingSort()
	{
		if (!m_pendingSort)
			return;
		auto comparator = std::move(*m_pendingSort);
		m_pendingSort.reset();
		sort(std::move(comparator));
	}

	void applySortAfterDisplayChange()
	{
		if (m_pendingSort)
		{
			applyPendingSort();
			return;
		}
		if (m_activeSort)
			startSortJob(m_activeSort);
	}

	PredicateFactory m_filterFactory;
	// Materialized from m_filterFactory for matching appended rows on the main thread.
	Predicate m_filter;

	// The master copy of every row, append-only and never reordered.
	std::vector<Row> m_rows;
	// Indices into m_rows that are currently displayed, in display order. This is the only thing
	// filtering and sorting rearrange, so neither copies the rows.
	std::vector<Index> m_display;

	// The sort job's output indices, read by its commit handler. Shared with the worker so the
	// future's own result store, which would be a second copy, is avoided.
	std::shared_ptr<std::vector<Index>> m_sortResult;
	// The filter job's future, whose per-chunk results its commit handler concatenates.
	QFuture<std::vector<Index>> m_filterResult;

	Comparator m_activeSort;
	// Bumped on every sort request and watched only by sort workers, so a running sort bails out
	// when a newer comparator arrives. Kept separate from m_filterGeneration so commitSortJob can
	// tell a superseded sort (skip straight to the new comparator) apart from a filter change (which
	// must re-filter first); one shared counter would force a full re-filter on every column re-sort.
	std::atomic<uint64_t> m_sortGeneration = 0;
	std::vector<Row> m_pendingRows;
	std::optional<Comparator> m_pendingSort;
	// Set once a sort commits over a non-empty row set, after which appended rows re-run the sort to
	// keep the display ordered. Left false during the initial bulk load so streamed rows append in
	// arrival order rather than triggering a sort per batch.
	bool m_maintainSortOnAppend = false;
};

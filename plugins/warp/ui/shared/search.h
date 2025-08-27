#pragma once

#include <QAbstractTableModel>
#include <QApplication>
#include <QClipboard>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QObject>
#include <QPainter>
#include <QVector>
#include <QString>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include "uitypes.h"
#include "warp.h"

// Will search in batches of 50 items.
constexpr auto SEARCH_PAGE_SIZE = 50;
// Will debounce the search for 350 MS.
constexpr auto SEARCH_DEBOUNCE_MS = 350;

// Table model showing a paginated list of SearchItem.
class WarpSearchModel final : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Columns : int
    {
        DisplayCol = 0,
        KindCol,
        SourceCol,
        ColumnCount
    };

    explicit WarpSearchModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    int rowCount(const QModelIndex &parent) const override
    {
        if (parent.isValid()) return 0;
        return m_items.size();
    }

    int columnCount(const QModelIndex &parent) const override
    {
        Q_UNUSED(parent);
        return ColumnCount;
    }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    // Begin a new search session: clears all current items and resets counters.
    Q_INVOKABLE void beginNewSearch(std::size_t pageSize = SEARCH_PAGE_SIZE)
    {
        beginResetModel();
        m_items.clear();
        m_total = 0;
        m_pageSize = pageSize;
        endResetModel();
        emit cleared();
        // Immediately ask for the first page from offset 0
        emit fetchMoreRequested(0, m_pageSize);
    }

    // Append results from a Warp::ContainerSearchResponse (infinite scroll, no replacement).
    void appendResponse(const Warp::ContainerSearchResponse &resp)
    {
        // Update total first (so canFetchMore reflects new value)
        m_total = resp.total;
        if (resp.items.empty())
        {
            emit responseUpdated(currentCount(), m_total);
            return;
        }
        const int begin = m_items.size();
        const int end = begin + static_cast<int>(resp.items.size()) - 1;
        beginInsertRows(QModelIndex(), begin, end);
        for (const auto &refItem: resp.items)
            m_items.push_back(refItem);
        endInsertRows();
        emit responseUpdated(currentCount(), m_total);
    }

    // Qt's infinite scroll hooks: the view will call these when near the end.
    bool canFetchMore(const QModelIndex &parent) const override
    {
        Q_UNUSED(parent);
        return static_cast<std::size_t>(m_items.size()) < m_total;
    }

    void fetchMore(const QModelIndex &parent) override
    {
        Q_UNUSED(parent);
        if (!canFetchMore({}))
            return;
        const std::size_t nextOffset = m_items.size();
        emit fetchMoreRequested(nextOffset, m_pageSize);
    }

    // Convenience accessors.
    std::size_t total() const { return m_total; }
    int currentCount() const { return m_items.size(); }
    void setPageSize(std::size_t pageSize) { m_pageSize = pageSize; }

    Q_INVOKABLE Warp::Ref<Warp::ContainerSearchItem> itemAt(int row) const
    {
        if (row < 0 || row >= m_items.size())
            return {};
        return m_items[row];
    }

signals:
    // Emitted when model is cleared for a new query.
    void cleared();

    // Emitted after items are appended or totals updated.
    void responseUpdated(int currentCount, std::size_t total);

    // Request the next page; connect this to your async search runner.
    void fetchMoreRequested(std::size_t offset, std::size_t limit);

private:
    QVector<Warp::Ref<Warp::ContainerSearchItem> > m_items;
    std::size_t m_total = 0;
    std::size_t m_pageSize = SEARCH_PAGE_SIZE;
};

// A delegate to render the DisplayCol text with an icon (mapped from KindCol) on the right.
class WarpSearchDelegate final : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit WarpSearchDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent)
    {
    }

    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        // Base text size + space for an icon on the right
        const QSize base = QStyledItemDelegate::sizeHint(option, index);
        const int iconSide = 16;
        return QSize(base.width(), qMax(base.height(), iconSide + 4)); // keep row height >= icon
    }

    void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

private:
    static QString kindToIcon(const QString &kind)
    {
        // Example mapping; extend as needed
        if (kind.compare(QStringLiteral("Function"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("ƒ");
        if (kind.compare(QStringLiteral("Type"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("𝑇");
        if (kind.compare(QStringLiteral("Source"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("📦");
        // Default: no icon
        return {};
    }
};

class WarpSearchRunner : public QObject
{
    Q_OBJECT

public:
    explicit WarpSearchRunner(Warp::Ref<Warp::Container> container, QObject *parent = nullptr)
        : QObject(parent), m_container(std::move(container))
    {
    }

signals:
    // Emitted on the UI thread after the worker finishes
    void pageReady(std::uint64_t sessionId, Warp::ContainerSearchResponse resp);

    void pageError(std::uint64_t sessionId, QString message);

public slots:
    // Start a new logical search session (new query or new filters)
    void startSession(QString queryText, const std::optional<Warp::Source> &source)
    {
        m_queryText = std::move(queryText);
        m_source = source;
        m_sessionId.fetchAndAddRelaxed(1);
    }

    // Fetch a page for the current session. Safe to call multiple times (infinite scroll).
    void fetchPage(std::size_t offset, std::size_t limit);

private:
    std::uint64_t currentSession() const { return m_sessionId.loadRelaxed(); }

    Warp::Ref<Warp::Container> m_container;
    QAtomicInteger<quint64> m_sessionId{0};
    QString m_queryText;
    std::optional<Warp::Source> m_source;
};

class WarpSearchWidget : public QWidget
{
    Q_OBJECT

public:
    explicit WarpSearchWidget(Warp::Ref<Warp::Container> container, QWidget *parent = nullptr);

    void setSourceFilter(const std::optional<Warp::Source> &src)
    {
        m_source = src;
        m_debounce.start();
    }

private:
    WarpSearchModel *m_model;
    WarpSearchRunner *m_runner;
    QLineEdit *m_query;
    QLabel *m_status;
    QTableView *m_view;
    QTimer m_debounce;
    // Source to filter for if no source is provided in the search.
    std::optional<Warp::Source> m_source;
};

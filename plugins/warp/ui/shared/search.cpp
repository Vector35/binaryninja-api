#include "search.h"
#include "misc.h"
#include "../../../../../ui/mainwindow.h"

QVariant WarpSearchModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_items.size())
        return {};
    const auto &it = m_items[index.row()];

    // Provide tokenized type for functions via UserRole for TokenDataDelegate
    if (role == Qt::UserRole && index.column() == DisplayCol)
    {
        if (it && it->GetKind() == WARPContainerSearchItemKindFunction)
            if (auto itemType = it->GetType(nullptr))
                return QVariant::fromValue(TokenData(*itemType, it->GetName()));
        return {};
    }


    if (role == Qt::DisplayRole)
    {
        // TODO: We might want to run the demangler here on the name.
        switch (index.column())
        {
            case DisplayCol: return QString::fromStdString(it->GetName());
            case KindCol:
            {
                switch (it->GetKind())
                {
                    case WARPContainerSearchItemKindFunction: return "Function";
                    case WARPContainerSearchItemKindType: return "Type";
                    case WARPContainerSearchItemKindSource: return "Source";
                    case WARPContainerSearchItemKindSymbol: return "Symbol";
                    default: return {};
                }
            }
            case SourceCol: return QString::fromStdString(it->GetSource().ToString());
            default: return {};
        }
    }
    return {};
}

QVariant WarpSearchModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
    {
        switch (section)
        {
            case DisplayCol: return "Item";
            case KindCol: return "Kind";
            case SourceCol: return "Source";
            default: return {};
        }
    }
    return {};
}

void WarpSearchDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    // TODO: We actually still want the function icon, I think? So this should not early return and instead replace the name.
    // If model provided TokenData (e.g., for function types), render via TokenDataDelegate
    if (index.data(Qt::UserRole).canConvert<TokenData>())
    {
        TokenDataDelegate(parent()).paint(p, option, index);
        return;
    }


    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);

    // We will draw the background/selection via style, and custom-draw icon (left) + text.
    const QWidget *w = option.widget;
    QStyle *style = w ? w->style() : QApplication::style();

    // Let style draw the item background/selection etc., but not the default text
    QString originalText = opt.text;
    opt.text.clear();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, p, w);

    // Retrieve text for DisplayCol
    const QString &text = originalText;

    // Retrieve kind text from the hidden KindCol
    const QModelIndex kindIndex = index.sibling(index.row(), WarpSearchModel::KindCol);
    const QString kind = kindIndex.isValid() ? kindIndex.data(Qt::DisplayRole).toString() : QString();

    // Map kind -> icon (emoji for simplicity; replace with QIcon/QPixmap if desired)
    const QString icon = kindToIcon(kind);

    // Layout rects
    const QRect r = opt.rect;
    const int marginH = 8;
    const int iconSide = 16;
    const int spacing = 8;

    // Reserve space on the left for the icon if we have one
    QRect iconRect = QRect(r.left() + marginH, r.center().y() - iconSide / 2, iconSide, iconSide);
    QRect textRect = r.adjusted((icon.isEmpty() ? marginH : (marginH + iconSide + spacing)), 0, -marginH, 0);

    // Draw icon first (without clipping), then text with clipping
    p->save();
    if (!icon.isEmpty())
    {
        QFont iconFont = opt.font;
        iconFont.setPointSizeF(iconFont.pointSizeF() + 2);
        p->setFont(iconFont);
        p->setPen(
            opt.palette.color(opt.state & QStyle::State_Selected ? QPalette::HighlightedText : QPalette::Text));
        p->drawText(iconRect, Qt::AlignCenter, icon);
    }
    p->restore();

    // Draw elided text, vertically centered (with clipping so long strings don't overflow)
    p->save();
    p->setClipRect(textRect);
    const QFontMetrics fm(opt.font);
    const QString elided = fm.elidedText(text, Qt::ElideRight, textRect.width());
    p->setPen(opt.palette.color(opt.state & QStyle::State_Selected ? QPalette::HighlightedText : QPalette::Text));
    p->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft, elided);
    p->restore();
}

void WarpSearchRunner::fetchPage(std::size_t offset, std::size_t limit)
{
    const auto session = currentSession();
    auto container = m_container;
    auto q = m_queryText;
    auto src = m_source;

    // Runs search on Qt threadpool then moves the result to the main thread to update the UI.
    using TaskResult = std::pair<std::optional<Warp::ContainerSearchResponse>, QString>;
    QFutureWatcher<TaskResult> *watcher = new QFutureWatcher<TaskResult>(this);
    const auto future = QtConcurrent::run([container, q, src, offset, limit]() -> TaskResult {
        const Warp::ContainerSearchQuery query(q.toStdString(), offset, limit, src);
        auto respOpt = container->Search(query);
        // TODO: We may want to provide better errors in the future, e.g. BNWARPGetError
        if (!respOpt.has_value())
            return {std::nullopt, QStringLiteral("No response from container")};
        return {std::move(respOpt), QString()};
    });
    connect(watcher, &QFutureWatcher<TaskResult>::finished, this, [this, watcher, session]() {
        const TaskResult result = watcher->result();
        watcher->deleteLater();
        if (const auto &err = result.second; !err.isEmpty())
            emit pageError(session, err);
        else if (const auto &resp = result.first; resp.has_value())
            emit pageReady(session, *resp);
    });
    watcher->setFuture(future);
}

WarpSearchWidget::WarpSearchWidget(Warp::Ref<Warp::Container> container, QWidget *parent) : QWidget(parent)
{
    m_model = new WarpSearchModel(this);
    m_runner = new WarpSearchRunner(container, this);
    auto *layout = new QVBoxLayout(this);
    m_query = new QLineEdit(this);
    m_status = new QLabel(this);
    m_view = new QTableView(this);

    // TODO: I am not necessarily a fan with how this looks.
    m_query->setPlaceholderText("Search… (Optionally filter with source:<uuid>)");

    // This is where we make the table not look like a table but instead a list.
    m_view->setShowGrid(false);
    m_view->verticalHeader()->setVisible(false);
    m_view->horizontalHeader()->setVisible(false);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::SingleSelection);
    m_view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_view->setFocusPolicy(Qt::NoFocus);

    layout->addWidget(m_query);
    layout->addWidget(m_status);
    layout->addWidget(m_view);

    m_view->setModel(m_model);

    // Use a delegate to draw the DisplayCol text with an icon (optionally) aligned to the left.
    m_view->setItemDelegateForColumn(WarpSearchModel::DisplayCol, new WarpSearchDelegate(m_view));

    // Hide extra columns: only show the combined "Item" column; do not display source GUID.
    m_view->setColumnHidden(WarpSearchModel::KindCol, true);
    m_view->setColumnHidden(WarpSearchModel::SourceCol, true);
    m_view->horizontalHeader()->setSectionResizeMode(WarpSearchModel::DisplayCol, QHeaderView::Stretch);

    // Debounce user input
    m_debounce.setSingleShot(true);
    m_debounce.setInterval(SEARCH_DEBOUNCE_MS);
    connect(m_query, &QLineEdit::textChanged, this, [this](const QString &) { m_debounce.start(); });

    connect(&m_debounce, &QTimer::timeout, this, [this]() {
        const QString raw = m_query->text();

        // Parse generic qualifiers and clean the free-text query
        const auto parsed = ParsedQuery(raw);

        std::optional<Warp::Source> inlineSource = std::nullopt;
        if (const auto val = parsed.GetValue("source"); val.has_value())
            inlineSource = Warp::Source::FromString(val.value().toStdString());
        const auto effectiveSource = inlineSource.has_value() ? inlineSource : m_source;
        // TODO: Filter for tags and function guid.

        m_runner->startSession(parsed.query, effectiveSource);
        m_model->beginNewSearch(SEARCH_PAGE_SIZE);
    });


    // Infinite scroll trigger
    connect(m_model, &WarpSearchModel::fetchMoreRequested, this, [this](std::size_t offset, std::size_t limit) {
        m_status->setText(QStringLiteral("Loading… (%1/%2)").arg(m_model->currentCount()).arg(m_model->total()));
        m_runner->fetchPage(offset, limit);
    });

    // Append results if session still valid
    connect(m_runner, &WarpSearchRunner::pageReady, this,
            [this](std::uint64_t, const Warp::ContainerSearchResponse &resp) {
                m_model->appendResponse(resp);
                m_status->setText(
                    QStringLiteral("Showing %1 of %2").arg(m_model->currentCount()).arg(m_model->total()));
            });

    // In cases like if the network container server goes down.
    connect(m_runner, &WarpSearchRunner::pageError, this,
            [this](std::uint64_t, const QString &msg) {
                m_status->setText(QStringLiteral("Error: %1").arg(msg));
            });

    // Add a context menu so that we can actually do actionable things with what we find.
    m_view->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_view, &QTableView::customContextMenuRequested, this, [this](const QPoint &pos) {
        const QModelIndex idx = m_view->indexAt(pos);
        if (!idx.isValid())
            return;

        // TODO: Getting the current view here is really awful, but i dont care right now.
        auto ctx = MainWindow::activeContext();
        auto view = ctx->getCurrentView();
        auto binaryView = view->getData();
        auto viewFrame = ctx->getCurrentViewFrame();
        auto viewLocation = viewFrame->getViewLocation();
        auto func = viewLocation.getFunction();

        // Retrieve the current architecture from the current function or try the current view.
        auto arch = binaryView->GetDefaultArchitecture();
        if (func)
            arch = func->GetArchitecture();

        const int row = idx.row();
        const auto item = m_model->itemAt(row);
        const auto itemType = item->GetType(arch);
        const auto itemFunc = item->GetFunction();

        QMenu menu(this);
        QAction *copySourceId = menu.addAction(tr("Copy Source"));
        QAction *searchSource = menu.addAction(tr("Search Source"));
        QAction *applyType = menu.addAction(tr("Apply Type"));
        QAction *applyFunction = menu.addAction(tr("Apply to Current Function"));

        // We let users apply the type for types and functions (assuming the function has one)
        // if the user applies a function, we actually will set the user type for the current view location function.
        // For types, we will just throw it in the user types.
        applyType->setEnabled(itemType != nullptr);
        applyType->setVisible(applyType->isEnabled());

        applyFunction->setEnabled(func != nullptr && itemFunc);
        applyFunction->setVisible(applyFunction->isEnabled());

        QAction *chosen = menu.exec(m_view->viewport()->mapToGlobal(pos));
        if (!chosen)
            return;
        if (chosen == copySourceId)
            QApplication::clipboard()->setText(QString::fromStdString(item->GetSource().ToString()));
        else if (chosen == searchSource)
        {
            const QString sourceId = QString::fromStdString(item->GetSource().ToString());
            // TODO: This does not preserve the query that existed prior, doing so may result in duplicate source qualifiers.
            m_query->setText(QStringLiteral("source:\"%1\"").arg(sourceId));
        } else if (chosen == applyType)
        {
            if (func && item->GetKind() == WARPContainerSearchItemKindFunction)
            {
                func->SetUserType(itemType);
                binaryView->UpdateAnalysis();
            }
            else
                binaryView->DefineUserType(item->GetName(), itemType);
        } else if (chosen == applyFunction)
        {
            itemFunc->Apply(*func);
            binaryView->UpdateAnalysis();
        }
    });

    // This will start searching with an empty query once the widget is constructed. This is a decent behavior considering
    // we should be heavily caching queries such as an empty one.
    m_debounce.start();
}

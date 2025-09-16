#include "containers.h"

QVariant WarpSourcesModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return {};
    if (index.row() < 0 || index.row() >= rowCount())
        return {};

    const auto &r = m_rows[static_cast<size_t>(index.row())];

    // Build a small two-dot status icon (left: writable, right: uncommitted)
    auto statusIcon = [](bool writable, bool uncommitted) -> QIcon {
        static QIcon cache[2][2]; // [writable][uncommitted]
        QIcon &cached = cache[writable ? 1 : 0][uncommitted ? 1 : 0];
        if (!cached.isNull())
            return cached;

        const int w = 16, h = 12, radius = 4;
        QPixmap pm(w, h);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);

        // Colors
        QColor writableOn(76, 175, 80); // green
        QColor writableOff(158, 158, 158); // grey
        QColor uncommittedOn(255, 193, 7); // amber
        QColor uncommittedOff(158, 158, 158); // grey

        // Left dot: writable
        p.setBrush(writable ? writableOn : writableOff);
        p.setPen(Qt::NoPen);
        p.drawEllipse(QPoint(4, h / 2), radius, radius);

        // Right dot: uncommitted
        p.setBrush(uncommitted ? uncommittedOn : uncommittedOff);
        p.drawEllipse(QPoint(w - 6, h / 2), radius, radius);

        p.end();
        cached = QIcon(pm);
        return cached;
    };

    if (role == Qt::DecorationRole && index.column() == PathCol)
    {
        return statusIcon(r.writable, r.uncommitted);
    }

    if (role == Qt::ToolTipRole && index.column() == PathCol)
    {
        QStringList parts;
        parts << (r.writable ? "Writable" : "Read-only");
        parts << (r.uncommitted ? "Uncommitted changes" : "No uncommitted changes");
        return parts.join(" • ");
    }

    if (role == Qt::DisplayRole)
    {
        switch (index.column())
        {
            case GuidCol: return r.guid;
            case PathCol: return r.path;
            case WritableCol: return r.writable ? "Yes" : "No";
            case UncommittedCol: return r.uncommitted ? "Yes" : "No";
            default: return {};
        }
    }

    if (role == Qt::CheckStateRole)
    {
        // Optional: expose as checkboxes if someone ever shows these columns
        switch (index.column())
        {
            case WritableCol: return r.writable ? Qt::Checked : Qt::Unchecked;
            case UncommittedCol: return r.uncommitted ? Qt::Checked : Qt::Unchecked;
            default: break;
        }
    }

    return {};
}

WarpContainerWidget::WarpContainerWidget(Warp::Ref<Warp::Container> container, QWidget *parent) : QWidget(parent)
{
    m_container = std::move(container);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    m_tabs = new QTabWidget(this);
    layout->addWidget(m_tabs);

    // Sources tab
    m_sourcesPage = new QWidget(this);
    auto *sourcesLayout = new QVBoxLayout(m_sourcesPage);
    m_sourcesView = new QTableView(m_sourcesPage);
    m_sourcesModel = new WarpSourcesModel(m_sourcesPage);
    m_sourcesModel->setContainer(m_container);
    m_sourcesView->setModel(m_sourcesModel);
    m_sourcesView->horizontalHeader()->setStretchLastSection(true);
    m_sourcesView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_sourcesView->setSelectionMode(QAbstractItemView::SingleSelection);

    // Make the table look like a simple list that shows only the source path
    m_sourcesView->setShowGrid(false);
    m_sourcesView->verticalHeader()->setVisible(false);
    m_sourcesView->horizontalHeader()->setVisible(false);
    m_sourcesView->setAlternatingRowColors(false);
    m_sourcesView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_sourcesView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_sourcesView->setWordWrap(false);
    m_sourcesView->setIconSize(QSize(16, 12));
    // Ensure long paths truncate from the left: "...tail/of/the/path"
    m_sourcesView->setTextElideMode(Qt::ElideLeft);
    // Hide GUID column, keep only the Path column visible
    m_sourcesView->setColumnHidden(WarpSourcesModel::GuidCol, true);
    // Also hide boolean columns; their state is shown as an icon next to the path
    m_sourcesView->setColumnHidden(WarpSourcesModel::WritableCol, true);
    m_sourcesView->setColumnHidden(WarpSourcesModel::UncommittedCol, true);
    // Ensure the remaining (Path) column fills the width
    m_sourcesView->horizontalHeader()->setSectionResizeMode(WarpSourcesModel::PathCol, QHeaderView::Stretch);

    // Per-item context menu
    m_sourcesView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_sourcesView, &QWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QMenu menu(m_sourcesView);
        const QModelIndex index = m_sourcesView->indexAt(pos);

        if (!index.isValid())
        {
            QAction *actAdd = menu.addAction(tr("Add Source"));
            QAction *chosen = menu.exec(m_sourcesView->viewport()->mapToGlobal(pos));
            if (!chosen)
                return;
            if (chosen == actAdd)
            {
                std::string sourceName;
                if (!BinaryNinja::GetTextLineInput(sourceName, "Source name:", "Add Source"))
                    return;
                if (const auto sourceId = m_container->AddSource(sourceName); !sourceId.has_value())
                {
                    BinaryNinja::LogAlertF("Failed to add source: {}", sourceName);
                    return;
                }
                m_sourcesModel->reload();
            }
        } else
        {
            m_sourcesView->setCurrentIndex(index.sibling(index.row(), WarpSourcesModel::PathCol));

            const int row = index.row();
            const QModelIndex pathIdx = m_sourcesModel->index(row, WarpSourcesModel::PathCol);
            const QModelIndex guidIdx = m_sourcesModel->index(row, WarpSourcesModel::GuidCol);
            const QString path = m_sourcesModel->data(pathIdx, Qt::DisplayRole).toString();
            const QFileInfo fi(path);
            
            const QString guid = m_sourcesModel->data(guidIdx, Qt::DisplayRole).toString();

            QAction *actReveal = menu.addAction(tr("Reveal in File Browser"));
            actReveal->setEnabled(fi.exists());
            QAction *actCopyPath = menu.addAction(tr("Copy Path"));
            QAction *actCopyGuid = menu.addAction(tr("Copy GUID"));
            
            QAction *chosen = menu.exec(m_sourcesView->viewport()->mapToGlobal(pos));
            if (!chosen)
                return;
            if (chosen == actCopyPath)
                QGuiApplication::clipboard()->setText(path);
            else if (chosen == actCopyGuid)
                QGuiApplication::clipboard()->setText(guid);
            else if (chosen == actReveal)
                QDesktopServices::openUrl(QUrl::fromLocalFile(fi.absoluteFilePath()));
        }
    });


    sourcesLayout->addWidget(m_sourcesView);
    m_tabs->addTab(m_sourcesPage, tr("Sources"));

    // Search tab
    m_searchTab = new WarpSearchWidget(m_container, this);
    m_tabs->addTab(m_searchTab, tr("Search"));

    // Periodic refresh timer for the Sources view
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(5000);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        // Only refresh if the widget and the Sources page are actually visible
        if (!this->isVisible() || !m_sourcesPage || !m_sourcesPage->isVisible())
            return;

        // Preserve selection by GUID across reloads
        QString currentGuid;
        if (const QModelIndex currentIdx = m_sourcesView->currentIndex(); currentIdx.isValid())
        {
            const int row = currentIdx.row();
            const QModelIndex guidIdx = m_sourcesModel->index(row, WarpSourcesModel::GuidCol);
            currentGuid = m_sourcesModel->data(guidIdx, Qt::DisplayRole).toString();
        }

        m_sourcesModel->reload();

        if (!currentGuid.isEmpty())
        {
            for (int r = 0; r < m_sourcesModel->rowCount(); ++r)
            {
                const QModelIndex gIdx = m_sourcesModel->index(r, WarpSourcesModel::GuidCol);
                if (m_sourcesModel->data(gIdx, Qt::DisplayRole).toString() == currentGuid)
                {
                    m_sourcesView->setCurrentIndex(m_sourcesModel->index(r, WarpSourcesModel::PathCol));
                    break;
                }
            }
        }
    });
    m_refreshTimer->start();

    // Optional: force a refresh when switching back to the Sources tab
    connect(m_tabs, &QTabWidget::currentChanged, this, [this](const int idx) {
        QWidget *w = m_tabs->widget(idx);
        if (w == m_sourcesPage)
            m_sourcesModel->reload();
    });
}

WarpContainersPane::WarpContainersPane(QWidget *parent) : QWidget(parent)
{
    auto *splitter = new QSplitter(Qt::Vertical, this);
    splitter->setContentsMargins(0, 0, 0, 0);
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);
    mainLayout->addWidget(splitter);
    auto newPalette = palette();
    newPalette.setColor(QPalette::Window, getThemeColor(SidebarWidgetBackgroundColor));
    setAutoFillBackground(true);
    setPalette(newPalette);

    // List on top
    m_list = new QListWidget(splitter);
    m_list->setSelectionMode(QAbstractItemView::SingleSelection);
    m_list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_list->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
    m_list->setUniformItemSizes(true);

    // Make names larger and show end of long strings (elide at the start)
    {
        QFont f = m_list->font();
        f.setPointSizeF(f.pointSizeF() + 2.0); // bump size
        m_list->setFont(f);
        m_list->setTextElideMode(Qt::ElideLeft);
    }

    // Container view (tabs) below
    m_stack = new QStackedWidget(splitter);
    m_stack->setContentsMargins(0, 0, 0, 0);

    splitter->setStretchFactor(0, 0); // list: minimal growth
    splitter->setStretchFactor(1, 1); // stack: takes remaining space
    splitter->setCollapsible(0, false);
    splitter->setCollapsible(1, false);

    populate();

    connect(m_list, &QListWidget::currentRowChanged, this, [this](int row) {
        if (row >= 0 && row < m_stack->count())
            m_stack->setCurrentIndex(row);
    });

    // Select the first container if available
    if (m_list->count() > 0)
    {
        m_list->setCurrentRow(0);
    }
}

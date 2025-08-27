#pragma once

#include <QWidget>
#include <optional>
#include <QClipboard>
#include <QDesktopServices>
#include <QInputDialog>
#include <QListWidget>
#include "shared/search.h"

#include "theme.h"
#include "warp.h"
#include "../../../../ui/mainwindow.h"

class WarpSourcesModel final : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Columns : int
    {
        GuidCol = 0,
        PathCol,
        ColumnCount
    };

    explicit WarpSourcesModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    void setContainer(Warp::Ref<Warp::Container> container)
    {
        beginResetModel();
        m_container = std::move(container);
        m_rows.clear();
        endResetModel();
        reload();
    }

    void reload()
    {
        // Fetch synchronously (can be adapted to async if needed)
        beginResetModel();
        m_rows.clear();
        for (const auto &src: m_container->GetSources())
        {
            QString guid = QString::fromStdString(src.ToString());
            QString path = QString::fromStdString(m_container->SourcePath(src).value_or(std::string{}));
            m_rows.push_back({guid, path});
        }
        endResetModel();
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        if (parent.isValid()) return 0;
        return static_cast<int>(m_rows.size());
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent);
        return ColumnCount;
    }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override
    {
        if (!index.isValid() || role != Qt::DisplayRole)
            return {};
        if (index.row() < 0 || index.row() >= rowCount())
            return {};
        const auto &r = m_rows[static_cast<size_t>(index.row())];
        switch (index.column())
        {
            case GuidCol: return r.guid;
            case PathCol: return r.path;
            default: return {};
        }
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            switch (section)
            {
                case GuidCol: return "Source GUID";
                case PathCol: return "Path";
                default: return {};
            }
        }
        return {};
    }

private:
    struct Row
    {
        QString guid;
        QString path;
    };

    std::vector<Row> m_rows;
    Warp::Ref<Warp::Container> m_container;
};

class WarpContainerWidget : public QWidget
{
    Q_OBJECT

public:
    explicit WarpContainerWidget(Warp::Ref<Warp::Container> container, QWidget *parent = nullptr)
        : QWidget(parent), m_container(std::move(container))
    {
        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        m_tabs = new QTabWidget(this);
        layout->addWidget(m_tabs);

        // Sources tab
        auto *sourcesPage = new QWidget(this);
        auto *sourcesLayout = new QVBoxLayout(sourcesPage);
        m_sourcesView = new QTableView(sourcesPage);
        m_sourcesModel = new WarpSourcesModel(sourcesPage);
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
        // Ensure long paths truncate from the left: "...tail/of/the/path"
        m_sourcesView->setTextElideMode(Qt::ElideLeft);
        // Hide GUID column, keep only the Path column visible
        m_sourcesView->setColumnHidden(WarpSourcesModel::GuidCol, true);
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
            }
            else
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
        m_tabs->addTab(sourcesPage, tr("Sources"));

        // Search tab
        m_searchTab = new WarpSearchWidget(m_container, this);
        m_tabs->addTab(m_searchTab, tr("Search"));
    }

private:
    Warp::Ref<Warp::Container> m_container;

    QTabWidget *m_tabs = nullptr;

    // Sources
    QTableView *m_sourcesView = nullptr;
    WarpSourcesModel *m_sourcesModel = nullptr;

    // Search
    WarpSearchWidget *m_searchTab = nullptr;
};

class WarpContainersPane : public QWidget
{
    Q_OBJECT

public:
    explicit WarpContainersPane(QWidget *parent = nullptr)
        : QWidget(parent)
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

    void refresh()
    {
        // Clear and repopulate from current container list
        m_list->clear();
        while (m_stack->count() > 0)
        {
            QWidget *w = m_stack->widget(0);
            m_stack->removeWidget(w);
            delete w;
        }
        m_containers.clear();
        populate();
        if (m_list->count() > 0)
            m_list->setCurrentRow(0);
    }

private:
    void populate()
    {
        // Retrieve all available containers
        const auto all = Warp::Container::All();
        m_containers = all; // copy vector<Ref<Container>>

        for (const auto &c: m_containers)
        {
            const QString name = QString::fromStdString(c->GetName());
            auto *item = new QListWidgetItem(name, m_list);
            item->setSizeHint(QSize(item->sizeHint().width(), itemHeightPx()));
            auto *widget = new WarpContainerWidget(c, m_stack);
            m_stack->addWidget(widget);
        }

        // Visual style: behave like a vertical tab bar
        // m_list->setFrameShape(QFrame::NoFrame);
        // m_list->setSpacing(0);
    }

    static int itemHeightPx()
    {
        // A reasonable, readable height per entry
        return 28;
    }

private:
    QListWidget *m_list = nullptr;
    QStackedWidget *m_stack = nullptr;
    std::vector<Warp::Ref<Warp::Container> > m_containers;
};

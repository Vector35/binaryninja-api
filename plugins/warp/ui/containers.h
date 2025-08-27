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
        WritableCol,
        UncommittedCol,
        ColumnCount
    };

    explicit WarpSourcesModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    void setContainer(Warp::Ref<Warp::Container> container)
    {
        m_container = std::move(container);
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
            bool writable = m_container->IsSourceWritable(src);
            bool uncommitted = m_container->IsSourceUncommitted(src);
            m_rows.push_back({guid, path, writable, uncommitted});
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

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            switch (section)
            {
                case GuidCol: return "Source GUID";
                case PathCol: return "Path";
                case WritableCol: return "Writable";
                case UncommittedCol: return "Uncommitted";
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
        bool writable;
        bool uncommitted;
    };

    std::vector<Row> m_rows;
    Warp::Ref<Warp::Container> m_container;
};

class WarpContainerWidget : public QWidget
{
    Q_OBJECT

public:
    explicit WarpContainerWidget(Warp::Ref<Warp::Container> container, QWidget *parent = nullptr);

private:
    Warp::Ref<Warp::Container> m_container;

    QTabWidget *m_tabs = nullptr;

    // Sources
    QTableView *m_sourcesView = nullptr;
    WarpSourcesModel *m_sourcesModel = nullptr;
    QWidget* m_sourcesPage = nullptr;
    QTimer* m_refreshTimer = nullptr;

    // Search
    WarpSearchWidget *m_searchTab = nullptr;
};

class WarpContainersPane : public QWidget
{
    Q_OBJECT

public:
    explicit WarpContainersPane(QWidget *parent = nullptr);

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

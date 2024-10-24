//
// by kat // 9/15/22.
//

#ifndef SHAREDCACHE_DSCSIDEBARWIDGET_H
#define SHAREDCACHE_DSCSIDEBARWIDGET_H

#include <QtCore/QAbstractItemModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtWidgets/QTreeView>

#include "ui/filter.h"
#include "ui/sidebar.h"
#include "ui/uitypes.h"
#include <binaryninjaapi.h>
#include <sharedcacheapi.h>

#include <mutex>


class DSCContentsModel;

class DSCFilterModel;

class DSCSidebarView;

enum ModelItemType {
    FolderModelItem,
    ImageModelItem
};

class DSCContentsModelItem {
    friend class ComponentModel;

    friend class ComponentFilterModel;

    friend class DSCSidebarView;

    ModelItemType m_type;

    DSCContentsModelItem *m_parent;
    std::vector<DSCContentsModelItem *> m_children;

    BinaryViewRef m_bv;

    std::string m_name;
    std::string m_installName; // only set on images, not dirs

    bool m_hasDataVar = false;
    BinaryNinja::DataVariable m_dataVar;

public:
    explicit DSCContentsModelItem(DSCContentsModelItem *parent = nullptr);

    explicit DSCContentsModelItem(BinaryViewRef, std::string, std::string, DSCContentsModelItem *parent = nullptr);

    /// Get the "name" that should be displayed for an item.
    QString displayName() const;

    size_t childCount() const;

    DSCContentsModelItem *child(size_t);

    void addChild(DSCContentsModelItem *);

    DSCContentsModelItem *parent() const;

    size_t row() const;

    QVariant data(int column) const;

    QImage icon() const;
};

class DSCContentsModel : public QAbstractItemModel {
Q_OBJECT

    BinaryViewRef m_bv;
    SharedCacheAPI::SCRef<SharedCacheAPI::SharedCache> m_cache;
    DSCContentsModelItem *m_root;

    std::unordered_map<std::string, DSCContentsModelItem *> m_dscItems;

    std::mutex m_updateMutex;

    void refresh();

public:
    enum Column : int {
        NameColumn = 0,
        AddressColumn,
        KindColumn,
    };

    DSCContentsModel(BinaryViewRef, QObject *parent = nullptr);

    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;

    QModelIndex parent(const QModelIndex &) const override;

    QVariant headerData(int, Qt::Orientation, int role = Qt::DisplayRole) const override;

    QVariant data(const QModelIndex &, int role = Qt::DisplayRole) const override;

    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

    Qt::ItemFlags flags(const QModelIndex &) const override;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    Qt::DropActions supportedDropActions() const override;

};

/// Filtering model to wrap a `ComponentModel`.
class DSCFilterModel : public QSortFilterProxyModel {
Q_OBJECT

    DSCContentsModel *m_model;

public:
    DSCFilterModel(BinaryViewRef, QObject *parent = nullptr);

    [[nodiscard]] bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
};

class DSCSidebarView : public QTreeView {
    BinaryViewRef m_data;
    ViewFrame *m_frame;
    QWidget *m_parent;

    void navigateToIndex(const QModelIndex &);

    QMenu *createContextMenu();

public:
    DSCSidebarView(ViewFrame *, BinaryViewRef, QWidget *parent = nullptr);
};

class DSCSidebarWidget : public SidebarWidget, public FilterTarget {
Q_OBJECT

    friend DSCSidebarView;

    BinaryViewRef m_data;
    ViewFrame *m_frame;
    QWidget *m_header;

    DSCSidebarView *m_tree;

    QSortFilterProxyModel *m_model;

    FilterEdit *m_filterEdit;
    FilteredView *m_filterView;

public:
    DSCSidebarWidget(ViewFrame *, BinaryViewRef);

    QWidget *headerWidget() override;

    void focus() override;

    void setFilter(const std::string &) override;

    void scrollToFirstItem() override;

    void scrollToCurrentItem() override;

    void selectFirstItem() override;

    void activateFirstItem() override;
};

class DSCSidebarWidgetType : public SidebarWidgetType {
public:
    DSCSidebarWidgetType();

    bool ValidForView(BinaryNinja::BinaryView* view)
    {
        if (!view)
            return false;
        return (view->GetTypeName() == VIEW_NAME);
    }

    SidebarWidget *createWidget(ViewFrame *, BinaryViewRef) override;
};

#endif //SHAREDCACHE_DSCSIDEBARWIDGET_H

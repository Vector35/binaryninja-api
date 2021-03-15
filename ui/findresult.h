#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QModelIndex>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QDialog>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "filter.h"
#include "expandablegroup.h"

#define FIND_RESULT_LIST_UPDATE_INTERVAL 250

class FindResultItem
{
private:
    uint64_t m_addr;
    BinaryNinja::DataBuffer m_buffer;
    FunctionRef m_func;

public:
    FindResultItem() {}
    FindResultItem(uint64_t addr, const BinaryNinja::DataBuffer& buffer, FunctionRef func);
    FindResultItem(const FindResultItem& other):
        m_addr(other.addr()), m_buffer(other.buffer()), m_func(other.func())
    {}
    uint64_t addr() const { return m_addr; }
    BinaryNinja::DataBuffer buffer() const { return m_buffer; }
    FunctionRef func() const { return m_func; }
};

Q_DECLARE_METATYPE(FindResultItem);

class BINARYNINJAUIAPI FindResultModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    BinaryNinja::FindParameters m_params;
    std::vector<FindResultItem> m_refs;

    std::mutex m_updateMutex;
    std::vector<FindResultItem> m_pendingFindResults;

public:
    enum ColumnHeaders
    {
        AddressColumn = 0,
        DataColumn = 1,
        FunctionColumn = 2,
        PreviewColumn = 3
    };

    FindResultModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~FindResultModel();

    void reset();
    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return (int)m_refs.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 4; }
    FindResultItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void addItem(const FindResultItem& addr);
    void clear();
    void updateFindParameters(const BinaryNinja::FindParameters params);
    void updateFindResults();
};


class BINARYNINJAUIAPI FindResultFilterProxyModel: public QSortFilterProxyModel
{
    Q_OBJECT

public:
    FindResultFilterProxyModel(QObject* parent);
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;
    virtual bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;
    virtual QVariant data(const QModelIndex& idx, int role) const override;
};


class BINARYNINJAUIAPI FindResultItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    FindResultItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;

};

class FindResultWidget;
class BINARYNINJAUIAPI FindResultTable: public QTableView
{
    Q_OBJECT

    ViewFrame* m_view;
    FindResultModel* m_table;
    FindResultFilterProxyModel* m_model;
    FindResultItemDelegate* m_itemDelegate;
    BinaryViewRef m_data;
    BinaryNinja::FindParameters m_params;
    QTimer* m_updateTimer;

public:
    FindResultTable(FindResultWidget* parent, ViewFrame* view, BinaryViewRef data);
    virtual ~FindResultTable();

    void addFindResult(const FindResultItem& addr);
    void updateFindParameters(const BinaryNinja::FindParameters& params);
    void clearFindResult();

    void updateFontAndHeaderSize();

    virtual void keyPressEvent(QKeyEvent* e) override;

    virtual bool hasSelection() const { return selectionModel()->selectedRows().size() != 0; }
	virtual QModelIndexList selectedRows() const { return selectionModel()->selectedRows(); }

    void goToResult(const QModelIndex& idx);

public Q_SLOTS:
    void resultActivated(const QModelIndex& idx);
    void updateFilter(const QString& filterText);
    void updateTimerEvent();
};


class BINARYNINJAUIAPI FindResultWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;
    FindResultTable* m_table;
    QLabel* m_label;
    QLineEdit* m_lineEdit;
    ExpandableGroup* m_group;
    BinaryNinja::FindParameters m_params;

public:
    FindResultWidget(ViewFrame* frame, BinaryViewRef data);
    ~FindResultWidget();

    virtual void notifyFontChanged() override;
    // virtual bool shouldBeVisiable(ViewFrame* frame) override;

    void startNewFind(const BinaryNinja::FindParameters& params);
    virtual QString getHeaderText();

    void addFindResult(uint64_t addr, const BinaryNinja::DataBuffer& match);
    void clearFindResult();

};

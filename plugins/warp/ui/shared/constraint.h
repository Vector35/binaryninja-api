#pragma once
#include <qstandarditemmodel.h>
#include <QTableView>
#include <QWidget>

#include "filter.h"
#include "misc.h"
#include "warp.h"

class WarpConstraintItem : public QStandardItem
{
    Warp::Ref<Warp::Constraint> m_constraint;

public:
    WarpConstraintItem(Warp::Ref<Warp::Constraint> constraint);

    Warp::Ref<Warp::Constraint> GetConstraint() { return m_constraint; }
};

class WarpConstraintItemModel : public QStandardItemModel
{
    Q_OBJECT

    // The current analysis constraints used to highlight matching constraints.
    std::vector<Warp::Ref<Warp::Constraint>> m_matchedConstraints;
public:
    WarpConstraintItemModel(const QStringList &labels, QObject *parent);

    static constexpr int COL_CONSTRAINT_ITEM = 0;

    void AddItem(WarpConstraintItem* item);
    WarpConstraintItem* GetItem(const QModelIndex &index) const;

    QVariant data(const QModelIndex &index, int role) const override;

    void SetMatchedConstraints(const std::vector<Warp::Ref<Warp::Constraint>> &analysisConstraints)
    {
        m_matchedConstraints = analysisConstraints;
    }
};

class WarpConstraintTableWidget : public QWidget, public FilterTarget
{
    Q_OBJECT

    QTableView* m_table;
    WarpConstraintItemModel* m_model;
    GenericTextFilterModel* m_proxyModel;
    FilterEdit* m_filterEdit;
    FilteredView* m_filterView;

public:
    explicit WarpConstraintTableWidget(QWidget *parent = nullptr);

    void SetConstraints(QVector<WarpConstraintItem*> constraints);
    void SetMatchedConstraints(const std::vector<Warp::Ref<Warp::Constraint>> &analysisConstraints);

    void setFilter(const std::string&) override;
    void scrollToFirstItem() override {}
    void scrollToCurrentItem() override {}
    void selectFirstItem() override {}
    void activateFirstItem() override {}
};
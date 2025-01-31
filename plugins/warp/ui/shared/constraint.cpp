#include "constraint.h"

#include <QGridLayout>
#include <QHeaderView>

WarpConstraintItem::WarpConstraintItem(Warp::Ref<Warp::Constraint> constraint)
{
    m_constraint = constraint;

    // TODO: Display the offset like GUID @ 0x400 maybe?
    std::string guidStr = constraint->GetGUID().ToString();
    setText(QString::fromStdString(guidStr));
}

WarpConstraintItemModel::WarpConstraintItemModel(const QStringList &labels, QObject *parent)
{
    this->setHorizontalHeaderLabels(labels);
}

void WarpConstraintItemModel::AddItem(WarpConstraintItem* item)
{
    QList<QStandardItem *> row = {};
    row.insert(COL_CONSTRAINT_ITEM, item);
    appendRow(row);
}

WarpConstraintItem * WarpConstraintItemModel::GetItem(const QModelIndex &index) const
{
    if (!index.isValid())
        return nullptr;
    return dynamic_cast<WarpConstraintItem *>(item(index.row(), COL_CONSTRAINT_ITEM));
}

QVariant WarpConstraintItemModel::data(const QModelIndex &index, int role) const
{
    // Highlight constraints that are found in analysis.
    if (role == Qt::BackgroundRole)
    {
        if (const auto item = GetItem(index); item)
        {
            auto itemConstraint = item->GetConstraint();
            auto itemGuid = itemConstraint->GetGUID();

            // TODO: We really should store the guid in a hashmap or something instead of looping over it for every item.
            // TODO: A less intense green?
            // TODO: Take into account the constraint offset.
            for (const auto& constraint: m_matchedConstraints)
                if (constraint->GetGUID() == itemGuid)
                    return QBrush(Qt::green);
        }
    }

    return QStandardItemModel::data(index, role);
}

WarpConstraintTableWidget::WarpConstraintTableWidget(QWidget *parent)
{
    QGridLayout* layout = new QGridLayout(this);
    layout->setContentsMargins(2, 2, 2, 2);
    layout->setVerticalSpacing(4);

    m_table = new QTableView(this);
    m_model = new WarpConstraintItemModel({"Constraint"}, this);
    m_proxyModel = new GenericTextFilterModel(this);
    m_proxyModel->setSourceModel(m_model);
    m_table->setModel(m_proxyModel);

    m_filterEdit = new FilterEdit(this);
    m_filterView = new FilteredView(this, m_table, this, m_filterEdit);
    m_filterView->setFilterPlaceholderText("Search constraints");

    layout->addWidget(m_filterEdit, 0, 0, 1, 5);
    layout->addWidget(m_table, 1, 0, 1, 5);

    // Make the table look nice.
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->hide();
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setFocusPolicy(Qt::NoFocus);
    m_table->setShowGrid(false);
    m_table->setAlternatingRowColors(false);
    m_table->setSortingEnabled(true);
    // NOTE: We only have a single column right now, so disable the header.
    m_table->horizontalHeader()->hide();
    // Decrease row height to make it look nice.
    m_table->verticalHeader()->setDefaultSectionSize(30);
}

void WarpConstraintTableWidget::SetConstraints(QVector<WarpConstraintItem *> constraints)
{
    // Clear matches as they are no longer valid.
    m_model->clear();
    m_model->setRowCount(0);

    // Temporarily disable sorting so we can add rows faster
    m_table->setModel(m_model);
    m_table->setSortingEnabled(false);
    m_table->setEnabled(false);

    for (const auto& constraint : constraints)
        m_model->AddItem(constraint);

    // We are done, re-enable table.
    m_table->setEnabled(true);
    m_table->setModel(m_proxyModel);
    m_table->setSortingEnabled(true);
}

void WarpConstraintTableWidget::SetMatchedConstraints(
    const std::vector<Warp::Ref<Warp::Constraint>> &analysisConstraints)
{
    m_model->SetMatchedConstraints(analysisConstraints);
}

void WarpConstraintTableWidget::setFilter(const std::string &filter)
{
    m_proxyModel->setFilterFixedString(QString::fromStdString(filter));
    m_filterView->showFilter(QString::fromStdString(filter));
}

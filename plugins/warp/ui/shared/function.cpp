#include "theme.h"

#include "function.h"

#include <QClipboard>
#include <QGridLayout>
#include <QHeaderView>

#include "constraint.h"
#include "misc.h"

WarpFunctionItem::WarpFunctionItem(Warp::Ref<Warp::Function> function,
                                   BinaryNinja::Ref<BinaryNinja::Function> analysisFunction)
{
    m_function = function;

    BinaryNinja::Ref<BinaryNinja::Symbol> symbol = m_function->GetSymbol(*analysisFunction);
    std::string symbolName = symbol->GetShortName();
    setText(QString::fromStdString(symbolName));

    // Serialize the tokens to make it accessible via QModelIndex.
    // We will take these tokens and then user them in our custom item delegate.
    TokenData tokenData = TokenData(symbolName);
    if (BinaryNinja::Ref<BinaryNinja::Type> type = m_function->GetType(*analysisFunction))
        tokenData = TokenData(*type, symbolName);
    setData(QVariant::fromValue(tokenData), Qt::UserRole);
}

void WarpFunctionItem::SetContainer(const Warp::Ref<Warp::Container> &container)
{
    m_container = container;

    // Add the container string to data so the filter model picks it up.
    auto containerName = m_container->GetName();
    setData(QString::fromStdString(containerName), Qt::UserRole + 2);
}

void WarpFunctionItem::SetSource(Warp::Source source)
{
    m_source = source;

    // Add the source string to data so the filter model picks it up.
    std::string sourceStr = m_source->ToString();
    setData(QString::fromStdString(sourceStr), Qt::UserRole + 1);
}

WarpFunctionItemModel::WarpFunctionItemModel(const QStringList &labels, QObject *parent)
{
    this->setHorizontalHeaderLabels(labels);
}

void WarpFunctionItemModel::AppendFunction(WarpFunctionItem *item)
{
    QList<QStandardItem *> row = {};
    row.insert(COL_FUNCTION_ITEM, item);
    appendRow(row);
}

void WarpFunctionItemModel::InsertFunction(uint64_t address, WarpFunctionItem *item)
{
    // Update item if already available, this lets us keep the model
    const auto iter = m_insertableFunctionRows.find(address);
    if (iter != m_insertableFunctionRows.end())
    {
        setItem(iter->second, COL_FUNCTION_ITEM, item);
        return;
    }

    AppendFunction(item);
    m_insertableFunctionRows[address] = rowCount() - 1;
}

WarpFunctionItem *WarpFunctionItemModel::GetItem(const QModelIndex &index) const
{
    if (!index.isValid())
        return nullptr;
    return dynamic_cast<WarpFunctionItem *>(item(index.row(), COL_FUNCTION_ITEM));
}

std::optional<uint64_t> WarpFunctionItemModel::GetAddress(const QModelIndex &index) const
{
    if (!index.isValid())
        return std::nullopt;
    // TODO: This is a hack, this means we must enumerate all rows to get the address.
    for (const auto &[addr, row]: m_insertableFunctionRows)
        if (row == index.row())
            return addr;
    return std::nullopt;
}

QVariant WarpFunctionItemModel::data(const QModelIndex &index, int role) const
{
    if (role == Qt::BackgroundRole)
    {
        auto itemFunction = GetItem(index);
        // Check if we have a valid item and it's the matched function
        if (m_matchedFunction && itemFunction)
        {
            // TODO: Why wont == go to the correct call???
            if (BNWARPFunctionsEqual(itemFunction->GetFunction()->m_object, m_matchedFunction->m_object))
            {
                // TODO: Better color?
                static QColor matchedColor = getThemeColor(BlueStandardHighlightColor);
                matchedColor.setAlpha(128);
                return matchedColor;
            }
        }
    }

    if (role == Qt::DisplayRole)
    {
        // We really only use this for searching as we have TokenData for our delegate.
        WarpFunctionItem *item = GetItem(index);
        if (!item)
            return QVariant();
        TokenData tokenData = item->data(Qt::UserRole).value<TokenData>();
        // Add the function guid so we can filter by that.
        QString text = tokenData.toString() + " " + QString::fromStdString(item->GetFunction()->GetGUID().ToString());
        if (auto source = item->GetSource(); source)
        {
            // Add the source guid so we can also filter by that.
            std::string sourceStr = source->ToString();
            text = text + " " + QString::fromStdString(sourceStr);
        }
        return text;
    }

    return QStandardItemModel::data(index, role);
}

bool WarpFunctionFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    const QString filterString = filterRegularExpression().pattern();
    if (filterString.isEmpty())
        return true;

    // Filter on the first column only, this contains our actual function.
    auto index = sourceModel()->index(sourceRow, 0, sourceParent);
    auto data = QRegularExpression::escape(index.data().toString());
    if (data.contains(filterString, Qt::CaseInsensitive))
        return true;
    return false;
}

bool WarpFunctionFilterModel::lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const
{
    // TODO: When we make the stuff _actually_ sortable.
    return sourceLeft.row() < sourceRight.row();
}

WarpFunctionTableWidget::WarpFunctionTableWidget(QWidget *parent) : QWidget(parent)
{
    QGridLayout *layout = new QGridLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    m_table = new QTableView(this);
    m_model = new WarpFunctionItemModel({"Function"}, this);
    m_proxyModel = new WarpFunctionFilterModel(this);
    m_proxyModel->setSourceModel(m_model);
    m_table->setModel(m_proxyModel);

    m_filterEdit = new FilterEdit(this);
    m_filterView = new FilteredView(this, m_table, this, m_filterEdit);
    m_filterView->setFilterPlaceholderText("Search functions (By GUID, name or source)");

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
    // NOTE: We only have a single column right now, so disable header.
    m_table->horizontalHeader()->hide();
    // Decrease row height to make it look nice.
    m_table->verticalHeader()->setDefaultSectionSize(30);

    // Make the highlight less bright.
    QPalette palette = m_table->palette();
    palette.setColor(QPalette::Highlight, getThemeColor(SelectionColor));
    m_table->setPalette(palette);

    TokenDataDelegate *tokenDelegate = new TokenDataDelegate(this);
    // NOTE: Column 0 is assumed to be the function with the token data.
    m_table->setItemDelegateForColumn(0, tokenDelegate);

    AddressColorDelegate *addressDelegate = new AddressColorDelegate(this);
    // NOTE: Column 1 is assumed to be the function address.
    m_table->setItemDelegateForColumn(1, addressDelegate);

    // Add a dynamic context menu to the table.
    // NOTE: This is a bit stupid, I am sure there is a better way to do this in QT.
    m_contextMenu = new QMenu(this);
    RegisterContextMenuAction("Copy Name", [](WarpFunctionItem *item, std::optional<uint64_t>) {
        QClipboard *clipboard = QGuiApplication::clipboard();
        clipboard->setText(item->text());
    });
    RegisterContextMenuAction("Copy GUID", [](WarpFunctionItem *item, std::optional<uint64_t>) {
        QClipboard *clipboard = QGuiApplication::clipboard();
        Warp::Ref<Warp::Function> function = item->GetFunction();
        std::string guidStr = function->GetGUID().ToString();
        clipboard->setText(QString::fromStdString(guidStr));
    });

    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested, this, [&](QPoint pos) {
        const QModelIndex index = m_table->indexAt(pos);
        if (!index.isValid())
            return;
        const QModelIndex sourceIndex = m_proxyModel->mapToSource(index);
        WarpFunctionItem *item = m_model->GetItem(sourceIndex);
        if (!item || !item->GetFunction())
            return;

        // Execute the menu and get the selected action
        const QAction *selectedAction = m_contextMenu->exec(m_table->viewport()->mapToGlobal(pos));
        if (!selectedAction)
            return;

        const auto name = selectedAction->text();
        const auto iter = m_contextMenuActions.find(name);
        if (iter != m_contextMenuActions.end())
            iter->second(item, m_model->GetAddress(sourceIndex));
    });
}

void WarpFunctionTableWidget::RegisterContextMenuAction(const QString &name,
                                                        const std::function<void(
                                                            WarpFunctionItem *, std::optional<uint64_t>)> &callback)
{
    m_contextMenu->addAction(name);
    m_contextMenuActions[name] = callback;
}

void WarpFunctionTableWidget::SetFunctions(QVector<WarpFunctionItem *> functions)
{
    // Clear matches as they are no longer valid.
    m_model->clear();
    m_model->setRowCount(0);

    // Temporarily disable sorting so we can add rows faster
    m_table->setModel(m_model);
    m_table->setSortingEnabled(false);
    m_table->setEnabled(false);

    for (const auto &function: functions)
        m_model->AppendFunction(function);

    // We are done, re-enable table.
    m_table->setEnabled(true);
    m_table->setModel(m_proxyModel);
    m_table->setSortingEnabled(true);

    // Update the filter text with the new count of functions.
    m_filterView->setFilterPlaceholderText(QString("Search %1 functions").arg(m_model->rowCount()));
}

void WarpFunctionTableWidget::InsertFunction(uint64_t address, WarpFunctionItem *function)
{
    m_model->InsertFunction(address, function);
}

void WarpFunctionTableWidget::setFilter(const std::string &filter)
{
    m_proxyModel->setFilterFixedString(QString::fromStdString(filter));
    m_filterView->showFilter(QString::fromStdString(filter));
}

WarpFunctionInfoWidget::WarpFunctionInfoWidget(QWidget *parent)
    : QWidget(parent)
{
    // Create a tab widget
    QTabWidget *tabWidget = new QTabWidget(this);
    tabWidget->setContentsMargins(0, 0, 0, 0);

    // Create tables for the "Constraints", "Comments", and "Variables" tabs
    m_commentsTable = new QTableView(this);
    // m_variablesTable = new QTableView(this);

    // TODO: On click navigate to where the constraint is located.
    m_constraintsTable = new WarpConstraintTableWidget(this);
    tabWidget->addTab(m_constraintsTable, "Constraints");

    // Set up comments tab
    m_commentsModel = new QStandardItemModel(this);
    m_commentsModel->setHorizontalHeaderLabels({"Offset", "Text"});
    m_commentsModel->setColumnCount(2);
    m_commentsTable->setModel(m_commentsModel);
    m_commentsTable->horizontalHeader()->setStretchLastSection(true);
    m_commentsTable->horizontalHeader()->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_commentsTable->horizontalHeader()->setSelectionMode(QAbstractItemView::SingleSelection);
    m_commentsTable->horizontalHeader()->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_commentsTable->verticalHeader()->hide();
    m_commentsTable->horizontalHeader()->hide();
    tabWidget->addTab(m_commentsTable, "Comments");

    // Set up variables tab
    // m_variablesTable->setModel(new QStandardItemModel(this));
    // TODO: Add variables to data.
    // tabWidget->addTab(m_variablesTable, "Variables");

    // Add the tab widget to this widget's layout
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(tabWidget);

    setLayout(layout);
}

void WarpFunctionInfoWidget::UpdateInfo()
{
    m_commentsModel->clear();
    m_commentsModel->setRowCount(0);
    m_constraintsTable->SetMatchedConstraints({});
    m_constraintsTable->SetConstraints({});

    Warp::Ref<Warp::Function> function = GetFunction();
    if (!function)
        return;

    // Set the analysis constraints if there is an analysis function.
    if (const auto analysisFunction = GetAnalysisFunction())
    {
        const auto analysisConstraints = Warp::Function::Get(*analysisFunction)->GetConstraints();
        m_constraintsTable->SetMatchedConstraints(analysisConstraints);
    }

    // Add all the constraints for the current function to the model.
    QVector<WarpConstraintItem *> constraints;
    for (const auto &constraint: function->GetConstraints())
        constraints.push_back(new WarpConstraintItem(constraint));
    m_constraintsTable->SetConstraints(constraints);

    // Add all the comments to the model.
    for (const auto &comment: function->GetComments())
    {
        m_commentsModel->appendRow({
            new QStandardItem(QString("0x%1").arg(comment.offset, 0, 16)),
            new QStandardItem(QString::fromStdString(comment.text))
        });
    }
}

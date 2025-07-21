#include "matched.h"

#include <QGridLayout>

#include "theme.h"

const char *WARP_APPLY_ACTIVITY = "analysis.warp.apply";

WarpMatchedWidget::WarpMatchedWidget(BinaryViewRef current)
{
    m_current = current;
    // Create the QT stuff
    QGridLayout *layout = new QGridLayout(this);
    layout->setContentsMargins(2, 2, 2, 2);
    layout->setSpacing(2);
    auto newPalette = palette();
    newPalette.setColor(QPalette::Window, getThemeColor(SidebarWidgetBackgroundColor));
    setAutoFillBackground(true);
    setPalette(newPalette);

    // TODO: Split horizontally if the widget is displayed in a sidebar that is vertically challenged.
    m_splitter = new QSplitter(Qt::Vertical);
    m_splitter->setContentsMargins(0, 0, 0, 0);

    // Add a widget to display the matches.
    m_tableWidget = new WarpFunctionTableWidget(this);
    m_tableWidget->setContentsMargins(0, 0, 0, 0);
    m_splitter->addWidget(m_tableWidget);

    // Toggle the applying workflow, this workflow sets all the data for the function based on the matched function data.
    m_tableWidget->RegisterContextMenuAction("Toggle Application",
     [this](WarpFunctionItem *, std::optional<uint64_t> address) {
             if (!address.has_value())
                 return;
             for (const auto &func: m_current->GetAnalysisFunctionsForAddress(
                      *address))
             {
                 const bool previous = BinaryNinja::Settings::Instance()->Get<bool>(
                     WARP_APPLY_ACTIVITY, func);
                 BinaryNinja::Settings::Instance()->Set(
                     WARP_APPLY_ACTIVITY, !previous, func);
                 func->Reanalyze();
             }
         });

    layout->addWidget(m_splitter, 1, 0, 1, 5);
    setLayout(layout);

    Update();

    connect(m_tableWidget->GetTableView(), &QTableView::clicked, this,
            [this](const QModelIndex &index) {
                if (m_current == nullptr)
                    return;
                if (!index.isValid())
                    return;
                const QModelIndex sourceIndex = m_tableWidget->GetProxyModel()->mapToSource(index);
                if (!sourceIndex.isValid())
                    return;
                auto selectedItem = m_tableWidget->GetModel()->GetAddress(sourceIndex);
                if (!selectedItem.has_value())
                    return;
                // Navigate to the address in the view, so the user feels like they are doing something.
                auto currentView = m_current->GetCurrentView();
                m_current->Navigate(currentView, selectedItem.value());
            });
}

void WarpMatchedWidget::Update()
{
    m_tableWidget->GetTableView()->setSortingEnabled(false);
    m_tableWidget->GetTableView()->setEnabled(false);
    m_tableWidget->GetProxyModel()->setDynamicSortFilter(false);
    m_tableWidget->GetTableView()->setUpdatesEnabled(false);
    m_tableWidget->GetTableView()->setModel(nullptr);
    m_tableWidget->GetProxyModel()->setSourceModel(nullptr);
    for (const auto &analysisFunction: m_current->GetAnalysisFunctionList())
    {
        if (const auto &matchedFunction = Warp::Function::GetMatched(*analysisFunction))
        {
            uint64_t startAddress = analysisFunction->GetStart();
            m_tableWidget->InsertFunction(startAddress, new WarpFunctionItem(matchedFunction, analysisFunction));
        }
    }
    m_tableWidget->GetTableView()->setModel(m_tableWidget->GetProxyModel());
    m_tableWidget->GetProxyModel()->setSourceModel(m_tableWidget->GetModel());
    m_tableWidget->GetProxyModel()->setDynamicSortFilter(true);
    m_tableWidget->GetTableView()->setEnabled(true);
    m_tableWidget->GetTableView()->setSortingEnabled(true);
    m_tableWidget->GetTableView()->setUpdatesEnabled(true);
}

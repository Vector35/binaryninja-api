#include <QGridLayout>
#include <QHeaderView>

#include "matches.h"

#include <QClipboard>
#include <QFormLayout>
#include <thread>

#include "theme.h"
#include "warp.h"
#include "shared/misc.h"

WarpCurrentFunctionWidget::WarpCurrentFunctionWidget(FunctionRef current)
{
    // NOTE: Might be nullptr if the no selected function.
    m_current = current;

    m_logger = new BinaryNinja::Logger("WARP");

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

    // Add a widget to display the info about the selected function match.
    m_infoWidget = new WarpFunctionInfoWidget(this);
    m_infoWidget->setContentsMargins(0, 0, 0, 0);
    m_splitter->addWidget(m_infoWidget);

    layout->addWidget(m_splitter, 1, 0, 1, 5);
    setLayout(layout);

    m_tableWidget->RegisterContextMenuAction("Apply", [this](WarpFunctionItem *item, std::optional<uint64_t>) {
        if (item == nullptr)
            return;
        Warp::Ref<Warp::Function> selectedFunction = item->GetFunction();
        if (!selectedFunction)
            return;
        selectedFunction->Apply(*m_current);
        // Update analysis so that the selected function shows.
        m_current->GetView()->UpdateAnalysis();
        // So it shows visually as selected.
        m_tableWidget->GetModel()->SetMatchedFunction(selectedFunction);
    });
    m_tableWidget->RegisterContextMenuAction("Search for Source",
                                             [this](WarpFunctionItem *item, std::optional<uint64_t>) {
                                                 // Apply the source as the filter.
                                                 if (const auto source = item->GetSource(); source)
                                                     m_tableWidget->setFilter(source->ToString());
                                             });

    connect(m_tableWidget->GetTableView(), &QTableView::clicked, this,
            [this](const QModelIndex &index) {
                if (m_current == nullptr)
                    return;
                if (!index.isValid())
                    return;
                const QModelIndex sourceIndex = m_tableWidget->GetProxyModel()->mapToSource(index);
                if (!sourceIndex.isValid())
                    return;
                auto selectedItem = m_tableWidget->GetModel()->GetItem(sourceIndex);
                // Access the first column in the row
                if (!selectedItem)
                    return;
                m_infoWidget->SetFunction(selectedItem->GetFunction());
                m_infoWidget->UpdateInfo();
            });


    connect(m_tableWidget->GetTableView(), &QTableView::doubleClicked, this, [=](const QModelIndex &index) {
        if (m_current == nullptr)
            return;
        // Get the selected row for the given index.
        if (!index.isValid())
            return;
        const QModelIndex sourceIndex = m_tableWidget->GetProxyModel()->mapToSource(index);
        if (!sourceIndex.isValid())
            return;
        auto selectedItem = m_tableWidget->GetModel()->GetItem(sourceIndex);
        // Access the first column in the row
        if (!selectedItem)
            return;
        Warp::Ref<Warp::Function> selectedFunction = selectedItem->GetFunction();

        // Actually apply the newly selected function.
        selectedFunction->Apply(*m_current);

        // Update analysis so that the selected function shows.
        m_current->GetView()->UpdateAnalysis();

        // So it shows visually as selected.
        m_tableWidget->GetModel()->SetMatchedFunction(selectedFunction);
    });
}

void WarpCurrentFunctionWidget::SetCurrentFunction(FunctionRef current)
{
    if (m_current == current)
        return;
    m_current = current;
    m_infoWidget->SetAnalysisFunction(m_current);

    if (current)
    {
        // Add the function to the processing list only if we have no already done so.
        // If a user goes to a function, then navigates away, they do not want to
        // have us try and send a network request!
        {
            std::lock_guard<std::mutex> lock(m_requestMutex);
            uint64_t funcStart = current->GetStart();
            if (m_processedFunctions.find(funcStart) == m_processedFunctions.end()) {
                m_pendingRequests.push_back(current);
            }
        }
        if (!m_requestInProgress.exchange(true)) {
            BinaryNinja::WorkerPriorityEnqueue([this]() {
                ProcessPendingFetchRequests();
            });
        }
    }

    UpdateMatches();
}

void WarpCurrentFunctionWidget::UpdateMatches()
{
    if (!m_current)
        return;
    const auto guid = Warp::GetAnalysisFunctionGUID(*m_current);
    if (!guid.has_value())
        return;

    // Set the matched function for highlighting.
    Warp::Ref<Warp::Function> matchedFunction = Warp::Function::GetMatched(*m_current);
    m_tableWidget->GetModel()->SetMatchedFunction(matchedFunction);

    // We swapped functions, reset the info widget to the default state with new analysis function.
    m_infoWidget->SetFunction(matchedFunction);
    m_infoWidget->UpdateInfo();

    Warp::Ref<Warp::Target> target = Warp::Target::FromPlatform(*m_current->GetPlatform());

    // Add all the possible matches for the current function to the model.
    QVector<WarpFunctionItem *> matches;
    bool matchedFuncAdded = false;
    // TODO: When we add in the networked container we need to update this stuff on a separate thread and show a spinny thing.
    for (const auto &container: Warp::Container::All())
    {
        for (const auto &source: container->GetSourcesWithFunctionGUID(*target, guid.value()))
        {
            for (const auto &function: container->GetFunctionsWithGUID(*target, source, guid.value()))
            {
                // TODO: This does not work.
                if (matchedFunction && BNWARPFunctionsEqual(function->m_object, matchedFunction->m_object))
                    matchedFuncAdded = true;
                auto item = new WarpFunctionItem(function, m_current);
                item->SetContainer(container);
                item->SetSource(source);
                matches.emplace_back(item);
            }
        }
    }

    // Add the matched function unconditionally, assuming it has not been found in a container.
    // NOTE: This happens when you load from a database for example.
    if (matchedFunction && !matchedFuncAdded)
    {
        auto item = new WarpFunctionItem(matchedFunction, m_current);
        matches.emplace_back(item);
    }

    m_tableWidget->SetFunctions(matches);
}

void WarpCurrentFunctionWidget::ProcessPendingFetchRequests()
{
    std::vector<FunctionRef> requests;
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        requests = std::move(m_pendingRequests);
        m_pendingRequests.clear();
    }

    if (requests.empty()) {
        m_requestInProgress = false;
        return;
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    std::vector<Warp::FunctionGUID> guids;
    Warp::Ref<Warp::Target> target;
    for (const auto& func : requests) {
        // TODO: Need to send multiple requests if there is multiple targets.
        if (!target)
            target = Warp::Target::FromPlatform(*func->GetPlatform());
        if (const auto guid = Warp::GetAnalysisFunctionGUID(*func); guid.has_value())
            guids.push_back(guid.value());
    }

    // Actually fetch the data!
    if (!guids.empty())
        for (const auto &container: Warp::Container::All())
            container->FetchFunctions(*target, guids);

    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        for (const auto& func : requests) {
            m_processedFunctions.insert(func->GetStart());
        }
    }

    // TODO: Update the matches, make sure there was stuff added first lol.
    // TODO: UpdateMatches();

    const auto end_time = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebug("ProcessPendingRequests took %f seconds", elapsed_time.count());

    m_requestInProgress = false;
}

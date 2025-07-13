#pragma once

#include <QSplitter>

#include "filter.h"
#include "render.h"
#include "shared/function.h"

class WarpCurrentFunctionWidget : public QWidget
{
    Q_OBJECT
    FunctionRef m_current;

    QSplitter *m_splitter;

    WarpFunctionTableWidget *m_tableWidget;
    WarpFunctionInfoWidget *m_infoWidget;

    LoggerRef m_logger;

    std::mutex m_requestMutex;
    std::vector<FunctionRef> m_pendingRequests;
    std::atomic<bool> m_requestInProgress {false};
    std::unordered_set<uint64_t> m_processedFunctions;

public:
    explicit WarpCurrentFunctionWidget(FunctionRef current);

    ~WarpCurrentFunctionWidget() override = default;

    void SetCurrentFunction(FunctionRef current);

    FunctionRef GetCurrentFunction() { return m_current; };

    void UpdateMatches();

    void ProcessPendingFetchRequests();
};

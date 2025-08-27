#pragma once

#include <QSplitter>

#include "filter.h"
#include "render.h"
#include "shared/fetcher.h"
#include "shared/function.h"

class WarpCurrentFunctionWidget : public QWidget
{
    Q_OBJECT
    FunctionRef m_current;

    QSplitter *m_splitter;

    WarpFunctionTableWidget *m_tableWidget;
    WarpFunctionInfoWidget *m_infoWidget;

    LoggerRef m_logger;

    std::shared_ptr<WarpFetcher> m_fetcher;

public:
    explicit WarpCurrentFunctionWidget();

    ~WarpCurrentFunctionWidget() override = default;

    void SetFetcher(std::shared_ptr<WarpFetcher> fetcher);

    void SetCurrentFunction(FunctionRef current);

    FunctionRef GetCurrentFunction() { return m_current; };

    void UpdateMatches();
};

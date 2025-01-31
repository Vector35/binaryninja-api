#pragma once

#include <QSplitter>

#include "filter.h"
#include "render.h"
#include "shared/function.h"

class WarpCurrentFunctionWidget : public QWidget
{
    Q_OBJECT
    FunctionRef m_current;

    QSplitter* m_splitter;

    WarpFunctionTableWidget* m_tableWidget;
    WarpFunctionInfoWidget* m_infoWidget;

public:
    explicit WarpCurrentFunctionWidget(FunctionRef current);

    ~WarpCurrentFunctionWidget() override = default;

    void SetCurrentFunction(FunctionRef current);

    FunctionRef GetCurrentFunction() { return m_current; };
    void UpdateMatches();
};

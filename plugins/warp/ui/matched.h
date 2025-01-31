#pragma once
#include <QSplitter>

#include "uitypes.h"
#include "shared/function.h"

class WarpMatchedFunctionTableWidget : public WarpFunctionTableWidget
{
    Q_OBJECT


};

class WarpMatchedWidget : public QWidget
{
    Q_OBJECT
    BinaryViewRef m_current;

    QSplitter* m_splitter;

    WarpFunctionTableWidget* m_tableWidget;

public:
    explicit WarpMatchedWidget(BinaryViewRef current);

    ~WarpMatchedWidget() override = default;

    void Update();
};

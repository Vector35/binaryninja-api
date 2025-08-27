#pragma once

#include "matched.h"
#include "matches.h"
#include "sidebar.h"
#include "sidebarwidget.h"
#include "containers.h"

class WarpSidebarWidget : public SidebarWidget
{
    Q_OBJECT
    BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
    BinaryViewRef m_data;
    ViewFrame *m_currentFrame;
    QWidget *m_headerWidget;

    BinaryNinja::Ref<BinaryNinja::AnalysisCompletionEvent> m_analysisEvent;
    QAction *m_matcherAction;
    bool isMatcherRunning = false;

    WarpCurrentFunctionWidget *m_currentFunctionWidget;
    WarpMatchedWidget *m_matchedWidget;
    WarpContainersPane *m_containerWidget;

public:
    explicit WarpSidebarWidget(BinaryViewRef data);

    ~WarpSidebarWidget() override;

    QWidget *headerWidget() override { return m_headerWidget; }

    void focus() override;

    void Update();

    void setMatcherActionIcon(bool running);

    void notifyViewChanged(ViewFrame *) override;

    void notifyViewLocationChanged(View *, const ViewLocation &) override;
};

class WarpSidebarWidgetType : public SidebarWidgetType
{
public:
    WarpSidebarWidgetType();

    SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
    SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }

    WarpSidebarWidget *createWidget(ViewFrame *viewFrame, BinaryViewRef data) override
    {
        return new WarpSidebarWidget(data);
    }
};

#pragma once

#include <QAction>
#include <QToolBar>
#include <QPushButton>
#include <QIcon>
#include <QLabel>
#include <QPropertyAnimation>
#include "binaryninjaapi.h"
#include "sidebarwidget.h"
#include "uicontext.h"


class BINARYNINJAUIAPI WorkflowMonitorWidget : public SidebarWidget
{
	Q_OBJECT
	Q_PROPERTY(qreal dotBrightness READ dotBrightness WRITE setDotBrightness)

	BinaryViewRef m_data;
	FunctionRef m_function;
	WorkflowRef m_workflow;

	Menu* m_menu;
	ContextMenuManager* m_contextMenuManager;
	UIActionHandler m_actionHandler;

	QToolBar* m_toolbar;

	QAction* m_startAction;
	QAction* m_haltAction;
	QAction* m_stepAction;
	QAction* m_resetAction;
	QAction* m_toggleSuspendAction;
	QAction* m_toggleLogAction;
	QAction* m_topologyAction;
	QPushButton* m_contextButton;
	QLabel* m_contextLabel;

	std::map<std::string, QIcon> m_iconCache;
	std::map<std::string, QColor> m_colorCache;
	std::string m_lastState;
	QColor m_lastStatusColor;
	QColor m_labelColor;

	QLabel* m_currentActivity;
	QLabel* m_statusIndicator;
	QPropertyAnimation* m_dotAnimation;
	qreal m_dotBrightness;
	bool m_animationRunning;

	virtual void contextMenuEvent(QContextMenuEvent*) override;

	void updateToolbarActions(bool force = false);
	void updateToolbarIcons();
	void setupToolbar();
	void setupActions();
	void updateStatusIndicator();

	qreal dotBrightness() const;
	void setDotBrightness(qreal brightness);

public:
	WorkflowMonitorWidget(BinaryViewRef data);
	~WorkflowMonitorWidget();

	void notifyRefresh() override;
	void notifyFontChanged() override;
	void notifyThemeChanged() override;
	void notifyViewLocationChanged(View* view, const ViewLocation& viewLocation) override;

	void startDotAnimation();
	void stopDotAnimation();
};


class BINARYNINJAUIAPI WorkflowMonitorWidgetType : public SidebarWidgetType
{
public:
	WorkflowMonitorWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::LeftReference; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
};

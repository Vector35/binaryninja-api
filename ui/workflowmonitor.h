#pragma once

#include <QAction>
#include <QToolBar>
#include <QPushButton>
#include <QIcon>
#include <QLabel>
#include <QPropertyAnimation>
#include <QTabWidget>
#include "binaryninjaapi.h"
#include "flowgraphwidget.h"
#include "fontsettings.h"
#include "pane.h"
#include "sidebarwidget.h"
#include "uicontext.h"
#include "viewframe.h"


class BINARYNINJAUIAPI WorkflowMonitorWidget : public QWidget
{
	Q_OBJECT
	Q_PROPERTY(qreal dotBrightness READ dotBrightness WRITE setDotBrightness)

	BinaryViewRef m_data;
	FunctionRef m_function;
	WorkflowRef m_workflow;

	Menu* m_menu;
	//ContextMenuManager* m_contextMenuManager;
	UIActionHandler m_actionHandler;

	QToolBar* m_toolbar;
	QTabWidget* m_tabs;
	FlowGraphWidget* m_flowGraphWidget;

	QAction* m_startAction;
	QAction* m_haltAction;
	QAction* m_stepAction;
	QAction* m_resetAction;
	QAction* m_toggleSuspendAction;
	QAction* m_toggleLogAction;
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

	void updateToolbarActions(bool force = false);
	void updateToolbarIcons();
	void setupToolbar();
	void setupActions();
	void updateStatusIndicator();

	qreal dotBrightness() const;
	void setDotBrightness(qreal brightness);

public:
	WorkflowMonitorWidget(BinaryViewRef data, FunctionRef function = nullptr);
	~WorkflowMonitorWidget();

	FunctionRef getCurrentFunction() const { return m_function; }

	void notifyRefresh();
	void notifyFontChanged();
	void notifyThemeChanged();
	void notifyViewLocationChanged(View* view, const ViewLocation& viewLocation);

	void startDotAnimation();
	void stopDotAnimation();
};


class BINARYNINJAUIAPI WorkflowMonitorSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	WorkflowMonitorWidget* m_widget;

public:
	WorkflowMonitorSidebarWidget(BinaryViewRef data);

	void notifyRefresh() override { m_widget->notifyRefresh(); }
	void notifyFontChanged() override { m_widget->notifyFontChanged(); }
	void notifyThemeChanged() override { m_widget->notifyThemeChanged(); }
	void notifyViewLocationChanged(View* view, const ViewLocation& viewLocation) override { m_widget->notifyViewLocationChanged(view, viewLocation); }
};


class BINARYNINJAUIAPI WorkflowMonitorSidebarWidgetType : public SidebarWidgetType
{
public:
	WorkflowMonitorSidebarWidgetType();

	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::LeftReference; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }

	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;

	bool canUseAsPane(SplitPaneWidget* panes, BinaryViewRef data) const override { return true; }
	Pane* createPane(SplitPaneWidget* panes, BinaryViewRef data) override;
};


class BINARYNINJAUIAPI WorkflowView : public QWidget, public View
{
	Q_OBJECT

	BinaryViewRef m_data;
	uint64_t m_currentOffset = 0;
	WorkflowMonitorWidget* m_widget;

public:
	WorkflowView(BinaryViewRef data, ViewFrame* frame);

	void notifyRefresh() override { m_widget->notifyRefresh(); }
	BinaryViewRef getData() override { return m_data; }
	uint64_t getCurrentOffset() override { return m_currentOffset; }
	void setSelectionOffsets(BNAddressRange range) override { m_currentOffset = range.start; }
	bool navigate(uint64_t offset) override;
	QFont getFont() override { return getMonospaceFont(m_widget); }
	FunctionRef getCurrentFunction() override { return m_widget->getCurrentFunction(); }
};


class BINARYNINJAUIAPI WorkflowViewType : public ViewType
{
	static WorkflowViewType* m_instance;

public:
	WorkflowViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};

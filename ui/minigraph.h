#pragma once

#include <QtGui/QMouseEvent>
#include <QtGui/QPaintEvent>
#include <QtWidgets/QWidget>

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "sidebar.h"

class ContextMenuManager;
class FlowGraphWidget;
class Menu;
class ViewFrame;

class BINARYNINJAUIAPI MiniGraph : public SidebarWidget, public UIContextNotification
{
	Q_OBJECT

	ViewFrame* m_frame = nullptr;
	FlowGraphWidget* m_flowGraphWidget = nullptr;
	QWidget* m_header = nullptr;
	bool m_popout;
	QRect m_miniRenderRect;

  public:
	MiniGraph(bool popout = false);
	~MiniGraph();

	// Called when used in sidebar
	virtual void notifyViewChanged(ViewFrame* frame) override;

	// Called when popped out of sidebar
	virtual void OnViewChange(UIContext* context, ViewFrame* frame, const QString& type) override;

	virtual QWidget* headerWidget() override { return m_header; }
	virtual QSize sizeHint() const override { return QSize(200, 200); }

	void setSource(ViewFrame* frame, FlowGraphWidget* graphView);

  protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void scrollTo(int x, int y);

  public Q_SLOTS:
	void notifyUpdate();
	void graphDestroyed();
	void newPane();
};


class BINARYNINJAUIAPI MiniGraphSidebarWidgetType : public SidebarWidgetType
{
  public:
	MiniGraphSidebarWidgetType();
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual bool isInReferenceArea() const override { return true; }
};

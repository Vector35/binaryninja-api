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

class BINARYNINJAUIAPI MiniGraph: public SidebarWidget
{
	Q_OBJECT

	ViewFrame* m_frame;
	FlowGraphWidget* m_flowGraphWidget = nullptr;

public:
	MiniGraph(ViewFrame* frame);
	~MiniGraph();

	virtual void notifyViewChanged(ViewFrame* frame) override;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void scrollTo(int x, int y);

public Q_SLOTS:
	void notifyUpdate();
};


class BINARYNINJAUIAPI MiniGraphSidebarWidgetType: public SidebarWidgetType
{
public:
	MiniGraphSidebarWidgetType();
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual bool isInReferenceArea() const override { return true; }
};

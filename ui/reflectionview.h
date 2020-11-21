#pragma once

#include <QtGui/QMouseEvent>
#include <QtGui/QPaintEvent>
#include <QtWidgets/QWidget>

#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "uitypes.h"

class ContextMenuManager;
class DisassemblyContainer;
class Menu;
class ViewFrame;

class BINARYNINJAUIAPI ReflectionView: public QWidget, public DockContextHandler
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	ViewFrame* m_frame;
	BinaryViewRef m_data;
	DisassemblyContainer* m_disassemblyContainer;

public:
	ReflectionView(ViewFrame* frame, BinaryViewRef data);
	~ReflectionView();

	virtual void notifyOffsetChanged(uint64_t offset) override;
	virtual void notifyViewChanged(ViewFrame* frame) override;
	virtual bool shouldBeVisible(ViewFrame* frame) override;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
};

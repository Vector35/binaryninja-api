#pragma once

#include <QtCore/QPointer>
#include <QtWidgets/QMenu>
#include <QtWidgets/QWidget>
#include <functional>
#include <map>
#include <string>
#include "binaryninjaapi.h"
#include "viewframe.h"

class BINARYNINJAUIAPI ContextMenuManager
{
	QWidget* m_parent;
	QPointer<QMenu> m_menu;
	MenuInstance* m_instance;

public:
	ContextMenuManager(QWidget* parent);
	~ContextMenuManager();
	QMenu* create();
	MenuInstance* show(View* view);
	MenuInstance* show(Menu* source, UIActionHandler* handler);
	bool isActive() { return !m_menu.isNull(); }
};

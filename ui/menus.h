#pragma once

#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMenu>
#include <QtWidgets/QWidget>
#include <functional>
#include <map>
#include <string>
#include "binaryninjaapi.h"
#include "action.h"
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


class BINARYNINJAUIAPI MenuHelper: public QLabel
{
	Q_OBJECT

	QPalette::ColorRole m_backgroundRole;
	QPalette::ColorRole m_foregroundRole;
	QPalette::ColorRole m_activeForegroundRole;

protected:
	Menu m_menu;
	ContextMenuManager m_contextMenuManager;
	QTimer* m_timer;

public:
	MenuHelper(QWidget* parent);

	void setBackgroundColorRole(QPalette::ColorRole role = QPalette::Highlight);
	void setForegroundColorRole(QPalette::ColorRole role = QPalette::WindowText);
	void setActiveForegroundColorRole(QPalette::ColorRole role = QPalette::HighlightedText);

Q_SIGNALS:
	void clicked();

protected Q_SLOTS:
	virtual void showMenu() = 0;

private Q_SLOTS:
	void underMouseTimerEvent();

protected:
	void enterEvent(QEvent* event) override;
	void leaveEvent(QEvent* event) override;
	void mouseReleaseEvent(QMouseEvent* event) override;
};

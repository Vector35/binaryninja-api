#pragma once

#include <QtCore/QObject>
#include <QtCore/QSettings>
#include <QtWidgets/QDockWidget>
#include <map>

#include "binaryninjaapi.h"
#include "action.h"
#include "uitypes.h"

class ContextMenuManager;
class DockHandler;
class Menu;
class View;
class ViewFrame;

struct BINARYNINJAUIAPI DockProperties
{
	DockProperties() { };
	DockProperties(QDockWidget* dw, bool vis, Qt::DockWidgetArea dar, Qt::Orientation dor, bool dvis, bool vs) :
		dockWidget(dw), visibleState(vis), defaultArea(dar), defaultOrientation(dor), defaultVisibility(dvis),
		viewSensitive(vs), neverBeenVisible(true), sizeStash(0, 0), actionOnShow(nullptr) { }
	DockProperties(const DockProperties &dp) :
		dockWidget(dp.dockWidget), visibleState(dp.visibleState), defaultArea(dp.defaultArea),
		defaultOrientation(dp.defaultOrientation), defaultVisibility(dp.defaultVisibility),
		viewSensitive(dp.viewSensitive), neverBeenVisible(dp.neverBeenVisible), sizeStash(dp.sizeStash), actionOnShow(dp.actionOnShow) { }

	QDockWidget* dockWidget;
	bool visibleState;
	Qt::DockWidgetArea defaultArea;
	Qt::Orientation defaultOrientation;
	bool defaultVisibility;
	bool viewSensitive;
	bool neverBeenVisible;
	QSize sizeStash;
	std::function<void()> actionOnShow;
};

struct DockSizePrefs
{
	DockSizePrefs() { }
	QList<QDockWidget*> docks;
	QList<int> hDockSizes;
	QList<int> vDockSizes;
	bool nonUniformVisibility = false;
};

class BINARYNINJAUIAPI DockContextHandler
{
protected:
	QString m_name;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager = nullptr;
	Menu* m_menu = nullptr;
	QWidget* m_parentWindow;

public:
	DockContextHandler(QWidget* widget, const QString& name);
	virtual ~DockContextHandler();

	QWidget* getParentWindow() { return m_parentWindow; }

	virtual void focusInput() { };
	virtual void notifyViewChanged(ViewFrame* /*frame*/) { };
	virtual bool shouldBeVisible(ViewFrame* /*frame*/) { return true; };
	virtual void updateFonts() { };
	virtual void updateTheme() { };
};

class BINARYNINJAUIAPI DockHandler: public QObject
{
	Q_OBJECT

	int m_windowIndex = 0;
	ViewFrame* m_viewFrame = nullptr;
	View* m_view = nullptr;
	BinaryViewRef m_data;
	std::map<QString, DockProperties> m_docks;
	bool m_resizeDocksRequest = false;
	bool m_shouldResizeDocks = false;
	std::map<Qt::DockWidgetArea, bool> m_enableHiddenGroupSave;

public:
	explicit DockHandler(QObject* parent, int windowIndex);

	void close();
	void notifyRestoredFromState();
	void reset(bool initial = false);
	void reset(const QString& name);
	void resizeDocksOnShow(bool resizeDocks) { m_resizeDocksRequest = resizeDocks; }
	bool addDockWidget(const QString& name, QWidget* primaryWidget, Qt::DockWidgetArea area = Qt::BottomDockWidgetArea, Qt::Orientation orientation = Qt::Horizontal, bool defaultVisibility = false);
	QDockWidget* getDockWidget(const QString& name);
	ViewFrame* getViewFrame() { return m_viewFrame; }
	bool isVisible(const QString& name);
	void setVisible(const QString& name, bool visible);

	void saveState(QSettings& settings, const QString& windowStateName);
	void restoreState(QSettings& settings, const QString& windowStateName);
	void saveDockSizes(bool nullFrame = false);
	void restoreDockSizes();

	bool shouldResizeDocks();
	void updateFonts();
	void addActionOnShow(const QString& name, const std::function<void()>& action);

	static DockHandler* getActiveDockHandler();

public Q_SLOTS:
	void viewChanged(ViewFrame* frame);
	void topLevelChanged(bool topLevel);
};

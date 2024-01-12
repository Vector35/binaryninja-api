#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QWidget>
#include "splitter.h"

class Sidebar;
class SidebarWidgetType;
class SidebarWidgetAndHeader;
class SplitPaneWidget;

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI FloatingSidebarStackedWidget: public QWidget
{
	Q_OBJECT

	SidebarWidgetType* m_type;
	bool m_isWindowed;
	QSize m_savedSize;
	std::optional<QPoint> m_savedPosition;
	bool m_visible = false;

public:
	FloatingSidebarStackedWidget(
		SidebarWidgetType* type, QStackedWidget* stackedWidget, const QString& title, bool windowed);
	bool isWindowed() const;
	void setWindowed(bool windowed);
	void setVisible(bool visible) override;

	QRect savedGeometry() const;
	void setSavedGeometry(const QRect& rect);

protected:
	void closeEvent(QCloseEvent* event) override;

Q_SIGNALS:
	void floatingWidgetClosed(SidebarWidgetType* type);
};

/*!
    \ingroup sidebar
*/
struct BINARYNINJAUIAPI SidebarStackedWidget
{
	bool floating;
	QStackedWidget* stackedWidget;
	FloatingSidebarStackedWidget* floatingWidget;
};

/*!
    \ingroup sidebar
*/
enum SidebarContainerLocation
{
	LeftSideContainer,
	LeftBottomContainer,
	RightSideContainer,
	RightBottomContainer
};

/*!
    \ingroup sidebar
*/
struct BINARYNINJAUIAPI SidebarFloatingWidgetState
{
	bool floating, windowed;
	QRect rect;
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarWidgetContainer : public QWidget
{
	Q_OBJECT

	Sidebar* m_sidebar;
	SidebarContainerLocation m_location;

	Splitter* m_contentSplitter;
	std::map<SplitPaneWidget*, std::map<QString, QVariantMap>> m_priorContentSplitterState;

	std::set<SidebarWidgetType*> m_active, m_docked;
	std::map<SidebarWidgetType*, SidebarStackedWidget> m_stackedWidgets;
	std::map<SplitPaneWidget*,
		std::map<ViewFrame*, std::map<QString, std::map<SidebarWidgetType*, SidebarWidgetAndHeader*>>>>
		m_widgets;
	std::map<SplitPaneWidget*, std::map<QString, std::set<SidebarWidgetType*>>> m_priorWidgets;

	std::map<SidebarWidgetType*, SidebarFloatingWidgetState> m_savedFloatingWidgetState;

	SidebarStackedWidget& stackedWidgetForType(SidebarWidgetType* type);
	std::vector<SidebarWidgetAndHeader*> widgetsForContext() const;
	void insertWidgetIntoContainer(SidebarWidgetType* type, QStackedWidget* widget);
	void updateContentsVisibility();

private Q_SLOTS:
	void floatingWidgetClosed(SidebarWidgetType* type);

public:
	SidebarWidgetContainer(Sidebar* sidebar, SidebarContainerLocation location);

	Sidebar* sidebar() const { return m_sidebar; }
	Splitter* contentSplitter() const { return m_contentSplitter; }
	SidebarContainerLocation location() const { return m_location; }

	void savePriorContext();
	void setActiveContext(SplitPaneWidget* panes, const QString& dataType);
	void destroyContext(ViewFrame* frame);
	void destroyContext(SplitPaneWidget* panes);

	bool isContentActive() const { return !m_docked.empty(); }
	bool isActive(SidebarWidgetType* type) const { return m_active.count(type) != 0; }
	const std::set<SidebarWidgetType*>& activeTypes() const { return m_active; }
	const std::set<SidebarWidgetType*>& dockedTypes() const { return m_docked; }

	void activate(SidebarWidgetType* type);
	void deactivate(SidebarWidgetType* type);

	void moveSidebarWidgetType(SidebarWidgetType* type);
	void transferSidebarWidgetType(SidebarWidgetType* type, SidebarWidgetContainer* target);

	SidebarWidget* widget(SidebarWidgetType* type) const;
	SidebarWidget* widget(const QString& name) const;
	SidebarWidgetAndHeader* widgetAndHeader(SidebarWidgetType* type) const;

	void addWidget(SidebarWidgetType* type, SidebarWidget* widget, bool canClose = false);
	void removeWidget(SidebarWidgetType* type, SidebarWidget* widget);
	SidebarWidget* widgetWithTitle(SidebarWidgetType* type, const QString& title) const;
	bool hasWidgetWithTitle(SidebarWidgetType* type, const QString& title) const;
	bool activateWidgetWithTitle(SidebarWidgetType* type, const QString& title) const;
	bool hasContent(SidebarWidgetType* type) const;

	virtual QSize sizeHint() const override;

	void updateTheme();
	void updateFonts();

	void saveSizes(QSettings& settings, const QString& windowStateName);
	void restoreSizes(const QSettings& settings, const QString& windowStateName);
	std::optional<SidebarFloatingWidgetState> floatingWidgetState(SidebarWidgetType* type) const;
	void restoreFloatingWidgetState(SidebarWidgetType* type, const SidebarFloatingWidgetState& state);

	void updateViewLocation(View* view, const ViewLocation& viewLocation);
	void viewChanged();

	void moveContextToContainer(SplitPaneWidget* panes, SidebarWidgetContainer* target);

	void dockWidget(SidebarWidgetType* type);
	void floatWidget(SidebarWidgetType* type);
	void windowedWidget(SidebarWidgetType* type);
	bool isDocked(SidebarWidgetType* type);
	bool isFloating(SidebarWidgetType* type);
	bool isWindowed(SidebarWidgetType* type);

Q_SIGNALS:
	void showContents();
	void hideContents();
};

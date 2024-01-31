#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QLabel>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtGui/QPicture>
#include "theme.h"

class ContextMenuManager;
class SplitTabWidget;
class SidebarWidgetType;
class SidebarHeader;
class DockableTabCollection;
class Pane;
class SplitPaneWidget;
class DockableTabStyle;

/*!
	\defgroup sidebar Sidebar
 	\ingroup uiapi
*/

/*!
	\ingroup sidebar
*/
struct BINARYNINJAUIAPI SidebarIcon
{
	QImage original;
	QImage active;
	QImage inactive;

	static SidebarIcon generate(const QImage& src);
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarWidget : public QWidget
{
	Q_OBJECT

protected:
	QString m_title;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager = nullptr;
	Menu* m_menu = nullptr;

	QTimer* m_updateTimer = nullptr;

public:
	SidebarWidget(const QString& title);
	~SidebarWidget() { closing(); }
	const QString& title() const { return m_title; }

	void enableRefreshTimer(int interval);
	void setRefreshQuiesce(bool enable);
	virtual void notifyRefresh() {};

	virtual void notifyFontChanged() {}
	virtual void notifyOffsetChanged(uint64_t /*offset*/) {}
	virtual void notifyThemeChanged();
	virtual void notifyViewChanged(ViewFrame* /*frame*/) {}
	virtual void notifyViewLocationChanged(View* /*view*/, const ViewLocation& /*viewLocation*/) {}
	virtual void focus();
	virtual void closing() {}
	virtual void setPrimaryOrientation(Qt::Orientation /*orientation*/) {}

	virtual QWidget* headerWidget() { return nullptr; }
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarWidgetAndHeader : public QWidget
{
	Q_OBJECT
	bool m_tabsActive = false;
	bool m_combinedTabsAndHeader = false;
	bool m_alwaysShowTabs;
	bool m_fixedHeaderWidget;
	SidebarWidgetType* m_type;
	SidebarWidget* m_widget = nullptr;
	SidebarHeader* m_header = nullptr;

	QVBoxLayout* m_layout;
	SplitTabWidget* m_tabs = nullptr;
	DockableTabCollection* m_tabCollection = nullptr;
	QStackedWidget* m_headerStack;
	std::map<QWidget*, SidebarHeader*> m_headerWidgets;
	std::set<SidebarWidget*> m_activeWidgets;
	QLabel* m_noWidgetLabel = nullptr;

private Q_SLOTS:
	void tabChanged(QWidget* widget);
	void tabClosed(QWidget* widget);

public:
	SidebarWidgetAndHeader(SidebarWidgetType* type, SplitPaneWidget* panes, ViewFrame* frame, BinaryViewRef data);
	~SidebarWidgetAndHeader() override;

	SidebarWidget* widget() const { return m_widget; }
	QWidget* header() const;

	void addWidget(SidebarWidget* widget, bool canClose = false);
	void removeWidget(SidebarWidget* widget);
	SidebarWidget* widgetWithTitle(const QString& title) const;
	bool hasWidgetWithTitle(const QString& title) const;
	bool activateWidgetWithTitle(const QString& title);
	bool hasContent() const;

	void updateTheme();
	void updateFonts();
	void closing();
	void notifyViewChanged(ViewFrame* frame);
	void notifyViewLocationChanged(View* view, const ViewLocation& viewLocation);
	void notifyOffsetChanged(uint64_t offset);

	void forAllWidgets(const std::function<void(SidebarWidget*)>& func) const;
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarHeaderTitle : public QLabel
{
	Q_OBJECT

public:
	SidebarHeaderTitle(const QString& name);
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarHeader : public QWidget
{
	Q_OBJECT
	bool m_hasRightSide = false;

public:
	SidebarHeader(const QString& name, QWidget* rightSide = nullptr);
	bool hasRightSide() const { return m_hasRightSide; }
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarInvalidContextWidget : public SidebarWidget
{
	Q_OBJECT

public:
	SidebarInvalidContextWidget(const QString& title);

private Q_SLOTS:
	void openFile();
};

/*!
    \ingroup sidebar
*/
enum SidebarWidgetLocation
{
	LeftContent,
	LeftReference,
	LeftBottom,
	RightContent,
	RightReference,
	RightBottom
};

enum SidebarContextSensitivity
{
	GlobalSidebarContext,
	SelfManagedSidebarContext,
	PerTabSidebarContext,
	PerViewTypeSidebarContext,
	PerPaneSidebarContext
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarWidgetType
{
	SidebarIcon m_icon;
	QString m_name;

public:
	SidebarWidgetType(const QImage& icon, const QString& name);
	virtual ~SidebarWidgetType() {}

	const SidebarIcon& icon() const { return m_icon; }
	const QString& name() const { return m_name; }

	/*!
	    \deprecated Use `defaultLocation()`
	*/
	virtual bool isInReferenceArea() const { return false; }

	/*!
	    \deprecated Use `contextSensitivity()`
	*/
	virtual bool viewSensitive() const { return true; }

	virtual SidebarWidgetLocation defaultLocation() const;
	virtual SidebarContextSensitivity contextSensitivity() const;
	virtual bool alwaysShowTabs() const { return false; }
	virtual bool hideIfNoContent() const { return false; }

	virtual SidebarWidget* createWidget(ViewFrame* /*frame*/, BinaryViewRef /*data*/) { return nullptr; }
	virtual SidebarWidget* createInvalidContextWidget();
	virtual QWidget* headerWidget(SplitPaneWidget* /*panes*/, ViewFrame* /*frame*/, BinaryViewRef /*data*/)
	{
		return nullptr;
	}
	virtual bool focusHeaderWidget() const { return false; }
	virtual QString noWidgetMessage() const { return "No content active"; }
	virtual DockableTabStyle* tabStyle() const;

	virtual bool canUseAsPane(SplitPaneWidget* /*panes*/, BinaryViewRef /*data*/) const { return false; }
	virtual Pane* createPane(SplitPaneWidget* /*panes*/, BinaryViewRef /*data*/) { return nullptr; }

	void updateTheme();
};

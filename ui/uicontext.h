#pragma once

#include <QtWidgets/QWidget>
#include <QtCore/QMetaType>
#include <QtWidgets/QMainWindow>
#include <QtGui/QWheelEvent>
#include <QtCore/QSettings>
#include "binaryninjaapi.h"
#include "action.h"
#include "preview.h"
#include "uitypes.h"

#define PREVIEW_HOVER_TIME 500

typedef bool (*UIPluginInitFunction)(void);
typedef void (*UIPluginDependencyFunction)(void);
typedef uint32_t (*UIPluginABIVersionFunction)(void);

class ViewFrame;
class UIActionHandler;
class FileContext;
class ViewLocation;
class Sidebar;
class SidebarWidgetContainer;
class GlobalArea;
class Pane;
class ProjectStatusWidget;
struct SelectionInfoForXref;

/*!

	\defgroup uicontext UIContext
 	\ingroup uiapi
*/

/*!
    Interface used to receive notifications related to files and contexts. Many notifications include the ability
    to modify the behavior of the context.

    \ingroup uicontext
 */
class BINARYNINJAUIAPI UIContextNotification
{
  public:
	virtual ~UIContextNotification();

	/*!
	    Callback after a UIContext is opened (eg MainWindow)
	    \param context Opened context
	 */
	virtual void OnContextOpen(UIContext* context) { (void)context; }
	/*!
	    Callback right before closing a UIContext
	    \param context Closing context
	 */
	virtual void OnContextClose(UIContext* context) { (void)context; }

	/*!
	    Callback before a database (specifically a database, not a raw file) is opened
	    \param context Context opening the database
	    \param metadata Object with info about the database file
	    \return True if the database should be opened
	 */
	virtual bool OnBeforeOpenDatabase(UIContext* context, FileMetadataRef metadata)
	{
		(void)context;
		(void)metadata;
		return true;
	}
	/*!
	    Callback after a database (specifically a database, not a raw file) is opened
	    \param context Context which opened the database
	    \param metadata Object with info about the database file
	    \param data Raw data which is backed by the database
	    \return True if the database should be opened
	 */
	virtual bool OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data)
	{
		(void)context;
		(void)metadata;
		(void)data;
		return true;
	}
	/*!
	    Callback after a project is opened
	    \param context Context which opened the project
	    \param project Project that was opened
	    \param frame ViewFrame constructed to display the project
	 */
	virtual void OnAfterOpenProject(UIContext* context, ProjectRef project)
	{
		(void)context;
		(void)project;
	}
	/*!
	    Callback before a project file is opened
	    \param context Context opening the project file
	    \param projectFile Project file that is being opened
	    \return True if the project file should be opened
	 */
	virtual bool OnBeforeOpenProjectFile(UIContext* context, ProjectFileRef projectFile)
	{
		(void)context;
		(void)projectFile;
		return true;
	}
	/*!
	    Callback after a project file is opened
	    \param context Context which opened the project file
	    \param projectFile Project file that was opened
	    \param frame ViewFrame constructed to display the project file
	 */
	virtual void OnAfterOpenProjectFile(UIContext* context, ProjectFileRef projectFile, ViewFrame* frame)
	{
		(void)context;
		(void)projectFile;
		(void)frame;
	}
	/*!
	    Callback before a file (raw or database) is opened (after OnAfterOpenDatabase if opening a database)
	    \param context Context opening the file
	    \param file Context with the file and ui views
	    \return True if the file should be opened
	 */
	virtual bool OnBeforeOpenFile(UIContext* context, FileContext* file)
	{
		(void)context;
		(void)file;
		return true;
	}
	/*!
	    Callback after a file (raw or database) is opened
	    \param context Context which opened the file
	    \param file Context with the file and ui views
	    \param frame ViewFrame constructed to display the file
	 */
	virtual void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
	{
		(void)context;
		(void)file;
		(void)frame;
	}
	/*!
	    Callback before a file is saved (either as a database or raw)
	    \param context Context which is saving the file
	    \param file Context with the file and ui views
	    \param frame ViewFrame for the file
	    \return True if the file should be saved
	 */
	virtual bool OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
	{
		(void)context;
		(void)file;
		(void)frame;
		return true;
	}
	/*!
	    Callback after a file is saved (either as a database or raw)
	    \param context Context which saved the file
	    \param file Context with the file and ui views
	    \param frame ViewFrame for the file
	 */
	virtual void OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
	{
		(void)context;
		(void)file;
		(void)frame;
	}
	/*!
	    Callback before a file is closed
	    \param context Context which is closing the file
	    \param file Context with the file and ui views
	    \param frame ViewFrame for the file
	    \return True if the file should be closed
	 */
	virtual bool OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
	{
		(void)context;
		(void)file;
		(void)frame;
		return true;
	}
	/*!
	    Callback after a file is closed
	    \param context Context which closed the file
	    \param file Context with the file and ui views
	    \param frame ViewFrame which former showed the file (will be deleted after this)
	 */
	virtual void OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
	{
		(void)context;
		(void)file;
		(void)frame;
	}
	/*!
	    Callback after a ViewFrame is replaced in an open file (e.g. on Rebase or Sync)
	    \param context Context which replaced the view
	    \param file Context with the file and ui views
	    \param oldFrame Old ViewFrame being deleted
	    \param newFrame New ViewFrame being created
	 */
	virtual void OnViewReplaced(
		UIContext* context,
		FileContext* file,
		ViewFrame* oldFrame,
		ViewFrame* newFrame
	)
	{
		(void)context;
		(void)file;
		(void)oldFrame;
		(void)newFrame;
	}
	/*!
	    Callback after a BinaryView is replaced in an open file (e.g. on Rebase)
	    \param context Context which replaced the view
	    \param file Context with the file and ui views
	    \param oldData Old BinaryView with that name
	    \param newData New BinaryView with that name
	 */
	virtual void OnDataViewReplaced(UIContext* context, FileContext* file, BinaryViewRef oldData, BinaryViewRef newData)
	{
		(void)context;
		(void)file;
		(void)oldData;
		(void)newData;
	}
	/*!
	    Callback when the ui changes views
	    \param context Context changing views
	    \param frame ViewFrame which changed views
	    \param type New view name
	 */
	virtual void OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
	{
		(void)context;
		(void)frame;
		(void)type;
	}
	/*!
	    Callback when the ui changes address
	    \param context Context changing address
	    \param frame ViewFrame which changed address
	    \param view Currently open View
	    \param location New location
	 */
	virtual void OnAddressChange(UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location)
	{
		(void)context;
		(void)frame;
		(void)view;
		(void)location;
	}

	/*!
	    Callback to modify the displayed file name for a FileContext (eg in the window title or tab title)
	    Note: Due to the out param &name, this is not usable from Python with PySide
	    \param context Context which will display this name
	    \param file File whose name to get
	    \param name [Out] Name to be displayed
	    \return True if the value in name should be used
	 */
	virtual bool GetNameForFile(UIContext* context, FileContext* file, QString& name)
	{
		(void)context;
		(void)file;
		(void)name;
		return false;
	}
	/*!
	    Callback to modify the displayed file name for a file path (eg in the new tab widget)
	    Note: Due to the out param &name, this is not usable from Python with PySide
	    \param context Context which will display this name
	    \param path Path to file whose name to get
	    \param name [Out] Name to be displayed
	    \return True if the value in name should be used
	 */
	virtual bool GetNameForPath(UIContext* context, const QString& path, QString& name)
	{
		(void)context;
		(void)path;
		(void)name;
		return false;
	}

	/*!
	    Callback when the ui changes selection and should update cross references
	    \param context Context changing selection
	    \param frame ViewFrame which changed selection
	    \param view View that changed selection
	    \param selection New selection
	 */
	virtual void OnNewSelectionForXref(
	    UIContext* context, ViewFrame* frame, View* view, const SelectionInfoForXref& selection)
	{
		(void)context;
		(void)frame;
		(void)view;
		(void)selection;
	}

	/*!
	    Callback when an action is executed, allowing plugins to intercept and modify
	    the behavior of the action. Plugins may modify the `action` parameter and
	    specify new behavior for the action to execute, which will happen immediately
	    after all registered notifications have been notified.

	    The original behavior (potentially modified by another notification) can be
	    executed by saving a copy of the value of `action` and calling it from within
	    your modified value.

	    \param context
	    \param handler
	    \param name
	    \param ctx
	    \param action
	 */
	virtual void OnActionExecuted(UIContext* context, UIActionHandler* handler, const QString& name, const UIActionContext& ctx, std::function<void(const UIActionContext&)>& action)
	{
		(void)context;
		(void)handler;
		(void)name;
		(void)ctx;
		(void)action;
	}

	/*!
	    Callback when a context menu is created, allowing plugins to modify the menu,
	    e.g., registering and adding new actions into it. This allow plugins to add
	    new entries into the top-level context menu in a non-hacky way. However, it
	    is advised that the plugin should only use this instead of PluginCommand::Register
	    or similar APIs when it is necessary. Besides, if a plugins wishes to add multiple
	    actions, it is better to put them as sub-menus under a single top-level entry,
	    avoiding making the context menu crowded.

		This only works for linear/graph/hex/types/stack view due to the way other views
	 	create the context menus.

	    \param context
	    \param view
	    \param menu
	 */
	virtual void OnContextMenuCreated(UIContext* context, View* view, Menu& menu)
	{
		(void)context;
		(void)view;
		(void)menu;
	}
};

/*!

    \ingroup uicontext
*/
class BINARYNINJAUIAPI UIContextHandler
{
  public:
	virtual ~UIContextHandler();
	virtual void updateStatus() = 0;
	virtual void notifyThemeChanged() = 0;
	virtual void registerFileOpenMode(const QString& buttonName, const QString& description, const QString& action);
};

/*!

    \ingroup uicontext
*/
class BINARYNINJAUIAPI UIContext
{
	static UIContextHandler* m_handler;
	static std::set<UIContext*> m_contexts;
	UIActionHandler m_globalActions;
	static std::list<UIContextNotification*> m_notifications;

	static QPointer<PreviewWidget> m_currentPreview;

	QSettings m_qsettings;

  protected:
	void setupUIContext(QWidget* obj);

public:
	UIContext();
	virtual ~UIContext();

	virtual QMainWindow* mainWindow() = 0;
	virtual void releaseBinaryView(BinaryViewRef view);
	virtual void viewChanged(ViewFrame* frame, const QString& type);
	virtual bool navigateForBinaryView(BinaryViewRef view, uint64_t addr);
	/*!
	    Navigate to a named type in the context, optionally at a member offset
	    \param name Name of type to which to navigate
	    \param offset Offset of member in type to which to navigate
	    \return True if navigation succeeded
	 */
	virtual bool navigateToType(const std::string& name, uint64_t offset = 0) = 0;

	/*!
	    Get a list of all opened binary views, and their names
	    \return List of binary views and names
	 */
	virtual std::vector<std::pair<BinaryViewRef, QString>> getAvailableBinaryViews() = 0;

	/*!
		Gets the tab for for a given sessionId
	 */
	virtual QWidget* getTabForSessionId(uint64_t sessionId) = 0;

	/*!
		Gets the name of a tab for the given session
	 */
	virtual QString getTabNameForSessionId(uint64_t sessionId) = 0;

	/*!
	    Get the currently visible View for the currently visible ViewFrame (if it exists)
	    \return Current View or nullptr if the current ViewFrame is null or does not have a View
	 */
	virtual View* getCurrentView() = 0;
	/*!
	    Get the currently visible ViewFrame (if it exists)
	    \return Current ViewFrame or nullptr if the current widget does not have a ViewFrame
	 */
	virtual ViewFrame* getCurrentViewFrame() = 0;
	/*!
	    Get the current Action Handler for the focused widget
	    \return Current Action Handler if the focused widget (or one of its parents) has one, else nullptr
	 */
	virtual UIActionHandler* getCurrentActionHandler() = 0;

	/*!
	    Open a tab containing the given widget with the given name
	    \param name Name for tab
	    \param widget Widget to display in the tab (optionally a ViewFrame)
	    \return Index of created tab
	 */
	virtual int createTabForWidget(const QString& name, QWidget* widget) = 0;

	/*!
	 * Open a new window with the same file context and Navigate to a given location
	 * @param location
	 */
	virtual void splitToNewWindowAndNavigateToLocation(uint64_t location) = 0;

	/*!
	 * Open a new tab with the same file context and Navigate to a given location
	 * @param location
	 */
	virtual void splitToNewTabAndNavigateToLocation(uint64_t location) = 0;

	/*!
		Open a new pane in the active tab
		\param pane Pane widget to open
		\param primaryDirection Primary axis for content in pane (determines default split direction)
	 */
	virtual void openPane(Pane* pane, Qt::Orientation primaryDirection = Qt::Vertical) = 0;
	/*!
	    Get a list of all tabs as QWidgets
	    \return All tabs
	 */
	virtual QList<QWidget*> getTabs() = 0;
	/*!
	    Get the QWidget responsible for the tab with the given name
	    \param name Name of tab to get
	    \return QWidget of tab if one with that name exists
	 */
	virtual QWidget* getTabForName(const QString& name) = 0;
	/*!
	    Get the QWidget responsible for the tab with the given file
	    \param file File of tab to get
	    \return QWidget of tab if one with that file exists
	 */
	virtual QWidget* getTabForFile(FileContext* file) = 0;
	/*!
	    Get the name of the tab with the given QWidget
	    \param tab QWidget which is in a tab
	    \return Name of the tab, or empty string if no tab is found
	 */
	virtual QString getNameForTab(QWidget* tab) = 0;
	/*!
	    Activate and make visible the tab with the given QWidget
	    \param tab QWidget which is in a tab
	 */
	virtual void activateTab(QWidget* tab) = 0;
	/*!
	    Close the tab with the given QWidget
	    \param tab QWidget which is in a tab
	    \param closeWindowIfLast If false, displays the new tab page if the widget was the last tab
	 */
	virtual void closeTab(QWidget* tab, bool closeWindowIfLast = false) = 0;
	/*!
	    Get the QWidget in the currently open tab
	    \return QWidget for current tab. Qt claims "this value is never 0 (but if you try hard enough, it can be)"
	 */
	virtual QWidget* getCurrentTab() = 0;

	virtual QWidget* createNewTab(bool focus = true) = 0;

	/*!
	    Get the current View associated with the given QWidget, if it exists
	    \param tab QWidget which could be a ViewFrame
	    \return View for the QWidget, or nullptr if the QWidget is not a ViewFrame or does not have a View
	 */
	virtual View* getViewForTab(QWidget* tab) = 0;
	/*!
	    Get the active ViewFrame associated with the given QWidget, if it exists
	    \param tab QWidget which could be a ViewFrame
	    \return ViewFrame for the QWidget (which is likely itself), or nullptr if the QWidget is not a ViewFrame
	 */
	virtual ViewFrame* getViewFrameForTab(QWidget* tab) const = 0;

	/*!
	    Get all ViewFrame instances associated with the given QWidget, if they exist
	    \param tab QWidget which could contain a ViewFrame
	    \return List of ViewFrame objects for the QWidget
	 */
	virtual std::vector<ViewFrame*> getAllViewFramesForTab(QWidget* tab) const = 0;

	virtual ProjectRef getProject();
	virtual ProjectStatusWidget* getProjectStatusWidget();

	virtual bool openFilename(const QString& path, bool openOptions = false);
	virtual ProjectRef openProject(const QString& path);
	virtual ViewFrame* openFileContext(FileContext* file, const QString& forcedView = "", bool addTab = true);
	virtual bool openProjectFile(ProjectFileRef file, ExternalLocationRef loc = nullptr, bool openWithOptions = false);
	virtual bool openUrl(const QUrl& url, bool openWithOptions = false);
	virtual void recreateViewFrames(FileContext* file) = 0;

	UIActionHandler* globalActions() { return &m_globalActions; }
	virtual UIActionHandler* contentActionHandler() = 0;

	virtual Sidebar* sidebar() = 0;
	virtual GlobalArea* globalArea() = 0;

	void NotifyOnContextOpen();
	void NotifyOnContextClose();

	bool NotifyOnBeforeOpenDatabase(FileMetadataRef metadata);
	bool NotifyOnAfterOpenDatabase(FileMetadataRef metadata, BinaryViewRef data);
	void NotifyOnAfterOpenProject(ProjectRef project);
	bool NotifyOnBeforeOpenProjectFile(ProjectFileRef projectFile);
	void NotifyOnAfterOpenProjectFile(ProjectFileRef projectFile, ViewFrame* frame);
	bool NotifyOnBeforeOpenFile(FileContext* file);
	void NotifyOnAfterOpenFile(FileContext* file, ViewFrame* frame);
	bool NotifyOnBeforeSaveFile(FileContext* file, ViewFrame* frame);
	void NotifyOnAfterSaveFile(FileContext* file, ViewFrame* frame);
	bool NotifyOnBeforeCloseFile(FileContext* file, ViewFrame* frame);
	void NotifyOnAfterCloseFile(FileContext* file, ViewFrame* frame);
	void NotifyOnViewReplaced(FileContext* file, ViewFrame* oldFrame, ViewFrame* newFrame);
	void NotifyOnDataViewReplaced(FileContext* file, BinaryViewRef oldView, BinaryViewRef newView);

	void NotifyOnViewChange(ViewFrame* frame, const QString& type);
	void NotifyOnAddressChange(ViewFrame* frame, View* view, const ViewLocation& location);
	void updateCrossReferences(ViewFrame* frame, View* view, const SelectionInfoForXref& selection);
	void NotifyOnActionExecuted(UIActionHandler* handler, const QString& name, const UIActionContext& ctx, std::function<void(const UIActionContext&)>& action);
	void NotifyOnContextMenuCreated(View* view, Menu& menu);

	virtual void findAll(const BinaryNinja::FindParameters& params);

	/*!
	    Register an object to receive notifications of UIContext events
	    \param notification Object which will receive notifications
	 */
	static void registerNotification(UIContextNotification* notification);
	/*!
	    Unregister an object from receiving notifications of UIContext events
	    \param notification Object which will no longer receive notifications
	 */
	static void unregisterNotification(UIContextNotification* notification);

	/*!
	    Get the displayed name for a given file
	    \param file File whose displayed name to get
	    \return Name to display for this file
	 */
	QString GetNameForFile(FileContext* file);
	/*!
	    Get the displayed name for a path to a file
	    \param path Path to file whose displayed name you want
	    \return Name to display for this path
	 */
	QString GetNameForPath(const QString& path);

	virtual QWidget* fileContentsLockStatusWidget() = 0;

	void associateAdditionalWindowWithContext(QWidget* window);
	static void deassociateAdditionalWindowWithContext(QWidget* window);

	static void setHandler(UIContextHandler* handler);

	static QSize getScaledWindowSize(int x, int y);
	static void updateStatus();
	static void notifyThemeChanged();
	static void showPreview(QWidget* parent, PreviewWidget* preview, QPoint localPos, bool anchorAtPoint = false);
	static void closePreview();
	static bool sendPreviewWheelEvent(QWheelEvent* event);
	static void closeOtherActiveModalWidget(QWidget* current);
	static void registerFileOpenMode(const QString& buttonName, const QString& description, const QString& action);

	static UIContext* contextForWidget(QWidget* widget);
	static UIContext* activeContext();
	static std::set<UIContext*> allContexts();

	static QWidget* topLevelAt(const QPoint& pt, QWidget* ignoreWidget = nullptr);

	static QRect placeNewTopLevelWindow(QScreen* screen, const QPoint& pos, QWidget* existingWidget);

	static ViewFrame* currentViewFrameForWidget(QWidget* widget);
};

Q_DECLARE_METATYPE(UIContext*)

/*!
    @addtogroup uicontext
    @{
*/
void BINARYNINJAUIAPI InitUIViews();
void BINARYNINJAUIAPI InitUIActions();

void BINARYNINJAUIAPI InitUIPlugins();
void BINARYNINJAUIAPI SetCurrentUIPluginLoadOrder(BNPluginLoadOrder order);
void BINARYNINJAUIAPI AddRequiredUIPluginDependency(const std::string& name);
void BINARYNINJAUIAPI AddOptionalUIPluginDependency(const std::string& name);

/*!
	@}
*/

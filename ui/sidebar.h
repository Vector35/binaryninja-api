#pragma once

#include <QtWidgets/QSplitter>
#include <QtCore/QSettings>
#include "sidebarwidget.h"
#include "sidebarcontainer.h"
#include "sidebaricons.h"
#include "splitter.h"

class ViewFrame;

/*!
    \ingroup sidebar
*/
struct BINARYNINJAUIAPI SidebarMetrics
{
	int iconWidth, iconHeight;
	int paddingX, paddingY;
	int separatorPadding;
	int iconTotalWidth, iconTotalHeight;
	int dragIconPadding;
	int dropIconPadding;
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI Sidebar : public QObject
{
	Q_OBJECT

	struct SavedTypeOrderingInfo
	{
		QString typeName;
		bool isDefaultArea;
	};

	SidebarIconsWidget* m_left;
	SidebarIconsWidget* m_right;
	Splitter* m_parentSideSplitter = nullptr;
	Splitter* m_parentExtendedSideSplitter = nullptr;
	Splitter* m_parentBottomSplitter = nullptr;
	Splitter* m_parentBottomSeparatorSplitter = nullptr;

	SplitPaneWidget* m_panes = nullptr;
	ViewFrame* m_frame = nullptr;
	QString m_dataType;
	BinaryViewRef m_data;

	std::map<SplitPaneWidget*, std::map<QString, QVariantMap>> m_priorParentSideSplitterSizes;
	std::map<SplitPaneWidget*, std::map<QString, QVariantMap>> m_priorParentExtendedSideSplitterSizes;
	std::map<SplitPaneWidget*, std::map<QString, QVariantMap>> m_priorParentBottomSplitterSizes;
	std::map<SplitPaneWidget*, std::map<QString, QVariantMap>> m_priorParentBottomSeparatorSplitterSizes;
	std::map<SplitPaneWidget*, std::map<ViewFrame*, std::map<QString, std::pair<View*, ViewLocation>>>>
		m_currentViewLocation;
	std::set<SidebarWidgetType*> m_toggledWidgets;

	static std::map<SidebarWidgetLocation, std::vector<SidebarWidgetType*>> m_types;
	static std::map<SidebarWidgetLocation, std::vector<SavedTypeOrderingInfo>> m_savedTypeOrdering;
	static std::set<Sidebar*> m_instances;
	static std::set<SidebarWidgetType*> m_defaultTypes;
	static std::optional<SidebarMetrics> m_metrics;

private Q_SLOTS:
	void containerUpdated();

public:
	Sidebar(QWidget* parent);
	virtual ~Sidebar();

	SidebarIconsWidget* left() const { return m_left; }
	SidebarIconsWidget* right() const { return m_right; }
	static SidebarWidgetLocation locationForType(SidebarWidgetType* type);
	static SidebarLocation sideForLocation(SidebarWidgetLocation location);
	static SidebarContainerLocation containerLocationForWidgetLocation(SidebarWidgetLocation location);
	SidebarWidgetContainer* containerForLocation(SidebarWidgetLocation location) const;
	static Qt::Orientation primaryOrientationForLocation(SidebarWidgetLocation location);
	void forAllContainers(const std::function<void(SidebarWidgetContainer*)>& func) const;

	void setSplitters(Splitter* sideSplitter, Splitter* extendedSideSplitter, Splitter* bottomSplitter,
		Splitter* bottomSeparatorSplitter);

	void setActiveContext(SplitPaneWidget* panes, ViewFrame* frame, const QString& dataType, BinaryViewRef data);
	void destroyContext(ViewFrame* frame);
	void destroyContext(SplitPaneWidget* panes);
	void moveContextToContainer(SplitPaneWidget* panes, Sidebar* target);

	SplitPaneWidget* currentPanes(SidebarWidgetType* type = nullptr) const;
	ViewFrame* currentFrame(SidebarWidgetType* type = nullptr) const;
	const QString& currentDataType(SidebarWidgetType* type = nullptr) const;
	BinaryViewRef currentData(SidebarWidgetType* type = nullptr) const;
	std::optional<std::pair<View*, ViewLocation>> currentViewLocation() const;

	SidebarWidget* widget(SidebarWidgetType* type);
	SidebarWidget* widget(const QString& name);
	SidebarWidgetAndHeader* widgetAndHeader(SidebarWidgetType* type);
	SidebarWidgetAndHeader* widgetAndHeader(const QString& name);

	void addWidget(SidebarWidgetType* type, SidebarWidget* widget, bool canClose = false);
	void addWidget(const QString& name, SidebarWidget* widget, bool canClose = false);
	void removeWidget(SidebarWidgetType* type, SidebarWidget* widget);
	void removeWidget(const QString& typeName, SidebarWidget* widget);
	SidebarWidget* widgetWithTitle(SidebarWidgetType* type, const QString& title) const;
	SidebarWidget* widgetWithTitle(const QString& typeName, const QString& title) const;
	bool hasWidgetWithTitle(SidebarWidgetType* type, const QString& title) const;
	bool hasWidgetWithTitle(const QString& typeName, const QString& title) const;
	void focusWidgetWithTitle(SidebarWidgetType* type, const QString& title);
	void focusWidgetWithTitle(const QString& typeName, const QString& title);

	void activate(SidebarWidgetType* type, bool alwaysAllowMultipleOpen = true);
	void activate(const QString& name, bool alwaysAllowMultipleOpen = true);
	void activateDefaultTypes();
	void deactivate(SidebarWidgetType* type);
	void deactivate(const QString& name);
	void focus(SidebarWidgetType* type);
	void focus(const QString& name);
	void toggle(SidebarWidgetType* type);
	void toggle(const QString& name);
	bool isActive(SidebarWidgetType* type) const;
	bool isActive(const QString& name) const;
	bool isContentActive() const;
	bool isSideContentActive() const;
	bool isBottomContentActive() const;

	void updateTheme();
	void updateFonts();

	void toggleSidebar();

	void updateViewLocation(View* view, const ViewLocation& viewLocation);
	void viewChanged();

	void saveState(QSettings& settings, const QString& windowStateName, bool globalStateOnly = false);
	QVariant saveActiveState();
	void restoreState(const QSettings& settings, const QString& windowStateName, bool globalStateOnly = false);
	bool restoreActiveState(const QVariant& state);

	static void addSidebarWidgetType(SidebarWidgetType* type);
	static void moveSidebarWidgetType(SidebarWidgetType* type, SidebarWidgetLocation newLocation, size_t newIndex);
	static SidebarWidgetType* typeFromName(const QString& name);
	static bool isTypeRegistered(const QString& name);
	static std::vector<SidebarWidgetType*> types();
	static const std::vector<SidebarWidgetType*>& typesForLocation(SidebarWidgetLocation location);
	static std::vector<SidebarWidgetType*> typesForContainerLocation(SidebarContainerLocation location);
	static void initSavedTypeOrdering();
	static void saveTypeOrdering();

	static SidebarMetrics metrics();
	static void refreshMetrics();

	static std::set<SidebarWidgetType*> defaultTypes() { return m_defaultTypes; }
	static void setDefaultTypes(const std::set<SidebarWidgetType*>& types) { m_defaultTypes = types; }

	static Sidebar* current()
	{
		UIContext* context = UIContext::activeContext();
		if (!context)
			return nullptr;
		return context->sidebar();
	}

	template <class T>
	static T* widget(SidebarWidgetType* type)
	{
		Sidebar* sidebar = current();
		if (!type || !sidebar || !sidebar->isActive(type))
			return (T*)nullptr;
		QWidget* widget = sidebar->widget(type);
		if (!widget)
			return (T*)nullptr;
		return qobject_cast<T*>(widget);
	}

	template <class T>
	static T* widget(const QString& name)
	{
		return widget<T>(Sidebar::typeFromName(name));
	}

	template <class T>
	static T* activateWidget(SidebarWidgetType* type)
	{
		Sidebar* sidebar = current();
		if (!type || !sidebar)
			return (T*)nullptr;
		sidebar->activate(type);
		QWidget* widget = sidebar->widget(type);
		if (!widget)
			return (T*)nullptr;
		T* result = qobject_cast<T*>(widget);
		if (!result)
			return (T*)nullptr;
		return result;
	}

	template <class T>
	static T* activateWidget(const QString& name)
	{
		return activateWidget<T>(Sidebar::typeFromName(name));
	}

	template <class T>
	static UIAction globalSidebarAction(const QString& name, const std::function<void(T* obj)>& activate)
	{
		return globalSidebarAction<T>(
		    name, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalSidebarAction(
	    const QString& name, const std::function<void(T* obj, const UIActionContext& ctxt)>& activate)
	{
		return globalSidebarAction<T>(name, activate, [](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalSidebarAction(
	    const QString& name, const std::function<void(T* obj)>& activate, const std::function<bool(T* obj)>& isValid)
	{
		return globalSidebarAction<T>(
		    name, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T* obj, const UIActionContext&) { return isValid(obj); });
	}

	template <class T>
	static UIAction globalSidebarAction(const QString& name,
	    const std::function<void(T* obj, const UIActionContext& ctxt)>& activate,
	    const std::function<bool(T* obj, const UIActionContext& ctxt)>& isValid)
	{
		return globalSidebarAction<T>(Sidebar::typeFromName(name), activate, isValid);
	}

	template <class T>
	static UIAction globalSidebarAction(SidebarWidgetType* type, const std::function<void(T* obj)>& activate)
	{
		return globalSidebarAction<T>(
		    type, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalSidebarAction(
	    SidebarWidgetType* type, const std::function<void(T* obj, const UIActionContext& ctxt)>& activate)
	{
		return globalSidebarAction<T>(type, activate, [](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalSidebarAction(SidebarWidgetType* type, const std::function<void(T* obj)>& activate,
	    const std::function<bool(T* obj)>& isValid)
	{
		return globalSidebarAction<T>(
		    type, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T* obj, const UIActionContext&) { return isValid(obj); });
	}

	template <class T>
	static UIAction globalSidebarAction(SidebarWidgetType* type,
	    const std::function<void(T* obj, const UIActionContext& ctxt)>& activate,
	    const std::function<bool(T* obj, const UIActionContext& ctxt)>& isValid)
	{
		std::function<T*(const UIActionContext& ctxt)> lookup = [=](const UIActionContext& ctxt) {
			if (!type || !ctxt.context)
				return (T*)nullptr;
			Sidebar* sidebar = ctxt.context->sidebar();
			if (!sidebar->isActive(type))
				return (T*)nullptr;
			QWidget* widget = sidebar->widget(type);
			if (!widget)
				return (T*)nullptr;
			return qobject_cast<T*>(widget);
		};
		return UIAction(
		    [=](const UIActionContext& ctxt) {
			    T* obj = lookup(ctxt);
			    if (obj)
				    activate(obj, ctxt);
		    },
		    [=](const UIActionContext& ctxt) {
			    T* obj = lookup(ctxt);
			    if (obj)
				    return isValid(obj, ctxt);
			    return false;
		    });
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalSidebarActionChecked(
	    const QString& name, const std::function<bool(T* obj)>& isChecked)
	{
		return globalSidebarActionChecked<T>(name, [=](T* obj, const UIActionContext&) { return isChecked(obj); });
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalSidebarActionChecked(
	    const QString& name, const std::function<bool(T* obj, const UIActionContext& ctxt)>& isChecked)
	{
		return globalSidebarActionChecked<T>(Sidebar::typeFromName(name), isChecked);
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalSidebarActionChecked(
	    SidebarWidgetType* type, const std::function<bool(T* obj)>& isChecked)
	{
		return globalSidebarActionChecked<T>(type, [=](T* obj, const UIActionContext&) { return isChecked(obj); });
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalSidebarActionChecked(
	    SidebarWidgetType* type, const std::function<bool(T* obj, const UIActionContext& ctxt)>& isChecked)
	{
		return [=](const UIActionContext& ctxt) {
			if (!type || !ctxt.context)
				return false;
			Sidebar* sidebar = ctxt.context->sidebar();
			if (!sidebar->isActive(type))
				return false;
			QWidget* widget = sidebar->widget(type);
			if (!widget)
				return false;
			T* obj = qobject_cast<T*>(widget);
			if (obj)
				return isChecked(obj, ctxt);
			return false;
		};
	}
};

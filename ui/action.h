#pragma once

#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtGui/QIcon>
#include <QtWidgets/QShortcut>
#include <QtCore/QPointer>
#include <functional>
#include <map>
#include <set>
#include <vector>
#include "uitypes.h"

#define MENU_ORDER_FIRST 0
#define MENU_ORDER_EARLY 64
#define MENU_ORDER_NORMAL 128
#define MENU_ORDER_LATE 192
#define MENU_ORDER_LAST 255

class View;
class UIContext;
struct LinearViewCursorPosition;

struct BINARYNINJAUIAPI HighlightTokenState
{
	bool valid;
	bool secondaryHighlight;
	BNInstructionTextTokenType type;
	BinaryNinja::InstructionTextToken token;
	ArchitectureRef arch;
	bool addrValid, localVarValid, isDest;
	uint64_t addr;
	BinaryNinja::Variable localVar;
	size_t tokenIndex;

	HighlightTokenState();
};


struct BINARYNINJAUIAPI UIActionContext
{
	UIContext* context;
	View* view;
	QWidget* widget;
	HighlightTokenState token;

	BinaryViewRef binaryView;
	uint64_t address, length;
	size_t instrIndex;
	FunctionRef function;
	LowLevelILFunctionRef lowLevelILFunction;
	MediumLevelILFunctionRef mediumLevelILFunction;
	LinearViewCursorPosition* cursorPosition;

	UIActionContext();
	UIActionContext(const BinaryNinja::PluginCommandContext& pluginContext);
	operator BinaryNinja::PluginCommandContext() const;
};

struct BINARYNINJAUIAPI UIAction
{
	std::function<void (const UIActionContext& context)> activate;
	std::function<bool (const UIActionContext& context)> isValid;

	UIAction();
	UIAction(const std::function<void (const UIActionContext& context)>& activate);
	UIAction(const std::function<void()>& activate);
	UIAction(const std::function<void (const UIActionContext& context)>& activate,
		const std::function<bool (const UIActionContext& context)>& isValid);
	UIAction(const std::function<void()>& activate,
		const std::function<bool (const UIActionContext& context)>& isValid);
	UIAction(const std::function<void (const UIActionContext& context)>& activate,
		const std::function<bool()>& isValid);
	UIAction(const std::function<void()>& activate,
		const std::function<bool()>& isValid);
	UIAction(const UIAction& other);
	UIAction& operator=(const UIAction& other);

	static void registerAction(const QString& name, const QKeySequence& defaultKeyBinding = QKeySequence());
	static void registerAction(const QString& name, const QList<QKeySequence>& defaultKeyBinding);
	static void unregisterAction(const QString& name);

	static void registerTransformActions();
	static void registerPluginCommandActions();
	static void registerPluginCommandActions(const QString& prefix);
	static void registerHighlightColorActions(const QString& prefix);
	static void registerBookmarkActions(const QString& prefix);

	static void setActionDisplayName(const QString& registeredName, const QString& displayName);
	static void setActionDisplayName(const QString& registeredName, const std::function<QString()>& displayNameFunc);
	static void setActionDisplayName(const QString& registeredName, const std::function<QString(const UIActionContext&)>& displayNameFunc);

	static bool isActionRegistered(const QString& name);
	static std::set<QString> getAllRegisteredActions();
	static QList<QKeySequence> getDefaultKeyBinding(const QString& name);
	static QList<QKeySequence> getKeyBinding(const QString& name);
	static QString getActionDisplayName(const QString& name, const UIActionContext& context);

	static int rawControl();
	static int rawMeta();

	static void setUserKeyBinding(const QString& name, const QList<QKeySequence>& keyBinding);
	static void resetKeyBindingToDefault(const QString& name);
	static void readKeyBindingsFile();
	static void writeKeyBindingsFile();
};

struct BINARYNINJAUIAPI UITransformAction
{
	std::function<void (const UIActionContext& context, TransformRef xform)> activate;
	std::function<bool (const UIActionContext& context, TransformRef xform)> isValid;

	UITransformAction();
	UITransformAction(const std::function<void (const UIActionContext& context, TransformRef xform)>& activate);
	UITransformAction(const std::function<void(TransformRef xform)>& activate);
	UITransformAction(const std::function<void (const UIActionContext& context, TransformRef xform)>& activate,
		const std::function<bool (const UIActionContext& context, TransformRef xform)>& isValid);
	UITransformAction(const std::function<void(TransformRef xform)>& activate,
		const std::function<bool (const UIActionContext& context, TransformRef xform)>& isValid);
	UITransformAction(const std::function<void (const UIActionContext& context, TransformRef xform)>& activate,
		const std::function<bool(TransformRef xform)>& isValid);
	UITransformAction(const std::function<void(TransformRef xform)>& activate,
		const std::function<bool(TransformRef xform)>& isValid);
	UITransformAction(const UITransformAction& other);
};

struct BINARYNINJAUIAPI UIHighlightColorAction
{
	std::function<void (const UIActionContext& context, BNHighlightColor color)> activate;
	std::function<bool (const UIActionContext& context)> isValid;

	UIHighlightColorAction();
	UIHighlightColorAction(const std::function<void (const UIActionContext& context, BNHighlightColor color)>& activate);
	UIHighlightColorAction(const std::function<void(BNHighlightColor color)>& activate);
	UIHighlightColorAction(const std::function<void (const UIActionContext& context, BNHighlightColor color)>& activate,
		const std::function<bool (const UIActionContext& context)>& isValid);
	UIHighlightColorAction(const std::function<void(BNHighlightColor color)>& activate,
		const std::function<bool (const UIActionContext& context)>& isValid);
	UIHighlightColorAction(const std::function<void (const UIActionContext& context, BNHighlightColor color)>& activate,
		const std::function<bool()>& isValid);
	UIHighlightColorAction(const std::function<void(BNHighlightColor color)>& activate,
		const std::function<bool()>& isValid);
	UIHighlightColorAction(const UIHighlightColorAction& other);
};

struct BINARYNINJAUIAPI UIBookmarkAction
{
	std::function<void (const UIActionContext& context, int index)> activate;
	std::function<bool (const UIActionContext& context, int index)> isValid;

	UIBookmarkAction(const std::function<void (const UIActionContext& context, int index)>& activate, const std::function<bool (const UIActionContext& context, int index)>& isValid);
};

enum ActionPriority
{
	LowActionPriority,
	NormalActionPriority,
	HighActionPriority
};

class BINARYNINJAUIAPI UIActionHandler
{
	std::map<QString, UIAction> m_actions;
	std::map<QString, ActionPriority> m_priority;
	std::map<QString, std::function<QString(const UIActionContext&)>> m_actionDisplayNames;
	std::map<QString, std::function<bool(const UIActionContext&)>> m_checked;
	QWidget* m_handlerWidget;
	std::map<QString, std::vector<QShortcut*>> m_handlerWidgetShortcuts;
	UIActionHandler* m_parent;
	std::set<UIActionHandler*> m_children;
	bool m_isGlobal, m_inheritParentBindings;
	std::function<UIActionContext()> m_actionContextOverride;

	static std::map<QString, std::set<UIActionHandler*>> m_actionBindings;
	static std::set<QString> m_globalMenuActions;

	void bindActionShortcutToWidget(const QString& name);
	void unbindActionShortcut(const QString& name);
	void addActionToChildren(const QString& name);
	void removeActionFromChildren(const QString& name);

public:
	UIActionHandler(bool isGlobal = false);
	virtual ~UIActionHandler();
	void setupActionHandler(QWidget* obj, bool inheritParentBindings = true);

	static UIActionHandler* actionHandlerFromWidget(QWidget* widget);
	static UIActionHandler* globalActions();

	void bindAction(const QString& name, const UIAction& action);
	void bindAction(const QString& name, const UIAction& action, ActionPriority priority);
	void unbindAction(const QString& name);

	void executeAction(const QString& name);
	void executeAction(const QString& name, const UIActionContext& context);
	bool isBoundAction(const QString& name);
	bool isValidAction(const QString& name);
	bool isValidAction(const QString& name, const UIActionContext& context);
	ActionPriority getPriority(const QString& name);

	void bindCopyAsActions(const UITransformAction& action);
	void bindPasteFromActions(const UITransformAction& action);
	void bindTransformActions(const UITransformAction& encode, const UITransformAction& decode);
	void unbindCopyAsActions();
	void unbindPasteFromActions();
	void unbindTransformActions();

	void bindPluginCommandActions();
	void bindPluginCommandActions(const QString& prefix,
		const std::function<UIActionContext(const UIActionContext&, const BinaryNinja::PluginCommand&)>& context,
		const std::function<bool(const UIActionContext&, const BinaryNinja::PluginCommand&)>& isValid);
	void unbindPluginCommandActions();
	void unbindPluginCommandActions(const QString& prefix);

	void bindHighlightColorActions(const QString& prefix, const UIHighlightColorAction& action);
	void unbindHighlightColorActions(const QString& prefix);

	void bindBookmarkActions(const QString& prefix, const UIBookmarkAction& action);
	void unbindBookmarkActions(const QString& prefix);

	void setActionDisplayName(const QString& registeredName, const QString& displayName);
	void setActionDisplayName(const QString& registeredName, const std::function<QString()>& displayNameFunc);
	void setActionDisplayName(const QString& registeredName, const std::function<QString(const UIActionContext&)>& displayNameFunc);
	QString getActionDisplayName(const QString& name);
	QString getActionDisplayName(const QString& name, const UIActionContext& context);

	void setChecked(const QString& name, bool checked);
	void setChecked(const QString& name, const std::function<bool()>& checked);
	void setChecked(const QString& name, const std::function<bool(const UIActionContext&)>& checked);
	bool isChecked(const QString& name);
	bool isChecked(const QString& name, const UIActionContext& context);
	bool isCheckable(const QString& name);

	std::set<QString> getAllValidActions();
	std::set<QString> getAllValidActions(const UIActionContext& context);

	UIActionContext defaultActionContext();
	virtual UIActionContext actionContext();
	void setActionContext(const std::function<UIActionContext()>& contextFunc);

	QWidget* widget() { return m_handlerWidget; }

	static void updateActionBindings(const QString& name);
	static bool isActionBoundToAnyHandler(const QString& name);
	static void addGlobalMenuAction(const QString& name);
	static void removeGlobalMenuAction(const QString& name);

	static void reparentWidget(QWidget* widget);
};

enum MenuItemVisibility
{
	DefaultMenuItemVisibility,
	ShowMenuItemOnlyWhenActive,
	AlwaysShowMenuItem,
	NeverShowMenuItem
};

class MenuInstance;

class BINARYNINJAUIAPI Menu
{
	std::map<QString, QString> m_actions;
	std::map<QString, QString> m_groups;
	std::map<QString, uint8_t> m_order, m_groupOrder;
	std::map<QString, MenuItemVisibility> m_visibility;
	std::map<QString, QAction::MenuRole> m_roles;
	std::map<QString, QIcon> m_icons;
	uint64_t m_version;
	bool m_global;

	Menu(bool global);
	void setParentOrdering(const QString& path, const QString& group, uint8_t order);

public:
	Menu();
	Menu(const Menu& menu);

	void addAction(const QString& action, const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void addAction(const QString& submenu, const QString& action, const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void removeAction(const QString& action);
	void removeAction(const QString& submenu, const QString& action);

	void addCopyAsActions(const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void addPasteFromActions(const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void addTransformActions(const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void removeCopyAsActions();
	void removePasteFromActions();
	void removeTransformActions();

	void addPluginCommandActions(const QString& group);
	void addPluginCommandActions(const QString& prefix, const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void addPluginCommandSubmenuActions(const QString& submenu, const QString& group);
	void addPluginCommandSubmenuActions(const QString& submenu, const QString& prefix, const QString& group,
		uint8_t order = MENU_ORDER_NORMAL);
	void removePluginCommandActions();
	void removePluginCommandSubmenuActions(const QString& submenu);

	void addHighlightColorActions(const QString& submenu, const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void removeHighlightColorActions(const QString& submenu);

	void setOrdering(const QString& path, const QString& group, uint8_t order = MENU_ORDER_NORMAL);
	void setGroupOrdering(const QString& group, uint8_t order);

	void setVisibility(const QString& path, MenuItemVisibility visibility);
	void setRole(const QString& path, QAction::MenuRole role);

	void setIcon(const QString& path, const QIcon& icon);

	MenuInstance* create(QWidget* owner, UIActionHandler* handler, bool showInactiveActions = false);
	MenuInstance* create(QWidget* owner, UIActionHandler* handler, const UIActionContext& context,
		bool showInactiveActions = false);

	uint64_t getVersion();
	const std::map<QString, QString>& getActions();
	QString getGroupForAction(const QString& name);
	uint8_t getOrderForAction(const QString& name);
	uint8_t getOrderForGroup(const QString& name);
	MenuItemVisibility getVisibility(const QString& name);
	QAction::MenuRole getRole(const QString& name);
	QIcon getIcon(const QString& name);

	static Menu* mainMenu(const QString& name);
	static void setMainMenuOrder(const QString& name, uint8_t order);
	static std::vector<QString> getMainMenus();
};

class BINARYNINJAUIAPI MenuInstance
{
	Menu* m_menu;
	QMenu* m_instance;
	UIActionHandler* m_handler;
	UIActionContext m_context;
	uint64_t m_version;
	std::map<QString, QPointer<QAction>> m_actions;

	struct Group;

	struct Item
	{
		QString name, action;
		uint8_t order;
		QAction::MenuRole role;
		QIcon icon;
		bool checkable;
		std::vector<Group> submenu;
	};

	struct Group
	{
		QString name;
		std::vector<Item> items;
		uint8_t order;
	};

	static std::map<QString, std::set<MenuInstance*>> m_actionBindings;

	std::vector<Group> layoutMenu(const std::map<QString, QString>& actions, const QString& prefix,
		bool showInactiveActions);
	void addGroupsToMenu(QMenu* menu, const std::vector<Group>& groups);

public:
	MenuInstance(Menu* menu, QMenu* instance);
	virtual ~MenuInstance();
	void update(UIActionHandler* handler, bool showInactiveActions = false);
	void update(UIActionHandler* handler, const UIActionContext& context, bool showInactiveActions = false);

	Menu* source() const { return m_menu; }
	QMenu* instance() const { return m_instance; }

	static void updateActionBindings(const QString& name);
};

class BINARYNINJAUIAPI MainMenuInstance
{
	QMenuBar* m_instance;
	std::map<QString, MenuInstance*> m_menus;

public:
	MainMenuInstance(QMenuBar* instance);
	~MainMenuInstance();
	void update(UIActionHandler* handler);
	void update(UIActionHandler* handler, const UIActionContext& context);
};

Q_DECLARE_METATYPE(UIActionHandler*)

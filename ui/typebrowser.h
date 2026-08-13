#pragma once

#include <QtWidgets/QTreeView>
#include <QtCore/QSortFilterProxyModel>
#include <QtGui/QStandardItemModel>
#include <QtWidgets/QItemDelegate>
#include <QtWidgets/QTextEdit>
#include <memory>
#include "sidebar.h"
#include "viewframe.h"
#include "filter.h"
#include "notificationsdispatcher.h"
#include "progresstask.h"
#include "typeeditor.h"


enum BINARYNINJAUIAPI TypeBrowserFilterMode
{
	NamesOnly = 0,
	NamesAndMembers = 1,
	FullDefinitions = 2
};


// A single container's types: type id -> (name, definition). This is a plain snapshot of
// TypeContainer::GetTypes() with no ties to live model/tree state, so it can be built on a
// background thread (the expensive part) and consumed by the tree diff on the main thread.
using TypeBrowserContainerTypes = std::map<std::string, std::pair<BinaryNinja::QualifiedName, TypeRef>>;
// All containers' pre-fetched types, keyed by container id.
using TypeBrowserTypeSnapshot = std::map<std::string, TypeBrowserContainerTypes>;


// A pure-data description of what changed between two snapshots, computed off the main thread
// (including the deep Type comparisons) so the main thread only has to apply it to the tree.
struct TypeBrowserTypeEntry
{
	std::string id;
	BinaryNinja::QualifiedName name;
	TypeRef type;
};

// Type-level changes within a single container.
struct TypeBrowserTypeDelta
{
	std::vector<std::string> removed;          // type ids that disappeared
	std::vector<TypeBrowserTypeEntry> added;   // types that appeared
	std::vector<TypeBrowserTypeEntry> updated; // types whose name or definition changed

	bool empty() const { return removed.empty() && added.empty() && updated.empty(); }
};

// The full delta applied to the tree in one update cycle.
struct TypeBrowserDelta
{
	std::vector<std::string> removedContainerIds;
	// Newly-added containers, in display order, each carrying its full type list.
	std::vector<std::pair<std::string, std::vector<TypeBrowserTypeEntry>>> addedContainers;
	// Type-level changes for containers that persist across the update.
	std::map<std::string, TypeBrowserTypeDelta> typeChanges;

	bool empty() const { return removedContainerIds.empty() && addedContainers.empty() && typeChanges.empty(); }
};


class BINARYNINJAUIAPI TypeBrowserTreeNode : public std::enable_shared_from_this<TypeBrowserTreeNode>
{
public:
	struct UpdateData
	{
		enum UpdateType
		{
			NodeInserted,
			NodeUpdated,
			NodeRemoved,
			UpdatesFinished,
		};

		UpdateType type;
		std::shared_ptr<TypeBrowserTreeNode> parent;
		std::shared_ptr<TypeBrowserTreeNode> node;
		std::function<void(const UpdateData&)> commit;
	};

	typedef std::function<void(UpdateData)> UpdateNodeCallback;

protected:
	class TypeBrowserModelData* m_model;
	std::optional<std::weak_ptr<TypeBrowserTreeNode>> m_parent;
	std::vector<std::shared_ptr<TypeBrowserTreeNode>> m_children;
	std::unordered_map<const TypeBrowserTreeNode*, size_t> m_childIndices;
	bool m_hasGeneratedChildren;

	TypeBrowserTreeNode(class TypeBrowserModelData* model, std::optional<std::weak_ptr<TypeBrowserTreeNode>> parent);
	virtual ~TypeBrowserTreeNode() = default;
	virtual void generateChildren() = 0;
	void updateChildIndices();

	void removeChild(std::shared_ptr<TypeBrowserTreeNode> child);
	void addChild(std::shared_ptr<TypeBrowserTreeNode> child);

public:
	class TypeBrowserModelData* model() const { return m_model; }
	std::optional<std::shared_ptr<TypeBrowserTreeNode>> parent() const;
	const std::vector<std::shared_ptr<TypeBrowserTreeNode>>& children();
	int indexOfChild(std::shared_ptr<const TypeBrowserTreeNode> child) const;

	virtual std::string text(int column) const = 0;
	virtual bool lessThan(const TypeBrowserTreeNode& other, int column) const = 0;
	virtual bool filter(const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const = 0;
	// Apply a pre-computed delta to the tree, emitting one UpdateData per change. Only the root
	// implements this; the default is a no-op.
	virtual void applyDelta(const TypeBrowserDelta& delta, UpdateNodeCallback update);
};


class BINARYNINJAUIAPI EmptyTreeNode : public TypeBrowserTreeNode
{
public:
	EmptyTreeNode(class TypeBrowserModelData* model, std::optional<std::weak_ptr<TypeBrowserTreeNode>> parent);
	virtual ~EmptyTreeNode() = default;

	virtual std::string text(int column) const override;
	virtual bool lessThan(const TypeBrowserTreeNode& other, int column) const override;
	virtual bool filter(const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const override;

protected:
	virtual void generateChildren() override;
};


class BINARYNINJAUIAPI RootTreeNode : public TypeBrowserTreeNode
{
	std::map<std::string, std::shared_ptr<class TypeContainerTreeNode>> m_containerNodes;

public:
	RootTreeNode(class TypeBrowserModelData* model, std::optional<std::weak_ptr<TypeBrowserTreeNode>> parent);
	virtual ~RootTreeNode() = default;

	virtual std::string text(int column) const override;
	virtual bool lessThan(const TypeBrowserTreeNode& other, int column) const override;
	virtual bool filter(const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const override;

	virtual void applyDelta(const TypeBrowserDelta& delta, UpdateNodeCallback update) override;

protected:
	virtual void generateChildren() override;
};


class BINARYNINJAUIAPI TypeTreeNode : public TypeBrowserTreeNode
{
public:
	enum SourceType
	{
		None,
		TypeLibrary,
		TypeArchive,
		DebugInfo,
		Platform,
		Other
	};

private:
	std::string m_id;
	BinaryNinja::QualifiedName m_name;
	TypeRef m_type;
	std::string m_sortName;

	SourceType m_sourceType;
	std::optional<TypeLibraryRef> m_sourceLibrary;
	std::optional<TypeArchiveRef> m_sourceArchive;
	std::optional<std::string> m_sourceDebugInfoParser;
	std::optional<PlatformRef> m_sourcePlatform;
	std::optional<std::string> m_sourceOtherName;
	std::optional<BinaryNinja::QualifiedName> m_sourceOriginalName;

public:
	TypeTreeNode(class TypeBrowserModelData* model, std::optional<std::weak_ptr<TypeBrowserTreeNode>> parent, const std::string& id, BinaryNinja::QualifiedName name, TypeRef type);
	virtual ~TypeTreeNode() = default;

	const std::string& id() const { return m_id; }
	const BinaryNinja::QualifiedName& name() const { return m_name; }
	const TypeRef& type() const { return m_type; }
	void setType(const std::string& id, const BinaryNinja::QualifiedName& name, const TypeRef& type);
	const std::string& sortName() const { return m_sortName; }

	const SourceType& sourceType() const { return m_sourceType; }
	std::optional<BinaryNinja::TypeContainer> typeContainer() const;
	std::optional<BinaryNinja::TypeContainer> sourceTypeContainer() const;
	PlatformRef sourcePlatform() const;

	virtual std::string text(int column) const override;
	virtual bool lessThan(const TypeBrowserTreeNode& other, int column) const override;
	virtual bool filter(const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const override;

protected:
	virtual void generateChildren() override;
};


class BINARYNINJAUIAPI TypeContainerTreeNode : public TypeBrowserTreeNode
{
	std::string m_containerId;
	// TODO: Gross
	std::map<std::string, std::pair<std::pair<BinaryNinja::QualifiedName, TypeRef>, std::shared_ptr<TypeTreeNode>>> m_typeNodes;

public:
	TypeContainerTreeNode(class TypeBrowserModelData* model, std::optional<std::weak_ptr<TypeBrowserTreeNode>> parent, const std::string& m_containerId);
	virtual ~TypeContainerTreeNode();

	virtual std::string text(int column) const override;
	virtual bool filter(const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const override;
	virtual bool lessThan(const TypeBrowserTreeNode& other, int column) const override;

	const std::string& containerId() const { return m_containerId; }
	std::optional<PlatformRef> platform() const;
	std::optional<BinaryNinja::TypeContainer> typeContainer() const;
	std::optional<BNTypeContainerType> containerType() const;
	// Apply a container's type-level delta, emitting one UpdateData per change. Called by
	// RootTreeNode::applyDelta.
	void applyTypeDelta(const TypeBrowserTypeDelta& delta, UpdateNodeCallback update);

protected:
	virtual void generateChildren() override;
};

//-----------------------------------------------------------------------------

/*! Cursed data struct behind a shared_ptr so Qt stops deleting our model while the background updates run */
class TypeBrowserModelData: public std::enable_shared_from_this<TypeBrowserModelData> // TODO enable_shared is not necessary
{
	BinaryViewRef m_data;

	std::shared_ptr<TypeBrowserTreeNode> m_rootNode;

	std::vector<std::string> m_containerIds;
	std::map<std::string, std::string> m_containerNames;
	std::map<std::string, BNTypeContainerType> m_containerTypes;
	std::map<std::string, BinaryNinja::TypeContainer> m_containers;

	std::map<std::string, BinaryViewRef> m_containerViews;
	std::map<std::string, TypeArchiveRef> m_containerArchives;
	std::map<std::string, std::string> m_containerArchiveIds;
	std::map<std::string, TypeLibraryRef> m_containerLibraries;
	std::map<std::string, DebugInfoRef> m_containerDebugInfos;
	std::map<std::string, PlatformRef> m_containerPlatforms;

	friend class TypeBrowserModel;

public:
	/*! Self-contained snapshot of the container/type state, built from the core with no ties
	    to the live model. The enumeration and the (expensive) per-container type reads run on
	    a background thread; the main thread then resolves the deferred display names and swaps
	    the descriptor maps into the model via applySnapshot(). */
	struct Snapshot
	{
		std::vector<std::string> containerIds;
		std::map<std::string, std::string> containerNames;
		std::map<std::string, BNTypeContainerType> containerTypes;
		std::map<std::string, BinaryNinja::TypeContainer> containers;
		std::map<std::string, BinaryViewRef> containerViews;
		std::map<std::string, TypeArchiveRef> containerArchives;
		std::map<std::string, std::string> containerArchiveIds;
		std::map<std::string, TypeLibraryRef> containerLibraries;
		std::map<std::string, DebugInfoRef> containerDebugInfos;
		std::map<std::string, PlatformRef> containerPlatforms;
		// Display names that require the UI context (main-thread only) are deferred here as
		// id -> (prefix, rawPath); applySnapshot() resolves them via filePathToName().
		std::map<std::string, std::pair<std::string, std::string>> pendingNames;
		// Pre-fetched per-container types (the expensive read), keyed by container id.
		TypeBrowserTypeSnapshot types;
	};

	explicit TypeBrowserModelData(BinaryViewRef data);
	~TypeBrowserModelData();
	TypeBrowserModelData(const TypeBrowserModelData&) = delete;
	TypeBrowserModelData(TypeBrowserModelData&&) = delete;
	TypeBrowserModelData& operator=(const TypeBrowserModelData&) = delete;
	TypeBrowserModelData& operator=(TypeBrowserModelData&&) = delete;

	BinaryViewRef getData();
	std::shared_ptr<TypeBrowserTreeNode> getRootNode();

	std::vector<std::string> containerIds() const;

	std::string nameForContainerId(const std::string& id) const;
	std::optional<std::reference_wrapper<BinaryNinja::TypeContainer>> containerForContainerId(const std::string& id);
	std::optional<std::reference_wrapper<const BinaryNinja::TypeContainer>> containerForContainerId(const std::string& id) const;
	std::optional<BinaryViewRef> viewForContainerId(const std::string& id) const;
	std::optional<TypeArchiveRef> archiveForContainerId(const std::string& id) const;
	std::optional<std::string> archiveIdForContainerId(const std::string& id) const;
	std::optional<TypeLibraryRef> libraryForContainerId(const std::string& id) const;
	std::optional<DebugInfoRef> debugInfoForContainerId(const std::string& id) const;
	std::optional<PlatformRef> platformForContainerId(const std::string& id) const;

	// Build a full self-contained snapshot from the core (all containers + their types). Safe
	// to call off the main thread; touches no model or tree state and defers UI-context-
	// dependent naming. Used when a rebuild is warranted (initial load / archive changes).
	Snapshot buildSnapshot() const;
	// Fetch just the view's own (user/auto) container types. This is the common incremental
	// case: a view-level type edit cannot change any other container's contents, so re-reading
	// only these two avoids the full GetTypes() sweep. Safe to call off the main thread.
	TypeBrowserTypeSnapshot buildViewTypeSnapshot() const;
	// Adopt a snapshot: resolve deferred names and move its descriptor maps into the model.
	// Must run on the main thread (resolves names + is read by the Qt model). The snapshot's
	// pre-fetched `types` are left intact for the caller to drive the tree diff.
	void applySnapshot(Snapshot& snapshot);

	std::vector<std::shared_ptr<TypeContainerTreeNode>> containerNodes() const;

private:
	void addContainer(BinaryNinja::TypeContainer cont, Snapshot& out) const;
	void addAllContainersForView(BinaryViewRef view, Snapshot& out) const;
	void addContainerForView(BinaryViewRef view, Snapshot& out) const;
	void addUserContainerForView(BinaryViewRef view, Snapshot& out) const;
	void addAutoContainerForView(BinaryViewRef view, Snapshot& out) const;
	void addContainerForArchive(TypeArchiveRef archive, Snapshot& out) const;
	void addContainerForArchiveId(const std::string& archiveId, const std::string& path, Snapshot& out) const;
	void addContainerForLibrary(TypeLibraryRef library, Snapshot& out) const;
	void addContainerForDebugInfo(DebugInfoRef debugInfo, const std::string& parser, Snapshot& out) const;
	void addContainerForPlatform(PlatformRef platform, Snapshot& out) const;
};

//-----------------------------------------------------------------------------

class BINARYNINJAUIAPI TypeBrowserModel : public QAbstractItemModel
{
	Q_OBJECT

	BinaryViewRef m_data;
	std::shared_ptr<class TypeBrowserModelData> m_modelData;
	std::unique_ptr<NotificationsDispatcher> m_dispatcher = nullptr;
	std::unique_ptr<TypeArchiveNotificationDispatcher> m_typeArchiveDispatcher = nullptr;

	void commitUpdate(const TypeBrowserTreeNode::UpdateData& update);
	void commitUpdates(const std::vector<TypeBrowserTreeNode::UpdateData>& updates);

public:
	TypeBrowserModel(BinaryViewRef data, QObject* parent);
	virtual ~TypeBrowserModel();
	BinaryViewRef getData();
	std::shared_ptr<TypeBrowserTreeNode> getRootNode();

	std::vector<std::string> containerIds() const;
	std::vector<std::shared_ptr<TypeContainerTreeNode>> containerNodes() const;

	std::string nameForContainerId(const std::string& id) const;
	std::optional<std::reference_wrapper<BinaryNinja::TypeContainer>> containerForContainerId(const std::string& id);
	std::optional<std::reference_wrapper<const BinaryNinja::TypeContainer>> containerForContainerId(const std::string& id) const;
	std::optional<BinaryViewRef> viewForContainerId(const std::string& id) const;
	std::optional<TypeArchiveRef> archiveForContainerId(const std::string& id) const;
	std::optional<std::string> archiveIdForContainerId(const std::string& id) const;
	std::optional<TypeLibraryRef> libraryForContainerId(const std::string& id) const;
	std::optional<DebugInfoRef> debugInfoForContainerId(const std::string& id) const;
	std::optional<PlatformRef> platformForContainerId(const std::string& id) const;

	void updateFonts();

	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

	std::shared_ptr<TypeBrowserTreeNode> nodeForIndex(const QModelIndex& index) const;
	QModelIndex indexForNode(std::shared_ptr<TypeBrowserTreeNode> node, int column = 0) const;

	bool filter(const QModelIndex& index, const std::string& filter, TypeBrowserFilterMode mode, bool caseSensitive) const;
	bool lessThan(const QModelIndex& left, const QModelIndex& right) const;

Q_SIGNALS:
	void updatesAboutToHappen();
	void updateComplete(bool didAnyHappen);

public Q_SLOTS:
	void notifyRefresh();
};


class BINARYNINJAUIAPI TypeBrowserFilterModel : public QSortFilterProxyModel
{
	Q_OBJECT
	BinaryViewRef m_data;
	TypeBrowserModel* m_model;
	std::string m_originalFilter;
	std::string m_filter;
	bool m_filterCaseSensitive = false;
	TypeBrowserFilterMode m_filterMode;
	bool m_exactOnTop;

protected:
	bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;
	bool lessThan(const QModelIndex& source_left, const QModelIndex& source_right) const override;

public:
	TypeBrowserFilterModel(BinaryViewRef data, TypeBrowserModel* model, QObject* parent);

	void setFilter(const std::string& filter, FilterOptions options);
	TypeBrowserFilterMode filterMode() const { return m_filterMode; }
	void setFilterMode(TypeBrowserFilterMode newMode) { m_filterMode = newMode; }

Q_SIGNALS:
	void filterAboutToBeChanged();
	void filterChanged();
};


class BINARYNINJAUIAPI TypeBrowserItemDelegate : public QItemDelegate
{
	QFont m_font;
	QFont m_monospaceFont;
	float m_charWidth, m_charHeight, m_charOffset;
	float m_baseline;
	class TypeBrowserView* m_view;

	void initFont();
public:
	TypeBrowserItemDelegate(class TypeBrowserView* view);
	int lineHeight() const;
	void updateFonts();
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};


class BINARYNINJAUIAPI TypeBrowserTreeView : public QTreeView
{
	Q_OBJECT
	UIActionHandler m_actionHandler;

protected:
	virtual void scrollContentsBy(int dx, int dy) override;

public:
	explicit TypeBrowserTreeView(class TypeBrowserView* parent);
};


struct BINARYNINJAUIAPI TypeReference
{
	std::string containerId;
	BinaryNinja::QualifiedName typeName;

	TypeReference() = default;
	TypeReference(std::string containerId, BinaryNinja::QualifiedName typeName);
};


class BINARYNINJAUIAPI TypeBrowserView : public QFrame, public View, public FilterTarget
{
	Q_OBJECT
	BinaryViewRef m_data;
	class TypeBrowserContainer* m_container;
	ContextMenuManager* m_contextMenuManager;

	QSplitter* m_splitter;

	TypeBrowserModel* m_model;
	TypeBrowserFilterModel* m_filterModel;
	QStandardItemModel* m_loadingModel;
	QTreeView* m_tree;
	TypeBrowserItemDelegate* m_delegate;
	bool m_updatedWidths;

	bool m_navigateToNextInsert;
	QModelIndex m_lastPosition;
	QModelIndex m_lastInsert;
	TypeEditor::SavedCursorPosition m_editorPosition;

	TypeEditor* m_typeEditor;
	QTextEdit* m_debugText;

	void updateInTransaction(std::function<bool()> transaction);
	std::string dumpTypeDefinition(BinaryNinja::TypeContainer container, TypeRef type, std::string name);

public:
	TypeBrowserView(BinaryViewRef data, TypeBrowserContainer* container);

	TypeBrowserContainer* getContainer() { return m_container; }
	TypeBrowserModel* getModel() { return m_model; }
	TypeBrowserFilterModel* getFilterModel() { return m_filterModel; }
	QTreeView* getTreeView() { return m_tree; }
	TypeEditor* getTypeEditor() { return m_typeEditor; }

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual bool navigate(uint64_t offset) override;
	virtual SelectionInfoForXref getSelectionForXref() override;
	virtual QFont getFont() override;
	virtual void updateFonts() override;

	virtual void showEvent(QShowEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;

	virtual StatusBarWidget* getStatusBarWidget() override;
	virtual QWidget* getHeaderOptionsWidget() override;

	virtual void setFilter(const std::string& filter, FilterOptions options) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void ensureSelection() override;
	virtual void activateSelection() override;

	virtual void notifyRefresh() override;

	void showSelectedTypes();
	void showTypes(const std::vector<TypeReference>& types);
	void selectTypeByName(const std::string& name, bool newSelection);

	bool navigateToType(const std::string& typeName, uint64_t offset);
	void scrollToIndexWithContext(const QModelIndex& index, int context = 1);

	void setPrimaryOrientation(Qt::Orientation orientation);

	// Selection helpers

	// All nodes
	std::vector<std::shared_ptr<TypeBrowserTreeNode>> selectedNodes() const;
	// BV selected or BV relevant to selected types, only if JUST bv stuff is selected
	std::optional<BinaryViewRef> selectedBV() const;
	// If selectedBV exists, names of selected types
	std::optional<std::unordered_set<BinaryNinja::QualifiedName>> selectedBVTypeNames() const;

	std::optional<std::pair<BinaryNinja::TypeContainer, BinaryNinja::QualifiedName>> selectedTypeNameAndContainer() const;
	// All selected type names, grouped by type container
	std::vector<std::pair<BinaryNinja::TypeContainer, std::vector<BinaryNinja::QualifiedName>>> selectedTypeNamesByContainers() const;
	// Selected type reference
	std::optional<TypeReference> selectedType() const;
	// Selected type references
	std::vector<TypeReference> selectedTypes() const;
	// Selected type container, or container of selected type
	// makeSureItHasPlatform: if the type container is a BV with no platform (raw), ask for one and return nullopt if rejected
	// preferView: if the type container is a BV and the user/auto-only container, switch to the whole-view container for that BV instead
	std::optional<BinaryNinja::TypeContainer> selectedTypeContainer(bool makeSureItHasPlatform = true, bool preferView = false) const;
	// Which (selection preferred) container should be used for creating new types
	std::optional<BinaryNinja::TypeContainer> typeContainerForCreating(bool makeSureItHasPlatform = true, bool preferView = false) const;
	// Selected type container ids, or containers of selected types
	std::unordered_set<std::string> selectedTypeContainerIds() const;

	// TA selected or TA relevant to selected types, only if JUST ta stuff is selected and only 1 TA
	std::optional<TypeArchiveRef> selectedTA() const;
	// Id of TA selected or TA relevant to selected types, only if JUST ta stuff is selected and only 1 TA
	std::optional<std::string> selectedTAId() const;
	// TAs selected or TAs relevant to selected types, only if JUST ta stuff is selected
	std::optional<std::unordered_set<TypeArchiveRef>> selectedTAs() const;
	// Ids of TAs selected or TAs relevant to selected types, only if JUST ta stuff is selected
	std::optional<std::unordered_set<std::string>> selectedTAIds() const;
	// If selectedTAs exist, map of ta ids to ids of selected types from that ta
	std::optional<std::unordered_map<std::string, std::unordered_set<std::string>>> selectedTATypeIds() const;
	// All type archives that are attached and connected
	std::vector<TypeArchiveRef> connectedTAs(BinaryViewRef view) const;

	// Names -> Ids, if any don't exist then nullopt
	static std::optional<std::unordered_set<std::string>> typeIdsFromNames(BinaryViewRef view, const std::unordered_set<BinaryNinja::QualifiedName>& names);
	// Ids -> Option<TypeArchive>
	static std::unordered_map<std::optional<TypeArchiveRef>, std::unordered_set<std::string>> associatedTypeArchivesForTypeIds(BinaryViewRef view, const std::unordered_set<std::string>& typeIds);

	std::optional<BinaryNinja::TypeContainer> containerForId(const std::string& containerId, bool makeSureItHasPlatform = false, bool preferView = false) const;

	// Menu actions
	static void registerActions();
	void bindActions();
	void showContextMenu();

	bool canConnectTypeArchive();
	void connectTypeArchive();

	bool canCreateTypeArchive();
	void createTypeArchive();
	bool canAttachTypeArchive();
	void attachTypeArchive();
	bool canDetachTypeArchive();
	void detachTypeArchive();

	bool canSyncSelectedTypes();
	void syncSelectedTypes();
	bool pushTypesFromView(BinaryViewRef view, const std::unordered_set<BinaryNinja::QualifiedName>& names);
	bool canPushSelectedTypes();
	void pushSelectedTypes();
	bool canPushAllTypes();
	void pushAllTypes();
	bool pullTypesFromView(BinaryViewRef view, const std::unordered_set<BinaryNinja::QualifiedName>& viewTypeNames);
	bool pullTypesFromArchives(BinaryViewRef view, const std::unordered_map<std::string, std::unordered_set<std::string>>& archiveTypeIdSelection);
	bool canPullSelectedTypes();
	void pullSelectedTypes();
	bool canPullAllTypes();
	void pullAllTypes();
	bool canDisassociateSelectedTypes();
	void disassociateSelectedTypes();

	bool canCreateNewTypes();
	void createNewTypes();
	bool canCreateNewStructure();
	void createNewStructure();
	bool canCreateNewEnumeration();
	void createNewEnumeration();
	bool canCreateNewUnion();
	void createNewUnion();
	bool canRenameTypes();
	void renameTypes();
	bool canCopyTypeNames();
	void copyTypeNames();
	bool canCopyTypeDefinitions();
	void copyTypeDefinitions();
	bool canDeleteTypes();
	void deleteTypes();
	bool canChangeTypes();
	void changeTypes();
	bool canCreateStructureMemberAtOffset();
	void createStructureMemberAtOffset();
	bool canImportType();
	void importType();
	bool canImportTypeByGUID(BinaryViewRef view);
	void importTypeByGUID();
	bool canAddTypeLibrary();
	void addTypeLibrary();
	bool canExpandAll();
	void expandAll();
	bool canCollapseAll();
	void collapseAll();
	bool canSwitchLayout();
	void switchLayout();

Q_SIGNALS:
	void typeNameNavigated(const std::string& typeName, bool newSelection);

protected:
	void itemSelected(const QItemSelection& selected, const QItemSelection& deselected);
	void itemDoubleClicked(const QModelIndex& index);
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual bool event(QEvent* event) override;
	virtual bool eventFilter(QObject* obj, QEvent* event) override;
	virtual void focusInEvent(QFocusEvent* event) override;
	void ensureTypeEditorHasSelection();
};

class BINARYNINJAUIAPI TypeBrowserOptionsIconWidget : public QWidget
{
public:
	TypeBrowserOptionsIconWidget(TypeBrowserView* parent);

private:
	TypeBrowserView* m_view;

	void showMenu();
};

class BINARYNINJAUIAPI TypeBrowserContainer : public QWidget, public ViewContainer
{
	Q_OBJECT

	BinaryViewRef m_data;
	TypeBrowserView* m_view;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit;
	class TypeBrowserSidebarWidget* m_sidebarWidget;
	UIActionHandler m_actionHandler;

private:
	void bindNavigationShortcuts();
	void navigateBack();
	void navigateForward();

public:
	TypeBrowserContainer(BinaryViewRef data, class TypeBrowserSidebarWidget* parent);
	virtual View* getView() override { return m_view; }

	BinaryViewRef getData() { return m_data; }
	TypeBrowserView* getTypeBrowserView() { return m_view; }
	FilteredView* getFilter() { return m_filter; }
	FilterEdit* getSeparateFilterEdit() { return m_separateEdit; }
	class TypeBrowserSidebarWidget* getSidebarWidget() { return m_sidebarWidget; }
	void showContextMenu();

protected:
	virtual void focusInEvent(QFocusEvent* event) override;
	virtual bool event(QEvent* event) override;
};


class BINARYNINJAUIAPI TypeBrowserViewType : public ViewType
{
	static TypeBrowserViewType* g_instance;

public:
	TypeBrowserViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* frame) override;
	static void init();
};


class BINARYNINJAUIAPI TypeBrowserSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	QWidget* m_header;
	TypeBrowserContainer* m_container;

public:
	TypeBrowserSidebarWidget(BinaryViewRef data);
	TypeBrowserContainer* container() { return m_container; }
	virtual void notifyRefresh() override;
	virtual QWidget* headerWidget() override { return m_header; }
	virtual void focus() override;
	virtual void setPrimaryOrientation(Qt::Orientation orientation) override;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

private Q_SLOTS:
	void showContextMenu();
};


class BINARYNINJAUIAPI TypeBrowserSidebarWidgetType : public SidebarWidgetType
{
public:
	TypeBrowserSidebarWidgetType();
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;

	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::LeftContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	virtual bool canUseAsPane(SplitPaneWidget*, BinaryViewRef) const override { return true; }
	virtual Pane* createPane(SplitPaneWidget* panes, BinaryViewRef data) override;
};

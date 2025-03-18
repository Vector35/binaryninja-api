#pragma once

#include <QtWidgets/QGestureEvent>
#include <QtGui/QAction>
#include <QtWidgets/QLabel>
#include <QtCore/QPointer>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <map>
#include <stack>
#include <utility>
#include <vector>
#include <functional>
#include "binaryninjaapi.h"
#include "filecontext.h"
#include "viewtype.h"
#include "action.h"
#include "sidebar.h"

/*!

	\defgroup viewframe ViewFrame
 	\ingroup uiapi
*/

/*! This struct is used to pass selection information for cross references

	\ingroup viewframe
*/
struct BINARYNINJAUIAPI SelectionInfoForXref
{
	// Check these booleans before accessing the address/type/variable info,
	// since the invalid fields are not guaranteed to be initialized/zero-ed.
	// At any given time, at most one of these four should be true.
	bool addrValid, typeValid, typeFieldValid, localVarValid;

	BNFunctionGraphType ilSource;

	uint64_t start;
	uint64_t end;

	BinaryNinja::QualifiedName type;
	uint64_t offset;

	BinaryNinja::Variable var;

	// These two need to be tested against nullptr before de-referencing
	FunctionRef func;
	ArchitectureRef arch;

	bool operator==(const SelectionInfoForXref& other) const
	{
		if (addrValid && other.addrValid)
			return (start == other.start) && (end == other.end) && (func == other.func) && (arch == other.arch);
		else if (typeValid && other.typeValid)
			return type == other.type;
		else if (typeFieldValid && other.typeFieldValid)
			return (type == other.type) && (offset == other.offset);
		else if (localVarValid && other.localVarValid)
			return (var == other.var) && (ilSource == other.ilSource);
		return false;
	}

	bool operator!=(const SelectionInfoForXref& other) const { return !(*this == other); }
	bool isValid() const { return addrValid || typeValid || typeFieldValid || localVarValid; }
};

/*!

	\ingroup viewframe
*/
class BINARYNINJAUIAPI HistoryEntry : public BinaryNinja::RefCountObject
{
	QString m_viewType;

  public:
	virtual ~HistoryEntry() {}

	QString getViewType() const { return m_viewType; }
	void setViewType(const QString& type) { m_viewType = type; }

	/*!
	    Serialize to json representation
	    \return Json representation of history entry. In the Python api, this must be a dict.
	 */
	virtual Json::Value serialize() const;
	/*!
	    Deserialize from json representation. This method should clear any previously entered data
	    on the HistoryEntry as if it were newly created.
	    \param value Json representation of history entry. In the Python api, this will be a dict.
	    \return If deserialization was successful
	 */
	virtual bool deserialize(const Json::Value& value);
};


class AssembleDialog;
class ClickableStateLabel;
class CompileDialog;
class FeatureMap;
class StatusBarWidget;
class ViewNavigationMode;
class TransformParameterDialog;
class ViewPaneHeaderSubtypeWidget;
// struct BinaryNinjaCore::LinearDisassemblyLine;

/*!

	\ingroup viewframe
*/
class BINARYNINJAUIAPI View
{
  protected:
	Menu m_contextMenu;
	UIActionHandler m_actionHandler;
	bool m_binaryDataNavigable = false;
	QPointer<TransformParameterDialog> m_transformParamDialog;

	bool m_quiesceState = true;
	QTimer* m_updateTimer = nullptr;

	bool writeDataToClipboard(const BinaryNinja::DataBuffer& data, bool binary, TransformRef xform);
	BinaryNinja::DataBuffer readDataFromClipboard(TransformRef xform);

  public:
	View();
	virtual ~View() {}

	void enableRefreshTimer(QWidget* owner, int interval);
	void setRefreshQuiesce(bool enable);
	bool isQuiesced() const { return m_quiesceState; }
	virtual void notifyRefresh() {};
	virtual void notifyQuiesce(bool /*quiesce*/) {};

	void setupView(QWidget* widget);

	virtual bool canAssemble() { return false; }
	virtual bool canCompile() { return false; }

	virtual bool findNextData(uint64_t start, uint64_t end, const BinaryNinja::DataBuffer& data, uint64_t& addr,
	    BNFindFlag flags, const std::function<bool(size_t current, size_t total)>& cb);
	virtual bool findNextText(uint64_t start, uint64_t end, const std::string& text, uint64_t& addr,
	    DisassemblySettingsRef settings, BNFindFlag flags, const BinaryNinja::FunctionViewType& graph,
	    const std::function<bool(size_t current, size_t total)>& cb);
	virtual bool findNextConstant(uint64_t start, uint64_t end, uint64_t constant, uint64_t& addr,
	    DisassemblySettingsRef settings, const BinaryNinja::FunctionViewType& graph,
	    const std::function<bool(size_t current, size_t total)>& cb);

	virtual bool findAllData(uint64_t start, uint64_t end, const BinaryNinja::DataBuffer& data, BNFindFlag flags,
	    const std::function<bool(size_t current, size_t total)>& cb,
	    const std::function<bool(uint64_t addr, const BinaryNinja::DataBuffer& match)>& matchCallback);
	virtual bool findAllText(uint64_t start, uint64_t end, const std::string& data, DisassemblySettingsRef settings,
	    BNFindFlag flags, const BinaryNinja::FunctionViewType& graph, const std::function<bool(size_t current, size_t total)>& cb,
	    const std::function<bool(
	        uint64_t addr, const std::string& match, const BinaryNinja::LinearDisassemblyLine& line)>& matchCallback);
	virtual bool findAllConstant(uint64_t start, uint64_t end, uint64_t constant, DisassemblySettingsRef settings,
	    const BinaryNinja::FunctionViewType& graph, const std::function<bool(size_t current, size_t total)>& cb,
	    const std::function<bool(uint64_t addr, const BinaryNinja::LinearDisassemblyLine& line)>& matchCallback);

	virtual BinaryViewRef getData() = 0;
	virtual uint64_t getCurrentOffset() = 0;
	virtual BNAddressRange getSelectionOffsets();
	virtual SelectionInfoForXref getSelectionForXref();
	virtual void setSelectionOffsets(BNAddressRange range) = 0;
	virtual bool navigate(uint64_t offset) = 0;
	virtual bool navigateToFunction(FunctionRef func, uint64_t offset);
	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target);
	virtual bool navigateToViewLocation(const ViewLocation& viewLocation, bool center = false);

	bool navigateOnOtherPane(uint64_t offset);
	bool navigateToFunctionOnOtherPane(FunctionRef func, uint64_t offset);

	bool isBinaryDataNavigable() { return m_binaryDataNavigable; }
	void setBinaryDataNavigable(bool navigable) { m_binaryDataNavigable = navigable; }

	virtual bool closeRequest() { return true; }
	virtual void closing() {}
	virtual void updateFonts() {}
	virtual void updateTheme() {}

	virtual void undo();
	virtual void redo();
	virtual bool canUndo();
	virtual bool canRedo();

	virtual void cut();
	virtual void copy(TransformRef xform = nullptr);
	virtual void copyAddress();
	virtual void paste(TransformRef xform = nullptr);
	virtual bool canCut();
	virtual bool canCopy();
	virtual bool canCopyWithTransform();
	virtual bool canCopyAddress();
	virtual bool canPaste();
	virtual bool canPasteWithTransform();

	virtual void transform(TransformRef xform, bool encode);
	virtual bool canTransform();

	virtual void writeData(const BinaryNinja::DataBuffer& data, uint64_t addr);

	virtual bool canDisplayAs(const UIActionContext& context, const BNIntegerDisplayType);
	virtual void displayAs(const UIActionContext& context, BNIntegerDisplayType type);

	virtual BinaryNinja::Ref<HistoryEntry> getHistoryEntry();
	virtual void navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry);

	virtual StatusBarWidget* getStatusBarWidget() { return nullptr; }
	virtual ViewPaneHeaderSubtypeWidget* getHeaderSubtypeWidget() { return nullptr; }
	virtual QWidget* getHeaderOptionsWidget() { return nullptr; }

	static View* getViewFromWidget(QWidget* widget);

	virtual FunctionRef getCurrentFunction() { return nullptr; }
	virtual BasicBlockRef getCurrentBasicBlock() { return nullptr; }
	virtual ArchitectureRef getCurrentArchitecture() { return nullptr; }

	virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() { return nullptr; }
	virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() { return nullptr; }
	virtual HighLevelILFunctionRef getCurrentHighLevelILFunction() { return nullptr; }
	virtual BinaryNinja::FunctionViewType getILViewType() { return InvalidILViewType; }
	virtual void setILViewType(const BinaryNinja::FunctionViewType& ilViewType) {}
	virtual size_t getCurrentILInstructionIndex() { return BN_INVALID_EXPR; }
	virtual size_t getSelectionStartILInstructionIndex() { return BN_INVALID_EXPR; }
	virtual BNILIndexRange getILIndexRange() { return {BN_INVALID_EXPR, BN_INVALID_EXPR}; }

	virtual QFont getFont() = 0;
	virtual DisassemblySettingsRef getDisassemblySettings();
	virtual void setDisassemblySettings(DisassemblySettingsRef settings) { (void)settings; }

	virtual HighlightTokenState getHighlightTokenState();

	virtual UIActionContext actionContext();
	Menu& contextMenu() { return m_contextMenu; }
	UIActionHandler* actionHandler() { return &m_actionHandler; }
	QWidget* widget() { return m_actionHandler.widget(); }

	QString viewType();

	void updateCrossReferenceSelection(ViewFrame* frame = nullptr);
	void forceSyncFromView(ViewFrame* frame = nullptr);

	virtual void clearRelatedHighlights() {}
	virtual void setRelatedIndexHighlights(FunctionRef func, const std::set<size_t>& related) { (void)func; (void)related; }
	virtual void setRelatedInstructionHighlights(FunctionRef func, const std::set<uint64_t>& related) { (void)func; (void)related; }

	static void registerActions();
	static void registerLateActions();

	void notifyContextMenuCreated();
};


/*!

	\ingroup viewframe
*/
class BINARYNINJAUIAPI ViewLocation
{
	bool m_valid = false;
	QString m_viewType;
	FunctionRef m_function = nullptr;
	uint64_t m_offset = 0;
	BinaryNinja::FunctionViewType m_ilViewType = InvalidILViewType;
	size_t m_instrIndex = BN_INVALID_EXPR;

  public:
	ViewLocation() {}
	ViewLocation(const QString& viewType, uint64_t offset) : m_valid(true), m_viewType(viewType), m_offset(offset) {}
	ViewLocation(const QString& viewType, uint64_t offset, const BinaryNinja::FunctionViewType& ilViewType) :
	    m_valid(true), m_viewType(viewType), m_offset(offset), m_ilViewType(ilViewType)
	{}
	ViewLocation(const QString& viewType, uint64_t offset, const BinaryNinja::FunctionViewType& ilViewType, size_t instrIndex) :
	    m_valid(true), m_viewType(viewType), m_offset(offset), m_ilViewType(ilViewType), m_instrIndex(instrIndex)
	{}
	ViewLocation(const QString& viewType, FunctionRef function, uint64_t offset, const BinaryNinja::FunctionViewType& ilViewType,
	    size_t instrIndex) :
	    m_valid(true),
	    m_viewType(viewType), m_function(function), m_offset(offset), m_ilViewType(ilViewType), m_instrIndex(instrIndex)
	{}
	ViewLocation(
	    FunctionRef function, uint64_t offset, const BinaryNinja::FunctionViewType& ilViewType, size_t instrIndex = BN_INVALID_EXPR) :
	    m_valid(true),
	    m_function(function), m_offset(offset), m_ilViewType(ilViewType), m_instrIndex(instrIndex)
	{}

	bool isValid() const { return m_valid; }
	QString getViewType() const { return m_viewType; }
	uint64_t getOffset() const { return m_offset; }
	const BinaryNinja::FunctionViewType& getILViewType() const { return m_ilViewType; }
	size_t getInstrIndex() const { return m_instrIndex; }
	FunctionRef getFunction() const { return m_function; }

	void setViewType(const QString& viewType) { m_viewType = viewType; }
	void setOffset(uint64_t offset) { m_offset = offset; }
	void setILViewType(const BinaryNinja::FunctionViewType& ilViewType) { m_ilViewType = ilViewType; }
	void setInstrIndex(uint64_t index) { m_instrIndex = index; }
	void setFunction(FunctionRef function) { m_function = function; }

	bool operator==(const ViewLocation& other) const
	{
		return (m_valid == other.m_valid) && (m_viewType == other.m_viewType) && (m_offset == other.m_offset)
		       && (m_ilViewType == other.m_ilViewType) && (m_instrIndex == other.m_instrIndex)
		       && (m_function == other.m_function);
	}
	bool operator!=(const ViewLocation& other) const { return !((*this) == other); }
};

/*!

	\ingroup viewframe
*/
class BINARYNINJAUIAPI ViewContainer
{
  public:
	virtual ~ViewContainer();
	virtual View* getView() = 0;
};

class SymbolsView;
class ViewFrame;
class ViewPane;


class TimerWithMaxTries: public QObject
{
	Q_OBJECT

	QTimer* timer;
	size_t attempts;
	size_t initialDelay;
	size_t maxTries;
	size_t delay;
	std::atomic<bool> stopped = false;

public:
	TimerWithMaxTries(QWidget* parent, size_t initialDelay, size_t n, size_t msec);
	void start();
	void stop();
	~TimerWithMaxTries();

Q_SIGNALS:
	void timeout();
};


/*!

	\ingroup viewframe
*/
class BINARYNINJAUIAPI ViewFrame : public QWidget
{
	Q_OBJECT

  private:
	QWidget* createView(const QString& typeName, ViewType* type, BinaryViewRef data);
	BinaryNinja::Ref<HistoryEntry> getHistoryEntry();
	ViewFrame* searchForOtherPane(const std::function<void(const std::function<void(ViewPane*)>&)>& enumerator);

	FileContext* m_context;
	bool m_fileContentsLock = true;  // file contents protection from accidental modification in the UI
	BinaryViewRef m_data = nullptr;
	QWidget* m_view = nullptr;
	QWidget* m_viewContainer;
	QVBoxLayout* m_viewLayout;
	std::map<QString, QWidget*> m_viewCache;
	std::list<BinaryNinja::Ref<HistoryEntry>> m_back, m_forward;
	bool m_graphViewPreferred = false;
	QStringList m_viewTypePriority;
	int m_preferredSyncGroup = 1;
	bool m_aboutToClose = false;

	UIActionHandler m_actionHandler;
	TimerWithMaxTries* m_mainNavigationTimer;

  protected:
	QPointer<CompileDialog> compileDialog;

	bool event(QEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	bool gestureEvent(QGestureEvent* event);

	void setView(QWidget* view);
	/*!
	    Load one history entry from json representation
	    \param json Json rep of history entry
	    \return Entry, if successful, else nullptr
	 */
	BinaryNinja::Ref<HistoryEntry> deserializeHistoryEntry(const Json::Value& json);

	bool tryMainSymbolsNavigation();

  public:
	explicit ViewFrame(QWidget* parent, FileContext* file, const QString& type);
	virtual ~ViewFrame();

	FileContext* getFileContext() const { return m_context; }
	bool areFileContentsLocked(bool showToolTip = false);
	void setFileContentsLocked(bool enable);

	QString getTabName();
	QString getShortFileName();
	std::vector<QString> getAvailableTypes() const;

	QString getCurrentView() const;
	BinaryViewRef getCurrentBinaryView() const;
	QString getCurrentDataType() const;
	uint64_t getCurrentOffset() const;
	BNAddressRange getSelectionOffsets() const;

	ViewLocation getViewLocation() const;
	void setViewLocation(const ViewLocation& viewLocation);

	View* getCurrentViewInterface() const { return View::getViewFromWidget(m_view); }
	QWidget* getCurrentWidget() const { return m_view; }

	bool isGraphViewPreferred();
	void setPriorityView(const QString& viewType);
	bool setViewType(const QString& viewType);
	void focus();

	Sidebar* getSidebar();

	template <class T>
	T* getSidebarWidget(const QString& name)
	{
		Sidebar* sidebar = getSidebar();
		if (!sidebar)
			return (T*)nullptr;
		QWidget* widget = sidebar->widget(name);
		if (!widget)
			return (T*)nullptr;
		return qobject_cast<T*>(widget);
	}

	bool navigate(const QString& type, uint64_t offset, bool updateInfo = true, bool addHistoryEntry = true);
	bool navigate(const QString& type, const std::function<bool(View*)>& handler, bool updateInfo = true, bool addHistoryEntry = true);
	bool navigate(BinaryViewRef data, uint64_t offset, bool updateInfo = true, bool addHistoryEntry = true);
	bool navigateToFunction(FunctionRef func, uint64_t offset, bool updateInfo = true, bool addHistoryEntry = true);
	bool goToReference(BinaryViewRef data, FunctionRef func, uint64_t source, uint64_t target, bool addHistoryEntry = true);
	bool navigateToViewLocation(BinaryViewRef data, const ViewLocation& viewLocation, bool addHistoryEntry = true, bool center = false);
	bool navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry);
	QString getTypeForView(QWidget* view) const;
	QString getDataTypeForView(const QString& type) const;
	QString getDataTypeForView(QWidget* view) const;
	QWidget* getViewWidgetForType(const QString& type);
	View* getViewForType(const QString& type);

	void aboutToClose() { m_aboutToClose = true; }
	bool isAboutToClose() { return m_aboutToClose; }
	bool closeRequest();
	void closing();

	void updateFonts();
	void updateTheme();
	void addHistoryEntry();
	/*!
	    Parse history entries from the raw data associated with a BinaryView, loading them into the back/forward
	    navigation stacks, and navigating to the saved position.
	    \param data View containing history entries
		 \param restoreLocation whether or not to navigate to the location stored in the database
	 */
	void readHistoryEntries(BinaryViewRef data, bool restoreLocation);
	/*!
	    Serialize history entries and current position, storing them in the raw data associated with a BinaryView.
	    \param data View for saving history entries
	 */
	void writeHistoryEntries(BinaryViewRef data);
	bool canNavigateBack();
	bool canNavigateForward();
	void back();
	void forward();

	static bool getAddressFromString(QWidget* parent, BinaryViewRef data, uint64_t& offset, uint64_t currentAddress,
	    const QString& addrStr, std::string& errorString);
	static bool getAddressFromInput(QWidget* parent, BinaryViewRef data, uint64_t& offset, uint64_t currentAddress,
	    const QString& title = "Go to Address", const QString& msg = "Address:", bool defaultToCurrent = false);
	static bool getFileOffsetFromInput(QWidget* parent, BinaryViewRef data, uint64_t& offset, uint64_t currentAddress,
	    const QString& title = "Go to File Offset", const QString& msg = "File Offset:", bool defaultToCurrent = false);

	void setCurrentFunction(FunctionRef func);
	void updateCrossReferences();
	void updateCrossReferenceSelection();
	void nextCrossReference();
	void prevCrossReference();
	void tryNavigateToMain();

	void updateVariableList();
	void updateStackView();

	void showTags();
	void editTag(TagRef tag);
	void nextTag();
	void prevTag();

	virtual UIActionContext actionContext();
	void bindActions();
	static void registerActions();

	static ViewFrame* viewFrameForWidget(QWidget* widget);
	static bool lineHasInstructionToken(const BinaryNinja::DisassemblyTextLine& line);
	static QString getDisassemblyText(const std::vector<BinaryNinja::DisassemblyTextLine>& lines);

	int preferredSyncGroup() const { return m_preferredSyncGroup; }
	void setPreferredSyncGroup(int syncGroup) { m_preferredSyncGroup = syncGroup; }
	void disableSync();
	void enableSync();
	void enableSync(int id);
	void newSyncGroup();
	void toggleSync();
	SyncGroup* syncGroup();

	void syncToOtherViews();
	void forceSyncFromView();

	ViewFrame* getOtherPane();

  public Q_SLOTS:
	virtual void assemble();
	virtual void compile();

  Q_SIGNALS:
	void notifyCloseFeatureMap(bool recreate);
	void notifyViewChanged(ViewFrame* frame);
};

Q_DECLARE_METATYPE(View*)

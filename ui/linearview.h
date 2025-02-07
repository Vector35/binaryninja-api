#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QTimer>
#include <shared_mutex>
#include <optional>
#include <utility>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "progressindicator.h"
#include "commentdialog.h"
#include "menus.h"
#include "statusbarwidget.h"
#include "uicontext.h"
#include "instructionedit.h"
#include "ilchooser.h"
#include <assembledialog.h>

#define LINEAR_VIEW_UPDATE_CHECK_INTERVAL 200
#define MAX_STRING_TYPE_LENGTH            1048576

/*!

	\defgroup linearview LinearView
 	\ingroup uiapi
*/

/*!

    \ingroup linearview
*/
struct BINARYNINJAUIAPI LinearViewLine : public BinaryNinja::LinearDisassemblyLine
{
	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> cursor;
	size_t cursorSize;
	size_t lineIndex;
};

/*!

    \ingroup linearview
*/
struct BINARYNINJAUIAPI LinearViewCursorPosition
{
	FunctionRef function;
	BasicBlockRef block;
	uint64_t address;
	size_t instrIndex;
	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> cursor;
	size_t lineIndex;
	size_t tokenIndex;
	size_t characterIndex;
	// Directly from QMouseEvent, not used in comparators
	int cursorX;
	int cursorY;

	LinearViewCursorPosition();
	LinearViewCursorPosition(const LinearViewCursorPosition& pos);
	LinearViewCursorPosition(const LinearViewLine& line);
	LinearViewCursorPosition& operator=(const LinearViewCursorPosition& pos);

	bool operator==(const LinearViewCursorPosition& other) const;
	bool operator!=(const LinearViewCursorPosition& other) const;
	bool operator<(const LinearViewCursorPosition& other) const;
	bool operator<=(const LinearViewCursorPosition& other) const;
	bool operator>=(const LinearViewCursorPosition& other) const;
	bool operator>(const LinearViewCursorPosition& other) const;

	LinearViewCursorPosition AsLine() const;
};

/*!

    \ingroup linearview
*/
class BINARYNINJAUIAPI LinearViewHistoryEntry : public HistoryEntry
{
	std::vector<BinaryNinja::LinearViewObjectIdentifier> m_topPath;
	size_t m_topLineIndex;
	uint64_t m_topAddr;
	std::vector<BinaryNinja::LinearViewObjectIdentifier> m_cursorPath;
	size_t m_cursorLineIndex;
	uint64_t m_cursorAddr;
	PlatformRef m_platform;
	uint64_t m_func;
	bool m_inFunc = false;
	HighlightTokenState m_highlight;

public:
	const std::vector<BinaryNinja::LinearViewObjectIdentifier>& getTopPath() const { return m_topPath; }
	size_t getTopLineIndex() const { return m_topLineIndex; }
	uint64_t getTopAddress() const { return m_topAddr; }
	const std::vector<BinaryNinja::LinearViewObjectIdentifier>& getCursorPath() const { return m_cursorPath; }
	size_t getCursorLineIndex() const { return m_cursorLineIndex; }
	uint64_t getCursorAddress() const { return m_cursorAddr; }
	PlatformRef getPlatform() const { return m_platform; }
	uint64_t getFunction() const { return m_func; }
	bool inFunction() const { return m_inFunc; }
	const HighlightTokenState& getHighlightTokenState() const { return m_highlight; }

	void setTopPath(const std::vector<BinaryNinja::LinearViewObjectIdentifier>& path) { m_topPath = path; }
	void setTopLineIndex(size_t offset) { m_topLineIndex = offset; }
	void setTopAddress(uint64_t addr) { m_topAddr = addr; }
	void setCursorPath(const std::vector<BinaryNinja::LinearViewObjectIdentifier>& path) { m_cursorPath = path; }
	void setCursorLineIndex(size_t offset) { m_cursorLineIndex = offset; }
	void setCursorAddress(uint64_t addr) { m_cursorAddr = addr; }
	void setPlatform(PlatformRef platform) { m_platform = platform; }
	void setFunction(uint64_t f) { m_func = f; }
	void setInFunction(bool inFunc) { m_inFunc = inFunc; }
	void setHighlightTokenState(const HighlightTokenState& state) { m_highlight = state; }

	virtual Json::Value serialize() const override;
	virtual bool deserialize(const Json::Value& value) override;
};

class LinearView;

class StickyHeader: public QWidget
{
	RenderContext m_render;
	BinaryViewRef m_data;

	uint64_t m_gutterWidth;
	uint64_t m_gutterWidthChars;

	LinearViewLine m_line;
	BinaryNinja::FunctionViewType m_viewType;
	QProgressIndicator* m_updateIndicator;

public:
	StickyHeader(BinaryViewRef data, LinearView* parent);

	void updateLine(const LinearViewLine& line);
	void updateViewType(const BinaryNinja::FunctionViewType& viewType);
	void updateFonts();

	virtual void paintEvent(QPaintEvent* event) override;
};


/*!

    \ingroup linearview
*/
class BINARYNINJAUIAPI LinearView : public QAbstractScrollArea, public View, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	class LinearViewOptionsWidget : public MenuHelper
	{
	public:
		LinearViewOptionsWidget(LinearView* parent);

	protected:
		virtual void showMenu();

	private:
		LinearView* m_view;
	};

	class LinearViewOptionsIconWidget : public QWidget
	{
	public:
		LinearViewOptionsIconWidget(LinearView* parent);

	private:
		LinearView* m_view;
		ContextMenuManager* m_contextMenuManager;
		Menu m_menu;

		void showMenu();
	};

	class LinearViewStatusBarWidget : public StatusBarWidget
	{
	public:
		LinearViewStatusBarWidget(LinearView* parent);
		virtual void updateStatus() override;

	private:
		LinearView* m_view;
		LinearViewOptionsWidget* m_options;
		ILChooserWidget* m_chooser;
	};

	BinaryViewRef m_data;
	ViewFrame* m_view;
	uint64_t m_allocatedLength;

	StickyHeader* m_header;
	RenderContext m_render;
	int m_cols, m_rows;
	uint64_t m_scrollBarMultiplier;
	int m_wheelDelta;
	bool m_updatingScrollBar;

	std::atomic<bool> m_updatesRequired;
	bool m_updateBounds;

	LinearViewCursorPosition m_cursorPos, m_selectionStartPos;
	bool m_cursorAscii;
	bool m_tokenSelection = false;
	HighlightTokenState m_highlight;
	bool m_displayCollapseIndicators = false;
	uint64_t m_navByRefTarget;
	bool m_navByRef = false;
	bool m_doubleClickLatch = false;
	FunctionRef m_relatedHighlightFunction;
	std::set<size_t> m_relatedIndexHighlights;
	std::set<uint64_t> m_relatedInstructionHighlights;

	SettingsRef m_settings;
	DisassemblySettingsRef m_options;
	BinaryNinja::FunctionViewType m_ilViewType, m_prevILViewType = InvalidILViewType;
	HexEditorHighlightState m_highlightState;
	bool m_singleFunctionView = false;

	InstructionEdit* m_instrEdit;

	BNAddressRange m_cacheBounds;
	std::vector<BNAddressRange> m_cachedRegions;
	std::shared_mutex m_cacheMutex;
	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> m_topPosition, m_bottomPosition;
	std::vector<LinearViewLine> m_lines;
	size_t m_emptyPrevCursors;
	size_t m_emptyNextCursors;
	size_t m_topLine;
	std::optional<double> m_topOrderingIndexOffset;

	QTimer* m_hoverTimer;
	QPointF m_previewPos;

	ContextMenuManager* m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	std::map<FunctionRef, BinaryNinja::AdvancedFunctionAnalysisDataRequestor> m_analysisRequestors;

	std::string m_navigationMode = "";

	ClickableIcon* m_dataButton = nullptr;
	QWidget* m_dataButtonContainer = nullptr;
	QHBoxLayout* m_dataButtonLayout = nullptr;

	std::set<std::string> m_layers;

	void setTopToAddress(uint64_t addr);
	void setTopToOrderingIndex(uint64_t idx);
	void refreshLines(size_t lineOffset = 0, bool refreshUIContext = true);
	bool cachePreviousLines();
	bool cacheNextLines();
	void updateCache();
	void updateBounds();
	void updateHighlight();
	void refreshAtCurrentLocation(bool cursorFixup = false);
	bool navigateToAddress(uint64_t addr, bool center, bool updateHighlight, bool navByRef = false);
	bool navigateToLine(
		FunctionRef func, uint64_t offset, size_t instrIndex, bool center, bool updateHighlight, bool navByRef = false);
	bool navigateToGotoLabel(uint64_t label);
	bool navigateToMatchingBrace();
	bool navigateToExternalLink(uint64_t linkSourceAddr);
	void setSelectionOffsetsInternal(BNAddressRange range, bool navigateToStart = true);
	void viewData();

	void scrollLines(int count);

	void bindActions();
	void bindDynamicActions();
	static void addOptionsMenuActions(Menu& menu);

	void getHexDumpLineBytes(
		const BinaryNinja::LinearDisassemblyLine& line, size_t& skippedBytes, size_t& totalBytes, size_t& totalCols);

	void paintHexDumpLine(QPainter& p, const LinearViewLine& line, int xoffset, int y, int tagOffset);
	void paintAnalysisWarningLine(QPainter& p, const LinearViewLine& line, int xoffset, int y);
	void paintTokenLine(QPainter& p, const LinearViewLine& line, int xoffset, int y, QRect eventRect, int tagOffset);

	void setSectionSemantics(const std::string& name, BNSectionSemantics semantics);

	bool isLineValidHighlight(const BinaryNinja::LinearDisassemblyLine& line);
	void ensureLineVisible(size_t line);

	TypeRef createStructure(BinaryNinja::QualifiedName& name, uint64_t size);
	TypeRef getInnerType(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerType(
		TypeRef type, TypeRef baseType, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerPointer(TypeRef type, ArchitectureRef arch, uint64_t baseAddress, uint64_t offset,
		uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerStruct(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerArray(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerName(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerIntegerSize(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerSign(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	TypeRef getPointerTypeAndName(ArchitectureRef arch, uint64_t addr, std::string& name);
	std::string getVariableName(uint64_t addr);

	BinaryNinja::Ref<BinaryNinja::LinearViewObject> createLinearViewObject();
	LinearViewCursorPosition getPositionForCursor(BinaryNinja::LinearViewCursor* cursor);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate, BinaryNinja::LinearViewCursor* matched, bool fullMatch);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate, BinaryNinja::LinearViewCursor* newCursor);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate,
		const std::vector<BinaryNinja::LinearViewObjectIdentifier>& path, BinaryNinja::LinearViewCursor* newCursor);
	uint64_t getOrderingIndexForLine(const LinearViewLine& line);

	void updateAnalysisRequestorsForCache();

	ArchitectureRef getArchitecture(const LinearViewLine& line);
	uint64_t getTokenAddress();

	BNAnalysisWarningActionType getAnalysisWarningActionAtPos(const LinearViewLine& line, int x);

	void getCurrentOffsetByTypeInternal(
		TypeRef resType, uint64_t baseAddr, uint64_t& begin, uint64_t& end, bool singleLine, std::set<TypeRef>& seen);

	BNDeadStoreElimination getCurrentVariableDeadStoreElimination();

	void setDataButtonVisible(bool visible);
	std::optional<std::pair<BinaryNinja::Variable, BinaryNinja::Variable>> getMergeVariablesAtCurrentLocation();

private Q_SLOTS:
	void adjustSize(int width, int height);
	void viewInHexEditor();
	void viewInGraph();
	void cycleILView(bool forward);
	void copyAddressSlot();
	void goToAddress();
	void goToEntryPoint();
	void goToAddressAtFileOffset();
	void defineNameAtAddr(uint64_t addr);
	void defineName();
	void undefine();
	void setUserVariableValue();
	void clearUserVariableValue();
	void createFunc(const UIActionContext& context);
	void createFuncWithPlatform(PlatformRef platform, bool autoSelect = false);
	void defineFuncName();
	void editFunctionProperties();
	void reanalyze();
	void forwardPropagateType();
	void inferFunctionType();
	void propagateVariableTypeAndName();
	void comment();
	void commentAccepted();
	void addUserXref();
	void bookmarkAddress();
	void unbookmarkAddress();
	void tagAddress();
	void tagAddressAccepted(TagTypeRef tt, const QString& text);
	void manageAddressTags();

	void createExternalLink();
	void editExternalLink();
	void removeExternalLink();

	void convertToNop();
	void alwaysBranch();
	void invertBranch();
	void skipAndReturnZero();
	void skipAndReturnValue();

	void makeTypes(TypeRef type);
	void makeInt8();
	void makeInt16();
	void makeInt32();
	void makeInt64();
	void toggleIntSize();
	void toggleIntSign();
	void makeFloat32();
	void makeFloat64();
	void toggleFloatSize();
	void makePtr();
	void makeString(size_t charSize = 1);
	void changeType(const UIActionContext& context);
	void undefineInRange();
	void displayAs(const UIActionContext& context, BNIntegerDisplayType displayType) override;
	void createStructOrInferStructureType();
	bool autoCreateArray();
	void createArray();
	void createStruct();
	void createNewTypes();
	void mergeVariables();
	void mergeVariablesAtCurrentLocation();
	void splitVariable();

	//! Get the length of of the string (if there is one) starting at the
	//! given address. String type is assumed to be UTF-8 by default, but the
	//! `charSize` parameter can be set to 2 or 4 to look for UTF-16 or
	//! UTF-32 string, respectively.
	//!
	//! Returns the length of the string in bytes, NOT the number of characters.
	size_t getStringLength(uint64_t startAddr, size_t charSize = 1);

	void setInstructionHighlight(BNHighlightColor color);
	void setBlockHighlight(BNHighlightColor color);

	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void hoverTimerEvent();

	void setStackAdjustment();
	void setCallTypeAdjustment();

	void editInstruction();
	void instrEditDoneEvent();
	std::optional<uint64_t> addressForCall();

	void setCurrentVariableDeadStoreElimination(BNDeadStoreElimination elimination);

Q_SIGNALS:
	void notifyResizeEvent(int width, int height);

public:
	explicit LinearView(BinaryViewRef data, ViewFrame* view);
	virtual ~LinearView();

	virtual void notifyRefresh() override;

	virtual bool canAssemble() override { return true; }
	virtual bool canCompile() override { return true; }

	virtual BinaryViewRef getData() override { return m_data; }
	void getCurrentOffsetByType(TypeRef resType, uint64_t baseAddr, uint64_t& begin, uint64_t& end, bool singleLine);
	virtual DisassemblySettingsRef getDisassemblySettings() override;
	virtual void setDisassemblySettings(DisassemblySettingsRef settings) override;
	virtual uint64_t getCurrentOffset() override;
	virtual UIActionContext actionContext() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual SelectionInfoForXref getSelectionForXref() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual FunctionRef getCurrentFunction() override;
	virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
	virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;
	virtual HighLevelILFunctionRef getCurrentHighLevelILFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;
	virtual size_t getCurrentILInstructionIndex() override;
	virtual size_t getSelectionStartILInstructionIndex() override;
	virtual BNILIndexRange getILIndexRange() override;
	virtual bool navigate(uint64_t offset) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t offset) override;
	virtual bool navigateToViewLocation(const ViewLocation& viewLocation, bool center = false) override;

	virtual BinaryNinja::Ref<HistoryEntry> getHistoryEntry() override;
	virtual void navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry) override;

	virtual void OnBinaryDataWritten(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataInserted(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataRemoved(BinaryNinja::BinaryView* data, uint64_t offset, uint64_t len) override;
	virtual void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnDataVariableAdded(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableRemoved(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableUpdated(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataMetadataUpdated(BinaryNinja::BinaryView* view, uint64_t offset) override;
	virtual void OnSymbolAdded(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* var) override;
	virtual void OnSymbolRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* var) override;
	virtual void OnSymbolUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* var) override;
	virtual void OnTagAdded(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;
	virtual void OnTagUpdated(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;
	virtual void OnTagRemoved(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;
	virtual void OnTypeDefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type) override;
	virtual void OnTypeUndefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type) override;
	virtual void OnSegmentAdded(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
	virtual void OnSegmentUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
	virtual void OnSegmentRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
	virtual void OnSectionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void MarkUpdatesForRegion(uint64_t start, uint64_t end);
	virtual void MarkUpdatesForFunction(BinaryNinja::Function* func);
	virtual void MarkUpdatesForType(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type);
	virtual void MarkUpdatesForDataVariable(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var);
	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;
	virtual ViewPaneHeaderSubtypeWidget* getHeaderSubtypeWidget() override;
	virtual QWidget* getHeaderOptionsWidget() override;

	virtual void followPointer();

	virtual bool canCopyWithTransform() override;
	virtual void cut() override;
	virtual void copy(TransformRef xform = nullptr) override;
	virtual void paste(TransformRef xform = nullptr) override;
	virtual void copyAddress() override;

	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }
	void setHighlightTokenState(const HighlightTokenState& hts);

	virtual BinaryNinja::FunctionViewType getILViewType() override { return m_ilViewType; };
	virtual void setILViewType(const BinaryNinja::FunctionViewType& ilViewType) override;

	void setHighlightMode(HexEditorHighlightMode mode);
	void setColorMode(HexEditorColorMode mode);
	void setContrast(HexEditorHighlightContrast mode);

	void toggleOption(BNDisassemblyOption option);
	void setAddressMode(std::optional<BNDisassemblyAddressMode> mode, std::optional<bool> hex, std::optional<bool> withName);
	void setCallParamHints(BNDisassemblyCallParameterHints hints);
	void setDisplayedFileName();
	void setAddressBaseOffset(bool toHere);

	void toggleRenderLayer(const std::string& layer);
	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> applyRenderLayers(BinaryNinja::Ref<BinaryNinja::LinearViewCursor> cursor);

	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;
	QFont getFont() override { return m_render.getFont(); }

	virtual void clearRelatedHighlights() override;
	virtual void setRelatedIndexHighlights(FunctionRef func, const std::set<size_t>& related) override;
	virtual void setRelatedInstructionHighlights(FunctionRef func, const std::set<uint64_t>& related) override;

	bool singleFunctionView() const { return m_singleFunctionView; }
	void setSingleFunctionView(bool singleFunctionView);

	static void registerActions();

protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;

	void up(bool selecting, size_t count = 1);
	void down(bool selecting, size_t count = 1);
	void left(bool selecting);
	void right(bool selecting);
	void leftToSymbol(bool selecting);
	void rightToSymbol(bool selecting);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView();
	void moveToEndOfView();
	void selectNone();
	void selectAll();
	void navigateToHighlightedToken();
	void splitToNewTabAndNavigateFromCursorPosition();
	void splitToNewWindowAndNavigateFromCursorPosition();
	void splitToNewPaneAndNavigateFromCursorPosition();

	void extendSelectionToStartOfBinary();
	void extendSelectionToEndOfBinary();
	void extendSelectionToStartOfSection();
	void extendSelectionToEndOfSection();
	void extendSelectionToStartOfSegment();
	void extendSelectionToEndOfSegment();
	void extendSelectionToStartOfDataVariable();
	void extendSelectionToEndOfDataVariable();
	void extendSelectionByBytes();
	void extendSelectionToAddress();
	void setSelectionSizeTo();
	void saveSelectionTo();

	bool canExtendSelectionToStartOfSection();
	bool canExtendSelectionToEndOfSection();
	bool canExtendSelectionToStartOfSegment();
	bool canExtendSelectionToEndOfSegment();
	bool canExtendSelectionToStartOfDataVariable();
	bool canExtendSelectionToEndOfDataVariable();
};

/*!

    \ingroup linearview
*/
class LinearViewType : public ViewType
{
	static LinearViewType* m_instance;

public:
	LinearViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void init();
};

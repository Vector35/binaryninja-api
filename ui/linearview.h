#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "commentdialog.h"
#include "menus.h"
#include "statusbarwidget.h"
#include "uicontext.h"
#include "instructionedit.h"
#include <assembledialog.h>

#define LINEAR_VIEW_UPDATE_CHECK_INTERVAL 200
#define MAX_STRING_TYPE_LENGTH 1048576

struct BINARYNINJAUIAPI LinearViewLine: public BinaryNinja::LinearDisassemblyLine
{
	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> cursor;
	size_t lineIndex;
};

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

class BINARYNINJAUIAPI LinearViewHistoryEntry: public HistoryEntry
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
};

class BINARYNINJAUIAPI LinearView: public QAbstractScrollArea, public View, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	class LinearViewOptionsWidget: public MenuHelper
	{
	public:
		LinearViewOptionsWidget(LinearView* parent);

	protected:
		virtual void showMenu();

	private:
		LinearView* m_view;
	};

	class LinearViewStatusBarWidget: public StatusBarWidget
	{
	public:
		LinearViewStatusBarWidget(LinearView* parent);
		virtual void updateStatus() override;

	private:
		LinearView* m_view;
		LinearViewOptionsWidget* m_options;
	};

	BinaryViewRef m_data;
	ViewFrame* m_view;
	uint64_t m_allocatedLength;

	RenderContext m_render;
	int m_cols, m_rows;
	uint64_t m_scrollBarMultiplier;
	int m_wheelDelta;
	bool m_updatingScrollBar;

	bool m_updatesRequired;
	bool m_updateBounds;

	LinearViewCursorPosition m_cursorPos, m_selectionStartPos;
	bool m_cursorAscii;
	bool m_tokenSelection = false;
	HighlightTokenState m_highlight;
	uint64_t m_navByRefTarget;
	bool m_navByRef = false;

	SettingsRef m_settings;
	DisassemblySettingsRef m_options;
	BNFunctionGraphType m_ilViewType;

	InstructionEdit* m_instrEdit;

	BinaryNinja::Ref<BinaryNinja::LinearViewCursor> m_topPosition, m_bottomPosition;
	std::vector<LinearViewLine> m_lines;
	size_t m_topLine;

	QTimer* m_updateTimer;

	ContextMenuManager* m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	std::map<FunctionRef, BinaryNinja::AdvancedFunctionAnalysisDataRequestor> m_analysisRequestors;

	std::string m_navigationMode = "";

	void setTopToAddress(uint64_t addr);
	void setTopToOrderingIndex(uint64_t idx);
	void refreshLines(size_t lineOffset = 0, bool refreshUIContext = true);
	bool cachePreviousLines();
	bool cacheNextLines();
	void updateCache();
	void refreshAtCurrentLocation(bool cursorFixup = false);
	bool navigateToAddress(uint64_t addr, bool center, bool updateHighlight, bool navByRef = false);
	bool navigateToLine(uint64_t offset, size_t instrIndex, bool center, bool updateHighlight, bool navByRef = false);
	bool navigateToGotoLabel(uint64_t label);

	void scrollLines(int count);

	void bindActions();
	void getHexDumpLineBytes(const BinaryNinja::LinearDisassemblyLine& line, size_t& skippedBytes, size_t& totalBytes,
		size_t& totalCols);

	void paintHexDumpLine(QPainter& p, const LinearViewLine& line, int xoffset, int y, uint32_t addrLen, int tagOffset);
	void paintAnalysisWarningLine(QPainter& p, const LinearViewLine& line, int xoffset, int y);
	void paintTokenLine(QPainter& p, const LinearViewLine& line, int xoffset, int y, QRect eventRect, int tagOffset);

	void setSectionSemantics(const std::string& name, BNSectionSemantics semantics);

	bool isLineValidHighlight(const BinaryNinja::LinearDisassemblyLine& line);
	void ensureLineVisible(size_t line);

	TypeRef createStructure(BinaryNinja::QualifiedName& name, uint64_t size);
	StructureRef defineInnerType(TypeRef type, TypeRef baseType, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerPointer(TypeRef type, ArchitectureRef arch, uint64_t baseAddress,
		uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerStruct(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerArray(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerName(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerUnknownType(QWidget* parent, TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerIntegerSize(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	StructureRef defineInnerSign(TypeRef type, uint64_t offset, uint64_t size, std::set<TypeRef>& seen);
	TypeRef getPointerTypeAndName(ArchitectureRef arch, uint64_t addr, std::string& name);
	std::string getVariableName(uint64_t addr);

	BinaryNinja::Ref<BinaryNinja::LinearViewObject> createLinearViewObject();
	LinearViewCursorPosition getPositionForCursor(BinaryNinja::LinearViewCursor* cursor);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate, BinaryNinja::LinearViewCursor* matched, bool fullMatch);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate, BinaryNinja::LinearViewCursor* newCursor);
	bool updateCursor(LinearViewCursorPosition& cursorToUpdate,
		const std::vector<BinaryNinja::LinearViewObjectIdentifier>& path,
		BinaryNinja::LinearViewCursor* newCursor);
	uint64_t getOrderingIndexForLine(const LinearViewLine& line);

	void updateAnalysisRequestorsForCache();

	ArchitectureRef getArchitecture(const LinearViewLine& line);
	uint64_t getTokenAddress();

	BNAnalysisWarningActionType getAnalysisWarningActionAtPos(const LinearViewLine& line, int x);

	void getCurrentOffsetByTypeInternal(TypeRef resType, uint64_t baseAddr, uint64_t& begin, uint64_t& end,
		bool singleLine, std::set<TypeRef>& seen);

	BNDeadStoreElimination getCurrentVariableDeadStoreElimination();

private Q_SLOTS:
	void adjustSize(int width, int height);
	void viewInHexEditor();
	void viewInGraph();
	void viewInTypesView(std::string typeName = "", uint64_t offset = 0);
	void cycleILView(bool forward);
	void copyAddressSlot();
	void goToAddress();
	void goToAddressAtFileOffset();
	void defineNameAtAddr(uint64_t addr);
	void defineName();
	void undefineName();
	void setUserVariableValue();
	void clearUserVariableValue();
	void createFunc();
	void createFuncWithPlatform(PlatformRef platform, bool autoSelect = false);
	void defineFuncName();
	void undefineFunc();
	void reanalyze();
	void comment();
	void commentAccepted();
	void addUserXref();
	void bookmarkAddress();
	void unbookmarkAddress();
	void tagAddress();
	void tagAddressAccepted(TagTypeRef tt);
	void manageAddressTags();

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
	void makePtr();
	void makeString();
	void changeType();
	void undefineVariable();
	void displayAs(const UIActionContext& context, BNIntegerDisplayType displayType) override;
	void createStructOrInferStructureType();
	void createArray();
	void createStruct();
	void createNewTypes();

	size_t getStringLength(uint64_t startAddr);

	void setInstructionHighlight(BNHighlightColor color);
	void setBlockHighlight(BNHighlightColor color);

	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void updateTimerEvent();

	void setStackAdjustment();
	void setCallTypeAdjustment();

	void editInstruction();
	void instrEditDoneEvent();

	void setCurrentVariableDeadStoreElimination(BNDeadStoreElimination elimination);

Q_SIGNALS:
	void notifyResizeEvent(int width, int height);

public:
	explicit LinearView(BinaryViewRef data, ViewFrame* view);
	virtual ~LinearView();

	virtual bool canAssemble() override { return true; }
	virtual bool canCompile() override { return true; }

	virtual BinaryViewRef getData() override { return m_data; }
	void getCurrentOffsetByType(TypeRef resType, uint64_t baseAddr, uint64_t& begin, uint64_t& end, bool singleLine);
	virtual uint64_t getCurrentOffset() override;
	virtual UIActionContext actionContext() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual SelectionInfoForXref getSelectionForXref() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;
	virtual size_t getCurrentILInstructionIndex() override;
	virtual bool navigate(uint64_t offset) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t offset) override;
	virtual bool navigateToViewLocation(const ViewLocation& viewLocation) override;

	virtual std::string getNavigationMode() override;
	virtual void setNavigationMode(std::string mode) override;
	virtual std::vector<std::string> getNavigationModes() override;

	virtual HistoryEntry* getHistoryEntry() override;
	virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

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
	virtual void OnTagUpdated(BinaryNinja::BinaryView* data, const BinaryNinja::TagReference& tagRef) override;

	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	virtual void followPointer();

	virtual void cut() override;
	virtual void copy(TransformRef xform = nullptr) override;
	virtual void paste(TransformRef xform = nullptr) override;
	virtual void copyAddress() override;

	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }

	virtual BNFunctionGraphType getILViewType() override { return m_ilViewType; };
	virtual void setILViewType(BNFunctionGraphType ilViewType) override;

	void toggleOption(BNDisassemblyOption option);

	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;
	QFont getFont() override { return m_render.getFont(); }

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
	void navigateToHighlightedToken();
};

class LinearViewType: public ViewType
{
	static LinearViewType* m_instance;

public:
	LinearViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void init();
};

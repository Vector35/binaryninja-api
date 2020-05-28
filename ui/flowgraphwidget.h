#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QAbstractScrollArea>
#include "binaryninjaapi.h"
#include "render.h"
#include "viewframe.h"
#include "menus.h"
#include "uicontext.h"
#include "commentdialog.h"
#include "instructionedit.h"

class BINARYNINJAUIAPI GraphLayoutCompleteEvent: public QEvent
{
	FlowGraphRef m_graph;
public:
	GraphLayoutCompleteEvent(QEvent::Type type, const FlowGraphRef& graph);
	FlowGraphRef GetGraph() { return m_graph; }
};

class BINARYNINJAUIAPI FlowGraphHistoryEntry: public HistoryEntry
{
	PlatformRef m_platform;
	ArchitectureRef m_arch;
	uint64_t m_func;
	int m_scrollX, m_scrollY;
	float m_scale;
	uint64_t m_addr;
	HighlightTokenState m_highlight;

public:
	PlatformRef getPlatform() const { return m_platform; }
	ArchitectureRef getArchitecture() const { return m_arch; }
	uint64_t getFunction() const { return m_func; }
	int getScrollX() const { return m_scrollX; }
	int getScrollY() const { return m_scrollY; }
	float getScale() const { return m_scale; }
	uint64_t getCurrentAddress() const { return m_addr; }
	const HighlightTokenState& getHighlightTokenState() const { return m_highlight; }

	void setPlatform(PlatformRef platform) { m_platform = platform; }
	void setArchitecture(ArchitectureRef arch) { m_arch = arch; }
	void setFunction(uint64_t f) { m_func = f; }
	void setScrollX(int x) { m_scrollX = x; }
	void setScrollY(int y) { m_scrollY = y; }
	void setScale(float s) { m_scale = s; }
	void setCurrentAddress(uint64_t a) { m_addr = a; }
	void setHighlightTokenState(const HighlightTokenState& state) { m_highlight = state; }
};

class BINARYNINJAUIAPI FlowGraphWidget: public QAbstractScrollArea, public View, public PreviewScrollHandler,
	public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	struct CursorPosition
	{
		size_t lineInNode;
		uint64_t address;
		size_t instrIndex;
		size_t lineIndexForAddress;
		size_t tokenIndex;
	};

	BinaryViewRef m_data;
	FlowGraphRef m_graph;
	FlowGraphRef m_updateGraph;
	FlowGraphLayoutRequestRef m_graphLayoutRequest;
	FlowGraphLayoutRequestRef m_updateGraphLayoutRequest;
	FunctionRef m_func;
	BinaryNinja::AdvancedFunctionAnalysisDataRequestor m_advancedAnalysisData;
	View* m_navigationTarget;

	bool m_ready;
	QTimer* m_loadingTimer;
	QTimer* m_updateTimer;
	QTimer* m_zoomTimer;
	QTimer* m_zoomPauseTimer;

	std::mutex m_updateMutex;
	bool m_updated;

	RenderContext m_render;
	int m_width, m_height;
	int m_renderXOfs, m_renderYOfs, m_renderWidth, m_renderHeight;
	float m_scale;
	QRect m_renderRect;
	QRect m_miniRenderRect;

	bool m_scrollMode;
	int m_scrollBaseX, m_scrollBaseY;
	bool m_mouseSelectMode = false;

	FlowGraphNodeRef m_selectedNode, m_selectedEdgeSource;
	bool m_selectedEdgeIncoming = false;
	std::map<FlowGraphNodeRef, FlowGraphNodeRef> m_selectedEdgeIncomingPriority, m_selectedEdgeOutgoingPriority;
	BinaryNinja::FlowGraphEdge m_selectedEdge;
	CursorPosition m_cursorPos, m_selectionStartPos;
	HighlightTokenState m_highlight;
	bool m_tokenSelection = false;

	ContextMenuManager m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	BinaryNinja::Ref<FlowGraphHistoryEntry> m_pendingHistoryEntry, m_layoutHistoryEntry;
	bool m_useAddrAfterLayout;
	uint64_t m_addrAfterLayout;
	bool m_pendingXrefNavigation, m_xrefNavigation;
	uint64_t m_xrefTarget;

	InstructionEdit* m_instrEdit;

	bool m_isPreview;
	QPointF m_previewPos;
	QTimer* m_hoverTimer;

	FlowGraphRef m_recenterWithGraph;
	int m_recenterXofs, m_recenterYofs;

	static int m_layoutCompleteEventType;
	static int m_updateCompleteEventType;

	void adjustSize(int width, int height);

	void defineNameAtAddr(uint64_t addr);

	static std::string getValueStr(int64_t value);
	static std::string getValueStr(uint64_t value);

	FlowGraphNodeRef findUpdatedNode(FlowGraphRef oldGraph, FlowGraphNodeRef oldNode, CursorPosition& pos);
	bool updatePositionForNode(FlowGraphNodeRef oldNode, FlowGraphNodeRef newNode, CursorPosition& pos);
	void recenterUpdatedGraph(FlowGraphRef oldGraph, int oldXOfs, int oldYOfs);

protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;

	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;

	virtual void customEvent(QEvent* event) override;

	virtual void scrollContentsBy(int dx, int dy) override;

	bool getNodeForMouseEvent(QMouseEvent* event, FlowGraphNodeRef& node);
	bool getLineForMouseEvent(QMouseEvent* event, CursorPosition& pos);
	bool getEdgeForMouseEvent(QMouseEvent* event, FlowGraphNodeRef& source,
		BinaryNinja::FlowGraphEdge& edge, bool& incoming);
	HighlightTokenState getTokenForMouseEvent(QMouseEvent* event);

	void showContextMenu();
	void bindActions();

	void navigateToAddress(uint64_t addr);
	void navigateToGotoLabel(uint64_t label);

	void setGraphInternal(FlowGraphRef graph, FlowGraphHistoryEntry* entry, bool useAddr, uint64_t addr, bool notify,
		bool recenterWithPreviousGraph);

	void up(bool selecting, size_t count = 1);
	void down(bool selecting, size_t count = 1);
	void left(bool selecting);
	void right(bool selecting);
	void leftToSymbol(bool selecting);
	void rightToSymbol(bool selecting);
	void pageUp(bool selecting);
	void pageDown(bool selecting);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView();
	void moveToEndOfView();
	void selectAll();
	void selectNone();
	void navigateToHighlightedToken();

	uint64_t getTokenAddress();

public:
	FlowGraphWidget(QWidget* parent, BinaryViewRef view, FlowGraphRef graph = FlowGraphRef());
	~FlowGraphWidget();

	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdateRequested(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnDataMetadataUpdated(BinaryNinja::BinaryView* data, uint64_t offset) override;
	virtual void OnTagUpdated(BinaryNinja::BinaryView* data, const BinaryNinja::TagReference& tagRef) override;

	void setInitialGraph(FlowGraphRef graph);
	void setInitialGraph(FlowGraphRef graph, uint64_t addr);

	void setGraph(FlowGraphRef graph);
	void setGraph(FlowGraphRef graph, uint64_t addr);
	void setGraph(FlowGraphRef graph, FlowGraphHistoryEntry* entry);
	void setRelatedGraph(FlowGraphRef graph);
	void updateToGraph(FlowGraphRef graph);
	virtual void updateFonts() override;

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual BNAddressRange getSelectionForInfo() override;
	virtual bool navigate(uint64_t pos) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;
	bool navigateWithHistoryEntry(uint64_t addr, FlowGraphHistoryEntry* entry);
	bool navigateWithHistoryEntry(FunctionRef func, uint64_t addr, FlowGraphHistoryEntry* entry);
	void setNavigationTarget(View* target) { m_navigationTarget = target; }

	virtual void zoom(bool direction);
	virtual void zoomActual();
	virtual bool event(QEvent* event) override;
	void disableZoom();
	virtual void sendWheelEvent(QWheelEvent* event) override;

	virtual void cut() override;
	virtual void copy(TransformRef xform) override;
	virtual void paste(TransformRef xform) override;

	virtual bool canAssemble() override;
	virtual bool canCompile() override;
	virtual bool canPaste() override;

	virtual void closing() override;

	virtual HistoryEntry* getHistoryEntry() override;
	void populateDefaultHistoryEntry(FlowGraphHistoryEntry* entry);
	virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;

	virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
	virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;
	virtual size_t getCurrentILInstructionIndex() override;

	void scrollToCursor();
	bool isUpdating();

	QFont getFont() override { return m_render.getFont(); }
	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }
	QRect getMiniRenderRect() const { return m_miniRenderRect; }
	void paintMiniGraphAndViewport(QWidget* owner);
	bool paintMiniGraph(QWidget* owner, QPainter& p);

	void showAddress(uint64_t addr, bool select = false);
	void showTopNode();
	void showNode(FlowGraphNodeRef node);
	void showLineInNode(FlowGraphNodeRef node, size_t lineIndex);
	void ensureCursorVisible();

	void viewInTypesView(std::string typeName);

	void setInstructionHighlight(BNHighlightColor color);
	void setBlockHighlight(BNHighlightColor color);

	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;

	void setHighlightToken(const HighlightTokenState& state, bool notify = true);

	virtual void notifyUpdateInProgress(FunctionRef func);
	virtual void onFunctionSelected(FunctionRef func);
	virtual void onHighlightChanged(const HighlightTokenState& highlight);

	static std::string getPossibleValueSetStateName(BNRegisterValueType state);
	static std::string getStringForRegisterValue(ArchitectureRef arch, BinaryNinja::RegisterValue value);
	static std::string getStringForPossibleValueSet(ArchitectureRef arch, const BinaryNinja::PossibleValueSet& values);

Q_SIGNALS:
	void layoutComplete();
	void updateMiniGraph();

private Q_SLOTS:
	void loadingTimerEvent();
	void updateTimerEvent();
	void hoverTimerEvent();
	void zoomTimerEvent();
	bool zoomDisabled();
	void zoomPauseTimerEvent();

	void goToAddress();
	void followPointer();
	void defineName();
	void undefineName();
	void defineFuncName();
	void undefineFunc();
	void createFunc();
	void changeType();
	void inferStructureType();
	void comment();
	void addUserXref();
	void functionComment();
	void commentAccepted();
	void functionCommentAccepted();
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

	void displayAsDefault();
	void displayAsBinary();
	void displayAsSignedOctal();
	void displayAsUnsignedOctal();
	void displayAsSignedDecimal();
	void displayAsUnsignedDecimal();
	void displayAsSignedHexadecimal();
	void displayAsUnsignedHexadecimal();
	void displayAsCharacterConstant();
	void displayAsPointer();

	void makePtr();
	void makeString();

	void reanalyze();

	void setStackAdjustment();
	void setCallTypeAdjustment();

	void editInstruction();
	void instrEditDoneEvent();
};

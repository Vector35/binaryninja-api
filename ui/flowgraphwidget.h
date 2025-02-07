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

/*!

	\defgroup flowgraphwidget FlowGraphWidget
 	\ingroup uiapi
*/

/*!

    \ingroup flowgraphwidget
*/
class BINARYNINJAUIAPI GraphLayoutCompleteEvent : public QEvent
{
	FlowGraphRef m_graph;

  public:
	GraphLayoutCompleteEvent(QEvent::Type type, const FlowGraphRef& graph);
	FlowGraphRef GetGraph() { return m_graph; }
};

/*!

    \ingroup flowgraphwidget
*/
class BINARYNINJAUIAPI FlowGraphHistoryEntry : public HistoryEntry
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

	virtual Json::Value serialize() const override;
	virtual bool deserialize(const Json::Value& value) override;
};

class BINARYNINJAUIAPI FlowGraphWidget :
    public QAbstractScrollArea,
    public View,
    public PreviewScrollHandler,
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
		size_t characterIndex;
		// Directly from QMouseEvent, not used in comparators
		int cursorX;
		int cursorY;

		bool operator==(const CursorPosition& other) const;
		bool operator<(const CursorPosition& other) const;
		bool operator<=(const CursorPosition& other) const;
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
	QTimer* m_zoomTimer;
	QTimer* m_zoomPauseTimer;

	std::mutex m_updateMutex;
	bool m_updated;

	RenderContext m_render;
	int m_width, m_height;
	int m_renderXOfs, m_renderYOfs, m_renderWidth, m_renderHeight;
	float m_scale;
	QRect m_renderRect;

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
	std::set<size_t> m_relatedIndexHighlights;
	std::set<uint64_t> m_relatedInstructionHighlights;

	ContextMenuManager* m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	BinaryNinja::Ref<FlowGraphHistoryEntry> m_pendingHistoryEntry, m_layoutHistoryEntry;
	bool m_useAddrAfterLayout;
	uint64_t m_addrAfterLayout;
	bool m_pendingXrefNavigation, m_xrefNavigation;
	uint64_t m_xrefTarget;
	size_t m_indexAfterlayout;

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

	BNDeadStoreElimination getCurrentVariableDeadStoreElimination();
	std::optional<std::pair<BinaryNinja::Variable, BinaryNinja::Variable>> getMergeVariablesAtCurrentLocation();

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

	HighlightTokenState getTokenForMouseEvent(QMouseEvent* event);

	virtual void contextMenuEvent(QContextMenuEvent*) override;
	void bindActions();
	virtual void bindDynamicActions();

	void navigateToAddress(uint64_t addr);
	void navigateToGotoLabel(uint64_t label);

	void setGraphInternal(FlowGraphRef graph, BinaryNinja::Ref<FlowGraphHistoryEntry> entry, bool useAddr,
	    uint64_t addr, bool notify, bool recenterWithPreviousGraph, size_t index = BN_INVALID_EXPR);

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
	std::optional<uint64_t> addressForCall();

	uint64_t getTokenAddress();

	bool isFunctionHeader();

	bool m_enableBlockIndicators = false;

  public:
	FlowGraphWidget(QWidget* parent, BinaryViewRef view, FlowGraphRef graph = FlowGraphRef());
	~FlowGraphWidget();

	virtual void notifyRefresh() override;

	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdateRequested(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnDataMetadataUpdated(BinaryNinja::BinaryView* data, uint64_t offset) override;
	virtual void OnTagUpdated(BinaryNinja::BinaryView* data, const BinaryNinja::TagReference& tagRef) override;

	void setInitialGraph(FlowGraphRef graph);
	void setInitialGraph(FlowGraphRef graph, uint64_t addr);

	void setGraph(FlowGraphRef graph);
	void setGraph(FlowGraphRef graph, uint64_t addr);
	void setGraphAtIndex(FlowGraphRef graph, size_t index);
	void setGraph(FlowGraphRef graph, BinaryNinja::Ref<FlowGraphHistoryEntry> entry);
	void setRelatedGraph(FlowGraphRef graph);
	void setRelatedGraph(FlowGraphRef graph, uint64_t addr);
	void updateToGraph(FlowGraphRef graph);
	virtual void updateFonts() override;

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual SelectionInfoForXref getSelectionForXref() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual bool navigate(uint64_t pos) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;
	virtual bool navigateToViewLocation(const ViewLocation& viewLocation, bool center = false) override;
	bool navigateWithHistoryEntry(uint64_t addr, BinaryNinja::Ref<FlowGraphHistoryEntry> entry);
	bool navigateWithHistoryEntry(FunctionRef func, uint64_t addr, BinaryNinja::Ref<FlowGraphHistoryEntry> entry);
	void setNavigationTarget(View* target) { m_navigationTarget = target; }

	virtual void clearRelatedHighlights() override;
	virtual void setRelatedIndexHighlights(FunctionRef func, const std::set<size_t>& related) override;
	virtual void setRelatedInstructionHighlights(FunctionRef func, const std::set<uint64_t>& related) override;

	float getScale() const { return m_scale; }
	float maxScale() const;
	virtual void zoom(bool direction);
	virtual void zoomToScale(float scale = 1.0f);
	virtual void zoomToCursor();
	virtual bool event(QEvent* event) override;
	void disableZoom();
	virtual void sendWheelEvent(QWheelEvent* event) override;

	virtual bool canCopyWithTransform() override;
	virtual bool canCut() override;
	virtual bool canCopy() override;
	virtual bool canCopyAddress() override;
	virtual bool canPaste() override;
	virtual void cut() override;
	virtual void copy(TransformRef xform) override;
	virtual void paste(TransformRef xform) override;

	virtual bool canAssemble() override;
	virtual bool canCompile() override;

	virtual void closing() override;

	virtual BinaryNinja::Ref<HistoryEntry> getHistoryEntry() override;
	void populateDefaultHistoryEntry(FlowGraphHistoryEntry* entry);
	virtual void navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry) override;

	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;

	virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
	virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;
	virtual HighLevelILFunctionRef getCurrentHighLevelILFunction() override;
	virtual size_t getCurrentILInstructionIndex() override;
	virtual size_t getSelectionStartILInstructionIndex() override;
	virtual BNILIndexRange getILIndexRange() override;

	void scrollToCursor(bool center = false);
	bool isUpdating();

	QFont getFont() override { return m_render.getFont(); }
	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }
	void paintMiniGraphAndViewport(QWidget* owner, QRect& miniRenderRect);
	bool paintMiniGraph(QWidget* owner, QPainter& p, QRect& miniRenderRect);

	void paintNode(QPainter& p, FlowGraphNodeRef& node, int minY, int maxY);
	void paintHighlight(QPainter& p, const std::vector<BinaryNinja::DisassemblyTextLine>& lines, int nodeX,
	    int nodeWidth, int x, int y, size_t line, int tagIndent);
	void paintEdge(QPainter& p, const FlowGraphNodeRef& node, const BinaryNinja::FlowGraphEdge& edge);

	void showAddress(uint64_t addr, bool select = false, bool center = false);
	void showIndex(size_t index, bool center = false);
	void showTopNode();
	void showNode(FlowGraphNodeRef node);
	void showLineInNode(FlowGraphNodeRef node, size_t lineIndex);
	void ensureCursorVisible();

	void setInstructionHighlight(BNHighlightColor color);
	void setBlockHighlight(BNHighlightColor color);

	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;

	void setHighlightToken(const HighlightTokenState& state, bool notify = true, bool update = false);

	virtual void notifyUpdateInProgress(FunctionRef func);
	virtual void onFunctionSelected(FunctionRef func);
	virtual void onHighlightChanged(const HighlightTokenState& highlight);

	// protected:
	// These APIs are really supposed to be protected but since the bindings need to call them
	// and they have out parameters (and thus need to be re-implemented) they must be public
	bool getNodeForMouseEvent(QMouseEvent* event, FlowGraphNodeRef& node);
	bool getLineForMouseEvent(QMouseEvent* event, CursorPosition& pos);
	bool getEdgeForMouseEvent(QMouseEvent* event, FlowGraphNodeRef& source, BinaryNinja::FlowGraphEdge& edge, bool& incoming);

	FlowGraphWidget* duplicate();

  Q_SIGNALS:
	void layoutComplete();
	void updateMiniGraph();

  private Q_SLOTS:
	void loadingTimerEvent();
	void hoverTimerEvent();
	void zoomTimerEvent();
	bool zoomDisabled();
	void zoomPauseTimerEvent();

	void goToAddress();
	void goToEntryPoint();
	void goToAddressAtFileOffset();
	void followPointer();
	void defineName();
	void undefine();
	void setUserVariableValue();
	void clearUserVariableValue();
	void defineFuncName();
	void editFunctionProperties();
	void createFunc(const UIActionContext& context);
	void createFuncWithPlatform(PlatformRef platform, bool autoSelect = false);
	void changeType();
	void inferStructureType(const UIActionContext& context);
	void forwardPropagateType();
	void inferFunctionType();
	void propagateVariableTypeAndName();
	void comment();
	void addUserXref();
	void functionComment();
	void commentAccepted();
	void functionCommentAccepted();
	void bookmarkAddress();
	void unbookmarkAddress();
	void tagAddress();
	void tagAddressAccepted(TagTypeRef tt, const QString& text);
	void manageAddressTags();
	void mergeVariables();
	void mergeVariablesAtCurrentLocation();
	void splitVariable();

	void convertToNop();
	void alwaysBranch();
	void invertBranch();
	void skipAndReturnZero();
	void skipAndReturnValue();

	void makePtr();
	void makeString(size_t charSize = 1);

	void reanalyze();

	void setStackAdjustment();
	void setCallTypeAdjustment();

	void editInstruction();
	void instrEditDoneEvent();

	void setCurrentVariableDeadStoreElimination(BNDeadStoreElimination elimination);
	void splitToNewTabAndNavigateFromCursorPosition();
	void splitToNewWindowAndNavigateFromCursorPosition();
	void splitToNewPaneAndNavigateFromCursorPosition();
};

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

#define LINEAR_VIEW_UPDATE_CHECK_INTERVAL 200
#define MAX_STRING_TYPE_LENGTH 1048576
#define EDGE_GUTTER_WIDTH 4

struct BINARYNINJAUIAPI LinearViewCursorPosition: public BinaryNinja::LinearDisassemblyPosition
{
	uint64_t lineAddress;
	size_t lineIndexForAddress;
	size_t tokenIndex;

	LinearViewCursorPosition();
	LinearViewCursorPosition(const LinearViewCursorPosition& pos);
	LinearViewCursorPosition(const BinaryNinja::LinearDisassemblyPosition& pos);
};

class BINARYNINJAUIAPI LinearViewHistoryEntry: public HistoryEntry
{
	BinaryNinja::LinearDisassemblyPosition m_topPosition;
	LinearViewCursorPosition m_cursorPosition;
	size_t m_topLineOffset;
	HighlightTokenState m_highlight;

public:
	const BinaryNinja::LinearDisassemblyPosition& getTopPosition() const { return m_topPosition; }
	const LinearViewCursorPosition& getCursorPosition() const { return m_cursorPosition; }
	size_t getTopLineOffset() const { return m_topLineOffset; }
	const HighlightTokenState& getHighlightTokenState() const { return m_highlight; }

	void setTopPosition(const BinaryNinja::LinearDisassemblyPosition& pos) { m_topPosition = pos; }
	void setCursorPosition(const LinearViewCursorPosition& pos) { m_cursorPosition = pos; }
	void setTopLineOffset(size_t offset) { m_topLineOffset = offset; }
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
	std::vector<BNAddressRange> m_ranges;
	uint64_t m_allocatedLength;

	RenderContext m_render;
	int m_cols, m_rows;
	uint64_t m_scrollBarMultiplier;
	int m_wheelDelta;
	bool m_updatingScrollBar;

	bool m_updatesRequired;
	bool m_updateBounds, m_updateBlockRef;

	LinearViewCursorPosition m_cursorPosition, m_selectionStartPos;
	bool m_tokenSelection = false;
	HighlightTokenState m_highlight;
	uint64_t m_navByRefTarget;
	bool m_navByRef = false;

	DisassemblySettingsRef m_settings;

	BinaryNinja::LinearDisassemblyPosition m_topPosition, m_bottomPosition;
	std::vector<BinaryNinja::LinearDisassemblyLine> m_lines;
	size_t m_topLine;

	QTimer* m_updateTimer;

	ContextMenuManager m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	void adjustSize(int width, int height);

	uint64_t getContiguousOffsetForAddress(uint64_t addr);
	uint64_t getAddressForContiguousOffset(uint64_t offset);

	void setTopToAddress(uint64_t addr);
	void refreshLines(size_t lineOffset = 0, bool refreshUIContext = true);
	bool cachePreviousLines();
	bool cacheNextLines(size_t& topLineAdjustment);
	void updateCache();
	void refreshAtCurrentLocation();
	bool navigateToAddress(uint64_t addr, bool center, bool updateHighlight, bool navByRef = false);

	void scrollLines(int count);

	void bindActions();
	void getHexDumpLineBytes(const BinaryNinja::LinearDisassemblyLine& line, size_t& skippedBytes, size_t& totalBytes,
		size_t& totalCols);

	void setSectionSemantics(const std::string& name, BNSectionSemantics semantics);

	bool isLineValidHighlight(const BinaryNinja::LinearDisassemblyLine& line);
	void ensureLineVisible(size_t line);

private Q_SLOTS:
	void viewInHexEditor();
	void viewInGraph();
	void viewInTypesView(std::string typeName = "");
	void copyAddressSlot();
	void goToAddress();
	void defineNameAtAddr(uint64_t addr);
	void defineName();
	void undefineName();
	void createFunc();
	void defineFuncName();
	void undefineFunc();
	void reanalyze();
	void comment();
	void commentAccepted();
	void addUserXref();

	void convertToNop();
	void alwaysBranch();
	void invertBranch();
	void skipAndReturnZero();
	void skipAndReturnValue();

	void makeInt8();
	void makeInt16();
	void makeInt32();
	void makeInt64();
	void toggleIntSize();
	void makePtr();
	void makeString();
	void changeType();
	size_t getStringLength(uint64_t startAddr);

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

	void setInstructionHighlight(BNHighlightColor color);
	void setBlockHighlight(BNHighlightColor color);

	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void updateTimerEvent();

public:
	explicit LinearView(BinaryViewRef data, ViewFrame* view);
	virtual ~LinearView();

	virtual bool canAssemble() override { return true; }
	virtual bool canCompile() override { return true; }

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual void getSelectionOffsets(uint64_t& begin, uint64_t& end) override;
	virtual void getSelectionForInfo(uint64_t& begin, uint64_t& end) override;
	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;
	virtual bool navigate(uint64_t pos) override;

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

	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	virtual void followPointer();

	virtual void cut() override;
	virtual void copy(TransformRef xform = nullptr) override;
	virtual void paste(TransformRef xform = nullptr) override;
	virtual void copyAddress() override;

	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }

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

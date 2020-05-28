#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "commentdialog.h"
#include "menus.h"
#include "uicontext.h"

class BINARYNINJAUIAPI TokenizedTextViewHistoryEntry: public HistoryEntry
{
	size_t m_topLine, m_cursorLine;
	HighlightTokenState m_highlight;

public:
	size_t getTopLine() const { return m_topLine; }
	size_t getCursorLine() const { return m_cursorLine; }
	const HighlightTokenState& getHighlightTokenState() const { return m_highlight; }

	void setTopLine(size_t line) { m_topLine = line; }
	void setCursorLine(size_t line) { m_cursorLine = line; }
	void setHighlightTokenState(const HighlightTokenState& state) { m_highlight = state; }
};

class BINARYNINJAUIAPI TokenizedTextView: public QAbstractScrollArea, public View, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	BinaryViewRef m_data;
	FunctionRef m_function;

	RenderContext m_render;
	int m_cols, m_rows;
	int m_wheelDelta;
	bool m_updatingScrollBar;

	bool m_updatesRequired;

	int m_cursorLine;
	HighlightTokenState m_highlight;
	uint64_t m_navByRefTarget;
	bool m_navByRef = false;

	std::vector<BinaryNinja::LinearDisassemblyLine> m_lines;
	DisassemblySettingsRef m_settings;

	QTimer* m_updateTimer;

	ContextMenuManager m_contextMenuManager;
	QPointer<CommentDialog> m_commentDialog;

	void adjustSize(int width, int height);

	void scrollLines(int count);

	void bindActions();
	void getHexDumpLineBytes(const BinaryNinja::LinearDisassemblyLine& line, size_t& skippedBytes, size_t& totalBytes,
		size_t& totalCols);

	void setSectionSemantics(const std::string& name, BNSectionSemantics semantics);

	void viewInHexEditor();
	void viewInGraph();
	void viewInTypesView(std::string typeName = "");
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
	void inferStructureType();
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

private Q_SLOTS:
	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void updateTimerEvent();

public:
	explicit TokenizedTextView(QWidget* parent, BinaryViewRef data,
		const std::vector<BinaryNinja::LinearDisassemblyLine>& lines = std::vector<BinaryNinja::LinearDisassemblyLine>());
	virtual ~TokenizedTextView();

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual BNAddressRange getSelectionForInfo() override;
	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;
	virtual bool navigate(uint64_t pos) override;

	virtual HistoryEntry* getHistoryEntry() override;
	void populateDefaultHistoryEntry(TokenizedTextViewHistoryEntry* entry);
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

	virtual void followPointer();

	virtual void cut() override;
	virtual void copy(TransformRef xform = nullptr) override;
	virtual void paste(TransformRef xform = nullptr) override;
	virtual void copyAddress() override;

	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }

	virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;
	QFont getFont() override { return m_render.getFont(); }

	static void registerActions();

	virtual void updateLines();
	void setLines(const std::vector<BinaryNinja::LinearDisassemblyLine>& lines);
	void setUpdatedLines(const std::vector<BinaryNinja::LinearDisassemblyLine>& lines);

	void setFunction(FunctionRef func);

protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;
};

#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QAction>
#include <QtCore/QTimer>
#include <string>
#include <utility>
#include <vector>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "menus.h"

#define TYPE_VIEW_UPDATE_CHECK_INTERVAL 200

class BINARYNINJAUIAPI TypeViewHistoryEntry: public HistoryEntry
{
	BinaryNinja::QualifiedName m_cursorType;
	size_t m_cursorLine;
	size_t m_cursorOffset;
	bool m_selectionValid;
	std::string m_selectionStartType;
	size_t m_selectionStartLine;
	size_t m_selectionStartOffset;
	HighlightTokenState m_highlight;

public:
	const BinaryNinja::QualifiedName& getCursorType() const { return m_cursorType; }
	size_t getCursorLine() const { return m_cursorLine; }
	size_t getCursorOffset() const { return m_cursorOffset; }

	bool isSelectionValid() const { return m_selectionValid; }
	const std::string& getSelectionStartType() const { return m_selectionStartType; }
	size_t getSelectionStartLine() const { return m_selectionStartLine; }
	size_t getSelectionStartOffset() const { return m_selectionStartOffset; }

	const HighlightTokenState& getHighlightTokenState() const { return m_highlight; }

	void setCursorType(const BinaryNinja::QualifiedName& type) { m_cursorType = type; }
	void setCursorLine(size_t line) { m_cursorLine = line; }
	void setCursorOffset(size_t offset) { m_cursorOffset = offset; }

	void setSelectionValid(bool valid) { m_selectionValid = valid; }
	void setSelectionStartType(const std::string& type) { m_selectionStartType = type; }
	void setSelectionStartLine(size_t line) { m_selectionStartLine = line; }
	void setSelectionStartOffset(size_t offset) { m_selectionStartOffset = offset; }

	void setHighlightTokenState(const HighlightTokenState& state) { m_highlight = state; }
};

class BINARYNINJAUIAPI TypeView: public QAbstractScrollArea, public View, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	enum TypeDefinitionLineType
	{
		TypedefLineType,
		StructDefinitionLineType,
		StructFieldLineType,
		StructDefinitionEndLineType,
		EnumDefinitionLineType,
		EnumMemberLineType,
		EnumDefinitionEndLineType,
		PaddingLineType
	};

	struct TypeDefinitionLine
	{
		TypeDefinitionLineType lineType;
		std::vector<BinaryNinja::InstructionTextToken> tokens;
		TypeRef type, rootType;
		uint64_t offset;
		size_t fieldIndex;
	};

	struct TypeLineIndex
	{
		BinaryNinja::QualifiedName name;
		int line, end;
	};

	BinaryViewRef m_data;
	ViewFrame* m_view;

	RenderContext m_render;
	QWidget* m_lineNumberArea;
	int m_lineNumberAreaWidth = 0;
	int m_lineCount = 0;
	int m_cols, m_rows, m_paddingCols;
	uint64_t m_maxOffset;
	size_t m_offsetWidth;
	HighlightTokenState m_highlight;
	BinaryNinja::QualifiedName m_cursorType;
	size_t m_cursorTypeIndex;
	size_t m_cursorLine;
	size_t m_cursorOffset;
	std::string m_navigationMode = "TypeNavigation";

	bool m_selectionValid;
	size_t m_selectionStartTypeIndex;
	size_t m_selectionStartLine;
	size_t m_selectionStartOffset;

	std::map<BinaryNinja::QualifiedName, std::vector<TypeDefinitionLine>> m_typeLines;
	std::vector<TypeLineIndex> m_types;

	bool m_updatesRequired;
	QTimer* m_updateTimer;

	Qt::KeyboardModifiers m_ctrl, m_command;

	ContextMenuManager m_contextMenuManager;
	QAction* m_actionCopy;
	QAction* m_actionSelectAll;

	void adjustSize(int width, int height);

	std::vector<TypeDefinitionLine> getLinesForType(const std::string& name, const std::string& varName, size_t index,
		TypeRef type, TypeRef parent);
	void refreshAllTypes();
	void ensureCursorVisible();
	void focusOnCursor();

	void changeToSpecificType(TypeRef type);
	bool canCreateMembersInSelectedRegion();
	void createMembersInSelectedRegion(TypeRef type);
	void deleteMembersInSelectedRegion();

	void moveUp(bool selecting);
	void moveDown(bool selecting);
	void moveLeft(size_t count, bool selecting);
	void moveRight(size_t count, bool selecting);
	void pageUp(bool selecting);
	void pageDown(bool selecting);
	void setCursorAbsoluteLine(size_t line);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView(bool selecting);
	void moveToEndOfView(bool selecting);
	void goToAddress(bool selecting);

	void moveCursorToMouse(QMouseEvent* event, bool selecting);
	void createNewTypes(const QString& definition = "");
	void bindActions();

	void checkForValidSelection();

public:
	explicit TypeView(BinaryViewRef data, ViewFrame* view);
	virtual ~TypeView();

	virtual bool findNextData(uint64_t start, uint64_t end, const BinaryNinja::DataBuffer& data, uint64_t& addr, BNFindFlag flags,
		const std::function<bool (size_t current, size_t total)>& cb) override;
	virtual bool findNextText(uint64_t start, uint64_t end, const std::string& text, uint64_t& addr,
		DisassemblySettingsRef settings, BNFindFlag flags,
		const std::function<bool (size_t current, size_t total)>& cb) override;
	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual bool navigate(uint64_t) override;

	virtual std::string getNavigationMode() override;
	virtual void setNavigationMode(std::string mode) override;
	virtual std::vector<std::string> getNavigationModes() override;

	bool navigateToType(const std::string& name);

	virtual void OnTypeDefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name,
		BinaryNinja::Type* type) override;
	virtual void OnTypeUndefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name,
		BinaryNinja::Type* type) override;

	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	virtual HistoryEntry* getHistoryEntry() override;
	virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

	void lineNumberAreaPaintEvent(QPaintEvent *event);
	int lineNumberAreaWidth();

	virtual bool canCut() override { return false; }
	virtual bool canCopy() override;
	virtual bool canCopyWithTransform() override { return false; }
	virtual bool canPaste() override { return false; }
	virtual bool canPasteWithTransform() override { return false; }
	virtual bool canTransform() override { return false; }
	virtual bool canCopyAddress() override { return false; }

	virtual void copy(TransformRef xform = nullptr) override;
	virtual QFont getFont() override { return m_render.getFont(); }

	virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }

	static void registerActions();

protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;
	virtual void scrollContentsBy(int dx, int dy) override;

private Q_SLOTS:
	void copySelection();
	void selectAll();
	void updateTimerEvent();
	void defineName();
	void undefine();
	void changeType();
	void makeInt8();
	void makeInt16();
	void makeInt32();
	void makeInt64();
	void makePtr();
	void makeString();
	void makeArray();
	void newTypes();
	void createStructure();
	void createUnion();
	void setStructureSize();
	void updateLineNumberAreaWidth(size_t lineCount);
};


class BINARYNINJAUIAPI LineNumberArea : public QWidget
{
public:
	LineNumberArea(TypeView *editor) : QWidget(editor), m_typeEditor(editor) { }

	QSize sizeHint() const override { return QSize(m_typeEditor->lineNumberAreaWidth(), 0); }

protected:
	void paintEvent(QPaintEvent *event) override { m_typeEditor->lineNumberAreaPaintEvent(event); }

private:
	TypeView* m_typeEditor;
};

class TypeViewType: public ViewType
{
	static TypeViewType* m_instance;

public:
	TypeViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	static void init();
};

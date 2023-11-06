#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QTimer>
#include <optional>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "commentdialog.h"
#include "menus.h"
#include "uicontext.h"

/*!

	\defgroup tokenizedtextwidget TokenizedTextWidget
 	\ingroup uiapi
*/


/*!

    \ingroup tokenizedtextwidget
*/
enum BINARYNINJAUIAPI TokenizedTextWidgetSelectionStyle
{
	NoSelection      = 1 << 0,
	SelectLines      = 1 << 1,
	SelectOneToken   = 1 << 2,
	SelectTokens     = 1 << 3,
	SelectCharacters = 1 << 4,

	AllStyles = NoSelection | SelectLines | SelectOneToken | SelectTokens | SelectCharacters,
};


/*!

    \ingroup tokenizedtextwidget
*/
struct BINARYNINJAUIAPI TokenizedTextWidgetCursorPosition
{
	/// Index of line in widget
	size_t lineIndex = BN_INVALID_OPERAND;
	/// Index of token in current line
	size_t tokenIndex = BN_INVALID_OPERAND;
	/// Index of character in current token
	size_t characterIndex = BN_INVALID_OPERAND;

	// Directly from QMouseEvent, not used in comparator
	int cursorX;
	int cursorY;

	bool isValid() const { return lineIndex != BN_INVALID_OPERAND; }
	bool operator==(const TokenizedTextWidgetCursorPosition& other) const;
	bool operator!=(const TokenizedTextWidgetCursorPosition& other) const { return !(*this == other); }
	bool operator<(const TokenizedTextWidgetCursorPosition& other) const;
};

/*!
    QWidget that displays lines of InstructionTextTokens with the ability to make selections

    \ingroup tokenizedtextwidget
*/
class BINARYNINJAUIAPI TokenizedTextWidget :
    public QAbstractScrollArea
{
protected:
	struct LineMetadata
	{
		size_t charWidth;
		int copyStyles;

		LineMetadata():
			charWidth(0),
			copyStyles(TokenizedTextWidgetSelectionStyle::AllStyles)
		{}
	};
	struct TokenMetadata
	{
		size_t charOffset;
		int copyStyles;
		bool selectLineTarget;

		TokenMetadata():
			charOffset(0),
			copyStyles(TokenizedTextWidgetSelectionStyle::AllStyles),
			selectLineTarget(false)
		{}
	};

private:
	Q_OBJECT

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu m_contextMenu;

	RenderContext m_render;
	int m_cols, m_rows;
	int m_contentsCols, m_contentsRows;
	int m_verticalWheelDelta, m_horizontalWheelDelta;
	bool m_updatingScrollBar;
	bool m_autoScrollHorizontal, m_autoScrollVertical;

	TokenizedTextWidgetCursorPosition m_cursorPos, m_selectionStartPos, m_hoverPos;
	TokenizedTextWidgetSelectionStyle m_selectionMode;
	size_t m_hoverLine;
	bool m_selectionStartedPastWidth;
	bool m_selectionStartedPastHeight;
	bool m_cursorKeys;
	bool m_forceLineSelect;

	std::vector<BinaryNinja::LinearDisassemblyLine> m_lines;
	std::vector<LineMetadata> m_lineMetadata;
	std::vector<std::vector<TokenMetadata>> m_tokenMetadata;
	DisassemblySettingsRef m_settings;

	void adjustSize(int width, int height);
	void clampCursorPosition(TokenizedTextWidgetCursorPosition& pos);
	void clampSelectionToValid();

  protected:
	virtual void updateMetadata(const std::vector<BinaryNinja::LinearDisassemblyLine>& lines, int& width, int& height);

  private Q_SLOTS:
	void verticalScrollBarMoved(int value);
	void verticalScrollBarAction(int action);
	void horizontalScrollBarMoved(int value);
	void horizontalScrollBarAction(int action);

  public:
	explicit TokenizedTextWidget(QWidget* parent,
	    const std::vector<BinaryNinja::LinearDisassemblyLine>& lines =
	        std::vector<BinaryNinja::LinearDisassemblyLine>());
	virtual ~TokenizedTextWidget();

	void bindActions();

	QFont font() const;
	void setFont(const QFont& font);

	DisassemblySettingsRef settings() { return m_settings; }
	const DisassemblySettingsRef& settings() const { return m_settings; }

	int topLineIndex() const;
	int leftmostCharIndex() const;
	int visibleColumnCount() const { return m_cols; }
	int visibleRowCount() const { return m_rows; }
	int contentsColumnCount() const { return m_contentsCols; }
	int contentsRowCount() const { return m_contentsRows; }

	bool hasSelection() const;
	// Lines vs Tokens vs Characters vs NoSelection
	TokenizedTextWidgetSelectionStyle selectionStyle() const;
	// Lower bound of selection
	TokenizedTextWidgetCursorPosition selectionBegin() const;
	// Upper bound of selection
	TokenizedTextWidgetCursorPosition selectionEnd() const;
	// Originally highlighted selection base
	TokenizedTextWidgetCursorPosition selectionBase() const;
	// Position of cursor for movement operations
	TokenizedTextWidgetCursorPosition cursorPosition() const;
	bool forceLineSelect() const { return m_forceLineSelect; }
	void setForceLineSelect(bool value) { m_forceLineSelect = value; }

	void setSelection(TokenizedTextWidgetCursorPosition base, TokenizedTextWidgetCursorPosition cursor, TokenizedTextWidgetSelectionStyle mode);
	void setCursorPosition(TokenizedTextWidgetCursorPosition newPosition, bool selecting, bool cursorKeys, bool evenIfNoChange);
	void moveCursorHorizontal(int count, bool allTheWay, bool selecting, bool cursorKeys);
	void moveCursorVertical(int count, bool allTheWay, bool selecting, bool cursorKeys);

	bool autoScrollHorizontal() const { return m_autoScrollHorizontal; }
	void setAutoScrollHorizontal(bool value) { m_autoScrollHorizontal = value; }
	bool autoScrollVertical() const { return m_autoScrollVertical; }
	void setAutoScrollVertical(bool value) { m_autoScrollVertical = value; }

	HighlightTokenState highlightTokenState();
	UIActionHandler* actionHandler() { return &m_actionHandler; }

	virtual UIActionContext actionContext();
	Menu& contextMenu() { return m_contextMenu; }
	void showContextMenu();

	void left(size_t count, bool selecting);
	void right(size_t count, bool selecting);
	void leftToWord(bool selecting);
	void rightToWord(bool selecting);
	void up(bool selecting);
	void down(bool selecting);
	void pageUp(bool selecting);
	void pageDown(bool selecting);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView(bool selecting);
	void moveToEndOfView(bool selecting);
	void selectAll();
	void selectNone();

	void scrollLines(int count);
	void scrollLineToVisible(int lineIndex);
	void scrollLineToTop(int lineIndex);

	void scrollChars(int count);
	void scrollCharToVisible(int charIndex);
	void scrollCharToLeftmost(int charIndex);

	void copy() const;
	std::string selectedText() const;

	const std::vector<BinaryNinja::LinearDisassemblyLine>& lines() const { return m_lines; }
	std::optional<std::reference_wrapper<const BinaryNinja::LinearDisassemblyLine>> lineAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<std::reference_wrapper<const BinaryNinja::InstructionTextToken>> tokenAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<char> charAtPosition(const TokenizedTextWidgetCursorPosition& position) const;

	void clearLines();
	void setLines(const std::vector<BinaryNinja::LinearDisassemblyLine>& lines, bool resetScroll = true);
	void setLines(const std::vector<BinaryNinja::DisassemblyTextLine>& lines, bool resetScroll = true);
	void setLines(const std::vector<BinaryNinja::TypeDefinitionLine>& lines, bool resetScroll = true);

	int lineCopyStyles(size_t lineIndex) const;
	void setLineCopyStyles(size_t lineIndex, int styles);

	int tokenCopyStyles(size_t lineIndex, size_t tokenIndex) const;
	void setTokenCopyStyles(size_t lineIndex, size_t tokenIndex, int styles);
	bool tokenSelectLineTarget(size_t lineIndex, size_t tokenIndex) const;
	void setTokenSelectLineTarget(size_t lineIndex, size_t tokenIndex, bool selectLineTarget);

  Q_SIGNALS:
	void sizeChanged(int cols, int rows);
	void visibleChanged(int leftCol, int topRow);
	void linesChanged();
	void selectionChanged(const TokenizedTextWidgetCursorPosition& begin, const TokenizedTextWidgetCursorPosition& end);
	void tokenLeftClicked(const TokenizedTextWidgetCursorPosition& position);
	void tokenRightClicked(const TokenizedTextWidgetCursorPosition& position);
	void tokenDoubleClicked(const TokenizedTextWidgetCursorPosition& position);
	void tokenOtherClicked(const TokenizedTextWidgetCursorPosition& position, Qt::MouseButton button);
	void tokenHovered(const TokenizedTextWidgetCursorPosition& position);
	void lineLeftClicked(size_t lineIndex);
	void lineRightClicked(size_t lineIndex);
	void lineDoubleClicked(size_t lineIndex);
	void lineOtherClicked(size_t lineIndex, Qt::MouseButton button);
	void lineHovered(size_t lineIndex);

  protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;
	virtual void focusInEvent(QFocusEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
};

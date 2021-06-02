#pragma once

#include <QtGui/QPainter>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "action.h"

enum HexEditorHighlightMode
{
	NoHighlight,
	ColumnHighlight,
	ByteValueHighlight
};

enum HexEditorColorMode
{
	NoColorization,
	AsciiColorization,
	ModificationColorization
};

enum HexEditorHighlightContrast
{
	NormalContrastHighlight,
	MediumContrastHighlight,
	HighContrastHighlight
};

struct BINARYNINJAUIAPI HexEditorHighlightState
{
	HexEditorHighlightMode mode;
	HexEditorColorMode color;
	HexEditorHighlightContrast contrast;

	void restoreSettings();
	void saveSettings();
};

class BINARYNINJAUIAPI FontParameters
{
	QWidget* m_owner;
	QFont m_font, m_emojiFont;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;
	float m_fontScale;
	bool m_customFont;

public:
	FontParameters(QWidget* parent, float fontScale = 1.0f);
	void update();

	QFont& getFont() { return m_font; }
	QFont& getEmojiFont() { return m_emojiFont; }
	void setFont(const QFont& font);
	void setEmojiFont(const QFont& emojiFont);
	int getBaseline() const { return m_baseline; }
	int getWidth() const { return m_charWidth; }
	int getHeight() const { return m_charHeight; }
	int getOffset() const { return m_charOffset; }
};

class BINARYNINJAUIAPI RenderContext
{
	QWidget* m_owner;
	FontParameters m_fontParams;
	bool m_drawIndents;

public:
	RenderContext(QWidget* parent, float fontScale = 1.0f);
	void update();

	FontParameters& getFontParamters() { return m_fontParams; }
	int getFontWidth() const { return m_fontParams.getWidth(); }
	int getFontHeight() const { return m_fontParams.getHeight(); }

	void init(QPainter& p);

	QColor getColorForHexDumpByte(const HexEditorHighlightState& state, BNModificationStatus modification, uint8_t byte);
	QColor getHighlightColor(BNHighlightColor color);

	HighlightTokenState getTokenForDisassemblyLinePosition(size_t col, const std::vector<BinaryNinja::InstructionTextToken>& tokens);
	HighlightTokenState getTokenForDisassemblyTokenIndex(size_t tokenIndex,
		const std::vector<BinaryNinja::InstructionTextToken>& tokens);
	HighlightTokenState getHighlightTokenForTextToken(const BinaryNinja::InstructionTextToken& token);

	void drawText(QPainter& p, int x, int y, QColor color, const QString& text);
	void drawUnderlinedText(QPainter& p, int x, int y, QColor color, const QString& text);

	void drawSeparatorLine(QPainter& p, QColor top, QColor bottom, QColor line, const QRect& rect);
	void drawInstructionHighlight(QPainter& p, const QRect& rect);

	void drawLinearDisassemblyLineBackground(QPainter& p, BNLinearDisassemblyLineType type, const QRect& rect,
		int gutterWidth);
	void drawDisassemblyLine(QPainter& p, int left, int top, const std::vector<BinaryNinja::InstructionTextToken>& tokens,
		HighlightTokenState& highlight, bool highlightOnly=false);

	void drawHexEditorLine(QPainter& p, int left, int top, const HexEditorHighlightState& highlight,
		BinaryViewRef view, uint64_t lineStartAddr, size_t cols, size_t firstCol, size_t count,
		bool cursorVisible, bool cursorAscii, size_t cursorPos, bool byteCursor);
	QFont getFont() { return m_fontParams.getFont(); }
	void setFont(const QFont& font);
};

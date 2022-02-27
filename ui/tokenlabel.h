#pragma once

#include "render.h"

#include <QtWidgets/QLabel>

//! Label type for rendering InstructionTextToken(s) as text.
class BINARYNINJAUIAPI TokenLabel : public QLabel
{
	Q_OBJECT

	std::map<int, BinaryNinja::InstructionTextToken> m_tokens;

protected:
	//! Get the token corresponding to a given horizontal advance.
	BinaryNinja::InstructionTextToken tokenForAdvance(int) const;

	void mouseMoveEvent(QMouseEvent*) override;

public:
	TokenLabel(QWidget* parent = nullptr);
	TokenLabel(std::vector<BinaryNinja::InstructionTextToken>, QWidget* parent = nullptr);

	//! Set the tokens to be displayed.
	//!
	//! Works similar to `setText()`, but operates on tokens.
	void setTokens(std::vector<BinaryNinja::InstructionTextToken>);
};

//! Label type for rendering InstructionTextToken(s) as text, supporting navigation.
class BINARYNINJAUIAPI NavigableTokenLabel : public TokenLabel
{
	//! Determines if a token should be treated as navigable.
	bool isNavigableTokenType(BNInstructionTextTokenType) const;

protected:
	void mouseMoveEvent(QMouseEvent*) override;
	void mousePressEvent(QMouseEvent*) override;

public:
	NavigableTokenLabel(QWidget* parent = nullptr);
	NavigableTokenLabel(std::vector<BinaryNinja::InstructionTextToken>, QWidget* parent = nullptr);
};

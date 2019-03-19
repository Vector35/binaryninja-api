#pragma once

#include <QtGui/QPalette>
#include <QtWidgets/QProxyStyle>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"

class BINARYNINJAUIAPI CustomFusionStyle: public QProxyStyle
{
public:
	CustomFusionStyle(QStyle* parent);
	virtual int pixelMetric(PixelMetric metric, const QStyleOption* option, const QWidget* widget) const override;
	virtual QIcon standardIcon(StandardPixmap standardIcon, const QStyleOption* option,
		const QWidget* widget) const override;
	virtual QPixmap standardPixmap(StandardPixmap standardPixmap, const QStyleOption* option,
		const QWidget* widget) const override;
};

enum ThemeColor
{
	// Hex dump colors
	AddressColor,
	ModifiedColor,
	InsertedColor,
	NotPresentColor,
	SelectionColor,
	OutlineColor,
	BackgroundHighlightDarkColor,
	BackgroundHighlightLightColor,
	BoldBackgroundHighlightDarkColor,
	BoldBackgroundHighlightLightColor,
	AlphanumericHighlightColor,
	PrintableHighlightColor,

	// Graph colors
	GraphBackgroundDarkColor,
	GraphBackgroundLightColor,
	GraphNodeDarkColor,
	GraphNodeLightColor,
	GraphNodeOutlineColor,
	TrueBranchColor,
	FalseBranchColor,
	UnconditionalBranchColor,
	AltTrueBranchColor,
	AltFalseBranchColor,
	AltUnconditionalBranchColor,

	// Disassembly colors
	RegisterColor,
	NumberColor,
	CodeSymbolColor,
	DataSymbolColor,
	StackVariableColor,
	ImportColor,
	InstructionHighlightColor,
	TokenHighlightColor,
	AnnotationColor,
	OpcodeColor,
	LinearDisassemblyFunctionHeaderColor,
	LinearDisassemblyBlockColor,
	LinearDisassemblyNoteColor,
	LinearDisassemblySeparatorColor,
	StringColor,
	TypeNameColor,
	FieldNameColor,
	KeywordColor,
	UncertainColor,
	NameSpaceColor,
	NameSpaceSeparatorColor,

	// Script console colors
	ScriptConsoleOutputColor,
	ScriptConsoleErrorColor,
	ScriptConsoleEchoColor,

	// Highlighting colors
	BlueStandardHighlightColor,
	GreenStandardHighlightColor,
	CyanStandardHighlightColor,
	RedStandardHighlightColor,
	MagentaStandardHighlightColor,
	YellowStandardHighlightColor,
	OrangeStandardHighlightColor,
	WhiteStandardHighlightColor,
	BlackStandardHighlightColor,

	// MiniGraph
	MiniGraphOverlayColor,

	// FeatureMap
	FeatureMapBaseColor,
	FeatureMapNavLineColor,
	FeatureMapNavHighlightColor,
	FeatureMapDataVariableColor,
	FeatureMapAsciiStringColor,
	FeatureMapUnicodeStringColor,
	FeatureMapFunctionColor,
	FeatureMapImportColor,
	FeatureMapExternColor
};

void BINARYNINJAUIAPI initThemes();
void BINARYNINJAUIAPI resetUserThemes();
void BINARYNINJAUIAPI refreshUserThemes();
std::vector<QString> BINARYNINJAUIAPI getAvailableThemes();
QString BINARYNINJAUIAPI getActiveTheme();
void BINARYNINJAUIAPI setActiveTheme(const QString& name, bool saveToSettings = true);

bool BINARYNINJAUIAPI isColorBlindMode();
void BINARYNINJAUIAPI setColorBlindMode(bool active);

QColor BINARYNINJAUIAPI getThemeColor(ThemeColor color);
QColor BINARYNINJAUIAPI getTokenColor(QWidget* widget, BNInstructionTextTokenType token);

QColor BINARYNINJAUIAPI avgColor(QColor a, QColor b);
QColor BINARYNINJAUIAPI mixColor(QColor a, QColor b, uint8_t mix);

QColor BINARYNINJAUIAPI getThemeHighlightColor(BNHighlightStandardColor color);

#pragma once

#include <QtGui/QFont>
#include <QtWidgets/QWidget>
#include "uicontext.h"

enum AntialiasingStyle
{
	SubpixelAntialiasing,
	GrayscaleAntialiasing,
	SubpixelAntialiasingUnlessHighDPI,
	NoAntialiasing
};

QFont BINARYNINJAUIAPI getDefaultMonospaceFont();
QFont BINARYNINJAUIAPI getMonospaceFont(QWidget* widget);
void BINARYNINJAUIAPI setMonospaceFont(const QFont& font);

int BINARYNINJAUIAPI getDefaultExtraFontSpacing();
int BINARYNINJAUIAPI getExtraFontSpacing();
void BINARYNINJAUIAPI setExtraFontSpacing(int spacing);

int BINARYNINJAUIAPI getFontVerticalOffset();

bool BINARYNINJAUIAPI allowBoldFonts();
void BINARYNINJAUIAPI setAllowBoldFonts(bool allow);

AntialiasingStyle BINARYNINJAUIAPI getAntialiasingStyle();
void BINARYNINJAUIAPI setAntialiasingStyle(AntialiasingStyle style);
void BINARYNINJAUIAPI adjustFontForAntialiasingSettings(QFont& font, QWidget* widget);

int BINARYNINJAUIAPI getFontWidthAndAdjustSpacing(QFont& font);

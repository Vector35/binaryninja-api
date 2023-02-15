#pragma once

#include <QtGui/QFont>
#include <QtWidgets/QWidget>
#include "uicontext.h"

/*!
    @addtogroup FontSettings
    \ingroup uiapi
    @{
*/

enum AntialiasingStyle
{
	SubpixelAntialiasing,
	GrayscaleAntialiasing,
	SubpixelAntialiasingUnlessHighDPI,
	NoAntialiasing
};

int BINARYNINJAUIAPI getDefaultFontSize();

QFont BINARYNINJAUIAPI getDefaultApplicationFont();
QFont BINARYNINJAUIAPI getApplicationFont(QWidget* widget);
void BINARYNINJAUIAPI setApplicationFont(const QFont& font);

QFont BINARYNINJAUIAPI getDefaultMonospaceFont();
QFont BINARYNINJAUIAPI getMonospaceFont(QWidget* widget);
void BINARYNINJAUIAPI setMonospaceFont(const QFont& font);

QFont BINARYNINJAUIAPI getDefaultEmojiFont();
QFont BINARYNINJAUIAPI getEmojiFont(QWidget* widget);
void BINARYNINJAUIAPI setEmojiFont(const QFont& font);

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

/*!
	@}
*/

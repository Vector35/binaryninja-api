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

//! Returns the default application font, ignoring user settings.
QFont BINARYNINJAUIAPI getDefaultApplicationFont();
//! Returns the currently configured application font (or the default, if it doesn't exist).
QFont BINARYNINJAUIAPI getApplicationFont(QWidget* widget);
/*!
 * Sets the currently configured application font.
 *
 * @param font The font to use. Passing nullptr will reset the application font to the user's configured default.
 */
void BINARYNINJAUIAPI setApplicationFont(const QFont* font);

//! Returns the default monospaced font, ignoring user settings.
QFont BINARYNINJAUIAPI getDefaultMonospaceFont();
//! Returns the currently configured monospaced font (or the default, if it doesn't exist).
QFont BINARYNINJAUIAPI getMonospaceFont(QWidget* widget);
/*!
 * Sets the currently configured monospaced font.
 *
 * @param font The font to use. Passing nullptr will reset the monospaced font to the user's configured default.
 */
void BINARYNINJAUIAPI setMonospaceFont(const QFont* font);

//! Returns the default emoji font, ignoring user settings.
QFont BINARYNINJAUIAPI getDefaultEmojiFont();
//! Returns the currently configured emoji font (or the default, if it doesn't exist).
QFont BINARYNINJAUIAPI getEmojiFont(QWidget* widget);
/*!
 * Sets the currently configured emoji font.
 *
 * @param font The font to use. Passing nullptr will reset the emoji font to the user's configured default.
 */
void BINARYNINJAUIAPI setEmojiFont(const QFont* font);

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

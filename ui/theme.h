#pragma once

#include <QtGui/QPalette>
#include <QtWidgets/QProxyStyle>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!
    @addtogroup Theme
    \ingroup uiapi
    @{
*/

class BINARYNINJAUIAPI CustomFusionStyle : public QProxyStyle
{
  public:
	CustomFusionStyle(QStyle* parent);
	virtual int pixelMetric(PixelMetric metric, const QStyleOption* option, const QWidget* widget) const override;
	virtual QIcon standardIcon(
	    StandardPixmap standardIcon, const QStyleOption* option, const QWidget* widget) const override;
	virtual QPixmap standardPixmap(
	    StandardPixmap standardPixmap, const QStyleOption* option, const QWidget* widget) const override;
	virtual QRect subElementRect(
	    QStyle::SubElement element, const QStyleOption *option, const QWidget *widget) const override;
	virtual void drawPrimitive(
	    PrimitiveElement elem, const QStyleOption *option, QPainter *painter, const QWidget *widget) const override;
	virtual int styleHint(
	    QStyle::StyleHint hint, const QStyleOption *option, const QWidget *widget, QStyleHintReturn *returnData) const override;
};


void BINARYNINJAUIAPI initThemes();
void BINARYNINJAUIAPI resetUserThemes();
void BINARYNINJAUIAPI refreshUserThemes();
std::vector<QString> BINARYNINJAUIAPI getAvailableThemes();
QString BINARYNINJAUIAPI getActiveTheme();
void BINARYNINJAUIAPI setActiveTheme(const QString& name, bool saveToSettings = true);

bool BINARYNINJAUIAPI isActiveThemeDark();

bool BINARYNINJAUIAPI isColorBlindMode();
void BINARYNINJAUIAPI setColorBlindMode(bool active);
void BINARYNINJAUIAPI pixmapForBWMaskIcon(const QString& url, QPixmap* pixmapOut, BNThemeColor color = SidebarActiveIconColor, const QString& cacheSuffix = "");

/*! This function allows registering themes from a plugin.

	The functionality and behavior of this is not guaranteed nor ardently supported. If you want to register and
		override the current theme, you will need to swap to it manually with \c setActiveTheme, and the user will be able
		to swap away from your overridden theme via Settings.

	This primarily makes sense for:
	- Themes generated at runtime
	- Themes with some special program functionality (i.e. an editor plugin)
	- A way to ship one/multiple themes that can be updated more easily.

 	That is, applications where the user \e intends to modify their theme with your plugin.

	It is not a solid way to apply changes to product UI from a plugin without user input.

	You should make special note that when using <tt>setActiveTheme(const QString& name, bool saveToSettings)</tt>
	in conjunction with a plugin-added theme, you should pass \c false for \c saveToSettings , to ensure
	the user's settings are not overriden.

	\param json
*/
void BINARYNINJAUIAPI addJsonTheme(const char* json);

QColor BINARYNINJAUIAPI getThemeColor(BNThemeColor color);
QColor BINARYNINJAUIAPI getTokenColor(QWidget* widget, BNInstructionTextTokenType token);

QColor BINARYNINJAUIAPI avgColor(QColor a, QColor b);
QColor BINARYNINJAUIAPI mixColor(QColor a, QColor b, uint8_t mix);

QColor BINARYNINJAUIAPI getThemeHighlightColor(BNHighlightStandardColor color);

/*!
	@}
*/

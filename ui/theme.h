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
		QStyle::StyleHint hint, const QStyleOption *option, const QWidget *widget, QStyleHintReturn *returnData) const;
	virtual void drawComplexControl(ComplexControl control, const QStyleOptionComplex *option, QPainter *painter,
		const QWidget *widget) const override;
	virtual QSize sizeFromContents(
		ContentsType ct, const QStyleOption* opt, const QSize & csz, const QWidget* widget) const override;
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

/*! \warning If registering themes from a plugin, you will also need to manually swap to them

	\param json
*/
void BINARYNINJAUIAPI addJsonTheme(const char* json);

QColor BINARYNINJAUIAPI getThemeColor(BNThemeColor color);
QColor BINARYNINJAUIAPI getTokenColor(QWidget* widget, BNInstructionTextTokenType token);
QColor BINARYNINJAUIAPI getTypeClassColor(const QWidget* widget, BNTypeClass typeClass);
std::optional<QColor> BINARYNINJAUIAPI getSymbolColor(SymbolRef symbol);
std::optional<QColor> BINARYNINJAUIAPI getSymbolColor(BNSymbolType type, BNSymbolBinding binding);

QColor BINARYNINJAUIAPI avgColor(QColor a, QColor b);
QColor BINARYNINJAUIAPI mixColor(QColor a, QColor b, uint8_t mix);

QColor BINARYNINJAUIAPI getThemeHighlightColor(BNHighlightStandardColor color);

/*!
	@}
*/

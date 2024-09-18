#pragma once

#include <QtGui/QPalette>
#include <QtWidgets/QProxyStyle>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include <QPushButton>
#include <QToolButton>

/*!
    @addtogroup Theme
    \ingroup uiapi
    @{
*/

class BINARYNINJAUIAPI CustomStyleFlatPushButton : public QPushButton
{
	Q_OBJECT
public:
	CustomStyleFlatPushButton(QWidget* parent = nullptr) : QPushButton(parent) {}
};


class BINARYNINJAUIAPI CustomStyleFlatToolButton : public QToolButton
{
Q_OBJECT
public:
	CustomStyleFlatToolButton(QWidget* parent = nullptr) : QToolButton(parent) {}
};


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
	    PrimitiveElement element, const QStyleOption *option, QPainter *painter, const QWidget *widget) const override;
	virtual int styleHint(QStyle::StyleHint hint, const QStyleOption *option = nullptr, const QWidget *widget = nullptr,
		QStyleHintReturn *returnData = nullptr) const override;
};

void BINARYNINJAUIAPI pixmapForBWMaskIcon(const QString& url, QPixmap* pixmapOut, BNThemeColor color = SidebarActiveIconColor, const QString& cacheSuffix = "");

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

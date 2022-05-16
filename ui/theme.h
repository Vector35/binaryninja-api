#pragma once

#include <QtGui/QPalette>
#include <QtWidgets/QProxyStyle>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"

class BINARYNINJAUIAPI CustomFusionStyle : public QProxyStyle
{
  public:
	CustomFusionStyle(QStyle* parent);
	virtual int pixelMetric(PixelMetric metric, const QStyleOption* option, const QWidget* widget) const override;
	virtual QIcon standardIcon(
	    StandardPixmap standardIcon, const QStyleOption* option, const QWidget* widget) const override;
	virtual QPixmap standardPixmap(
	    StandardPixmap standardPixmap, const QStyleOption* option, const QWidget* widget) const override;
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

QColor BINARYNINJAUIAPI getThemeColor(BNThemeColor color);
QColor BINARYNINJAUIAPI getTokenColor(QWidget* widget, BNInstructionTextTokenType token);

QColor BINARYNINJAUIAPI avgColor(QColor a, QColor b);
QColor BINARYNINJAUIAPI mixColor(QColor a, QColor b, uint8_t mix);

QColor BINARYNINJAUIAPI getThemeHighlightColor(BNHighlightStandardColor color);

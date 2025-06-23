#pragma once

#include <QtCore/QString>
#include <QtCore/QStringList>

#include "binaryninjaapi.h"
#include "uitypes.h"

class View;


struct BINARYNINJAUIAPI QuickSettingsInfo
{
	QString settingKey;
	QString displayName;
	bool workflowDependent;
};


class BINARYNINJAUIAPI QuickSettings
{
  public:
	static void bindDynamicActions(View* view, const std::function<bool()>& isValid);
	static void addQuickSetting(const QString& settingKey, const QString& displayName, const QString& group = "", bool workflowDependent = false);
	static void removeQuickSetting(const QString& settingKey, const QString& group = "");
	static bool isQuickSetting(const QString& settingKey, const QString& group = "");
	static QStringList getQuickSettingGroups();
	static QList<QuickSettingsInfo> getQuickSettings(const QString& group = "");
	static QString getDisplayName(const QString& settingKey, const QString& group = "");
	static void resetAllQuickSettings();
	static void printAll();
};

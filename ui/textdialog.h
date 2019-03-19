#pragma once

#include <QtWidgets/QDialog>
#include "binaryninjaapi.h"
#include "uitypes.h"

class BINARYNINJAUIAPI TextDialog: public QDialog
{
	Q_OBJECT
	QWidget* m_parent;
	QString m_title;
	QString m_msg;
	QStringList m_options;
	Qt::WindowFlags m_flags;
	QString m_qSettingsListName;
	int m_historySize;
	QString m_historyEntry;
	QString m_initialText;

public:
	TextDialog(QWidget* parent, const QString& title, const QString& msg, const QString& qSettingsListName,
		const std::string& initialText = "");
	TextDialog(QWidget* parent, const QString& title, const QString& msg, const QString& qSettingsListName,
		const QString& initialText);
	QString getItem(bool& ok);
	void setInitialText(const std::string& initialText) { m_initialText = QString::fromStdString(initialText); }
	void commitHistory();
};
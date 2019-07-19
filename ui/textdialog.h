#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLabel>

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "binaryninjaapi.h"

class BINARYNINJAUIAPI TextDialog: public QDialog
{
	Q_OBJECT
	QString m_qSettingsListName;
	int m_historySize;
	QString m_historyEntry;
	QString m_initialText;
	QStringList m_historyEntries;
	QLabel* m_messageText;
	QComboBox* m_combo;

public:
	TextDialog(QWidget* parent, const QString& title, const QString& msg, const QString& qSettingsListName,
		const std::string& initialText = "");
	TextDialog(QWidget* parent, const QString& title, const QString& msg, const QString& qSettingsListName,
		const QString& initialText);
	QString getItem();
	void setInitialText(const std::string& initialText) { m_initialText = QString::fromStdString(initialText); }
	void commitHistory();
};
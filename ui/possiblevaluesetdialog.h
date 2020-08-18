#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include <QToolTip>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "clickablelabel.h"

class BINARYNINJAUIAPI PossibleValueSetDialog: public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QLineEdit* m_value;
	QStringListModel* m_model;
	QLabel* m_prompt;
	QString m_promptText;
	ClickableLabel* m_valueLabel;
	BinaryViewRef m_view;
	bool m_resultValid;
	QStringList m_historyEntries;
	int m_historySize;
	QFont m_defaultFont;
	bool m_initialTextSelection;
	BinaryNinja::PossibleValueSet m_valueSet;
	QPushButton* m_acceptButton;
	QPalette m_defaultPalette;
	QString m_parseError;
	uint64_t m_here;
	QTimer* m_updateTimer;

private Q_SLOTS:
	void accepted();
	void checkParse();
	void updateTimerEvent();
	void showHelp();
	void stateChanged(const QString&);

public:
	PossibleValueSetDialog(QWidget* parent, BinaryViewRef view, uint64_t here);
	BinaryNinja::PossibleValueSet getPossibleValueSet() const { return m_valueSet; }
	static BNRegisterValueType getRegisterValueTypeFromString(const std::string& stateStr);
};

static const QStringList valueSets = {
	"ConstantValue",
	"ConstantPointerValue",
	"StackFrameOffset",
	"SignedRangeValue",
	"UnsignedRangeValue",
	"InSetOfValues",
	"NotInSetOfValues",
	"UndeterminedValue",
};

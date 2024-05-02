#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>

#include "uitypes.h"


/*!

    \ingroup uiapi
*/
class BINARYNINJAUIAPI PossibleValueSetDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_view;
	uint64_t m_addr;

	QComboBox* m_combo;
	QLineEdit* m_input;
	QPushButton* m_acceptButton;
	QLabel* m_formatLabel;
	QLabel* m_errorLabel;

	BNRegisterValueType m_curRegValueType;

	BinaryNinja::PossibleValueSet m_valueSet;

  public:
	PossibleValueSetDialog(
	    QWidget* parent, BinaryViewRef view, uint64_t addr, BinaryNinja::PossibleValueSet existingValue);

	BinaryNinja::PossibleValueSet getPossibleValueSet() const { return m_valueSet; }
	void validate(const QString& input);
};

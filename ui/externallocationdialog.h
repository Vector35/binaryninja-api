#pragma once

#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include "uitypes.h"


class BINARYNINJAUIAPI ExternalLocationDialog : public QDialog
{
	QPushButton* m_acceptButton;
	QPushButton* m_cancelButton;

	QLineEdit* m_internalSymbolField;
	QComboBox* m_libraryField;
	QLineEdit* m_externalSymbolField;
	QLineEdit* m_addressField;

	BinaryViewRef m_data;
	ExternalLocationRef m_location;

	void Submit();

	void updateForm();

public:
	ExternalLocationDialog(QWidget* parent, BinaryViewRef data, ExternalLocationRef loc = nullptr, ExternalLibraryRef lib = nullptr, std::optional<std::string> rawSym = {});
};

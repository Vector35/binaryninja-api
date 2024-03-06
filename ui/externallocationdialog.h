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

	QLineEdit* m_sourceSymbolField;
	QComboBox* m_libraryField;
	QLineEdit* m_targetSymbolField;
	QLineEdit* m_targetAddressField;

	BinaryViewRef m_data;
	std::vector<ExternalLocationRef> m_locations;

	void Submit();

	void updateForm();

public:
	ExternalLocationDialog(QWidget* parent, BinaryViewRef data, const std::vector<ExternalLocationRef>& locs = {}, ExternalLibraryRef lib = nullptr, std::optional<std::string> rawSym = {});
};

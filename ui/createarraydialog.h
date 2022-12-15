#include "uitypes.h"

#include <QtWidgets/QDialog>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>

class CreateArrayDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_data;

	uint64_t m_startAddress;
	TypeRef m_elementType;
	uint64_t m_elementCount;

	QLineEdit* m_startField;
	QComboBox* m_countTypeDropdown;
	QComboBox* m_typeDropdown;
	QSpinBox* m_countField;

	QPushButton* m_acceptButton;

	void validate();

public:
	CreateArrayDialog(BinaryViewRef data, QWidget* parent = nullptr);

	/// Set the initial start address, element type, and element count for
	/// the dialog. The element type may be null if no default is desired; a
	/// default will be chosen by the dialog.
	void setInitialState(uint64_t start, TypeRef elementType, uint64_t count);

	/// Get the desired start address from the accepted dialog.
	uint64_t startAddress() const;

	/// Get the desired array element type from the accepted dialog.
	///
	/// The returned value will NOT be of `Type::ArrayType(...)`, but rather
	/// the element inside.
	TypeRef elementType() const;

	/// Get the desired element count from the accepted dialog.
	uint64_t elementCount() const;

	void accept() override;
	void reject() override;
};

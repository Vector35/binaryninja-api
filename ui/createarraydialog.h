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
	size_t m_size;
	TypeRef m_elementType;
	uint64_t m_elementCount{};

	QLineEdit* m_startField;
	QComboBox* m_typeDropdown;
	QLineEdit* m_countField;

	QPushButton* m_cancelButton;
	QPushButton* m_createButton;

	void update();
	size_t guessElementCount(size_t elementWidth);

public:
	explicit CreateArrayDialog(BinaryViewRef data, BNAddressRange selection, QWidget* parent = nullptr);

	/// Set the initial start address, element type, and element count for
	/// the dialog. The element type may be null if no default is desired; a
	/// default will be chosen by the dialog.
	void setInitialState();

	/// Get the desired start address from the accepted dialog.
	[[nodiscard]] uint64_t startAddress() const;

	/// Get the desired array element type from the accepted dialog.
	///
	/// The returned value will NOT be of `Type::ArrayType(...)`, but rather
	/// the element inside.
	[[nodiscard]] TypeRef elementType() const;

	/// Get the desired element count from the accepted dialog.
	[[nodiscard]] uint64_t elementCount() const;

	void accept() override;
	void reject() override;
};

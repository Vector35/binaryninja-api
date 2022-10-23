#pragma once

#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!

    \ingroup uiapi
*/
class BINARYNINJAUIAPI InstructionEdit : public QLineEdit
{
	Q_OBJECT

	BinaryViewRef m_data;
	ArchitectureRef m_arch;
	FunctionRef m_func;
	uint64_t m_offset;
	bool m_preventDismiss;

  public:
	InstructionEdit(QWidget* parent, BinaryViewRef data, ArchitectureRef arch, FunctionRef func, uint64_t offset);

	void acceptInstruction();
	void rejectInstruction();

  protected:
	virtual void keyPressEvent(QKeyEvent* event);
	virtual void focusOutEvent(QFocusEvent* event);

  Q_SIGNALS:
	void done();
};

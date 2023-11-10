#pragma once

#include <QtWidgets/QLineEdit>
#include "uitypes.h"

class BINARYNINJAUIAPI PasswordEdit: public QLineEdit
{
public:
	PasswordEdit(QWidget* parent = nullptr);

	virtual void focusInEvent(QFocusEvent* e) override;
	virtual void focusOutEvent(QFocusEvent* e) override;
};

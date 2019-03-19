#pragma once

#include <QtWidgets/QTextEdit>
#include "uicontext.h"

class BINARYNINJAUIAPI DialogTextEdit: public QTextEdit
{
	Q_OBJECT

public:
	DialogTextEdit(QWidget* parent);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

Q_SIGNALS:
	void contentAccepted();
};

#pragma once

#include <QtWidgets/QLabel>
#include "viewframe.h"
#include "menus.h"
#include "uicontext.h"

class BINARYNINJAUIAPI AddressIndicator: public QLabel
{
	Q_OBJECT

	uint64_t m_begin, m_end;
	ContextMenuManager m_contextMenu;

public:
	AddressIndicator(QWidget* parent);

	void setOffsets(uint64_t begin, uint64_t end);

protected:
	virtual void mousePressEvent(QMouseEvent* event);
	virtual void enterEvent(QEvent* event);
	virtual void leaveEvent(QEvent* event);
};

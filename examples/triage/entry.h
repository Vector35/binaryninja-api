#pragma once

#include <QtWidgets/QWidget>
#include "uitypes.h"

class EntryWidget : public QWidget
{
	std::vector<FunctionRef> m_entry;

  public:
	EntryWidget(QWidget* parent, BinaryViewRef data);
	const std::vector<FunctionRef>& GetEntry() const { return m_entry; }
};

#pragma once
#include <QtWidgets/QWidget>
#include "uitypes.h"
#include "viewframe.h"

class LibrariesWidget : public QWidget
{
  public:
	LibrariesWidget(QWidget* parent, BinaryViewRef bv);
};

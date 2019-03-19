#pragma once

#include <QtWidgets/QFrame>
#include <QtWidgets/QLabel>
#include "uicontext.h"

class BINARYNINJAUIAPI StatusBarWidget: public QWidget
{
	Q_OBJECT

public:
	StatusBarWidget(QWidget* parent);
	virtual void updateStatus();
};

class BINARYNINJAUIAPI DisabledOptionsStatusBarWidget: public StatusBarWidget
{
public:
	DisabledOptionsStatusBarWidget(QFrame* parent);

private:
	QLabel* m_label;
};

#pragma once

#include <QtWidgets/QFrame>
#include <QtWidgets/QLabel>
#include "uicontext.h"

/*!

	\defgroup statusbarwidget StatusBarWidget
 	\ingroup uiapi
*/

/*!

    \ingroup statusbarwidget
*/
class BINARYNINJAUIAPI StatusBarWidget : public QWidget
{
	Q_OBJECT

  public:
	StatusBarWidget(QWidget* parent);
	virtual void updateStatus();
};

/*!

    \ingroup statusbarwidget
*/
class BINARYNINJAUIAPI DisabledOptionsStatusBarWidget : public StatusBarWidget
{
  public:
	DisabledOptionsStatusBarWidget(QFrame* parent);

  private:
	QLabel* m_label;
};

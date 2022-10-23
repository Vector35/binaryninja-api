#pragma once

#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>
#include "uitypes.h"

/*!

	\defgroup preview Preview
 	\ingroup uiapi
*/

/*!

    \ingroup preview
*/
class BINARYNINJAUIAPI PreviewScrollHandler
{
  public:
	virtual ~PreviewScrollHandler() {}
	virtual void sendWheelEvent(QWheelEvent* event) = 0;
};


/*!

    \ingroup preview
*/
class BINARYNINJAUIAPI PreviewWidget : public QFrame
{
	Q_OBJECT

	QWidget* m_contents;
	PreviewScrollHandler* m_scrollHandler;

  protected:
	virtual bool eventFilter(QObject* obj, QEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;

  public:
	PreviewWidget();
	virtual ~PreviewWidget();

	void setContents(QWidget* widget);
	void setScrollHandler(PreviewScrollHandler* handler);
	void sendWheelEvent(QWheelEvent* event);
	void closePreview();

	static bool isPreviewWidget(QWidget* widget);
};

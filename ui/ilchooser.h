#pragma once

#include "pane.h"
#include "menus.h"

/*!

	\defgroup ilchooser ILChooser
 	\ingroup uiapi
*/

/*!

    \ingroup ilchooser
*/
class BINARYNINJAUIAPI ILChooserWidget : public MenuHelper
{
	Q_OBJECT

	UIActionHandler* m_handler;
	bool m_longDescription;

  public:
	ILChooserWidget(QWidget* parent, UIActionHandler* handler, bool longDescription);
	void updateStatus(const BinaryNinja::FunctionViewType& current);

	static QString shortNameForILType(const BinaryNinja::FunctionViewType& type);
	static QString longNameForILType(const BinaryNinja::FunctionViewType& type);

  protected:
	virtual void showMenu() override;
};

/*!

    \ingroup ilchooser
*/
class BINARYNINJAUIAPI ViewPaneHeaderILChooserWidget : public ViewPaneHeaderSubtypeWidget
{
	Q_OBJECT

	View* m_view;
	ILChooserWidget* m_widget;

  public:
	ViewPaneHeaderILChooserWidget(View* view, UIActionHandler* handler);
	virtual void updateStatus();
};

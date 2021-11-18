#pragma once

#include "pane.h"
#include "menus.h"

class BINARYNINJAUIAPI ILChooserWidget: public MenuHelper
{
	Q_OBJECT

	UIActionHandler* m_handler;
	bool m_longDescription;

public:
	ILChooserWidget(QWidget* parent, UIActionHandler* handler, bool longDescription);
	void updateStatus(BNFunctionGraphType current);

	static QString shortNameForILType(BNFunctionGraphType type);
	static QString longNameForILType(BNFunctionGraphType type);

protected:
	virtual void showMenu() override;
};

class BINARYNINJAUIAPI ViewPaneHeaderILChooserWidget: public ViewPaneHeaderSubtypeWidget
{
	Q_OBJECT

	View* m_view;
	ILChooserWidget* m_widget;

public:
	ViewPaneHeaderILChooserWidget(View* view, UIActionHandler* handler);
	virtual void updateStatus();
};

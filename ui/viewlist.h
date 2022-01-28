#pragma once

#include <QtWidgets/QLabel>
#include <string>
#include "viewframe.h"
#include "menus.h"
#include "action.h"

class BINARYNINJAUIAPI ViewList : public MenuHelper
{
	Q_OBJECT

	FileContext* m_context = nullptr;
	QString m_currentType;
	std::string m_currentDataType;

	UIActionHandler* m_handler;

  public:
	ViewList(QWidget* parent);

	void bindActions(UIActionHandler* handler);
	void addMenuActions(Menu* menu, const QString& group);
	void setCurrentViewType(ViewFrame* view, const QString& type);

  protected:
	virtual void showMenu();

  Q_SIGNALS:
	void viewChanged(QString type);
};

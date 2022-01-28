#pragma once

#include <QtWidgets/QLabel>
#include <string>
#include "viewframe.h"
#include "menus.h"

class BINARYNINJAUIAPI DataTypeList : public MenuHelper
{
	Q_OBJECT

	FileContext* m_context = nullptr;
	QString m_currentType;
	std::string m_currentDataType;

  public:
	DataTypeList(QWidget* parent);

	void setCurrentViewType(ViewFrame* view, const QString& type);

  protected:
	virtual void showMenu();

  Q_SIGNALS:
	void viewChanged(QString type);
};

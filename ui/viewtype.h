#pragma once

#include <QtCore/QString>
#include <QtWidgets/QWidget>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"

class ViewFrame;

class BINARYNINJAUIAPI ViewType
{
	QString m_name, m_longName;

public:
	ViewType(const QString& name, const QString& longName);
	virtual ~ViewType();

	const QString& getName() { return m_name; }
	const QString& getLongName() { return m_longName; }
	virtual int getPriority(BinaryViewRef data, const QString& filename) = 0;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) = 0;

	virtual QString getDisplayName(BinaryViewTypeRef type);
	virtual QString getDisplayLongName(BinaryViewTypeRef type);

	static ViewType* getTypeByName(const QString& name);
	static const std::vector<ViewType*>& getTypes();

	static void registerViewType(ViewType* type);
};


class BINARYNINJAUIAPI ViewTypeContainer
{
public:
	std::vector<ViewType*> m_types;

	static ViewTypeContainer& GetViewTypeContainer();
};

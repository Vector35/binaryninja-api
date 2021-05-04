#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"

class BINARYNINJAUIAPI CreateStructDialog: public QDialog
{
	Q_OBJECT

	QLineEdit* m_name;
	QLineEdit* m_size;

	BinaryViewRef m_view;
	BinaryNinja::QualifiedName m_resultName;
	uint64_t m_resultSize;

public:
	CreateStructDialog(QWidget* parent, BinaryViewRef view, const std::string& name);

	BinaryNinja::QualifiedName getName() { return m_resultName; }
	uint64_t getSize() { return m_resultSize; }

private Q_SLOTS:
	void createStruct();

protected:
	virtual void showEvent(QShowEvent* e) override;

};

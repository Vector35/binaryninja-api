#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"

class BINARYNINJAUIAPI CreateTypeDialog : public QDialog
{
	Q_OBJECT

	QLineEdit* m_arguments;
	DialogTextEdit* m_code;
	QTextEdit* m_errors;

	BinaryViewRef m_data;
	std::vector<BinaryNinja::ParsedType> m_results;
	std::set<BinaryNinja::QualifiedName> m_typesAllowRedefinition;

  public:
	CreateTypeDialog(QWidget* parent, BinaryViewRef data, const QString& title, const QString& definition,
	    const std::set<BinaryNinja::QualifiedName>& typesAllowRedefinition = {});
	std::vector<BinaryNinja::ParsedType> getResults() { return m_results; }

  private Q_SLOTS:
	void createType();

  protected:
	virtual void showEvent(QShowEvent* e) override;
};

#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QTextEdit>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"

/*!

    \ingroup uiapi
*/
class BINARYNINJAUIAPI CreateTypeDialog : public QDialog
{
	Q_OBJECT

	QTextEdit* m_arguments;
	DialogTextEdit* m_code;
	QTextEdit* m_errors;

	BinaryNinja::TypeContainer m_container;
	std::vector<BinaryNinja::ParsedType> m_results;
	std::set<BinaryNinja::QualifiedName> m_typesAllowRedefinition;

  public:
	CreateTypeDialog(QWidget* parent, const BinaryNinja::TypeContainer& container, const QString& title, const QString& definition,
	    const std::set<BinaryNinja::QualifiedName>& typesAllowRedefinition = {});
	static CreateTypeDialog* createWithType(QWidget* parent, const BinaryNinja::TypeContainer& container, BinaryNinja::QualifiedName name, TypeRef type);

	std::vector<BinaryNinja::ParsedType> getResults() { return m_results; }
	void applyResults() { applyResultsTo(this, m_container); }
	void applyResultsTo(QWidget* parent, BinaryNinja::TypeContainer container);

  private Q_SLOTS:
	void createType();

  protected:
	void saveLocation();
	virtual void showEvent(QShowEvent* e) override;
	virtual void reject() override;
	virtual void accept() override;
};

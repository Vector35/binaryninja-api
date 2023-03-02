#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QCheckBox>
#include "uitypes.h"

/*!

	\ingroup uiapi
*/
class BINARYNINJAUIAPI BndbImportDialog : public QDialog
{
	Q_OBJECT
	QLineEdit* m_fileEdit;
	QPushButton* m_browseButton;
	QWidget* m_resultsWidget;
	QTreeWidget* m_typesTree;
	QPushButton* m_previewButton;
	QPushButton* m_importButton;
	BinaryViewRef m_data;

	std::string m_filePath;

	struct SymbolAndType
	{
		SymbolAndType(SymbolRef name, TypeRef type): name(name), type(type) {}
		SymbolRef name;
		TypeRef type;
	};

	std::vector<BinaryNinja::QualifiedNameAndType> m_types;
	std::vector<SymbolAndType> m_functions;
	std::vector<SymbolAndType> m_dataVariables;

	BinaryViewRef m_incomingView;
	LoggerRef m_logger;

protected Q_SLOTS:
	void browseFile();
	void updateButtons();
	void previewTypes();
	void importTypes();

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

private:
	bool loadTypes();
	bool isExistingType(const BinaryNinja::QualifiedName& name, bool function) const;
	bool isBuiltinType(const BinaryNinja::QualifiedName& name) const;
	void ApplyFunctionTypes(const std::vector<SymbolAndType>& functions);
	void ApplyDataVariables(const std::vector<SymbolAndType>& dataVariables);

public:
	BndbImportDialog(QWidget* parent, BinaryViewRef view);
	~BndbImportDialog() = default;
};

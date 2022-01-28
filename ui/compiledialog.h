#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLabel>
#include <set>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"

enum CompileMode
{
	CompileStandalone,
	CompilePatch
};

class BINARYNINJAUIAPI CompileDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_view;
	uint64_t m_addr;
	QComboBox* m_arch;
	QComboBox* m_os;
	DialogTextEdit* m_code;
	QLabel* m_optionsText;
	bool m_saveOSSetting;
	std::map<std::string, std::string> m_options;
	std::set<std::string> m_unsavedOptions;
	BinaryNinja::DataBuffer m_bytes;
	bool m_setDefault;

	void appendOptionString(std::string& out, const std::string& text);
	void updateOptionsText();

  public:
	CompileDialog(QWidget* parent, BinaryViewRef data, uint64_t addr, CompileMode mode, const QString& code = "");

	ArchitectureRef getArchitecture();
	const BinaryNinja::DataBuffer& getBytes() const { return m_bytes; }

  private Q_SLOTS:
	void saveOnFinish(int result);
	void compile();
	void options();

  protected:
	virtual void accept() override;
};

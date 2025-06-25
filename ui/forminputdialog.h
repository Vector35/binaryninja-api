#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLabel>
#include <vector>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!

    \ingroup uiapi
*/
class BINARYNINJAUIAPI FormInputDialog : public QDialog
{
	Q_OBJECT

	std::vector<BinaryNinja::FormInputField>* m_fields;
	std::vector<QWidget*> m_fieldControls;

	public:
	void openFileName(QLineEdit* edit, const std::string& ext);
	void saveFileName(QLineEdit* edit, const std::string& ext, const std::string& defaultName);
	void directoryName(QLineEdit* edit, const std::string& defaultName);

	FormInputDialog(QWidget* parent, std::vector<BinaryNinja::FormInputField>* fields, const std::string& title);
	// Callback function types
    typedef bool (*OpenFileNameCallback)(std::string& result, const std::string& ext);
    typedef bool (*SaveFileNameCallback)(std::string& result, const std::string& ext, const std::string& defaultName);
    typedef bool (*DirectoryNameCallback)(std::string& result, const std::string& defaultName);

    // Static callback pointers (will be set by main executable)
    static OpenFileNameCallback s_openFileNameCallback;
    static SaveFileNameCallback s_saveFileNameCallback;
    static DirectoryNameCallback s_directoryNameCallback;

    // Registration function (called by main executable during startup)
    static void registerFileDialogCallbacks(
        OpenFileNameCallback openFileCallback,
        SaveFileNameCallback saveFileCallback,
        DirectoryNameCallback directoryCallback
    );
  protected Q_SLOTS:
	void finish();
};

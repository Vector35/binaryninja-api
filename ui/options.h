#pragma once

#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QWidget>
#include "binaryninjaapi.h"
#include "viewtype.h"
#include "filecontext.h"

#include <string>
#include <tuple>
#include <vector>

/*!

	\defgroup options Options
 	\ingroup uiapi
*/

/*!

    \ingroup options
*/
class BINARYNINJAUIAPI OptionsDialog : public QDialog
{
	Q_OBJECT

	QString m_fileName;
	QLabel* m_fileLabel;
	QComboBox* m_loadAsCombo;
	QLabel* m_loadAsLabel;
	QLabel* m_objectLabel;
	QComboBox* m_objectCombo;
	QTabWidget* m_tab;
	std::map<std::string, QString> m_containerPath;
	QLabel* m_notification;
	std::map<std::string, QString> m_notificationMesssage;
	QPushButton* m_defaultsButton;

	bool m_isDatabase;
	FileContext* m_file = nullptr;
	FileMetadataRef m_fileMetadata = nullptr;
	BinaryViewRef m_rawData = nullptr;
	ProjectRef m_project = nullptr;
	std::vector<std::tuple<std::string, size_t, std::string, uint64_t, uint64_t, std::string>> m_objects;

	const std::string m_oldFlag = "old:";

  public:
	OptionsDialog(QWidget* parent, const QString& name);
	virtual ~OptionsDialog();
	bool loadViews();

  Q_SIGNALS:
	void openFile(FileContext* file);

  private Q_SLOTS:
	void defaults(int index);
	void cancel();
	void open();
	void addSettingsViewForType(const std::string& bvtName);
	void removeTabAndSettingsView(int index);
	void viewTabChanged(int index);
	void viewTabCloseRequested(int index);
	void viewTypeSelectionChanged();
};

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

class BINARYNINJAUIAPI OptionsDialog: public QDialog
{
	Q_OBJECT

	QString m_fileName;
	QLabel* m_fileLabel;
	QLabel* m_objectLabel;
	QComboBox* m_objectCombo;
	QTabWidget* m_tab;
	QLabel* m_notification;

	bool m_isDatabase;
	FileContext* m_file = nullptr;
	FileMetadataRef m_fileMetadata = nullptr;
	BinaryViewRef m_rawData = nullptr;
	std::vector<std::tuple<std::string, size_t, std::string, uint64_t, uint64_t, std::string>> m_objects;

public:
	OptionsDialog(QWidget* parent, const QString& name);
	virtual ~OptionsDialog();

Q_SIGNALS:
	void openFile(FileContext* file);

private Q_SLOTS:
	void cancel();
	void open();
	void addSettingsViewForType(const std::string& bvtName);
	void queryViewTypes();
	void viewTabCloseRequested(int index);
};

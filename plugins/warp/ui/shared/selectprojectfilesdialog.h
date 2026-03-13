#pragma once

#include <QComboBox>
#include <QDialog>
#include <QListWidget>

#include "binaryninjaapi.h"

class SelectProjectFilesDialog : public QDialog
{
	Q_OBJECT
	BinaryNinja::Ref<BinaryNinja::Project> m_currentProject;
	QComboBox* m_projectCombo;
	QLineEdit* m_searchBar;
	QListWidget* m_notAddingList;
	QListWidget* m_addingList;

public:
	SelectProjectFilesDialog(QWidget* parent = nullptr);

	void updateFileList();
	void filterLists();
	void moveSelected(QListWidget* from, QListWidget* to);
	[[nodiscard]] std::vector<BinaryNinja::Ref<BinaryNinja::ProjectFile>> getSelectedFiles() const;
	[[nodiscard]] BinaryNinja::Ref<BinaryNinja::Project> getSelectedProject() const;
};

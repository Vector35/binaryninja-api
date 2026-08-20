#include "selectprojectfilesdialog.h"

#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

using namespace BinaryNinja;

SelectProjectFilesDialog::SelectProjectFilesDialog(QWidget* parent) : QDialog(parent)
{
	setProperty("bn.uiTestId", "warpSelectProjectFilesDialog");
	setProperty("bn.uiTestScope", "warpSelectProjectFilesDialog");
	setAccessibleName("Select project files for WARP");
	setWindowTitle("Select Project Files");
	setMinimumSize(700, 400);
	auto* layout = new QVBoxLayout(this);

	auto* topLayout = new QFormLayout();
	m_projectCombo = new QComboBox(this);
	m_projectCombo->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.project");
	m_projectCombo->setAccessibleName("Project");
	auto projects = Project::GetOpenProjects();
	for (auto& project : projects)
	{
		m_projectCombo->addItem(QString::fromStdString(project->GetName()), QVariant::fromValue(project));
	}
	topLayout->addRow("Project:", m_projectCombo);
	layout->addLayout(topLayout);

	m_searchBar = new QLineEdit(this);
	m_searchBar->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.search");
	m_searchBar->setAccessibleName("Search project files");
	m_searchBar->setPlaceholderText("Search files...");
	connect(m_searchBar, &QLineEdit::textChanged, this, &SelectProjectFilesDialog::filterLists);
	layout->addWidget(m_searchBar);

	auto* listsLayout = new QHBoxLayout();

	auto* notAddingBox = new QVBoxLayout();
	notAddingBox->addWidget(new QLabel("Available:"));
	m_notAddingList = new QListWidget(this);
	m_notAddingList->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.available");
	m_notAddingList->setAccessibleName("Available project files");
	m_notAddingList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_notAddingList->setTextElideMode(Qt::ElideLeft);
	m_notAddingList->setStyleSheet("QListWidget::item { padding: 2px; }");
	notAddingBox->addWidget(m_notAddingList);
	listsLayout->addLayout(notAddingBox);

	auto* middleButtons = new QVBoxLayout();
	middleButtons->addStretch();
	auto* addButton = new QPushButton(">>", this);
	addButton->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.select");
	addButton->setAccessibleName("Select files");
	connect(addButton, &QPushButton::clicked, [this]() { moveSelected(m_notAddingList, m_addingList); });
	middleButtons->addWidget(addButton);
	auto* removeButton = new QPushButton("<<", this);
	removeButton->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.deselect");
	removeButton->setAccessibleName("Deselect files");
	connect(removeButton, &QPushButton::clicked, [this]() { moveSelected(m_addingList, m_notAddingList); });
	middleButtons->addWidget(removeButton);
	middleButtons->addStretch();
	listsLayout->addLayout(middleButtons);

	auto* addingBox = new QVBoxLayout();
	addingBox->addWidget(new QLabel("Selected:"));
	m_addingList = new QListWidget(this);
	m_addingList->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.selected");
	m_addingList->setAccessibleName("Selected project files");
	m_addingList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_addingList->setTextElideMode(Qt::ElideLeft);
	m_addingList->setStyleSheet("QListWidget::item { padding: 2px; }");
	addingBox->addWidget(m_addingList);
	listsLayout->addLayout(addingBox);

	layout->addLayout(listsLayout);

	auto* buttons = new QHBoxLayout(this);
	auto* ok = new QPushButton("Add", this);
	ok->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.add");
	connect(ok, &QPushButton::clicked, this, &QDialog::accept);
	auto* cancel = new QPushButton("Cancel", this);
	cancel->setProperty("bn.uiTestId", "warpSelectProjectFilesDialog.cancel");
	connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
	buttons->addStretch();
	buttons->addWidget(ok);
	buttons->addWidget(cancel);
	layout->addLayout(buttons);

	connect(m_projectCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
		&SelectProjectFilesDialog::updateFileList);

	connect(m_notAddingList, &QListWidget::itemDoubleClicked, [this](QListWidgetItem* item) {
		m_addingList->addItem(m_notAddingList->takeItem(m_notAddingList->row(item)));
		filterLists();
	});
	connect(m_addingList, &QListWidget::itemDoubleClicked, [this](QListWidgetItem* item) {
		m_notAddingList->addItem(m_addingList->takeItem(m_addingList->row(item)));
		filterLists();
	});

	updateFileList();
}

void SelectProjectFilesDialog::updateFileList()
{
	m_notAddingList->clear();
	m_addingList->clear();
	m_currentProject = m_projectCombo->currentData().value<Ref<Project>>();
	if (m_currentProject)
	{
		for (auto& file : m_currentProject->GetFiles())
		{
			auto* item = new QListWidgetItem(QString::fromStdString(file->GetPathInProject()));
			item->setData(Qt::UserRole, QVariant::fromValue(file));
			m_notAddingList->addItem(item);
		}
	}
	filterLists();
}

void SelectProjectFilesDialog::filterLists()
{
	QString filter = m_searchBar->text().toLower();
	for (int i = 0; i < m_notAddingList->count(); ++i)
	{
		auto* item = m_notAddingList->item(i);
		item->setHidden(!item->text().toLower().contains(filter));
	}
	for (int i = 0; i < m_addingList->count(); ++i)
	{
		auto* item = m_addingList->item(i);
		item->setHidden(!item->text().toLower().contains(filter));
	}
}

void SelectProjectFilesDialog::moveSelected(QListWidget* from, QListWidget* to)
{
	QList<QListWidgetItem*> items = from->selectedItems();
	for (auto* item : items)
		to->addItem(from->takeItem(from->row(item)));
	filterLists();
}

std::vector<Ref<ProjectFile>> SelectProjectFilesDialog::getSelectedFiles() const
{
	std::vector<Ref<ProjectFile>> files;
	for (int i = 0; i < m_addingList->count(); ++i)
		files.push_back(m_addingList->item(i)->data(Qt::UserRole).value<Ref<ProjectFile>>());
	return files;
}

Ref<Project> SelectProjectFilesDialog::getSelectedProject() const
{
	return m_currentProject;
}

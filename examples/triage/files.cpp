#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QMessageBox>
#include <QtCore/QSettings>
#include "files.h"


TriageFilePicker::TriageFilePicker(UIContext* context): m_contextMenuManager(this)
{
	m_context = context;
	m_actionHandler.setupActionHandler(this);

	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);

	m_model = new QFileSystemModel();
	m_model->setRootPath("");
	m_tree = new QTreeView(this);
	m_tree->setModel(m_model);
	m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_tree->setColumnWidth(0, 500);
	layout->addWidget(m_tree, 1);

	setLayout(layout);

	connect(m_tree, &QTreeView::doubleClicked, this, &TriageFilePicker::onDoubleClick);

	QString recentFile = QSettings().value("triage/recentFile", QDir::homePath()).toString();
	while (recentFile.size() > 0)
	{
		QModelIndex f = m_model->index(recentFile);
		if (f.isValid())
		{
			m_tree->scrollTo(f);
			m_tree->setExpanded(f, true);
			break;
		}
		QString parentDir = QFileInfo(recentFile).path();
		if (parentDir == recentFile)
			break;
		recentFile = parentDir;
	}

	m_actionHandler.bindAction("Open Selected Files", UIAction(
		[=]() { openSelectedFiles(); },
		[=]() { return areFilesSelected(); }));
	m_contextMenu.addAction("Open Selected Files", "Open");
}


void TriageFilePicker::contextMenuEvent(QContextMenuEvent*)
{
	m_contextMenuManager.show(&m_contextMenu, &m_actionHandler);
}


void TriageFilePicker::onDoubleClick(const QModelIndex&)
{
	openSelectedFiles();
}


void TriageFilePicker::openSelectedFiles()
{
	std::vector<QString> failedToOpen;
	std::set<QString> files;

	for (auto& index: m_tree->selectionModel()->selectedIndexes())
		if (m_model->fileInfo(index).isFile())
			files.insert(m_model->fileInfo(index).absoluteFilePath());

	for (auto& filename: files)
	{
		QSettings().setValue("triage/recentFile", filename);

		FileContext* f = FileContext::openFilename(filename);
		if (!f)
		{
			failedToOpen.push_back(filename);
			continue;
		}

		for (auto data: f->getAllDataViews())
		{
			BinaryNinja::Settings().Set("analysis.mode", BinaryNinja::Settings().Get<std::string>("triage.analysisMode"), data);
			BinaryNinja::Settings().Set("triage.preferSummaryView", true, data);
			if (data->GetTypeName() != "Raw")
			{
				std::string linearSweepMode = BinaryNinja::Settings().Get<std::string>("triage.linearSweep");
				if (linearSweepMode == "none")
				{
					BinaryNinja::Settings().Set("analysis.linearSweep.autorun", false, data);
				}
				else if (linearSweepMode == "partial")
				{
					BinaryNinja::Settings().Set("analysis.linearSweep.autorun", true, data);
					BinaryNinja::Settings().Set("analysis.linearSweep.controlFlowGraph", false, data);
				}
				else if (linearSweepMode == "full")
				{
					BinaryNinja::Settings().Set("analysis.linearSweep.autorun", true, data);
					BinaryNinja::Settings().Set("analysis.linearSweep.controlFlowGraph", true, data);
				}
			}
		}

		m_context->openFileContext(f);
	}

	if (failedToOpen.size() > 0)
	{
		QString message = "Unable to open:\n";
		for (auto& name: failedToOpen)
			message += name + "\n";
		QMessageBox::critical(this, "Error", message);
	}
}


bool TriageFilePicker::areFilesSelected()
{
	return m_tree->selectionModel()->hasSelection();
}

#include "processordialog.h"
#include "commitdialog.h"
#include "misc.h"
#include "selectprojectfilesdialog.h"

#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QDirIterator>
#include <QFileInfo>
#include <QDir>

using namespace BinaryNinja;

ProcessorDialog::ProcessorDialog(QWidget* parent) : QDialog(parent)
{
	setWindowModality(Qt::NonModal);
	setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
	setWindowTitle("WARP Processor");
	setMinimumSize(400, 300);

	auto* mainLayout = new QVBoxLayout(this);
	m_stack = new QStackedWidget(this);
	mainLayout->addWidget(m_stack);

	// Page 1: Configuration
	auto* configPage = new QWidget(this);
	auto* configLayout = new QVBoxLayout(configPage);

	auto* entrySearchLayout = new QHBoxLayout();
	entrySearchLayout->setContentsMargins(0, 0, 0, 0);
	m_entrySearch = new QLineEdit(this);
	m_entrySearch->setPlaceholderText("Search entries...");
	connect(m_entrySearch, &QLineEdit::textChanged, this, &ProcessorDialog::onSearchItems);
	entrySearchLayout->addWidget(m_entrySearch);

	m_addButton = new QPushButton("+", this);
	m_addButton->setFixedWidth(30);
	m_addButton->setToolTip("Add entries");
	connect(m_addButton, &QPushButton::clicked, this, &ProcessorDialog::onAddEntryMenu);
	entrySearchLayout->addWidget(m_addButton);
	configLayout->addLayout(entrySearchLayout);

	m_entryList = new QListWidget(this);
	m_entryList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_entryList->setContextMenuPolicy(Qt::CustomContextMenu);
	m_entryList->setTextElideMode(Qt::ElideLeft);
	m_entryList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_entryList->setStyleSheet("QListWidget::item { padding: 2px; }");
	connect(m_entryList, &QListWidget::customContextMenuRequested, this, &ProcessorDialog::showContextMenu);
	configLayout->addWidget(m_entryList);

	auto* formLayout = new QFormLayout();
	m_includedDataCombo = new QComboBox(this);
	m_includedDataCombo->addItem("Symbols", WARPProcessorIncludedDataSymbols);
	m_includedDataCombo->addItem("Signatures", WARPProcessorIncludedDataSignatures);
	m_includedDataCombo->addItem("Types", WARPProcessorIncludedDataTypes);
	m_includedDataCombo->addItem("All", WARPProcessorIncludedDataAll);
	m_includedDataCombo->setCurrentIndex(3);

	m_includedFunctionsCombo = new QComboBox(this);
	m_includedFunctionsCombo->addItem("Selected", WARPProcessorIncludedFunctionsSelected);
	m_includedFunctionsCombo->addItem("Annotated", WARPProcessorIncludedFunctionsAnnotated);
	m_includedFunctionsCombo->addItem("All", WARPProcessorIncludedFunctionsAll);
	m_includedFunctionsCombo->setCurrentIndex(1);

	m_workerCountSpinBox = new QSpinBox(this);
	m_workerCountSpinBox->setMinimum(2);
	m_workerCountSpinBox->setValue(GetWorkerThreadCount());

	formLayout->addRow("Included Data:", m_includedDataCombo);
	formLayout->addRow("Included Functions:", m_includedFunctionsCombo);
	formLayout->addRow("Worker Count:", m_workerCountSpinBox);
	configLayout->addLayout(formLayout);

	m_processButton = new QPushButton("Process", this);
	m_processButton->setEnabled(false);
	connect(m_processButton, &QPushButton::clicked, this, &ProcessorDialog::onStartProcessing);
	configLayout->addWidget(m_processButton, 0, Qt::AlignRight);
	m_stack->addWidget(configPage);

	// Page 2: Processing
	auto* processPage = new QWidget(this);
	auto* processLayout = new QVBoxLayout(processPage);
	m_processingLabel = new QLabel("Processing...", this);
	m_processingLabel->setAlignment(Qt::AlignCenter);
	m_progressBar = new QProgressBar(this);
	m_progressBar->setRange(0, 0);

	m_stateList = new QListWidget(this);
	m_stateList->setSelectionMode(QAbstractItemView::NoSelection);
	m_stateList->setFocusPolicy(Qt::NoFocus);
	m_stateList->setTextElideMode(Qt::ElideLeft);
	m_stateList->setWordWrap(false);
	m_stateList->setStyleSheet(
		"QListWidget { background: transparent; border: none; } QListWidget::item { padding: 1px; }");
	m_stateList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_stateList->setMinimumHeight(100);

	m_cancelButton = new QPushButton("Cancel", this);
	connect(m_cancelButton, &QPushButton::clicked, this, &ProcessorDialog::onCancelProcessing);

	m_updateTimer = new QTimer(this);
	connect(m_updateTimer, &QTimer::timeout, this, &ProcessorDialog::onUpdateState);

	processLayout->addStretch();
	processLayout->addWidget(m_processingLabel);
	processLayout->addWidget(m_progressBar);
	processLayout->addWidget(m_stateList);
	processLayout->addStretch();
	processLayout->addWidget(m_cancelButton, 0, Qt::AlignRight);
	m_stack->addWidget(processPage);

	// Page 3: Results
	auto* resultsPage = new QWidget(this);
	auto* resultsLayout = new QVBoxLayout(resultsPage);
	m_fileWidget = new FileWidget(this);
	resultsLayout->addWidget(m_fileWidget);

	auto* buttonLayout = new QHBoxLayout();
	m_saveButton = new QPushButton("Save to File", this);
	connect(m_saveButton, &QPushButton::clicked, this, &ProcessorDialog::onSaveToFile);
	m_elapsedLabel = new QLabel(this);
	m_commitButton = new QPushButton("Commit", this);
	connect(m_commitButton, &QPushButton::clicked, this, &ProcessorDialog::onCommit);
	buttonLayout->addWidget(m_elapsedLabel);
	buttonLayout->addStretch();
	buttonLayout->addWidget(m_saveButton);
	buttonLayout->addWidget(m_commitButton);
	resultsLayout->addLayout(buttonLayout);
	m_stack->addWidget(resultsPage);

	m_stack->setCurrentIndex(ConfigurationPage);
}

ProcessorDialog::~ProcessorDialog()
{
	m_updateTimer->stop();
	if (m_processor)
		m_processor->Cancel();
}

void ProcessorDialog::onStartProcessing()
{
	if (m_toProcess.empty())
		return;

	auto includedData = static_cast<BNWARPProcessorIncludedData>(m_includedDataCombo->currentData().toInt());
	auto includedFunctions =
		static_cast<BNWARPProcessorIncludedFunctions>(m_includedFunctionsCombo->currentData().toInt());
	auto workerCount = static_cast<size_t>(m_workerCountSpinBox->value());

	m_processor = std::make_shared<Warp::Processor>(includedData, includedFunctions, workerCount);

	for (const auto& item : m_toProcess)
	{
		switch (item.type)
		{
		case ToProcessEntry::ViewMode:
			m_processor->AddBinaryView(*item.view);
			break;
		case ToProcessEntry::PathMode:
			m_processor->AddPath(item.path);
			break;
		case ToProcessEntry::ProjectMode:
			m_processor->AddProject(*item.project);
			break;
		case ToProcessEntry::ProjectFileMode:
			m_processor->AddProjectFile(*item.projectFile);
			break;
		}
	}

	m_stack->setCurrentIndex(ProcessingPage);
	m_processTimer.start();
	auto* worker = new WarpProcessorWorker(m_processor);
	connect(worker, &WarpProcessorWorker::finishedProcessing, this, &ProcessorDialog::onProcessingFinished);
	connect(worker, &WarpProcessorWorker::finished, worker, &QObject::deleteLater);
	worker->start();

	m_cancelButton->setEnabled(true);
	m_updateTimer->start(100);
}

void ProcessorDialog::onAddEntryMenu()
{
	QMenu menu(nullptr);
	addAddActionsToMenu(&menu);
	menu.exec(m_addButton->mapToGlobal(QPoint(0, m_addButton->height())));
}

void ProcessorDialog::addAddActionsToMenu(QMenu* menu)
{
	menu->addAction("Add Files...", this, &ProcessorDialog::onAddPath);
	menu->addAction("Add Directory...", this, &ProcessorDialog::onAddDirectory);
	menu->addAction("Add Project Files", this, &ProcessorDialog::onAddProjectFiles);
}

void ProcessorDialog::showContextMenu(const QPoint& pos)
{
	QMenu menu(nullptr);
	addAddActionsToMenu(&menu);

	QListWidgetItem* item = m_entryList->itemAt(pos);
	if (item)
	{
		menu.addSeparator();
		menu.addAction("Remove", this, &ProcessorDialog::onRemoveItem);
	}

	menu.exec(m_entryList->mapToGlobal(pos));
}

void ProcessorDialog::onAddBinaryView(Ref<BinaryView> view)
{
	ToProcessEntry item;
	item.type = ToProcessEntry::ViewMode;
	item.view = view;
	item.displayName = QString("View: %1").arg(QString::fromStdString(view->GetFile()->GetFilename()));

	m_toProcess.push_back(item);
	m_entryList->addItem(item.displayName);
	onSearchItems();
	m_processButton->setEnabled(true);
}

void ProcessorDialog::onAddPath()
{
	QStringList paths = QFileDialog::getOpenFileNames(this, "Select Files", "", "All Files (*)");
	if (paths.isEmpty())
		return;

	for (const auto& path : paths)
		addPathRecursive(path);

	onSearchItems();
	m_processButton->setEnabled(true);
}

void ProcessorDialog::onAddDirectory()
{
	QString path = QFileDialog::getExistingDirectory(this, "Select Directory", "");
	if (path.isEmpty())
		return;

	addPathRecursive(path);

	onSearchItems();
	m_processButton->setEnabled(true);
}

void ProcessorDialog::addPathRecursive(const QString& path)
{
	QFileInfo info(path);
	if (info.isDir())
	{
		QDirIterator it(path, QDir::Files, QDirIterator::Subdirectories);
		while (it.hasNext())
		{
			addSinglePath(it.next());
		}
	}
	else
	{
		addSinglePath(path);
	}
}

void ProcessorDialog::addSinglePath(const QString& path)
{
	ToProcessEntry item;
	item.type = ToProcessEntry::PathMode;
	item.path = path.toStdString();
	item.displayName = QString("Path: %1").arg(path);

	m_toProcess.push_back(item);
	m_entryList->addItem(item.displayName);
}

void ProcessorDialog::onAddProjectFiles()
{
	auto projects = Project::GetOpenProjects();
	if (projects.empty())
	{
		QMessageBox::information(this, "Add Project Files", "No projects are currently open.");
		return;
	}

	SelectProjectFilesDialog dlg(this);
	if (dlg.exec() == Accepted)
	{
		auto selectedFiles = dlg.getSelectedFiles();
		if (selectedFiles.empty())
		{
			// If no files selected, add the entire project
			auto project = dlg.getSelectedProject();
			ToProcessEntry item;
			item.type = ToProcessEntry::ProjectMode;
			item.project = project;
			item.displayName = QString("Project: %1").arg(QString::fromStdString(project->GetName()));
			m_toProcess.push_back(item);
			m_entryList->addItem(item.displayName);
		}
		else
		{
			for (auto& file : selectedFiles)
			{
				ToProcessEntry item;
				item.type = ToProcessEntry::ProjectFileMode;
				item.projectFile = file;
				item.displayName = QString("File: %1").arg(QString::fromStdString(file->GetName()));
				m_toProcess.push_back(item);
				m_entryList->addItem(item.displayName);
			}
		}
		onSearchItems();
		m_processButton->setEnabled(true);
	}
}

void ProcessorDialog::onRemoveItem()
{
	auto selectedItems = m_entryList->selectedItems();
	if (selectedItems.isEmpty())
	{
		int row = m_entryList->currentRow();
		if (row >= 0 && row < (int)m_toProcess.size())
		{
			m_toProcess.erase(m_toProcess.begin() + row);
			delete m_entryList->takeItem(row);
		}
	}
	else
	{
		for (auto* item : selectedItems)
		{
			int row = m_entryList->row(item);
			if (row >= 0 && row < (int)m_toProcess.size())
			{
				m_toProcess.erase(m_toProcess.begin() + row);
				delete m_entryList->takeItem(row);
			}
		}
	}
	m_processButton->setEnabled(!m_toProcess.empty());
}

void ProcessorDialog::onSearchItems()
{
	QString filter = m_entrySearch->text().toLower();
	for (int i = 0; i < m_entryList->count(); ++i)
	{
		auto* item = m_entryList->item(i);
		item->setHidden(!item->text().toLower().contains(filter));
	}
}

void ProcessorDialog::onProcessingFinished(Warp::Ref<Warp::File> file)
{
	m_updateTimer->stop();

	if (!file)
	{
		QMessageBox::critical(this, "Error", "Failed to process the selected input.");
		m_stack->setCurrentIndex(ConfigurationPage);
		return;
	}

	auto elapsed = m_processTimer.elapsed();
	if (elapsed < 1000)
		m_elapsedLabel->setText(QString("Processing took: %1ms").arg(elapsed));
	else
		m_elapsedLabel->setText(QString("Processing took: %1s").arg(elapsed / 1000.0, 0, 'f', 2));

	m_file = file;
	m_fileWidget->setFile(m_file);
	m_stack->setCurrentIndex(ResultsPage);
}

void ProcessorDialog::onCancelProcessing()
{
	if (m_processor)
		m_processor->Cancel();
	m_cancelButton->setEnabled(false);
	m_processingLabel->setText("Cancelling...");
}

void ProcessorDialog::onUpdateState()
{
	if (!m_processor)
		return;

	auto state = m_processor->GetState();
	size_t total = state.processedFilesCount + state.unprocessedFilesCount;
	if (total > 0)
	{
		m_progressBar->setMaximum(total);
		m_progressBar->setValue(state.processedFilesCount);
	}

	m_stateList->clear();

	auto addToList = [&](const std::vector<std::string>& files, const QString& prefix) {
		for (auto it = files.rbegin(); it != files.rend(); ++it)
		{
			auto* item = new QListWidgetItem(prefix + QString::fromStdString(*it));
			item->setTextAlignment(Qt::AlignCenter);
			m_stateList->addItem(item);
		}
	};

	addToList(state.processingFiles, "Processing: ");
	addToList(state.analyzingFiles, "Analyzing: ");
}

void ProcessorDialog::onSaveToFile()
{
	if (!m_file)
		return;

	QString fileName = QFileDialog::getSaveFileName(this, "Save WARP File", "", "WARP Files (*.warp)");
	if (!fileName.isEmpty())
	{
		DataBuffer buffer = m_file->ToDataBuffer();
		QFile file(fileName);
		if (file.open(QIODevice::WriteOnly))
		{
			file.write(static_cast<const char*>(buffer.GetData()), buffer.GetLength());
			file.close();
			QMessageBox::information(this, "Success", "File saved successfully.");
		}
		else
		{
			QMessageBox::critical(this, "Error", "Failed to open file for writing.");
		}
	}
}

void ProcessorDialog::onCommit()
{
	if (!m_file)
		return;

	auto* dialog = new CommitDialog(m_file, this);
	dialog->setAttribute(Qt::WA_DeleteOnClose);
	dialog->show();
}

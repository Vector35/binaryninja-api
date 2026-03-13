#pragma once

#include <QDialog>
#include <QStackedWidget>
#include <QComboBox>
#include <QProgressBar>
#include <QThread>
#include <QTimer>
#include <QMenu>
#include <QSpinBox>
#include <QElapsedTimer>
#include <utility>

#include "binaryninjaapi.h"
#include "warp.h"
#include "file.h"

// TODO: Both of these are bothersome but I don't really want to do a ID lookup.
Q_DECLARE_METATYPE(BinaryNinja::Ref<BinaryNinja::Project>)
Q_DECLARE_METATYPE(BinaryNinja::Ref<BinaryNinja::ProjectFile>)

// Worker to run the processor
class WarpProcessorWorker : public QThread
{
	Q_OBJECT

	std::shared_ptr<Warp::Processor> m_processor;

public:
	WarpProcessorWorker(std::shared_ptr<Warp::Processor> processor, QObject* parent = nullptr) :
		QThread(parent), m_processor(std::move(processor))
	{}

	void run() override
	{
		Warp::Ref<Warp::File> file = m_processor->Start();
		emit finishedProcessing(file);
	}

signals:
	void finishedProcessing(Warp::Ref<Warp::File> file);
};

class ProcessorDialog : public QDialog
{
	Q_OBJECT

public:
	explicit ProcessorDialog(QWidget* parent = nullptr);
	~ProcessorDialog() override;

	void onAddBinaryView(BinaryNinja::Ref<BinaryNinja::BinaryView> view);
	void onAddProjectFiles();

private slots:
	void onStartProcessing();
	void onProcessingFinished(Warp::Ref<Warp::File> file);
	void onCancelProcessing();
	void onUpdateState();
	void onSaveToFile();
	void onCommit();
	void onAddPath();
	void onAddDirectory();
	void onRemoveItem();
	void onSearchItems();
	void onAddEntryMenu();
	void showContextMenu(const QPoint& pos);

private:
	void addAddActionsToMenu(QMenu* menu);
	void addPathRecursive(const QString& path);
	void addSinglePath(const QString& path);
	struct ToProcessEntry
	{
		enum Type
		{
			ViewMode,
			PathMode,
			ProjectMode,
			ProjectFileMode
		} type;
		BinaryNinja::Ref<BinaryNinja::BinaryView> view;
		std::string path;
		BinaryNinja::Ref<BinaryNinja::Project> project;
		BinaryNinja::Ref<BinaryNinja::ProjectFile> projectFile;
		QString displayName;
	};

	Warp::Ref<Warp::File> m_file;
	std::shared_ptr<Warp::Processor> m_processor;
	std::vector<ToProcessEntry> m_toProcess;

	enum Page
	{
		ConfigurationPage = 0,
		ProcessingPage = 1,
		ResultsPage = 2
	};

	QStackedWidget* m_stack;

	// Page 1: Configuration
	QLineEdit* m_entrySearch;
	QPushButton* m_addButton;
	QListWidget* m_entryList;

	// Global Config
	QComboBox* m_includedDataCombo;
	QComboBox* m_includedFunctionsCombo;
	QSpinBox* m_workerCountSpinBox;
	QPushButton* m_processButton;

	// Page 2: Processing
	QLabel* m_processingLabel;
	QProgressBar* m_progressBar;
	QListWidget* m_stateList;
	QPushButton* m_cancelButton;
	QTimer* m_updateTimer;

	// Page 3: Results
	FileWidget* m_fileWidget;
	QPushButton* m_saveButton;
	QLabel* m_elapsedLabel;
	QPushButton* m_commitButton;

	QElapsedTimer m_processTimer;
};

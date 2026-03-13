#pragma once

#include <QDialog>
#include <QStackedWidget>
#include <QComboBox>
#include <QProgressBar>
#include <QThread>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>

#include "binaryninjaapi.h"
#include "source.h"
#include "warp.h"
#include "source.h"

// Worker to commit a file to a container
class WarpCommitWorker : public QThread
{
	Q_OBJECT

	Warp::Ref<Warp::Container> m_container;
	Warp::Source m_source;
	Warp::Ref<Warp::File> m_file;

public:
	WarpCommitWorker(Warp::Ref<Warp::Container> container, Warp::Source source, Warp::Ref<Warp::File> file,
		QObject* parent = nullptr) : QThread(parent), m_container(container), m_source(source), m_file(file)
	{}

	void run() override
	{
		for (const auto& chunk : m_file->GetChunks())
		{
			if (auto target = chunk->GetTarget())
				m_container->AddFunctions(*target, m_source, chunk->GetFunctions());
			m_container->AddTypes(m_source, chunk->GetTypes());
		}

		const bool result = m_container->CommitSource(m_source);
		emit finishedCommitting(result);
	}

signals:
	void finishedCommitting(bool success);
};

class CommitDialog : public QDialog
{
	Q_OBJECT

public:
	explicit CommitDialog(Warp::Ref<Warp::File> file, QWidget* parent = nullptr);

private slots:
	void onContainerChanged(int index);
	void onCreateNewSource();
	void onCommit();
	void onCommitFinished(bool success);

private:
	void populateContainers();

	Warp::Ref<Warp::File> m_file;
	std::vector<Warp::Ref<Warp::Container>> m_containers;

	QComboBox* m_containerCombo;
	QLineEdit* m_sourceFilter;
	QPushButton* m_addSourceButton;
	QSortFilterProxyModel* m_proxyModel;
	WarpSourcesView* m_sourcesView;
	QPushButton* m_commitButton;
};
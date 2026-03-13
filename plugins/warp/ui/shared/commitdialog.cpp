#include "commitdialog.h"
#include "file.h"
#include "misc.h"

#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QPushButton>
#include <QTimer>

CommitDialog::CommitDialog(Warp::Ref<Warp::File> file, QWidget* parent) : QDialog(parent), m_file(file)
{
	setWindowModality(Qt::NonModal);
	setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
	setWindowTitle("Commit to Source");
	setMinimumSize(300, 200);

	auto* mainLayout = new QVBoxLayout(this);

	auto* commitFormLayout = new QFormLayout();

	m_containerCombo = new QComboBox(this);
	connect(
		m_containerCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &CommitDialog::onContainerChanged);

	m_sourcesView = new WarpSourcesView(this);
	m_proxyModel = new QSortFilterProxyModel(this);
	m_proxyModel->setSourceModel(m_sourcesView->sourceModel());
	m_proxyModel->setFilterKeyColumn(WarpSourcesModel::PathCol);
	m_proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
	m_sourcesView->setModel(m_proxyModel);

	auto* sourceLayout = new QVBoxLayout();

	auto* filterLayout = new QHBoxLayout();
	m_sourceFilter = new QLineEdit(this);
	m_sourceFilter->setPlaceholderText("Filter sources...");
	connect(m_sourceFilter, &QLineEdit::textChanged, m_proxyModel, &QSortFilterProxyModel::setFilterFixedString);
	filterLayout->addWidget(m_sourceFilter);

	m_addSourceButton = new QPushButton("+", this);
	m_addSourceButton->setFixedWidth(30);
	m_addSourceButton->setToolTip("Add source");
	connect(m_addSourceButton, &QPushButton::clicked, this, &CommitDialog::onCreateNewSource);
	filterLayout->addWidget(m_addSourceButton);

	sourceLayout->addLayout(filterLayout);
	sourceLayout->addWidget(m_sourcesView);

	commitFormLayout->addRow("Container:", m_containerCombo);
	commitFormLayout->addRow("Source:", sourceLayout);

	auto commitBtnLabel = QString("Commit %1 chunks").arg(m_file->GetChunks().size());
	m_commitButton = new QPushButton(commitBtnLabel, this);
	connect(m_commitButton, &QPushButton::clicked, this, &CommitDialog::onCommit);

	mainLayout->addLayout(commitFormLayout);
	mainLayout->addWidget(m_commitButton, 0, Qt::AlignRight);

	populateContainers();

	if (!m_containers.empty())
		m_sourcesView->setContainer(m_containers[m_containerCombo->currentIndex()]);
}

void CommitDialog::populateContainers()
{
	m_containers = Warp::Container::All();
	m_containerCombo->clear();
	for (const auto& container : m_containers)
		m_containerCombo->addItem(QString::fromStdString(container->GetName()));
}

void CommitDialog::onContainerChanged(int index)
{
	if (index >= 0 && index < m_containers.size())
		m_sourcesView->setContainer(m_containers[index]);
}

void CommitDialog::onCreateNewSource()
{
	if (m_sourcesView->addSource())
	{
		// Select the newly added source
		int rowCount = m_sourcesView->sourceModel()->rowCount();
		if (rowCount > 0)
		{
			QModelIndex sourceIdx = m_sourcesView->sourceModel()->index(rowCount - 1, WarpSourcesModel::PathCol);
			m_sourcesView->setCurrentIndex(m_proxyModel->mapFromSource(sourceIdx));
		}
	}
}

void CommitDialog::onCommit()
{
	if (!m_file)
		return;
	int containerIdx = m_containerCombo->currentIndex();
	QModelIndex proxyIdx = m_sourcesView->currentIndex();

	if (m_file->GetChunks().empty())
	{
		QMessageBox::critical(this, "Error", "No chunks to commit.");
		return;
	}

	if (containerIdx < 0 || !proxyIdx.isValid())
	{
		QMessageBox::critical(this, "Error", "No source selected, please select a source.");
		return;
	}

	auto container = m_containers[containerIdx];
	QModelIndex sourceIdx = m_proxyModel->mapToSource(proxyIdx);
	auto optSource = m_sourcesView->sourceFromRow(sourceIdx.row());
	if (!optSource.has_value())
	{
		QMessageBox::critical(this, "Error", "Failed to retrieve the selected source.");
		return;
	}
	auto source = optSource.value();

	m_commitButton->setEnabled(false);
	m_commitButton->setText("Committing...");

	auto* worker = new WarpCommitWorker(container, source, m_file);
	connect(worker, &WarpCommitWorker::finishedCommitting, this, &CommitDialog::onCommitFinished);
	connect(worker, &WarpCommitWorker::finished, worker, &QObject::deleteLater);
	worker->start();
}

void CommitDialog::onCommitFinished(bool success)
{
	m_commitButton->setEnabled(true);
	m_commitButton->setText("Commit");

	if (success)
		QMessageBox::information(this, "Success", "Successfully committed to the source.");
	else
		QMessageBox::critical(this, "Error", "Failed to commit to the source.");
}

#include "file.h"

#include <QVBoxLayout>

FileWidget::FileWidget(QWidget* parent) : QWidget(parent)
{
	setProperty("bn.uiTestId", "warpFile");
	setProperty("bn.uiTestScope", "warpFile");
	setAccessibleName("WARP file");
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	auto* splitter = new QSplitter(Qt::Horizontal, this);
	splitter->setProperty("bn.uiTestId", "warpFile.splitter");

	// Left side: List of chunks
	m_list = new QListWidget(this);
	m_list->setProperty("bn.uiTestId", "warpFile.chunkList");
	m_list->setAccessibleName("WARP file chunks");
	m_list->setSelectionMode(QAbstractItemView::SingleSelection);
	m_list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_list->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
	m_list->setUniformItemSizes(true);
	connect(m_list, &QListWidget::itemSelectionChanged, this, &FileWidget::onListSelectionChanged);
	splitter->addWidget(m_list);

	// Right side: Chunk Widget
	m_chunkWidget = new ChunkWidget(this);
	m_chunkWidget->setProperty("bn.uiTestId", "warpFile.selectedChunk");
	m_chunkWidget->setProperty("bn.uiTestScope", "warpFile.selectedChunk");
	splitter->addWidget(m_chunkWidget);

	splitter->setSizes({100, 900});
	layout->addWidget(splitter);
}

void FileWidget::setFile(Warp::Ref<Warp::File> file)
{
	m_file = file;
	m_list->clear();
	m_chunkWidget->setChunk(nullptr);
	m_currentChunks.clear();

	if (!m_file)
		return;

	m_currentChunks = m_file->GetChunks();
	for (size_t i = 0; i < m_currentChunks.size(); ++i)
	{
		auto* listItem = new QListWidgetItem(m_list);
		listItem->setText(QString("Chunk #%1").arg(i + 1));
		// Store the chunk index in the item's data for easy retrieval
		listItem->setData(Qt::UserRole, QVariant::fromValue(static_cast<qulonglong>(i)));
	}

	if (m_list->count() > 0)
		m_list->setCurrentRow(0);
}

void FileWidget::onListSelectionChanged()
{
	auto selectedItems = m_list->selectedItems();
	if (selectedItems.isEmpty())
	{
		m_chunkWidget->setChunk(nullptr);
		return;
	}

	auto* item = selectedItems.first();
	QVariant data = item->data(Qt::UserRole);
	if (data.isValid())
	{
		size_t index = data.value<qulonglong>();
		if (index < m_currentChunks.size())
		{
			m_chunkWidget->setChunk(m_currentChunks[index]);
		}
	}
}

//
// Created by kat on 8/15/24.
//

#include "dsctriage.h"
#include "ui/fontsettings.h"
#include <QPainter>
#include <QTextBrowser>
#include "tabwidget.h"
#include "globalarea.h"
#include "progresstask.h"

#include <cmath>
#include <QMessageBox>


#define QSETTINGS_KEY_SELECTED_TAB "DSCTriage-SelectedTab"
#define QSETTINGS_KEY_TAB_LAYOUT "DSCTriage-TabLayout"
#define QSETTINGS_KEY_IMAGELOAD_TAB_LAYOUT "DSCTriage-ImageLoadTabLayout"
#define QSETTINGS_KEY_ALPHA_POPUP_SEEN "DSCTriage-AlphaPopupSeenV2"


DSCCacheBlocksView::DSCCacheBlocksView(QWidget* parent, BinaryViewRef data, Ref<SharedCacheAPI::SharedCache> cache)
	: QWidget(parent), m_data(data), m_cache(cache)
{
	setMouseTracking(true);
	m_backingCacheCount = SharedCacheAPI::SharedCache::FastGetBackingCacheCount(data);
	if (m_backingCacheCount == 0)
		return;
	m_blockLuminance.resize(m_backingCacheCount, 128);
	m_blockSizeRatios.resize(m_backingCacheCount, 1);
	m_currentProgress = m_cache->GetLoadProgress(data);
	m_targetBlockSizeForAnimation.resize(m_backingCacheCount, 0);

	m_blockWaveAnimation = Animation::create(this)
							   ->withDuration(1200)
							   ->withEasingCurve(QEasingCurve::Linear)
	->thenOnValueChanged([this](double v)
	{
		for (size_t i = 0; i < m_backingCacheCount; i++)
		{
			// Create a wave effect.
			// We use sine to create the initial wave effect, and then cube it to make it more pronounced.
			m_blockLuminance[i] = 128 + 95 * (pow((sin(v * 2 * M_PI + i * M_PI / m_backingCacheCount) + 1) / 2, 3));
		}
		update();
	})
	->thenOnEnd([this](QAbstractAnimation::Direction)
	{
		m_currentProgress = m_cache->GetLoadProgress(m_data);
		if (m_currentProgress == BNDSCViewLoadProgress::LoadProgressFinished)
		{
			m_backingCaches = m_cache->GetBackingCaches();
			m_blockExpandAnimation->start();
		}
		else
		{
			m_blockWaveAnimation->start();
		}
	});
	m_blockExpandAnimation = Animation::create(this)
								 ->withDuration(600)
								 ->withEasingCurve(QEasingCurve::InOutCirc)
	->thenOnStart([this](QAbstractAnimation::Direction)
	{
		if (m_backingCaches.size() < m_backingCacheCount)
		{
			return;
		}
		uint64_t totalSize = 0;
		uint64_t sumCountForAvg = 0;
		for (size_t i = 0; i < m_backingCacheCount; i++)
		{
		  const auto& backingCache = m_backingCaches[i];
		  double sizeSum = 0.0;

		  for (const auto& mapping : backingCache.mappings)
		  {
			  sizeSum += mapping.size;
		  }
		  m_targetBlockSizeForAnimation[i] = sizeSum;
		  totalSize += sizeSum;
		  sumCountForAvg++;
		}

		uint64_t avgSize = totalSize / sumCountForAvg;

		for (size_t i = 0; i < m_backingCacheCount; i++)
		{
			m_blockSizeRatios[i] = avgSize;
		}

		m_averageBlockSizeForAnimationInterp = avgSize;
	})
	->thenOnValueChanged([this](double v)
	{
		for (size_t i = 0; i < m_backingCacheCount; i++)
		{
			m_blockSizeRatios[i] = m_averageBlockSizeForAnimationInterp + (v/2) * (m_targetBlockSizeForAnimation[i] - ((1.0 - (v/2)) * m_averageBlockSizeForAnimationInterp));

			// Adjust luminance based on animation progress
			m_blockLuminance[i] = 128 + (63 * v);
		}
		update();
	})
	->thenOnEnd([this](QAbstractAnimation::Direction)
	{
		std::fill(m_blockLuminance.begin(), m_blockLuminance.end(), 191);
		update();
		// wait 300, somehow
		emit loadDone();
		m_selectedBlock = 0;
		m_blockAutoselectAnimation->start();
	});

	m_blockAutoselectAnimation = Animation::create(this)
	->withDuration(100)
	->withEasingCurve(QEasingCurve::InOutCirc)
	->thenOnValueChanged([this](double v){
		m_blockLuminance[0] = 191 + (64 * v);
		update();
	})
	->thenOnEnd([this](QAbstractAnimation::Direction)
	{
		if (m_backingCaches.size() == 0)
			return;
		emit selectionChanged(m_backingCaches[0], true);
	});

	m_blockWaveAnimation->setDirection(QAbstractAnimation::Backward);
	m_blockWaveAnimation->start();

}

DSCCacheBlocksView::~DSCCacheBlocksView()
{

}

void DSCCacheBlocksView::mousePressEvent(QMouseEvent* event)
{
	if (m_currentProgress != BNDSCViewLoadProgress::LoadProgressFinished
		|| m_selectedBlock == -1)
	{
		return;
	}
	int blockIndex = getBlockIndexAtPosition(event->pos());
	blockSelected(blockIndex);
	QWidget::mousePressEvent(event);
}


void DSCCacheBlocksView::mouseReleaseEvent(QMouseEvent* event)
{
	QWidget::mouseReleaseEvent(event);
}


void DSCCacheBlocksView::mouseDoubleClickEvent(QMouseEvent* event)
{
	QWidget::mouseDoubleClickEvent(event);
}


void DSCCacheBlocksView::mouseMoveEvent(QMouseEvent* event)
{
	if (m_selectedBlock == -1)
	{
		return;
	}
	uint64_t hoveredIndex = getBlockIndexAtPosition(event->pos());
	std::fill(m_blockLuminance.begin(), m_blockLuminance.end(), 191);
	if (hoveredIndex != -1)
	{
		m_blockLuminance[hoveredIndex] = 255 - 32;
	}
	m_blockLuminance[m_selectedBlock] = 255;
	update();
}


void DSCCacheBlocksView::keyPressEvent(QKeyEvent* event)
{
	QWidget::keyPressEvent(event);
}


void DSCCacheBlocksView::keyReleaseEvent(QKeyEvent* event)
{
	QWidget::keyReleaseEvent(event);
	if (m_selectedBlock == -1)
	{
		return;
	}

	// left/right arrows, inc/dec m_selectedBlock
	if (event->key() == Qt::Key_Left)
	{
		if (m_selectedBlock > 0)
		{
			blockSelected(m_selectedBlock - 1);
		}
	}
	else if (event->key() == Qt::Key_Right)
	{
		if (m_selectedBlock < m_backingCacheCount - 1)
		{
			blockSelected(m_selectedBlock + 1);
		}
	}
}


void DSCCacheBlocksView::focusInEvent(QFocusEvent* event)
{
	QWidget::focusInEvent(event);
}


void DSCCacheBlocksView::focusOutEvent(QFocusEvent* event)
{
	QWidget::focusOutEvent(event);
}


void DSCCacheBlocksView::enterEvent(QEnterEvent* event)
{
	QWidget::enterEvent(event);
}


void DSCCacheBlocksView::leaveEvent(QEvent* event)
{
	QWidget::leaveEvent(event);
}

void DSCCacheBlocksView::paintEvent(QPaintEvent* event)
{
	QPainter painter(this);
	painter.setRenderHint(QPainter::Antialiasing, true);

	// Initial X position and total width of the widget
	int totalWidth = this->width();
	int totalHeight = 30;  // Height of the rectangles
	int totalSpacing = (m_blockSizeRatios.size() - 1) * 5;
	int availableWidth = totalWidth - (50 * 2) - totalSpacing; // availableWidth minus the initial padding

	// Calculate the total ratio of block sizes
	uint64_t totalRatio = 0;
	for (const auto& ratio : m_blockSizeRatios) {
		totalRatio += ratio;
	}

	std::vector<int> originalWidths;
	originalWidths.resize(m_blockSizeRatios.size(), (availableWidth / m_blockSizeRatios.size()));


	// Calculate center points for each block
	std::vector<int> centers;
	centers.reserve(m_blockSizeRatios.size());
	int currentX = 50;
	for (size_t i = 0; i < originalWidths.size(); ++i) {
		centers.push_back(currentX + (originalWidths[i] / 2)); // Store the center point
		currentX += originalWidths[i] + 5; // Update currentX for the next block
	}

	// Now draw the blocks, adjusting the position to keep the center point constant
	currentX = 50;
	uint64_t lastBlockEnd = currentX - 5;
	for (size_t i = 0; i < m_blockSizeRatios.size(); ++i) {
		// Recalculate the width during animation
		uint64_t adjustedAvailableWidth = availableWidth * m_blockSizeRatios[i];
		int blockWidth = std::max(10, static_cast<int>(adjustedAvailableWidth / totalRatio));

		// Calculate the new X position to maintain the center
		int newX = centers[i] - (blockWidth / 2);
		if (newX > lastBlockEnd + 5)
		{
			int diff = newX - (lastBlockEnd + 5);
			newX -= diff;
			blockWidth += diff;
		}
		if (newX < lastBlockEnd + 5)
		{
			int diff = (lastBlockEnd + 5) - newX;
			newX += diff;
			blockWidth -= diff;
		}
		lastBlockEnd = newX + blockWidth;

		QRect blockRect(newX, (height() - totalHeight) / 2, blockWidth, totalHeight);
		QColor blockColor(m_blockLuminance[i], m_blockLuminance[i], m_blockLuminance[i]);
		painter.setBrush(blockColor);
		painter.setPen(blockColor);
		painter.drawRect(blockRect);

		currentX += blockWidth + 5;  // Move to the next block's position
	}
}


int DSCCacheBlocksView::getBlockIndexAtPosition(const QPoint& clickPosition)
{
	// Initial X position and total width of the widget
	int totalWidth = this->width();
	int totalHeight = 50;  // Height of the rectangles
	int totalSpacing = (m_blockSizeRatios.size() - 1) * 5;
	int availableWidth = totalWidth - (50 * 2) - totalSpacing; // availableWidth minus the initial padding

	// Calculate the total ratio of block sizes
	uint64_t totalRatio = 0;
	for (const auto& ratio : m_blockSizeRatios)
	{
		totalRatio += ratio;
	}

	// Calculate center points for each block
	std::vector<int> originalWidths;
	originalWidths.resize(m_blockSizeRatios.size(), (availableWidth / m_blockSizeRatios.size()));

	std::vector<int> centers;
	centers.reserve(m_blockSizeRatios.size());
	int currentX = 50;
	for (size_t i = 0; i < originalWidths.size(); ++i)
	{
		centers.push_back(currentX + (originalWidths[i] / 2)); // Store the center point
		currentX += originalWidths[i] + 5; // Update currentX for the next block
	}

	// Now find the block that contains the click
	currentX = 50;
	uint64_t lastBlockEnd = currentX - 5;
	for (size_t i = 0; i < m_blockSizeRatios.size(); ++i)
	{
		// Recalculate the width during animation
		uint64_t adjustedAvailableWidth = availableWidth * m_blockSizeRatios[i];
		int blockWidth = std::max(10, static_cast<int>(adjustedAvailableWidth / totalRatio));

		// Calculate the new X position to maintain the center
		int newX = centers[i] - (blockWidth / 2);
		if (newX > lastBlockEnd + 5)
		{
			int diff = newX - (lastBlockEnd + 5);
			newX -= diff;
			blockWidth += diff;
		}
		if (newX < lastBlockEnd + 5)
		{
			int diff = (lastBlockEnd + 5) - newX;
			newX += diff;
			blockWidth -= diff;
		}
		lastBlockEnd = newX + blockWidth;

		// Check if the clickPosition is inside the current block's rectangle
		QRect blockRect(newX, (height() - totalHeight) / 2, blockWidth, totalHeight);
		if (blockRect.contains(clickPosition))
		{
			return static_cast<int>(i);  // Return the index of the clicked block
		}

		currentX += blockWidth + 5;  // Move to the next block's position
	}

	return -1;  // Return -1 if no block was clicked
}


void DSCCacheBlocksView::blockSelected(int index)
{
	std::fill(m_blockLuminance.begin(), m_blockLuminance.end(), 191);
	m_selectedBlock = index;
	if (index != -1)
		m_blockLuminance[index] = 255;
	update();
	if (index != -1)
		emit selectionChanged(m_backingCaches[index], false);
}


void DSCCacheBlocksView::resizeEvent(QResizeEvent* event)
{
	QWidget::resizeEvent(event);
}


QSize DSCCacheBlocksView::sizeHint() const
{
	return QWidget::sizeHint();
}


QSize DSCCacheBlocksView::minimumSizeHint() const
{
	return QWidget::minimumSizeHint();
}


SymbolTableModel::SymbolTableModel(SymbolTableView* parent)
	: QAbstractTableModel(parent), m_parent(parent) {
}

int SymbolTableModel::rowCount(const QModelIndex& parent) const {
	Q_UNUSED(parent);
	return static_cast<int>(m_symbols.size());
}

int SymbolTableModel::columnCount(const QModelIndex& parent) const {
	Q_UNUSED(parent);
	// We have 3 columns: Address, Name, and Image
	return 3;
}

QVariant SymbolTableModel::data(const QModelIndex& index, int role) const {
	if (!index.isValid() || role != Qt::DisplayRole) {
		return QVariant();
	}

	const SharedCacheAPI::DSCSymbol& symbol = m_symbols.at(index.row());

	switch (index.column()) {
	case 0: // Address column
		return QString("0x%1").arg(symbol.address, 0, 16); // Display address as hexadecimal
	case 1: // Name column
		return QString::fromStdString(symbol.name);
	case 2: // Image column
		return QString::fromStdString(symbol.image);
	default:
		return QVariant();
	}
}

QVariant SymbolTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
		return QVariant();
	}

	switch (section) {
	case 0:
		return QString("Address");
	case 1:
		return QString("Name");
	case 2:
		return QString("Image");
	default:
		return QVariant();
	}
}

void SymbolTableModel::updateSymbols() {
	m_symbols = m_parent->m_symbols;
	setFilter(m_filter);
}

const SharedCacheAPI::DSCSymbol& SymbolTableModel::symbolAt(int row) const {
	return m_symbols.at(row);
}


void SymbolTableModel::setFilter(std::string text)
{
	beginResetModel();

	m_filter = text;
	m_symbols.clear();

	if (m_filter.empty())
	{
		m_symbols = m_parent->m_symbols;
	}
	else
	{
		m_symbols.reserve(m_parent->m_symbols.size());
		for (const auto& symbol : m_parent->m_symbols)
		{
			if (symbol.name.find(m_filter) != std::string::npos)
			{
				m_symbols.push_back(symbol);
			}
		}
		m_symbols.shrink_to_fit();
	}

	endResetModel();
}


SymbolTableView::SymbolTableView(QWidget* parent, Ref<SharedCacheAPI::SharedCache> cache)
	: m_model(new SymbolTableModel(this)) {

	// Set up the filter model
	setModel(m_model);

	// Configure view settings
	horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);

	BackgroundThread::create(this)->thenBackground([this, cache=cache](){
		// LogInfo("Symbol Search: Loading symbols...");
		m_symbols = cache->LoadAllSymbolsAndWait();
		// LogInfo("Symbol Search: Loaded 0x%zx symbols", m_symbols.size());
	})->thenMainThread([this](){
		m_model->updateSymbols();
	})->start();
}

SymbolTableView::~SymbolTableView() {
	delete m_model;
}

void SymbolTableView::setFilter(const std::string& filter) {
	m_model->setFilter(filter);
}


DSCTriageView::DSCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), View(), m_data(data), m_cache(new SharedCacheAPI::SharedCache(data))
{
	setBinaryDataNavigable(false);
	setupView(this);

	m_triageCollection = new DockableTabCollection();
	m_triageTabs = new SplitTabWidget(m_triageCollection);

	auto triageTabStyle = new GlobalAreaTabStyle();
	m_triageTabs->setTabStyle(triageTabStyle);

	auto cacheInfoWidget = new QWidget;
	auto cacheInfoLayout = new QVBoxLayout(cacheInfoWidget);

	QSplitter* containerWidget = new QSplitter;
	containerWidget->setOrientation(Qt::Vertical);

	DSCCacheBlocksView* cacheBlocksView = new DSCCacheBlocksView(containerWidget, data, m_cache);
	cacheBlocksView->setMinimumHeight(60);

	auto cacheInfo = new CollapsibleSection(this);
	cacheInfo->setTitle(QString::fromStdString(data->GetFile()->GetOriginalFilename().substr(data->GetFile()->GetOriginalFilename().find_last_of('/') + 1)));

	auto cacheInfoSubwidget = new QWidget;

	auto mappingTable = new QTableView(cacheInfoSubwidget);
	auto mappingModel = new QStandardItemModel(0, 3, mappingTable);
	mappingModel->setHorizontalHeaderLabels({"VM Address", "File Address", "Size"});

	mappingTable->setModel(mappingModel);

	mappingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
	mappingTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
	mappingTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

	auto sectionTable = new QTableView(cacheInfoSubwidget);
	auto sectionModel = new QStandardItemModel(0, 3, sectionTable);
	sectionModel->setHorizontalHeaderLabels({"Name", "VM Address", "Size"});

	sectionTable->setModel(sectionModel);

	sectionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
	sectionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
	sectionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

	auto mappingLabel = new QLabel("Mappings");
	auto sectionLabel = new QLabel("Sections");

	auto mappingLayout = new QVBoxLayout;
	mappingLayout->addWidget(mappingLabel);
	mappingLayout->addWidget(mappingTable);

	auto sectionLayout = new QVBoxLayout;
	sectionLayout->addWidget(sectionLabel);
	sectionLayout->addWidget(sectionTable);

	cacheInfoLayout->addLayout(mappingLayout);
	cacheInfoLayout->addLayout(sectionLayout);

	cacheInfo->setContentWidget(cacheInfoSubwidget);

	cacheInfo->setMinimumHeight(170);

	connect(cacheBlocksView, &DSCCacheBlocksView::selectionChanged, [this, sectionModel, cacheInfo, cacheInfoWidget, mappingModel](const SharedCacheAPI::BackingCache& index, bool _auto)
	{
		if (!_auto)
			m_triageTabs->selectWidget(cacheInfoWidget);
		mappingModel->removeRows(0, mappingModel->rowCount());
		sectionModel->removeRows(0, sectionModel->rowCount());
		auto basename = index.path.substr(index.path.find_last_of('/') + 1);
		cacheInfo->setTitle(QString::fromStdString(basename));
		size_t sizeInBits = 0;
		for (const auto& mapping : index.mappings)
		{
			sizeInBits += mapping.size;
			mappingModel->appendRow({
				new QStandardItem(QString("0x%1").arg(mapping.vmAddress, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.fileOffset, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.size, 0, 16))});
		}

		for (const auto& header : m_headers)
		{
			uint64_t i = 0;
			for (const auto& section : header.sections)
			{
				for (const auto& mapping : index.mappings)
				{
					if (section.addr >= mapping.vmAddress && section.addr < mapping.vmAddress + mapping.size)
					{
						sectionModel->appendRow({
							new QStandardItem(QString::fromStdString(header.sectionNames[i])),
							new QStandardItem(QString("0x%1").arg(section.addr, 0, 16)),
							new QStandardItem(QString("0x%1").arg(section.size, 0, 16))});
						break;
					}
				}
				i++;
			}
			continue;
		}

		std::string sizeStr;
		if (sizeInBits < 1024)
		{
			sizeStr = std::to_string(sizeInBits) + " B";
		}
		else if (sizeInBits < 1024 * 1024)
		{
			sizeStr = std::to_string(sizeInBits / 1024) + " KB";
		}
		else if (sizeInBits < 1024 * 1024 * 1024)
		{
			sizeStr = std::to_string(sizeInBits / (1024 * 1024)) + " MB";
		}
		else
		{
			sizeStr = std::to_string(sizeInBits / (1024 * 1024 * 1024)) + " GB";
		}

		cacheInfo->setSubtitleRight(QString::fromStdString(sizeStr));
	});

	containerWidget->addWidget(cacheInfo);

	QWidget* defaultWidget = nullptr;

	m_bottomRegionCollection = new DockableTabCollection();
	m_bottomRegionTabs = new SplitTabWidget(m_bottomRegionCollection);
	m_bottomRegionTabs->setTabStyle(new GlobalAreaTabStyle());

	auto loadImageTable = new FilterableTableView;
	{
		auto loadImageModel = new QStandardItemModel(0, 2, loadImageTable);
		{
			connect(
				cacheBlocksView, &DSCCacheBlocksView::loadDone, [this, loadImageModel]()
				{
					for (const auto& img : m_cache->GetImages())
					{
						if (auto header = m_cache->GetMachOHeaderForAddress(img.headerAddress); header)
						{
							m_headers.push_back(*header);
						}
						loadImageModel->appendRow({
							new QStandardItem(QString::fromStdString(img.name)),
							new QStandardItem(QString("0x%1").arg(img.headerAddress, 0, 16))});
					}
				});
			loadImageModel->setHorizontalHeaderLabels({"Name", "VM Address"});
		} // loadImageModel

		auto loadImageButton = new CustomStyleFlatPushButton();
		{
			connect(loadImageButton, &QPushButton::clicked,
				[this, loadImageTable](bool) {
					auto selected = loadImageTable->selectionModel()->selectedRows();
					if (selected.size() == 0)
					{
						return;
					}

					auto name = selected[0].data().toString().toStdString();
					WorkerPriorityEnqueue([this, name]() { m_cache->LoadImageWithInstallName(name); });
				});
			loadImageButton->setText("Load");

			loadImageButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
			loadImageButton->setMinimumWidth(100);
			loadImageButton->setMinimumHeight(30);

		} // loadImageButton
		loadImageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

		auto loadImageFilterEdit = new FilterEdit(loadImageTable);
		{
			connect(loadImageFilterEdit, &FilterEdit::textChanged, [loadImageTable](const QString& filter) {
				loadImageTable->setFilter(filter.toStdString());
			});
		} // loadImageFilterEdit

		connect(loadImageTable, &FilterableTableView::activated, this, [=](const QModelIndex& index)
			{
				auto name = loadImageModel->item(index.row(), 0)->text().toStdString();
				WorkerPriorityEnqueue([this, name]()
					{
						m_cache->LoadImageWithInstallName(name);
					});
			});
		connect(loadImageTable, &FilterableTableView::doubleClicked, this, [=](const QModelIndex& index)
			{
				auto name = loadImageModel->item(index.row(), 0)->text().toStdString();
				WorkerPriorityEnqueue([this, name]()
					{
						m_cache->LoadImageWithInstallName(name);
					});
			});

		auto loadImageLayout = new QVBoxLayout;
		loadImageLayout->addWidget(loadImageFilterEdit);
		loadImageLayout->addWidget(loadImageTable);
		loadImageLayout->addWidget(loadImageButton);

		auto loadImageWidget = new QWidget;
		loadImageWidget->setLayout(loadImageLayout);

		m_bottomRegionTabs->addTab(loadImageWidget, "Load an Image");

		loadImageTable->setModel(loadImageModel);

		loadImageTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
		loadImageTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

		loadImageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
		loadImageTable->setSelectionMode(QAbstractItemView::SingleSelection);

		m_triageTabs->addTab(loadImageWidget, "Images");
		defaultWidget = loadImageWidget;
		m_triageTabs->setCanCloseTab(loadImageWidget, false);
	} // loadImageTable

	auto symbolSearch = new SymbolTableView(this, m_cache);
	{
		auto symbolFilterEdit = new FilterEdit(symbolSearch);
		{
			connect(symbolFilterEdit, &FilterEdit::textChanged, [symbolSearch](const QString& filter) {
				symbolSearch->setFilter(filter.toStdString());
			});
		}

		auto symbolLayout = new QVBoxLayout;
		symbolLayout->addWidget(symbolFilterEdit);
		symbolLayout->addWidget(symbolSearch);

		auto symbolWidget = new QWidget;
		symbolWidget->setLayout(symbolLayout);

		symbolSearch->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents); // Address
		symbolSearch->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);          // Name
		symbolSearch->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);          // Image

		symbolSearch->setSelectionBehavior(QAbstractItemView::SelectRows);
		symbolSearch->setSelectionMode(QAbstractItemView::SingleSelection);

		connect(symbolSearch, &SymbolTableView::activated, this, [=](const QModelIndex& index)
			{
				auto symbol = symbolSearch->getSymbolAtRow(index.row());
				auto dialog = new QMessageBox(this);
				dialog->setText("Load " + QString::fromStdString(symbol.image) + "?");
				dialog->setStandardButtons(QMessageBox::Yes | QMessageBox::No);

				connect(dialog, &QMessageBox::buttonClicked, this, [=](QAbstractButton* button)
				{
					if (button == dialog->button(QMessageBox::Yes))
					{
						WorkerPriorityEnqueue([this, symbol]()
						{
							m_cache->LoadImageWithInstallName(symbol.image);
						});
					}
				});
				dialog->exec();
			});

		m_triageTabs->addTab(symbolWidget, "Symbol Search");
		m_triageTabs->setCanCloseTab(symbolWidget, false);
	} // symbolSearch

	auto loadedRegions = new QTreeView;
	{
		auto loadedRegionsModel = new QStandardItemModel(0, 3, loadedRegions);
		loadedRegionsModel->setHorizontalHeaderLabels({"VM Address", "Size", "Pretty Name"});

		auto loadedRegionsLayout = new QVBoxLayout;
		loadedRegionsLayout->addWidget(loadedRegions);

		auto loadedRegionsWidget = new QWidget;
		loadedRegionsWidget->setLayout(loadedRegionsLayout);

		loadedRegions->setModel(loadedRegionsModel);

		loadedRegions->header()->setSectionResizeMode(QHeaderView::Stretch);

		loadedRegions->setSelectionBehavior(QAbstractItemView::SelectRows);
		loadedRegions->setSelectionMode(QAbstractItemView::SingleSelection);

		connect(loadedRegions, &QTreeView::doubleClicked, this, [=](const QModelIndex& index)
			{
				auto addr = loadedRegionsModel->item(index.row(), 0)->text().toULongLong(nullptr, 16);
			});

		connect(loadedRegions, &QTreeView::activated, this, [=](const QModelIndex& index)
			{
				auto addr = loadedRegionsModel->item(index.row(), 0)->text().toULongLong(nullptr, 16);
			});

		// m_triageTabs->addTab(loadedRegionsWidget, "Loaded Regions");
	} // loadedRegions

	m_triageTabs->addTab(cacheInfoWidget, "Cache Info");
	m_triageTabs->setCanCloseTab(cacheInfoWidget, false);

	// check for alpha popup qsetting
	QSettings settings;

	QTextBrowser *tb = new QTextBrowser(this);
	{
		tb->setOpenExternalLinks(true);
		auto alphaHtml =
			R"(
<h1>Dyld Shared Cache Alpha</h1>

<p> This is an experimental alpha release of the dyld shared cache view! We are hard at work improving this and adding features, but we wanted
to make it available for users to experiment with as soon as possible. </p>

<h2> Platforms </h2>
<dl>
	<dt> iOS 11-17 </dt><dd> Full Support </dd>
	<dt> iOS 18 </dt><dd> Partial support, may experience issues -- specifically, Objective-C optimization parsing is not implemented </dd>
	<dt> macOS x86/arm64e </dt><dd> Partial support, may experience issues </dd>
</dl>

<p> iOS parsing should work fairly well for now. macOS parsing should be usable, but both are still a work in progress. </p>
<h2> Getting the latest version of the plugin </h2>
<p> We frequently release "dev" builds which will contain the latest version of the dyld shared cache plugin (and many other things). </p>
<p> You can find instructions on how to install these builds <a href="https://docs.binary.ninja/guide/index.html#development-branch">here</a>. </p>

<h3> Reading / building the source </h3>
<p> Like most of our platforms, architectures, debug information parsing, and the entire API and documentation, this plugin is open source. </p>
<p> You can read the source and find instructions for building it <a href="https://github.com/Vector35/binaryninja-api/tree/dev/view/sharedcache">here</a>. </p>
<p> Contributions are always welcome! </p>
)";
		tb->setHtml(alphaHtml);

		m_triageTabs->addTab(tb, "Dyld Shared Cache Alpha");
		m_triageTabs->setCanCloseTab(tb, false);

	}
	if (!(settings.contains(QSETTINGS_KEY_ALPHA_POPUP_SEEN) && settings.value(QSETTINGS_KEY_ALPHA_POPUP_SEEN).toBool()))
	{
		LogAlert("dyld_shared_cache support is highly experimental! We do not expect it to work on all versions yet! See the 'Dlyd Shared Cache Alpha' tab in the DSCTriage view for more information. ");
		settings.setValue(QSETTINGS_KEY_ALPHA_POPUP_SEEN, true);
		defaultWidget = tb;
	}

	containerWidget->addWidget(m_bottomRegionTabs);

	m_layout = new QVBoxLayout(this);
	m_layout->addWidget(cacheBlocksView);
	m_layout->addWidget(m_triageTabs);
	setLayout(m_layout);

	m_triageTabs->selectWidget(defaultWidget);
}


QFont DSCTriageView::getFont()
{
	return getMonospaceFont(this);
}


BinaryViewRef DSCTriageView::getData()
{
	return m_data;
}


bool DSCTriageView::navigate(uint64_t offset)
{
	return true;
}


uint64_t DSCTriageView::getCurrentOffset()
{
	return 0;
}


CollapsibleSection::CollapsibleSection(QWidget* parent)
	: QWidget(parent)
{
	auto layout = new QVBoxLayout(this);
	{
		layout->setContentsMargins(0, 0, 0, 0);

		auto hLayout = new QHBoxLayout;
		{
			hLayout->setContentsMargins(0, 0, 0, 0);

			m_titleLabel = new QLabel;
			m_titleLabel->setStyleSheet("font-weight: bold; font-size: 16px;");
			hLayout->addWidget(m_titleLabel, 1);

			m_subtitleRightLabel = new QLabel;
			m_subtitleRightLabel->setStyleSheet("font-size: 12px;");
			hLayout->addWidget(m_subtitleRightLabel);

			m_collapseButton = new CustomStyleFlatPushButton;
			m_collapseButton->setFlat(true);
			m_collapseButton->setCheckable(true);
		}

		layout->addLayout(hLayout);
	}

	m_contentWidgetContainer = new QWidget;
	{
		layout->addWidget(m_contentWidgetContainer);
		new QVBoxLayout(m_contentWidgetContainer);
	}

}


void CollapsibleSection::setTitle(const QString& title)
{
	m_titleLabel->setText(title);
}


void CollapsibleSection::setSubtitleRight(const QString& subtitle)
{
	m_subtitleRightLabel->setVisible(subtitle != "");
	m_subtitleRightLabel->setText(subtitle);
}


void CollapsibleSection::setContentWidget(QWidget* contentWidget)
{
	m_contentWidget = contentWidget;
	m_contentWidgetContainer->layout()->addWidget(contentWidget);
}


QSize CollapsibleSection::sizeHint() const
{
	return QWidget::sizeHint();
}


void CollapsibleSection::setCollapsed(bool collapsed, bool animated)
{
	if (collapsed == m_collapsed)
	{
		return;
	}

	m_collapsed = collapsed;

	if (m_collapsed)
	{
		m_contentWidget->hide();
	}
	else
	{
		m_contentWidget->show();
	}

	if (animated)
	{
		m_onContentAddedAnimation->start();
	}
}


DSCTriageViewType::DSCTriageViewType()
	: ViewType("DSCTriage", "Dyld Shared Cache Triage")
{

}


int DSCTriageViewType::getPriority(BinaryViewRef data, const QString& filename)
{
	if (data->GetTypeName() == VIEW_NAME)
	{
		return 100;
	}
	return 1;
}


QWidget* DSCTriageViewType::create(BinaryViewRef data, ViewFrame* viewFrame)
{
	if (data->GetTypeName() != VIEW_NAME)
	{
		return nullptr;
	}
	if (SharedCacheAPI::SharedCache::FastGetBackingCacheCount(data) == 0)
	{
		return nullptr;
	}
	return new DSCTriageView(viewFrame, data);
}


void DSCTriageViewType::Register()
{
	ViewType::registerViewType(new DSCTriageViewType());
}

#include <QMessageBox>
#include <QPainter>
#include <cmath>
#include "globalarea.h"
#include "kctriage.h"
#include "ui/fontsettings.h"

using namespace BinaryNinja;
using namespace KernelCacheAPI;


KCTriageViewType::KCTriageViewType()
	: ViewType("KCTriage", "Kernel Cache Triage")
{}


int KCTriageViewType::getPriority(BinaryViewRef data, const QString& filename)
{
	if (data->GetTypeName() == KC_VIEW_NAME)
		return 100;
	return 0;
}


QWidget* KCTriageViewType::create(BinaryViewRef data, ViewFrame* viewFrame)
{
	if (data->GetTypeName() != KC_VIEW_NAME)
		return nullptr;
	return new KCTriageView(viewFrame, data);
}


void KCTriageViewType::Register()
{
	registerViewType(new KCTriageViewType());
}


KCTriageView::KCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), View(), m_data(data), m_cache(new KernelCache(data))
{
	setBinaryDataNavigable(false);
	setupView(this);

	UIContext::registerNotification(this);

	m_triageCollection = new DockableTabCollection();
	m_triageTabs = new SplitTabWidget(m_triageCollection);

	auto triageTabStyle = new GlobalAreaTabStyle();
	m_triageTabs->setTabStyle(triageTabStyle);

	QWidget* defaultWidget = initImageTable();
	initSymbolTable();

	m_layout = new QVBoxLayout(this);
	m_layout->addWidget(m_triageTabs);
	setLayout(m_layout);

	m_triageTabs->selectWidget(defaultWidget);
}


KCTriageView::~KCTriageView()
{
	UIContext::unregisterNotification(this);
}


void KCTriageView::loadImagesWithAddr(const std::vector<uint64_t>& addresses) {
	if (!m_cache)
		return;

	std::map<uint64_t, std::string> images;
	for (const uint64_t& addr : addresses)
	{
		auto imageName = m_cache->GetImageNameForAddress(addr);
		if (!imageName.empty() && !m_cache->IsImageLoaded(addr))
		{
			images.insert({addr, imageName});
		}
	}

	// Don't create a worker action if we don't have any images.
	if (images.empty())
		return;

	WorkerPriorityEnqueue([this, images]() {
		size_t loadedImages = 0;
		const std::string initialLoad = fmt::format("Loading images... (0/{})", images.size());
		auto imageLoadTask = BackgroundTask(initialLoad, true);

		for (const auto& [addr, imageName] : images)
		{
			if (imageLoadTask.IsCancelled())
				break;
			std::string newLoad = fmt::format("Loading images... ({}/{})", loadedImages++, images.size());
			imageLoadTask.SetProgressText(newLoad);
			if (m_cache->LoadImageWithInstallName(imageName))
				setImageLoaded(addr);
		}
		imageLoadTask.Finish();

		// We have loaded images, lets make sure to update analysis!
		this->m_data->AddAnalysisOption("linearsweep");
		this->m_data->UpdateAnalysis();
	});
}


void KCTriageView::setImageLoaded(const uint64_t imageHeaderAddr)
{
	// Go through the m_imageModel and find the image associated with the address
	// then set the image as loaded.
	for (int i = 0; i < m_imageModel->rowCount(); i++)
	{
		auto addrCol = m_imageModel->index(i, 0);
		const auto addr = addrCol.data().toString().toULongLong(nullptr, 16);
		if (addr == imageHeaderAddr)
		{
			auto statusCol = m_imageModel->index(i, 1);
			// See the `LoadedDelegate` class, we set 1 to indicate that this image is loaded.
			m_imageModel->setData(statusCol, "1", Qt::DisplayRole);
			break;
		}
	}
}


QWidget* KCTriageView::initImageTable()
{
	m_imageTable = new FilterableTableView(this);

	m_imageModel = new QStandardItemModel(0, 3, m_imageTable);
	m_imageModel->setHorizontalHeaderLabels({"VM Address", "Loaded", "Name"});

	// Apply custom column styling
	m_imageTable->setItemDelegateForColumn(0, new AddressColorDelegate(m_imageTable));
	m_imageTable->setItemDelegateForColumn(1, new LoadedDelegate(m_imageTable));

	// Context menu
	m_imageTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_imageTable, &QWidget::customContextMenuRequested, [this](const QPoint &pos) {
		QMenu contextMenu(tr("Load Image Actions"), m_imageTable);

		// Get number of selected images
		auto selected = m_imageTable->selectionModel()->selectedRows();
		int selectedCount = 0;
		std::vector<uint64_t> addresses;
		for (const auto& idx : selected)
		{
			// Skip rows hidden by the filter
			if (m_imageTable->isRowHidden(idx.row()))
				continue;
			addresses.push_back(idx.data().toString().toULongLong(nullptr, 16));
			selectedCount++;
		}

		QAction noSelectionAction("No Images Selected", m_imageTable);
		QAction loadImagesAction("", m_imageTable);
		if (selectedCount == 0)
		{
			noSelectionAction.setEnabled(false);
			contextMenu.addAction(&noSelectionAction);
		}
		else
		{
			// Format action text for loading selected images
			QString loadActionText = (selectedCount == 1) ? "Load Selected Image" : QString("Load %1 Selected Images").arg(selectedCount);
			loadImagesAction.setText(loadActionText);
			connect(&loadImagesAction, &QAction::triggered, [this, addresses]() {
				loadImagesWithAddr(addresses);
			});
			contextMenu.addAction(&loadImagesAction);
		}

		contextMenu.exec(m_imageTable->viewport()->mapToGlobal(pos));
	});

	BackgroundThread::create(m_imageTable)->thenBackground([this](const QVariant var) {
		QVariantList rows;

		auto images = m_cache->GetImages();

		auto newHeaders = std::make_shared<std::vector<KernelCacheMachOHeader>>();
		newHeaders->reserve(images.size());

		for (const auto& img : images)
		{
			if (auto header = m_cache->GetMachOHeaderForImage(img.name); header)
			{
				newHeaders->push_back(*header);
				rows.push_back(QList<QVariant>{
					QString("0x%1").arg(header->textBase, 0, 16),
					QString(""),
					QString::fromStdString(img.name)
				});
			}
		}

		std::unique_lock<std::mutex> lock(m_headersMutex);
		m_headers.swap(newHeaders);

		return QVariant(rows);
	})->thenMainThread([this](const QVariant var) {
		QVariantList rows = var.toList();

		if (m_imageModel->rowCount() > 0)
			m_imageModel->removeRows(0, m_imageModel->rowCount());

		for (const QVariant &rowVariant : rows) {
			QVariantList row = rowVariant.toList();

			QList<QStandardItem*> items;
			for (const QVariant &cellValue : row)
				items.append(new QStandardItem(cellValue.toString()));

			m_imageModel->appendRow(items);
			m_imageTable->resizeColumnsToContents();
		}
	})->start();

	auto loadImageButton = new QPushButton();
	connect(loadImageButton, &QPushButton::clicked, [this](bool) {
		// Collect only visible selected rows
		QModelIndexList selected;
		for (const auto& index : m_imageTable->selectionModel()->selectedRows()) {
			if (!m_imageTable->isRowHidden(index.row())) {
				selected.append(index);
			}
		}

		if (selected.empty())
			return;

		std::vector<uint64_t> addresses;
		for (const auto& idx : selected)
			addresses.push_back(idx.data().toString().toULongLong(nullptr, 16));
		loadImagesWithAddr(addresses);
	});
	loadImageButton->setText(" Load Selected ");

	auto loadImageFilterEdit = new FilterEdit(m_imageTable);
	connect(loadImageFilterEdit, &FilterEdit::textChanged, [this](const QString& filter) {
		m_imageTable->setFilter(filter.toStdString());
	});

	connect(m_imageTable, &FilterableTableView::activated, this, [=](const QModelIndex& index) {
		auto addr = m_imageModel->item(index.row(), 0)->text().toULongLong(nullptr, 16);
		loadImagesWithAddr({addr});
	});

	auto loadImageLayout = new QVBoxLayout;
	loadImageLayout->addWidget(loadImageFilterEdit);
	loadImageLayout->addWidget(m_imageTable);

	auto loadImageFooterLayout = new QHBoxLayout;
	loadImageFooterLayout->addWidget(loadImageButton);
	loadImageFooterLayout->setAlignment(Qt::AlignLeft);
	loadImageLayout->addLayout(loadImageFooterLayout);

	auto loadImageWidget = new QWidget;
	loadImageWidget->setLayout(loadImageLayout);

	m_imageTable->setModel(m_imageModel);

	m_imageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

	m_imageTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
	m_imageTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
	m_imageTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

	m_imageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_imageTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

	m_imageTable->setSortingEnabled(true);

	m_imageTable->verticalHeader()->setVisible(false);

	m_triageTabs->addTab(loadImageWidget, "Images");
	m_triageTabs->setCanCloseTab(loadImageWidget, false);

	return loadImageWidget; // For use as the default widget
}


void KCTriageView::initSymbolTable()
{
	m_symbolTable = new SymbolTableView(this, m_cache);

	auto symbolFilterEdit = new FilterEdit(m_symbolTable);
	connect(symbolFilterEdit, &FilterEdit::textChanged, [this](const QString& filter) {
		m_symbolTable->setFilter(filter.toStdString());
	});

	auto loadSymbolImageButton = new QPushButton();
	connect(loadSymbolImageButton, &QPushButton::clicked, [this](bool) {
		auto selected = m_symbolTable->selectionModel()->selectedRows();
		std::vector<uint64_t> addresses;
		for (const auto& row : selected)
			addresses.push_back(row.data().toString().toULongLong(nullptr, 16));
		loadImagesWithAddr(addresses);
	});
	loadSymbolImageButton->setText("Load Image");

	// Shows the current selected rows image name.
	auto currentImageLabel = new QLabel(this);
	currentImageLabel->setText("");
	currentImageLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	connect(m_symbolTable->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [this, currentImageLabel](const QModelIndex &current, const QModelIndex &) {
		auto symbol = m_symbolTable->getSymbolAtRow(current.row());
		auto imageName = m_cache->GetImageNameForAddress(symbol.address);
		currentImageLabel->setText("Image: " + QString::fromStdString(imageName));
	});

	auto symbolFooterLayout = new QHBoxLayout;
	symbolFooterLayout->addWidget(loadSymbolImageButton);
	symbolFooterLayout->addWidget(currentImageLabel);
	symbolFooterLayout->setAlignment(Qt::AlignLeft);

	auto symbolLayout = new QVBoxLayout;
	symbolLayout->addWidget(symbolFilterEdit);
	symbolLayout->addWidget(m_symbolTable);
	symbolLayout->addLayout(symbolFooterLayout);

	auto symbolWidget = new QWidget;
	symbolWidget->setLayout(symbolLayout);

	std::function<void(uint64_t)> navigateToAddress = [=](uint64_t addr) {
		ExecuteOnMainThread([addr, this](){
			if (Settings::Instance()->Get<bool>("ui.view.graph.preferred"))
				m_data->Navigate("Graph:KCView", addr);
			else
				m_data->Navigate("Linear:KCView", addr);
		});
	};

	connect(m_symbolTable, &SymbolTableView::activated, this, [=](const QModelIndex& index)
	{
		auto symbol = m_symbolTable->getSymbolAtRow(index.row());
		WorkerPriorityEnqueue([this, symbol, navigateToAddress]() {
			if (m_data->IsValidOffset(symbol.address))
				navigateToAddress(symbol.address);
			else
			{
				m_cache->LoadImageWithInstallName(symbol.image);
				navigateToAddress(symbol.address);
			}
		});
	});

	m_triageTabs->addTab(symbolWidget, "Symbols");
	m_triageTabs->setCanCloseTab(symbolWidget, false);
}


QFont KCTriageView::getFont()
{
	return getMonospaceFont(this);
}


BinaryViewRef KCTriageView::getData()
{
	return m_data;
}


bool KCTriageView::navigate(uint64_t offset)
{
	return false;
}


uint64_t KCTriageView::getCurrentOffset()
{
	return 0;
}

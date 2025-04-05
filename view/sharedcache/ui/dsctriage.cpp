//
// Created by kat on 8/15/24.
//

#include "ui/fontsettings.h"
#include "tabwidget.h"
#include "globalarea.h"
#include "progresstask.h"
#include <QMessageBox>
#include <QHeaderView>
#include "dsctriage.h"
#include "symboltable.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

DSCTriageViewType::DSCTriageViewType()
	: ViewType("DSCTriage", "Dyld Shared Cache Triage")
{}

int DSCTriageViewType::getPriority(BinaryViewRef data, const QString& filename)
{
	if (data->GetTypeName() == VIEW_NAME)
		return 100;
	return 0;
}

QWidget* DSCTriageViewType::create(BinaryViewRef data, ViewFrame* viewFrame)
{
	if (data->GetTypeName() != VIEW_NAME)
		return nullptr;
	// TODO: Check for dyld start. Then continue.
	return new DSCTriageView(viewFrame, data);
}

void DSCTriageViewType::Register()
{
	registerViewType(new DSCTriageViewType());
}

DSCTriageView::DSCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), m_data(data)
{
	setBinaryDataNavigable(false);
	setupView(this);

	UIContext::registerNotification(this);

	m_triageCollection = new DockableTabCollection();
	m_triageTabs = new SplitTabWidget(m_triageCollection);

	auto triageTabStyle = new GlobalAreaTabStyle();
	m_triageTabs->setTabStyle(triageTabStyle);

	QWidget* defaultWidget = nullptr;

	auto loadImagesWithAddr = [this](const std::vector<uint64_t>& addresses, bool includeDependencies = false) {
		auto controller = SharedCacheController::GetController(*this->m_data);
		if (!controller)
			return;

		std::map<uint64_t, CacheImage> images = {};
		for (const uint64_t& addr : addresses)
		{
			auto image = controller->GetImageContaining(addr);
			// Only try to load if we have not already.
			if (image.has_value() && !controller->IsImageLoaded(*image))
			{
				images.insert({image->headerAddress, *image});

				// TODO: We currently only add direct dependencies, may want to make the depth configurable?
				if (includeDependencies)
				{
					auto dependencies = controller->GetImageDependencies(*image);
					for (const auto& depName : dependencies)
					{
						auto depImage = controller->GetImageWithName(depName);
						if (depImage.has_value() && !controller->IsImageLoaded(*depImage))
						{
							images.insert({depImage->headerAddress, *depImage});
						}
					}
				}
			}

		}

		// Don't create a worker action if we don't have any images.
		if (images.empty())
			return;

		WorkerPriorityEnqueue([controller, this, images]() {
			size_t loadedImages = 0;
			const std::string initialLoad = fmt::format("Loading images... (0/{})", images.size());
			auto imageLoadTask = BackgroundTask(initialLoad, true);

			for (const auto& [addr, image] : images)
			{
				if (imageLoadTask.IsCancelled())
					break;
				std::string newLoad = fmt::format("Loading images... ({}/{})", loadedImages++, images.size());
				imageLoadTask.SetProgressText(newLoad);
				if (controller->ApplyImage(*this->m_data, image))
					setImageLoaded(image.headerAddress);
			}
			imageLoadTask.Finish();

			// We have loaded images, lets make sure to update analysis!
			this->m_data->AddAnalysisOption("linearsweep");
			this->m_data->UpdateAnalysis();
		});
	};

	// Tab: Images
	auto loadImageTable = new FilterableTableView(this);
	{
		m_imageModel = new QStandardItemModel(0, 3, loadImageTable);
		m_imageModel->setHorizontalHeaderLabels({"Address", "Loaded", "Name"});

		// Apply custom column styling
		loadImageTable->setItemDelegateForColumn(0, new AddressColorDelegate(loadImageTable));
		loadImageTable->setItemDelegateForColumn(1, new LoadedDelegate(loadImageTable));

		// Context menu
		loadImageTable->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(loadImageTable, &QWidget::customContextMenuRequested, [loadImageTable, loadImagesWithAddr](const QPoint &pos) {
			QMenu contextMenu(tr("Load Image Actions"), loadImageTable);

			// Get number of selected images
			auto selected = loadImageTable->selectionModel()->selectedRows();
			int selectedCount = 0;
			std::vector<uint64_t> addresses;
			for (const auto& idx : selected)
			{
				// Skip rows hidden by the filter
				if (loadImageTable->isRowHidden(idx.row()))
					continue;
				addresses.push_back(idx.data().toString().toULongLong(nullptr, 16));
				selectedCount++;
			}

			QAction noSelectionAction("No Images Selected", loadImageTable);
			QAction loadImagesAction("", loadImageTable);
			QAction loadImagesWithDepsAction("", loadImageTable);
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
				connect(&loadImagesAction, &QAction::triggered, [loadImagesWithAddr, addresses]() {
					loadImagesWithAddr(addresses, false);
				});
				contextMenu.addAction(&loadImagesAction);

				// Format action text for loading selected images with dependencies
				QString loadWithDepsActionText = (selectedCount == 1) ? "Load Selected Image and Dependencies" : QString("Load %1 Selected Images and Dependencies").arg(selectedCount);
				loadImagesWithDepsAction.setText(loadWithDepsActionText);
				connect(&loadImagesWithDepsAction, &QAction::triggered, [loadImagesWithAddr, addresses]() {
					loadImagesWithAddr(addresses, true);
				});
				contextMenu.addAction(&loadImagesWithDepsAction);
			}

			contextMenu.exec(loadImageTable->viewport()->mapToGlobal(pos));
		});

		auto loadImageButton = new QPushButton();
		connect(loadImageButton, &QPushButton::clicked,
			[loadImageTable, loadImagesWithAddr](bool) {
				auto selected = loadImageTable->selectionModel()->selectedRows();
				std::vector<uint64_t> addresses;
				for (const auto& idx : selected)
				{
					// Skip rows hidden by the filter
					if (loadImageTable->isRowHidden(idx.row()))
						continue;
					addresses.push_back(idx.data().toString().toULongLong(nullptr, 16));
				}
				loadImagesWithAddr(addresses);
			});
		loadImageButton->setText("Load Selected");

		auto refreshDataButton = new QPushButton();
		{
			// TODO: Might want to introduce a cooldown for this button (if we even keep it)
			connect(refreshDataButton, &QPushButton::clicked, [this](bool) { RefreshData(); });
			refreshDataButton->setText("Refresh");
		} // refreshDataButton

		auto loadImageFilterEdit = new FilterEdit(loadImageTable);
		connect(loadImageFilterEdit, &FilterEdit::textChanged, [loadImageTable](const QString& filter) {
			loadImageTable->setFilter(filter.toStdString());
		});

		connect(loadImageTable, &FilterableTableView::activated, this, [=](const QModelIndex& index) {
			auto addr = m_imageModel->item(index.row(), 0)->text().toULongLong(nullptr, 16);
			loadImagesWithAddr({addr});
		});

		auto loadImageLayout = new QVBoxLayout;
		loadImageLayout->addWidget(loadImageFilterEdit);
		loadImageLayout->addWidget(loadImageTable);
		auto buttonLayout = new QHBoxLayout;
		buttonLayout->addWidget(loadImageButton);
		buttonLayout->addWidget(refreshDataButton);
		buttonLayout->setAlignment(Qt::AlignLeft);
		loadImageLayout->addLayout(buttonLayout);

		auto loadImageWidget = new QWidget;
		loadImageWidget->setLayout(loadImageLayout);

		loadImageTable->setModel(m_imageModel);

		loadImageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

		loadImageTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
		loadImageTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
		loadImageTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

		loadImageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
		loadImageTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

		loadImageTable->setSortingEnabled(true);

		loadImageTable->verticalHeader()->setVisible(false);

		m_triageTabs->addTab(loadImageWidget, "Images");
		defaultWidget = loadImageWidget;
		m_triageTabs->setCanCloseTab(loadImageWidget, false);
	} // loadImageTable

	// Tab: Symbols
	m_symbolTable = new SymbolTableView(this);
	{
		auto symbolFilterEdit = new FilterEdit(m_symbolTable);
		connect(symbolFilterEdit, &FilterEdit::textChanged, [this](const QString& filter) {
			m_symbolTable->setFilter(filter.toStdString());
		});

		// Apply custom column styling
		m_symbolTable->setItemDelegateForColumn(0, new AddressColorDelegate(m_symbolTable));

		auto loadSymbolImageButton = new QPushButton();
		{
			connect(loadSymbolImageButton, &QPushButton::clicked,
				[this, loadImagesWithAddr](bool) {
					auto selected = m_symbolTable->selectionModel()->selectedRows();
					std::vector<uint64_t> addresses;
					for (const auto& row : selected)
						addresses.push_back(row.data().toString().toULongLong(nullptr, 16));
					loadImagesWithAddr(addresses);
				});
			loadSymbolImageButton->setText("Load Image");
		} // loadImageButton

		// Shows the current selected rows image name.
		auto currentImageLabel = new QLabel(this); {
			currentImageLabel->setText("");
			currentImageLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
		}

		// Update the label whenever the selection changes.
		connect(m_symbolTable->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
	        [this, currentImageLabel](const QModelIndex &current, const QModelIndex &) {
		        auto symbol = m_symbolTable->getSymbolAtRow(current.row());
		        auto controller = SharedCacheController::GetController(*this->m_data);
		        if (!controller)
			        return;
		        auto image = controller->GetImageContaining(symbol.address);
		        if (image)
			        currentImageLabel->setText("Image: " + QString::fromStdString(image->name));
		        else
			        currentImageLabel->setText("");
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

		connect(m_symbolTable, &SymbolTableView::activated, this, [=](const QModelIndex& index){
				auto symbol = m_symbolTable->getSymbolAtRow(index.row());
				auto dialog = new QMessageBox(this);

				auto controller = SharedCacheController::GetController(*this->m_data);
				if (!controller)
					return;

				auto image = controller->GetImageContaining(symbol.address);
				if (!image.has_value())
					return;

				dialog->setText("Load " + QString::fromStdString(image->name) + "?");
				dialog->setStandardButtons(QMessageBox::Yes | QMessageBox::No);

				connect(dialog, &QMessageBox::buttonClicked, this, [=](QAbstractButton* button)
				{
					if (button == dialog->button(QMessageBox::Yes))
						loadImagesWithAddr({image->headerAddress});
				});

				dialog->exec();
			});

		m_triageTabs->addTab(symbolWidget, "Symbols");
		m_triageTabs->setCanCloseTab(symbolWidget, false);
	} // symbolSearch

	// Tab: Mappings & Regions
	auto cacheInfoWidget = new QWidget;
	{
		auto cacheInfoLayout = new QVBoxLayout(cacheInfoWidget);

		auto cacheInfoSubwidget = new QWidget;

		auto mappingTable = new FilterableTableView(cacheInfoSubwidget);
		m_mappingModel = new QStandardItemModel(0, 4, mappingTable);
		m_mappingModel->setHorizontalHeaderLabels({"Address", "Size", "File Address", "File Path"});

		// Apply custom column styling
		mappingTable->setItemDelegateForColumn(0, new AddressColorDelegate(mappingTable));

		mappingTable->setModel(m_mappingModel);

		mappingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
		mappingTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
		mappingTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
		mappingTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

		mappingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

		mappingTable->setSelectionBehavior(QAbstractItemView::SelectRows);
		mappingTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

		mappingTable->setSortingEnabled(true);

		mappingTable->verticalHeader()->setVisible(false);

		auto regionTable = new FilterableTableView(cacheInfoSubwidget);
		m_regionModel = new QStandardItemModel(0, 4, regionTable);
		m_regionModel->setHorizontalHeaderLabels({"Address", "Size", "Type", "Name"});

		// Apply custom column styling
		regionTable->setItemDelegateForColumn(0, new AddressColorDelegate(regionTable));

		regionTable->setModel(m_regionModel);

		regionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
		regionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
		regionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
		regionTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

		regionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

		regionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
		regionTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

		regionTable->setSortingEnabled(true);

		regionTable->verticalHeader()->setVisible(false);

		auto mappingLabel = new QLabel("Mappings");
		auto mappingFilterEdit = new FilterEdit(mappingTable);
		{
			connect(mappingFilterEdit, &FilterEdit::textChanged, [mappingTable](const QString& filter) {
				mappingTable->setFilter(filter.toStdString());
			});
		}

		auto mappingHeaderLayout = new QHBoxLayout;
		mappingHeaderLayout->addWidget(mappingLabel);
		mappingHeaderLayout->addWidget(mappingFilterEdit);
		mappingHeaderLayout->setAlignment(Qt::AlignJustify);
		mappingHeaderLayout->setSpacing(30);

		auto regionLabel = new QLabel("Regions");
		auto regionFilterEdit = new FilterEdit(regionTable);
		{
			connect(regionFilterEdit, &FilterEdit::textChanged, [regionTable](const QString& filter) {
				regionTable->setFilter(filter.toStdString());
			});
		}

		auto regionHeaderLayout = new QHBoxLayout;
		regionHeaderLayout->addWidget(regionLabel);
		regionHeaderLayout->addWidget(regionFilterEdit);
		regionHeaderLayout->setAlignment(Qt::AlignJustify);
		regionHeaderLayout->setSpacing(30);

		auto mappingLayout = new QVBoxLayout;
		mappingLayout->addLayout(mappingHeaderLayout);
		mappingLayout->addWidget(mappingTable);

		auto regionLayout = new QVBoxLayout;
		regionLayout->addLayout(regionHeaderLayout);
		regionLayout->addWidget(regionTable);

		cacheInfoLayout->addLayout(mappingLayout);
		cacheInfoLayout->addLayout(regionLayout);

		m_triageTabs->addTab(cacheInfoWidget, "Mappings & Regions");
		m_triageTabs->setCanCloseTab(cacheInfoWidget, false);
	} // cacheInfoSection

	m_layout = new QVBoxLayout(this);
	m_layout->addWidget(m_triageTabs);
	setLayout(m_layout);

	// In case we have already initialized the controller (user has opened this view type again)
	// we will call refresh data. If this is the first triage view constructed (i.e. before view init) then this
	// will do nothing.
	RefreshData();

	m_triageTabs->selectWidget(defaultWidget);
}

DSCTriageView::~DSCTriageView()
{
	UIContext::unregisterNotification(this);
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
	// TODO: We have to set this to true otherwise view restore does not pickup this view.
	return true;
}

uint64_t DSCTriageView::getCurrentOffset()
{
	return 0;
}

SelectionInfoForXref DSCTriageView::getSelectionForXref()
{
	// TODO: If we are in the symbols view we _can_ actually show a useful xref to the selected symbols.
	SelectionInfoForXref selection = {};
	selection.addrValid = false;
	return selection;
}

void DSCTriageView::OnAfterOpenFile(UIContext *context, FileContext *file, ViewFrame *frame)
{
	RefreshData();
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}

// Called when shared cache information has changed.
void DSCTriageView::RefreshData()
{
	// Controller should be available after view init.
	auto controller = SharedCacheController::GetController(*m_data);
	if (!controller)
		return;

	m_imageModel->setRowCount(0);
	for (const auto& img : controller->GetImages())
	{
		m_imageModel->appendRow({
			new QStandardItem(QString("0x%1").arg(img.headerAddress, 0, 16)),
			new QStandardItem(""),
			new QStandardItem(QString::fromStdString(img.name))
		});
	}

	// Set images as loaded (updating the relevant image row)
	for (const auto& loadedImg : controller->GetLoadedImages())
		setImageLoaded(loadedImg.headerAddress);

	m_regionModel->setRowCount(0);
	for (const auto& region : controller->GetRegions())
	{
		m_regionModel->appendRow({
			new QStandardItem(QString("0x%1").arg(region.start, 0, 16)),
			new QStandardItem(QString("0x%1").arg(region.size, 0, 16)),
			new QStandardItem(QString::fromStdString(GetRegionTypeAsString(region.type))),
			new QStandardItem(QString::fromStdString(region.name))
		});
	}

	m_mappingModel->setRowCount(0);
	for (const auto& entry : controller->GetEntries())
	{
		for (const auto& mapping : entry.mappings)
		{
			m_mappingModel->appendRow({
				new QStandardItem(QString("0x%1").arg(mapping.vmAddress, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.size, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.fileOffset, 0, 16)),
				new QStandardItem(QString::fromStdString(entry.path))
			});
		}
	}

	m_symbolTable->populateSymbols(*m_data);
}

void DSCTriageView::setImageLoaded(const uint64_t imageHeaderAddr)
{
	// Go through the m_loadImageModel and find the image associated with the address
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
#include <QHeaderView>
#include <QMessageBox>
#include <utility>
#include "kctriage.h"
#include "globalarea.h"
#include "symboltable.h"
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


KCTriageView::KCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), m_data(std::move(data))
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

	// In case we have already initialized the controller (user has opened this view type again)
	// we will call refresh data. If this is the first triage view constructed (i.e. before view init) then this
	// will do nothing.
	RefreshData();

	m_triageTabs->selectWidget(defaultWidget);
}


KCTriageView::~KCTriageView()
{
	UIContext::unregisterNotification(this);
}


void KCTriageView::loadImagesWithAddr(const std::vector<uint64_t>& addresses, bool includeDependencies) {
	auto controller = KernelCacheController::GetController(*m_data);
	if (!controller)
		return;

	// TODO: NOTE ABOUT `IsImageLoaded` BEING COMMENTED OUT. PLEASE READ.
	// TODO: Because commiting undo actions will use main thread to synchronize we must not be holding any locks
	// TODO: This can really only ever be removed if:
	// TODO:	1. we can set a user function type without creating an undo action, basically like the rest of shared cache
	// TODo:		use an auto function or some hack to get the user function but without the undo action.
	// TODO:	2. we can use the undo buffer from any thread and not just the main thread
	// TODO: I have exhausted all other options, this is a serious issue we should address soon.
	typedef std::vector<CacheImage> ImageList;
	ImageList images = {};
	for (const uint64_t& addr : addresses)
	{
		std::optional<CacheImage> image = controller->GetImageContaining(addr);
		if (image.has_value())
		{
			// Only try to load if we have not already.
			// if (!controller->IsImageLoaded(*image))
			images.emplace_back(*image);

			// TODO: We currently only add direct dependencies, may want to make the depth configurable?
			if (includeDependencies)
			{
				auto dependencies = controller->GetImageDependencies(*image);
				for (const auto& depName : dependencies)
				{
					auto depImage = controller->GetImageWithName(depName);
					if (depImage.has_value()/* && !controller->IsImageLoaded(*depImage) */)
					{
						images.emplace_back(*depImage);
					}
				}
			}
		}
	}

	// Don't create a worker action if we don't have any images.
	if (images.empty())
		return;
	Ref<BackgroundTask> imageLoadTask = new BackgroundTask("Loading images...", true);

	// Apply the images in a future then update the triage view and run analysis.
	QPointer<QFutureWatcher<ImageList>> watcher = new QFutureWatcher<ImageList>(this);
	connect(watcher, &QFutureWatcher<ImageList>::finished, this, [watcher, this]() {
		if (watcher)
		{
			auto loadedImages = watcher->result();
			if (loadedImages.empty())
				return;

			// Update the triage to display the images as loaded.
			for (const auto& image : loadedImages)
				setImageLoaded(image.headerVirtualAddress);

			// Run analysis.
			this->m_data->AddAnalysisOption("linearsweep");
			this->m_data->UpdateAnalysis();
		}
	});
	QFuture<ImageList> future = QtConcurrent::run([this, controller, images, imageLoadTask]() {
		ImageList loadedImages = {};
		for (const auto& image : images)
		{
			if (imageLoadTask->IsCancelled() || QThread::currentThread()->isInterruptionRequested())
				break;
			std::string newLoad = fmt::format("Loading images... ({}/{})", loadedImages.size(), images.size());
			imageLoadTask->SetProgressText(newLoad);
			if (controller->ApplyImage(*this->m_data, image))
				loadedImages.emplace_back(image);
		}
		imageLoadTask->Finish();
		return loadedImages;
	});
	watcher->setFuture(future);
	connect(this, &QObject::destroyed, this, [watcher, imageLoadTask]() {
		if (watcher && watcher->isRunning()) {
			watcher->cancel();
			imageLoadTask->Cancel();
		}
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
	m_imageModel->setHorizontalHeaderLabels({"Address", "Loaded", "Name"});

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
				loadImagesWithAddr(addresses, false);
			});
			contextMenu.addAction(&loadImagesAction);
		}

		contextMenu.exec(m_imageTable->viewport()->mapToGlobal(pos));
	});

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

	auto refreshDataButton = new QPushButton();
	{
		// TODO: Might want to introduce a cooldown for this button (if we even keep it)
		connect(refreshDataButton, &QPushButton::clicked, [this](bool) { RefreshData(); });
		refreshDataButton->setText("Refresh");
	} // refreshDataButton

	auto loadImageFilterEdit = new FilterEdit(m_imageTable);
	loadImageFilterEdit->setPlaceholderText("Filter images");
	connect(loadImageFilterEdit, &FilterEdit::textChanged, [this](const QString& filter) {
		m_imageTable->setFilter(filter.toStdString());
	});

	connect(m_imageTable, &FilterableTableView::activated, this, [=, this](const QModelIndex& index) {
		auto addr = m_imageModel->item(index.row(), 0)->text().toULongLong(nullptr, 16);
		loadImagesWithAddr({addr});
	});

	auto loadImageLayout = new QVBoxLayout;
	loadImageLayout->addWidget(loadImageFilterEdit);
	loadImageLayout->addWidget(m_imageTable);

	auto loadImageFooterLayout = new QHBoxLayout;
	loadImageFooterLayout->addWidget(loadImageButton);
	loadImageFooterLayout->addWidget(refreshDataButton);
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

	m_imageTable->sortByColumn(0, Qt::AscendingOrder);
	m_imageTable->setSortingEnabled(true);

	m_imageTable->verticalHeader()->setVisible(false);

	m_triageTabs->addTab(loadImageWidget, "Images");
	m_triageTabs->setCanCloseTab(loadImageWidget, false);

	return loadImageWidget; // For use as the default widget
}


void KCTriageView::initSymbolTable()
{
	m_symbolTable = new SymbolTableView(this);

	// Apply custom column styling
	m_symbolTable->setItemDelegateForColumn(0, new AddressColorDelegate(m_symbolTable));

	auto symbolFilterEdit = new FilterEdit(m_symbolTable);
	symbolFilterEdit->setPlaceholderText("Filter symbols");
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
		auto controller = KernelCacheController::GetController(*this->m_data);
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

	connect(m_symbolTable, &SymbolTableView::activated, this, [=, this](const QModelIndex& index)
	{
		auto symbol = m_symbolTable->getSymbolAtRow(index.row());
		auto dialog = new QMessageBox(this);

		auto controller = KernelCacheController::GetController(*this->m_data);
		if (!controller)
			return;

		auto image = controller->GetImageContaining(symbol.address);
		if (!image.has_value())
			return;

		dialog->setText("Load " + QString::fromStdString(image->name) + "?");
		dialog->setStandardButtons(QMessageBox::Yes | QMessageBox::No);

		connect(dialog, &QMessageBox::buttonClicked, this, [=, this](QAbstractButton* button)
			{
				if (button == dialog->button(QMessageBox::Yes))
					loadImagesWithAddr({image->headerVirtualAddress});
			});

		dialog->exec();
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


SelectionInfoForXref KCTriageView::getSelectionForXref()
{
	// TODO: If we are in the symbols view we _can_ actually show a useful xref to the selected symbols.
	SelectionInfoForXref selection = {};
	selection.addrValid = false;
	return selection;
}


void KCTriageView::OnAfterOpenFile(UIContext *context, FileContext *file, ViewFrame *frame)
{
	RefreshData();
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}


// Called when shared cache information has changed.
void KCTriageView::RefreshData()
{
	// Controller should be available after view init.
	auto controller = KernelCacheController::GetController(*m_data);
	if (!controller)
		return;

	m_imageModel->setRowCount(0);
	for (const auto& img : controller->GetImages())
	{
		m_imageModel->appendRow({
			new QStandardItem(QString("0x%1").arg(img.headerVirtualAddress, 0, 16)),
			new QStandardItem(""),
			new QStandardItem(QString::fromStdString(img.name))
		});
	}

	// Set images as loaded (updating the relevant image row)
	for (const auto& loadedImg : controller->GetLoadedImages())
		setImageLoaded(loadedImg.headerVirtualAddress);

	m_symbolTable->populateSymbols(*m_data);

	// Reapply the current sort after repopulating the model
	// TODO: This should use `QSortFilterProxyModel`, but that's a bigger change.
	m_imageTable->setSortingEnabled(true);
}

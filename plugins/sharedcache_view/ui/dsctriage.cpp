#include <QElapsedTimer>
#include <QHeaderView>
#include <QHideEvent>
#include <QMessageBox>
#include <QShowEvent>
#include <QTimer>
#include <utility>
#include "dsctriage.h"
#include "globalarea.h"
#include "stringstable.h"
#include "symboltable.h"
#include "ui/fontsettings.h"

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
	return new DSCTriageView(viewFrame, data);
}


void DSCTriageViewType::Register()
{
	registerViewType(new DSCTriageViewType());
}


DSCTriageView::DSCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), m_data(std::move(data))
{
	setBinaryDataNavigable(false);
	setupView(this);

	UIContext::registerNotification(this);

	m_triageCollection = new DockableTabCollection(this);
	m_triageTabs = new SplitTabWidget(m_triageCollection);

	auto triageTabStyle = new GlobalAreaTabStyle();
	m_triageTabs->setTabStyle(triageTabStyle);

	QWidget* defaultWidget = initImageTable();
	initSymbolTable();
	initStringsTab();
	initCacheInfoTables();

	// The string scan and symbol fetch are expensive, so each panel starts its load only once its
	// tab is first shown, and clears its large result set after the tab leaves the screen.
	connect(m_triageTabs, &SplitTabWidget::currentChanged, this, [this](QWidget* widget) {
		m_stringsPanel->setCurrentTabWidget(widget);
		m_symbolsPanel->setCurrentTabWidget(widget);
	});

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


void DSCTriageView::loadImagesWithAddr(const std::vector<uint64_t>& addresses, bool includeDependencies,
	std::optional<uint64_t> navigateTo) {
	auto controller = SharedCacheController::GetController(*m_data);
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
		auto image = controller->GetImageContaining(addr);
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

	// Apply the images in a future than update the triage view and run analysis.
	QPointer<QFutureWatcher<ImageList>> watcher = new QFutureWatcher<ImageList>(this);
	connect(watcher, &QFutureWatcher<ImageList>::finished, this, [watcher, navigateTo, this]() {
		if (watcher)
		{
			auto loadedImages = watcher->result();
			if (!loadedImages.empty())
			{
				// Update the triage to display the images as loaded.
				for (const auto& image : loadedImages)
					setImageLoaded(image.headerAddress);

				// Run analysis.
				this->m_data->AddAnalysisOption("linearsweep");
				this->m_data->AddAnalysisOption("pointersweep");
				this->m_data->UpdateAnalysis();
			}

			if (navigateTo)
				navigateToAddress(*navigateTo);

			watcher->deleteLater();
		}
	});
	QFuture<ImageList> future = QtConcurrent::run([data = m_data, controller, images, imageLoadTask]() {
		ImageList loadedImages = {};
		for (const auto& image : images)
		{
			if (imageLoadTask->IsCancelled() || QThread::currentThread()->isInterruptionRequested())
				break;
			std::string newLoad = fmt::format("Loading images... ({}/{})", loadedImages.size(), images.size());
			imageLoadTask->SetProgressText(newLoad);
			if (controller->ApplyImage(*data, image))
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


void DSCTriageView::setImageLoaded(const uint64_t imageHeaderAddr)
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


QWidget* DSCTriageView::initImageTable()
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
		QAction loadImagesWithDepsAction("", m_imageTable);
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

			// Format action text for loading selected images with dependencies
			QString loadWithDepsActionText = (selectedCount == 1) ? "Load Selected Image and Dependencies" : QString("Load %1 Selected Images and Dependencies").arg(selectedCount);
			loadImagesWithDepsAction.setText(loadWithDepsActionText);
			connect(&loadImagesWithDepsAction, &QAction::triggered, [this, addresses]() {
				this->loadImagesWithAddr(addresses, true);
			});
			contextMenu.addAction(&loadImagesWithDepsAction);
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

	auto loadImageWithDepsButton = new QPushButton();
	connect(loadImageWithDepsButton, &QPushButton::clicked, [this](bool) {
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
		loadImagesWithAddr(addresses, true);
	});
	loadImageWithDepsButton->setText(" Load with Dependencies ");

	auto refreshDataButton = new QPushButton();
	{
		// TODO: Might want to introduce a cooldown for this button (if we even keep it)
		connect(refreshDataButton, &QPushButton::clicked, [this](bool) { RefreshData(); });
		refreshDataButton->setText("Refresh");
	} // refreshDataButton

	auto loadImageFilterEdit = new FilterEdit(m_imageTable);
	loadImageFilterEdit->setPlaceholderText("Filter images");
	connect(loadImageFilterEdit, &FilterEdit::textChanged, [this, loadImageFilterEdit](const QString& filter) {
		m_imageTable->setFilter(filter.toStdString(), loadImageFilterEdit->getFilterOptions());
	});
	connect(loadImageFilterEdit, &FilterEdit::optionsChanged, [this, loadImageFilterEdit](FilterOptions options) {
		m_imageTable->setFilter(loadImageFilterEdit->text().toStdString(), options);
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
	loadImageFooterLayout->addWidget(loadImageWithDepsButton);
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


void DSCTriageView::initSymbolTable()
{
	m_symbolTable = new SymbolTableView(this);
	m_symbolsPanel = new TriageTablePanel(this, m_symbolTable, "Filter symbols", "symbols");
	m_symbolsPanel->setLoader([this] { return startSymbolLoad(); });
	m_symbolsPanel->setClearHandler([this] {
		// Discard an in-flight symbol fetch rather than letting its results repopulate the
		// cleared table.
		if (m_symbolsWatcher)
		{
			m_symbolsWatcher->disconnect();
			m_symbolsWatcher->deleteLater();
		}
	});

	m_symbolsPanel->addFilterToggle(":/icons/images/folder.png", "Match Image Names",
		[this](bool checked) { m_symbolTable->symbolsModel()->setMatchImageNames(checked); });

	auto loadSymbolImageButton = m_symbolsPanel->addSelectionButton("Load Image");
	connect(loadSymbolImageButton, &QPushButton::clicked, [this](bool) {
		auto selected = m_symbolTable->selectionModel()->selectedRows();
		std::vector<uint64_t> addresses;
		for (const auto& row : selected)
			addresses.push_back(m_symbolTable->getSymbolAtRow(row.row()).address);
		loadImagesWithAddr(addresses);
	});

	connect(m_symbolTable, &SymbolTableView::activated, this, [this](const QModelIndex& index){
		auto symbol = m_symbolTable->getSymbolAtRow(index.row());

		auto controller = SharedCacheController::GetController(*this->m_data);
		if (!controller)
			return;

		auto image = controller->GetImageContaining(symbol.address);
		if (!image.has_value())
			return;

		if (controller->IsImageLoaded(*image))
		{
			navigateToAddress(symbol.address);
			return;
		}

		promptToLoadImage(image->name, image->headerAddress, symbol.address);
	});

	m_triageTabs->addTab(m_symbolsPanel, "Symbols");
	m_triageTabs->setCanCloseTab(m_symbolsPanel, false);
}


bool DSCTriageView::startSymbolLoad()
{
	// The controller is not available until view init has finished. Retry on the next activation.
	auto controller = SharedCacheController::GetController(*m_data);
	if (!controller)
		return false;

	m_symbolTable->setNameSources(*controller);
	m_symbolsPanel->statusLabel()->setText("Loading…");

	typedef std::vector<CacheSymbol> SymbolList;
	QPointer<QFutureWatcher<SymbolList>> watcher = new QFutureWatcher<SymbolList>(this);
	m_symbolsWatcher = watcher;
	connect(watcher, &QFutureWatcher<SymbolList>::finished, this, [watcher, this]() {
		if (!watcher)
			return;
		m_symbolTable->symbolsModel()->appendSymbols(watcher->result());
		m_symbolsPanel->finishLoad();
		watcher->deleteLater();
	});
	QFuture<SymbolList> future = QtConcurrent::run([controller]() { return controller->GetSymbols(); });
	watcher->setFuture(future);
	connect(this, &QObject::destroyed, this, [watcher]() {
		if (watcher && watcher->isRunning()) {
			watcher->cancel();
			watcher->waitForFinished();
		}
	});
	return true;
}


void DSCTriageView::promptToLoadImage(const std::string& imageName, uint64_t address, uint64_t navigateTo)
{
	auto dialog = new QMessageBox(this);
	dialog->setText("Load " + QString::fromStdString(imageName) + "?");
	auto loadButton = dialog->addButton("Load Image", QMessageBox::AcceptRole);
	dialog->addButton(QMessageBox::Cancel);
	dialog->setDefaultButton(loadButton);

	connect(dialog, &QMessageBox::buttonClicked, this, [=, this](QAbstractButton* button)
	{
		if (button == loadButton)
			loadImagesWithAddr({address}, false, navigateTo);
	});

	dialog->exec();
}


void DSCTriageView::initStringsTab()
{
	m_stringsTable = new StringsTableView(this);
	m_stringsPanel = new TriageTablePanel(this, m_stringsTable, "Filter strings", "strings");
	m_stringsPanel->setLoader([this] { return startStringScan(); });
	m_stringsPanel->setClearHandler([this] {
		m_stringsPollTimer->stop();
		m_stringScanner.reset();
	});
	// Strings hidden by the visibility toggles are not part of the searched population, so they
	// do not appear in the count unless a text filter narrows it.
	m_stringsPanel->setBaselineCount(
		[this] { return m_stringsTable->stringsModel()->baselineStringCount(); });

	m_stringsPanel->addFilterToggle(":/icons/images/folder.png", "Match Image Names",
		[this](bool checked) { m_stringsTable->stringsModel()->setMatchImageNames(checked); });
	// Strings in regions that belong to no image (dyld data and other non-image regions) are
	// rarely of interest, so they are hidden unless this is toggled on.
	m_stringsPanel->addFilterToggle(":/icons/images/stack.png", "Show Non-Image Strings",
		[this](bool checked) { m_stringsTable->stringsModel()->setShowNonImageStrings(checked); });

	auto loadStringImageButton = m_stringsPanel->addSelectionButton("Load Image");
	connect(loadStringImageButton, &QPushButton::clicked, [this](bool) {
		auto selected = m_stringsTable->selectionModel()->selectedRows();
		std::vector<uint64_t> imageAddresses;
		for (const auto& row : selected)
		{
			const auto string = m_stringsTable->getStringAtRow(row.row());
			if (string.imageStart)
				imageAddresses.push_back(string.address);
			else
				loadStringRegion(string, std::nullopt);
		}
		loadImagesWithAddr(imageAddresses);
	});

	connect(m_stringsTable, &StringsTableView::activated, this, [this](const QModelIndex& index) {
		const auto string = m_stringsTable->getStringAtRow(index.row());
		auto controller = SharedCacheController::GetController(*this->m_data);
		if (!controller)
			return;

		// Strings outside any image (e.g. the coalesced selector pool) load just their region.
		if (!string.imageStart)
		{
			loadStringRegion(string, string.address);
			return;
		}

		auto image = controller->GetImageAt(string.imageStart);
		if (!image.has_value())
			return;

		if (controller->IsImageLoaded(*image))
		{
			navigateToAddress(string.address);
			return;
		}

		promptToLoadImage(image->name, image->headerAddress, string.address);
	});

	m_stringsPollTimer = new QTimer(this);
	m_stringsPollTimer->setInterval(250);
	connect(m_stringsPollTimer, &QTimer::timeout, this, &DSCTriageView::pollStringScan);

	m_triageTabs->addTab(m_stringsPanel, "Strings");
	m_triageTabs->setCanCloseTab(m_stringsPanel, false);
}


void DSCTriageView::showEvent(QShowEvent* event)
{
	QWidget::showEvent(event);
	m_stringsPanel->setViewVisible(true);
	m_symbolsPanel->setViewVisible(true);
}


void DSCTriageView::hideEvent(QHideEvent* event)
{
	QWidget::hideEvent(event);
	m_stringsPanel->setViewVisible(false);
	m_symbolsPanel->setViewVisible(false);
}


bool DSCTriageView::startStringScan()
{
	// The controller is not available until view init has finished. Retry on the next activation.
	auto controller = SharedCacheController::GetController(*m_data);
	if (!controller)
		return false;

	m_stringsTable->setNameSources(*controller);
	m_stringScanner = controller->CreateStringScanner();
	m_stringScanner->Start();
	m_stringsPanel->statusLabel()->setText("Scanning…");
	m_stringsPollTimer->start();
	return true;
}


void DSCTriageView::pollStringScan()
{
	if (!m_stringScanner)
		return;

	auto model = m_stringsTable->stringsModel();
	constexpr uint64_t maxBatchSize = 250000;
	constexpr qint64 maxIngestMilliseconds = 150;
	// Ingest batches until the time budget is spent, then yield so the UI stays responsive.
	QElapsedTimer ingestTimer;
	ingestTimer.start();
	do
	{
		auto batch = m_stringScanner->TakeStrings(maxBatchSize);
		if (batch.empty())
			break;
		model->appendStrings(std::move(batch));
	} while (ingestTimer.elapsed() < maxIngestMilliseconds);

	const bool scanComplete = m_stringScanner->IsComplete();
	const QLocale locale;
	if (scanComplete && model->totalRowCount() == m_stringScanner->GetStringCount())
	{
		m_stringsPollTimer->stop();
		m_stringScanner.reset();
		m_stringsPanel->finishLoad();
	}
	else if (scanComplete)
	{
		// The scan has finished but the table is still ingesting batched results.
		const QString totalStrings = locale.toString(static_cast<qulonglong>(m_stringScanner->GetStringCount()));
		const QString fetchedStrings =
			locale.toString(static_cast<qulonglong>(model->totalRowCount())).rightJustified(totalStrings.size());
		m_stringsPanel->statusLabel()->setText(QString("Loading… %1 / %2 strings").arg(fetchedStrings, totalStrings));
	}
	else
	{
		const auto [current, total] = m_stringScanner->GetProgress();
		const QString totalMB = locale.toString(static_cast<qulonglong>(total / (1024 * 1024)));
		// Pad the growing values so the label width stays stable while scanning.
		const QString currentMB =
			locale.toString(static_cast<qulonglong>(current / (1024 * 1024))).rightJustified(totalMB.size());
		const QString stringCount =
			locale.toString(static_cast<qulonglong>(model->totalRowCount())).rightJustified(10);
		m_stringsPanel->statusLabel()->setText(
			QString("Scanning… %1 / %2 MB — %3 strings").arg(currentMB, totalMB, stringCount));
	}
}


void DSCTriageView::loadStringRegion(const CacheString& string, std::optional<uint64_t> navigateTo)
{
	auto controller = SharedCacheController::GetController(*m_data);
	if (!controller)
		return;

	auto region = controller->GetRegionAt(string.regionStart);
	if (!region.has_value())
		return;

	QPointer<QFutureWatcher<bool>> watcher = new QFutureWatcher<bool>(this);
	connect(watcher, &QFutureWatcher<bool>::finished, this, [watcher, navigateTo, this]() {
		if (!watcher)
			return;
		if (watcher->result())
			m_data->UpdateAnalysis();
		if (navigateTo)
			navigateToAddress(*navigateTo);
		watcher->deleteLater();
	});
	QFuture<bool> future = QtConcurrent::run([data = m_data, controller, region]() {
		return controller->ApplyRegion(*data, *region);
	});
	watcher->setFuture(future);
	connect(this, &QObject::destroyed, this, [watcher]() {
		if (watcher && watcher->isRunning()) {
			watcher->cancel();
			watcher->waitForFinished();
		}
	});
}


void DSCTriageView::navigateToAddress(uint64_t address)
{
	ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
	if (!frame)
		return;
	// Navigating the frame's current view would hit DSCTriageView::navigate, which is not
	// navigable. Switch to the linear view of the cache instead.
	frame->navigate("Linear:" + frame->getCurrentDataType(), address, true, true);
}


void DSCTriageView::initCacheInfoTables()
{
	auto cacheInfoWidget = new QWidget;

	auto cacheInfoLayout = new QVBoxLayout(cacheInfoWidget);

	auto cacheInfoSubwidget = new QWidget;

	m_mappingTable = new FilterableTableView(cacheInfoSubwidget);
	m_mappingModel = new QStandardItemModel(0, 5, m_mappingTable);
	m_mappingModel->setHorizontalHeaderLabels({"Address", "Size", "File Address", "File Name", "File Path"});

	// Apply custom column styling
	m_mappingTable->setItemDelegateForColumn(0, new AddressColorDelegate(m_mappingTable));

	m_mappingTable->setModel(m_mappingModel);

	m_mappingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
	m_mappingTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
	m_mappingTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
	m_mappingTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
	m_mappingTable->horizontalHeader()->resizeSection(3, 300);
	m_mappingTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

	m_mappingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

	m_mappingTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_mappingTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

	m_mappingTable->sortByColumn(0, Qt::AscendingOrder);
	m_mappingTable->setSortingEnabled(true);

	m_mappingTable->verticalHeader()->setVisible(false);

	m_regionTable = new FilterableTableView(cacheInfoSubwidget);
	m_regionModel = new QStandardItemModel(0, 4, m_regionTable);
	m_regionModel->setHorizontalHeaderLabels({"Address", "Size", "Type", "Name"});

	// Apply custom column styling
	m_regionTable->setItemDelegateForColumn(0, new AddressColorDelegate(m_regionTable));

	m_regionTable->setModel(m_regionModel);

	m_regionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
	m_regionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
	m_regionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
	m_regionTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

	m_regionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

	m_regionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_regionTable->setSelectionMode(QAbstractItemView::ExtendedSelection);

	m_regionTable->sortByColumn(0, Qt::AscendingOrder);
	m_regionTable->setSortingEnabled(true);

	m_regionTable->verticalHeader()->setVisible(false);

	auto mappingLabel = new QLabel("Mappings");
	auto mappingFilterEdit = new FilterEdit(m_mappingTable);
	mappingFilterEdit->setPlaceholderText("Filter mappings");
	connect(mappingFilterEdit, &FilterEdit::textChanged, [this, mappingFilterEdit](const QString& filter) {
		m_mappingTable->setFilter(filter.toStdString(), mappingFilterEdit->getFilterOptions());
	});
	connect(mappingFilterEdit, &FilterEdit::optionsChanged, [this, mappingFilterEdit](FilterOptions options) {
		m_mappingTable->setFilter(mappingFilterEdit->text().toStdString(), options);
	});

	auto mappingHeaderLayout = new QHBoxLayout;
	mappingHeaderLayout->addWidget(mappingLabel);
	mappingHeaderLayout->addWidget(mappingFilterEdit);
	mappingHeaderLayout->setAlignment(Qt::AlignJustify);
	mappingHeaderLayout->setSpacing(30);

	auto regionLabel = new QLabel("Regions");
	auto regionFilterEdit = new FilterEdit(m_regionTable);
	regionFilterEdit->setPlaceholderText("Filter regions");
	connect(regionFilterEdit, &FilterEdit::textChanged, [this, regionFilterEdit](const QString& filter) {
		m_regionTable->setFilter(filter.toStdString(), regionFilterEdit->getFilterOptions());
	});
	connect(regionFilterEdit, &FilterEdit::optionsChanged, [this, regionFilterEdit](FilterOptions options) {
		m_regionTable->setFilter(regionFilterEdit->text().toStdString(), options);
	});

	auto regionHeaderLayout = new QHBoxLayout;
	regionHeaderLayout->addWidget(regionLabel);
	regionHeaderLayout->addWidget(regionFilterEdit);
	regionHeaderLayout->setAlignment(Qt::AlignJustify);
	regionHeaderLayout->setSpacing(30);

	auto mappingLayout = new QVBoxLayout;
	mappingLayout->addLayout(mappingHeaderLayout);
	mappingLayout->addWidget(m_mappingTable);

	auto regionLayout = new QVBoxLayout;
	regionLayout->addLayout(regionHeaderLayout);
	regionLayout->addWidget(m_regionTable);

	cacheInfoLayout->addLayout(mappingLayout);
	cacheInfoLayout->addLayout(regionLayout);

	m_triageTabs->addTab(cacheInfoWidget, "Mappings & Regions");
	m_triageTabs->setCanCloseTab(cacheInfoWidget, false);
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
	return false;
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

	// Reapply the current sort after repopulating the model
	// TODO: This should use `QSortFilterProxyModel`, but that's a bigger change.
	m_imageTable->setSortingEnabled(true);

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

	// Reapply the current sort after repopulating the model
	// TODO: This should use `QSortFilterProxyModel`, but that's a bigger change.
	m_regionTable->setSortingEnabled(true);

	m_mappingModel->setRowCount(0);
	for (const auto& entry : controller->GetEntries())
	{
		for (const auto& mapping : entry.mappings)
		{
			m_mappingModel->appendRow({
				new QStandardItem(QString("0x%1").arg(mapping.vmAddress, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.size, 0, 16)),
				new QStandardItem(QString("0x%1").arg(mapping.fileOffset, 0, 16)),
				new QStandardItem(QString::fromStdString(entry.name)),
				new QStandardItem(QString::fromStdString(entry.path))
			});
		}
	}

	// Reapply the current sort after repopulating the model
	// TODO: This should use `QSortFilterProxyModel`, but that's a bigger change.
	m_mappingTable->setSortingEnabled(true);

	// Symbols and strings are loaded lazily when their tabs are shown.
	// Discard any loaded content so the reload picks up the refreshed cache information.
	m_symbolsPanel->resetContent();
	m_stringsPanel->resetContent();
}

//
// Created by kat on 8/15/24.
//

#include "kctriage.h"
#include "ui/fontsettings.h"
#include <QPainter>
#include <QTextBrowser>
#include "tabwidget.h"
#include "globalarea.h"
#include "progresstask.h"

#include <cmath>
#include <QMessageBox>


#define QSETTINGS_KEY_SELECTED_TAB "KCTriage-SelectedTab"
#define QSETTINGS_KEY_TAB_LAYOUT "KCTriage-TabLayout"
#define QSETTINGS_KEY_IMAGELOAD_TAB_LAYOUT "KCTriage-ImageLoadTabLayout"
#define QSETTINGS_KEY_ALPHA_POPUP_SEEN "KCTriage-AlphaPopupSeenV2"


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

	const KernelCacheAPI::KCSymbol& symbol = m_symbols.at(index.row());

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

const KernelCacheAPI::KCSymbol& SymbolTableModel::symbolAt(int row) const {
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


SymbolTableView::SymbolTableView(QWidget* parent, Ref<KernelCacheAPI::KernelCache> cache)
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


KCTriageView::KCTriageView(QWidget* parent, BinaryViewRef data) : QWidget(parent), View(), m_data(data), m_cache(new KernelCacheAPI::KernelCache(data))
{
	setBinaryDataNavigable(true);
	setupView(this);

	m_triageCollection = new DockableTabCollection();
	m_triageTabs = new SplitTabWidget(m_triageCollection);

	auto triageTabStyle = new GlobalAreaTabStyle();
	m_triageTabs->setTabStyle(triageTabStyle);

	QSplitter* containerWidget = new QSplitter;
	containerWidget->setOrientation(Qt::Vertical);

	QWidget* defaultWidget = nullptr;

	m_bottomRegionCollection = new DockableTabCollection();
	m_bottomRegionTabs = new SplitTabWidget(m_bottomRegionCollection);
	m_bottomRegionTabs->setTabStyle(new GlobalAreaTabStyle());

	auto loadImageTable = new FilterableTableView;
	{
		auto loadImageModel = new QStandardItemModel(0, 2, loadImageTable);
		{
			loadImageModel->setHorizontalHeaderLabels({"Name", "VM Address"});
			BackgroundThread::create(loadImageTable)->thenBackground([this](QVariant var)
				{
					QVariantList rows;

					auto images = m_cache->GetImages();

					auto newHeaders = std::make_shared<std::vector<KernelCacheAPI::KernelCacheMachOHeader>>();
					newHeaders->reserve(images.size());

					for (const auto& img : images)
					{
						if (auto header = m_cache->GetMachOHeaderForImage(img.name); header)
						{
							newHeaders->push_back(*header);
							rows.push_back(QList<QVariant>{
								QString::fromStdString(img.name),
								QString("0x%1").arg(header->textBase, 0, 16)
							});
						}
					}

					{
						std::unique_lock<std::mutex> lock(m_headersMutex);
						m_headers.swap(newHeaders);
					}

					return QVariant(rows);
				})->thenMainThread([loadImageModel, loadImageTable](QVariant var){
					QVariantList rows = var.toList();

					if (loadImageModel->rowCount() > 0)
					{
						loadImageModel->removeRows(0, loadImageModel->rowCount());
					}

					for (const QVariant &rowVariant : rows) {
						QVariantList row = rowVariant.toList();

						QList<QStandardItem*> items;
						for (const QVariant &cellValue : row) {
							items.append(new QStandardItem(cellValue.toString()));
						}

						loadImageModel->appendRow(items);
						loadImageTable->resizeColumnsToContents();
					}
				})->start();
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

					for (const auto& selection : selected)
					{
						auto name = selection.data().toString().toStdString();
						WorkerPriorityEnqueue([this, name]() { m_cache->LoadImageWithInstallName(name); });
					}
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
				auto selected = loadImageTable->selectionModel()->selectedRows();
				if (selected.size() == 0)
				{
					return;
				}

				for (const auto& selection : selected)
				{
					auto name = selection.data().toString().toStdString();
					WorkerPriorityEnqueue([this, name]() { m_cache->LoadImageWithInstallName(name); });
				}
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

		std::function<void(uint64_t)> navigateToAddress = [=](uint64_t addr){
			ExecuteOnMainThread([addr, this](){
				if (BinaryNinja::Settings::Instance()->Get<bool>("ui.view.graph.preferred"))
					m_data->Navigate("Graph:KCView", addr);
				else
					m_data->Navigate("Linear:KCView", addr);
			});
		};

		connect(symbolSearch, &SymbolTableView::activated, this, [=](const QModelIndex& index)
			{
				auto symbol = symbolSearch->getSymbolAtRow(index.row());
				WorkerPriorityEnqueue([this, symbol, navigateToAddress]()
					{
						if (m_data->IsValidOffset(symbol.address))
							navigateToAddress(symbol.address);
						else
						{
							m_cache->LoadImageWithInstallName(symbol.image);
							navigateToAddress(symbol.address);
						}
					});
			});

		m_triageTabs->addTab(symbolWidget, "Symbol Search");
		m_triageTabs->setCanCloseTab(symbolWidget, false);
	} // symbolSearch

	{ // Doc tabs

		QTextBrowser *mainDocBrowser = new QTextBrowser(this);
		{
			mainDocBrowser->setOpenExternalLinks(true);
			auto alphaHtml =
				R"(
<h1>KernelCache Parser</h1>

<p> This parser has support for MH_FILESET (>= macOS 11, >= iOS 14) kernels. </p>

<h2> Getting the latest version of the plugin </h2>
<p> We frequently release "dev" builds which will contain the latest version of the KernelCache plugin (and many other things). </p>
<p> You can find instructions on how to install these builds <a href="https://docs.binary.ninja/guide/index.html#development-branch">here</a>. </p>

<h3> Reading / building the source </h3>
<p> Like most of our platforms, architectures, debug information parsing, and the entire API and documentation, this plugin is open source. </p>
<p> You can read the source and find instructions for building it <a href="https://github.com/Vector35/binaryninja-api/tree/dev/view/kernelcache">here</a>. </p>
<p> Contributions are always welcome! </p>
)";
			mainDocBrowser->setHtml(alphaHtml);

			m_triageTabs->addTab(mainDocBrowser, "KernelCache Parser");
			m_triageTabs->setCanCloseTab(mainDocBrowser, false);

		}
	}

	containerWidget->addWidget(m_bottomRegionTabs);

	m_layout = new QVBoxLayout(this);
	m_layout->addWidget(m_triageTabs);
	setLayout(m_layout);

	m_triageTabs->selectWidget(defaultWidget);
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


KCTriageViewType::KCTriageViewType()
	: ViewType("KCTriage", "Kernel Cache Triage")
{

}


int KCTriageViewType::getPriority(BinaryViewRef data, const QString& filename)
{
	if (data->GetTypeName() == KC_VIEW_NAME)
	{
		return 100;
	}
	return 0;
}


QWidget* KCTriageViewType::create(BinaryViewRef data, ViewFrame* viewFrame)
{
	if (data->GetTypeName() != KC_VIEW_NAME)
	{
		return nullptr;
	}
	return new KCTriageView(viewFrame, data);
}


void KCTriageViewType::Register()
{
	ViewType::registerViewType(new KCTriageViewType());
}

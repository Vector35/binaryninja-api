#include "containers.h"

WarpContainerWidget::WarpContainerWidget(Warp::Ref<Warp::Container> container, QWidget* parent) : QWidget(parent)
{
	m_container = std::move(container);
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	m_tabs = new QTabWidget(this);
	layout->addWidget(m_tabs);

	// Sources tab
	m_sourcesPage = new QWidget(this);
	auto* sourcesLayout = new QVBoxLayout(m_sourcesPage);

	m_sourcesView = new WarpSourcesView(m_sourcesPage);
	m_sourcesView->setContainer(m_container);

	sourcesLayout->addWidget(m_sourcesView);
	m_tabs->addTab(m_sourcesPage, tr("Sources"));

	// TODO: Maybe introduce some callbacks or something, but i feel like this is fine for now.
	// Periodic refresh timer for the Sources view
	m_refreshTimer = new QTimer(this);
	m_refreshTimer->setInterval(5000);
	connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
		// Only refresh if the widget and the Sources page are actually visible
		if (!this->isVisible() || !m_sourcesPage || !m_sourcesPage->isVisible())
			return;

		WarpSourcesModel* sourcesModel = m_sourcesView->sourceModel();
		// Preserve selection by GUID across reloads
		QString currentGuid;
		if (const QModelIndex currentIdx = m_sourcesView->currentIndex(); currentIdx.isValid())
		{
			const int row = currentIdx.row();
			const QModelIndex guidIdx = sourcesModel->index(row, WarpSourcesModel::GuidCol);
			currentGuid = sourcesModel->data(guidIdx, Qt::DisplayRole).toString();
		}

		sourcesModel->reload();

		if (!currentGuid.isEmpty())
		{
			for (int r = 0; r < sourcesModel->rowCount(); ++r)
			{
				const QModelIndex gIdx = sourcesModel->index(r, WarpSourcesModel::GuidCol);
				if (sourcesModel->data(gIdx, Qt::DisplayRole).toString() == currentGuid)
				{
					m_sourcesView->setCurrentIndex(sourcesModel->index(r, WarpSourcesModel::PathCol));
					break;
				}
			}
		}
	});
	m_refreshTimer->start();

	// TODO: Do we want to reload this on tab changed???
	connect(m_tabs, &QTabWidget::currentChanged, this, [this](const int idx) {
		QWidget* w = m_tabs->widget(idx);
		if (w == m_sourcesPage)
			m_sourcesView->sourceModel()->reload();
	});
}

WarpContainersPane::WarpContainersPane(QWidget* parent) : QWidget(parent)
{
	auto* splitter = new QSplitter(Qt::Vertical, this);
	splitter->setContentsMargins(0, 0, 0, 0);
	auto* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);
	mainLayout->addWidget(splitter);
	auto newPalette = palette();
	newPalette.setColor(QPalette::Window, getThemeColor(SidebarWidgetBackgroundColor));
	setAutoFillBackground(true);
	setPalette(newPalette);

	// List on top
	m_list = new QListWidget(splitter);
	m_list->setSelectionMode(QAbstractItemView::SingleSelection);
	m_list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_list->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
	m_list->setUniformItemSizes(true);

	// Make names larger and show end of long strings (elide at the start)
	{
		QFont f = m_list->font();
		f.setPointSizeF(f.pointSizeF() + 2.0);  // bump size
		m_list->setFont(f);
		m_list->setTextElideMode(Qt::ElideLeft);
	}

	// Container view (tabs) below
	m_stack = new QStackedWidget(splitter);
	m_stack->setContentsMargins(0, 0, 0, 0);

	splitter->setStretchFactor(0, 0);  // list: minimal growth
	splitter->setStretchFactor(1, 1);  // stack: takes remaining space
	splitter->setCollapsible(0, false);
	splitter->setCollapsible(1, false);

	populate();

	connect(m_list, &QListWidget::currentRowChanged, this, [this](int row) {
		if (row >= 0 && row < m_stack->count())
			m_stack->setCurrentIndex(row);
	});

	// Select the first container if available
	if (m_list->count() > 0)
	{
		m_list->setCurrentRow(0);
	}
}

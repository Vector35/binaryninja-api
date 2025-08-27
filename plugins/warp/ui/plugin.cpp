#include "plugin.h"

#include <QToolBar>

#include "matched.h"
#include "matches.h"
#include "symbollist.h"
#include "viewframe.h"
#include "shared/fetchdialog.h"

using namespace BinaryNinja;

QIcon GetColoredIcon(const QString &iconPath, const QColor &color)
{
	auto pixmap = QPixmap(iconPath);
	auto mask = pixmap.createMaskFromColor(QColor(0, 0, 0), Qt::MaskInColor);
	pixmap.fill(color);
	pixmap.setMask(mask);
	return QIcon(pixmap);
}

Ref<BackgroundTask> GetMatcherTask()
{
	// TODO: What happens if we have multiple views open matching? This fails.
	// Look for the matcher background task to determine if we are stopping or starting it.
	Ref<BackgroundTask> matcherTask = nullptr;
	for (const auto &task: BackgroundTask::GetRunningTasks())
	{
		std::string progressText = task->GetProgressText();
		if (progressText.find("Matching on WARP") != std::string::npos)
			matcherTask = task;
	}
	return matcherTask;
}

void ShowNetworkNotice()
{
	// By default, network access is disabled for WARP, this function will show the user a notice to enable it and restart.
	const auto settings = Settings::Instance();
	const bool networkNoticeShown = QSettings().value("warp/NetworkNoticeShown", false).toBool();
	QSettings().setValue("warp/NetworkNoticeShown", true);
	if (!networkNoticeShown && settings->Contains("network.enableWARP") && !settings->Get<bool>("network.enableWARP"))
	{
		const bool enable = ShowMessageBox("Enable WARP Network Access?",
			"Network access is disabled by default. Enable WARP network features now?\n\n"
			"You can change this later in Settings.",
			YesNoButtonSet, InformationIcon) == YesButton;
		settings->Set("network.enableWARP", enable);
		// TODO: Add a notifyRestartRequired call here
		if (enable)
			ShowMessageBox("WARP Network Enabled", "Please restart Binary Ninja to allow WARP to make requests to the server.", OKButtonSet, InformationIcon);
		else
			ShowMessageBox("WARP Network Disabled", "WARP network access will remain disabled. You can enable it later from Settings.", OKButtonSet, InformationIcon);
	}
}

WarpSidebarWidget::WarpSidebarWidget(BinaryViewRef data) : SidebarWidget("WARP"), m_data(data)
{
	m_logger = LogRegistry::CreateLogger("WARP UI");
	m_currentFrame = nullptr;

	// If not already shown, opening the sidebar will give notice.
	ShowNetworkNotice();

	m_headerWidget = new QWidget();
	QHBoxLayout *headerLayout = new QHBoxLayout();
	headerLayout->setContentsMargins(0, 0, 0, 0);
	headerLayout->setSpacing(0);

	QToolBar *headerToolbar = new QToolBar(this);
	headerToolbar->setContentsMargins(0, 0, 0, 0);
	headerToolbar->setIconSize(QSize(20, 20));

	auto fetchIcon = GetColoredIcon(":/icons/images/arrow-pull.png", getThemeColor(BlueStandardHighlightColor));
	auto fetchAction = headerToolbar->addAction(fetchIcon, "Fetch data from WARP containers", [this]() {
		UIActionHandler *handler = m_currentFrame->getCurrentViewInterface()->actionHandler();
		handler->executeAction("WARP\\Fetch");
	});
	fetchAction->setToolTip("Fetch data from WARP containers");

	auto commitIcon = GetColoredIcon(":/icons/images/arrow-push.png", getThemeColor(BlueStandardHighlightColor));
	auto commitAction = headerToolbar->addAction(commitIcon, "Commit a WARP file to a source", [this]() {
		UIActionHandler *handler = m_currentFrame->getCurrentViewInterface()->actionHandler();
		handler->executeAction("WARP\\Commit File");
	});
	commitAction->setToolTip("Commit a WARP file to a source");

	// We want to make it clear that the container actions for fetching and pushing are seperate.
	headerToolbar->addSeparator();

	auto loadIcon = GetColoredIcon(":/icons/images/file-add.png", getThemeColor(BlueStandardHighlightColor));
	auto loadAction = headerToolbar->addAction(loadIcon, "Load Signature File", [this]() {
		UIActionHandler *handler = m_currentFrame->getCurrentViewInterface()->actionHandler();
		handler->executeAction("WARP\\Load File");
	});
	loadAction->setToolTip("Load a signature file to match against");

	auto saveIcon = GetColoredIcon(":/icons/images/edit.png", getThemeColor(BlueStandardHighlightColor));
	auto saveAction = headerToolbar->addAction(saveIcon, "Create Signature File", [this]() {
		UIActionHandler *handler = m_currentFrame->getCurrentViewInterface()->actionHandler();
		handler->executeAction("WARP\\Create\\From Current View");
	});
	saveAction->setToolTip("Save data to a signature file");

	headerToolbar->addSeparator();

	static auto matcherStopIcon = GetColoredIcon(":/icons/images/stop.png", getThemeColor(RedStandardHighlightColor));
	static auto matcherStartIcon = GetColoredIcon(":/icons/images/start.png",
												  getThemeColor(GreenStandardHighlightColor));
	m_matcherAction = headerToolbar->addAction(matcherStartIcon, "Run Matcher", [this]() {
		UIActionHandler *handler = m_currentFrame->getCurrentViewInterface()->actionHandler();
		if (Ref<BackgroundTask> matcherTask = GetMatcherTask())
			matcherTask->Cancel();
		else if (!isMatcherRunning)
		{
			handler->executeAction("WARP\\Run Matcher");
			setMatcherActionIcon(true);
		}
	});
	m_matcherAction->setToolTip("Run the matcher on all functions");

	auto refreshIcon = GetColoredIcon(":/icons/images/refresh.png", getThemeColor(BlueStandardHighlightColor));
	auto refreshAction = headerToolbar->addAction(refreshIcon, "Refresh the view data", [this]() {
		Update();
	});
	refreshAction->setToolTip("Refresh the sidebar data");

	// Push the toolbar to the right using a stretch space.
	headerLayout->addStretch();
	headerLayout->addWidget(headerToolbar, 0);
	m_headerWidget->setLayout(headerLayout);

	QFrame *currentFunctionFrame = new QFrame(this);
	m_currentFunctionWidget = new WarpCurrentFunctionWidget();
	QVBoxLayout *currentFunctionLayout = new QVBoxLayout();
	currentFunctionLayout->setContentsMargins(0, 0, 0, 0);
	currentFunctionLayout->setSpacing(0);
	currentFunctionLayout->addWidget(m_currentFunctionWidget);
	currentFunctionFrame->setLayout(currentFunctionLayout);

	QFrame *matchedFrame = new QFrame(this);
	m_matchedWidget = new WarpMatchedWidget(m_data);
	QVBoxLayout *matchedLayout = new QVBoxLayout();
	matchedLayout->setContentsMargins(0, 0, 0, 0);
	matchedLayout->setSpacing(0);
	matchedLayout->addWidget(m_matchedWidget);
	matchedFrame->setLayout(matchedLayout);

	QFrame *containerFrame = new QFrame(this);
	m_containerWidget = new WarpContainersPane();
	QVBoxLayout *containerLayout = new QVBoxLayout();
	containerLayout->setContentsMargins(0, 0, 0, 0);
	containerLayout->setSpacing(0);
	containerLayout->addWidget(m_containerWidget);
	containerFrame->setLayout(containerLayout);

	QVBoxLayout *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	auto tabWidget = new QTabWidget(this);
	tabWidget->addTab(currentFunctionFrame, "Current Function");
	tabWidget->addTab(matchedFrame, "Matched Functions");
	tabWidget->addTab(containerFrame, "Containers");

	m_analysisEvent = new AnalysisCompletionEvent(m_data, [this]() {
		ExecuteOnMainThread([this]() {
			Update();
		});
	});

	layout->addWidget(tabWidget);
	this->setLayout(layout);

	// NOTE: This fetcher is shared with the fetch dialog that is constructed on initialization of this plugin.
	m_currentFunctionWidget->SetFetcher(WarpFetcher::Global());
}

WarpSidebarWidget::~WarpSidebarWidget()
{
	m_analysisEvent->Cancel();
}

void WarpSidebarWidget::focus()
{
}

void WarpSidebarWidget::Update()
{
	m_currentFunctionWidget->UpdateMatches();
	m_matchedWidget->Update();
	// TODO: Obviously this probably should not be called here.
	setMatcherActionIcon(false);
}

void WarpSidebarWidget::setMatcherActionIcon(bool running)
{
	static auto matcherStopIcon = GetColoredIcon(":/icons/images/stop.png", getThemeColor(RedStandardHighlightColor));
	static auto matcherStartIcon = GetColoredIcon(":/icons/images/start.png",
	                                              getThemeColor(GreenStandardHighlightColor));
	isMatcherRunning = running;
	if (running)
	{
		m_matcherAction->setIcon(matcherStopIcon);
		m_matcherAction->setToolTip("Stop the matcher");
		m_matcherAction->setIconText("Stop Matcher");
	} else
	{
		m_matcherAction->setIcon(matcherStartIcon);
		m_matcherAction->setToolTip("Run the matcher on all functions");
		m_matcherAction->setIconText("Run Matcher");
	}
}

void WarpSidebarWidget::notifyViewChanged(ViewFrame *view)
{
	if (!view)
		return;

	if (view == m_currentFrame)
		return;
	m_currentFrame = view;
	// TODO: We need to set some stuff here prolly.
}

void WarpSidebarWidget::notifyViewLocationChanged(View *view, const ViewLocation &location)
{
	// Warp sidebar really should only update if it is visible, otherwise its a waste of cycles.
	if (!this->isVisible())
		return;
	auto function = location.getFunction();
	// TODO: Only update if the function exists?
	// NOTE: The function called will exit early if it is the same function.
	m_currentFunctionWidget->SetCurrentFunction(function);
}

WarpSidebarWidgetType::WarpSidebarWidgetType() : SidebarWidgetType(QImage(":/icons/images/warp.png"), "WARP")
{

}


extern "C" {
BN_DECLARE_UI_ABI_VERSION

BINARYNINJAPLUGIN void CorePluginDependencies()
{
	// We must have WARP to enable this plugin!
	AddRequiredPluginDependency("warp_ninja");
}

BINARYNINJAPLUGIN bool UIPluginInit()
{
	RegisterWarpFetchFunctionsCommand();
	Sidebar::addSidebarWidgetType(new WarpSidebarWidgetType());
	return true;
}
}

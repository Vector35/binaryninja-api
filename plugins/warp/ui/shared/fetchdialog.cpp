#include "fetchdialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QInputDialog>
#include <QLabel>

#include "action.h"
#include "fetcher.h"
#include "misc.h"

using namespace BinaryNinja;

static void AddListItem(QListWidget* list, const QString& value)
{
	if (value.trimmed().isEmpty())
		return;
	// Avoid duplicates
	for (int i = 0; i < list->count(); ++i)
		if (list->item(i)->text().compare(value, Qt::CaseInsensitive) == 0)
			return;
	list->addItem(value.trimmed());
}

WarpFetchDialog::WarpFetchDialog(BinaryViewRef bv, std::shared_ptr<WarpFetcher> fetcher, QWidget* parent) :
	QDialog(parent), m_fetchProcessor(std::move(fetcher)), m_bv(std::move(bv))
{
	setWindowTitle("WARP Fetcher");

	auto form = new QFormLayout();
	m_containerCombo = new QComboBox(this);
	populateContainers();
	m_containerCombo->addItem("All Containers");  // index 0 for "all"
	for (const auto& c : m_containers)
		m_containerCombo->addItem(QString::fromStdString(c->GetName()));

	// Tags editor
	m_tagsList = new QListWidget(this);
	m_addTagBtn = new QPushButton(this);
	m_addTagBtn->setText("+");
	m_addTagBtn->setToolTip("Add tag");
	m_removeTagBtn = new QPushButton(this);
	m_removeTagBtn->setText("-");
	m_removeTagBtn->setToolTip("Remove selected tag(s)");
	m_resetTagBtn = new QPushButton(this);
	m_resetTagBtn->setText("Reset");
	m_resetTagBtn->setToolTip("Reset tags to: official, trusted");
	auto tagBtnRow = new QHBoxLayout();
	tagBtnRow->addWidget(m_addTagBtn);
	tagBtnRow->addWidget(m_removeTagBtn);
	tagBtnRow->addWidget(m_resetTagBtn);
	tagBtnRow->addStretch();
	auto tagCol = new QVBoxLayout();
	tagCol->addWidget(m_tagsList);
	tagCol->addLayout(tagBtnRow);
	auto tagWrapper = new QWidget(this);
	tagWrapper->setLayout(tagCol);

	// Make tags list compact with a fixed maximum height and no vertical expansion
	m_tagsList->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
	m_tagsList->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	m_tagsList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
	m_tagsList->setMaximumHeight(120);
	m_tagsList->setToolTip("A source must have atleast ONE of these tags to be considered");

	// Defaults from processor tags
	for (const auto& t : GetAllowedTagsFromView(m_bv))
		AddListItem(m_tagsList, QString::fromStdString(t));

	m_rerunMatcher = new QCheckBox("Re-run matcher after fetch", this);
	m_rerunMatcher->setChecked(true);

	m_clearProcessed = new QCheckBox("Refetch all functions", this);
	m_clearProcessed->setToolTip(
		"Clears the processed cache before fetching again, this will refetch all functions in the view");
	m_clearProcessed->setChecked(false);

	form->addRow(new QLabel("Container: "), m_containerCombo);
	form->addRow(new QLabel("Allowed Tags: "), tagWrapper);
	form->addRow(m_rerunMatcher);
	form->addRow(m_clearProcessed);

	auto buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	connect(buttons, &QDialogButtonBox::accepted, this, &WarpFetchDialog::onAccept);
	connect(buttons, &QDialogButtonBox::rejected, this, &WarpFetchDialog::onReject);

	auto root = new QVBoxLayout(this);
	root->addLayout(form);
	root->addWidget(buttons);
	setLayout(root);

	// Wire buttons
	connect(m_addTagBtn, &QPushButton::clicked, this, &WarpFetchDialog::onAddTag);
	connect(m_removeTagBtn, &QPushButton::clicked, this, &WarpFetchDialog::onRemoveTag);
	connect(m_resetTagBtn, &QPushButton::clicked, this, &WarpFetchDialog::onResetTags);
}

void WarpFetchDialog::populateContainers()
{
	m_containers = Warp::Container::All();
}

void WarpFetchDialog::onAddTag()
{
	bool ok = false;
	const auto text = QInputDialog::getText(this, "Add Tag", "Tag:", QLineEdit::Normal, {}, &ok);
	if (ok)
		AddListItem(m_tagsList, text);
}

void WarpFetchDialog::onRemoveTag()
{
	for (auto* item : m_tagsList->selectedItems())
		delete item;
}

void WarpFetchDialog::onResetTags()
{
	m_tagsList->clear();
	AddListItem(m_tagsList, "official");
	AddListItem(m_tagsList, "trusted");
}

std::vector<Warp::SourceTag> WarpFetchDialog::collectTags() const
{
	std::vector<Warp::SourceTag> out;
	out.reserve(m_tagsList->count());
	for (int i = 0; i < m_tagsList->count(); ++i)
		out.emplace_back(m_tagsList->item(i)->text().trimmed().toStdString());
	return out;
}

void WarpFetchDialog::onAccept()
{
	const int idx = m_containerCombo->currentIndex();
	std::optional<size_t> containerIndex;
	if (idx > 0)  // 0 == All Containers
		containerIndex = static_cast<size_t>(idx - 1);

	const bool rerun = m_rerunMatcher->isChecked();

	const auto tags = collectTags();
	// Persist tags to the view settings.
	SetTagsToView(m_bv, tags);

	if (m_clearProcessed->isChecked())
		m_fetchProcessor->ClearProcessed();

	// Execute the network fetch in batches
	runBatchedFetch(containerIndex, tags, rerun);

	accept();
}

void WarpFetchDialog::onReject()
{
	const auto tags = collectTags();
	// Persist tags to the view settings.
	SetTagsToView(m_bv, tags);
	reject();
}

void WarpFetchDialog::runBatchedFetch(
	const std::optional<size_t>& containerIndex, const std::vector<Warp::SourceTag>& allowedTags, bool rerunMatcher)
{
	if (!m_bv)
		return;
	// Collect functions in the view and enqueue them to the shared fetcher
	std::vector<Ref<Function>> funcs = m_bv->GetAnalysisFunctionList();
	if (funcs.empty())
		return;

	// Create a background task to show progress in the UI
	Ref<BackgroundTask> task =
		new BackgroundTask("Fetching WARP functions (0 / " + std::to_string(funcs.size()) + ")", true);

	auto fetcher = m_fetchProcessor;
	auto bv = m_bv;

	// TODO: Too many captures in this thing lol.
	WorkerInteractiveEnqueue([fetcher, bv, funcs = std::move(funcs), rerunMatcher, task, allowedTags]() mutable {
		const auto batchSize = GetBatchSizeFromView(bv);
		size_t processed = 0;
		while (processed < funcs.size())
		{
			if (task->IsCancelled())
				break;
			const size_t remaining = funcs.size() - processed;
			const size_t thisBatchCount = std::min(batchSize, remaining);
			for (size_t i = 0; i < thisBatchCount; ++i)
				fetcher->AddPendingFunction(funcs[processed + i]);
			fetcher->FetchPendingFunctions(allowedTags);
			processed += thisBatchCount;
			task->SetProgressText(
				"Fetching WARP functions (" + std::to_string(processed) + " / " + std::to_string(funcs.size()) + ")");
		}

		task->Finish();
		Logger("WARP Fetcher").LogInfo("Finished fetching WARP functions in %d seconds...", task->GetRuntimeSeconds());

		if (rerunMatcher && bv)
			Warp::RunMatcher(*bv);
	});
}

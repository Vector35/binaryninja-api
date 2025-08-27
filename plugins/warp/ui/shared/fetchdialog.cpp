#include "fetchdialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QInputDialog>
#include <QLabel>

#include "action.h"
#include "fetcher.h"

using namespace BinaryNinja;

static void AddListItem(QListWidget *list, const QString &value)
{
    if (value.trimmed().isEmpty())
        return;
    // Avoid duplicates
    for (int i = 0; i < list->count(); ++i)
        if (list->item(i)->text().compare(value, Qt::CaseInsensitive) == 0)
            return;
    list->addItem(value.trimmed());
}

WarpFetchDialog::WarpFetchDialog(BinaryViewRef bv,
                                 std::shared_ptr<WarpFetcher> fetcher,
                                 QWidget *parent)
    : QDialog(parent), m_fetchProcessor(std::move(fetcher)), m_bv(std::move(bv))
{
    setWindowTitle("Fetch WARP Functions");

    auto form = new QFormLayout();
    m_containerCombo = new QComboBox(this);
    populateContainers();
    m_containerCombo->addItem("All Containers"); // index 0 for "all"
    for (const auto &c: m_containers)
        m_containerCombo->addItem(QString::fromStdString(c->GetName()));

    // TODO: Need to add tooltip to explain that a source must have atleast one of these tags to be considered.

    // Tags editor
    m_tagsList = new QListWidget(this);
    m_addTagBtn = new QPushButton("Add", this);
    m_removeTagBtn = new QPushButton("Remove", this);
    auto tagBtnRow = new QHBoxLayout();
    tagBtnRow->addWidget(m_addTagBtn);
    tagBtnRow->addWidget(m_removeTagBtn);
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
    for (const auto &t: m_fetchProcessor->GetTags())
        AddListItem(m_tagsList, QString::fromStdString(t));

    // Batch size and matcher checkbox
    m_batchSize = new QSpinBox(this);
    m_batchSize->setRange(10, 1000);
    m_batchSize->setValue(100);
    m_batchSize->setToolTip("Number of functions to fetch in each batch");

    m_rerunMatcher = new QCheckBox("Re-run matcher after fetch", this);
    m_rerunMatcher->setChecked(true);

    m_clearProcessed = new QCheckBox("Refetch all functions", this);
    m_clearProcessed->setToolTip("Clears the processed cache before fetching again, this will refetch all functions in the view");
    m_clearProcessed->setChecked(false);

    form->addRow(new QLabel("Container: "), m_containerCombo);
    // TODO: Need to plumb this through to the fetcher, and also likely have a blacklisted or whitelist mode for this dialog.
    // TODO: Alos wan to prefill the list of sources from the view/global settings.
    // form->addRow(new QLabel("Allowed Sources: "), srcWrapper);
    form->addRow(new QLabel("Allowed Tags: "), tagWrapper);
    form->addRow(new QLabel("Batch Size: "), m_batchSize);
    form->addRow(m_rerunMatcher);
    form->addRow(m_clearProcessed);

    auto buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &WarpFetchDialog::onAccept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto root = new QVBoxLayout(this);
    root->addLayout(form);
    root->addWidget(buttons);
    setLayout(root);

    // Wire buttons
    connect(m_addTagBtn, &QPushButton::clicked, this, &WarpFetchDialog::onAddTag);
    connect(m_removeTagBtn, &QPushButton::clicked, this, &WarpFetchDialog::onRemoveTag);
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
    for (auto *item: m_tagsList->selectedItems())
        delete item;
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
    if (idx > 0) // 0 == All Containers
        containerIndex = static_cast<size_t>(idx - 1);

    auto tags = collectTags();
    const auto batch = static_cast<size_t>(m_batchSize->value());
    const bool rerun = m_rerunMatcher->isChecked();

    // Persist tags to the shared processor for consistency across navigation
    m_fetchProcessor->SetTags(tags);

    if (m_clearProcessed->isChecked())
        m_fetchProcessor->ClearProcessed();

    // Execute the network fetch in batches
    runBatchedFetch(containerIndex, tags, batch, rerun);

    accept();
}

void WarpFetchDialog::runBatchedFetch(const std::optional<size_t> &containerIndex,
                                      const std::vector<Warp::SourceTag> &tags,
                                      size_t batchSize,
                                      bool rerunMatcher)
{
    if (!m_bv)
        return;
    // Collect functions in the view and enqueue them to the shared fetcher
    std::vector<Ref<Function>> funcs = m_bv->GetAnalysisFunctionList();
    if (funcs.empty())
        return;
    const size_t totalFuncs = funcs.size();
    const size_t totalBatches = (totalFuncs + batchSize - 1) / batchSize;

    // Create a background task to show progress in the UI
    Ref<BackgroundTask> task = new BackgroundTask("Fetching WARP functions (0 / " + std::to_string(totalBatches) + ")", false);

    auto fetcher = m_fetchProcessor;
    auto bv = m_bv;

    // TODO: Too many captures in this thing lol.
    WorkerInteractiveEnqueue([fetcher, bv, funcs = std::move(funcs), batchSize, rerunMatcher, task]() mutable {
        size_t processed = 0;
        size_t batchIndex = 0;

        while (processed < funcs.size())
        {
            const size_t remaining = funcs.size() - processed;
            const size_t thisBatchCount = std::min(batchSize, remaining);

            for (size_t i = 0; i < thisBatchCount; ++i)
                fetcher->AddPendingFunction(funcs[processed + i]);

            fetcher->FetchPendingFunctions();

            ++batchIndex;
            processed += thisBatchCount;

            task->SetProgressText("Fetching WARP functions (" + std::to_string(batchIndex) + " / " + std::to_string((funcs.size() + batchSize - 1) / batchSize) + ")");
        }

        task->Finish();
        // TODO: Print how long it took?
        Logger("WARP Fetcher").LogInfo("Finished fetching WARP functions...");

        if (rerunMatcher && bv)
            Warp::RunMatcher(*bv);
    });
}

void RegisterWarpFetchFunctionsCommand()
{
    // Register a UI action and bind it globally. Add it to the Tools menu.
    const QString actionName = "WARP\\Fetch";

    // TODO: Because we register this in every widget this will happen, this is bad behavior!
    if (!UIAction::isActionRegistered(actionName))
        UIAction::registerAction(actionName);

    UIActionHandler::globalActions()->bindAction(
        actionName,
        UIAction(
            [](const UIActionContext &context) {
                if (const BinaryViewRef bv = context.binaryView; bv)
                {
                    WarpFetchDialog dlg(bv, WarpFetcher::Global(), nullptr);
                    dlg.exec();
                }
            },
            [](const UIActionContext &context) {
                return context.binaryView != nullptr;
            }
        )
    );

    Menu::mainMenu("Plugins")->addAction(actionName, "Plugins");
}

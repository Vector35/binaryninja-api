#include "fetcher.h"

#include <QSettings>

WarpFetcher::WarpFetcher()
{
    m_logger = new BinaryNinja::Logger("WARP Fetcher");
    QSettings qtSettings;
    const QString key = "warp/allowedTags";

    QStringList tags = qtSettings.value(key).toStringList();
    if (tags.isEmpty()) {
        tags = QStringList{ "official", "trusted" };
        qtSettings.setValue(key, tags);
        qtSettings.sync();
    }

    std::vector<Warp::SourceTag> initialTags;
    initialTags.reserve(tags.size());
    for (const auto& t : tags)
        initialTags.emplace_back(t.trimmed().toStdString());

    SetTags(initialTags);
}

void WarpFetcher::AddPendingFunction(const FunctionRef &func)
{
    std::lock_guard<std::mutex> lock(m_requestMutex);
    const auto guid = Warp::GetAnalysisFunctionGUID(*func);
    if (!guid.has_value() || m_processedGuids.contains(*guid))
        return;
    m_pendingRequests.push_back(func);
}

std::vector<FunctionRef> WarpFetcher::FlushPendingFunctions()
{
    std::lock_guard<std::mutex> lock(m_requestMutex);
    std::vector<FunctionRef> requests = std::move(m_pendingRequests);
    m_pendingRequests.clear();
    return requests;
}

void WarpFetcher::ExecuteCompletionCallback()
{
    BinaryNinja::ExecuteOnMainThread([this]() {
        // TODO: Holding the mutex here is dangerous!
        std::lock_guard<std::mutex> lock(m_requestMutex);
        m_completionCallbacks.erase(
            std::ranges::remove_if(m_completionCallbacks,
                                   [](const auto &cb) { return cb() != RemoveCallback; }).begin(),
            m_completionCallbacks.end());
    });
}

std::shared_ptr<WarpFetcher> WarpFetcher::Global()
{
    static auto global = std::make_shared<WarpFetcher>();
    return global;
}

void WarpFetcher::FetchPendingFunctions()
{
    m_requestInProgress = true;
    const auto requests = FlushPendingFunctions();
    if (requests.empty())
    {
        m_logger->LogDebug("No pending requests to fetch... skipping");
        m_requestInProgress = false;
        return;
    }

    const auto start_time = std::chrono::high_resolution_clock::now();

    // Because we must fetch for a single target we map the function guids to the associated platform to perform fetches for each.
    std::map<PlatformRef, std::vector<Warp::FunctionGUID>> platformMappedGuids;
    for (const auto &func: requests)
    {
        const auto guid = Warp::GetAnalysisFunctionGUID(*func);
        if (!guid.has_value())
            continue;
        auto platform = func->GetPlatform();
        platformMappedGuids[platform].push_back(guid.value());
    }

    const auto tags = GetTags();
    for (const auto &[platform, guids] : platformMappedGuids)
    {
        m_logger->LogDebugF("Fetching {} functions for platform {}", guids.size(), platform->GetName());
        auto target = Warp::Target::FromPlatform(*platform);
        for (const auto &container: Warp::Container::All())
            container->FetchFunctions(*target, guids, tags);

        std::lock_guard<std::mutex> lock(m_requestMutex);
        for (const auto &guid: guids)
            m_processedGuids.insert(guid);
    }

    m_requestInProgress = false;
    ExecuteCompletionCallback();
    const auto end_time = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebug("Fetch batch took %f seconds", elapsed_time.count());
}

void WarpFetcher::ClearProcessed()
{
    m_logger->LogInfoF("Clearing {} processed functions from cache...", m_processedGuids.size());
    m_processedGuids.clear();
}

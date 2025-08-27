#pragma once

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <vector>
#include <functional>
#include <QSettings>

#include "warp.h"
#include "binaryninjaapi.h"
#include "uitypes.h"

enum WarpFetchCompletionStatus
{
    KeepCallback,
    RemoveCallback,
};

// Responsible for fetching data from the containers, to later be queried from the container interface.
class WarpFetcher
{
    LoggerRef m_logger;

    std::mutex m_requestMutex;
    std::vector<FunctionRef> m_pendingRequests;
    // TODO: Easy way to clear this if user wants to refetch.
    std::unordered_set<Warp::FunctionGUID> m_processedGuids;

    // List of callbacks to call when done fetching data, assume that others are using this as well.
    std::vector<std::function<WarpFetchCompletionStatus()> > m_completionCallbacks;

public:
    explicit WarpFetcher();

    // The global fetcher instance, this is used for the fetch dialog and the sidebar.
    static std::shared_ptr<WarpFetcher> Global();

    std::atomic<bool> m_requestInProgress = false;

    // Set the allowed source tags, sources with none of these tags will not be fetched from.
    void SetTags(const std::vector<Warp::SourceTag> &tags)
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        // TODO: This is kinda a hack, the fetcher instance should not sync through qt settings!
        QStringList qtTags = {};
        for (const auto& t : tags)
            qtTags.append(QString::fromStdString(t));
        QSettings().setValue("warp/allowedTags", qtTags);
    }

    std::vector<Warp::SourceTag> GetTags() const
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(m_requestMutex));
        // TODO: This is kinda a hack, the fetcher instance should not sync through qt settings!
        QSettings qtSettings;
        QStringList tags = qtSettings.value("warp/allowedTags").toStringList();
        if (tags.isEmpty()) {
            // The default tags to allow.
            tags = QStringList{ "official", "trusted" };
            qtSettings.setValue("warp/allowedTags", tags);
            qtSettings.sync();
        }
        std::vector<Warp::SourceTag> initialTags = {};
        for (const auto& t : tags)
            initialTags.emplace_back(t.trimmed().toStdString());
        return initialTags;
    }

    void AddCompletionCallback(std::function<WarpFetchCompletionStatus()> cb)
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        m_completionCallbacks.push_back(std::move(cb));
    }

    void AddPendingFunction(const FunctionRef &func);

    void FetchPendingFunctions();

    void ClearProcessed();
private:
    std::vector<FunctionRef> FlushPendingFunctions();

    void ExecuteCompletionCallback();
};

#pragma once

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <vector>
#include <functional>

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

    // TODO: Blacklisted and whitelisted source guids.
    // Tags to include with fetch requests (persisted as processor state)
    std::vector<Warp::SourceTag> m_tags;
    // Sources to allow for fetch requests.
    std::vector<Warp::Source> m_sources;

    // List of callbacks to call when done fetching data, assume that others are using this as well.
    std::vector<std::function<WarpFetchCompletionStatus()> > m_completionCallbacks;

public:
    explicit WarpFetcher();

    std::atomic<bool> m_requestInProgress = false;

    // Set the allowed source tags, sources with none of these tags will not be fetched from.
    void SetTags(const std::vector<Warp::SourceTag> &tags)
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        m_tags = tags;
    }

    std::vector<Warp::SourceTag> GetTags() const
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(m_requestMutex));
        return m_tags;
    }

    // Set the allowed sources, any source not in this list will not be fetched from.
    void SetSources(const std::vector<Warp::Source> &sources)
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        m_sources = sources;
    }

    std::vector<Warp::Source> GetSources() const
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(m_requestMutex));
        return m_sources;
    }

    void AddCompletionCallback(std::function<WarpFetchCompletionStatus()> cb)
    {
        std::lock_guard<std::mutex> lock(m_requestMutex);
        m_completionCallbacks.push_back(std::move(cb));
    }

    void AddPendingFunction(const FunctionRef &func);

    void FetchPendingFunctions();
private:
    std::vector<FunctionRef> FlushPendingFunctions();

    void ExecuteCompletionCallback();
};

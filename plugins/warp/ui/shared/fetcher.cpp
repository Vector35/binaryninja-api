#include "fetcher.h"

#include <chrono>

WarpFetcher::WarpFetcher()
{
	m_logger = new BinaryNinja::Logger("WARP Fetcher");
}

void WarpFetcher::AddPendingFunction(const FunctionRef& func)
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
	std::vector<std::pair<CallbackId, CompletionCallback>> callbacks;
	{
		std::lock_guard<std::mutex> lock(m_requestMutex);
		callbacks.insert(callbacks.end(), m_completionCallbacks.begin(), m_completionCallbacks.end());
	}

	std::vector<CallbackId> toRemove = {};
	for (auto& [id, cb] : callbacks)
		if (cb() == RemoveCallback)
			toRemove.push_back(id);

	std::lock_guard<std::mutex> lock(m_requestMutex);
	for (auto id : toRemove)
		m_completionCallbacks.erase(id);
}

std::shared_ptr<WarpFetcher> WarpFetcher::Global()
{
	static auto global = std::make_shared<WarpFetcher>();
	return global;
}

void WarpFetcher::FetchPendingFunctions(const std::vector<Warp::SourceTag>& allowedTags)
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

	// Because we must fetch for a single target we map the function guids to the associated platform to perform fetches
	// for each.
	std::map<PlatformRef, std::unordered_set<Warp::FunctionGUID>> platformMappedGuidSet;
	std::map<PlatformRef, std::unordered_set<Warp::ConstraintGUID>> platformMappedConstraintSet;
	for (const auto& func : requests)
	{
		const auto warpFunc = Warp::Function::Get(*func);
		if (!warpFunc)
			continue;
		auto platform = func->GetPlatform();
		platformMappedGuidSet[platform].insert(warpFunc->GetGUID());

		// We want to keep track of the guids so we can constrain the server response to only return functions with any
		// of them.
		const auto constraints = warpFunc->GetConstraints();
		std::vector<Warp::ConstraintGUID> constraintGuids;
		constraintGuids.reserve(constraints.size());
		for (const auto& constraint : constraints)
			constraintGuids.push_back(constraint.guid);
		platformMappedConstraintSet[platform].insert(constraintGuids.begin(), constraintGuids.end());
	}

	std::map<PlatformRef, std::vector<Warp::FunctionGUID>> platformMappedGuids;
	for (const auto& [platform, guids] : platformMappedGuidSet)
		platformMappedGuids[platform] = std::vector(guids.begin(), guids.end());

	// We keep them in the set above so we don't duplicate a bunch for functions with the same set of constraint guids.
	std::map<PlatformRef, std::vector<Warp::ConstraintGUID>> platformMappedConstraints;
	for (const auto& [platform, guids] : platformMappedConstraintSet)
		platformMappedConstraints[platform] = std::vector(guids.begin(), guids.end());

	for (const auto& [platform, guids] : platformMappedGuids)
	{
		m_logger->LogDebugF("Fetching {} functions for platform {}", guids.size(), platform->GetName());
		auto target = Warp::Target::FromPlatform(*platform);
		for (const auto& container : Warp::Container::All())
			container->FetchFunctions(*target, guids, allowedTags, platformMappedConstraints[platform]);

		std::lock_guard<std::mutex> lock(m_requestMutex);
		for (const auto& guid : guids)
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

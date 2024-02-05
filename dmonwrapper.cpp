#include "binaryninjaapi.h"
#define DMON_IMPL

#include "dmonwrapper.h"


bool DMonWrapper::g_dmonInitialized = false;
std::mutex DMonWrapper::g_dmonMutex;


DMonWrapper::DMonWrapper()
{
	std::unique_lock<std::mutex> lock(g_dmonMutex);

	if (!g_dmonInitialized)
	{
		dmon_init();
		g_dmonInitialized = true;
	}
}


DMonWrapper::~DMonWrapper()
{
	for (const auto& i : m_callbacks)
	{
		dmon_watch_id id;
		id.id = i.first;

		dmon_unwatch(id);
		free(i.second);
	}
	m_callbacks.clear();
}


dmon_watch_id DMonWrapper::Watch(const std::filesystem::path& path, CallbackFunction callback, bool recursive)
{
	std::unique_lock<std::mutex> lock(g_dmonMutex);

	auto flags = recursive ? DMON_WATCHFLAGS_RECURSIVE : 0;

	CallbackContext* ctxt = new CallbackContext();
	ctxt->callback = callback;

	dmon_watch_id dmonId = dmon_watch(path.string().c_str(), [](dmon_watch_id watch_id, dmon_action action, const char* rootdir, const char* filepath, const char* oldfilepath, void* userData) {
		CallbackContext* ctxt = reinterpret_cast<CallbackContext*>(userData);
		BinaryNinja::ExecuteOnMainThreadAndWait([ctxt, action, rootdir, filepath, oldfilepath](){
			if (ctxt->callback)
				ctxt->callback(action, rootdir, filepath, oldfilepath == NULL ? "" : oldfilepath);
		});
	}, flags, (void*)ctxt);

	if (dmonId.id == 0)
	{
		BinaryNinja::LogError("Failed to watch path %s", path.string().c_str());
		free(ctxt);
		return dmonId;
	}

	m_callbacks[dmonId.id] = ctxt;

	return dmonId;
}


std::vector<dmon_watch_id> DMonWrapper::GetWatchIds()
{
	std::unique_lock<std::mutex> lock(g_dmonMutex);

	std::vector<dmon_watch_id> out;
	out.reserve(m_callbacks.size());

	for (const auto& i : m_callbacks)
	{
		dmon_watch_id id;
		id.id = i.first;
		out.push_back(id);
	}

	return out;
}


void DMonWrapper::Unwatch(dmon_watch_id watchId)
{
	std::unique_lock<std::mutex> lock(g_dmonMutex);

	auto itr = m_callbacks.find(watchId.id);
	if (itr != m_callbacks.end())
	{
		dmon_unwatch(watchId);
		free(itr->second);
		m_callbacks.erase(itr);
	}
}

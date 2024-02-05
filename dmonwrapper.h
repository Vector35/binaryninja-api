#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <vector>
#define DMON_MAX_WATCHES 256
#include "vendor/dmon/dmon.h"


typedef std::function<void(dmon_action action, std::string dirname, std::string filename, std::string oldname)> CallbackFunction;

class DMonWrapper
{
	struct CallbackContext
	{
		CallbackFunction callback;
	};

	static bool g_dmonInitialized;
	static std::mutex g_dmonMutex;

	std::map<uint32_t, CallbackContext*> m_callbacks;

public:
	DMonWrapper();
	~DMonWrapper();

	dmon_watch_id Watch(const std::filesystem::path& path, CallbackFunction callback, bool recursive = false);
	void Unwatch(dmon_watch_id watchId);
	std::vector<dmon_watch_id> GetWatchIds();
};

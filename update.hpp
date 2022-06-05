#pragma once
#include <functional>
#include <vector>
#include <exception>
#include "update.h"

namespace BinaryNinja {
	class UpdateException : public std::exception
	{
		const std::string m_desc;

	  public:
		UpdateException(const std::string& desc) : std::exception(), m_desc(desc) {}
		virtual const char* what() const NOEXCEPT { return m_desc.c_str(); }
	};

	struct UpdateChannel
	{
		std::string name;
		std::string description;
		std::string latestVersion;

		static std::vector<UpdateChannel> GetList();

		bool AreUpdatesAvailable(uint64_t* expireTime, uint64_t* serverTime);

		BNUpdateResult UpdateToVersion(const std::string& version);
		BNUpdateResult UpdateToVersion(
		    const std::string& version, const std::function<bool(uint64_t progress, uint64_t total)>& progress);
		BNUpdateResult UpdateToLatestVersion();
		BNUpdateResult UpdateToLatestVersion(const std::function<bool(uint64_t progress, uint64_t total)>& progress);
	};

	/*! UpdateVersion documentation
	 */
	struct UpdateVersion
	{
		std::string version;
		std::string notes;
		time_t time;

		static std::vector<UpdateVersion> GetChannelVersions(const std::string& channel);
	};

	struct UpdateProgress
	{
		std::function<bool(uint64_t progress, uint64_t total)> func;

		static bool UpdateCallback(void* ctxt, uint64_t progress, uint64_t total)
		{
			UpdateProgress* self = (UpdateProgress*)ctxt;
			return self->func(progress, total);
		}
	};
}  // namespace BinaryNinja

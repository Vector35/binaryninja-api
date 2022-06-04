#pragma once
#include <string>
#include <vector>
#include "pluginmanager.h"
#include "refcount.hpp"

namespace BinaryNinja {
	typedef BNPluginOrigin PluginOrigin;
	typedef BNPluginStatus PluginStatus;
	typedef BNPluginType PluginType;

	class RepoPlugin : public CoreRefCountObject<BNRepoPlugin, BNNewPluginReference, BNFreePlugin>
	{
	  public:
		RepoPlugin(BNRepoPlugin* plugin);
		PluginStatus GetPluginStatus() const;
		std::vector<std::string> GetApis() const;
		std::vector<std::string> GetInstallPlatforms() const;
		std::string GetPath() const;
		std::string GetSubdir() const;
		std::string GetDependencies() const;
		std::string GetPluginDirectory() const;
		std::string GetAuthor() const;
		std::string GetDescription() const;
		std::string GetLicense() const;
		std::string GetLicenseText() const;
		std::string GetLongdescription() const;
		std::string GetName() const;
		std::vector<PluginType> GetPluginTypes() const;
		std::string GetPackageUrl() const;
		std::string GetProjectUrl() const;
		std::string GetAuthorUrl() const;
		std::string GetVersion() const;
		std::string GetCommit() const;
		std::string GetRepository() const;
		std::string GetProjectData();
		std::string GetInstallInstructions(const std::string& platform) const;
		uint64_t GetMinimumVersion() const;
		uint64_t GetLastUpdate();
		bool IsBeingDeleted() const;
		bool IsBeingUpdated() const;
		bool IsInstalled() const;
		bool IsEnabled() const;
		bool IsRunning() const;
		bool IsUpdatePending() const;
		bool IsDisablePending() const;
		bool IsDeletePending() const;
		bool IsUpdateAvailable() const;
		bool AreDependenciesBeingInstalled() const;

		bool Uninstall();
		bool Install();
		bool InstallDependencies();
		// `force` ignores optional checks for platform/api compliance
		bool Enable(bool force);
		bool Disable();
		bool Update();
	};

	class Repository : public CoreRefCountObject<BNRepository, BNNewRepositoryReference, BNFreeRepository>
	{
	  public:
		Repository(BNRepository* repository);
		std::string GetUrl() const;
		std::string GetRepoPath() const;
		std::string GetLocalReference() const;
		std::string GetRemoteReference() const;
		std::vector<Ref<RepoPlugin>> GetPlugins() const;
		std::string GetPluginDirectory() const;
		Ref<RepoPlugin> GetPluginByPath(const std::string& pluginPath);
		std::string GetFullPath() const;
	};

	class RepositoryManager :
	    public CoreRefCountObject<BNRepositoryManager, BNNewRepositoryManagerReference, BNFreeRepositoryManager>
	{
	  public:
		RepositoryManager(const std::string& enabledPluginsPath);
		RepositoryManager(BNRepositoryManager* repoManager);
		RepositoryManager();
		bool CheckForUpdates();
		std::vector<Ref<Repository>> GetRepositories();
		Ref<Repository> GetRepositoryByPath(const std::string& repoName);
		bool AddRepository(const std::string& url,  // URL to raw plugins.json file
		    const std::string& repoPath);           // Relative path within the repositories directory
		Ref<Repository> GetDefaultRepository();
	};
}
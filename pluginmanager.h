#pragma once

#include "binaryninja_defs.h"

extern "C" {
	struct BNRepoPlugin;
	struct BNRepository;
	struct BNRepositoryManager;

	enum BNPluginOrigin
	{
		OfficialPluginOrigin,
		CommunityPluginOrigin,
		OtherPluginOrigin
	};

	enum BNPluginStatus
	{
		NotInstalledPluginStatus = 0x00000000,
		InstalledPluginStatus = 0x00000001,
		EnabledPluginStatus = 0x00000002,
		UpdateAvailablePluginStatus = 0x00000010,
		DeletePendingPluginStatus = 0x00000020,
		UpdatePendingPluginStatus = 0x00000040,
		DisablePendingPluginStatus = 0x00000080,
		PendingRestartPluginStatus = 0x00000200,
		BeingUpdatedPluginStatus = 0x00000400,
		BeingDeletedPluginStatus = 0x00000800,
		DependenciesBeingInstalledStatus = 0x00001000
	};

	enum BNPluginType
	{
		CorePluginType,
		UiPluginType,
		ArchitecturePluginType,
		BinaryViewPluginType,
		HelperPluginType
	};


	// Plugin repository APIs
	BINARYNINJACOREAPI char** BNPluginGetApis(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI const char* BNPluginGetAuthor(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetDescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLicense(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLicenseText(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetLongdescription(BNRepoPlugin* p);
	BINARYNINJACOREAPI uint64_t BNPluginGetMinimumVersion(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetName(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetProjectUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetPackageUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetAuthorUrl(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetVersion(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetCommit(BNRepoPlugin* p);
	BINARYNINJACOREAPI void BNFreePluginTypes(BNPluginType* r);
	BINARYNINJACOREAPI BNRepoPlugin* BNNewPluginReference(BNRepoPlugin* r);
	BINARYNINJACOREAPI void BNFreePlugin(BNRepoPlugin* plugin);
	BINARYNINJACOREAPI const char* BNPluginGetPath(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetSubdir(BNRepoPlugin* p);
	BINARYNINJACOREAPI const char* BNPluginGetDependencies(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsInstalled(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsEnabled(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginStatus BNPluginGetPluginStatus(BNRepoPlugin* p);
	BINARYNINJACOREAPI BNPluginType* BNPluginGetPluginTypes(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI bool BNPluginEnable(BNRepoPlugin* p, bool force);
	BINARYNINJACOREAPI bool BNPluginDisable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginInstall(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginInstallDependencies(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginUninstall(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginUpdate(BNRepoPlugin* p);
	BINARYNINJACOREAPI char* BNPluginGetInstallInstructions(BNRepoPlugin* p, const char* platform);
	BINARYNINJACOREAPI char** BNPluginGetPlatforms(BNRepoPlugin* p, size_t* count);
	BINARYNINJACOREAPI void BNFreePluginPlatforms(char** platforms, size_t count);
	BINARYNINJACOREAPI const char* BNPluginGetRepository(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsBeingDeleted(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsBeingUpdated(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsRunning(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsUpdatePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsDisablePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsDeletePending(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginIsUpdateAvailable(BNRepoPlugin* p);
	BINARYNINJACOREAPI bool BNPluginAreDependenciesBeingInstalled(BNRepoPlugin* p);

	BINARYNINJACOREAPI char* BNPluginGetProjectData(BNRepoPlugin* p);
	BINARYNINJACOREAPI uint64_t BNPluginGetLastUpdate(BNRepoPlugin* p);

	BINARYNINJACOREAPI BNRepository* BNNewRepositoryReference(BNRepository* r);
	BINARYNINJACOREAPI void BNFreeRepository(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetUrl(BNRepository* r);
	BINARYNINJACOREAPI char* BNRepositoryGetRepoPath(BNRepository* r);
	BINARYNINJACOREAPI BNRepoPlugin** BNRepositoryGetPlugins(BNRepository* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryPluginList(BNRepoPlugin** r);
	BINARYNINJACOREAPI void BNRepositoryFreePluginDirectoryList(char** list, size_t count);
	BINARYNINJACOREAPI BNRepoPlugin* BNRepositoryGetPluginByPath(BNRepository* r, const char* pluginPath);
	BINARYNINJACOREAPI const char* BNRepositoryGetPluginsPath(BNRepository* r);

	BINARYNINJACOREAPI BNRepositoryManager* BNCreateRepositoryManager(const char* enabledPluginsPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNNewRepositoryManagerReference(BNRepositoryManager* r);
	BINARYNINJACOREAPI void BNFreeRepositoryManager(BNRepositoryManager* r);
	BINARYNINJACOREAPI bool BNRepositoryManagerCheckForUpdates(BNRepositoryManager* r);
	BINARYNINJACOREAPI BNRepository** BNRepositoryManagerGetRepositories(BNRepositoryManager* r, size_t* count);
	BINARYNINJACOREAPI void BNFreeRepositoryManagerRepositoriesList(BNRepository** r);
	BINARYNINJACOREAPI bool BNRepositoryManagerAddRepository(
		BNRepositoryManager* r, const char* url, const char* repoPath);
	BINARYNINJACOREAPI BNRepository* BNRepositoryGetRepositoryByPath(BNRepositoryManager* r, const char* repoPath);
	BINARYNINJACOREAPI BNRepositoryManager* BNGetRepositoryManager();

	BINARYNINJACOREAPI BNRepository* BNRepositoryManagerGetDefaultRepository(BNRepositoryManager* r);
}
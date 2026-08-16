#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

#define RETURN_STRING(s) \
	do \
	{ \
		char* contents = (char*)(s); \
		string result(contents ? contents : ""); \
		BNFreeString(contents); \
		return result; \
	} while (0)

Extension::Extension(BNPlugin* plugin)
{
	m_object = plugin;
}

string Extension::GetPath() const
{
	RETURN_STRING(BNPluginGetPath(m_object));
}

string Extension::GetSubdir() const
{
	RETURN_STRING(BNPluginGetSubdir(m_object));
}

string Extension::GetDependencies() const
{
	RETURN_STRING(BNPluginGetDependencies(m_object));
}

string Extension::GetPluginDirectory() const
{
	// v2 manifests do not expose a separate plugin-directory field
	return GetPath();
}

bool Extension::IsInstalled() const
{
	return BNPluginIsInstalled(m_object);
}


bool Extension::IsListed() const
{
	return BNPluginIsListed(m_object);
}


bool Extension::IsDeprecated() const
{
	return BNPluginIsDeprecated(m_object);
}

bool Extension::IsEnabled() const
{
	return BNPluginIsEnabled(m_object);
}

PluginStatus Extension::GetPluginStatus() const
{
	return BNPluginGetPluginStatus(m_object);
}

vector<string> Extension::GetApis() const
{
	vector<string> result;
	size_t count = 0;
	char** apis = BNPluginGetApis(m_object, &count);
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(apis[i]);

	BNFreeStringList(apis, count);
	return result;
}

vector<string> Extension::GetInstallPlatforms() const
{
	vector<string> result;
	size_t count = 0;
	char** platforms = BNPluginGetPlatforms(m_object, &count);
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(platforms[i]);
	BNFreePluginPlatforms(platforms, count);
	return result;
}

string Extension::GetAuthor() const
{
	RETURN_STRING(BNPluginGetAuthor(m_object));
}

string Extension::GetDescription() const
{
	RETURN_STRING(BNPluginGetDescription(m_object));
}

string Extension::GetLicenseText() const
{
	RETURN_STRING(BNPluginGetLicenseText(m_object));
}

static VersionInfo ConvertVersionInfo(const BNVersionInfo& coreInfo)
{
	VersionInfo result;
	result.major = coreInfo.major;
	result.minor = coreInfo.minor;
	result.build = coreInfo.build;
	result.channel = coreInfo.channel ? coreInfo.channel : "";
	return result;
}

VersionInfo Extension::GetMinimumVersionInfo() const
{
	auto coreInfo = BNPluginGetMinimumVersionInfo(m_object);
	VersionInfo result = ConvertVersionInfo(coreInfo);
	BNFreeString(coreInfo.channel);
	return result;
}

VersionInfo Extension::GetMaximumVersionInfo() const
{
	auto coreInfo = BNPluginGetMaximumVersionInfo(m_object);
	VersionInfo result = ConvertVersionInfo(coreInfo);
	BNFreeString(coreInfo.channel);
	return result;
}

static ExtensionVersion::PlatformInfo ConvertVersionPlatform(const BNPluginVersionPlatform& corePlatform)
{
	ExtensionVersion::PlatformInfo result;
	result.name = corePlatform.name ? corePlatform.name : "";
	result.downloadUrl = corePlatform.downloadUrl ? corePlatform.downloadUrl : "";
	result.untrackedDownloadUrl = corePlatform.untrackedDownloadUrl ? corePlatform.untrackedDownloadUrl : "";
	return result;
}

string Extension::GetName() const
{
	RETURN_STRING(BNPluginGetName(m_object));
}

vector<PluginType> Extension::GetPluginTypes() const
{
	size_t count;
	BNPluginType* pluginTypesPtr = BNPluginGetPluginTypes(m_object, &count);
	vector<PluginType> pluginTypes;
	pluginTypes.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		pluginTypes.push_back((PluginType)pluginTypesPtr[i]);
	}
	BNFreePluginTypes(pluginTypesPtr);
	return pluginTypes;
}


string Extension::GetProjectUrl() const
{
	RETURN_STRING(BNPluginGetProjectUrl(m_object));
}

string Extension::GetPackageUrl() const
{
	RETURN_STRING(BNPluginGetPackageUrl(m_object));
}

string Extension::GetAuthorUrl() const
{
	RETURN_STRING(BNPluginGetAuthorUrl(m_object));
}


std::vector<ExtensionVersion> Extension::GetVersions() const
{
	size_t count;
	BNPluginVersion* versionsPtr = BNPluginGetVersions(m_object, &count);
	std::vector<ExtensionVersion> versions;
	for (size_t i = 0; i < count; i++)
	{
		ExtensionVersion version;
		version.id = versionsPtr[i].id ? versionsPtr[i].id : "";
		version.version = versionsPtr[i].versionString ? versionsPtr[i].versionString :
		    "";
		version.longDescription = versionsPtr[i].longDescription ? versionsPtr[i].longDescription : "";
		version.changelog = versionsPtr[i].changelog ? versionsPtr[i].changelog : "";
		version.subdir = versionsPtr[i].subdir ? versionsPtr[i].subdir : "";
		version.dependencies = versionsPtr[i].dependencies ? versionsPtr[i].dependencies : "";
		version.minimumClientVersion = versionsPtr[i].minimumClientVersion;
		version.platforms.reserve(versionsPtr[i].platformCount);
		for (size_t j = 0; j < versionsPtr[i].platformCount; j++)
			version.platforms.push_back(ConvertVersionPlatform(versionsPtr[i].platforms[j]));
		version.created = versionsPtr[i].created ? versionsPtr[i].created : "";
		versions.push_back(version);
	}
	BNFreePluginVersions(versionsPtr, count);
	return versions;
}


ExtensionVersion Extension::GetCurrentVersion() const
{
	ExtensionVersion version;
	BNPluginVersion currentVersion = BNPluginGetCurrentVersion(m_object);
	version.id = currentVersion.id ? currentVersion.id : "";
	version.version = currentVersion.versionString ? currentVersion.versionString : "";
	version.longDescription = currentVersion.longDescription ? currentVersion.longDescription : "";
	version.changelog = currentVersion.changelog ? currentVersion.changelog : "";
	version.subdir = currentVersion.subdir ? currentVersion.subdir : "";
	version.dependencies = currentVersion.dependencies ? currentVersion.dependencies : "";
	version.minimumClientVersion = currentVersion.minimumClientVersion;
	version.platforms.reserve(currentVersion.platformCount);
	for (size_t i = 0; i < currentVersion.platformCount; i++)
		version.platforms.push_back(ConvertVersionPlatform(currentVersion.platforms[i]));
	version.created = currentVersion.created ? currentVersion.created : "";
	BNPluginFreeVersion(currentVersion);
	return version;
}


std::string Extension::GetCurrentVersionID() const
{
	RETURN_STRING(BNPluginGetCurrentVersionID(m_object));
}


std::string Extension::GetLatestVersionID() const
{
	RETURN_STRING(BNPluginGetLatestVersionID(m_object));
}


bool Extension::IsVersionIDLessThan(const std::string& smaller, const std::string& larger) const
{
	return BNPluginVersionIDLessThan(m_object, smaller.c_str(), larger.c_str());
}

string Extension::GetCommit() const
{
	RETURN_STRING(BNPluginGetCommit(m_object));
}


bool Extension::IsViewOnly() const
{
	return BNPluginGetViewOnly(m_object);
}


bool Extension::IsPaid() const
{
	return BNPluginGetIsPaid(m_object);
}


string Extension::GetRepository() const
{
	RETURN_STRING(BNPluginGetRepository(m_object));
}


bool Extension::IsBeingDeleted() const
{
	return BNPluginIsBeingDeleted(m_object);
}

bool Extension::IsBeingUpdated() const
{
	return BNPluginIsBeingUpdated(m_object);
}

bool Extension::IsRunning() const
{
	return BNPluginIsRunning(m_object);
}


bool Extension::IsUpdatePending() const
{
	return BNPluginIsUpdatePending(m_object);
}


bool Extension::IsDisablePending() const
{
	return BNPluginIsDisablePending(m_object);
}


bool Extension::IsDeletePending() const
{
	return BNPluginIsDeletePending(m_object);
}


bool Extension::IsUpdateAvailable() const
{
	return BNPluginIsUpdateAvailable(m_object);
}


bool Extension::AreDependenciesBeingInstalled() const
{
	return BNPluginAreDependenciesBeingInstalled(m_object);
}

string Extension::GetCreationDate()
{
	RETURN_STRING(BNPluginGetCurrentVersionCreationDate(m_object));
}

string Extension::GetProjectData()
{
	RETURN_STRING(BNPluginGetProjectData(m_object));
}


bool Extension::Uninstall()
{
	return BNPluginUninstall(m_object);
}


bool Extension::CancelUninstall()
{
	return BNPluginCancelUninstall(m_object);
}


bool Extension::Install(std::string versionID)
{
	char* versionIDStr = BNAllocString(versionID.c_str());
	auto success = BNPluginInstall(m_object, versionIDStr);
	BNFreeString(versionIDStr);
	return success;
}


bool Extension::InstallDependencies()
{
	return BNPluginInstallDependencies(m_object);
}

bool Extension::InstallDependencies(const std::string& versionID)
{
	return BNPluginInstallDependenciesForVersion(m_object, versionID.c_str());
}


bool Extension::Enable(bool force)
{
	return BNPluginEnable(m_object, force);
}


bool Extension::Update(std::string versionID)
{
	char* versionIDStr = BNAllocString(versionID.c_str());
	auto success = BNPluginUpdate(m_object, versionIDStr);
	BNFreeString(versionIDStr);
	return success;
}


bool Extension::Disable()
{
	return BNPluginDisable(m_object);
}


Repository::Repository(BNRepository* r)
{
	m_object = r;
}

string Repository::GetUrl() const
{
	RETURN_STRING(BNRepositoryGetUrl(m_object));
}


string Repository::GetRepoPath() const
{
	RETURN_STRING(BNRepositoryGetRepoPath(m_object));
}

string Repository::GetLocalReference() const
{
	// v2 manifests do not expose legacy git references
	return "";
}

string Repository::GetRemoteReference() const
{
	// v2 manifests do not expose legacy git references
	return "";
}


vector<Ref<Extension>> Repository::GetPlugins() const
{
	vector<Ref<Extension>> plugins;
	size_t count = 0;
	BNPlugin** pluginsPtr = BNRepositoryGetPlugins(m_object, &count);
	plugins.reserve(count);
	for (size_t i = 0; i < count; i++)
		plugins.push_back(new Extension(BNNewPluginReference(pluginsPtr[i])));
	BNFreeRepositoryPluginList(pluginsPtr);
	return plugins;
}


Ref<Extension> Repository::GetPluginByPath(const string& pluginPath)
{
	BNPlugin* plugin = BNRepositoryGetPluginByPath(m_object, pluginPath.c_str());
	if (!plugin)
		return nullptr;
	return new Extension(plugin);
}

string Repository::GetFullPath() const
{
	RETURN_STRING(BNRepositoryGetPluginsPath(m_object));
}

string Repository::GetPluginDirectory() const
{
	return GetFullPath();
}

bool RepositoryManager::CheckForUpdates()
{
	return BNRepositoryManagerCheckForUpdates();
}

vector<Ref<Repository>> RepositoryManager::GetRepositories()
{
	vector<Ref<Repository>> repos;
	size_t count = 0;
	BNRepository** reposPtr = BNRepositoryManagerGetRepositories(&count);
	for (size_t i = 0; i < count; i++)
		repos.push_back(new Repository(BNNewRepositoryReference(reposPtr[i])));
	BNFreeRepositoryManagerRepositoriesList(reposPtr);
	return repos;
}

bool RepositoryManager::AddRepository(const std::string& url,
    const std::string& repoPath)  // Relative path within the channels directory
{
	return BNRepositoryManagerAddRepository(url.c_str(), repoPath.c_str());
}

Ref<Repository> RepositoryManager::GetRepositoryByPath(const std::string& repoPath)
{
	BNRepository* repo = BNRepositoryGetRepositoryByPath(repoPath.c_str());
	if (!repo)
		return nullptr;
	return new Repository(repo);
}

Ref<Repository> RepositoryManager::GetDefaultRepository()
{
	BNRepository* repo = BNRepositoryManagerGetDefaultRepository();
	if (!repo)
		return nullptr;
	return new Repository(repo);
}

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

#define RETURN_STRING(s) do { \
	char* contents = (char*)(s); \
	string result(contents); \
	BNFreeString(contents); \
	return result; \
}while(0)

RepoPlugin::RepoPlugin(BNRepoPlugin* plugin)
{
	m_object = plugin;
}

string RepoPlugin::GetPath() const
{
	RETURN_STRING(BNPluginGetPath(m_object));
}

bool RepoPlugin::IsInstalled() const
{
	return BNPluginIsInstalled(m_object);
}

void RepoPlugin::SetEnabled(bool enabled)
{
	return BNPluginSetEnabled(m_object, enabled);
}

bool RepoPlugin::IsEnabled() const
{
	return BNPluginIsEnabled(m_object);
}

PluginUpdateStatus RepoPlugin::GetPluginUpdateStatus() const
{
	return BNPluginGetPluginUpdateStatus(m_object);
}

string RepoPlugin::GetApi() const
{
	RETURN_STRING(BNPluginGetApi(m_object));
}

string RepoPlugin::GetAuthor() const
{
	RETURN_STRING(BNPluginGetAuthor(m_object));
}

string RepoPlugin::GetDescription() const
{
	RETURN_STRING(BNPluginGetDescription(m_object));
}

string RepoPlugin::GetLicense() const
{
	RETURN_STRING(BNPluginGetLicense(m_object));
}

string RepoPlugin::GetLicenseText() const
{
	RETURN_STRING(BNPluginGetLicenseText(m_object));
}

string RepoPlugin::GetLongdescription() const
{
	RETURN_STRING(BNPluginGetLongdescription(m_object));
}

string RepoPlugin::GetMinimimVersions() const
{
	RETURN_STRING(BNPluginGetMinimimVersions(m_object));
}

string RepoPlugin::GetName() const
{
	RETURN_STRING(BNPluginGetName(m_object));
}

vector<PluginType> RepoPlugin::GetPluginTypes() const
{
	size_t count;
	BNPluginType* pluginTypesPtr = BNPluginGetPluginTypes(m_object, &count);
	vector<PluginType> pluginTypes;
	for (size_t i = 0; i < count; i++)
	{
		pluginTypes.push_back((PluginType)pluginTypesPtr[i]);
	}
	BNFreePluginTypes(pluginTypesPtr);
	return pluginTypes;
}

string RepoPlugin::GetUrl() const
{
	RETURN_STRING(BNPluginGetUrl(m_object));
}

string RepoPlugin::GetVersion() const
{
	RETURN_STRING(BNPluginGetVersion(m_object));
}

Repository::Repository(BNRepository* r)
{
	m_object = r;
}

Repository::~Repository()
{
	BNFreeRepository(m_object);
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
	RETURN_STRING(BNRepositoryGetLocalReference(m_object));
}

string Repository::GetRemoteReference() const
{
	RETURN_STRING(BNRepositoryGetRemoteReference(m_object));
}

vector<Ref<RepoPlugin>> Repository::GetPlugins() const
{
	vector<Ref<RepoPlugin>> plugins;
	size_t count = 0;
	BNRepoPlugin** pluginsPtr = BNRepositoryGetPlugins(m_object, &count);
	for (size_t i = 0; i < count; i++)
		plugins.push_back(new RepoPlugin(BNNewPluginReference(pluginsPtr[i])));
	BNFreeRepositoryPluginList(pluginsPtr);
	return plugins;
}

bool Repository::IsInitialized() const
{
	return BNRepositoryIsInitialized(m_object);
}

Ref<RepoPlugin> Repository::GetPluginByPath(const string& pluginPath)
{
	return new RepoPlugin(BNNewPluginReference(BNRepositoryGetPluginByPath(m_object, pluginPath.c_str())));
}

string Repository::GetFullPath() const
{
	RETURN_STRING(BNRepositoryGetPluginsPath(m_object));
}

RepositoryManager::RepositoryManager(const string& enabledPluginsPath)
	:m_core(false)
{
	m_object = BNCreateRepositoryManager(enabledPluginsPath.c_str());
}

RepositoryManager::RepositoryManager(BNRepositoryManager* mgr)
	:m_core(false)
{
	m_object = mgr;
}

RepositoryManager::RepositoryManager()
	:m_core(true)
{
	m_object = BNGetRepositoryManager();
}

RepositoryManager::~RepositoryManager()
{
	if (!m_core)
		BNFreeRepositoryManager(m_object);
}

bool RepositoryManager::CheckForUpdates()
{
	return BNRepositoryManagerCheckForUpdates(m_object);
}

vector<Ref<Repository>> RepositoryManager::GetRepositories()
{
	vector<Ref<Repository>> repos;
	size_t count = 0;
	BNRepository** reposPtr = BNRepositoryManagerGetRepositories(m_object, &count);
	for (size_t i = 0; i < count; i++)
		repos.push_back(new Repository(BNNewRepositoryReference(reposPtr[i])));
	BNFreeRepositoryManagerRepositoriesList(reposPtr);
	return repos;
}

bool RepositoryManager::AddRepository(const std::string& url,
	const std::string& repoPath, // Relative path within the repositories directory
	const std::string& localReference,
	const std::string& remoteReference)
{
	return BNRepositoryManagerAddRepository(m_object,
		url.c_str(),
		repoPath.c_str(),
		localReference.c_str(),
		remoteReference.c_str());
}

Ref<Repository> RepositoryManager::GetRepositoryByPath(const std::string& repoPath)
{
	return new Repository(BNNewRepositoryReference(BNRepositoryGetRepositoryByPath(m_object, repoPath.c_str())));
}

Ref<Repository> RepositoryManager::GetDefaultRepository()
{
	return new Repository(BNNewRepositoryReference(BNRepositoryManagerGetDefaultRepository(m_object)));
}

# Copyright (c) 2015-2023 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import ctypes
import json
from datetime import datetime, date
from typing import List, Dict, Optional

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from .enums import PluginType


class RepoPlugin:
	"""
	``RepoPlugin`` is mostly read-only, however you can install/uninstall enable/disable plugins. RepoPlugins are
	created by parsing the plugins.json in a plugin repository.
	"""
	def __init__(self, handle: core.BNRepoPluginHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreePlugin(self.handle)

	def __repr__(self):
		return f"<{self.path} {'installed' if self.installed else 'not-installed'}/{'enabled' if self.enabled else 'disabled'}>"

	@property
	def path(self) -> str:
		"""Relative path from the base of the repository to the actual plugin"""
		result = core.BNPluginGetPath(self.handle)
		assert result is not None, "core.BNPluginGetPath returned None"
		return result

	@property
	def subdir(self) -> str:
		"""Optional sub-directory the plugin code lives in as a relative path from the plugin root"""
		result = core.BNPluginGetSubdir(self.handle)
		assert result is not None, "core.BNPluginGetSubdir returned None"
		return result

	@property
	def dependencies(self) -> str:
		"""Dependencies required for installing this plugin"""
		result = core.BNPluginGetDependencies(self.handle)
		assert result is not None, "core.BNPluginGetDependencies returned None"
		return result

	@property
	def installed(self) -> bool:
		"""Boolean True if the plugin is installed, False otherwise"""
		return core.BNPluginIsInstalled(self.handle)

	def install(self) -> bool:
		"""Attempt to install the given plugin"""
		self.install_dependencies()
		return core.BNPluginInstall(self.handle)

	def uninstall(self) -> bool:
		"""Attempt to uninstall the given plugin"""
		return core.BNPluginUninstall(self.handle)

	@installed.setter
	def installed(self, state: bool):
		if state:
			self.install_dependencies()
			core.BNPluginInstall(self.handle)
		else:
			core.BNPluginUninstall(self.handle)

	def install_dependencies(self) -> bool:
		return core.BNPluginInstallDependencies(self.handle)

	@property
	def enabled(self) -> bool:
		"""Boolean True if the plugin is currently enabled, False otherwise"""
		return core.BNPluginIsEnabled(self.handle)

	@enabled.setter
	def enabled(self, state: bool):
		if state:
			core.BNPluginEnable(self.handle, False)
		else:
			core.BNPluginDisable(self.handle)

	def enable(self, force: bool = False) -> bool:
		"""
		Enable this plugin, optionally trying to force it. \
		Force loading a plugin with ignore platform and api constraints. \
		 (e.g. The plugin author says the plugin will only work on Linux-python3 but you'd like to \
		 attempt to load it on Macos-python2)
		"""
		return core.BNPluginEnable(self.handle, force)

	@property
	def api(self) -> List[str]:
		"""String indicating the API used by the plugin"""
		result: List[str] = []
		count = ctypes.c_ulonglong(0)
		platforms = core.BNPluginGetApis(self.handle, count)
		assert platforms is not None, "core.BNPluginGetApis returned None"
		try:
			for i in range(count.value):
				result.append(platforms[i].decode("utf-8"))
			return result
		finally:
			core.BNFreePluginPlatforms(platforms, count.value)

	@property
	def description(self) -> Optional[str]:
		"""String short description of the plugin"""
		return core.BNPluginGetDescription(self.handle)

	@property
	def license(self) -> Optional[str]:
		"""String short license description (ie MIT, BSD, GPLv2, etc)"""
		return core.BNPluginGetLicense(self.handle)

	@property
	def license_text(self) -> Optional[str]:
		"""String complete license text for the given plugin"""
		return core.BNPluginGetLicenseText(self.handle)

	@property
	def long_description(self) -> Optional[str]:
		"""String long description of the plugin"""
		return core.BNPluginGetLongdescription(self.handle)

	@property
	def minimum_version(self) -> int:
		"""String minimum version the plugin was tested on"""
		return core.BNPluginGetMinimumVersion(self.handle)

	@property
	def name(self) -> str:
		"""String name of the plugin"""
		result = core.BNPluginGetName(self.handle)
		assert result is not None, "core.BNPluginGetName returned None"
		return result

	@property
	def plugin_types(self) -> List[PluginType]:
		"""List of PluginType enumeration objects indicating the plugin type(s)"""
		result = []
		count = ctypes.c_ulonglong(0)
		plugintypes = core.BNPluginGetPluginTypes(self.handle, count)
		assert plugintypes is not None, "core.BNPluginGetPluginTypes returned None"
		try:
			for i in range(count.value):
				result.append(PluginType(plugintypes[i]))
			return result
		finally:
			core.BNFreePluginTypes(plugintypes)

	@property
	def project_url(self) -> Optional[str]:
		"""String URL of the plugin's git repository"""
		return core.BNPluginGetProjectUrl(self.handle)

	@property
	def package_url(self) -> Optional[str]:
		"""String URL of the plugin's zip file"""
		return core.BNPluginGetPackageUrl(self.handle)

	@property
	def author_url(self) -> Optional[str]:
		"""String URL of the plugin author's url"""
		return core.BNPluginGetAuthorUrl(self.handle)

	@property
	def author(self) -> Optional[str]:
		"""String of the plugin author"""
		return core.BNPluginGetAuthor(self.handle)

	@property
	def version(self) -> Optional[str]:
		"""String version of the plugin"""
		return core.BNPluginGetVersion(self.handle)

	def install_instructions(self, platform: str) -> Optional[str]:
		"""
		Installation instructions for the given platform

		:param str platform: One of the valid platforms "Windows", "Linux", "Darwin"
		:return: String of the installation instructions for the provided platform
		:rtype: str
		"""
		return core.BNPluginGetInstallInstructions(self.handle, platform)

	@property
	def install_platforms(self) -> List[str]:
		"""List of platforms this plugin can execute on"""
		result = []
		count = ctypes.c_ulonglong(0)
		platforms = core.BNPluginGetPlatforms(self.handle, count)
		assert platforms is not None, "core.BNPluginGetPlatforms returned None"
		try:
			for i in range(count.value):
				result.append(platforms[i].decode("utf-8"))
			return result
		finally:
			core.BNFreePluginPlatforms(platforms, count.value)

	@property
	def being_deleted(self) -> bool:
		"""Boolean status indicating that the plugin is being deleted"""
		return core.BNPluginIsBeingDeleted(self.handle)

	@property
	def being_updated(self) -> bool:
		"""Boolean status indicating that the plugin is being updated"""
		return core.BNPluginIsBeingUpdated(self.handle)

	@property
	def running(self) -> bool:
		"""Boolean status indicating that the plugin is currently running"""
		return core.BNPluginIsRunning(self.handle)

	@property
	def update_pending(self) -> bool:
		"""Boolean status indicating that the plugin has updates will be installed after the next restart"""
		return core.BNPluginIsUpdatePending(self.handle)

	@property
	def disable_pending(self) -> bool:
		"""Boolean status indicating that the plugin will be disabled after the next restart"""
		return core.BNPluginIsDisablePending(self.handle)

	@property
	def delete_pending(self) -> bool:
		"""Boolean status indicating that the plugin will be deleted after the next restart"""
		return core.BNPluginIsDeletePending(self.handle)

	@property
	def update_available(self) -> bool:
		"""Boolean status indicating that the plugin has updates available"""
		return core.BNPluginIsUpdateAvailable(self.handle)

	@property
	def dependencies_being_installed(self) -> bool:
		"""Boolean status indicating that the plugin's dependencies are currently being installed"""
		return core.BNPluginAreDependenciesBeingInstalled(self.handle)

	@property
	def project_data(self) -> Dict:
		"""Gets a json object of the project data field"""
		data = core.BNPluginGetProjectData(self.handle)
		assert data is not None, "core.BNPluginGetProjectData returned None"
		return json.loads(data)

	@property
	def last_update(self) -> date:
		"""Returns a datetime object representing the plugins last update"""
		return datetime.fromtimestamp(core.BNPluginGetLastUpdate(self.handle))


class Repository:
	"""
	``Repository`` is a read-only class. Use RepositoryManager to Enable/Disable/Install/Uninstall plugins.
	"""
	def __init__(self, handle: core.BNRepositoryHandle) -> None:
		self.handle = handle

	def __del__(self) -> None:
		if core is not None:
			core.BNFreeRepository(self.handle)

	def __repr__(self) -> str:
		return f"<Repository: {self.path}>"

	def __getitem__(self, plugin_path: str):
		for plugin in self.plugins:
			if plugin_path == plugin.path:
				return plugin
		raise KeyError()

	@property
	def url(self) -> str:
		"""String URL of the git repository where the plugin repository's are stored"""
		result = core.BNRepositoryGetUrl(self.handle)
		assert result is not None
		return result

	@property
	def path(self) -> str:
		"""String local path to store the given plugin repository"""
		result = core.BNRepositoryGetRepoPath(self.handle)
		assert result is not None
		return result

	@property
	def full_path(self) -> str:
		"""String full path the repository"""
		result = core.BNRepositoryGetPluginsPath(self.handle)
		assert result is not None
		return result

	@property
	def plugins(self) -> List[RepoPlugin]:
		"""List of RepoPlugin objects contained within this repository"""
		pluginlist = []
		count = ctypes.c_ulonglong(0)
		result = core.BNRepositoryGetPlugins(self.handle, count)
		assert result is not None, "core.BNRepositoryGetPlugins returned None"
		try:
			for i in range(count.value):
				plugin_ref = core.BNNewPluginReference(result[i])
				assert plugin_ref is not None, "core.BNNewPluginReference returned None"
				pluginlist.append(RepoPlugin(plugin_ref))
			return pluginlist
		finally:
			core.BNFreeRepositoryPluginList(result)
			del result


class RepositoryManager:
	"""
	``RepositoryManager`` Keeps track of all the repositories and keeps the enabled_plugins.json file coherent with
	the plugins that are installed/uninstalled enabled/disabled
	"""
	def __init__(self):
		binaryninja._init_plugins()
		self.handle = core.BNGetRepositoryManager()

	def __getitem__(self, repo_path: str) -> Repository:
		for repo in self.repositories:
			if repo_path == repo.path:
				return repo
		raise KeyError()

	def check_for_updates(self) -> bool:
		"""Check for updates for all managed Repository objects"""
		return core.BNRepositoryManagerCheckForUpdates(self.handle)

	@property
	def repositories(self) -> List[Repository]:
		"""List of Repository objects being managed"""
		result = []
		count = ctypes.c_ulonglong(0)
		repos = core.BNRepositoryManagerGetRepositories(self.handle, count)
		assert repos is not None, "core.BNRepositoryManagerGetRepositories returned None"
		try:
			for i in range(count.value):
				repo_ref = core.BNNewRepositoryReference(repos[i])
				assert repo_ref is not None, "core.BNNewRepositoryReference returned None"
				result.append(Repository(repo_ref))
			return result
		finally:
			core.BNFreeRepositoryManagerRepositoriesList(repos)

	@property
	def plugins(self) -> Dict[str, List[RepoPlugin]]:
		"""List of all RepoPlugins in each repository"""
		plugin_list = {}
		for repo in self.repositories:
			plugin_list[repo.path] = repo.plugins
		return plugin_list

	@property
	def default_repository(self) -> Repository:
		"""Gets the default Repository"""
		repo_handle = core.BNRepositoryManagerGetDefaultRepository(self.handle)
		assert repo_handle is not None, "core.BNRepositoryManagerGetDefaultRepository returned None"
		repo_handle_ref = core.BNNewRepositoryReference(repo_handle)
		assert repo_handle_ref is not None, "core.BNNewRepositoryReference returned None"
		return Repository(repo_handle_ref)

	def add_repository(self, url: Optional[str] = None, repopath: Optional[str] = None) -> bool:
		"""
		``add_repository`` adds a new plugin repository for the manager to track.

		There is currently no function to remove a repository. If you want to
		remove a repository, you must delete the directory and remove the
		plugin_status.json entries from repositories/ file in the User Folder

		:param str url: URL to the plugins.json containing the records for this repository
		:param str repopath: path to where the repository will be stored on disk locally
		:return: Boolean value True if the repository was successfully added, False otherwise.
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.add_repository("https://raw.githubusercontent.com/Vector35/community-plugins/master/plugins.json", "community")
			True
			>>>
		"""
		if not isinstance(url, str) or not isinstance(repopath, str):
			raise ValueError("Expected url or repopath to be of type str.")

		return core.BNRepositoryManagerAddRepository(self.handle, url, repopath)

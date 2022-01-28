# Copyright (c) 2015-2022 Vector 35 Inc
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
from datetime import datetime

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from .enums import PluginType


class RepoPlugin:
	"""
	``RepoPlugin`` is mostly read-only, however you can install/uninstall enable/disable plugins. RepoPlugins are
	created by parsing the plugins.json in a plugin repository.
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNRepoPlugin)

	def __del__(self):
		if core is not None:
			core.BNFreePlugin(self.handle)

	def __repr__(self):
		return "<{} {}/{}>".format(
		    self.path, "installed" if self.installed else "not-installed", "enabled" if self.enabled else "disabled"
		)

	@property
	def path(self):
		"""Relative path from the base of the repository to the actual plugin"""
		return core.BNPluginGetPath(self.handle)

	@property
	def subdir(self):
		"""Optional sub-directory the plugin code lives in as a relative path from the plugin root"""
		return core.BNPluginGetSubdir(self.handle)

	@property
	def dependencies(self):
		"""Dependencies required for installing this plugin"""
		return core.BNPluginGetDependencies(self.handle)

	@property
	def installed(self):
		"""Boolean True if the plugin is installed, False otherwise"""
		return core.BNPluginIsInstalled(self.handle)

	def install(self):
		"""Attempt to install the given plugin"""
		self.install_dependencies()
		return core.BNPluginInstall(self.handle)

	def uninstall(self):
		"""Attempt to uninstall the given plugin"""
		return core.BNPluginUninstall(self.handle)

	@installed.setter
	def installed(self, state):
		if state:
			self.install_dependencies()
			return core.BNPluginInstall(self.handle)
		else:
			return core.BNPluginUninstall(self.handle)

	def install_dependencies(self):
		return core.BNPluginInstallDependencies(self.handle)

	@property
	def enabled(self):
		"""Boolean True if the plugin is currently enabled, False otherwise"""
		return core.BNPluginIsEnabled(self.handle)

	@enabled.setter
	def enabled(self, state):
		if state:
			return core.BNPluginEnable(self.handle, False)
		else:
			return core.BNPluginDisable(self.handle)

	def enable(self, force=False):
		"""
		Enable this plugin, optionally trying to force it. \
		Force loading a plugin with ignore platform and api constraints. \
		 (e.g. The plugin author says the plugin will only work on Linux-python3 but you'd like to \
		 attempt to load it on Macos-python2)
		"""
		return core.BNPluginEnable(self.handle, force)

	@property
	def api(self):
		"""String indicating the API used by the plugin"""
		result = []
		count = ctypes.c_ulonglong(0)
		platforms = core.BNPluginGetApis(self.handle, count)
		assert platforms is not None, "core.BNPluginGetApis returned None"
		for i in range(count.value):
			result.append(platforms[i].decode("utf-8"))
		core.BNFreePluginPlatforms(platforms, count.value)
		return result

	@property
	def description(self):
		"""String short description of the plugin"""
		return core.BNPluginGetDescription(self.handle)

	@property
	def license(self):
		"""String short license description (ie MIT, BSD, GPLv2, etc)"""
		return core.BNPluginGetLicense(self.handle)

	@property
	def license_text(self):
		"""String complete license text for the given plugin"""
		return core.BNPluginGetLicenseText(self.handle)

	@property
	def long_description(self):
		"""String long description of the plugin"""
		return core.BNPluginGetLongdescription(self.handle)

	@property
	def minimum_version(self):
		"""String minimum version the plugin was tested on"""
		return core.BNPluginGetMinimumVersion(self.handle)

	@property
	def name(self):
		"""String name of the plugin"""
		return core.BNPluginGetName(self.handle)

	@property
	def plugin_types(self):
		"""List of PluginType enumeration objects indicating the plugin type(s)"""
		result = []
		count = ctypes.c_ulonglong(0)
		plugintypes = core.BNPluginGetPluginTypes(self.handle, count)
		assert plugintypes is not None, "core.BNPluginGetPluginTypes returned None"
		for i in range(count.value):
			result.append(PluginType(plugintypes[i]))
		core.BNFreePluginTypes(plugintypes)
		return result

	@property
	def project_url(self):
		"""String URL of the plugin's git repository"""
		return core.BNPluginGetProjectUrl(self.handle)

	@property
	def package_url(self):
		"""String URL of the plugin's zip file"""
		return core.BNPluginGetPackageUrl(self.handle)

	@property
	def author_url(self):
		"""String URL of the plugin author's url"""
		return core.BNPluginGetAuthorUrl(self.handle)

	@property
	def author(self):
		"""String of the plugin author"""
		return core.BNPluginGetAuthor(self.handle)

	@property
	def version(self):
		"""String version of the plugin"""
		return core.BNPluginGetVersion(self.handle)

	def install_instructions(self, platform):
		"""
		Installation instructions for the given platform

		:param str platform: One of the valid platforms "Windows", "Linux", "Darwin"
		:return: String of the installation instructions for the provided platform
		:rtype: str
		"""
		return core.BNPluginGetInstallInstructions(self.handle, platform)

	@property
	def install_platforms(self):
		"""List of platforms this plugin can execute on"""
		result = []
		count = ctypes.c_ulonglong(0)
		platforms = core.BNPluginGetPlatforms(self.handle, count)
		assert platforms is not None, "core.BNPluginGetPlatforms returned None"
		for i in range(count.value):
			result.append(platforms[i].decode("utf-8"))
		core.BNFreePluginPlatforms(platforms, count.value)
		return result

	@property
	def being_deleted(self):
		"""Boolean status indicating that the plugin is being deleted"""
		return core.BNPluginIsBeingDeleted(self.handle)

	@property
	def being_updated(self):
		"""Boolean status indicating that the plugin is being updated"""
		return core.BNPluginIsBeingUpdated(self.handle)

	@property
	def running(self):
		"""Boolean status indicating that the plugin is currently running"""
		return core.BNPluginIsRunning(self.handle)

	@property
	def update_pending(self):
		"""Boolean status indicating that the plugin has updates will be installed after the next restart"""
		return core.BNPluginIsUpdatePending(self.handle)

	@property
	def disable_pending(self):
		"""Boolean status indicating that the plugin will be disabled after the next restart"""
		return core.BNPluginIsDisablePending(self.handle)

	@property
	def delete_pending(self):
		"""Boolean status indicating that the plugin will be deleted after the next restart"""
		return core.BNPluginIsDeletePending(self.handle)

	@property
	def update_available(self):
		"""Boolean status indicating that the plugin has updates available"""
		return core.BNPluginIsUpdateAvailable(self.handle)

	@property
	def dependencies_being_installed(self):
		"""Boolean status indicating that the plugin's dependencies are currently being installed"""
		return core.BNPluginAreDependenciesBeingInstalled(self.handle)

	@property
	def project_data(self):
		"""Gets a json object of the project data field"""
		return json.loads(core.BNPluginGetProjectData(self.handle))

	@property
	def last_update(self):
		"""Returns a datetime object representing the plugins last update"""
		return datetime.fromtimestamp(core.BNPluginGetLastUpdate(self.handle))


class Repository:
	"""
	``Repository`` is a read-only class. Use RepositoryManager to Enable/Disable/Install/Uninstall plugins.
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNRepository)

	def __del__(self):
		if core is not None:
			core.BNFreeRepository(self.handle)

	def __repr__(self):
		return "<{}>".format(self.path)

	def __getitem__(self, plugin_path):
		for plugin in self.plugins:
			if plugin_path == plugin.path:
				return plugin
		raise KeyError()

	@property
	def url(self):
		"""String URL of the git repository where the plugin repository's are stored"""
		return core.BNRepositoryGetUrl(self.handle)

	@property
	def path(self):
		"""String local path to store the given plugin repository"""
		return core.BNRepositoryGetRepoPath(self.handle)

	@property
	def full_path(self):
		"""String full path the repository"""
		return core.BNRepositoryGetPluginsPath(self.handle)

	@property
	def plugins(self):
		"""List of RepoPlugin objects contained within this repository"""
		pluginlist = []
		count = ctypes.c_ulonglong(0)
		result = core.BNRepositoryGetPlugins(self.handle, count)
		assert result is not None, "core.BNRepositoryGetPlugins returned None"
		for i in range(count.value):
			pluginlist.append(RepoPlugin(core.BNNewPluginReference(result[i])))
		core.BNFreeRepositoryPluginList(result)
		del result
		return pluginlist


class RepositoryManager:
	"""
	``RepositoryManager`` Keeps track of all the repositories and keeps the enabled_plugins.json file coherent with
	the plugins that are installed/uninstalled enabled/disabled
	"""
	def __init__(self, handle=None):
		self.handle = core.BNGetRepositoryManager()

	def __getitem__(self, repo_path):
		for repo in self.repositories:
			if repo_path == repo.path:
				return repo
		raise KeyError()

	def check_for_updates(self):
		"""Check for updates for all managed Repository objects"""
		return core.BNRepositoryManagerCheckForUpdates(self.handle)

	@property
	def repositories(self):
		"""List of Repository objects being managed"""
		result = []
		count = ctypes.c_ulonglong(0)
		repos = core.BNRepositoryManagerGetRepositories(self.handle, count)
		assert repos is not None, "core.BNRepositoryManagerGetRepositories returnedNone"
		for i in range(count.value):
			result.append(Repository(core.BNNewRepositoryReference(repos[i])))
		core.BNFreeRepositoryManagerRepositoriesList(repos)
		return result

	@property
	def plugins(self):
		"""List of all RepoPlugins in each repository"""
		plugin_list = {}
		for repo in self.repositories:
			plugin_list[repo.path] = repo.plugins
		return plugin_list

	@property
	def default_repository(self):
		"""Gets the default Repository"""
		binaryninja._init_plugins()
		return Repository(core.BNNewRepositoryReference(core.BNRepositoryManagerGetDefaultRepository(self.handle)))

	def add_repository(self, url=None, repopath=None):
		"""
		``add_repository`` adds a new plugin repository for the manager to track.

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
			raise ValueError("Parameter is incorrect type")

		return core.BNRepositoryManagerAddRepository(self.handle, url, repopath)

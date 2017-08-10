# Copyright (c) 2015-2017 Vector 35 LLC
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

# Binary Ninja components
import _binaryninjacore as core
from .enums import PluginType, PluginUpdateStatus
import startup


class RepoPlugin(object):
	"""
	``RepoPlugin` is mostly read-only, however you can install/uninstall enable/disable plugins. RepoPlugins are
	created by parsing the plugins.json in a plugin repository.
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNRepoPlugin)

	def __del__(self):
		core.BNFreePlugin(self.handle)

	def __repr__(self):
		return "<{} {}/{}>".format(self.path, "installed" if self.installed else "not-installed", "enabled" if self.enabled else "disabled")

	@property
	def path(self):
		"""Relative path from the base of the repository to the actual plugin"""
		return core.BNPluginGetPath(self.handle)

	@property
	def installed(self):
		"""Boolean True if the plugin is installed, False otherwise"""
		return core.BNPluginIsInstalled(self.handle)

	@installed.setter
	def installed(self, state):
		if state:
			return core.BNPluginInstall(self.handle)
		else:
			return core.BNPluginUninstall(self.handle)

	@property
	def enabled(self):
		"""Boolean True if the plugin is currently enabled, False otherwise"""
		return core.BNPluginIsEnabled(self.handle)

	@enabled.setter
	def enabled(self, state):
		if state:
			return core.BNPluginEnable(self.handle)
		else:
			return core.BNPluginDisable(self.handle)

	@property
	def api(self):
		"""string indicating the api used by the plugin"""
		return core.BNPluginGetApi(self.handle)

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
		return core.BNPluginGetMinimimVersions(self.handle)

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
		for i in xrange(count.value):
			result.append(PluginType(plugintypes[i]))
		core.BNFreePluginTypes(plugintypes)
		return result

	@property
	def url(self):
		"""String url of the plugin's git repository"""
		return core.BNPluginGetUrl(self.handle)

	@property
	def version(self):
		"""String version of the plugin"""
		return core.BNPluginGetVersion(self.handle)

	@property
	def update_status(self):
		"""PluginUpdateStatus enumeration indicating if the plugin is up to date or not"""
		return PluginUpdateStatus(core.BNPluginGetPluginUpdateStatus(self.handle))


class Repository(object):
	"""
	``Repository`` is a read-only class. Use RepositoryManager to Enable/Disable/Install/Uninstall plugins.
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNRepository)

	def __del__(self):
		core.BNFreeRepository(self.handle)

	def __repr__(self):
		return "<{} - {}/{}>".format(self.path, self.remote_reference, self.local_reference)

	def __getitem__(self, plugin_path):
		for plugin in self.plugins:
			if plugin_path == plugin.path:
				return plugin
		raise KeyError()

	@property
	def url(self):
		"""String url of the git repository where the plugin repository's are stored"""
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
	def local_reference(self):
		"""String for the local git reference (ie 'master')"""
		return core.BNRepositoryGetLocalReference(self.handle)

	@property
	def remote_reference(self):
		"""String for the remote git reference (ie 'origin')"""
		return core.BNRepositoryGetRemoteReference(self.handle)

	@property
	def plugins(self):
		"""List of RepoPlugin objects contained within this repository"""
		pluginlist = []
		count = ctypes.c_ulonglong(0)
		result = core.BNRepositoryGetPlugins(self.handle, count)
		for i in xrange(count.value):
			pluginlist.append(RepoPlugin(handle=result[i]))
		core.BNFreeRepositoryPluginList(result, count.value)
		del result
		return pluginlist

	@property
	def initialized(self):
		"""Boolean True when the repository has been initialized"""
		return core.BNRepositoryIsInitialized(self.handle)


class RepositoryManager(object):
	"""
	``RepositoryManager`` Keeps track of all the repositories and keeps the enabled_plugins.json file coherent with
	the plugins that are installed/unstalled enabled/disabled
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
		for i in xrange(count.value):
			result.append(Repository(handle=repos[i]))
		core.BNFreeRepositoryManagerRepositoriesList(repos)
		return result

	@property
	def plugins(self):
		"""List of all RepoPlugins in each repository"""
		plgs = {}
		for repo in self.repositories:
			plgs[repo.path] = repo.plugins
		return plgs

	@property
	def default_repository(self):
		"""Gets the default Repository"""
		startup._init_plugins()
		return Repository(handle=core.BNRepositoryManagerGetDefaultRepository(self.handle))

	def enable_plugin(self, plugin, install=True, repo=None):
		"""
		``enable_plugin`` Enables the installed plugin 'plugin', optionally installing the plugin if `install` is set to
		True (default), and optionally using the non-default repository.

		:param str name: Name of the plugin to enable
		:param Boolean install: Optionally install the repo, defaults to True.
		:param str repo: Optional, specify a repository other than the default repository.
		:return: Boolean value True if the plugin was successfully enabled, False otherwise
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.enable_plugin('binaryninja-bookmarks')
			True
			>>>
		"""
		if install:
			if not self.install_plugin(plugin, repo):
				return False

		if repo is None:
			repo = self.default_repository
		repopath = repo
		pluginpath = plugin
		if not isinstance(repo, str):
			repopath = repo.path
		if not isinstance(plugin, str):
			pluginpath = plugin.path
		return core.BNRepositoryManagerEnablePlugin(self.handle, repopath, pluginpath)

	def disable_plugin(self, plugin, repo=None):
		"""
		``disable_plugin`` Disable the specified plugin, pluginpath

		:param Repository or str repo: Repository containing the plugin to disable
		:param RepoPlugin or str plugin: RepoPlugin to disable
		:return: Boolean value True if the plugin was successfully disabled, False otherwise
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.disable_plugin('binaryninja-bookmarks')
			True
			>>>
		"""
		if repo is None:
			repo = self.default_repository
		repopath = repo
		pluginpath = plugin
		if not isinstance(repo, str):
			repopath = repo.path
		if not isinstance(plugin, str):
			pluginpath = plugin.path
		return core.BNRepositoryManagerDisablePlugin(self.handle, repopath, pluginpath)

	def install_plugin(self, plugin, repo=None):
		"""
		``install_plugin`` install the specified plugin, pluginpath

		:param Repository or str repo: Repository containing the plugin to install
		:param RepoPlugin or str plugin: RepoPlugin to install
		:return: Boolean value True if the plugin was successfully installed, False otherwise
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.install_plugin('binaryninja-bookmarks')
			True
			>>>
		"""
		if repo is None:
			repo = self.default_repository
		repopath = repo
		pluginpath = plugin
		if not isinstance(repo, str):
			repopath = repo.path
		if not isinstance(plugin, str):
			pluginpath = plugin.path
		return core.BNRepositoryManagerInstallPlugin(self.handle, repopath, pluginpath)

	def uninstall_plugin(self, plugin, repo=None):
		"""
		``uninstall_plugin`` uninstall the specified plugin, pluginpath

		:param Repository or str repo: Repository containing the plugin to uninstall
		:param RepoPlugin or str plugin: RepoPlugin to uninstall
		:return: Boolean value True if the plugin was successfully uninstalled, False otherwise
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.uninstall_plugin('binaryninja-bookmarks')
			True
			>>>
		"""
		if repo is None:
			repo = self.default_repository
		repopath = repo
		pluginpath = plugin
		if not isinstance(repo, str):
			repopath = repo.path
		if not isinstance(plugin, str):
			pluginpath = plugin.path
		return core.BNRepositoryManagerUninstallPlugin(self.handle, repopath, pluginpath)

	def update_plugin(self, plugin, repo=None):
		"""
		``update_plugin`` update the specified plugin, pluginpath

		:param Repository or str repo: Repository containing the plugin to update
		:param RepoPlugin or str plugin: RepoPlugin to update
		:return: Boolean value True if the plugin was successfully updated, False otherwise
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.update_plugin('binaryninja-bookmarks')
			True
			>>>
		"""
		if repo is None:
			repo = self.default_repository
		repopath = repo
		pluginpath = plugin
		if not isinstance(repo, str):
			repopath = repo.path
		if not isinstance(plugin, str):
			pluginpath = plugin.path
		return core.BNRepositoryManagerUpdatePlugin(self.handle, repopath, pluginpath)

	def add_repository(self, url=None, repopath=None, localreference="master", remotereference="origin"):
		"""
		``add_repository`` adds a new plugin repository for the manager to track.

		:param str url: Url to the git repository where the plugins are stored.
		:param str repopath: path to where the repository will be stored on disk locally
		:param str localreference: Optional reference to the local tracking branch typically "master"
		:param str remotereference: Optional reference to the remote tracking branch typically "origin"
		:return: Boolean value True if the repository was successfully added, False otherwise.
		:rtype: Boolean
		:Example:

			>>> mgr = RepositoryManager()
			>>> mgr.add_repository(url="https://github.com/vector35/community-plugins.git",
			                       repopath="myrepo",
			                       repomanifest="plugins",
			                       localreference="master", remotereference="origin")
			True
			>>>
		"""
		if not (isinstance(url, str) and isinstance(repopath, str) and
			isinstance(localreference, str) and isinstance(remotereference, str)):
			raise ValueError("Parameter is incorrect type")

		return core.BNRepositoryManagerAddRepository(self.handle, url, repopath, localreference, remotereference)

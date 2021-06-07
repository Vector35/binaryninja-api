# Copyright (c) 2015-2021 Vector 35 Inc
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

import traceback
import ctypes
from typing import Any, Callable, Optional, List

# Binary Ninja Components
import binaryninja
from . import _binaryninjacore as core
from .enums import SaveOption
from . import associateddatastore #required for _FileMetadataAssociatedDataStore
from . import log
from . import binaryview

ProgressFuncType = Callable[[int, int], bool]
ViewName = str

class NavigationHandler(object):
	def _register(self, handle) -> None:
		self._cb = core.BNNavigationHandler()
		self._cb.context = 0
		self._cb.getCurrentView = self._cb.getCurrentView.__class__(self._get_current_view)
		self._cb.getCurrentOffset = self._cb.getCurrentOffset.__class__(self._get_current_offset)
		self._cb.navigate = self._cb.navigate.__class__(self._navigate)
		core.BNSetFileMetadataNavigationHandler(handle, self._cb)

	def _get_current_view(self, ctxt:Any):
		try:
			view = self.get_current_view()
		except:
			log.log_error(traceback.format_exc())
			view = ""
		return core.BNAllocString(view)

	def _get_current_offset(self, ctxt:Any) -> int:
		try:
			return self.get_current_offset()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _navigate(self, ctxt:Any, view:ViewName, offset:int) -> bool:
		try:
			return self.navigate(view, offset)
		except:
			log.log_error(traceback.format_exc())
			return False

	def get_current_view(self) -> str:
		return NotImplemented

	def get_current_offset(self) -> int:
		return NotImplemented

	def navigate(self, view:ViewName, offset:int) -> bool:
		return NotImplemented


class SaveSettings(object):
	"""
	``class SaveSettings`` is used to specify actions and options that apply to saving a database (.bndb).
	"""

	def __init__(self, handle=None):
		if handle is None:
			self.handle = core.BNCreateSaveSettings()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeSaveSettings(self.handle)

	def is_option_set(self, option:SaveOption) -> bool:
		if isinstance(option, str):
			option = SaveOption[option]
		return core.BNIsSaveSettingsOptionSet(self.handle, option)

	def set_option(self, option:SaveOption, state:bool=True):
		"""
		Set a SaveOption in this instance.

		:param SaveOption option: Option to set.
		:param bool state: State to assign. Defaults to True.
		:Example:
			>>> settings = SaveSettings()
			>>> settings.set_option(SaveOption.TrimSnapshots)
		"""
		if isinstance(option, str):
			option = SaveOption[option]
		core.BNSetSaveSettingsOption(self.handle, option, state)


class _FileMetadataAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class FileMetadata(object):
	"""
	``class FileMetadata`` represents the file being analyzed by Binary Ninja. It is responsible for opening,
	closing, creating the database (.bndb) files, and is used to keep track of undoable actions.
	"""

	_associated_data = {}

	def __init__(self, filename = None, handle = None):
		"""
		Instantiates a new FileMetadata class.

		:param str filename: The string path to the file to be opened. Defaults to None.
		:param handle: A handle to the underlying C FileMetadata object. Defaults to None.
		"""
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFileMetadata)
		else:
			binaryninja._init_plugins()
			self.handle = core.BNCreateFileMetadata()
			if filename is not None:
				core.BNSetFilename(self.handle, str(filename))
		self._nav:Optional[NavigationHandler] = None

	def __repr__(self):
		return "<FileMetadata: %s>" % self.filename

	def __del__(self):
		if self.navigation is not None:
			core.BNSetFileMetadataNavigationHandler(self.handle, None)
		core.BNFreeFileMetadata(self.handle)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		assert self.handle is not None
		assert other.handle is not None
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		assert self.handle is not None
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def nav(self) -> Optional[NavigationHandler]:
		return self._nav

	@nav.setter
	def nav(self, value:NavigationHandler) -> None:
		self._nav = value

	@classmethod
	def _unregister(cls, f):
		handle = ctypes.cast(f, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@staticmethod
	def set_default_session_data(name:str, value:Any) -> None:
		_FileMetadataAssociatedDataStore.set_default(name, value)

	@property
	def original_filename(self) -> str:
		"""The original name of the binary opened if a bndb, otherwise reads or sets the current filename (read/write)"""
		return core.BNGetOriginalFilename(self.handle)

	@original_filename.setter
	def original_filename(self, value:str) -> None:
		core.BNSetOriginalFilename(self.handle, str(value))

	@property
	def filename(self) -> str:
		"""The name of the open bndb or binary filename (read/write)"""
		return core.BNGetFilename(self.handle)

	@filename.setter
	def filename(self, value:str) -> None:
		core.BNSetFilename(self.handle, str(value))

	@property
	def modified(self) -> bool:
		"""Boolean result of whether the file is modified (Inverse of 'saved' property) (read/write)"""
		return core.BNIsFileModified(self.handle)

	@modified.setter
	def modified(self, value:bool) -> None:
		if value:
			core.BNMarkFileModified(self.handle)
		else:
			core.BNMarkFileSaved(self.handle)

	@property
	def analysis_changed(self) -> bool:
		"""Boolean result of whether the auto-analysis results have changed (read-only)"""
		return core.BNIsAnalysisChanged(self.handle)

	@property
	def has_database(self, binary_view_type:ViewName="") -> bool:
		"""Whether the FileMetadata is backed by a database, or if specified, a specific BinaryViewType (read-only)"""
		return core.BNIsBackedByDatabase(self.handle, binary_view_type)

	@property
	def view(self) -> ViewName:
		return core.BNGetCurrentView(self.handle)

	@view.setter
	def view(self, value:ViewName) -> None:
		core.BNNavigate(self.handle, str(value), core.BNGetCurrentOffset(self.handle))

	@property
	def offset(self) -> int:
		"""The current offset into the file (read/write)"""
		return core.BNGetCurrentOffset(self.handle)

	@offset.setter
	def offset(self, value:int) -> None:
		core.BNNavigate(self.handle, core.BNGetCurrentView(self.handle), value)

	@property
	def raw(self) -> Optional['binaryview.BinaryView']:
		"""Gets the "Raw" BinaryView of the file"""
		view = core.BNGetFileViewOfType(self.handle, "Raw")
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	@property
	def saved(self) -> bool:
		"""Boolean result of whether the file has been saved (Inverse of 'modified' property) (read/write)"""
		return not core.BNIsFileModified(self.handle)

	@saved.setter
	def saved(self, value:bool) -> None:
		if value:
			core.BNMarkFileSaved(self.handle)
		else:
			core.BNMarkFileModified(self.handle)

	@property
	def navigation(self) -> Optional[NavigationHandler]:
		"""Alias for nav"""
		return self._nav

	@navigation.setter
	def navigation(self, value:NavigationHandler) -> None:
		assert self.handle is not None
		value._register(self.handle)
		self._nav = value

	@property
	def session_data(self) -> Any:
		"""Dictionary object where plugins can store arbitrary data associated with the file"""
		assert self.handle is not None, "Attempting to set session_data when handle is None"
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in FileMetadata._associated_data:
			obj = _FileMetadataAssociatedDataStore()
			FileMetadata._associated_data[handle.value] = obj
			return obj
		else:
			return FileMetadata._associated_data[handle.value]

	@property
	def snapshot_data_applied_without_error(self) -> bool:
		return core.BNIsSnapshotDataAppliedWithoutError(self.handle)

	def close(self) -> None:
		"""
		Closes the underlying file handle. It is recommended that this is done in a
		`finally` clause to avoid handle leaks.
		"""
		core.BNCloseFile(self.handle)

	def begin_undo_actions(self) -> None:
		"""
		``begin_undo_actions`` start recording actions taken so the can be undone at some point.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		core.BNBeginUndoActions(self.handle)

	def commit_undo_actions(self) -> None:
		"""
		``commit_undo_actions`` commit the actions taken since the last commit to the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		core.BNCommitUndoActions(self.handle)

	def undo(self) -> None:
		"""
		``undo`` undo the last committed action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.redo()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>>
		"""
		core.BNUndo(self.handle)

	def redo(self) -> None:
		"""
		``redo`` redo the last committed action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.redo()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>>
		"""
		core.BNRedo(self.handle)

	def navigate(self, view:ViewName, offset:int) -> bool:
		"""
		``navigate`` navigates the UI to the specified virtual address

		.. note:: Despite the confusing name, ``view`` in this context is not a BinaryView but rather a string describing the different UI Views.  Check :py:attr:`view` while in different views to see examples such as ``Linear:ELF``, ``Graph:PE``.

		:param str view: virtual address to read from.
		:param int offset: address to navigate to
		:return: whether or not navigation succeeded
		:rtype: bool
		:Example:

			>>> import random
			>>> bv.navigate(bv.view, random.choice(list(bv.functions)).start)
			True
		"""
		return core.BNNavigate(self.handle, str(view), offset)

	def create_database(self, filename:str, progress_func:Optional[ProgressFuncType]= None, settings:SaveSettings=None):
		"""
		``create_database`` writes the current database (.bndb) out to the specified file.

		:param str filename: path and filename to write the bndb to, this string `should` have ".bndb" appended to it.
		:param callback progress_func: optional function to be called with the current progress and total count.
		:param SaveSettings settings: optional argument for special save options.
		:return: true on success, false on failure
		:rtype: bool
		:Example:
			>>> settings = SaveSettings()
			>>> bv.file.create_database(f"{bv.file.filename}.bndb", None, settings)
			True
		"""
		_settings = None
		if settings is not None:
			_settings = settings.handle

		assert self.raw is not None, "BinaryView.create_database called when raw view is None"
		if progress_func is None:
			return core.BNCreateDatabase(self.raw.handle, str(filename), _settings)
		else:
			_progress_func = progress_func
			return core.BNCreateDatabaseWithProgress(self.raw.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
					lambda ctxt, cur, total: _progress_func(cur, total)), settings)

	def open_existing_database(self, filename:str, progress_func:Callable[[int, int], bool]=None):
		if progress_func is None:
			view = core.BNOpenExistingDatabase(self.handle, str(filename))
		else:
			view = core.BNOpenExistingDatabaseWithProgress(self.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
				lambda ctxt, cur, total: progress_func(cur, total)))
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	def open_database_for_configuration(self, filename:str) -> Optional['binaryview.BinaryView']:
		view = core.BNOpenDatabaseForConfiguration(self.handle, str(filename))
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	def save_auto_snapshot(self, progress_func:Optional[ProgressFuncType]=None, settings:SaveSettings=None):
		_settings = None
		if settings is not None:
			_settings = settings.handle

		assert self.raw is not None, "BinaryView.save_auto_snapshot called when raw view is None"
		if progress_func is None:
			return core.BNSaveAutoSnapshot(self.raw.handle, _settings)
		else:
			_progress_func = progress_func
			return core.BNSaveAutoSnapshotWithProgress(self.raw.handle, None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
					lambda ctxt, cur, total: _progress_func(cur, total)), _settings)

	def merge_user_analysis(self, path:str, progress_func:ProgressFuncType):
		return core.BNMergeUserAnalysis(self.handle, str(path), None,
			ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
			lambda ctxt, cur, total: progress_func(cur, total)))

	def get_view_of_type(self, name:str) -> Optional['binaryview.BinaryView']:
		view = core.BNGetFileViewOfType(self.handle, str(name))
		if view is None:
			view_type = core.BNGetBinaryViewTypeByName(str(name))
			if view_type is None:
				return None

			assert self.raw is not None, "BinaryView.save_auto_snapshot called when raw view is None"
			view = core.BNCreateBinaryViewOfType(view_type, self.raw.handle)
			if view is None:
				return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	def open_project(self) -> bool:
		return core.BNOpenProject(self.handle)

	def close_project(self) -> None:
		core.BNCloseProject(self.handle)

	def is_project_open(self) -> bool:
		return core.BNIsProjectOpen(self.handle)

	@property
	def existing_views(self) -> List[ViewName]:
		length = ctypes.c_ulonglong()
		result = core.BNGetExistingViews(self.handle, ctypes.byref(length))
		assert result is not None, "core.BNGetExistingViews returned None"
		views = []
		for i in range(length.value):
			views.append(result[i].decode("utf-8"))
		core.BNFreeStringList(result, length)
		return views
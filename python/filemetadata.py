# Copyright (c) 2015-2024 Vector 35 Inc
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
import contextlib
import traceback
import ctypes
from typing import Any, Callable, Optional, List, Generator

# Binary Ninja Components
import binaryninja
from . import _binaryninjacore as core
from .enums import SaveOption
from . import associateddatastore  #required for _FileMetadataAssociatedDataStore
from .log import log_error
from . import binaryview
from . import database
from . import deprecation
from . import project
from . import undo

ProgressFuncType = Callable[[int, int], bool]
ViewName = str


class NavigationHandler:
	def _register(self, handle) -> None:
		self._cb = core.BNNavigationHandler()
		self._cb.context = 0
		self._cb.getCurrentView = self._cb.getCurrentView.__class__(self._get_current_view)
		self._cb.getCurrentOffset = self._cb.getCurrentOffset.__class__(self._get_current_offset)
		self._cb.navigate = self._cb.navigate.__class__(self._navigate)
		core.BNSetFileMetadataNavigationHandler(handle, self._cb)

	def _get_current_view(self, ctxt: Any):
		try:
			view = self.get_current_view()
		except:
			log_error(traceback.format_exc())
			view = ""
		return core.BNAllocString(view)

	def _get_current_offset(self, ctxt: Any) -> int:
		try:
			return self.get_current_offset()
		except:
			log_error(traceback.format_exc())
			return 0

	def _navigate(self, ctxt: Any, view: ViewName, offset: int) -> bool:
		try:
			return self.navigate(view, offset)
		except:
			log_error(traceback.format_exc())
			return False

	def get_current_view(self) -> str:
		return NotImplemented

	def get_current_offset(self) -> int:
		return NotImplemented

	def navigate(self, view: ViewName, offset: int) -> bool:
		return NotImplemented


class SaveSettings:
	"""
	``class SaveSettings`` is used to specify actions and options that apply to saving a database (.bndb).
	"""
	def __init__(self, handle=None):
		if handle is None:
			self.handle = core.BNCreateSaveSettings()
		else:
			self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeSaveSettings(self.handle)

	def is_option_set(self, option: SaveOption) -> bool:
		if isinstance(option, str):
			option = SaveOption[option]
		return core.BNIsSaveSettingsOptionSet(self.handle, option)

	def set_option(self, option: SaveOption, state: bool = True):
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


class FileMetadata:
	"""
	``class FileMetadata`` represents the file being analyzed by Binary Ninja. It is responsible for opening,
	closing, creating the database (.bndb) files, and is used to keep track of undoable actions.

	:param str filename: The string path to the file to be opened. Defaults to None.
	:param handle: A handle to the underlying C FileMetadata object. Defaults to None. (Internal use only.)
	"""

	_associated_data = {}

	def __init__(self, filename: Optional[str] = None, handle: Optional[core.BNFileMetadataHandle] = None):
		if handle is not None:
			_type = core.BNFileMetadataHandle
			_handle = ctypes.cast(handle, _type)
		else:
			binaryninja._init_plugins()
			_handle = core.BNCreateFileMetadata()
			if filename is not None:
				core.BNSetFilename(_handle, str(filename))
		self._nav: Optional[NavigationHandler] = None
		assert _handle is not None
		self.handle = _handle

	def __repr__(self):
		return f"<FileMetadata: {self.filename}>"

	def __del__(self):
		if core is not None:
			if self.navigation is not None:
				core.BNSetFileMetadataNavigationHandler(self.handle, None)
			core.BNFreeFileMetadata(self.handle)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def nav(self) -> Optional[NavigationHandler]:
		"""Navigation handler for this FileMetadata (read/write)"""
		return self._nav

	@nav.setter
	def nav(self, value: NavigationHandler) -> None:
		self._nav = value

	@property
	def session_id(self) -> int:
		return core.BNFileMetadataGetSessionId(self.handle)

	@classmethod
	def _unregister(cls, f):
		handle = ctypes.cast(f, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@staticmethod
	def set_default_session_data(name: str, value: Any) -> None:
		_FileMetadataAssociatedDataStore.set_default(name, value)

	@property
	def original_filename(self) -> str:
		"""
		The original name of the binary opened if a bndb, otherwise reads or sets the current filename (read/write)

		.. note:: With projects, ``bv.file.original_filename`` queries the path of the binary as staged in the project directory. Use ``bv.project_file.name`` to query the original name of the opened binary.
		"""
		return core.BNGetOriginalFilename(self.handle)

	@original_filename.setter
	def original_filename(self, value: str) -> None:
		core.BNSetOriginalFilename(self.handle, str(value))

	@property
	def filename(self) -> str:
		"""The name of the open bndb or binary filename (read/write)"""
		return core.BNGetFilename(self.handle)

	@filename.setter
	def filename(self, value: str) -> None:
		core.BNSetFilename(self.handle, str(value))

	@property
	def modified(self) -> bool:
		"""Boolean result of whether the file is modified (Inverse of 'saved' property) (read/write)"""
		return core.BNIsFileModified(self.handle)

	@modified.setter
	def modified(self, value: bool) -> None:
		if value:
			core.BNMarkFileModified(self.handle)
		else:
			core.BNMarkFileSaved(self.handle)

	@property
	def analysis_changed(self) -> bool:
		"""Boolean result of whether the auto-analysis results have changed (read-only)"""
		return core.BNIsAnalysisChanged(self.handle)

	@property
	def has_database(self, binary_view_type: ViewName = "") -> bool:
		"""Whether the FileMetadata is backed by a database, or if specified, a specific BinaryViewType (read-only)"""
		return core.BNIsBackedByDatabase(self.handle, binary_view_type)

	@property
	def view(self) -> ViewName:
		return core.BNGetCurrentView(self.handle)

	@view.setter
	def view(self, value: ViewName) -> None:
		core.BNNavigate(self.handle, str(value), core.BNGetCurrentOffset(self.handle))

	@property
	def offset(self) -> int:
		"""The current offset into the file (read/write)"""
		return core.BNGetCurrentOffset(self.handle)

	@offset.setter
	def offset(self, value: int) -> None:
		core.BNNavigate(self.handle, core.BNGetCurrentView(self.handle), value)

	@property
	def raw(self) -> Optional['binaryview.BinaryView']:
		"""Gets the "Raw" BinaryView of the file"""
		view = core.BNGetFileViewOfType(self.handle, "Raw")
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata=self, handle=view)

	@property
	def database(self) -> Optional['database.Database']:
		"""Gets the backing Database of the file"""
		handle = core.BNGetFileMetadataDatabase(self.handle)
		if handle is None:
			return None
		return database.Database(handle=handle)

	@property
	def saved(self) -> bool:
		"""Boolean result of whether the file has been saved (Inverse of 'modified' property) (read/write)"""
		return not core.BNIsFileModified(self.handle)

	@saved.setter
	def saved(self, value: bool) -> None:
		if value:
			core.BNMarkFileSaved(self.handle)
		else:
			core.BNMarkFileModified(self.handle)

	@property
	def navigation(self) -> Optional[NavigationHandler]:
		"""Alias for nav"""
		return self._nav

	@navigation.setter
	def navigation(self, value: NavigationHandler) -> None:
		value._register(self.handle)
		self._nav = value

	@property
	def session_data(self) -> Any:
		"""Dictionary object where plugins can store arbitrary data associated with the file"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)  # type: ignore
		if handle.value not in FileMetadata._associated_data:
			obj = _FileMetadataAssociatedDataStore()
			FileMetadata._associated_data[handle.value] = obj
			return obj
		else:
			return FileMetadata._associated_data[handle.value]

	@property
	def snapshot_data_applied_without_error(self) -> bool:
		return core.BNIsSnapshotDataAppliedWithoutError(self.handle)

	@property
	def project(self) -> Optional['project.Project']:
		project_file = self.project_file
		if project_file is None:
			return None
		return project_file.project

	@property
	def project_file(self) -> Optional['project.ProjectFile']:
		handle = core.BNGetProjectFile(self.handle)
		if handle is None:
			return None
		return project.ProjectFile(handle)

	def close(self) -> None:
		"""
		Closes the underlying file handle. It is recommended that this is done in a
		`finally` clause to avoid handle leaks.
		"""
		core.BNCloseFile(self.handle)

	@contextlib.contextmanager
	def undoable_transaction(self) -> Generator:
		"""
		``undoable_transaction`` gives you a context in which you can make changes to analysis,
		and creates an Undo state containing those actions. If an exception is thrown, any
		changes made to the analysis inside the transaction are reverted.

		:return: Transaction context manager, which will commit/revert actions depending on if an exception
		         is thrown when it goes out of scope.
		:rtype: Generator
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> # Actions inside the transaction will be committed to the undo state upon exit
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> # A thrown exception inside the transaction will undo all changes made inside it
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)  # Reverted on thrown exception
			>>>     raise RuntimeError("oh no")
			RuntimeError: oh no
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
		"""
		state = self.begin_undo_actions(False)
		try:
			yield state
			self.commit_undo_actions(state)
		except:
			self.revert_undo_actions(state)
			raise

	def begin_undo_actions(self, anonymous_allowed: bool = True) -> str:
		"""
		``begin_undo_actions`` starts recording actions taken so they can be undone at some point.

		:param bool anonymous_allowed: Legacy interop: prevent empty calls to :py:func:`commit_undo_actions`` from
		                               affecting this undo state. Specifically for :py:func:`undoable_transaction``
		:return: Id of undo state, for passing to :py:func:`commit_undo_actions`` or :py:func:`revert_undo_actions`.
		:rtype: str
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		id = core.BNBeginUndoActions(self.handle, anonymous_allowed)
		return id

	def commit_undo_actions(self, id: Optional[str] = None) -> None:
		"""
		``commit_undo_actions`` commits the actions taken since a call to :py:func:`begin_undo_actions`
		Pass as `id` the value returned by :py:func:`begin_undo_actions`. Empty values of
		`id` will commit all changes since the last call to :py:func:`begin_undo_actions`.

		:param Optional[str] id: id of undo state, from :py:func:`begin_undo_actions`
		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""

		if id is None:
			id = ""
		core.BNCommitUndoActions(self.handle, id)

	def forget_undo_actions(self, id: Optional[str] = None) -> None:
		"""
		``forget_undo_actions`` removes the actions taken since a call to :py:func:`begin_undo_actions`
		Pass as `id` the value returned by :py:func:`begin_undo_actions`. Empty values of
		`id` will remove all changes since the last call to :py:func:`begin_undo_actions`.

		:param Optional[str] id: id of undo state, from :py:func:`begin_undo_actions`
		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.forget_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>>
		"""

		if id is None:
			id = ""
		core.BNForgetUndoActions(self.handle, id)

	def revert_undo_actions(self, id: Optional[str] = None) -> None:
		"""
		``revert_undo_actions`` reverts the actions taken since a call to :py:func:`begin_undo_actions`
		Pass as `id` the value returned by :py:func:`begin_undo_actions`. Empty values of
		`id` will revert all changes since the last call to :py:func:`begin_undo_actions`.

		:param Optional[str] id: id of undo state, from :py:func:`begin_undo_actions`
		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.revert_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""

		if id is None:
			id = ""
		core.BNRevertUndoActions(self.handle, id)

	def undo(self) -> None:
		"""
		``undo`` undo the last committed transaction in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
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
		``redo`` redo the last committed transaction in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
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

	@property
	def undo_entries(self) -> List['undo.UndoEntry']:
		count = ctypes.c_ulonglong()

		entries = core.BNGetUndoEntries(self.handle, count)
		assert entries is not None, "core.BNGetUndoEntries returned None"

		result = []
		try:
			for i in range(0, count.value):
				tag_handle = core.BNNewUndoEntryReference(entries[i])
				assert tag_handle is not None, "core.BNNewUndoEntryReference returned None"
				result.append(undo.UndoEntry(tag_handle))
			return result
		finally:
			core.BNFreeUndoEntryList(entries, count.value)

	@property
	def redo_entries(self) -> List['undo.UndoEntry']:
		count = ctypes.c_ulonglong()

		entries = core.BNGetRedoEntries(self.handle, count)
		assert entries is not None, "core.BNGetRedoEntries returned None"

		result = []
		try:
			for i in range(0, count.value):
				tag_handle = core.BNNewUndoEntryReference(entries[i])
				assert tag_handle is not None, "core.BNNewUndoEntryReference returned None"
				result.append(undo.UndoEntry(tag_handle))
			return result
		finally:
			core.BNFreeUndoEntryList(entries, count.value)

	def navigate(self, view: ViewName, offset: int) -> bool:
		"""
		``navigate`` navigates the UI to the specified virtual address

		.. note:: Despite the confusing name, ``view`` in this context is not a BinaryView but rather a string describing the different UI Views. Check :py:attr:`view` while in different views to see examples such as ``Linear:ELF``, ``Graph:PE``.

		:param str view: view name
		:param int offset: address to navigate to
		:return: whether or not navigation succeeded
		:rtype: bool
		:Example:

			>>> import random
			>>> bv.navigate(bv.view, random.choice(list(bv.functions)).start)
			True
		"""
		return core.BNNavigate(self.handle, str(view), offset)

	def create_database(
	    self, filename: str, progress_func: Optional[ProgressFuncType] = None, settings: Optional[SaveSettings] = None
	) -> bool:
		"""
		``create_database`` writes the current database (.bndb) out to the specified file.

		:param str filename: path and filename to write the bndb to, this string `should` have ".bndb" appended to it.
		:param callback progress_func: optional function to be called with the current progress and total count.
		:param SaveSettings settings: optional argument for special save options.
		:return: true on success, false on failure
		:rtype: bool

		.. note:: The progress_func callback **must** return True to continue the save operation, False will abort the save operation.

		.. warning:: The calling thread must not hold a lock on the BinaryView instance as this action is run on the main thread which requires the lock.

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
			return core.BNCreateDatabaseWithProgress(
			    self.raw.handle, str(filename), None,
			    ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong,
			                     ctypes.c_ulonglong)(lambda ctxt, cur, total: _progress_func(cur, total)), _settings
			)

	# TODO : When this is removed, you can probably remove `BNOpenExistingDatabase` and `BNOpenExistingDatabaseWithProgress` too

	def save_auto_snapshot(self, progress_func: Optional[ProgressFuncType] = None, settings: Optional[SaveSettings] = None) -> bool:
		_settings = None
		if settings is not None:
			_settings = settings.handle

		assert self.raw is not None, "BinaryView.save_auto_snapshot called when raw view is None"
		if progress_func is None:
			return core.BNSaveAutoSnapshot(self.raw.handle, _settings)
		else:
			_progress_func = progress_func
			return core.BNSaveAutoSnapshotWithProgress(
			    self.raw.handle, None,
			    ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong,
			                     ctypes.c_ulonglong)(lambda ctxt, cur, total: _progress_func(cur, total)), _settings
			)

	def get_view_of_type(self, name: str) -> Optional['binaryview.BinaryView']:
		view = core.BNGetFileViewOfType(self.handle, str(name))
		if view is None:
			view_type = core.BNGetBinaryViewTypeByName(str(name))
			if view_type is None:
				return None

			assert self.raw is not None, "BinaryView.get_view_of_type called when raw view is None"
			view = core.BNCreateBinaryViewOfType(view_type, self.raw.handle)
			if view is None:
				return None
		return binaryview.BinaryView(file_metadata=self, handle=view)


	@property
	def existing_views(self) -> List[ViewName]:
		length = ctypes.c_ulonglong()
		result = core.BNGetExistingViews(self.handle, ctypes.byref(length))
		assert result is not None, "core.BNGetExistingViews returned None"
		views = []
		for i in range(length.value):
			views.append(result[i].decode("utf-8"))
		core.BNFreeStringList(result, length.value)
		return views

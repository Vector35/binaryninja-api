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

import traceback
import ctypes

# Binary Ninja components
import _binaryninjacore as core
import startup
import associateddatastore
import log
import binaryview


class NavigationHandler(object):
	def _register(self, handle):
		self._cb = core.BNNavigationHandler()
		self._cb.context = 0
		self._cb.getCurrentView = self._cb.getCurrentView.__class__(self._get_current_view)
		self._cb.getCurrentOffset = self._cb.getCurrentOffset.__class__(self._get_current_offset)
		self._cb.navigate = self._cb.navigate.__class__(self._navigate)
		core.BNSetFileMetadataNavigationHandler(handle, self._cb)

	def _get_current_view(self, ctxt):
		try:
			view = self.get_current_view()
		except:
			log.log_error(traceback.format_exc())
			view = ""
		return core.BNAllocString(view)

	def _get_current_offset(self, ctxt):
		try:
			return self.get_current_offset()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _navigate(self, ctxt, view, offset):
		try:
			return self.navigate(view, offset)
		except:
			log.log_error(traceback.format_exc())
			return False


class _FileMetadataAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class FileMetadata(object):
	_associated_data = {}

	"""
	``class FileMetadata`` represents the file being analyzed by Binary Ninja. It is responsible for opening,
	closing, creating the database (.bndb) files, and is used to keep track of undoable actions.
	"""
	def __init__(self, filename = None, handle = None):
		"""
		Instantiates a new FileMetadata class.

		:param filename: The string path to the file to be opened. Defaults to None.
		:param handle: A handle to the underlying C FileMetadata object. Defaults to None.
		"""
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFileMetadata)
		else:
			startup._init_plugins()
			self.handle = core.BNCreateFileMetadata()
			if filename is not None:
				core.BNSetFilename(self.handle, str(filename))
		self.nav = None

	def __del__(self):
		if self.navigation is not None:
			core.BNSetFileMetadataNavigationHandler(self.handle, None)
		core.BNFreeFileMetadata(self.handle)

	def __eq__(self, value):
		if not isinstance(value, FileMetadata):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, FileMetadata):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@classmethod
	def _unregister(cls, f):
		handle = ctypes.cast(f, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@classmethod
	def set_default_session_data(cls, name, value):
		_FileMetadataAssociatedDataStore.set_default(name, value)

	@property
	def filename(self):
		"""The name of the file (read/write)"""
		return core.BNGetFilename(self.handle)

	@filename.setter
	def filename(self, value):
		core.BNSetFilename(self.handle, str(value))

	@property
	def modified(self):
		"""Boolean result of whether the file is modified (Inverse of 'saved' property) (read/write)"""
		return core.BNIsFileModified(self.handle)

	@modified.setter
	def modified(self, value):
		if value:
			core.BNMarkFileModified(self.handle)
		else:
			core.BNMarkFileSaved(self.handle)

	@property
	def analysis_changed(self):
		"""Boolean result of whether the auto-analysis results have changed (read-only)"""
		return core.BNIsAnalysisChanged(self.handle)

	@property
	def has_database(self):
		"""Whether the FileMetadata is backed by a database (read-only)"""
		return core.BNIsBackedByDatabase(self.handle)

	@property
	def view(self):
		return core.BNGetCurrentView(self.handle)

	@view.setter
	def view(self, value):
		core.BNNavigate(self.handle, str(value), core.BNGetCurrentOffset(self.handle))

	@property
	def offset(self):
		"""The current offset into the file (read/write)"""
		return core.BNGetCurrentOffset(self.handle)

	@offset.setter
	def offset(self, value):
		core.BNNavigate(self.handle, core.BNGetCurrentView(self.handle), value)

	@property
	def raw(self):
		"""Gets the "Raw" BinaryView of the file"""
		view = core.BNGetFileViewOfType(self.handle, "Raw")
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	@property
	def saved(self):
		"""Boolean result of whether the file has been saved (Inverse of 'modified' property) (read/write)"""
		return not core.BNIsFileModified(self.handle)

	@saved.setter
	def saved(self, value):
		if value:
			core.BNMarkFileSaved(self.handle)
		else:
			core.BNMarkFileModified(self.handle)

	@property
	def navigation(self):
		return self.nav

	@navigation.setter
	def navigation(self, value):
		value._register(self.handle)
		self.nav = value

	@property
	def session_data(self):
		"""Dictionary object where plugins can store arbitrary data associated with the file"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in FileMetadata._associated_data:
			obj = _FileMetadataAssociatedDataStore()
			FileMetadata._associated_data[handle.value] = obj
			return obj
		else:
			return FileMetadata._associated_data[handle.value]

	def close(self):
		"""
		Closes the underlying file handle. It is recommended that this is done in a
		`finally` clause to avoid handle leaks.
		"""
		core.BNCloseFile(self.handle)

	def begin_undo_actions(self):
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

	def commit_undo_actions(self):
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

	def undo(self):
		"""
		``undo`` undo the last commited action in the undo database.

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

	def redo(self):
		"""
		``redo`` redo the last commited action in the undo database.

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

	def navigate(self, view, offset):
		return core.BNNavigate(self.handle, str(view), offset)

	def create_database(self, filename, progress_func = None):
		if progress_func is None:
			return core.BNCreateDatabase(self.raw.handle, str(filename))
		else:
			return core.BNCreateDatabaseWithProgress(self.raw.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
					lambda ctxt, cur, total: progress_func(cur, total)))

	def open_existing_database(self, filename, progress_func = None):
		if progress_func is None:
			view = core.BNOpenExistingDatabase(self.handle, str(filename))
		else:
			view = core.BNOpenExistingDatabaseWithProgress(self.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
				lambda ctxt, cur, total: progress_func(cur, total)))
		if view is None:
			return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	def save_auto_snapshot(self, progress_func = None):
		if progress_func is None:
			return core.BNSaveAutoSnapshot(self.raw.handle)
		else:
			return core.BNSaveAutoSnapshotWithProgress(self.raw.handle, None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
					lambda ctxt, cur, total: progress_func(cur, total)))

	def get_view_of_type(self, name):
		view = core.BNGetFileViewOfType(self.handle, str(name))
		if view is None:
			view_type = core.BNGetBinaryViewTypeByName(str(name))
			if view_type is None:
				return None
			view = core.BNCreateBinaryViewOfType(view_type, self.raw.handle)
			if view is None:
				return None
		return binaryview.BinaryView(file_metadata = self, handle = view)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)
